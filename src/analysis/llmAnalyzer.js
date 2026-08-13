/**
 * LLM vision analyzer — BytePlus Ark Responses API after KBS.
 * Produces llmAnalysis for side-by-side comparison; KBS remains the pipeline primary.
 */

import fs from "fs/promises";
import path from "path";
import {
  ABUSE_TYPES,
  ABUSE_TYPE_DESCRIPTIONS,
  normalizeAbuseType,
} from "../shared/constants/abuse.constant.js";
import {
  ARK_RESPONSES_URL,
  EMBEDDING_MODEL_API_KEY,
  LLM_MODEL,
} from "../../config/config.js";

const MAX_SIGNALS = 40;
const MAX_EVIDENCE_CHARS = 240;
const RISK_LEVELS = new Set(["Low", "Medium", "High"]);

/**
 * @typedef {Object} LlmAnalysis
 * @property {"Low"|"Medium"|"High"} riskLevel
 * @property {string} websiteTone
 * @property {string} riskCategory
 * @property {string} summary
 * @property {boolean} hasError
 * @property {number} confidenceScore
 */

/**
 * @typedef {Object} LlmAnalyzerResult
 * @property {LlmAnalysis|null} llmAnalysis
 * @property {string} [error]
 */

/**
 * @typedef {Object} LlmAnalyzerContext
 * @property {string} url
 * @property {import("./kbs.js").KBSResult} kbsResult
 * @property {Record<string, unknown>} [scanData]
 * @property {string} [userInput]
 * @property {string|null} [screenshotPath]
 */

/**
 * @param {string|null|undefined} screenshotPath
 * @returns {Promise<{ dataUrl: string|null, error: string|null }>}
 */
export async function toDataUrl(screenshotPath) {
  if (!screenshotPath || typeof screenshotPath !== "string") {
    return { dataUrl: null, error: "No screenshot path provided" };
  }
  try {
    const buf = await fs.readFile(screenshotPath);
    const ext = path.extname(screenshotPath).toLowerCase().replace(".", "");
    const mime =
      ext === "jpg" || ext === "jpeg"
        ? "image/jpeg"
        : ext === "webp"
          ? "image/webp"
          : "image/png";
    return {
      dataUrl: `data:${mime};base64,${buf.toString("base64")}`,
      error: null,
    };
  } catch (err) {
    return {
      dataUrl: null,
      error: err instanceof Error ? err.message : String(err),
    };
  }
}

/**
 * @param {import("./kbs.js").KBSResult} kbsResult
 * @returns {string}
 */
export function formatKbsForPrompt(kbsResult) {
  const classifiedAs = Array.isArray(kbsResult?.classifiedAs)
    ? kbsResult.classifiedAs
    : [];
  const scores = kbsResult?.classificationScores ?? {};
  const scoreLines = Object.entries(scores)
    .sort((a, b) => (b[1] ?? 0) - (a[1] ?? 0))
    .map(([name, score]) => `  - ${name}: ${Number(score).toFixed(3)}`)
    .join("\n");

  const signals = Array.isArray(kbsResult?.signals) ? kbsResult.signals : [];
  const signalLines = signals
    .slice(0, MAX_SIGNALS)
    .map((s) => {
      const evidence = Array.isArray(s.evidence)
        ? s.evidence.join("; ")
        : String(s.evidence ?? "");
      const clipped =
        evidence.length > MAX_EVIDENCE_CHARS
          ? `${evidence.slice(0, MAX_EVIDENCE_CHARS)}…`
          : evidence;
      return `- ${s.name} (strength=${s.strength ?? "?"}): ${clipped}`;
    })
    .join("\n");

  const omitted =
    signals.length > MAX_SIGNALS
      ? `\n(… ${signals.length - MAX_SIGNALS} more signals omitted)`
      : "";

  return [
    `KBS classifiedAs: ${classifiedAs.length ? classifiedAs.join(", ") : "(none)"}`,
    "KBS classificationScores:",
    scoreLines || "  (none)",
    "KBS signals (priors / hypotheses — not ground truth):",
    signalLines || "(none)",
    omitted,
  ]
    .filter(Boolean)
    .join("\n");
}

/**
 * @param {Object} opts
 * @param {string} opts.url
 * @param {string} [opts.userInput]
 * @param {import("./kbs.js").KBSResult} opts.kbsResult
 * @param {boolean} opts.screenshotAttached
 * @returns {string}
 */
export function buildClassificationPrompt({
  url,
  userInput = "",
  kbsResult,
  screenshotAttached,
}) {
  const catalog = ABUSE_TYPES.map((t) => {
    const desc = ABUSE_TYPE_DESCRIPTIONS[t] ?? t;
    return `- ${t} — ${desc}`;
  }).join("\n");

  const screenshotNote = screenshotAttached
    ? "A full-page screenshot is attached as an image. Treat it as primary visual evidence."
    : "No screenshot was available. Rely on KBS priors only; set hasError=true.";

  return `You are a brand-protection analyst. Classify the target website.

The screenshot (when present) is primary visual evidence. KBS tags below are structured priors / hypotheses from an automated rules engine — NOT ground truth.

Instructions:
- Read each KBS signal name, strength, and evidence carefully.
- Note classifiedAs and scores — treat them as suggestions you may accept or reject.
- You MAY disagree with KBS. If tags are incomplete, misleading, or wrong given the screenshot/evidence, revise riskCategory and briefly say what you overrode and why in summary.
- Do not invent KBS signal names that were not provided; you may still conclude a different riskCategory than KBS promoted.
- Prefer the most specific abuse type when multiple apply (e.g. credential harvest → Phishing over generic Scam).
- Friendly non-infringing sites → Other_Site; for-sale/parked → Parking_Site; social profile redirects → Social_Profile_Redirection.
- When screenshot and KBS conflict, trust the screenshot for visual content (brand UI, forms, adult/gambling, parking) and use KBS mainly for infra/structural cues (TLS, WHOIS, dead links).
- HTTP deny (451/403/410) or DNS sinkhole → Access_Denied; content cannot be judged.
- Return ONLY a single JSON object (no markdown fences) with exactly these keys:
  {
    "riskLevel": "Low" | "Medium" | "High",
    "websiteTone": string slug (e.g. phishing, scam, ecommerce, corporate, parking, gambling, adult, other),
    "riskCategory": one allowed value below,
    "summary": readable bullet-style string,
    "hasError": boolean,
    "confidenceScore": number 0-100
  }

Target website: ${url || "(unknown)"}
Brand hint: ${userInput || "(none)"}
${screenshotNote}

${formatKbsForPrompt(kbsResult)}

Allowed riskCategory values:
${catalog}
`;
}

/**
 * @param {string} raw
 * @returns {unknown}
 */
export function parseLlmJson(raw) {
  if (typeof raw !== "string" || !raw.trim()) {
    throw new Error("Empty LLM response text");
  }
  let text = raw.trim();
  const fence = text.match(/```(?:json)?\s*([\s\S]*?)```/i);
  if (fence) {
    text = fence[1].trim();
  }
  const start = text.indexOf("{");
  const end = text.lastIndexOf("}");
  if (start === -1 || end === -1 || end <= start) {
    throw new Error("No JSON object found in LLM response");
  }
  return JSON.parse(text.slice(start, end + 1));
}

/**
 * @param {unknown} parsed
 * @param {{ forceHasError?: boolean }} [opts]
 * @returns {LlmAnalysis}
 */
export function normalizeLlmAnalysis(parsed, opts = {}) {
  if (!parsed || typeof parsed !== "object") {
    throw new Error("LLM JSON is not an object");
  }
  const obj = /** @type {Record<string, unknown>} */ (parsed);

  let riskLevel = String(obj.riskLevel ?? "Medium");
  riskLevel = riskLevel.charAt(0).toUpperCase() + riskLevel.slice(1).toLowerCase();
  if (!RISK_LEVELS.has(riskLevel)) {
    riskLevel = "Medium";
  }

  const websiteTone =
    typeof obj.websiteTone === "string" && obj.websiteTone.trim()
      ? obj.websiteTone.trim().toLowerCase().replace(/\s+/g, "_")
      : "other";

  const riskCategory = normalizeAbuseType(obj.riskCategory);

  const summary =
    typeof obj.summary === "string" && obj.summary.trim()
      ? obj.summary.trim()
      : "No summary provided by model.";

  let confidenceScore = Number(obj.confidenceScore);
  if (!Number.isFinite(confidenceScore)) confidenceScore = 50;
  confidenceScore = Math.max(0, Math.min(100, Math.round(confidenceScore)));

  const hasError = Boolean(obj.hasError) || Boolean(opts.forceHasError);

  return {
    riskLevel: /** @type {"Low"|"Medium"|"High"} */ (riskLevel),
    websiteTone,
    riskCategory,
    summary,
    hasError,
    confidenceScore,
  };
}

/**
 * Extract assistant text from Ark Responses API payload.
 * @param {unknown} payload
 * @returns {string}
 */
export function extractResponseText(payload) {
  if (!payload || typeof payload !== "object") return "";
  const body = /** @type {Record<string, unknown>} */ (payload);

  if (typeof body.output_text === "string" && body.output_text.trim()) {
    return body.output_text;
  }

  const output = body.output;
  if (Array.isArray(output)) {
    const chunks = [];
    for (const item of output) {
      if (!item || typeof item !== "object") continue;
      const content = /** @type {Record<string, unknown>} */ (item).content;
      if (!Array.isArray(content)) continue;
      for (const part of content) {
        if (!part || typeof part !== "object") continue;
        const p = /** @type {Record<string, unknown>} */ (part);
        if (
          (p.type === "output_text" || p.type === "text") &&
          typeof p.text === "string"
        ) {
          chunks.push(p.text);
        }
      }
    }
    if (chunks.length) return chunks.join("\n");
  }

  return "";
}

/**
 * @returns {string}
 */
function resolveApiKey() {
  return (
    process.env.ARK_API_KEY ||
    process.env.EMBEDDING_MODEL_API_KEY ||
    EMBEDDING_MODEL_API_KEY ||
    ""
  );
}

/**
 * Run vision LLM classification with KBS context and optional screenshot.
 *
 * @param {LlmAnalyzerContext} context
 * @returns {Promise<LlmAnalyzerResult>}
 */
export async function runLlmAnalyzer(context) {
  const apiKey = resolveApiKey();
  if (!apiKey) {
    return { llmAnalysis: null, error: "Missing ARK_API_KEY" };
  }

  const screenshotPath =
    context.screenshotPath ||
    (typeof context.scanData?.screenshotPath === "string"
      ? context.scanData.screenshotPath
      : null);

  const { dataUrl, error: shotError } = await toDataUrl(screenshotPath);
  const screenshotAttached = Boolean(dataUrl);

  const prompt = buildClassificationPrompt({
    url: context.url ?? "",
    userInput: context.userInput ?? "",
    kbsResult: context.kbsResult,
    screenshotAttached,
  });

  /** @type {Array<{ type: string, text?: string, image_url?: string }>} */
  const content = [];
  if (dataUrl) {
    content.push({ type: "input_image", image_url: dataUrl });
  }
  content.push({ type: "input_text", text: prompt });

  let payload;
  try {
    const res = await fetch(ARK_RESPONSES_URL, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${apiKey}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        model: LLM_MODEL,
        stream: false,
        thinking: { type: "disabled" },
        input: [{ role: "user", content }],
      }),
    });

    const rawBody = await res.text();
    if (!res.ok) {
      return {
        llmAnalysis: null,
        error: `Ark API ${res.status}: ${rawBody.slice(0, 500)}`,
      };
    }
    payload = JSON.parse(rawBody);
  } catch (err) {
    return {
      llmAnalysis: null,
      error: err instanceof Error ? err.message : String(err),
    };
  }

  try {
    const text = extractResponseText(payload);
    const parsed = parseLlmJson(text);
    const llmAnalysis = normalizeLlmAnalysis(parsed, {
      forceHasError: !screenshotAttached || Boolean(shotError),
    });
    return { llmAnalysis };
  } catch (err) {
    return {
      llmAnalysis: null,
      error: err instanceof Error ? err.message : String(err),
    };
  }
}
