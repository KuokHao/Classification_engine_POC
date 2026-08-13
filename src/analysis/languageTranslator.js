/**
 * Translate webpage visible text → English via ByteDance-Seed-Translation
 * (seed-translation-250915) on the Ark Responses API.
 *
 * Speed strategy:
 *   1) Pack short strings with numbered [[i]] markers (few API calls).
 *   2) Run packs in parallel (bounded concurrency).
 *   3) On unpack/API failure: fan-out that pack to concurrent per-string calls.
 *
 * Preserves list length and order for downstream chunking (chunker.py).
 */

import { ARK_API_KEY } from "../../config/config.js";

export const ARK_RESPONSES_URL =
  "https://ark.ap-southeast.bytepluses.com/api/v3/responses";
export const MODEL_ID = "seed-translation-250915";

const MAX_PACK_CHARS = 900;
const MAX_PACK_ITEMS = 8;
const MAX_SLICE_CHARS = 900;
const MAX_PACKABLE_LEN = 80;

const MAX_RETRIES = 3;
const MAX_WORKERS = 10;
const FANOUT_WORKERS = 8;

const TAG_RE = /\[\[(\d+)\]\]/g;
const TAG_IN_TEXT_RE = /\[\[(\d+)\]\]/g;

const SUPPORTED_LANGS = new Set([
  "zh",
  "zh-Hant",
  "en",
  "ja",
  "ko",
  "de",
  "fr",
  "es",
  "it",
  "pt",
  "ru",
  "th",
  "vi",
  "ar",
  "cs",
  "da",
  "fi",
  "hr",
  "hu",
  "id",
  "ms",
  "nb",
  "nl",
  "pl",
  "ro",
  "sv",
]);

// ---------------------------------------------------------------------------
// Lang
// ---------------------------------------------------------------------------

/**
 * Read document language from raw HTML (<html lang> / content-language meta).
 * @param {string} rawHtml
 * @returns {string}
 */
export function extractHtmlLang(rawHtml) {
  const html = String(rawHtml ?? "");
  const langAttr =
    html.match(/<html\b[^>]*\blang\s*=\s*["']?\s*([a-zA-Z-]+)/i)?.[1] ||
    html.match(/\bxml:lang\s*=\s*["']?\s*([a-zA-Z-]+)/i)?.[1] ||
    "";
  if (langAttr) return langAttr.toLowerCase().trim();

  const metaLang =
    html.match(
      /<meta\b[^>]*http-equiv\s*=\s*["']?content-language["']?[^>]*content\s*=\s*["']?\s*([a-zA-Z-]+)/i,
    )?.[1] ||
    html.match(
      /<meta\b[^>]*content\s*=\s*["']?\s*([a-zA-Z-]+)["']?[^>]*http-equiv\s*=\s*["']?content-language/i,
    )?.[1] ||
    "";
  return metaLang ? metaLang.toLowerCase().trim() : "";
}

/**
 * Map html lang → Seed source_language, or null to skip translate.
 * @param {string} htmlLang
 * @returns {string|null}
 */
export function resolveSourceLanguage(htmlLang) {
  const raw = String(htmlLang || "").trim();
  if (!raw) return null;

  const lower = raw.toLowerCase();
  if (
    lower === "zh-hant" ||
    lower === "zh-tw" ||
    lower === "zh-hk" ||
    lower === "zh-mo" ||
    lower.startsWith("zh-hant")
  ) {
    return "zh-Hant";
  }

  const primary = lower.split("-")[0];
  if (primary === "en") return null;
  if (primary === "zh") return "zh";
  if (SUPPORTED_LANGS.has(primary)) return primary;
  return null;
}

// ---------------------------------------------------------------------------
// Flatten / rebuild (pipeline shape for chunker)
// ---------------------------------------------------------------------------

/**
 * Flatten body/analysis/visible + textZones strings into an ordered list + rebuild plan.
 * @param {object} analysis
 * @returns {{ texts: string[], plan: Array<{ kind: string, key?: string, index?: number }> }}
 */
export function flattenTexts(analysis) {
  /** @type {string[]} */
  const texts = [];
  /** @type {Array<{ kind: string, key?: string, index?: number }>} */
  const plan = [];

  if (typeof analysis?.bodyText === "string" && analysis.bodyText.trim()) {
    texts.push(analysis.bodyText);
    plan.push({ kind: "bodyText" });
  }
  if (typeof analysis?.analysisText === "string" && analysis.analysisText.trim()) {
    texts.push(analysis.analysisText);
    plan.push({ kind: "analysisText" });
  }
  if (
    typeof analysis?.renderedText === "string" &&
    analysis.renderedText.trim()
  ) {
    texts.push(analysis.renderedText);
    plan.push({ kind: "renderedText" });
  }

  const vt = analysis?.visibleText;
  if (Array.isArray(vt)) {
    for (let i = 0; i < vt.length; i++) {
      texts.push(String(vt[i] ?? ""));
      plan.push({ kind: "visibleText", index: i });
    }
  } else if (typeof vt === "string") {
    texts.push(vt);
    plan.push({ kind: "visibleText" });
  }

  const zones = analysis?.textZones;
  if (zones && typeof zones === "object") {
    for (const [key, value] of Object.entries(zones)) {
      if (typeof value === "string") {
        texts.push(value);
        plan.push({ kind: "zone", key });
      } else if (Array.isArray(value)) {
        for (let i = 0; i < value.length; i++) {
          if (typeof value[i] === "string") {
            texts.push(value[i]);
            plan.push({ kind: "zone", key, index: i });
          }
        }
      }
    }
  }

  return { texts, plan };
}

/**
 * Apply translated strings back onto a shallow-cloned analysis.
 * @param {object} analysis
 * @param {string[]} translated
 * @param {Array<{ kind: string, key?: string, index?: number }>} plan
 */
export function rebuildAnalysis(analysis, translated, plan) {
  const out = {
    ...analysis,
    visibleText: Array.isArray(analysis.visibleText)
      ? [...analysis.visibleText]
      : analysis.visibleText,
    textZones:
      analysis.textZones && typeof analysis.textZones === "object"
        ? { ...analysis.textZones }
        : analysis.textZones,
  };

  if (out.textZones) {
    for (const [key, value] of Object.entries(out.textZones)) {
      if (Array.isArray(value)) out.textZones[key] = [...value];
    }
  }

  for (let i = 0; i < plan.length; i++) {
    const slot = plan[i];
    const text = translated[i] ?? "";
    if (slot.kind === "bodyText") {
      out.bodyText = text;
    } else if (slot.kind === "analysisText") {
      out.analysisText = text;
    } else if (slot.kind === "renderedText") {
      out.renderedText = text;
    } else if (slot.kind === "visibleText") {
      if (Array.isArray(out.visibleText) && slot.index != null) {
        out.visibleText[slot.index] = text;
      } else {
        out.visibleText = text;
      }
    } else if (slot.kind === "zone" && out.textZones && slot.key) {
      if (slot.index != null && Array.isArray(out.textZones[slot.key])) {
        out.textZones[slot.key][slot.index] = text;
      } else {
        out.textZones[slot.key] = text;
      }
    }
  }

  return out;
}

// ---------------------------------------------------------------------------
// Packing
// ---------------------------------------------------------------------------

/** Neutralize [[n]] markers if they appear in source text. */
export function safePiece(s) {
  return String(s ?? "").replace(TAG_IN_TEXT_RE, "[[ $1 ]]");
}

/**
 * @param {string[]} batch
 * @returns {string}
 */
export function pack(batch) {
  return batch.map((t, i) => `[[${i}]]${t}`).join("");
}

/**
 * Recover n items by [[i]] markers. null if any index missing.
 * @param {string} translated
 * @param {number} n
 * @returns {string[]|null}
 */
export function unpack(translated, n) {
  if (n === 1) {
    let t = String(translated ?? "").trim();
    if (t.startsWith("[[0]]")) t = t.slice(5);
    return [t.trim()];
  }

  const matches = [...String(translated ?? "").matchAll(TAG_RE)];
  if (matches.length === 0) return null;

  /** @type {Map<number, string>} */
  const found = new Map();
  for (let j = 0; j < matches.length; j++) {
    const m = matches[j];
    const idx = Number(m[1]);
    const start = (m.index ?? 0) + m[0].length;
    const end =
      j + 1 < matches.length
        ? (matches[j + 1].index ?? translated.length)
        : translated.length;
    found.set(idx, translated.slice(start, end).trim());
  }

  for (let i = 0; i < n; i++) {
    if (!found.has(i)) return null;
  }
  return Array.from({ length: n }, (_, i) => found.get(i) ?? "");
}

/**
 * Pack short strings together; long strings are solo packs.
 * @param {string[]} texts
 * @returns {string[][]}
 */
export function batchTexts(texts) {
  /** @type {string[][]} */
  const batches = [];
  /** @type {string[]} */
  let current = [];
  let size = 0;

  const flush = () => {
    if (current.length) {
      batches.push(current);
      current = [];
      size = 0;
    }
  };

  for (const raw of texts) {
    const s = safePiece(raw);

    if (s.length > MAX_SLICE_CHARS) {
      flush();
      for (let i = 0; i < s.length; i += MAX_SLICE_CHARS) {
        batches.push([s.slice(i, i + MAX_SLICE_CHARS)]);
      }
      continue;
    }

    if (s.length > MAX_PACKABLE_LEN) {
      flush();
      batches.push([s]);
      continue;
    }

    const add = s.length + 6;
    if (
      current.length &&
      (current.length >= MAX_PACK_ITEMS || size + add > MAX_PACK_CHARS)
    ) {
      flush();
    }
    current.push(s);
    size += add;
  }

  flush();
  return batches;
}

// ---------------------------------------------------------------------------
// HTTP / Seed API
// ---------------------------------------------------------------------------

/**
 * Extract output text from Ark Responses payload.
 * @param {object} payload
 * @returns {string}
 */
export function extractOutputText(payload) {
  if (typeof payload?.output_text === "string" && payload.output_text.trim()) {
    return payload.output_text.trim();
  }

  /** @type {string[]} */
  const chunks = [];
  for (const item of payload?.output ?? []) {
    if (!item || typeof item !== "object") continue;
    for (const part of item.content ?? []) {
      if (!part || typeof part !== "object") continue;
      if (
        (part.type === "output_text" || part.type === "text") &&
        typeof part.text === "string"
      ) {
        chunks.push(part.text);
      }
    }
  }
  return chunks.join("\n").trim();
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function getApiKey() {
  return process.env.ARK_API_KEY || ARK_API_KEY || "";
}

/**
 * Build Seed Responses request body for translation.
 * @param {string} text
 * @param {string} sourceLang
 */
export function buildTranslateBody(text, sourceLang) {
  return {
    model: MODEL_ID,
    input: [
      {
        role: "user",
        content: [
          {
            type: "input_text",
            text,
            translation_options: {
              source_language: sourceLang,
              target_language: "en",
            },
          },
        ],
      },
    ],
  };
}

/**
 * One Seed call; retries 429/5xx. Returns null on hard failure.
 * @param {string} text
 * @param {string} sourceLang
 * @param {{ apiKey?: string }} [opts]
 * @returns {Promise<string|null>}
 */
export async function callSeedTranslate(text, sourceLang, opts = {}) {
  if (!String(text ?? "").trim()) return text;

  const apiKey = opts.apiKey ?? getApiKey();
  if (!apiKey) {
    console.warn("[languageTranslator] missing ARK_API_KEY");
    return null;
  }

  const body = buildTranslateBody(text, sourceLang);

  for (let attempt = 1; attempt <= MAX_RETRIES; attempt++) {
    try {
      const res = await fetch(ARK_RESPONSES_URL, {
        method: "POST",
        headers: {
          Authorization: `Bearer ${apiKey}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify(body),
        signal: AbortSignal.timeout(90_000),
      });

      if (res.status === 429 || res.status >= 500) {
        const detail = (await res.text().catch(() => "")).slice(0, 300);
        console.warn(
          `[languageTranslator] retryable HTTP ${res.status} (attempt ${attempt}/${MAX_RETRIES}): ${detail}`,
        );
        await sleep(Math.min(2 ** (attempt - 1) * 1000, 4000));
        continue;
      }

      if (!res.ok) {
        const detail = (await res.text().catch(() => "")).slice(0, 300);
        console.warn(`[languageTranslator] hard HTTP ${res.status}: ${detail}`);
        return null;
      }

      const payload = await res.json();
      const out = extractOutputText(payload);
      if (out) return out;
      console.warn(
        `[languageTranslator] empty translation response (attempt ${attempt}/${MAX_RETRIES})`,
      );
    } catch (err) {
      console.warn(
        `[languageTranslator] request failed (attempt ${attempt}/${MAX_RETRIES}):`,
        err?.message ?? err,
      );
      await sleep(Math.min(2 ** (attempt - 1) * 1000, 4000));
    }
  }

  return null;
}

/**
 * Run async tasks with a concurrency limit.
 * @template T
 * @param {Array<() => Promise<T>>} tasks
 * @param {number} limit
 * @returns {Promise<T[]>}
 */
async function mapPool(tasks, limit) {
  /** @type {T[]} */
  const results = new Array(tasks.length);
  let next = 0;

  async function worker() {
    while (next < tasks.length) {
      const i = next++;
      results[i] = await tasks[i]();
    }
  }

  const n = Math.min(limit, Math.max(1, tasks.length));
  await Promise.all(Array.from({ length: n }, () => worker()));
  return results;
}

/**
 * Translate each string concurrently (used when a pack fails).
 * @param {string[]} batch
 * @param {string} sourceLang
 * @param {{ apiKey?: string, packIndex?: number }} [opts]
 */
async function fanoutSingles(batch, sourceLang, opts = {}) {
  if (batch.length === 1) {
    const r = await callSeedTranslate(batch[0], sourceLang, opts);
    return [r != null ? r : batch[0]];
  }

  const packLabel =
    opts.packIndex != null ? `pack ${opts.packIndex + 1}` : "pack";
  console.log(
    `[languageTranslator] ${packLabel} fan-out singles (size=${batch.length})`,
  );

  const out = await mapPool(
    batch.map(
      (s, i) => async () => {
        const r = await callSeedTranslate(s, sourceLang, opts);
        return r != null ? r : batch[i];
      },
    ),
    Math.min(FANOUT_WORKERS, batch.length),
  );
  return out;
}

/**
 * Translate one pack; fan-out to concurrent singles on failure.
 * @param {string[]} batch
 * @param {string} sourceLang
 * @param {{ apiKey?: string, packIndex?: number, totalPacks?: number }} [opts]
 */
async function translatePack(batch, sourceLang, opts = {}) {
  if (!batch.length) return [];
  if (batch.every((s) => !String(s ?? "").trim())) return [...batch];

  const packIndex = opts.packIndex ?? 0;

  if (batch.length === 1) {
    const r = await callSeedTranslate(batch[0], sourceLang, opts);
    return [r != null ? r : batch[0]];
  }

  const packed = pack(batch);
  const out = await callSeedTranslate(packed, sourceLang, opts);
  if (out != null) {
    const parts = unpack(out, batch.length);
    if (parts != null) return parts;
    console.warn(
      `[languageTranslator] unpack failed for pack ${packIndex + 1} (size=${batch.length}); fan-out singles`,
    );
  } else {
    console.warn(
      `[languageTranslator] pack API failed for pack ${packIndex + 1} (size=${batch.length}); fan-out singles`,
    );
  }

  return fanoutSingles(batch, sourceLang, opts);
}

/**
 * Translate webpage strings to English. Same length/order as `texts`.
 * @param {string[]} texts
 * @param {string} htmlLang - raw html lang (mapped via resolveSourceLanguage)
 * @param {{ apiKey?: string }} [opts]
 * @returns {Promise<string[]>}
 */
export async function translateTexts(texts, htmlLang, opts = {}) {
  if (!texts.length) return [];

  const source = resolveSourceLanguage(htmlLang);
  if (source == null) return [...texts];

  const apiKey = opts.apiKey ?? getApiKey();
  if (!apiKey) {
    console.error("[languageTranslator] missing ARK_API_KEY; returning originals");
    return [...texts];
  }

  /** @type {string[]} */
  const pieces = [];
  /** @type {number[]} */
  const owners = [];
  for (let i = 0; i < texts.length; i++) {
    const s = safePiece(texts[i]);
    if (s.length <= MAX_SLICE_CHARS) {
      pieces.push(s);
      owners.push(i);
    } else {
      for (let j = 0; j < s.length; j += MAX_SLICE_CHARS) {
        pieces.push(s.slice(j, j + MAX_SLICE_CHARS));
        owners.push(i);
      }
    }
  }

  const packs = batchTexts(pieces);
  const flatN = packs.reduce((n, p) => n + p.length, 0);
  if (flatN !== pieces.length) {
    console.error("[languageTranslator] pack flatten mismatch; returning originals");
    return [...texts];
  }

  const workers = Math.min(MAX_WORKERS, Math.max(1, packs.length));
  console.log(
    `[languageTranslator] translating ${pieces.length} strings → ${packs.length} packs (source=${source}, workers=${workers})`,
  );

  const started = Date.now();
  let doneCount = 0;
  const logEvery = Math.max(1, Math.ceil(packs.length / 10));

  const packResults = await mapPool(
    packs.map(
      (batch, idx) => async () => {
        const result = await translatePack(batch, source, {
          apiKey,
          packIndex: idx,
          totalPacks: packs.length,
        });
        doneCount += 1;
        if (doneCount === packs.length || doneCount % logEvery === 0) {
          console.log(
            `[languageTranslator] pack ${doneCount}/${packs.length} done`,
          );
        }
        return result;
      },
    ),
    workers,
  );

  /** @type {string[]} */
  const translatedPieces = [];
  for (const packResult of packResults) {
    translatedPieces.push(...(packResult ?? []));
  }

  if (translatedPieces.length !== pieces.length) {
    console.error(
      `[languageTranslator] piece count mismatch (${translatedPieces.length} vs ${pieces.length}); returning originals`,
    );
    return [...texts];
  }

  /** @type {string[][]} */
  const buckets = texts.map(() => []);
  for (let i = 0; i < owners.length; i++) {
    buckets[owners[i]].push(translatedPieces[i]);
  }
  const joined = buckets.map((parts) => parts.join(""));

  const elapsed = ((Date.now() - started) / 1000).toFixed(1);
  const changed = joined.some((t, i) => t !== texts[i]);
  console.log(
    `[languageTranslator] done in ${elapsed}s (translated=${changed}, strings=${texts.length})`,
  );

  return joined;
}

// ---------------------------------------------------------------------------
// Pipeline entry
// ---------------------------------------------------------------------------

/**
 * Ensure htmlAnalysis text for chunking/semantic is English when html lang
 * is a supported non-English Seed language. Structural fields stay unchanged.
 *
 * @param {object} htmlAnalysis
 * @param {string} rawHtml
 * @returns {Promise<{ analysis: object, language: { detected: string, translated: boolean, reason: string } }>}
 */
export async function ensureEnglishHtmlAnalysis(htmlAnalysis, rawHtml) {
  const analysis = htmlAnalysis ?? {};
  const htmlLang = extractHtmlLang(rawHtml);
  const primary = (htmlLang.split("-")[0] || "").toLowerCase();
  const detected = htmlLang || primary || "unknown";

  if (primary === "en") {
    console.log(
      `[languageTranslator] skip (detected=${detected}, reason=html_lang_en)`,
    );
    return {
      analysis,
      language: { detected, translated: false, reason: "html_lang_en" },
    };
  }

  const source = resolveSourceLanguage(htmlLang);
  if (source == null) {
    console.log(
      `[languageTranslator] skip (detected=${detected || "unknown"}, reason=unsupported_lang)`,
    );
    return {
      analysis,
      language: {
        detected: detected || "unknown",
        translated: false,
        reason: "unsupported_lang",
      },
    };
  }

  const { texts, plan } = flattenTexts(analysis);
  if (texts.length === 0) {
    console.log(
      `[languageTranslator] skip translate, no text (detected=${detected})`,
    );
    return {
      analysis,
      language: { detected, translated: false, reason: "non_en_no_text" },
    };
  }

  try {
    const translated = await translateTexts(texts, htmlLang);
    const safe = translated.length === texts.length ? translated : texts;
    const didTranslate = safe.some((t, i) => t !== texts[i]);
    const next = rebuildAnalysis(analysis, safe, plan);

    return {
      analysis: next,
      language: {
        detected,
        translated: didTranslate,
        reason: didTranslate ? "seed_translate" : "translate_noop",
      },
    };
  } catch (err) {
    console.warn("[languageTranslator] soft-fail:", err?.message ?? err);
    return {
      analysis,
      language: {
        detected,
        translated: false,
        reason: "translate_error",
      },
    };
  }
}
