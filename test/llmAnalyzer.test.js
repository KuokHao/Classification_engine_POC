import { describe, it } from "node:test";
import assert from "node:assert/strict";
import path from "path";
import { fileURLToPath } from "url";
import {
  buildClassificationPrompt,
  formatKbsForPrompt,
  parseLlmJson,
  normalizeLlmAnalysis,
  extractResponseText,
  toDataUrl,
} from "../src/analysis/llm/llmAnalyzer.js";
import { ABUSE_TYPES, ABUSE_TYPE_DESCRIPTIONS } from "../src/shared/constants/abuse.constant.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

const fixtureKbs = {
  signals: [
    {
      name: "brand_name_present",
      group: "identity",
      strength: 1,
      evidence: ["Brand name detected in page text"],
    },
    {
      name: "excessive_dead_links",
      group: "structural",
      strength: 0.85,
      evidence: ["12/20 anchors broken (60%)"],
    },
  ],
  classificationScores: {
    Impersonation: 0.75,
    Fake_Shop: 0.35,
    Other_Site: 0.1,
  },
  classifiedAs: ["Impersonation"],
};

describe("llmAnalyzer helpers", () => {
  it("exports a description for every ABUSE_TYPE", () => {
    for (const t of ABUSE_TYPES) {
      assert.ok(
        ABUSE_TYPE_DESCRIPTIONS[t],
        `missing description for ${t}`,
      );
    }
  });

  it("formats KBS signals and scores for the prompt", () => {
    const text = formatKbsForPrompt(fixtureKbs);
    assert.match(text, /KBS classifiedAs: Impersonation/);
    assert.match(text, /brand_name_present/);
    assert.match(text, /excessive_dead_links/);
    assert.match(text, /Impersonation: 0\.750/);
  });

  it("builds a prompt that allows disagreeing with KBS", () => {
    const prompt = buildClassificationPrompt({
      url: "https://evil.example",
      userInput: "U Mobile",
      kbsResult: fixtureKbs,
      screenshotAttached: true,
    });
    assert.match(prompt, /MAY disagree with KBS/i);
    assert.match(prompt, /Allowed riskCategory values/);
    assert.match(prompt, /Phishing/);
    assert.match(prompt, /Official/);
    assert.doesNotMatch(prompt, /Access Denied/);
    assert.match(prompt, /screenshot is attached/i);
  });

  it("parses JSON from fenced or raw model output", () => {
    const raw = parseLlmJson(`\`\`\`json
{"riskLevel":"High","websiteTone":"phishing","riskCategory":"Phishing","summary":"- login form","hasError":false,"confidenceScore":88}
\`\`\``);
    const normalized = normalizeLlmAnalysis(raw);
    assert.equal(normalized.riskLevel, "High");
    assert.equal(normalized.riskCategory, "Phishing");
    assert.equal(normalized.confidenceScore, 88);
    assert.equal(normalized.hasError, false);
  });

  it("normalizes riskCategory aliases and clamps confidence", () => {
    const normalized = normalizeLlmAnalysis(
      {
        riskLevel: "high",
        websiteTone: "Fake Shop",
        riskCategory: "fake shop",
        summary: "hollow storefront",
        hasError: false,
        confidenceScore: 140,
      },
      { forceHasError: true },
    );
    assert.equal(normalized.riskLevel, "High");
    assert.equal(normalized.riskCategory, "Fake_Shop");
    assert.equal(normalized.websiteTone, "fake_shop");
    assert.equal(normalized.confidenceScore, 100);
    assert.equal(normalized.hasError, true);
  });

  it("extracts text from Ark-style output payload", () => {
    const text = extractResponseText({
      output: [
        {
          type: "message",
          content: [{ type: "output_text", text: '{"riskLevel":"Low"}' }],
        },
      ],
    });
    assert.equal(text, '{"riskLevel":"Low"}');
  });

  it("toDataUrl returns error when path missing", async () => {
    const { dataUrl, error } = await toDataUrl(null);
    assert.equal(dataUrl, null);
    assert.ok(error);
  });

  it("toDataUrl loads a local PNG when present", async () => {
    const pngPath = path.join(
      __dirname,
      "..",
      "temp",
      "u.com.my.png",
    );
    const { dataUrl, error } = await toDataUrl(pngPath);
    if (error) {
      assert.match(error, /ENOENT|no such file/i);
      return;
    }
    assert.ok(dataUrl?.startsWith("data:image/png;base64,"));
  });
});
