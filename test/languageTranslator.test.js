import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  extractHtmlLang,
  resolveSourceLanguage,
  pack,
  unpack,
  batchTexts,
  safePiece,
  flattenTexts,
  rebuildAnalysis,
  ensureEnglishHtmlAnalysis,
  buildTranslateBody,
  MODEL_ID,
} from "../src/analysis/translate/languageTranslator.js";

describe("resolveSourceLanguage", () => {
  it("skips English variants", () => {
    assert.equal(resolveSourceLanguage("en"), null);
    assert.equal(resolveSourceLanguage("en-US"), null);
    assert.equal(resolveSourceLanguage("EN-gb"), null);
  });

  it("maps French and other supported primaries", () => {
    assert.equal(resolveSourceLanguage("fr"), "fr");
    assert.equal(resolveSourceLanguage("fr-FR"), "fr");
    assert.equal(resolveSourceLanguage("de"), "de");
    assert.equal(resolveSourceLanguage("ja"), "ja");
  });

  it("maps Traditional Chinese variants to zh-Hant", () => {
    assert.equal(resolveSourceLanguage("zh-TW"), "zh-Hant");
    assert.equal(resolveSourceLanguage("zh-HK"), "zh-Hant");
    assert.equal(resolveSourceLanguage("zh-hant"), "zh-Hant");
    assert.equal(resolveSourceLanguage("zh-Hant-TW"), "zh-Hant");
  });

  it("maps Simplified Chinese to zh", () => {
    assert.equal(resolveSourceLanguage("zh"), "zh");
    assert.equal(resolveSourceLanguage("zh-CN"), "zh");
  });

  it("returns null for missing or unsupported", () => {
    assert.equal(resolveSourceLanguage(""), null);
    assert.equal(resolveSourceLanguage("xx"), null);
    assert.equal(resolveSourceLanguage("tlh"), null);
  });
});

describe("extractHtmlLang", () => {
  it("reads html lang attribute", () => {
    assert.equal(extractHtmlLang('<html lang="fr">'), "fr");
    assert.equal(extractHtmlLang('<HTML LANG="en-US">'), "en-us");
  });

  it("falls back to content-language meta", () => {
    const html =
      '<html><meta http-equiv="content-language" content="de"></html>';
    assert.equal(extractHtmlLang(html), "de");
  });
});

describe("pack / unpack", () => {
  it("round-trips a multi-item pack", () => {
    const batch = ["Accueil", "Réparation", "Contact"];
    const packed = pack(batch);
    assert.match(packed, /^\[\[0\]\]Accueil\[\[1\]\]/);
    const parts = unpack(packed, batch.length);
    assert.deepEqual(parts, batch);
  });

  it("handles single-item unpack with optional [[0]] prefix", () => {
    assert.deepEqual(unpack("Hello world", 1), ["Hello world"]);
    assert.deepEqual(unpack("[[0]]Hello world", 1), ["Hello world"]);
  });

  it("returns null when a marker is missing", () => {
    assert.equal(unpack("[[0]]a[[2]]c", 3), null);
    assert.equal(unpack("no markers here", 2), null);
  });

  it("safePiece neutralizes embedded markers", () => {
    assert.equal(safePiece("see [[0]] later"), "see [[ 0 ]] later");
  });
});

describe("batchTexts", () => {
  it("packs short strings together", () => {
    const shorts = ["a", "b", "c", "d"];
    const batches = batchTexts(shorts);
    assert.equal(batches.length, 1);
    assert.deepEqual(batches[0], shorts);
  });

  it("puts long strings in solo packs", () => {
    const long = "x".repeat(100);
    const batches = batchTexts(["hi", long, "yo"]);
    assert.ok(batches.length >= 2);
    assert.ok(batches.some((b) => b.length === 1 && b[0] === long));
  });
});

describe("buildTranslateBody", () => {
  it("sets source_language from html lang mapping and target en", () => {
    const body = buildTranslateBody("Bonjour", "fr");
    assert.equal(body.model, MODEL_ID);
    const opts = body.input[0].content[0].translation_options;
    assert.equal(opts.source_language, "fr");
    assert.equal(opts.target_language, "en");
  });
});

describe("flattenTexts / rebuildAnalysis", () => {
  it("preserves length and order", () => {
    const analysis = {
      visibleText: ["A", "B"],
      textZones: {
        titleText: "Title",
        headingText: ["H1", "H2"],
      },
    };
    const { texts, plan } = flattenTexts(analysis);
    assert.equal(texts.length, plan.length);
    assert.deepEqual(texts.slice(0, 2), ["A", "B"]);

    const translated = texts.map((t) => `EN:${t}`);
    const next = rebuildAnalysis(analysis, translated, plan);
    assert.deepEqual(next.visibleText, ["EN:A", "EN:B"]);
    assert.equal(next.textZones.titleText, "EN:Title");
    assert.deepEqual(next.textZones.headingText, ["EN:H1", "EN:H2"]);
  });
});

describe("ensureEnglishHtmlAnalysis skip paths", () => {
  it("skips English pages without calling the API", async () => {
    const analysis = {
      visibleText: ["Hello"],
      textZones: { titleText: "Hi" },
    };
    const { analysis: out, language } = await ensureEnglishHtmlAnalysis(
      analysis,
      '<html lang="en-US"><body>Hello</body></html>',
    );
    assert.equal(language.reason, "html_lang_en");
    assert.equal(language.translated, false);
    assert.equal(out.visibleText[0], "Hello");
  });

  it("skips unsupported languages", async () => {
    const analysis = { visibleText: ["x"], textZones: {} };
    const { language } = await ensureEnglishHtmlAnalysis(
      analysis,
      '<html lang="xx"><body>x</body></html>',
    );
    assert.equal(language.reason, "unsupported_lang");
    assert.equal(language.translated, false);
  });

  it("skips when there is no text", async () => {
    const { language } = await ensureEnglishHtmlAnalysis(
      { visibleText: [], textZones: {} },
      '<html lang="fr"></html>',
    );
    assert.equal(language.reason, "non_en_no_text");
  });
});
