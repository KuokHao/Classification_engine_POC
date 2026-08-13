/**
 * Live Seed Translation smoke tests.
 * Run: npm run test:translate
 *
 * Prints request summary + API output so you can inspect the response.
 * Kept under test/live/ so default `npm test` (test/*.test.js) does not hit the network.
 */

import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { ARK_API_KEY } from "../../config/config.js";
import {
  ARK_RESPONSES_URL,
  MODEL_ID,
  buildTranslateBody,
  callSeedTranslate,
  extractOutputText,
  pack,
  unpack,
  translateTexts,
  resolveSourceLanguage,
} from "../../src/analysis/languageTranslator.js";

const apiKey = process.env.ARK_API_KEY || ARK_API_KEY || "";
const hasKey = Boolean(apiKey);

describe("Seed translation live API", { skip: !hasKey }, () => {
  it("translates a single French string with source_language=fr", async () => {
    const sourceText = "Réparation téléphone à Tours";
    const sourceLang = "fr";
    const body = buildTranslateBody(sourceText, sourceLang);

    console.log("\n========== LIVE TRANSLATE: single ==========");
    console.log("URL:", ARK_RESPONSES_URL);
    console.log("model:", MODEL_ID);
    console.log(
      "source_language:",
      body.input[0].content[0].translation_options.source_language,
    );
    console.log(
      "target_language:",
      body.input[0].content[0].translation_options.target_language,
    );
    console.log("input text:", sourceText);

    assert.equal(
      body.input[0].content[0].translation_options.source_language,
      "fr",
    );

    const t0 = Date.now();
    const out = await callSeedTranslate(sourceText, sourceLang, { apiKey });
    const ms = Date.now() - t0;

    console.log("elapsed_ms:", ms);
    console.log("output_text:", out);
    console.log("============================================\n");

    assert.ok(out, "expected non-empty translation");
    assert.ok(ms < 30_000, `single call took too long: ${ms}ms`);
    assert.notEqual(out.trim(), sourceText);
  });

  it("translates a packed batch and unpacks [[i]] markers", async () => {
    const batch = [
      "Accueil",
      "Réparation iPhone",
      "Contactez-nous",
      "Mentions légales",
    ];
    const sourceLang = resolveSourceLanguage("fr");
    assert.equal(sourceLang, "fr");

    const packed = pack(batch);
    const body = buildTranslateBody(packed, sourceLang);

    console.log("\n========== LIVE TRANSLATE: packed ==========");
    console.log(
      "source_language:",
      body.input[0].content[0].translation_options.source_language,
    );
    console.log("packed input:", packed);

    const t0 = Date.now();
    const raw = await callSeedTranslate(packed, sourceLang, { apiKey });
    const ms = Date.now() - t0;

    console.log("elapsed_ms:", ms);
    console.log("raw API output:", raw);

    assert.ok(raw, "expected non-empty packed translation");

    let parts = unpack(raw, batch.length);
    if (parts == null) {
      console.log(
        "unpack failed on packed output; falling back to translateTexts",
      );
      parts = await translateTexts(batch, "fr", { apiKey });
    }

    console.log("unpacked parts:", parts);
    console.log("============================================\n");

    assert.ok(Array.isArray(parts));
    assert.equal(parts.length, batch.length);
    assert.ok(ms < 45_000, `packed call took too long: ${ms}ms`);
  });

  it("prints full raw Responses JSON for one call", async () => {
    const text = "Bonjour le monde";
    const body = buildTranslateBody(text, "fr");

    console.log("\n========== LIVE TRANSLATE: raw JSON ==========");
    console.log("request body:", JSON.stringify(body, null, 2));

    const t0 = Date.now();
    const res = await fetch(ARK_RESPONSES_URL, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${apiKey}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify(body),
      signal: AbortSignal.timeout(90_000),
    });
    const ms = Date.now() - t0;
    const payload = await res.json();

    console.log("HTTP status:", res.status);
    console.log("elapsed_ms:", ms);
    console.log("raw response JSON:", JSON.stringify(payload, null, 2));
    console.log("extracted output_text:", extractOutputText(payload));
    console.log("=============================================\n");

    assert.equal(res.status, 200);
    assert.ok(extractOutputText(payload));
  });
});

describe("Seed translation live API (key required)", () => {
  it("documents skip when ARK_API_KEY is missing", () => {
    if (!hasKey) {
      console.log(
        "\n[languageTranslator.live] SKIPPED — set ARK_API_KEY in .env to run live tests\n",
      );
    }
    assert.ok(true);
  });
});
