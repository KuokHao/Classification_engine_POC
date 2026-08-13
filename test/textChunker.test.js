import test from "node:test";
import assert from "node:assert/strict";

import { analyzeHtml } from "../src/analysis/htmlAnalyzer.js";
import {
  chunkHtmlAnalysis,
  slidingWindowChunker,
  smartTextChunker,
} from "../src/analysis/textChunker.js";

const PHISHING_ZONES = {
  textZones: {
    titleText: "Critical security alert",
    headingText: ["Action required"],
    paragraphText: [
      "Critical security alert Action required claim cash now please verify your identity immediately",
    ],
    buttonText: ["Claim cash now"],
    linkText: ["  Verify   account  "],
    iframeText: [],
    labelText: [],
    placeholderText: ["Email address"],
    footerText: ["Copyright 2024"],
    imageAltText: ["Bank logo"],
    formNearbyText: ["Sign in to continue"],
  },
};

// ---------------------------------------------------------------------------
// Sliding window
// ---------------------------------------------------------------------------

test("slidingWindowChunker — short text stays one chunk", () => {
  assert.deepEqual(
    slidingWindowChunker("Critical security alert Action required claim cash now"),
    ["Critical security alert Action required claim cash now"],
  );
});

test("slidingWindowChunker — 8-word window / 4-word step", () => {
  const text =
    "Critical security alert Action required claim cash now please verify your identity immediately";
  assert.deepEqual(slidingWindowChunker(text), [
    "Critical security alert Action required claim cash now",
    "required claim cash now please verify your identity",
    "please verify your identity immediately",
  ]);
});

test("slidingWindowChunker — collapses whitespace", () => {
  assert.deepEqual(slidingWindowChunker("  hello\n\tworld   foo  "), [
    "hello world foo",
  ]);
});

test("slidingWindowChunker — empty / invalid input", () => {
  assert.deepEqual(slidingWindowChunker(""), []);
  assert.deepEqual(slidingWindowChunker("   "), []);
  assert.deepEqual(slidingWindowChunker("hello", 0, 4), []);
  assert.deepEqual(slidingWindowChunker("hello", 8, 0), []);
});

// ---------------------------------------------------------------------------
// Zone split + pipeline helper
// ---------------------------------------------------------------------------

test("smartTextChunker — never merges heading with paragraph", () => {
  const chunks = smartTextChunker({
    textZones: {
      headingText: ["Action required"],
      paragraphText: ["Please verify your identity immediately to avoid closure"],
    },
  });
  assert.deepEqual(
    chunks.map((c) => c.metadata.zone),
    ["heading", "paragraph"],
  );
  assert.equal(chunks[0].text, "Action required");
  assert.ok(!chunks[0].text.includes("verify"));
});

test("smartTextChunker — preserves ZONE_ORDER (iframe before heading)", () => {
  const chunks = smartTextChunker({
    textZones: {
      headingText: ["Page heading"],
      iframeText: ["Iframe body copy"],
      titleText: "Page title",
    },
  });
  assert.deepEqual(
    chunks.map((c) => c.text),
    ["Page title", "Iframe body copy", "Page heading"],
  );
});

test("smartTextChunker — empty zones fall through to visibleText", () => {
  const chunks = smartTextChunker({
    textZones: { headingText: [], paragraphText: [] },
    visibleText: ["Fallback block one", "Fallback block two"],
  });
  assert.deepEqual(
    chunks.map((c) => c.metadata.zone),
    ["visibleText", "visibleText"],
  );
  assert.deepEqual(
    chunks.map((c) => c.text),
    ["Fallback block one", "Fallback block two"],
  );
});

test("smartTextChunker — last window may be shorter than 8", () => {
  const chunks = smartTextChunker({
    textZones: {
      paragraphText: ["one two three four five six seven eight nine ten eleven"],
    },
  });
  assert.deepEqual(
    chunks.map((c) => c.text),
    [
      "one two three four five six seven eight",
      "five six seven eight nine ten eleven",
    ],
  );
});

test("chunkHtmlAnalysis — matches smartTextChunker on analyzer-shaped payload", () => {
  const analysis = {
    visibleText: ["ignored when zones exist"],
    textZones: PHISHING_ZONES.textZones,
  };
  assert.deepEqual(chunkHtmlAnalysis(analysis), smartTextChunker(analysis));
});

test("chunkHtmlAnalysis — chunks real analyzeHtml zones in reading order", () => {
  const doc = analyzeHtml(`<html><head><title>Acme Login</title></head><body>
    <h1>Welcome back</h1>
    <p>Critical security alert Action required claim cash now please verify your identity immediately</p>
    <button>Sign in</button>
    <a href="/help">Need help with your account</a>
    <label>Email</label>
    <input placeholder="Enter email">
    <footer>Copyright 2024 Acme Bank</footer>
    <img alt="Acme Bank logo">
    <form><p>Sign in to continue</p></form>
    <section data-captured-iframe="true">Renew Your Domain Name Now</section>
  </body></html>`);

  const chunks = chunkHtmlAnalysis(doc);
  const zones = chunks.map((c) => c.metadata.zone);

  assert.ok(zones.includes("title"));
  assert.ok(zones.indexOf("iframe") < zones.indexOf("heading"));
  assert.ok(zones.indexOf("heading") < zones.indexOf("paragraph"));
  assert.ok(
    chunks.some((c) => c.text.includes("Critical security alert")),
    "long paragraph should be windowed, not dropped",
  );
  assert.ok(chunks.every((c) => c.text.trim()));
});
