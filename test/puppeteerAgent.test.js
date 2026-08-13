import test from "node:test";
import assert from "node:assert/strict";

import { mergeFramesIntoHtml, classifyHttpsNavError } from "../src/collection/capture/puppeteerAgent.js";
import { analyzeHtml } from "../src/analysis/htmlAnalyzer.js";

// ---------------------------------------------------------------------------
// mergeFramesIntoHtml — must use the document </body>, not one inside <script>
// ---------------------------------------------------------------------------

test("mergeFramesIntoHtml — skips </body> buried in ad-script strings", () => {
  // Mirrors evergreenfarms: outer page has a JS string that embeds HTML with </body>
  const mainHtml = `<html><head></head><body>
<div id="shell"><iframe src="https://ads.example/safe.html"></iframe></div>
<script>
  var t = '<!DOCTYPE html><html><body onload="x()">SYNC</body></html>';
  e.write(t);
</script>
<a href="#">Do Not Sell</a>
</body></html>`;

  const frames = [
    {
      url: "https://ads.example/safe.html",
      html: `<html><body>
        <a href="https://www.register.com/my-account/login?promo=EPRenew">Renew Your Domain Name Now</a>
        <script>var noise = "</body>";</script>
      </body></html>`,
      text: "Renew Your Domain Name Now",
    },
  ];

  const merged = mergeFramesIntoHtml(mainHtml, frames);

  // Captured block must sit in the real document body, after the ad script.
  const captureAt = merged.indexOf("<!-- captured iframe content -->");
  const scriptCloseAt = merged.lastIndexOf("</script>");
  const realBodyCloseAt = merged.toLowerCase().lastIndexOf("</body>");

  assert.ok(captureAt > 0, "capture marker present");
  assert.ok(
    captureAt > scriptCloseAt,
    "capture must come after the outer ad <script>, not inside its string",
  );
  assert.ok(
    captureAt < realBodyCloseAt,
    "capture must come before the real document </body>",
  );
  assert.match(
    merged,
    /data-captured-iframe="true"[\s\S]*Renew Your Domain Name Now/,
  );
  // Script from iframe body should be stripped
  assert.doesNotMatch(merged, /var noise/);
});

test("mergeFramesIntoHtml — analyzer can read renew link after merge", () => {
  const mainHtml = `<html><body><p>outer</p></body></html>`;
  const frames = [
    {
      url: "https://netresultshub.com/safe.html",
      html: `<html><body>
        <a href="https://www.register.com/my-account/login?promo=EPRenew" target="_blank">Renew Your Domain Name Now</a>
      </body></html>`,
      text: "Renew Your Domain Name Now",
    },
  ];

  const merged = mergeFramesIntoHtml(mainHtml, frames);
  const analysis = analyzeHtml(merged);
  const hit = analysis.links.find((l) =>
    (l.href || "").includes("register.com/my-account/login"),
  );

  assert.ok(hit, "renew link should be extractable");
  assert.equal(hit.text, "Renew Your Domain Name Now");
  assert.ok(
    analysis.textZones.iframeText.some((t) =>
      t.includes("Renew Your Domain Name Now"),
    ),
  );
});

test("mergeFramesIntoHtml — no frames leaves HTML unchanged", () => {
  const mainHtml = `<html><body><p>hi</p></body></html>`;
  assert.equal(mergeFramesIntoHtml(mainHtml, []), mainHtml);
  assert.equal(
    mergeFramesIntoHtml(mainHtml, [{ url: "about:blank", html: "", text: "" }]),
    mainHtml,
  );
});

test("mergeFramesIntoHtml — appends when no </body> present", () => {
  const mainHtml = `<html><div>partial</div></html>`;
  const merged = mergeFramesIntoHtml(mainHtml, [
    { url: "https://x.test/", html: "<html><body><p>frame</p></body></html>", text: "frame" },
  ]);
  assert.match(merged, /data-captured-iframe="true"/);
  assert.match(merged, /<p>frame<\/p>/);
});

test("classifyHttpsNavError — cert vs connection vs other", () => {
  assert.equal(
    classifyHttpsNavError(
      new Error("net::ERR_CERT_AUTHORITY_INVALID at https://example"),
    ),
    "cert",
  );
  assert.equal(
    classifyHttpsNavError(new Error("net::ERR_CONNECTION_REFUSED")),
    "connection",
  );
  assert.equal(
    classifyHttpsNavError(new Error("net::ERR_CONNECTION_TIMED_OUT")),
    "connection",
  );
  assert.equal(
    classifyHttpsNavError(new Error("Navigation timeout of 60000 ms exceeded")),
    "other",
  );
});
