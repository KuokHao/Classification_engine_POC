import test from "node:test";
import assert from "node:assert/strict";

import {
  parsePriceString,
  detectUnrealisticDiscount,
  extractPricePairs,
  detectGamblingLanguage,
  detectAdultLanguage,
  detectAdultAgeGate,
  detectAdultTld,
  detectDenseMediaGallery,
  containsBrand,
  containsBrandName,
  brandInMarkup,
  brandInHostname,
  detectSuspiciousShopTld,
  detectFreeWebmailContact,
} from "../src/analysis/pageFindings.js";
import { analyzeHtml } from "../src/analysis/htmlAnalyzer.js";

// ---------------------------------------------------------------------------
// parsePriceString
// ---------------------------------------------------------------------------

test("parsePriceString — US formats", () => {
  assert.equal(parsePriceString("$1,299.99"), 1299.99);
  assert.equal(parsePriceString("$19.99"), 19.99);
  assert.equal(parsePriceString("$999"), 999);
  assert.equal(parsePriceString("USD 50.00"), 50);
  assert.equal(parsePriceString("1,000"), 1000);
  assert.equal(parsePriceString("MYR 1,000.00"), 1000);
});

test("parsePriceString — European formats", () => {
  assert.equal(parsePriceString("€1.299,99"), 1299.99);
  assert.equal(parsePriceString("€49,99"), 49.99);
  assert.equal(parsePriceString("€899,00"), 899);
  assert.equal(parsePriceString("1.000"), 1000);
  assert.equal(parsePriceString("10.000"), 10000);
});

test("parsePriceString — edge cases", () => {
  assert.equal(parsePriceString(null), null);
  assert.equal(parsePriceString(""), null);
  assert.equal(parsePriceString("N/A"), null);
  assert.equal(parsePriceString("free"), null);
  assert.equal(parsePriceString("£ 1,000"), 1000);
});

// ---------------------------------------------------------------------------
// detectUnrealisticDiscount
// ---------------------------------------------------------------------------

test("detectUnrealisticDiscount — European pairs compute correct discount", () => {
  const pairs = [
    { original: "€1.299,99", sale: "€49,99" },
    { original: "€899,00", sale: "€29,99" },
  ];
  assert.equal(detectUnrealisticDiscount(pairs), true);
});

test("detectUnrealisticDiscount — legitimate US store", () => {
  const pairs = [
    { original: "$100.00", sale: "$80.00" },
    { original: "$50.00", sale: "$45.00" },
    { original: "$200.00", sale: "$150.00" },
    { original: "$99.99", sale: "$79.99" },
  ];
  assert.equal(detectUnrealisticDiscount(pairs), false);
});

test("detectUnrealisticDiscount — fake shop US pattern", () => {
  const pairs = [
    { original: "$1,299.99", sale: "$49.99" },
    { original: "$899.00", sale: "$29.99" },
    { original: "$499.00", sale: "$19.99" },
    { original: "$199.00", sale: "$9.99" },
  ];
  assert.equal(detectUnrealisticDiscount(pairs), true);
});

test("detectUnrealisticDiscount — hook alone below density threshold", () => {
  const pairs = [
    { original: "$100", sale: "$20" },
    { original: "$100", sale: "$50" },
    { original: "$100", sale: "$55" },
  ];
  assert.equal(detectUnrealisticDiscount(pairs), false);
});

test("detectUnrealisticDiscount — empty and invalid input", () => {
  assert.equal(detectUnrealisticDiscount([]), false);
  assert.equal(
    detectUnrealisticDiscount([{ original: "N/A", sale: "free" }]),
    false,
  );
});

// ---------------------------------------------------------------------------
// extractPricePairs → detectUnrealisticDiscount pipeline
// ---------------------------------------------------------------------------

test("extractPricePairs — del + sale-price class (strategy A)", () => {
  const html = `
    <div class="product">
      <del class="old-price">$199.00</del>
      <span class="sale-price">$19.99</span>
    </div>
  `;
  const pairs = extractPricePairs(html);
  assert.equal(pairs.length, 1);
  assert.equal(pairs[0].original, "$199.00");
  assert.equal(pairs[0].sale, "$19.99");
});

test("extractPricePairs — sibling fallback without sale class (strategy B)", () => {
  const html = `
    <div class="product">
      <s>$899.00</s>
      <span>$29.99</span>
    </div>
  `;
  const pairs = extractPricePairs(html);
  assert.equal(pairs.length, 1);
  assert.equal(pairs[0].original, "$899.00");
  assert.equal(pairs[0].sale, "$29.99");
});

test("extractPricePairs — European prices with compare-at class", () => {
  const html = `
    <div class="item">
      <span class="compare-at-price">€1.299,99</span>
      <span class="special-price">€49,99</span>
    </div>
  `;
  const pairs = extractPricePairs(html);
  assert.equal(pairs.length, 1);
  assert.equal(pairs[0].original, "€1.299,99");
  assert.equal(pairs[0].sale, "€49,99");
});

test("extractPricePairs — empty / no prices returns []", () => {
  assert.deepEqual(extractPricePairs(""), []);
  assert.deepEqual(extractPricePairs("<p>No prices here</p>"), []);
  assert.deepEqual(extractPricePairs(null), []);
});

test("extractPricePairs + detectUnrealisticDiscount — fake shop catalog", () => {
  const html = `
    <div class="grid">
      <div class="product">
        <del>$1,299.99</del><span class="sale-price">$49.99</span>
      </div>
      <div class="product">
        <del>$899.00</del><span class="sale-price">$29.99</span>
      </div>
      <div class="product">
        <del>$499.00</del><span class="sale-price">$19.99</span>
      </div>
      <div class="product">
        <del>$199.00</del><span class="sale-price">$9.99</span>
      </div>
    </div>
  `;
  const pairs = extractPricePairs(html);
  assert.equal(pairs.length, 4);
  assert.equal(detectUnrealisticDiscount(pairs), true);
});

test("extractPricePairs + detectUnrealisticDiscount — mild discounts stay false", () => {
  const html = `
    <div class="product"><del>$100.00</del><span class="sale-price">$80.00</span></div>
    <div class="product"><del>$50.00</del><span class="sale-price">$45.00</span></div>
    <div class="product"><del>$200.00</del><span class="sale-price">$150.00</span></div>
  `;
  const pairs = extractPricePairs(html);
  assert.equal(pairs.length, 3);
  assert.equal(detectUnrealisticDiscount(pairs), false);
});

// ---------------------------------------------------------------------------
// detectGamblingLanguage (tiered; operates on visible text, not raw HTML)
// ---------------------------------------------------------------------------

test("detectGamblingLanguage — definitive casino / sportsbook hits", () => {
  const casino = detectGamblingLanguage("Play blackjack at our casino tonight");
  assert.ok(casino.definitiveCount >= 1);
  assert.ok(casino.definitiveMatches.some((m) => /casino/i.test(m)));

  const book = detectGamblingLanguage("Place your bet on the sportsbook");
  assert.ok(book.definitiveCount >= 1);
  assert.ok(book.definitiveMatches.some((m) => /sportsbook/i.test(m)));

  const dealer = detectGamblingLanguage("Try our live dealer tables");
  assert.ok(dealer.definitiveCount >= 1);
});

test("detectGamblingLanguage — strong sports/esports and mechanics", () => {
  const nba = detectGamblingLanguage("NBA betting markets open now");
  assert.equal(nba.definitiveCount, 0);
  assert.ok(nba.strongCount >= 1);
  assert.ok(nba.strongMatches.some((m) => /NBA betting/i.test(m)));

  const cs2 = detectGamblingLanguage("CS2 betting odds updated hourly");
  assert.ok(cs2.strongCount >= 1);

  const rtp = detectGamblingLanguage("High RTP 96% and free spins on video slots");
  assert.ok(rtp.strongCount >= 2);
});

test("detectGamblingLanguage — weak Limited Slots veto / bare sport", () => {
  const limited = detectGamblingLanguage("July 2026 — Limited Slots Get Your Free Wi-Fi Router");
  assert.equal(limited.definitiveCount, 0);
  assert.equal(limited.strongCount, 0);
  assert.equal(limited.weakCount, 0);

  const bareNba = detectGamblingLanguage("Watch the NBA finals on TV");
  assert.equal(bareNba.definitiveCount, 0);
  assert.equal(bareNba.strongCount, 0);
  assert.ok(bareNba.weakCount >= 1);

  const empty = detectGamblingLanguage("");
  assert.equal(empty.definitiveCount, 0);
  assert.equal(detectGamblingLanguage(null).strongCount, 0);
});

test("detectGamblingLanguage — pipeline uses htmlAnalyzer.analysisText not raw HTML attrs", () => {
  const html = `
    <html><body>
      <div class="casino-widget-root">
        <h1>UHome 5G Internet</h1>
        <p>July 2026 — Limited Slots available for signup</p>
      </div>
      <!-- casino hidden in attribute noise should not be scanned by detector input -->
    </body></html>
  `;
  const analysis = analyzeHtml(html);
  const result = detectGamblingLanguage(analysis.analysisText);
  assert.equal(result.definitiveCount, 0, "no definitive from visible telecom copy");
  assert.equal(result.strongCount, 0);
  // "Limited Slots" vetoed — should not yield weak slot(s)
  assert.ok(
    !result.weakMatches.some((m) => /^slots?$/i.test(m)),
    "limited slots must not count as weak slot",
  );
});

// ---------------------------------------------------------------------------
// detectAdultLanguage + structural buddies
// ---------------------------------------------------------------------------

test("detectAdultLanguage — definitive porn / xxx videos hits", () => {
  const porn = detectAdultLanguage("Watch free porn tonight");
  assert.ok(porn.definitiveCount >= 1);
  assert.ok(porn.definitiveMatches.some((m) => /porn/i.test(m)));

  const xxx = detectAdultLanguage("Browse xxx videos in HD");
  assert.ok(xxx.definitiveCount >= 1);
  assert.ok(xxx.definitiveMatches.some((m) => /xxx videos/i.test(m)));
});

test("detectAdultLanguage — weak 18+ only; adult education veto", () => {
  const weak = detectAdultLanguage("This site is 18+");
  assert.equal(weak.definitiveCount, 0);
  assert.equal(weak.strongCount, 0);
  assert.ok(weak.weakCount >= 1);
  assert.ok(weak.weakMatches.some((m) => m === "18+"));

  const veto = detectAdultLanguage(
    "Enroll in adult education classes for career growth",
  );
  assert.equal(veto.definitiveCount, 0);
  assert.equal(veto.strongCount, 0);
  assert.equal(veto.weakCount, 0);

  assert.equal(detectAdultLanguage("").definitiveCount, 0);
  assert.equal(detectAdultLanguage(null).strongCount, 0);
});

test("detectAdultAgeGate — entry wall phrases; bare 18+ is not age-gate", () => {
  const gate = detectAdultAgeGate("Please confirm your age to continue");
  assert.equal(gate.detected, true);
  assert.ok(gate.matched.some((m) => /confirm your age/i.test(m)));

  const over = detectAdultAgeGate("I am over 18 and agree to the terms");
  assert.equal(over.detected, true);

  const bare = detectAdultAgeGate("This site is 18+");
  assert.equal(bare.detected, false);
});

test("detectAdultTld — .xxx / .porn vs .com", () => {
  assert.deepEqual(detectAdultTld("https://tube.xxx/home"), {
    isAdultTld: true,
    tld: "xxx",
  });
  assert.deepEqual(detectAdultTld("videos.porn"), {
    isAdultTld: true,
    tld: "porn",
  });
  assert.deepEqual(detectAdultTld("https://news.example.com/"), {
    isAdultTld: false,
    tld: "com",
  });
});

test("detectDenseMediaGallery — dense tube vs sparse corporate", () => {
  const imgs = (n) =>
    Array.from({ length: n }, (_, i) => `<img src="/t${i}.jpg" alt="t">`).join(
      "",
    );
  const denseHtml = `<html><body>${imgs(12)}<video src="/clip.mp4"></video></body></html>`;
  const dense = analyzeHtml(denseHtml);
  const denseHit = detectDenseMediaGallery(dense, denseHtml);
  assert.equal(denseHit.detected, true);
  assert.ok(denseHit.imageCount >= 12);
  assert.equal(denseHit.hasVideo, true);

  const manyOnly = `<html><body>${imgs(20)}</body></html>`;
  const many = analyzeHtml(manyOnly);
  assert.equal(detectDenseMediaGallery(many, manyOnly).detected, true);

  const sparseHtml = `<html><body>${imgs(3)}<p>About us</p></body></html>`;
  const sparse = analyzeHtml(sparseHtml);
  assert.equal(detectDenseMediaGallery(sparse, sparseHtml).detected, false);
});

// ---------------------------------------------------------------------------
// Brand matching (boundary-aware)
// ---------------------------------------------------------------------------

test("containsBrand — exact token, not substring or domain label", () => {
  assert.equal(containsBrand("Powered by umobile network", "umobile"), true);
  assert.equal(containsBrand("Logo or Umobile", "umobile"), true);
  assert.equal(containsBrand("Switch to U MOBILE today", "U MOBILE"), true);
  assert.equal(containsBrand("Visit jiuyoumobile.com", "umobile"), false);
  assert.equal(containsBrand("Link to umobile.com.my", "umobile"), false);
  assert.equal(containsBrand("Get umobiles new plan", "umobile"), false);
  assert.equal(containsBrand("Buy an Apple product", "Apple"), true);
  assert.equal(containsBrand("I love pineapple", "Apple"), false);
  assert.equal(containsBrand("Subscribe to Disney+", "Disney+"), true);
});

test("brandInMarkup — rejects jiuyoumobile false positive", () => {
  const jiuyou = `
    <html><head>
      <link rel="canonical" href="https://www.jiuyoumobile.com.cn/">
      <meta content="https://www.jiuyoumobile.com.cn/" property="og:url">
    </head>
    <body><img alt="jiuyou" src="/goco-logo.webp"></body></html>`;
  assert.equal(brandInMarkup(jiuyou, "umobile"), false);

  const spoof = `<img alt="umobile official logo" src="/x.png">`;
  assert.equal(brandInMarkup(spoof, "umobile"), true);

  const classSpoof = `<div class="umobile-header"></div>`;
  assert.equal(brandInMarkup(classSpoof, "umobile"), true);
});

test("brandInHostname — label / hyphen parts only", () => {
  assert.equal(brandInHostname("jiuyoumobile.com.cn", "umobile"), false);
  assert.equal(brandInHostname("umobile.com.my", "umobile"), true);
  assert.equal(brandInHostname("login.umobile.evil.test", "umobile"), true);
  assert.equal(brandInHostname("login-umobile.evil.test", "umobile"), true);
  assert.equal(brandInHostname("https://secure.acme.phish.test/", "Acme Bank"), true);
});

test("containsBrandName — visible text only", () => {
  assert.equal(
    containsBrandName("<p>Welcome to umobile</p><a href='https://jiuyoumobile.com.cn'>x</a>", "umobile"),
    true,
  );
  assert.equal(
    containsBrandName("<p>Visit jiuyoumobile today</p>", "umobile"),
    false,
  );
});

test("detectSuspiciousShopTld — high-risk TLDs", () => {
  assert.equal(detectSuspiciousShopTld("https://deals.example.top/sale").isSuspicious, true);
  assert.equal(detectSuspiciousShopTld("https://deals.example.top/sale").tld, "top");
  assert.equal(detectSuspiciousShopTld("cheap.shop").isSuspicious, true);
  assert.equal(detectSuspiciousShopTld("https://www.brand.com.my/").isSuspicious, false);
});

test("detectFreeWebmailContact — mailto and visible gmail", () => {
  const hit = detectFreeWebmailContact(
    `<p>Email <a href="mailto:help@gmail.com">help</a> or support@yahoo.com</p>`,
  );
  assert.equal(hit.found, true);
  assert.ok(hit.samples.includes("help@gmail.com"));
  assert.ok(hit.samples.includes("support@yahoo.com"));

  const miss = detectFreeWebmailContact(`<p>Contact sales@brand.com</p>`);
  assert.equal(miss.found, false);
});
