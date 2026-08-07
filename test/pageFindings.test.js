import test from "node:test";
import assert from "node:assert/strict";

import { parsePriceString, detectUnrealisticDiscount, extractPricePairs, detectGamblingPhrases, containsBrand, containsBrandName, brandInMarkup, brandInHostname, detectSuspiciousShopTld, detectFreeWebmailContact } from "../src/analysis/findings/pageFindings.js";

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
// detectGamblingPhrases
// ---------------------------------------------------------------------------

test("detectGamblingPhrases — casino vocabulary hits", () => {
  assert.equal(detectGamblingPhrases("<p>Play slots and blackjack at our casino</p>"), true);
  assert.equal(detectGamblingPhrases("<p>Place your bet on the sportsbook</p>"), true);
  assert.equal(detectGamblingPhrases("<p>Online poker and roulette tonight</p>"), true);
});

test("detectGamblingPhrases — benign pages miss", () => {
  assert.equal(detectGamblingPhrases("<p>We sell sports apparel and running shoes</p>"), false);
  assert.equal(detectGamblingPhrases(""), false);
  assert.equal(detectGamblingPhrases(null), false);
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
