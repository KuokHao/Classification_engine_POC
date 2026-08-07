import test from "node:test";
import assert from "node:assert/strict";

import { analyzeHtml } from "../src/analysis/parse/htmlAnalyzer.js";
import { runKBS } from "../src/analysis/kbs/kbs.js";
import {
  containsBrandName,
  brandInHostname,
  detectSensitiveInputs,
  hasFileUpload,
  analyzeFormActions,
  isOfficialSubdomain,
  extractTrustNavigation,
  detectEcommerceSchema,
  hasPricingPatterns,
} from "../src/analysis/findings/pageFindings.js";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const EMPTY_SEMANTIC = {
  scores: {},
  zoneScores: {},
  derivedFacts: [],
  evidence: [],
};

function withUrgencySemantic(overrides = {}) {
  return {
    scores: { urgencyScore: 0.75, ...overrides.scores },
    zoneScores: {},
    derivedFacts: ["semantic_urgency_language_detected"],
    evidence: [{
      fact: "semantic_urgency_language_detected",
      concept: "urgencyScore",
      score: 0.75,
      matchedChunk: "Action required immediately",
      matchedReferencePhrase: "immediate action required",
      zone: "paragraphText",
    }],
    ...overrides,
  };
}

/** Returns true if the signals array contains a signal with the given name. */
function hasSignal(signals, name) {
  return signals.some((s) => s.name === name);
}

/** Returns the signal with the given name, or undefined. */
function getSignal(signals, name) {
  return signals.find((s) => s.name === name);
}

/**
 * Offline page findings via pageFindings.js (no checkRedirects / probeTrustLinks).
 * Mirrors the presence-only bag built in classificationPipeline.
 */
function buildPageFindingsOffline(html, pageUrl, brandName = "", officialDomains = []) {
  const findings = {};

  if (brandName && containsBrandName(html, brandName)) {
    findings.brandNamePresent = true;
  }

  if (brandName && brandInHostname(pageUrl, brandName)) {
    findings.brandInHostname = true;
  }

  const sensitive = detectSensitiveInputs(html);
  const sensitivePresent = {};
  if (sensitive.hasPassword) sensitivePresent.hasPassword = true;
  if (sensitive.hasUsername) sensitivePresent.hasUsername = true;
  if (sensitive.hasOTP) sensitivePresent.hasOTP = true;
  if (sensitive.hasFinancial) sensitivePresent.hasFinancial = true;
  if (sensitive.hasIdentity) sensitivePresent.hasIdentity = true;
  if (Object.keys(sensitivePresent).length > 0) {
    findings.sensitiveInputs = sensitivePresent;
  }

  if (hasFileUpload(html)) {
    findings.hasFileUpload = true;
  }

  for (const domain of officialDomains) {
    if (isOfficialSubdomain(pageUrl, domain)) {
      findings.isOfficialSubdomain = true;
      break;
    }
  }

  let officialDomain = officialDomains[0] ?? null;
  if (!officialDomain) {
    try {
      officialDomain = new URL(pageUrl).hostname.replace(/^www\./, "");
    } catch {
      officialDomain = null;
    }
  }

  if (officialDomain) {
    const formActions = analyzeFormActions(html, officialDomain);
    if (
      formActions.isLikelyPhishing ||
      (formActions.suspiciousActions?.length ?? 0) > 0
    ) {
      findings.formActions = {
        hasForms: formActions.hasForms,
        suspiciousActions: formActions.suspiciousActions,
        isLikelyPhishing: formActions.isLikelyPhishing,
      };
    }
  }

  const { links, trustNavigation } = extractTrustNavigation(html);
  findings.links = links;
  // Mirror classificationPipeline offline (no HTTP probe): missing vs broken.
  if (!trustNavigation.found) {
    trustNavigation.status = "missing";
  } else if ((trustNavigation.candidates ?? []).length === 0) {
    trustNavigation.status = "broken";
  } else {
    trustNavigation.status = "ok";
  }
  findings.trustNavigation = trustNavigation;

  const ecommerceSchema = detectEcommerceSchema(html);
  if (ecommerceSchema.hasSchema) {
    findings.ecommerceSchema = {
      usesMicrodata: ecommerceSchema.usesMicrodata,
      usesJsonLd: ecommerceSchema.usesJsonLd,
    };
  }

  if (hasPricingPatterns(html)) {
    findings.hasPricingPatterns = true;
  }

  return findings;
}

function classifyKbs(html, options = {}) {
  const htmlAnalysis = analyzeHtml(html);
  const pageUrl = options.pageUrl ?? "https://example.test";
  const pageFindings = {
    ...buildPageFindingsOffline(
      html,
      pageUrl,
      options.brandName ?? "",
      options.officialDomains ?? [],
    ),
    ...(options.findingsExtra ?? {}),
  };
  if (options.brandDependentPath) {
    pageFindings.brandNamePresent = true;
  }
  const semanticOutput = {
    ...EMPTY_SEMANTIC,
    ...(options.semanticOutput ?? {}),
  };
  const kbsResult = runKBS(
    htmlAnalysis,
    pageUrl,
    semanticOutput,
    {
      ...(options.scanData ?? {}),
      pageFindings,
    },
  );
  return { htmlAnalysis, pageFindings, semanticOutput, kbsResult, pageUrl };
}

// ---------------------------------------------------------------------------
// HTML structure + tools analysis tests
// ---------------------------------------------------------------------------

test("HTML structure exposes forms; trust links come from tools", () => {
  const html = `
    <main>
      <p>Clearance: 90% off every product today.</p>
      <a href="/privacy">Privacy Policy</a>
      <a href="#">Terms and Conditions</a>
      <button>Contact us</button>
      <form><input type="password" autocomplete="off"></form>
    </main>
  `;
  const analysis = analyzeHtml(html);
  const findings = buildPageFindingsOffline(html, "https://example.test");

  assert.equal(analysis.forms[0].inputCount, 1);
  assert.equal(analysis.forms[0].allInputs[0].autocomplete, "off");
  assert.equal(analysis.trustNavigation, undefined);

  assert.deepEqual(
    findings.trustNavigation.candidates.map((c) => c.trustCategory),
    ["privacy"],
  );
  assert.deepEqual(
    findings.trustNavigation.nonFunctional.map((c) => c.trustCategory).sort(),
    ["contact", "terms"],
  );
});

test("valid trust links are distinct from inert trust controls", () => {
  const valid = extractTrustNavigation(`
    <a href="/privacy">Privacy</a><a href="/terms">Terms</a><a href="/contact">Contact</a>
  `);
  const inert = extractTrustNavigation(`
    <a href="#">Privacy</a><button>Terms of Service</button><a>Contact us</a>
  `);

  assert.deepEqual(
    valid.trustNavigation.candidates.map((c) => c.trustCategory).sort(),
    ["contact", "privacy", "terms"],
  );
  assert.deepEqual(valid.trustNavigation.nonFunctional, []);
  assert.deepEqual(
    inert.trustNavigation.nonFunctional.map((c) => c.trustCategory).sort(),
    ["contact", "privacy", "terms"],
  );
  assert.deepEqual(inert.trustNavigation.candidates, []);
});

// ---------------------------------------------------------------------------
// KBS signal tests
// ---------------------------------------------------------------------------

test("ecommerce schema and pricing patterns produce KBS input signals", () => {
  const { kbsResult, pageFindings } = classifyKbs(`
    <html>
      <head>
        <script type="application/ld+json">
          {"@type":"Product","name":"Keyboard","offers":{"@type":"Offer","price":"49.99","priceCurrency":"USD"}}
        </script>
      </head>
      <body>
        <h1>Mechanical Keyboard</h1>
        <p>Price: $49.99</p>
        <a href="/privacy">Privacy</a>
        <a href="/terms">Terms</a>
        <a href="/contact">Contact</a>
      </body>
    </html>
  `);

  assert.equal(pageFindings.ecommerceSchema.usesJsonLd, true);
  assert.equal(pageFindings.hasPricingPatterns, true);
  assert.ok(hasSignal(kbsResult.signals, "ecommerce_schema_present"));
  assert.ok(hasSignal(kbsResult.signals, "pricing_patterns_present"));
});

test("a password form produces a has_password_input signal", () => {
  const { kbsResult } = classifyKbs(`
    <h1>Member sign in</h1>
    <form action="/session">
      <input type="email" autocomplete="username">
      <input type="password" autocomplete="current-password">
    </form>
    <a href="/privacy">Privacy Policy</a>
    <a href="/terms">Terms of Service</a>
    <a href="/contact">Contact us</a>
  `);

  assert.ok(hasSignal(kbsResult.signals, "has_password_input"), "should signal has_password_input");
  assert.ok(!hasSignal(kbsResult.signals, "external_form_action"), "no external form action");
});

test("an OTP input field produces a has_otp_input signal", () => {
  const { kbsResult } = classifyKbs(`
    <h1>Verify your account</h1>
    <form><input id="otp" autocomplete="off"></form>
  `);

  assert.ok(hasSignal(kbsResult.signals, "has_otp_input"), "should signal has_otp_input");
});

test("urgency semantic derivedFact surfaces as a signal", () => {
  const { kbsResult } = classifyKbs(`
    <h1>Urgent service notice</h1>
    <p>Action required immediately. This maintenance warning will expire in 24 hours.</p>
    <a href="/details">Read details</a>
  `, { semanticOutput: withUrgencySemantic() });

  assert.ok(
    hasSignal(kbsResult.signals, "semantic_urgency_language_detected"),
    "urgency derived fact should appear as a signal"
  );
  assert.ok(!hasSignal(kbsResult.signals, "has_password_input"), "no password field");
});

test("external password form action produces has_password_input and external_form_action signals", () => {
  const { kbsResult } = classifyKbs(`
    <h1>Secure member access portal</h1>
    <form action="https://collector.example/submit"><input type="password"></form>
    <a href="/privacy">Privacy Policy</a>
    <a href="/terms">Terms</a>
    <a href="/contact">Contact</a>
  `);

  assert.ok(hasSignal(kbsResult.signals, "has_password_input"), "has_password_input signal");
  assert.ok(hasSignal(kbsResult.signals, "external_form_action"), "external_form_action signal");
  const extSignal = getSignal(kbsResult.signals, "external_form_action");
  assert.ok(
    Array.isArray(extSignal.value)
      ? extSignal.value.some((v) => String(v).includes("collector.example"))
      : extSignal.evidence.some((e) => e.includes("collector.example")),
    "evidence or value includes external URL"
  );
});

test("tls_risk signal requires http scheme; young_domain requires whois collectedData", () => {
  const html = "<h1>Informational page</h1><p>General information about this service.</p>";
  const unknown = classifyKbs(html).kbsResult;
  const httpOnly = classifyKbs(html, {
    pageUrl: "http://new-domain.test",
  }).kbsResult;
  const withWhois = classifyKbs(html, {
    pageUrl: "https://new-domain.test",
    scanData: {
      collectedData: {
        tls: null,
        whois: { ageInDays: 10, createdDate: null, expiresDate: null, registrantOrg: null, domainStatus: [] },
        dns: null,
        geo: null,
      },
    },
  }).kbsResult;

  assert.ok(!hasSignal(unknown.signals, "young_domain"), "no young_domain without whois");
  assert.ok(!hasSignal(unknown.signals, "tls_risk"), "no tls_risk on HTTPS without cert data");
  assert.ok(hasSignal(httpOnly.signals, "tls_risk"), "tls_risk signal from http:// scheme");
  assert.ok(hasSignal(withWhois.signals, "is_newly_registered"), "newly registered from whois age");
});

test("autocomplete-off on password field produces autocomplete_off_on_password signal", () => {
  const { kbsResult } = classifyKbs(`
    <form><input type="password" autocomplete="off"></form>
  `);

  assert.ok(hasSignal(kbsResult.signals, "has_password_input"));
  assert.ok(hasSignal(kbsResult.signals, "autocomplete_off_on_password"));
});

test("inert trust navigation produces error_trust_navigation signal", () => {
  const { kbsResult } = classifyKbs(`
    <h1>Login</h1>
    <form><input type="password"></form>
    <a href="#">Privacy Policy</a>
    <button>Terms and Conditions</button>
  `);

  assert.ok(hasSignal(kbsResult.signals, "error_trust_navigation"));
  const signal = getSignal(kbsResult.signals, "error_trust_navigation");
  assert.ok(
    signal.evidence.some((e) => /trust|inert|non-navigable|work/i.test(e)),
    "evidence describes broken trust controls"
  );
});

test("semantic_ecommerce_language_detected opens shop context without Fake_Shop score", () => {
  const { kbsResult } = classifyKbs(
    `<h1>Outlet sale</h1><p>Warehouse clearance up to 95% off all products.</p>
     <a href="/privacy">Privacy</a><a href="/terms">Terms</a><a href="/contact">Contact</a>`,
    {
      semanticOutput: {
        scores: { shoppingScore: 0.8 },
        zoneScores: {},
        derivedFacts: ["semantic_ecommerce_language_detected"],
        evidence: [],
      },
    }
  );

  assert.ok(hasSignal(kbsResult.signals, "semantic_ecommerce_language_detected"));
  assert.ok(hasSignal(kbsResult.signals, "shop_storefront_context"));
  assert.equal(kbsResult.classificationScores.Fake_Shop, 0);
});

test("gambling semantic derivedFact surfaces as a signal", () => {
  const { kbsResult } = classifyKbs(
    "<h1>Casino games</h1><p>Play online games and review the available entertainment.</p>",
    {
      semanticOutput: {
        scores: { gamblingScore: 0.9 },
        zoneScores: {},
        derivedFacts: ["semantic_gambling_language_detected"],
        evidence: [],
      },
    }
  );

  assert.ok(hasSignal(kbsResult.signals, "semantic_gambling_language_detected"));
});

test("recruitment semantic derivedFacts surface as signals", () => {
  const { kbsResult } = classifyKbs(
    "<h1>Job opportunity</h1><p>Apply now and start your career today.</p>",
    {
      semanticOutput: {
        scores: { recruitmentScore: 0.75, recruitmentFeeScore: 0.8 },
        zoneScores: {},
        derivedFacts: [
          "semantic_recruitment_language_detected",
          "semantic_recruitment_fee_language_detected",
        ],
        evidence: [],
      },
    }
  );

  assert.ok(hasSignal(kbsResult.signals, "semantic_recruitment_language_detected"));
  assert.ok(hasSignal(kbsResult.signals, "semantic_recruitment_fee_language_detected"));
});

test("each signal carries human-readable evidence and a 0–1 strength", () => {
  const { kbsResult } = classifyKbs(`
    <form action="https://evil.example/steal">
      <input type="password">
    </form>
  `);

  for (const signal of kbsResult.signals) {
    assert.ok(Array.isArray(signal.evidence), `signal ${signal.name} should have evidence array`);
    assert.ok(signal.evidence.length > 0, `signal ${signal.name} evidence should not be empty`);
    assert.ok(typeof signal.strength === "number", `signal ${signal.name} strength should be a number`);
    assert.ok(signal.strength >= 0 && signal.strength <= 1, `signal ${signal.name} strength should be 0–1`);
  }
});

test("benign page always includes hostname and may include missing trust categories", () => {
  const { kbsResult } = classifyKbs(`
    <h1>About us</h1>
    <p>We are a company that does things.</p>
    <a href="/privacy">Privacy</a>
    <a href="/terms">Terms</a>
    <a href="/contact">Contact</a>
  `);

  assert.ok(hasSignal(kbsResult.signals, "hostname"));
  assert.ok(!hasSignal(kbsResult.signals, "has_password_input"));
  assert.ok(!hasSignal(kbsResult.signals, "ecommerce_language_detected"));
});

test("kbsResult exposes classificationScores and classifiedAs", () => {
  const { kbsResult } = classifyKbs(`
    <form><input type="password"><input type="email"></form>
  `);

  assert.ok(typeof kbsResult.classificationScores === "object", "classificationScores should be an object");
  assert.ok(Array.isArray(kbsResult.classifiedAs), "classifiedAs should be an array");
});

test("signal value carries the extracted primitive", () => {
  const { kbsResult } = classifyKbs(`
    <form><input type="password"><input type="email"></form>
  `);

  const pwSignal = getSignal(kbsResult.signals, "has_password_input");
  assert.ok(pwSignal, "has_password_input signal should exist");
  assert.equal(pwSignal.value, true);

  const hostnameSignal = getSignal(kbsResult.signals, "hostname");
  assert.ok(hostnameSignal, "hostname signal should exist");
  assert.equal(typeof hostnameSignal.value, "string");
});

test("brand_name_present signal when brand appears in page text", () => {
  const { kbsResult } = classifyKbs(
    `<h1>Welcome to Acme Bank</h1><p>Sign in to continue.</p>`,
    { brandName: "Acme Bank" },
  );
  assert.ok(hasSignal(kbsResult.signals, "brand_name_present"));
});

// ---------------------------------------------------------------------------
// Impersonation rules
// ---------------------------------------------------------------------------

test("brand mention without tone or credentials gets commentary exemption", () => {
  const { kbsResult } = classifyKbs(
    `<h1>News about Acme Bank</h1><p>Analysts discuss Acme Bank quarterly results.</p>`,
    { brandName: "Acme Bank", pageUrl: "https://news.example.test/acme" },
  );

  assert.ok(hasSignal(kbsResult.signals, "impersonation_candidate"));
  assert.ok(hasSignal(kbsResult.signals, "impersonation_exempt"));
  assert.ok(!hasSignal(kbsResult.signals, "phishing_trap"));
  assert.ok(!hasSignal(kbsResult.signals, "deceptive_subdomain"));
  assert.ok(!kbsResult.classifiedAs.includes("Impersonation"));
});

test("deceptive subdomain spoof promotes Impersonation", () => {
  const { kbsResult } = classifyKbs(
    `<h1>Acme Bank</h1><form><input type="password"></form>`,
    {
      brandName: "Acme Bank",
      pageUrl: "https://login.acme.secure-update.evil.test/signin",
    },
  );

  assert.ok(hasSignal(kbsResult.signals, "is_subdomain"));
  assert.ok(hasSignal(kbsResult.signals, "deceptive_subdomain"));
  assert.ok(kbsResult.classifiedAs.includes("Impersonation"));
  assert.ok(kbsResult.classificationScores.Impersonation >= 0.6);
});

test("phishing trap scores Impersonation and Phishing for brand + password off-domain", () => {
  const { kbsResult } = classifyKbs(
    `<h1>Acme Bank secure login</h1><form><input type="password"></form>`,
    {
      brandName: "Acme Bank",
      pageUrl: "https://evil-phish.test/login",
    },
  );

  assert.ok(hasSignal(kbsResult.signals, "phishing_trap"));
  assert.ok(!hasSignal(kbsResult.signals, "impersonation_exempt"));
  assert.ok(kbsResult.classificationScores.Impersonation >= 0.45);
  assert.ok(kbsResult.classificationScores.Phishing >= 0.4);
});

test("is_official_subdomain input signal does not gate KBS impersonation scoring", () => {
  const { kbsResult } = classifyKbs(
    `<h1>Acme Bank</h1><form><input type="password"></form>`,
    {
      brandName: "Acme Bank",
      pageUrl: "https://login.acmebank.com/signin",
      officialDomains: ["acmebank.com"],
    },
  );

  assert.ok(hasSignal(kbsResult.signals, "is_official_subdomain"));
  assert.ok(hasSignal(kbsResult.signals, "impersonation_candidate"));
  assert.ok(hasSignal(kbsResult.signals, "phishing_trap"));
});

// ---------------------------------------------------------------------------
// Fake_Shop checklist
// ---------------------------------------------------------------------------

/** Aged domain + OV TLS → scam_exempt via legitimate_business_exemption. */
function exemptCollectedData() {
  return {
    tls: {
      usesHttps: true,
      authorized: true,
      error: null,
      subjectCN: "shop.example",
      issuerOrg: "DigiCert Inc",
      issuerLevel: "OV",
      validTo: "2028-01-01",
      isExpired: false,
      hostnameMismatch: false,
    },
    whois: {
      ageInDays: 3000,
      createdDate: "2017-01-01",
      expiresDate: "2028-01-01",
      registrantOrg: "Real Retail Inc",
      domainStatus: ["clientTransferProhibited"],
    },
    dns: {
      aRecords: ["1.2.3.4"],
      mxRecords: [{ exchange: "mail.example", priority: 10 }],
      hasMX: true,
    },
    geo: null,
  };
}

test("Fake_Shop: risk cues without shop context do not score", () => {
  const { kbsResult } = classifyKbs(
    `<h1>About us</h1><p>Contact support@gmail.com for help.</p>`,
    {
      pageUrl: "http://about.example.top/",
      findingsExtra: {
        freeWebmailContact: ["support@gmail.com"],
        suspiciousShopTld: "top",
        missingCopyright: true,
      },
      semanticOutput: {
        scores: {},
        zoneScores: {},
        derivedFacts: ["semantic_urgency_language_detected"],
        evidence: [],
      },
    },
  );

  assert.ok(!hasSignal(kbsResult.signals, "shop_storefront_context"));
  assert.equal(kbsResult.classificationScores.Fake_Shop, 0);
  assert.ok(!kbsResult.classifiedAs.includes("Fake_Shop"));
});

test("Fake_Shop: single checklist cue does not promote", () => {
  const { kbsResult } = classifyKbs(
    `<h1>Store</h1><p>Price: $49.99</p>
     <a href="/privacy">Privacy</a><a href="/terms">Terms</a><a href="/contact">Contact</a>`,
    {
      pageUrl: "https://store.example/",
      findingsExtra: { unrealisticDiscountDetected: true },
    },
  );

  assert.ok(hasSignal(kbsResult.signals, "shop_storefront_context"));
  assert.ok(kbsResult.classificationScores.Fake_Shop > 0);
  assert.ok(kbsResult.classificationScores.Fake_Shop < 0.45);
  assert.ok(!kbsResult.classifiedAs.includes("Fake_Shop"));
});

test("Fake_Shop: discount + hollow trust promotes", () => {
  const { kbsResult } = classifyKbs(
    `<h1>Flash sale</h1><p>Everything 90% off. Price: $9.99 was $99.99</p>`,
    {
      pageUrl: "https://deal-barn.example/",
      findingsExtra: {
        hasPricingPatterns: true,
        unrealisticDiscountDetected: true,
        missingCopyright: true,
      },
    },
  );

  assert.ok(hasSignal(kbsResult.signals, "shop_storefront_context"));
  assert.ok(hasSignal(kbsResult.signals, "missing_trust_navigation"));
  assert.ok(kbsResult.firedRules.includes("fake_shop_unrealistic_discount"));
  assert.ok(kbsResult.firedRules.includes("fake_shop_trust_hollow"));
  assert.ok(kbsResult.classifiedAs.includes("Fake_Shop"));
  assert.ok(kbsResult.classificationScores.Fake_Shop >= 0.45);
});

test("Fake_Shop: scam_exempt zeros all Fake_Shop scoring", () => {
  const { kbsResult } = classifyKbs(
    `<h1>Clearance</h1><p>Price: $9.99</p><p>Email support@gmail.com</p>`,
    {
      pageUrl: "http://clearance.example.shop/",
      findingsExtra: {
        hasPricingPatterns: true,
        unrealisticDiscountDetected: true,
        freeWebmailContact: ["support@gmail.com"],
        suspiciousShopTld: "shop",
      },
      semanticOutput: {
        scores: {},
        zoneScores: {},
        derivedFacts: ["semantic_urgency_language_detected"],
        evidence: [],
      },
      scanData: { collectedData: exemptCollectedData() },
    },
  );

  assert.ok(hasSignal(kbsResult.signals, "scam_exempt"));
  assert.ok(hasSignal(kbsResult.signals, "shop_storefront_context"));
  assert.equal(kbsResult.classificationScores.Fake_Shop, 0);
  assert.ok(!kbsResult.classifiedAs.includes("Fake_Shop"));
  assert.ok(!kbsResult.firedRules.includes("fake_shop_unrealistic_discount"));
});

test("impersonation_gate opens on brand_in_markup via hasBrandClaim", () => {
  const { kbsResult } = classifyKbs(
    `<h1>Sign in</h1><form><input type="password"></form>
     <a href="/privacy">Privacy</a><a href="/terms">Terms</a><a href="/contact">Contact</a>`,
    {
      brandName: "OtherBrand",
      pageUrl: "https://markup-gate.test/login",
      findingsExtra: { brandInMarkup: true },
    },
  );

  assert.ok(hasSignal(kbsResult.signals, "brand_in_markup"));
  assert.ok(hasSignal(kbsResult.signals, "impersonation_candidate"));
});
