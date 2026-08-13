import test from "node:test";
import assert from "node:assert/strict";

import { analyzeHtml } from "../src/analysis/htmlAnalyzer.js";
import { runKBS } from "../src/analysis/kbs.js";
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
  detectOffplatformChatContact,
  detectFreeWebmailContact,
  detectGamblingLanguage,
  detectAdultLanguage,
  detectAdultAgeGate,
  detectAdultTld,
  detectDenseMediaGallery,
  detectParkingKeywords,
} from "../src/analysis/pageFindings.js";

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

  const webmail = detectFreeWebmailContact(html);
  if (webmail.found && webmail.samples.length > 0) {
    findings.freeWebmailContact = webmail.samples;
  }
  const chat = detectOffplatformChatContact(html);
  if (chat.found && chat.samples.length > 0) {
    findings.offplatformChatContact = chat.samples;
  }

  return findings;
}

/**
 * Attach tiered gambling findings from htmlAnalyzer.analysisText (mirrors pipeline).
 * @param {object} findings
 * @param {import("../src/analysis/htmlAnalyzer.js").HtmlAnalysis} htmlAnalysis
 */
function attachGamblingFromAnalysisText(findings, htmlAnalysis) {
  const corpus =
    (typeof htmlAnalysis?.analysisText === "string" &&
      htmlAnalysis.analysisText.trim()) ||
    (typeof htmlAnalysis?.bodyText === "string" &&
      htmlAnalysis.bodyText.trim()) ||
    "";
  const gambling = detectGamblingLanguage(corpus);
  if (
    gambling.definitiveCount > 0 ||
    gambling.strongCount > 0 ||
    gambling.weakCount > 0
  ) {
    findings.gamblingLanguage = {
      definitiveMatches: gambling.definitiveMatches,
      strongMatches: gambling.strongMatches,
      weakMatches: gambling.weakMatches,
      definitiveCount: gambling.definitiveCount,
      strongCount: gambling.strongCount,
      weakCount: gambling.weakCount,
    };
  }
}

/**
 * Attach adult lexical + structural findings (mirrors classificationPipeline).
 * @param {object} findings
 * @param {import("../src/analysis/htmlAnalyzer.js").HtmlAnalysis} htmlAnalysis
 * @param {string} html
 * @param {string} pageUrl
 */
function attachAdultFromAnalysis(findings, htmlAnalysis, html, pageUrl) {
  const corpus =
    (typeof htmlAnalysis?.analysisText === "string" &&
      htmlAnalysis.analysisText.trim()) ||
    (typeof htmlAnalysis?.bodyText === "string" &&
      htmlAnalysis.bodyText.trim()) ||
    "";
  const adult = detectAdultLanguage(corpus);
  if (
    adult.definitiveCount > 0 ||
    adult.strongCount > 0 ||
    adult.weakCount > 0
  ) {
    findings.adultLanguage = {
      definitiveMatches: adult.definitiveMatches,
      strongMatches: adult.strongMatches,
      weakMatches: adult.weakMatches,
      definitiveCount: adult.definitiveCount,
      strongCount: adult.strongCount,
      weakCount: adult.weakCount,
    };
  }
  if (detectAdultAgeGate(corpus).detected) {
    findings.adultAgeGateDetected = true;
  }
  const tldHit = detectAdultTld(pageUrl);
  if (tldHit.isAdultTld && tldHit.tld) {
    findings.adultTld = tldHit.tld;
  }
  const gallery = detectDenseMediaGallery(htmlAnalysis, html);
  if (gallery.detected) {
    findings.denseMediaGallery = {
      imageCount: gallery.imageCount,
      hasVideo: gallery.hasVideo,
    };
  }
}

/**
 * Attach parking gate findings from htmlAnalyzer.analysisText (mirrors pipeline).
 * @param {object} findings
 * @param {import("../src/analysis/htmlAnalyzer.js").HtmlAnalysis} htmlAnalysis
 */
function attachParkingFromAnalysisText(findings, htmlAnalysis) {
  const corpus =
    (typeof htmlAnalysis?.analysisText === "string" &&
      htmlAnalysis.analysisText.trim()) ||
    (typeof htmlAnalysis?.bodyText === "string" &&
      htmlAnalysis.bodyText.trim()) ||
    "";
  const parking = detectParkingKeywords(corpus);
  if (parking.isSuspicious) {
    findings.parkingKeywordsPresent = true;
    if (parking.foundClues?.length) {
      findings.parkingKeywordClues = parking.foundClues;
    }
  }
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
  if (!options.findingsExtra?.gamblingLanguage) {
    attachGamblingFromAnalysisText(pageFindings, htmlAnalysis);
  }
  if (
    !options.findingsExtra?.adultLanguage &&
    options.findingsExtra?.adultAgeGateDetected === undefined &&
    options.findingsExtra?.adultTld === undefined &&
    options.findingsExtra?.denseMediaGallery === undefined
  ) {
    attachAdultFromAnalysis(pageFindings, htmlAnalysis, html, pageUrl);
  }
  if (options.findingsExtra?.parkingKeywordsPresent === undefined) {
    attachParkingFromAnalysisText(pageFindings, htmlAnalysis);
  }
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

test("semantic_transaction_language_detected opens shop context without Fake_Shop score", () => {
  const { kbsResult } = classifyKbs(
    `<h1>Outlet sale</h1><p>Warehouse clearance up to 95% off all products.</p>
     <a href="/privacy">Privacy</a><a href="/terms">Terms</a><a href="/contact">Contact</a>`,
    {
      semanticOutput: {
        scores: { shoppingScore: 0.8 },
        zoneScores: {},
        derivedFacts: ["semantic_transaction_language_detected"],
        evidence: [],
      },
    }
  );

  assert.ok(hasSignal(kbsResult.signals, "semantic_transaction_language_detected"));
  assert.ok(hasSignal(kbsResult.signals, "shop_storefront_context"));
  assert.equal(kbsResult.classificationScores.Fake_Shop, 0);
});

test("gambling semantic derivedFact surfaces as a signal and promotes", () => {
  const { kbsResult } = classifyKbs(`<p>Welcome</p>`, {
    pageUrl: "https://odds.example/",
    semanticOutput: {
      scores: { gamblingScore: 0.9 },
      zoneScores: {},
      derivedFacts: ["semantic_gambling_language_detected"],
      evidence: [],
    },
  });

  assert.ok(hasSignal(kbsResult.signals, "semantic_gambling_language_detected"));
  assert.ok(kbsResult.firedRules.includes("gambling_semantic"));
  assert.ok(kbsResult.classificationScores.Gambling >= 0.65);
  assert.ok(kbsResult.classifiedAs.includes("Gambling"));
});

test("Gambling: definitive keyword casino promotes alone", () => {
  const { kbsResult, pageFindings } = classifyKbs(
    `<h1>Welcome to our casino</h1><p>Play today</p>`,
    { pageUrl: "https://play.example/" },
  );

  assert.ok(pageFindings.gamblingLanguage?.definitiveCount >= 1);
  assert.ok(hasSignal(kbsResult.signals, "definitive_gambling_language"));
  assert.ok(kbsResult.firedRules.includes("gambling_definitive_keywords"));
  assert.ok(kbsResult.classificationScores.Gambling >= 0.7);
  assert.ok(kbsResult.classifiedAs.includes("Gambling"));
});

test("Gambling: two strong keywords promote; one strong alone does not", () => {
  const one = classifyKbs(`<p>Try NBA betting this weekend</p>`, {
    pageUrl: "https://tips.example/",
  });
  assert.ok(hasSignal(one.kbsResult.signals, "strong_gambling_language"));
  assert.ok(one.kbsResult.classificationScores.Gambling < 0.6);
  assert.ok(!one.kbsResult.classifiedAs.includes("Gambling"));

  const two = classifyKbs(
    `<p>NBA betting and online slots with free spins</p>`,
    { pageUrl: "https://lobby.example/" },
  );
  assert.ok((two.pageFindings.gamblingLanguage?.strongCount ?? 0) >= 2);
  assert.ok(two.kbsResult.classificationScores.Gambling >= 0.6);
  assert.ok(two.kbsResult.classifiedAs.includes("Gambling"));
});

test("Gambling FP: Limited Slots telecom copy does not promote", () => {
  const { kbsResult, pageFindings } = classifyKbs(
    `<h1>UHome 5G</h1>
     <p>July 2026 — Limited Slots Get Your Free Wi-Fi 6 Router</p>
     <a href="https://wspp.my/uhome5g">SIGN UP NOW</a>`,
    { pageUrl: "https://umobile.network/" },
  );

  assert.equal(pageFindings.gamblingLanguage?.definitiveCount ?? 0, 0);
  assert.equal(pageFindings.gamblingLanguage?.strongCount ?? 0, 0);
  assert.ok((kbsResult.classificationScores.Gambling ?? 0) < 0.6);
  assert.ok(!kbsResult.classifiedAs.includes("Gambling"));
  assert.ok(!hasSignal(kbsResult.signals, "gambling_phrases_present"));
});

test("Gambling: weak alone does not promote", () => {
  const { kbsResult } = classifyKbs(`<p>Watch the NBA on TV tonight</p>`, {
    pageUrl: "https://news.example/",
    findingsExtra: {
      gamblingLanguage: {
        definitiveMatches: [],
        strongMatches: [],
        weakMatches: ["NBA"],
        definitiveCount: 0,
        strongCount: 0,
        weakCount: 1,
      },
    },
  });

  assert.ok(hasSignal(kbsResult.signals, "weak_gambling_language"));
  assert.ok(kbsResult.firedRules.includes("gambling_weak_prior"));
  assert.equal(kbsResult.classificationScores.Gambling, 0.15);
  assert.ok(!kbsResult.classifiedAs.includes("Gambling"));
});

test("Pornography: definitive keyword porn promotes alone", () => {
  const { kbsResult, pageFindings } = classifyKbs(
    `<h1>Free porn videos</h1><p>Watch tonight</p>`,
    { pageUrl: "https://tube.example/" },
  );

  assert.ok(pageFindings.adultLanguage?.definitiveCount >= 1);
  assert.ok(hasSignal(kbsResult.signals, "definitive_adult_language"));
  assert.ok(kbsResult.firedRules.includes("adult_definitive_keywords"));
  assert.ok(kbsResult.classificationScores.Pornography >= 0.7);
  assert.ok(kbsResult.classifiedAs.includes("Pornography"));
});

test("Pornography: two strong keywords promote; one strong alone does not", () => {
  const one = classifyKbs(`<p>Book an escort this weekend</p>`, {
    pageUrl: "https://listings.example/",
  });
  assert.ok(hasSignal(one.kbsResult.signals, "strong_adult_language"));
  assert.ok(one.kbsResult.classificationScores.Pornography < 0.6);
  assert.ok(!one.kbsResult.classifiedAs.includes("Pornography"));

  const two = classifyKbs(
    `<p>Live cam and erotic webcam show tonight</p>`,
    { pageUrl: "https://cams.example/" },
  );
  assert.ok((two.pageFindings.adultLanguage?.strongCount ?? 0) >= 2);
  assert.ok(two.kbsResult.classificationScores.Pornography >= 0.6);
  assert.ok(two.kbsResult.classifiedAs.includes("Pornography"));
});

test("Pornography: weak alone does not promote", () => {
  const { kbsResult } = classifyKbs(`<p>This site is 18+</p>`, {
    pageUrl: "https://news.example/",
    findingsExtra: {
      adultLanguage: {
        definitiveMatches: [],
        strongMatches: [],
        weakMatches: ["18+"],
        definitiveCount: 0,
        strongCount: 0,
        weakCount: 1,
      },
    },
  });

  assert.ok(hasSignal(kbsResult.signals, "weak_adult_language"));
  assert.ok(kbsResult.firedRules.includes("adult_weak_prior"));
  assert.equal(kbsResult.classificationScores.Pornography, 0.15);
  assert.ok(!kbsResult.classifiedAs.includes("Pornography"));
});

test("Pornography: age-gate + adult TLD promotes", () => {
  const { kbsResult, pageFindings } = classifyKbs(
    `<h1>Welcome</h1><p>Please confirm your age to enter</p>`,
    { pageUrl: "https://gallery.xxx/" },
  );

  assert.equal(pageFindings.adultAgeGateDetected, true);
  assert.equal(pageFindings.adultTld, "xxx");
  assert.ok(hasSignal(kbsResult.signals, "adult_age_gate_detected"));
  assert.ok(hasSignal(kbsResult.signals, "adult_tld_detected"));
  assert.ok(kbsResult.classificationScores.Pornography >= 0.6);
  assert.ok(kbsResult.classifiedAs.includes("Pornography"));
});

test("Pornography: dense gallery alone does not promote", () => {
  const { kbsResult } = classifyKbs(`<h1>Photo dump</h1>`, {
    pageUrl: "https://photos.example/",
    findingsExtra: {
      denseMediaGallery: { imageCount: 24, hasVideo: true },
    },
  });

  assert.ok(hasSignal(kbsResult.signals, "dense_media_gallery"));
  assert.equal(kbsResult.classificationScores.Pornography, 0.2);
  assert.ok(!kbsResult.classifiedAs.includes("Pornography"));
});

test("Pornography FP: adult education does not promote", () => {
  const { kbsResult, pageFindings } = classifyKbs(
    `<h1>Community College</h1>
     <p>Enroll in adult education classes for career growth</p>`,
    { pageUrl: "https://college.example.edu/" },
  );

  assert.equal(pageFindings.adultLanguage?.definitiveCount ?? 0, 0);
  assert.equal(pageFindings.adultLanguage?.strongCount ?? 0, 0);
  assert.ok((kbsResult.classificationScores.Pornography ?? 0) < 0.6);
  assert.ok(!kbsResult.classifiedAs.includes("Pornography"));
  assert.ok(!hasSignal(kbsResult.signals, "definitive_adult_language"));
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
      brandDependentPath: true,
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
      brandDependentPath: true,
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
      brandDependentPath: true,
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

// ---------------------------------------------------------------------------
// Scam + Recruitment additive checklist
// ---------------------------------------------------------------------------

/** Young / privacy / no-MX / optional bulletproof host (not scam_exempt). */
function disposableCollectedData(overrides = {}) {
  return {
    tls: {
      usesHttps: true,
      authorized: true,
      error: null,
      subjectCN: "scam.example",
      issuerOrg: "Let's Encrypt",
      issuerLevel: "DV",
      validTo: "2027-01-01",
      isExpired: false,
      hostnameMismatch: false,
    },
    whois: {
      ageInDays: 45,
      createdDate: "2026-06-01",
      expiresDate: "2027-06-01",
      registrantOrg: "Privacy Protect, LLC",
      domainStatus: ["ok"],
    },
    dns: {
      aRecords: ["1.2.3.4"],
      mxRecords: [],
      hasMX: false,
    },
    geo: {
      country: "RU",
      isp: "Bulletproof Hosting",
      asn: "AS99999",
      isBulletproof: true,
    },
    ...overrides,
  };
}

test("Scam FP: infra-only cues do not promote", () => {
  const { kbsResult } = classifyKbs(
    `<h1>Welcome</h1><p>Hello world.</p>
     <a href="/privacy">Privacy</a><a href="/terms">Terms</a><a href="/contact">Contact</a>`,
    {
      pageUrl: "https://new-host.example/",
      scanData: { collectedData: disposableCollectedData() },
    },
  );

  assert.ok(hasSignal(kbsResult.signals, "young_domain"));
  assert.ok(hasSignal(kbsResult.signals, "has_hidden_registrant"));
  assert.ok(hasSignal(kbsResult.signals, "no_email_capability"));
  assert.ok(hasSignal(kbsResult.signals, "is_hosted_on_bulletproof"));
  assert.ok(kbsResult.classificationScores.Scam < 0.5);
  assert.ok(!kbsResult.classifiedAs.includes("Scam"));
});

test("Scam FP: investment language alone does not promote", () => {
  const { kbsResult } = classifyKbs(
    `<h1>Invest with us</h1><p>Learn about markets.</p>
     <a href="/privacy">Privacy</a><a href="/terms">Terms</a><a href="/contact">Contact</a>`,
    {
      pageUrl: "https://blog.example/",
      semanticOutput: {
        scores: {},
        zoneScores: {},
        derivedFacts: ["semantic_investment_scam_language_detected"],
        evidence: [],
      },
    },
  );

  // No risk/extraction → lure leaf gated off
  assert.ok(!kbsResult.firedRules.includes("scam_investment_language"));
  assert.ok(kbsResult.classificationScores.Scam < 0.5);
  assert.ok(!kbsResult.classifiedAs.includes("Scam"));
});

test("Scam FP: official tone + young domain without extraction does not promote", () => {
  const { kbsResult } = classifyKbs(
    `<h1>Official website</h1><p>Welcome.</p>
     <a href="/privacy">Privacy</a><a href="/terms">Terms</a><a href="/contact">Contact</a>`,
    {
      pageUrl: "https://young-official.example/",
      brandDependentPath: true,
      semanticOutput: {
        scores: {},
        zoneScores: {},
        derivedFacts: ["semantic_official_brand_tone_detected"],
        evidence: [],
      },
      scanData: {
        collectedData: disposableCollectedData({
          geo: { country: "US", isp: "AWS", asn: "AS16509", isBulletproof: false },
          whois: {
            ageInDays: 45,
            createdDate: "2026-06-01",
            expiresDate: "2028-06-01",
            registrantOrg: "Alice",
            domainStatus: ["ok"],
          },
          dns: {
            aRecords: ["1.2.3.4"],
            mxRecords: [{ exchange: "mail.example", priority: 10 }],
            hasMX: true,
          },
        }),
      },
    },
  );

  // Lure+risk can score weakly but stay under threshold without extraction
  assert.ok(kbsResult.classificationScores.Scam < 0.5);
  assert.ok(!kbsResult.classifiedAs.includes("Scam"));
});

test("Scam FP: reward language alone does not promote", () => {
  const { kbsResult } = classifyKbs(
    `<h1>Prizes</h1>
     <a href="/privacy">Privacy</a><a href="/terms">Terms</a><a href="/contact">Contact</a>`,
    {
      pageUrl: "https://prizes.example/",
      semanticOutput: {
        scores: {},
        zoneScores: {},
        derivedFacts: ["semantic_reward_or_grant_scam_language_detected"],
        evidence: [],
      },
    },
  );

  assert.ok(!kbsResult.firedRules.includes("scam_reward_language"));
  assert.ok(kbsResult.classificationScores.Scam < 0.5);
  assert.ok(!kbsResult.classifiedAs.includes("Scam"));
});

test("Scam FP: financial form + young clean host does not promote Scam", () => {
  const { kbsResult } = classifyKbs(
    `<h1>Checkout</h1>
     <form><input name="cc-number" autocomplete="cc-number"></form>
     <a href="/privacy">Privacy</a><a href="/terms">Terms</a><a href="/contact">Contact</a>`,
    {
      pageUrl: "https://young-checkout.example/",
      brandDependentPath: true,
      scanData: {
        collectedData: disposableCollectedData({
          geo: { country: "US", isp: "AWS", asn: "AS16509", isBulletproof: false },
          whois: {
            ageInDays: 45,
            createdDate: "2026-06-01",
            expiresDate: "2028-06-01",
            registrantOrg: "Alice",
            domainStatus: ["ok"],
          },
          dns: {
            aRecords: ["1.2.3.4"],
            mxRecords: [{ exchange: "mail.example", priority: 10 }],
            hasMX: true,
          },
        }),
      },
    },
  );

  assert.ok(hasSignal(kbsResult.signals, "has_financial_input"));
  assert.ok(hasSignal(kbsResult.signals, "young_domain"));
  assert.ok(kbsResult.firedRules.includes("phishing_sensitive_inputs"));
  assert.ok(kbsResult.classificationScores.Phishing >= 0.3);
  assert.ok(kbsResult.classificationScores.Scam < 0.5);
  assert.ok(!kbsResult.classifiedAs.includes("Scam"));
});

test("Scam FP: recruitment language alone does not promote Recruitment_Fraud", () => {
  const { kbsResult } = classifyKbs(
    `<h1>Careers</h1><p>Join our team.</p>
     <a href="/privacy">Privacy</a><a href="/terms">Terms</a><a href="/contact">Contact</a>`,
    {
      pageUrl: "https://careers.example/",
      brandDependentPath: true,
      semanticOutput: {
        scores: {},
        zoneScores: {},
        derivedFacts: ["semantic_recruitment_language_detected"],
        evidence: [],
      },
    },
  );

  assert.ok(kbsResult.firedRules.includes("recruitment_language_prior"));
  assert.ok(kbsResult.classificationScores.Recruitment_Fraud < 0.5);
  assert.ok(!kbsResult.classifiedAs.includes("Recruitment_Fraud"));
});

test("Scam FP: scam_exempt zeros checklist scoring despite lure+extraction", () => {
  const { kbsResult } = classifyKbs(
    `<h1>Invest now</h1>
     <form><input name="cc-number" autocomplete="cc-number"></form>`,
    {
      pageUrl: "https://broker.example/",
      semanticOutput: {
        scores: {},
        zoneScores: {},
        derivedFacts: [
          "semantic_investment_scam_language_detected",
          "semantic_fee_collection_language_detected",
        ],
        evidence: [],
      },
      scanData: { collectedData: exemptCollectedData() },
    },
  );

  assert.ok(hasSignal(kbsResult.signals, "scam_exempt"));
  assert.equal(kbsResult.classificationScores.Scam, 0);
  assert.equal(kbsResult.classificationScores.Recruitment_Fraud, 0);
  assert.ok(!kbsResult.firedRules.includes("scam_investment_language"));
  assert.ok(!kbsResult.firedRules.includes("scam_fee_language"));
  assert.ok(!kbsResult.classifiedAs.includes("Scam"));
});

test("Scam FN: WhatsApp + young + hidden registrant promotes without semantics", () => {
  const { kbsResult } = classifyKbs(
    `<h1>Support</h1>
     <a href="https://wa.me/15551234567">Chat on WhatsApp</a>
     <a href="/privacy">Privacy</a><a href="/terms">Terms</a><a href="/contact">Contact</a>`,
    {
      pageUrl: "https://hyip-chat.example/",
      brandDependentPath: true,
      scanData: {
        collectedData: disposableCollectedData({
          geo: { country: "US", isp: "DigitalOcean", asn: "AS14061", isBulletproof: false },
          whois: {
            ageInDays: 45,
            createdDate: "2026-06-01",
            expiresDate: "2028-06-01",
            registrantOrg: "WhoisGuard, Inc.",
            domainStatus: ["ok"],
          },
          dns: {
            aRecords: ["1.2.3.4"],
            mxRecords: [{ exchange: "mail.example", priority: 10 }],
            hasMX: true,
          },
        }),
      },
    },
  );

  assert.ok(hasSignal(kbsResult.signals, "offplatform_chat_contact"));
  assert.ok(hasSignal(kbsResult.signals, "young_domain"));
  assert.ok(hasSignal(kbsResult.signals, "has_hidden_registrant"));
  assert.ok(kbsResult.firedRules.includes("scam_offplatform_chat"));
  assert.ok(kbsResult.firedRules.includes("scam_young_domain"));
  assert.ok(kbsResult.firedRules.includes("scam_hidden_registrant"));
  assert.ok(kbsResult.classifiedAs.includes("Scam"));
  assert.ok(kbsResult.classificationScores.Scam >= 0.5);
});

test("Scam FN: fee lang + young + hidden registrant promotes", () => {
  const { kbsResult } = classifyKbs(
    `<h1>Claim your prize</h1>
     <a href="/privacy">Privacy</a><a href="/terms">Terms</a><a href="/contact">Contact</a>`,
    {
      pageUrl: "https://prize-claim.example/",
      brandDependentPath: true,
      semanticOutput: {
        scores: {},
        zoneScores: {},
        derivedFacts: [
          "semantic_reward_or_grant_scam_language_detected",
          "semantic_fee_collection_language_detected",
        ],
        evidence: [],
      },
      scanData: {
        collectedData: disposableCollectedData({
          geo: { country: "US", isp: "AWS", asn: "AS16509", isBulletproof: false },
          whois: {
            ageInDays: 45,
            createdDate: "2026-06-01",
            expiresDate: "2028-06-01",
            registrantOrg: "WhoisGuard, Inc.",
            domainStatus: ["ok"],
          },
          dns: {
            aRecords: ["1.2.3.4"],
            mxRecords: [{ exchange: "mail.example", priority: 10 }],
            hasMX: true,
          },
        }),
      },
    },
  );

  assert.ok(hasSignal(kbsResult.signals, "has_hidden_registrant"));
  assert.ok(kbsResult.firedRules.includes("scam_reward_language"));
  assert.ok(kbsResult.firedRules.includes("scam_fee_language"));
  assert.ok(kbsResult.firedRules.includes("scam_young_domain"));
  assert.ok(kbsResult.firedRules.includes("scam_hidden_registrant"));
  assert.ok(kbsResult.classifiedAs.includes("Scam"));
  assert.ok(kbsResult.classificationScores.Scam >= 0.5);
});

test("Scam FN: excessive dead links + free webmail + young + hidden promotes", () => {
  const { kbsResult } = classifyKbs(
    `<h1>Rewards</h1>
     <a href="mailto:support@gmail.com">Email us</a>
     <a href="/privacy">Privacy</a><a href="/terms">Terms</a><a href="/contact">Contact</a>`,
    {
      pageUrl: "https://dead-links-scam.example/",
      brandDependentPath: true,
      findingsExtra: {
        linkHealth: {
          brokenRatio: 0.6,
          brokenCount: 6,
          evaluableCount: 10,
          placeholderCount: 2,
          conversionDestinationDead: false,
        },
      },
      scanData: {
        collectedData: disposableCollectedData({
          geo: { country: "US", isp: "Linode", asn: "AS63949", isBulletproof: false },
          whois: {
            ageInDays: 40,
            createdDate: "2026-06-20",
            expiresDate: "2027-06-20",
            registrantOrg: "Privacy Protect, LLC",
            domainStatus: ["ok"],
          },
          dns: {
            aRecords: ["1.2.3.4"],
            mxRecords: [{ exchange: "mail.example", priority: 10 }],
            hasMX: true,
          },
        }),
      },
    },
  );

  assert.ok(hasSignal(kbsResult.signals, "excessive_dead_links"));
  assert.ok(hasSignal(kbsResult.signals, "free_webmail_contact"));
  assert.ok(kbsResult.firedRules.includes("scam_excessive_dead_links"));
  assert.ok(kbsResult.firedRules.includes("scam_free_webmail"));
  assert.ok(kbsResult.classifiedAs.includes("Scam"));
  assert.ok(kbsResult.classificationScores.Scam >= 0.5);
});

test("Scam FN: brand spoof + reward + fee + young scores Scam", () => {
  const { kbsResult } = classifyKbs(
    `<h1>Acme Bank reward</h1>
     <a href="/privacy">Privacy</a><a href="/terms">Terms</a><a href="/contact">Contact</a>`,
    {
      brandName: "Acme Bank",
      pageUrl: "https://acme-rewards-fake.example/",
      semanticOutput: {
        scores: {},
        zoneScores: {},
        derivedFacts: [
          "semantic_reward_or_grant_scam_language_detected",
          "semantic_fee_collection_language_detected",
          "semantic_urgency_language_detected",
        ],
        evidence: [],
      },
      scanData: {
        collectedData: disposableCollectedData({
          geo: { country: "US", isp: "Vultr", asn: "AS20473", isBulletproof: false },
          whois: {
            ageInDays: 40,
            createdDate: "2026-06-20",
            expiresDate: "2027-06-20",
            registrantOrg: "WhoisGuard, Inc.",
            domainStatus: ["ok"],
          },
          dns: {
            aRecords: ["1.2.3.4"],
            mxRecords: [{ exchange: "mail.example", priority: 10 }],
            hasMX: true,
          },
        }),
      },
    },
  );

  assert.ok(hasSignal(kbsResult.signals, "impersonation_candidate"));
  assert.ok(!hasSignal(kbsResult.signals, "impersonation_exempt"));
  assert.ok(kbsResult.firedRules.includes("scam_brand_claim"));
  assert.ok(kbsResult.firedRules.includes("impersonation_scam_fee_trap"));
  assert.ok(kbsResult.classifiedAs.includes("Scam"));
});

test("Phishing: identity input scores via phishing_sensitive_inputs", () => {
  const { kbsResult } = classifyKbs(
    `<h1>Verify</h1>
     <form><input name="passport" autocomplete="passport"></form>
     <a href="/privacy">Privacy</a><a href="/terms">Terms</a><a href="/contact">Contact</a>`,
    { pageUrl: "https://id-form.example/", brandDependentPath: true },
  );

  assert.ok(hasSignal(kbsResult.signals, "has_identity_input"));
  assert.ok(kbsResult.firedRules.includes("phishing_sensitive_inputs"));
  assert.ok(kbsResult.classificationScores.Phishing >= 0.3);
});

test("detectOffplatformChatContact finds WhatsApp and Telegram links", () => {
  const hit = detectOffplatformChatContact(
    `<a href="https://wa.me/123">WA</a><a href="https://t.me/agent">TG</a>`,
  );
  const miss = detectOffplatformChatContact(`<a href="/contact">Contact</a>`);
  assert.equal(hit.found, true);
  assert.ok(hit.samples.some((s) => /wa\.me/i.test(s)));
  assert.equal(miss.found, false);
});

test("Recruitment FN: recruitment + fee + young domain promotes Recruitment_Fraud", () => {
  const { kbsResult } = classifyKbs(`<h1>Work from home</h1><p>Apply today</p>`, {
    pageUrl: "https://job-fee.example/",
    brandDependentPath: true,
    semanticOutput: {
      scores: {},
      zoneScores: {},
      derivedFacts: [
        "semantic_recruitment_language_detected",
        "semantic_recruitment_fee_language_detected",
      ],
      evidence: [],
    },
    scanData: {
      collectedData: disposableCollectedData({
        geo: { country: "US", isp: "Hetzner", asn: "AS24940", isBulletproof: false },
        whois: {
          ageInDays: 50,
          createdDate: "2026-06-01",
          expiresDate: "2027-06-01",
          registrantOrg: "Carol",
          domainStatus: ["ok"],
        },
        dns: {
          aRecords: ["1.2.3.4"],
          mxRecords: [{ exchange: "mail.example", priority: 10 }],
          hasMX: true,
        },
      }),
    },
  });

  assert.ok(hasSignal(kbsResult.signals, "advance_fee_recruitment_trap"));
  assert.ok(kbsResult.firedRules.includes("recruitment_language_prior"));
  assert.ok(kbsResult.firedRules.includes("recruitment_advance_fee"));
  assert.ok(kbsResult.classifiedAs.includes("Recruitment_Fraud"));
  assert.ok(kbsResult.classificationScores.Recruitment_Fraud >= 0.5);
});

test("Brand gate FP: no brand + phishing/scam cues keep brand-dependent scores at 0", () => {
  const { kbsResult } = classifyKbs(
    `<h1>Casino reviews</h1>
     <p>Best slots and online casino bonuses.</p>
     <a href="https://t.me/agent">Telegram</a>`,
    {
      pageUrl: "https://sirumobile-kasinot.example/",
      brandName: "umobile",
      semanticOutput: {
        scores: {},
        zoneScores: {},
        derivedFacts: [
          "semantic_account_verification_language_detected",
          "semantic_credential_login_language_detected",
          "semantic_credential_capture_language_detected",
        ],
        evidence: [],
      },
      scanData: {
        collectedData: disposableCollectedData({
          geo: { country: "US", isp: "AWS", asn: "AS16509", isBulletproof: false },
          whois: {
            ageInDays: 40,
            createdDate: "2026-06-20",
            expiresDate: "2027-06-20",
            registrantOrg: "Privacy Protect, LLC",
            domainStatus: ["ok"],
          },
          dns: {
            aRecords: ["1.2.3.4"],
            mxRecords: [],
            hasMX: false,
          },
        }),
      },
    },
  );

  assert.ok(!hasSignal(kbsResult.signals, "brand_name_present"));
  assert.ok(!hasSignal(kbsResult.signals, "impersonation_candidate"));
  assert.equal(kbsResult.classificationScores.Phishing, 0);
  assert.equal(kbsResult.classificationScores.Scam, 0);
  assert.equal(kbsResult.classificationScores.Fake_Shop, 0);
  assert.equal(kbsResult.classificationScores.Recruitment_Fraud, 0);
  assert.equal(kbsResult.classificationScores.Impersonation, 0);
  assert.ok(kbsResult.classificationScores.Gambling > 0);
});

test("Brand gate FN: brand + password login still scores Phishing", () => {
  const { kbsResult } = classifyKbs(
    `<h1>Acme Bank</h1><form><input type="password"></form>
     <a href="/privacy">Privacy</a><a href="/terms">Terms</a><a href="/contact">Contact</a>`,
    {
      brandName: "Acme Bank",
      pageUrl: "https://login-phish.example/",
    },
  );

  assert.ok(hasSignal(kbsResult.signals, "brand_name_present"));
  assert.ok(kbsResult.firedRules.includes("credential_capture"));
  assert.ok(kbsResult.classificationScores.Phishing >= 0.4);
});

test("Brand gate FN: brand + WhatsApp + young still scores Scam", () => {
  const { kbsResult } = classifyKbs(
    `<h1>Acme Bank Support</h1>
     <a href="https://wa.me/15551234567">Chat on WhatsApp</a>
     <a href="/privacy">Privacy</a><a href="/terms">Terms</a><a href="/contact">Contact</a>`,
    {
      brandName: "Acme Bank",
      pageUrl: "https://brand-wa-scam.example/",
      scanData: {
        collectedData: disposableCollectedData({
          geo: { country: "US", isp: "DigitalOcean", asn: "AS14061", isBulletproof: false },
          whois: {
            ageInDays: 45,
            createdDate: "2026-06-01",
            expiresDate: "2028-06-01",
            registrantOrg: "WhoisGuard, Inc.",
            domainStatus: ["ok"],
          },
          dns: {
            aRecords: ["1.2.3.4"],
            mxRecords: [{ exchange: "mail.example", priority: 10 }],
            hasMX: true,
          },
        }),
      },
    },
  );

  assert.ok(hasSignal(kbsResult.signals, "brand_name_present"));
  assert.ok(kbsResult.classifiedAs.includes("Scam"));
  assert.ok(kbsResult.classificationScores.Scam >= 0.5);
});

// ---------------------------------------------------------------------------
// Parking_Site gate + semantic-first scoring
// ---------------------------------------------------------------------------

test("detectParkingKeywords opens gate on domain / domain name only", () => {
  const hitDomain = detectParkingKeywords(
    "This domain is available to be registered.",
  );
  const hitName = detectParkingKeywords("Buy a domain name today.");
  const miss = detectParkingKeywords("Welcome to our shop. Contact support.");

  assert.equal(hitDomain.isSuspicious, true);
  assert.deepEqual(hitDomain.foundClues, ["domain"]);
  assert.equal(hitName.isSuspicious, true);
  assert.deepEqual(hitName.foundClues, ["domain name"]);
  assert.equal(miss.isSuspicious, false);
  assert.deepEqual(miss.foundClues, []);
});

test("Parking: gate opens on available-to-register copy", () => {
  const { pageFindings, kbsResult } = classifyKbs(
    `<h1>cndrbnumobiletelugu.org.ph</h1>
     <p>This domain is available to be registered. Click here to register.</p>
     <footer>© 2026 ParkLogic.com</footer>`,
    { pageUrl: "https://parked-example.test/" },
  );

  assert.equal(pageFindings.parkingKeywordsPresent, true);
  assert.ok(hasSignal(kbsResult.signals, "parking_keywords_present"));
  assert.ok(hasSignal(kbsResult.signals, "parking_candidate"));
});

test("Parking FN: gate + semantic parking promotes Parking_Site", () => {
  const { kbsResult } = classifyKbs(
    `<h1>example.test</h1>
     <p>This domain is available to be registered.</p>
     <a href="/privacy">Privacy</a><a href="/terms">Terms</a><a href="/contact">Contact</a>`,
    {
      pageUrl: "https://parklogic-lander.test/",
      semanticOutput: {
        scores: { parkingScore: 0.88 },
        zoneScores: {},
        derivedFacts: ["semantic_parking_language_detected"],
        evidence: [],
      },
    },
  );

  assert.ok(hasSignal(kbsResult.signals, "parking_candidate"));
  assert.ok(hasSignal(kbsResult.signals, "semantic_parking_language_detected"));
  assert.ok(kbsResult.firedRules.includes("parking_semantic_primary"));
  assert.ok(kbsResult.classifiedAs.includes("Parking_Site"));
  assert.ok(kbsResult.classificationScores.Parking_Site >= 0.4);
});

test("Parking FP: domain alone without semantic/infra does not promote", () => {
  const { kbsResult } = classifyKbs(
    `<h1>About our domain</h1>
     <p>We discuss domain strategy for startups.</p>
     <a href="/privacy">Privacy</a><a href="/terms">Terms</a><a href="/contact">Contact</a>`,
    { pageUrl: "https://blog-about-domains.test/" },
  );

  assert.ok(hasSignal(kbsResult.signals, "parking_candidate"));
  assert.ok(!kbsResult.firedRules.includes("parking_semantic_primary"));
  assert.equal(kbsResult.classificationScores.Parking_Site, 0);
  assert.ok(!kbsResult.classifiedAs.includes("Parking_Site"));
});

test("Parking FP: semantic parking without gate does not promote", () => {
  const { kbsResult } = classifyKbs(
    `<h1>Welcome</h1>
     <p>Hello world. Contact us anytime.</p>
     <a href="/privacy">Privacy</a><a href="/terms">Terms</a><a href="/contact">Contact</a>`,
    {
      pageUrl: "https://no-domain-token.test/",
      findingsExtra: { parkingKeywordsPresent: false },
      semanticOutput: {
        scores: { parkingScore: 0.9 },
        zoneScores: {},
        derivedFacts: ["semantic_parking_language_detected"],
        evidence: [],
      },
    },
  );

  assert.ok(!hasSignal(kbsResult.signals, "parking_candidate"));
  assert.ok(hasSignal(kbsResult.signals, "semantic_parking_language_detected"));
  assert.ok(!kbsResult.firedRules.includes("parking_semantic_primary"));
  assert.equal(kbsResult.classificationScores.Parking_Site, 0);
  assert.ok(!kbsResult.classifiedAs.includes("Parking_Site"));
});

// ---------------------------------------------------------------------------
// Access_Denied — HTTP deny status / DNS sinkhole
// ---------------------------------------------------------------------------

test("Access_Denied: HTTP 403 promotes and stops residual Other_Site", () => {
  const { kbsResult } = classifyKbs(`<h1>Hello</h1>`, {
    pageUrl: "https://blocked.example/",
    scanData: { httpStatus: 403 },
  });

  assert.ok(hasSignal(kbsResult.signals, "http_access_denied_status"));
  assert.equal(getSignal(kbsResult.signals, "http_access_denied_status").value, 403);
  assert.ok(kbsResult.firedRules.includes("access_denied_http_status"));
  assert.ok(kbsResult.classifiedAs.includes("Access_Denied"));
  assert.ok(kbsResult.classificationScores.Access_Denied >= 0.4);
  assert.ok(!kbsResult.classifiedAs.includes("Other_Site"));
});

test("Access_Denied: HTTP 451 and 410 promote", () => {
  for (const status of [451, 410]) {
    const { kbsResult } = classifyKbs(`<p>gone</p>`, {
      pageUrl: "https://denied.example/",
      scanData: { httpStatus: status },
    });
    assert.ok(
      kbsResult.classifiedAs.includes("Access_Denied"),
      `expected Access_Denied for HTTP ${status}`,
    );
    assert.equal(
      getSignal(kbsResult.signals, "http_access_denied_status").value,
      status,
    );
  }
});

test("Access_Denied: DNS sinkhole A record promotes", () => {
  const { kbsResult } = classifyKbs(`<h1>Blocked</h1>`, {
    pageUrl: "https://sinkhole.example/",
    scanData: {
      collectedData: disposableCollectedData({
        dns: {
          aRecords: ["127.0.0.1"],
          mxRecords: [],
          hasMX: false,
        },
      }),
    },
  });

  assert.ok(hasSignal(kbsResult.signals, "dns_sinkhole_detected"));
  assert.deepEqual(
    getSignal(kbsResult.signals, "dns_sinkhole_detected").value,
    ["127.0.0.1"],
  );
  assert.ok(kbsResult.firedRules.includes("access_denied_dns_sinkhole"));
  assert.ok(kbsResult.classifiedAs.includes("Access_Denied"));
  assert.ok(!kbsResult.classifiedAs.includes("Other_Site"));
});

test("Access_Denied: normal public A record does not sinkhole", () => {
  const { kbsResult } = classifyKbs(`<h1>Hello</h1>`, {
    pageUrl: "https://normal.example/",
    scanData: {
      collectedData: disposableCollectedData({
        dns: {
          aRecords: ["1.2.3.4"],
          mxRecords: [{ exchange: "mail.example", priority: 10 }],
          hasMX: true,
        },
      }),
    },
  });

  assert.ok(!hasSignal(kbsResult.signals, "dns_sinkhole_detected"));
  assert.ok(!kbsResult.classifiedAs.includes("Access_Denied"));
});

test("Access_Denied: HTTP 200 does not assert deny status", () => {
  const { kbsResult } = classifyKbs(`<h1>Hello</h1>`, {
    pageUrl: "https://ok.example/",
    scanData: { httpStatus: 200 },
  });

  assert.ok(!hasSignal(kbsResult.signals, "http_access_denied_status"));
  assert.ok(!kbsResult.classifiedAs.includes("Access_Denied"));
});
