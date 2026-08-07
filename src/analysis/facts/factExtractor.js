/**
 * Fact Extractor — translates raw tool / pipeline outputs into KBS signals.
 *
 * Convention (presence-only):
 *   Assert a signal only when the check is positive / meaningful.
 *   Absence from working memory means "not detected" — never assert value: false
 *   for a missing boolean. Negatives are separate signals (e.g. insecure_connection,
 *   no_email_capability, country_mismatch) when rules need them.
 *   Categorical facts (hostname, hosting_country, hosting_provider_category) are
 *   always emitted when their source data exists — they are valued, not toggles.
 *
 * Public API:
 *   extractFacts(collectedData, opts)           → ExtractedFact[]  (TLS/WHOIS/DNS/Geo)
 *   extractInputFacts(inputs)                   → ExtractedFact[]  (all initial facts)
 *   assertExtractedSignals(wm, facts)           → void
 *
 * Groups used (aligned with kbs.js vocabulary):
 *   "identity"       — TLS / hostname / registrant authenticity signals
 *   "infrastructure" — Hosting provider, DNS capability signals
 *   "lifecycle"      — Domain registration age and status signals
 *   "phishing" / "scam" / "trust" / "structural" / "semantic" / "content"
 */

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/** Certificate issuers that provide free or fully automated DV certificates. */
const FREE_CA_LIST = [
  "let's encrypt",
  "zerossl",
  "cpanel",
  "r3",    // Let's Encrypt intermediate
  "e1",    // Let's Encrypt intermediate
  "e5",    // Let's Encrypt intermediate
  "r10",   // Let's Encrypt intermediate
  "r11",   // Let's Encrypt intermediate
];

/** Substrings that indicate WHOIS privacy / proxy services. */
const PRIVACY_KEYWORDS = [
  "privacy",
  "redacted",
  "proxy",
  "protected",
  "whoisguard",
  "domains by proxy",
  "contact privacy",
];

/** EPP status codes that mean a domain is not actively in use. */
const INACTIVE_STATUSES = [
  "inactive",
  "redemptionperiod",
  "serverhold",
  "pendingdelete",
  "pendingrestorationrequest",
];

/**
 * Hosting provider categories.
 * First match wins; the matched key is the `value` of the `hosting_provider_category` signal.
 */
const PROVIDER_CATEGORIES = {
  CDN:           ["cloudflare", "fastly", "akamai", "cdn77", "bunny"],
  MajorCloud:    ["amazon", "google", "microsoft", "azure", "digitalocean", "linode", "vultr", "hetzner"],
  SharedHosting: ["godaddy", "bluehost", "hostgator", "namecheap", "siteground", "hostinger"],
  CheapVPS:      ["frantech", "buyvm", "serverius", "hostwinds", "virmach", "netcup"],
};

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/**
 * @typedef {Object} ExtractedFact
 * @property {string}  signal   - KBS signal name to assert into WorkingMemory
 * @property {string}  group    - "identity" | "infrastructure" | "lifecycle"
 * @property {unknown} value    - Concrete value (boolean, string, number, string[])
 * @property {number}  strength - 0–1 confidence level
 * @property {string}  evidence - Single human-readable sentence explaining this fact
 */

/**
 * @typedef {Object} ExtractFactsOptions
 * @property {string|null} [expectedCountry] - Brand's expected hosting country (ISO name, e.g. "Malaysia").
 *   When provided, asserts `country_matches_target` or `country_mismatch` (presence-only).
 */

/**
 * Presence-only bag of raw page-analysis tool outputs (from utility.js).
 *
 * @typedef {Object} PageFindings
 * @property {true} [brandNamePresent]
 * @property {true} [brandImageDetected]
 * @property {true} [brandInMarkup]
 * @property {{ hasPassword?: true, hasUsername?: true, hasOTP?: true, hasFinancial?: true, hasIdentity?: true }} [sensitiveInputs]
 * @property {true} [hasFileUpload]
 * @property {{ hasForms?: boolean, suspiciousActions?: object[], isLikelyPhishing?: boolean }} [formActions]
 * @property {true} [isOfficialSubdomain]
 * @property {object} [redirects]
 * @property {object} [trustNavigation]
 * @property {object[]} [links]
 * @property {{ brokenRatio?: number, brokenCount?: number, evaluableCount?: number, placeholderCount?: number, conversionDestinationDead?: boolean, dominantUrl?: string|null, dominantShare?: number, samples?: object }} [linkHealth]
 * @property {true} [hasCopyright]
 * @property {true} [missingCopyright]
 * @property {{ usesMicrodata?: boolean, usesJsonLd?: boolean }} [ecommerceSchema]
 * @property {true} [hasPricingPatterns]
 * @property {true} [unrealisticDiscountDetected]
 * @property {string} [suspiciousShopTld]
 * @property {string[]} [freeWebmailContact]
 * @property {true} [gamblingPhrasesPresent]
 */

/**
 * @typedef {Object} ExtractInputFactsOptions
 * @property {import("../../collection/trust/heuristic.js").CollectedData|null} [collectedData]
 * @property {PageFindings|null} [pageFindings]
 * @property {import("./htmlAnalyzer.js").HtmlAnalysis|null} [htmlDocument]
 * @property {string} [pageUrl]
 * @property {string[]} [derivedFacts] - Semantic analyzer derived fact names
 * @property {string|null} [expectedCountry]
 * @property {import("../../collection/trust/heuristic.js").BrandConfig|null} [brandConfig]
 * @property {string|null} [trustStatus] - From heuristic: TRUSTED_INFRA seeds trusted_infra
 */

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/** @param {unknown} s */
function lower(s) {
  return String(s ?? "").toLowerCase();
}

/**
 * Collapse org / brand strings for comparison (alphanumeric only).
 * @param {unknown} s
 * @returns {string}
 */
function normalizeOrgKey(s) {
  return String(s ?? "")
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "");
}

/**
 * True when candidate org matches any known fingerprint (equality or containment).
 * Requires both sides to have at least 3 alphanumeric chars after normalize.
 *
 * @param {unknown} candidate
 * @param {string[]} knownList
 * @returns {boolean}
 */
function orgMatchesKnown(candidate, knownList) {
  const c = normalizeOrgKey(candidate);
  if (c.length < 3) return false;
  for (const known of knownList ?? []) {
    const k = normalizeOrgKey(known);
    if (k.length < 3) continue;
    if (c === k || c.includes(k) || k.includes(c)) return true;
  }
  return false;
}

/**
 * Compare scanned TLS subject.O / WHOIS registrant against brand fingerprints.
 * subjectOrg is the validated company on OV/EV certs — never the CA issuer.
 *
 * @param {import("../../collection/trust/heuristic.js").CollectedData|null|undefined} collectedData
 * @param {import("../../collection/trust/heuristic.js").BrandConfig|null|undefined} brandConfig
 * @returns {ExtractedFact[]}
 */
function extractBrandIdentityFacts(collectedData, brandConfig) {
  if (!collectedData || !brandConfig) return [];

  const facts = [];
  const brandNames = Array.isArray(brandConfig.brandNames)
    ? brandConfig.brandNames
    : [];
  const tlsOrgs = [
    ...(Array.isArray(brandConfig.tlsSubjectOrganizations)
      ? brandConfig.tlsSubjectOrganizations
      : []),
    ...brandNames,
  ];
  const registrantOrgs = [
    ...(Array.isArray(brandConfig.registrantOrganizations)
      ? brandConfig.registrantOrganizations
      : []),
    ...brandNames,
  ];

  const tls = collectedData.tls;
  const subjectOrg = tls?.subjectOrg ?? null;
  const isEnterprise =
    tls?.issuerLevel === "OV" || tls?.issuerLevel === "EV";

  if (subjectOrg && isEnterprise && orgMatchesKnown(subjectOrg, tlsOrgs)) {
    facts.push({
      signal: "brand_tls_org_match",
      group: "identity",
      value: subjectOrg,
      strength: 1,
      evidence: `TLS subject organization '${subjectOrg}' matches brand identity fingerprint`,
    });
  }

  const registrantOrg = collectedData.whois?.registrantOrg ?? null;
  if (registrantOrg && orgMatchesKnown(registrantOrg, registrantOrgs)) {
    facts.push({
      signal: "brand_registrant_org_match",
      group: "identity",
      value: registrantOrg,
      strength: 1,
      evidence: `WHOIS registrant organization '${registrantOrg}' matches brand identity fingerprint`,
    });
  }

  if (
    facts.some(
      (f) =>
        f.signal === "brand_tls_org_match" ||
        f.signal === "brand_registrant_org_match",
    )
  ) {
    facts.push({
      signal: "brand_org_identity_match",
      group: "identity",
      value: true,
      strength: 1,
      evidence:
        "Scanned site organization identity matches the brand profile (TLS subject and/or WHOIS registrant)",
    });
  }

  return facts;
}

/**
 * Days between two ISO date strings. Returns null if either is missing or unparseable.
 * @param {string|null} a
 * @param {string|null} b
 */
function daysBetween(a, b) {
  if (!a || !b) return null;
  const diff = new Date(b).getTime() - new Date(a).getTime();
  return Number.isNaN(diff) ? null : Math.floor(diff / (1000 * 60 * 60 * 24));
}

// ---------------------------------------------------------------------------
// TLS facts
// ---------------------------------------------------------------------------

/**
 * @param {import("../tools/tlsscraper.js").TLSAnalysis|null} tls
 * @returns {ExtractedFact[]}
 */
function extractTLSFacts(tls) {
  if (!tls) return [];
  const facts = [];

  const secure = Boolean(tls.usesHttps && tls.authorized && !tls.isExpired);
  if (secure) {
    facts.push({
      signal: "has_secure_connection",
      group: "identity",
      value: true,
      strength: 0.9,
      evidence: "Connection is encrypted and certificate chain is trusted",
    });
  } else {
    facts.push({
      signal: "insecure_connection",
      group: "identity",
      value: true,
      strength: 1.0,
      evidence: !tls.usesHttps
        ? "HTTP (no TLS)"
        : tls.isExpired
          ? `certificate expired on ${tls.validTo}`
          : `untrusted cert: ${tls.error ?? "unknown error"}`,
    });
  }

  if (tls.hostnameMismatch) {
    facts.push({
      signal: "tls_identity_mismatch",
      group: "identity",
      value: true,
      strength: 1.0,
      evidence:
        "TLS certificate subject does not match hostname — likely impersonation or misconfiguration",
    });
  }

  if (tls.isExpired) {
    facts.push({
      signal: "tls_is_expired",
      group: "identity",
      value: true,
      strength: 1.0,
      evidence: `TLS certificate expired on ${tls.validTo} — site is abandoned or misconfigured`,
    });
  }

  if (tls.issuerOrg) {
    const issuerLow = lower(tls.issuerOrg);
    const isFreeCA = FREE_CA_LIST.some((ca) => issuerLow.includes(ca));
    if (isFreeCA) {
      facts.push({
        signal: "is_free_or_automated_tls",
        group: "identity",
        value: tls.issuerOrg,
        strength: 0.5,
        evidence: `Certificate issued by free/automated CA (${tls.issuerOrg}) — normal for small sites, suspicious for impersonated brands`,
      });
    }
  }

  if (tls.issuerLevel === "OV" || tls.issuerLevel === "EV") {
    facts.push({
      signal: "has_enterprise_tls",
      group: "identity",
      value: tls.issuerLevel,
      strength: 0.9,
      evidence: `Certificate carries ${tls.issuerLevel} validation — organization identity verified by the CA`,
    });
  }

  return facts;
}

// ---------------------------------------------------------------------------
// WHOIS facts
// ---------------------------------------------------------------------------

/**
 * @param {import("../tools/whoisscraper.js").WhoisData|null} whois
 * @returns {ExtractedFact[]}
 */
function extractWhoisFacts(whois) {
  if (!whois) return [];
  const facts = [];
  const { ageInDays, createdDate, expiresDate, registrantOrg, domainStatus } = whois;

  // Age-based signals (mutually exclusive for newly/young; established can overlap)
  if (ageInDays !== null) {
    if (ageInDays < 30) {
      facts.push({
        signal: "is_newly_registered",
        group: "lifecycle",
        value: ageInDays,
        strength: 1.0,
        evidence: `Domain registered only ${ageInDays} day(s) ago — extremely high phishing/fake-store risk`,
      });
    } else if (ageInDays < 180) {
      facts.push({
        signal: "young_domain",
        group: "lifecycle",
        value: ageInDays,
        strength: Math.round((1 - ageInDays / 180) * 100) / 100,
        evidence: `Domain registered ${ageInDays} day(s) ago — relatively new`,
      });
    }

    if (ageInDays > 1825) {
      const years = Math.floor(ageInDays / 365);
      facts.push({
        signal: "established_domain",
        group: "lifecycle",
        value: ageInDays,
        strength: 1.0,
        evidence: `Domain is ${ageInDays} days (~${years} yrs) old — long-standing presence`,
      });
    }
  }

  // is_short_term_registration — single-year registrations are a known attacker cost-minimization tactic
  const registrationSpan = daysBetween(createdDate, expiresDate);
  if (registrationSpan !== null && registrationSpan < 400) {
    facts.push({
      signal: "is_short_term_registration",
      group: "lifecycle",
      value: registrationSpan,
      strength: 0.7,
      evidence: `Domain registered for ~${registrationSpan} days only — attackers minimize cost with single-year registrations`,
    });
  }

  // has_hidden_registrant — WHOIS privacy services are legitimate but add uncertainty
  if (registrantOrg) {
    const orgLow = lower(registrantOrg);
    const isPrivacy = PRIVACY_KEYWORDS.some((kw) => orgLow.includes(kw));
    if (isPrivacy) {
      facts.push({
        signal: "has_hidden_registrant",
        group: "identity",
        value: registrantOrg,
        strength: 0.4,
        evidence: `Registrant organization is privacy-shielded ('${registrantOrg}') — neutral for small sites, suspicious for impersonated brands`,
      });
    }
  }

  // is_inactive_domain_status — serverHold / redemptionPeriod etc. are strong parking/abuse signals
  const inactiveStatuses = (domainStatus ?? []).filter((s) =>
    INACTIVE_STATUSES.some((kw) => lower(s).includes(kw)),
  );
  if (inactiveStatuses.length > 0) {
    facts.push({
      signal: "is_inactive_domain_status",
      group: "lifecycle",
      value: inactiveStatuses,
      strength: 0.9,
      evidence: `Domain status '${inactiveStatuses[0]}' indicates it is inactive, parked, or in a legal/deletion hold`,
    });
  }

  return facts;
}

// ---------------------------------------------------------------------------
// DNS facts
// ---------------------------------------------------------------------------

/**
 * @param {import("../tools/dnsscraper.js").DNSData|null} dns
 * @returns {ExtractedFact[]}
 */
function extractDNSFacts(dns) {
  if (!dns) return [];

  if (dns.hasMX) {
    return [
      {
        signal: "has_email_capability",
        group: "infrastructure",
        value: true,
        strength: 0.8,
        evidence:
          "MX records present — domain has email infrastructure consistent with a real business",
      },
    ];
  }

  return [
    {
      signal: "no_email_capability",
      group: "infrastructure",
      value: true,
      strength: 0.9,
      evidence: "No MX records — domain likely not a legitimate business",
    },
  ];
}

// ---------------------------------------------------------------------------
// Geo facts
// ---------------------------------------------------------------------------

/**
 * Categorize a hosting provider from its ISP name and ASN string.
 * @param {string|null} isp
 * @param {string|null} asn
 * @returns {string}
 */
function classifyProvider(isp, asn) {
  const combined = lower(`${isp ?? ""} ${asn ?? ""}`);
  for (const [category, keywords] of Object.entries(PROVIDER_CATEGORIES)) {
    if (keywords.some((kw) => combined.includes(kw))) {
      return category;
    }
  }
  return "Unknown";
}

/**
 * @param {import("../tools/ipgeolocationscraper.js").GeoData|null} geo
 * @param {string|null} expectedCountry
 * @returns {ExtractedFact[]}
 */
function extractGeoFacts(geo, expectedCountry) {
  if (!geo) return [];
  const facts = [];

  // is_hosted_on_bulletproof
  if (geo.isBulletproof) {
    facts.push({
      signal: "is_hosted_on_bulletproof",
      group: "infrastructure",
      value: geo.isp,
      strength: 0.95,
      evidence: `Hosting provider '${geo.isp}' is flagged as bulletproof — strongly associated with scam and phishing infrastructure`,
    });
  }

  // Categorical: always emit when geo data exists
  const category = classifyProvider(geo.isp, geo.asn);
  facts.push({
    signal: "hosting_provider_category",
    group: "infrastructure",
    value: category,
    strength: 0.7,
    evidence: `Hosted on ${category} provider: ${geo.isp ?? "unknown"} (${geo.asn ?? "unknown"})`,
  });

  if (geo.country) {
    facts.push({
      signal: "hosting_country",
      group: "infrastructure",
      value: geo.country,
      strength: 1.0,
      evidence: `Hosted in ${geo.country} via ${geo.isp ?? "unknown"} (${geo.asn ?? "unknown"})`,
    });

    if (expectedCountry) {
      const matches = lower(geo.country) === lower(expectedCountry);
      if (matches) {
        facts.push({
          signal: "country_matches_target",
          group: "infrastructure",
          value: true,
          strength: 0.8,
          evidence: `Hosting country (${geo.country}) matches expected brand region`,
        });
      } else {
        facts.push({
          signal: "country_mismatch",
          group: "infrastructure",
          value: true,
          strength: 0.85,
          evidence: `Site hosted in ${geo.country} but brand targets ${expectedCountry} — possible impersonation`,
        });
      }
    }
  }

  return facts;
}

// ---------------------------------------------------------------------------
// URL / page-structure facts
// ---------------------------------------------------------------------------

/**
 * @param {string} pageUrl
 * @returns {ExtractedFact[]}
 */
function extractUrlFacts(pageUrl) {
  const facts = [];
  let hostname = "";
  let usesHttps = true;
  try {
    const parsed = new URL(pageUrl);
    hostname = parsed.hostname;
    usesHttps = parsed.protocol === "https:";
  } catch {
    hostname = String(pageUrl ?? "");
  }

  facts.push({
    signal: "hostname",
    group: "structural",
    value: hostname,
    strength: 1,
    evidence: `Hostname extracted from URL: ${hostname}`,
  });

  if (!usesHttps) {
    facts.push({
      signal: "no_https",
      group: "identity",
      value: true,
      strength: 1,
      evidence: "Page is served over HTTP — no TLS encryption",
    });
  }

  const parts = hostname.split(".").filter(Boolean);
  if (parts.length > 2) {
    facts.push({
      signal: "is_subdomain",
      group: "identity",
      value: true,
      strength: 1,
      evidence: `Hostname "${hostname}" has ${parts.length - 2} subdomain level(s)`,
    });
  }

  return facts;
}

/**
 * Structural form facts from the HTML document (autocomplete-off, external actions).
 * Password/OTP presence comes from pageFindings.sensitiveInputs instead.
 *
 * @param {import("./htmlAnalyzer.js").HtmlAnalysis|null|undefined} htmlDocument
 * @param {string} pageUrl
 * @returns {ExtractedFact[]}
 */
function extractFormStructureFacts(htmlDocument, pageUrl) {
  if (!htmlDocument) return [];
  const facts = [];
  const forms = htmlDocument.forms ?? [];

  let hostname = "";
  try {
    hostname = new URL(pageUrl).hostname;
  } catch {
    hostname = "";
  }

  const externalForms = forms.filter((f) => {
    if (!f.action) return false;
    try {
      const actionHost = new URL(f.action).hostname;
      return actionHost && actionHost !== hostname;
    } catch {
      return false;
    }
  });

  if (externalForms.length > 0) {
    const externalHosts = externalForms
      .map((f) => {
        try {
          return new URL(f.action).hostname;
        } catch {
          return f.action;
        }
      })
      .filter(Boolean);
    facts.push({
      signal: "external_form_action",
      group: "phishing",
      value: externalHosts,
      strength: 1,
      evidence: externalHosts.map((h) => `Form submits to external host: ${h}`).join("; "),
    });
  }

  const passwordWithAutocompleteOff = forms.some((f) =>
    f.allInputs?.some((i) => i.type === "password" && i.autocomplete === "off"),
  );
  if (passwordWithAutocompleteOff) {
    facts.push({
      signal: "autocomplete_off_on_password",
      group: "phishing",
      value: true,
      strength: 1,
      evidence: "Password field has autocomplete='off'",
    });
  }

  return facts;
}

// ---------------------------------------------------------------------------
// Page findings facts (utility + trust)
// ---------------------------------------------------------------------------

/**
 * @param {PageFindings|null|undefined} pageFindings
 * @returns {ExtractedFact[]}
 */
function extractPageUtilityFacts(pageFindings) {
  if (!pageFindings) return [];
  const facts = [];

  if (pageFindings.brandNamePresent) {
    facts.push({
      signal: "brand_name_present",
      group: "identity",
      value: true,
      strength: 1,
      evidence: "Brand name detected in page text content",
    });
  }

  if (pageFindings.brandImageDetected) {
    facts.push({
      signal: "brand_image_detected",
      group: "identity",
      value: true,
      strength: 1,
      evidence: "Brand logo / brand image detected on the page",
    });
  }

  if (pageFindings.brandInMarkup) {
    facts.push({
      signal: "brand_in_markup",
      group: "identity",
      value: true,
      strength: 1,
      evidence:
        "Brand name/token found in HTML markup attributes or paths (not visible text)",
    });
  }

  const sens = pageFindings.sensitiveInputs ?? {};
  if (sens.hasPassword) {
    facts.push({
      signal: "has_password_input",
      group: "phishing",
      value: true,
      strength: 1,
      evidence: "Password input field detected on the page",
    });
  }
  if (sens.hasUsername) {
    facts.push({
      signal: "has_username_input",
      group: "phishing",
      value: true,
      strength: 1,
      evidence: "Username / login input field detected on the page",
    });
  }
  if (sens.hasOTP) {
    facts.push({
      signal: "has_otp_input",
      group: "phishing",
      value: true,
      strength: 1,
      evidence: "OTP / verification code input field detected on the page",
    });
  }
  if (sens.hasFinancial) {
    facts.push({
      signal: "has_financial_input",
      group: "scam",
      value: true,
      strength: 1,
      evidence: "Financial / payment input field detected on the page",
    });
  }
  if (sens.hasIdentity) {
    facts.push({
      signal: "has_identity_input",
      group: "scam",
      value: true,
      strength: 1,
      evidence: "Identity / passport / national-ID input field detected on the page",
    });
  }

  if (pageFindings.hasFileUpload) {
    facts.push({
      signal: "has_file_upload",
      group: "phishing",
      value: true,
      strength: 1,
      evidence: "File upload input detected on the page",
    });
  }

  if (pageFindings.isOfficialSubdomain) {
    facts.push({
      signal: "is_official_subdomain",
      group: "structural",
      value: true,
      strength: 1,
      evidence: "Page hostname is the official domain or a valid subdomain of it",
    });
  }

  const formActions = pageFindings.formActions;
  if (formActions?.isLikelyPhishing || (formActions?.suspiciousActions?.length ?? 0) > 0) {
    const reasons = (formActions.suspiciousActions ?? []).map(
      (a) => a.reason ?? String(a.action ?? "suspicious form action"),
    );
    // Prefer structured form external_form_action from htmlDocument when present;
    // still record analyzeFormActions evidence under a distinct signal when needed.
    if (!facts.some((f) => f.signal === "external_form_action") && reasons.length > 0) {
      facts.push({
        signal: "external_form_action",
        group: "phishing",
        value: formActions.suspiciousActions,
        strength: 1,
        evidence: reasons.join("; "),
      });
    }
  }

  const redirects = pageFindings.redirects;
  if (redirects?.isCrossDomain) {
    facts.push({
      signal: "cross_domain_redirect",
      group: "structural",
      value: redirects.targets ?? true,
      strength: 0.9,
      evidence: `Page redirects cross-domain (types: ${(redirects.redirectTypes ?? []).join(", ") || "unknown"})`,
    });
  }
  if (redirects?.redirectTypes?.includes("http") && redirects.wasRedirected) {
    facts.push({
      signal: "http_redirect",
      group: "structural",
      value: redirects.targets ?? true,
      strength: 0.6,
      evidence: "HTTP redirect detected in the redirect chain",
    });
  }
  if (redirects?.redirectTypes?.includes("meta")) {
    facts.push({
      signal: "meta_redirect",
      group: "structural",
      value: redirects.targets ?? true,
      strength: 0.7,
      evidence: "Meta refresh redirect detected on the page",
    });
  }

  const linkHealth = pageFindings.linkHealth;
  if (linkHealth) {
    const pct = Math.round((linkHealth.brokenRatio ?? 0) * 100);
    const parts = [
      `${linkHealth.brokenCount ?? "?"}/${linkHealth.evaluableCount ?? "?"} anchors broken (${pct}%)`,
    ];
    if (linkHealth.placeholderCount) {
      parts.push(`${linkHealth.placeholderCount} placeholder (# / javascript:void)`);
    }
    if (linkHealth.conversionDestinationDead && linkHealth.dominantUrl) {
      parts.push(
        `dominant CTA ${linkHealth.dominantUrl} (${Math.round((linkHealth.dominantShare ?? 0) * 100)}% of anchors) is dead`,
      );
    }

    // Seed whenever pipeline stored linkHealth (already gated on exceedsThreshold).
    facts.push({
      signal: "excessive_dead_links",
      group: "structural",
      value: linkHealth,
      strength: 0.85,
      evidence: `Page link health is disproportionately poor: ${parts.join("; ")}`,
    });

    if (linkHealth.conversionDestinationDead) {
      facts.push({
        signal: "conversion_destination_dead",
        group: "structural",
        value: {
          url: linkHealth.dominantUrl,
          share: linkHealth.dominantShare,
        },
        strength: 0.9,
        evidence: `Primary conversion destination is unreachable: ${linkHealth.dominantUrl ?? "unknown"} (${Math.round((linkHealth.dominantShare ?? 0) * 100)}% of anchors)`,
      });
    }
  }

  // Footer copyright presence from hasCopyright() — hollow sites often omit notices.
  if (pageFindings.hasCopyright) {
    facts.push({
      signal: "has_copyright",
      group: "structural",
      value: true,
      strength: 0.5,
      evidence:
        "Copyright / rights notice found in footer or page content (©, copyright, or all rights reserved)",
    });
  }
  if (pageFindings.missingCopyright) {
    facts.push({
      signal: "missing_copyright",
      group: "structural",
      value: true,
      strength: 0.7,
      evidence:
        "No copyright / rights notice found in footer or page content",
    });
  }

  const ecommerceSchema = pageFindings.ecommerceSchema;
  if (ecommerceSchema) {
    const kinds = [];
    if (ecommerceSchema.usesMicrodata) kinds.push("microdata");
    if (ecommerceSchema.usesJsonLd) kinds.push("JSON-LD");
    facts.push({
      signal: "ecommerce_schema_present",
      group: "fake_shop",
      value: ecommerceSchema,
      strength: 1,
      evidence: `E-commerce Product/Offer schema detected (${kinds.join(" + ") || "unknown format"})`,
    });
  }

  if (pageFindings.hasPricingPatterns) {
    facts.push({
      signal: "pricing_patterns_present",
      group: "fake_shop",
      value: true,
      strength: 1,
      evidence: "Currency and price patterns detected in page content",
    });
  }

  // Presence-only Fake_Shop fact: catalog-wide extreme discount density.
  // Seeded only when page findings ran extractPricePairs → detectUnrealisticDiscount
  // behind the pricing/schema gate. Feeds Fake_Shop checklist scorers.
  if (pageFindings.unrealisticDiscountDetected) {
    facts.push({
      signal: "unrealistic_discount_detected",
      group: "fake_shop",
      value: true,
      strength: 1,
      evidence:
        "A high share of listed products show extreme original-vs-sale discounts typical of fake shopfronts",
    });
  }

  if (pageFindings.suspiciousShopTld) {
    facts.push({
      signal: "suspicious_shop_tld",
      group: "fake_shop",
      value: pageFindings.suspiciousShopTld,
      strength: 0.8,
      evidence: `Hostname uses a high-risk shop TLD (.${pageFindings.suspiciousShopTld})`,
    });
  }

  if (
    Array.isArray(pageFindings.freeWebmailContact) &&
    pageFindings.freeWebmailContact.length > 0
  ) {
    const samples = pageFindings.freeWebmailContact.slice(0, 3);
    facts.push({
      signal: "free_webmail_contact",
      group: "fake_shop",
      value: samples,
      strength: 0.75,
      evidence: `Support/contact uses free webmail (${samples.join(", ")}) instead of a company domain`,
    });
  }

  // Presence-only content fact: HTML keyword scan for casino/betting vocabulary.
  // Complements semantic_gambling_language_detected for the Gambling KBS path.
  if (pageFindings.gamblingPhrasesPresent) {
    facts.push({
      signal: "gambling_phrases_present",
      group: "content",
      value: true,
      strength: 1,
      evidence: "Common gambling or betting phrases detected in page text (e.g. casino, slots, poker, bet)",
    });
  }

  // Parking keyword gate + optional infra / email footprints from utility probes
  if (pageFindings.parkingKeywordsPresent) {
    const clues = pageFindings.parkingKeywordClues ?? [];
    facts.push({
      signal: "parking_keywords_present",
      group: "structural",
      value: true,
      strength: 1,
      evidence:
        clues.length > 0
          ? `Parking / for-sale page phrases detected: ${clues.slice(0, 5).join(", ")}`
          : "Parking / for-sale page phrases detected in visible text",
    });
  }

  if (pageFindings.parkedNameServers) {
    const matched = pageFindings.parkedNameServers.matchedFootprints ?? [];
    facts.push({
      signal: "parked_nameservers_detected",
      group: "structural",
      value: matched,
      strength: 0.9,
      evidence:
        matched.length > 0
          ? `Name servers match known parking / marketplace footprints: ${matched.join(", ")}`
          : "Name servers match known parking / marketplace footprints",
    });
  }

  if (pageFindings.parkedIps) {
    const matched = pageFindings.parkedIps.matchedFootprints ?? [];
    facts.push({
      signal: "parked_ip_detected",
      group: "structural",
      value: matched,
      strength: 0.95,
      evidence:
        matched.length > 0
          ? `A records match known parking infrastructure IPs: ${matched.join(", ")}`
          : "A records match known parking infrastructure IPs",
    });
  }

  if (pageFindings.noEmailInfrastructure) {
    facts.push({
      signal: "no_email_infrastructure",
      group: "structural",
      value: true,
      strength: 0.7,
      evidence:
        "Domain has null MX and/or strictly restricted SPF (v=spf1 -all) — common on parked domains",
    });
  }

  return facts;
}

/**
 * @param {object|null|undefined} trustNavigation
 * @returns {ExtractedFact[]}
 */
function extractTrustNavigationFacts(trustNavigation) {
  if (!trustNavigation) return [];
  const facts = [];
  const status = trustNavigation.status;

  if (status === "missing") {
    facts.push({
      signal: "missing_trust_navigation",
      group: "trust",
      value: true,
      strength: 0.8,
      evidence:
        "No trust links or controls found (privacy, terms, help, security, contact, etc.)",
    });
  } else if (status === "broken") {
    const failures = trustNavigation.failures ?? [];
    facts.push({
      signal: "error_trust_navigation",
      group: "trust",
      value: failures.length > 0 ? failures : true,
      strength: 0.75,
      evidence:
        failures.length > 0
          ? `Trust controls present but none work: ${failures.join("; ")}`
          : "Trust controls present but none work (inert, non-navigable, or HTTP failure)",
    });
  }

  return facts;
}

/**
 * @param {string[]} derivedFacts
 * @returns {ExtractedFact[]}
 */
function extractSemanticFacts(derivedFacts) {
  return (derivedFacts ?? []).map((fact) => ({
    signal: fact,
    group: "semantic",
    value: true,
    strength: 1,
    evidence: `Semantic analyzer derived fact: ${fact}`,
  }));
}

/**
 * Composite TLS risk from presence-only TLS / URL insecurity signals.
 * @param {ExtractedFact[]} facts
 * @returns {ExtractedFact[]}
 */
function extractTlsRiskFacts(facts) {
  const names = new Set(facts.map((f) => f.signal));
  const reasons = [];
  if (names.has("no_https")) reasons.push("Page served over HTTP");
  if (names.has("insecure_connection")) reasons.push("No trusted secure connection");
  if (names.has("tls_is_expired")) reasons.push("TLS certificate is expired");
  if (names.has("tls_identity_mismatch")) reasons.push("TLS certificate identity mismatch");
  if (names.has("invalid_cert")) reasons.push("TLS certificate is invalid or expired");
  if (reasons.length === 0) return [];
  return [
    {
      signal: "tls_risk",
      group: "identity",
      value: true,
      strength: 1,
      evidence: reasons.join("; "),
    },
  ];
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Extract a flat list of structured facts from the raw tool outputs.
 * Facts are ordered: TLS → WHOIS → DNS → Geo.
 *
 * @param {import("../../collection/trust/heuristic.js").CollectedData|null} collectedData
 * @param {ExtractFactsOptions} [opts]
 * @returns {ExtractedFact[]}
 */
export function extractFacts(collectedData, { expectedCountry = null } = {}) {
  if (!collectedData) return [];
  return [
    ...extractTLSFacts(collectedData.tls),
    ...extractWhoisFacts(collectedData.whois),
    ...extractDNSFacts(collectedData.dns),
    ...extractGeoFacts(collectedData.geo, expectedCountry),
  ];
}

/**
 * Extract all initial KBS input facts from pipeline outputs.
 *
 * @param {ExtractInputFactsOptions} [inputs]
 * @returns {ExtractedFact[]}
 */
export function extractInputFacts({
  collectedData = null,
  pageFindings = null,
  htmlDocument = null,
  pageUrl = "",
  derivedFacts = [],
  expectedCountry = null,
  brandConfig = null,
  trustStatus = null,
} = {}) {
  /** @type {ExtractedFact[]} */
  const trustFacts = [];
  // High structural trust (≥60) — KBS may run Official phase; skips brand-dependent abuse.
  if (trustStatus === "TRUSTED_INFRA") {
    trustFacts.push({
      signal: "trusted_infra",
      group: "identity",
      value: true,
      strength: 1,
      evidence:
        "Heuristic trust score ≥ 60 — structurally trusted host (not necessarily brand-official)",
    });
  }

  const facts = [
    ...trustFacts,
    ...extractUrlFacts(pageUrl),
    ...extractFormStructureFacts(htmlDocument, pageUrl),
    ...extractPageUtilityFacts(pageFindings),
    ...extractTrustNavigationFacts(pageFindings?.trustNavigation),
    ...extractSemanticFacts(derivedFacts),
    ...extractFacts(collectedData, { expectedCountry }),
    ...extractBrandIdentityFacts(collectedData, brandConfig),
  ];

  // Deduplicate by signal name (first wins) so formActions + form structure don't double-assert
  /** @type {Map<string, ExtractedFact>} */
  const byName = new Map();
  for (const fact of facts) {
    if (!byName.has(fact.signal)) byName.set(fact.signal, fact);
  }
  const deduped = [...byName.values()];
  return [...deduped, ...extractTlsRiskFacts(deduped)];
}

/**
 * Assert a list of ExtractedFacts into KBS WorkingMemory.
 *
 * @param {{ assertSignal: Function }} wm
 * @param {ExtractedFact[]} facts
 */
export function assertExtractedSignals(wm, facts) {
  for (const fact of facts ?? []) {
    wm.assertSignal(fact.signal, {
      group: fact.group,
      strength: fact.strength,
      value: fact.value,
      evidence: Array.isArray(fact.evidence) ? fact.evidence : [String(fact.evidence)],
    });
  }
}

