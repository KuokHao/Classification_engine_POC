/**
 * Domain trust evaluation — weighted scoring via TLS, WHOIS, DNS, and geo tools.
 *
 * Status meanings:
 *   OFFICIAL_SITE      — hostname is on the brand whitelist only (pipeline early-exit)
 *   TRUSTED_INFRA      — score ≥ 60: structurally healthy host; continue into KBS
 *                        (Official may still promote via org-identity rules)
 *   FLAGGED_SUSPICIOUS — score < 60: continue into full KBS abuse path
 *   REJECTED           — hard fail (no HTTPS, bad cert, tiny-young domain, …)
 *
 * collectedData is passed downstream to KBS when analysis continues.
 */

import { analyzeTLS } from "../intel/tlsScraper.js";
import { lookupWhois } from "../intel/whoisScraper.js";
import { checkDNS } from "../intel/dnsScraper.js";
import { geolocateIP } from "../intel/ipGeolocationScraper.js";
import { extractFacts } from "../../analysis/factExtractor.js";
import {
  findByBrandId,
  findByBrandName,
} from "../brand/brandRepository.js";
import { isOfficialSubdomain } from "../../analysis/pageFindings.js";

/**
 * @typedef {Object} BrandConfig
 * @property {string} id
 * @property {string} [brandId]
 * @property {string[]} brandNames
 * @property {string[]} officialDomains
 * @property {string|null} [expectedCountry]
 * @property {string} [logoPath] - Optional local path to official brand logo for image matching
 * @property {string[]} [registrantOrganizations] - WHOIS registrant orgs from official domains
 * @property {string[]} [tlsSubjectOrganizations] - TLS subject.O values from official OV/EV certs
 * @property {string[]} [registrarNames]
 * @property {string[]} [registrarIds]
 * @property {number} [minRegistrationAgeDays]
 */

/**
 * Pipeline scan payload — used for brand resolution and downstream KBS seeding.
 *
 * @typedef {Object} ScanData
 * @property {string} [brandId]
 * @property {string} [hostname]
 * @property {CollectedData} [collectedData]
 * @property {string} [screenshotPath]
 * @property {BrandConfig} [brandConfig]
 * @property {'REJECTED'|'FLAGGED_SUSPICIOUS'|'TRUSTED_INFRA'|'OFFICIAL_SITE'} [trustStatus]
 * @property {number} [trustScore]
 */

function isEmptyValue(value) {
  if (value == null) {
    return true;
  }
  const s = String(value).trim();
  return s === "" || s.toLowerCase() === "null";
}

function normalizeScanData(scanData) {
  if (scanData == null || typeof scanData !== "object") {
    return {};
  }
  return { ...scanData };
}

/**
 * Map a stored brand document to the BrandConfig shape used by the pipeline/KBS.
 * @param {object|null} doc
 * @returns {BrandConfig|null}
 */
function toBrandConfig(doc) {
  if (!doc) return null;
  const id = doc.brandId || doc.id;
  if (!id) return null;
  return {
    id,
    brandId: id,
    brandNames: Array.isArray(doc.brandNames) ? doc.brandNames : [],
    officialDomains: Array.isArray(doc.officialDomains)
      ? doc.officialDomains
      : [],
    expectedCountry: doc.expectedCountry ?? null,
    logoPath: doc.logoPath ?? undefined,
    registrantOrganizations: Array.isArray(doc.registrantOrganizations)
      ? doc.registrantOrganizations
      : [],
    tlsSubjectOrganizations: Array.isArray(doc.tlsSubjectOrganizations)
      ? doc.tlsSubjectOrganizations
      : [],
    registrarNames: Array.isArray(doc.registrarNames) ? doc.registrarNames : [],
    registrarIds: Array.isArray(doc.registrarIds) ? doc.registrarIds : [],
    minRegistrationAgeDays: doc.minRegistrationAgeDays ?? 365,
  };
}

/**
 * Resolve brand profile from the local brand store (data/brands.json).
 *
 * Order: brandId → exact brandName → userInput as brand name / id.
 *
 * @param {string} userInput
 * @param {ScanData} [scanData]
 * @returns {Promise<BrandConfig | null>}
 */
export async function getBrandConfig(userInput, scanData) {
  const data = normalizeScanData(scanData ?? {});

  if (!isEmptyValue(data.brandId)) {
    const byId = await findByBrandId(String(data.brandId));
    if (byId) return toBrandConfig(byId);
  }

  const hint = String(userInput ?? "").trim();
  if (hint) {
    const byName = await findByBrandName(hint);
    if (byName) return toBrandConfig(byName);

    // Slug of full hint: "U Mobile" → "umobile"
    const slug = hint.toLowerCase().replace(/[^a-z0-9]+/g, "");
    if (slug) {
      const bySlug = await findByBrandId(slug);
      if (bySlug) return toBrandConfig(bySlug);
    }

    // Token scan: "umobile phishing" → try brandId "umobile"
    const tokens = hint.toLowerCase().split(/[^a-z0-9]+/).filter(Boolean);
    for (const token of tokens) {
      const byToken = await findByBrandId(token);
      if (byToken) return toBrandConfig(byToken);
      const byTokenName = await findByBrandName(token);
      if (byTokenName) return toBrandConfig(byTokenName);
    }
  }

  return null;
}

/**
 * @typedef {Object} CollectedData
 * @property {import("../tools/tlsscraper.js").TLSAnalysis|null}  tls
 * @property {import("../tools/whoisscraper.js").WhoisData|null}  whois
 * @property {import("../tools/dnsscraper.js").DNSData|null}      dns
 * @property {import("../tools/ipgeolocationscraper.js").GeoData|null} geo
 */

/**
 * @typedef {Object} TrustResult
 * @property {'REJECTED'|'FLAGGED_SUSPICIOUS'|'TRUSTED_INFRA'|'OFFICIAL_SITE'} status
 * @property {number}        score          - 0–100 final trust score
 * @property {string}        reason         - Human-readable decision summary
 * @property {string[]}      flags          - Individual rules that fired
 * @property {CollectedData} collectedData  - Raw tool outputs for downstream use
 * @property {import("./factExtractor.js").ExtractedFact[]} extractedFacts - Structured facts for display and KBS seeding
 */

/**
 * Run all four intelligence tools in parallel against a URL.
 *
 * @param {string} url
 * @returns {Promise<CollectedData>}
 */
export async function runIntelligenceGather(url) {
  let hostname = "";
  try {
    hostname = new URL(url).hostname;
  } catch {
    hostname = url;
  }

  const [tlsResult, whoisResult, dnsResult, geoResult] = await Promise.allSettled([
    analyzeTLS(url),
    lookupWhois(hostname),
    checkDNS(hostname),
    geolocateIP(hostname),
  ]);

  return {
    tls: tlsResult.status === "fulfilled" ? tlsResult.value : null,
    whois: whoisResult.status === "fulfilled" ? whoisResult.value : null,
    dns: dnsResult.status === "fulfilled" ? dnsResult.value : null,
    geo: geoResult.status === "fulfilled" ? geoResult.value : null,
  };
}

/**
 * Apply the weighted scoring model to collected tool outputs.
 *
 * Starts at 100; auto-fails drop to 0 (REJECTED).
 * Score ≥ 60 → TRUSTED_INFRA (structurally healthy — not brand-Official).
 * Score < 60 → FLAGGED_SUSPICIOUS.
 *
 * Brand Official is never decided here unless the caller already whitelist-matched.
 *
 * @param {CollectedData} collectedData
 */
function scoreTrust(collectedData) {
  const { tls, whois, dns, geo } = collectedData;
  const flags = [];

  if (!tls || !tls.usesHttps) {
    return { score: 0, status: "REJECTED", reason: "URL does not use HTTPS", flags: ["no_https"] };
  }
  if (tls.isExpired) {
    return {
      score: 0,
      status: "REJECTED",
      reason: `TLS certificate expired on ${tls.validTo}`,
      flags: ["cert_expired"],
    };
  }
  if (!tls.authorized) {
    return {
      score: 0,
      status: "REJECTED",
      reason: `TLS certificate is invalid: ${tls.error ?? "unknown error"}`,
      flags: ["tls_invalid_cert"],
    };
  }
  if (tls.hostnameMismatch) {
    return {
      score: 0,
      status: "REJECTED",
      reason: "TLS cert subject does not match hostname",
      flags: ["hostname_mismatch"],
    };
  }
  if (whois && whois.ageInDays !== null && whois.ageInDays < 14) {
    return {
      score: 0,
      status: "REJECTED",
      reason: `Domain is only ${whois.ageInDays} day(s) old — below the 14-day minimum`,
      flags: ["domain_too_young"],
    };
  }

  let score = 100;

  if (tls.issuerLevel === "DV") {
    score -= 30;
    flags.push("tls_cert_dv");
  }

  if (!whois) {
    score -= 10;
    flags.push("whois_unavailable");
  }

  if (!dns) {
    score -= 15;
    flags.push("dns_unavailable");
  } else if (!dns.hasMX) {
    score -= 20;
    flags.push("no_mx_records");
  }

  if (!geo) {
    score -= 5;
    flags.push("geo_unavailable");
  } else if (geo.isBulletproof) {
    score -= 25;
    flags.push("bulletproof_hosting");
  }

  if (tls.issuerLevel === "OV" || tls.issuerLevel === "EV") {
    score += 20;
    flags.push(`tls_cert_${tls.issuerLevel.toLowerCase()}`);
  }
  if (whois && whois.ageInDays !== null && whois.ageInDays > 1825) {
    score += 10;
    flags.push("established_domain");
  }

  score = Math.min(100, Math.max(0, score));

  // High infra trust ≠ brand Official. KBS decides Official via org identity.
  if (score >= 60) {
    return {
      score,
      status: "TRUSTED_INFRA",
      reason:
        "Passed structural trust scoring (not brand-official unless whitelist/org match)",
      flags,
    };
  }
  return { score, status: "FLAGGED_SUSPICIOUS", reason: "Trust score below threshold", flags };
}

/**
 * @typedef {Object} EvaluateDomainTrustOptions
 * @property {string[]} [whitelistedDomains]
 */

/**
 * Evaluate the trustworthiness of a URL.
 *
 * OFFICIAL_SITE is returned only for brand-whitelist hits.
 * All other outcomes continue into the classification pipeline / KBS.
 *
 * @param {string} url
 * @param {EvaluateDomainTrustOptions} [options]
 * @returns {Promise<TrustResult>}
 */
export async function evaluateDomainTrust(url, { whitelistedDomains = [] } = {}) {
  let hostname = "";
  try {
    hostname = new URL(url).hostname;
  } catch {
    hostname = url;
  }

  // Whitelist only: exact official domain or subdomain → Official early-exit.
  if (
    whitelistedDomains.length > 0 &&
    whitelistedDomains.some((d) => isOfficialSubdomain(url || hostname, d))
  ) {
    return {
      status: "OFFICIAL_SITE",
      score: 100,
      reason: `Hostname "${hostname}" is the official domain or a subdomain of a brand whitelist entry`,
      flags: ["whitelist_match"],
      collectedData: { tls: null, whois: null, dns: null, geo: null },
      extractedFacts: [],
    };
  }

  const collectedData = await runIntelligenceGather(url);
  const { score, status, reason, flags } = scoreTrust(collectedData);
  const extractedFacts = extractFacts(collectedData);

  return { status, score, reason, flags, collectedData, extractedFacts };
}
