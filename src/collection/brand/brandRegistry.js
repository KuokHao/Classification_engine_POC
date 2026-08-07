/**
 * Brand registry ingest — gather official-domain intel and upsert into local store.
 */

import { runIntelligenceGather } from "../trust/heuristic.js";
import { upsertBrand } from "./brandRepository.js";

/**
 * Slugify a brand name into a stable brandId (e.g. "U Mobile" → "umobile").
 * @param {string} brandName
 * @returns {string}
 */
export function toBrandId(brandName) {
  return String(brandName ?? "")
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "")
    .replace(/^-+|-+$/g, "");
}

/**
 * @param {string} value
 * @returns {string|null}
 */
function hostnameFrom(value) {
  if (!value || typeof value !== "string") return null;
  const trimmed = value.trim();
  try {
    const withProto = /^https?:\/\//i.test(trimmed)
      ? trimmed
      : `https://${trimmed}`;
    return new URL(withProto).hostname.replace(/^www\./i, "").toLowerCase();
  } catch {
    return trimmed
      .replace(/^https?:\/\//i, "")
      .split("/")[0]
      .replace(/^www\./i, "")
      .toLowerCase() || null;
  }
}

/**
 * Unique non-empty strings, order-preserving.
 * @param {Array<string|null|undefined>} values
 * @returns {string[]}
 */
function uniq(values) {
  const out = [];
  const seen = new Set();
  for (const v of values) {
    if (v == null) continue;
    const s = String(v).trim();
    if (!s) continue;
    const key = s.toLowerCase();
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(s);
  }
  return out;
}

/**
 * Most frequent non-null country string.
 * @param {Array<string|null|undefined>} countries
 * @returns {string|null}
 */
function modeCountry(countries) {
  /** @type {Map<string, number>} */
  const counts = new Map();
  for (const c of countries) {
    if (!c) continue;
    const key = String(c).trim();
    if (!key) continue;
    counts.set(key, (counts.get(key) ?? 0) + 1);
  }
  let best = null;
  let bestN = 0;
  for (const [k, n] of counts) {
    if (n > bestN) {
      best = k;
      bestN = n;
    }
  }
  return best;
}

/**
 * Register / refresh a brand profile from its official site + whitelist domains.
 * Persists via brandRepository (local JSON file).
 *
 * @param {Object} opts
 * @param {string} opts.brandName - Display name (also used for brandId slug)
 * @param {string} opts.officialSite - Primary official URL or hostname
 * @param {string[]} [opts.whitelistDomains] - Extra official domains
 * @param {string} [opts.logoPath]
 * @param {string[]} [opts.brandNames] - Extra aliases; brandName is always included
 * @returns {Promise<object>} Upserted brand document
 */
export async function registerBrand({
  brandName,
  officialSite,
  whitelistDomains = [],
  logoPath = null,
  brandNames = [],
}) {
  if (!brandName || !officialSite) {
    throw new Error("registerBrand requires brandName and officialSite");
  }

  const brandId = toBrandId(brandName);
  if (!brandId) {
    throw new Error("Could not derive brandId from brandName");
  }

  const primaryHost = hostnameFrom(officialSite);
  const domains = uniq([
    primaryHost,
    ...(Array.isArray(whitelistDomains) ? whitelistDomains.map(hostnameFrom) : []),
  ]);

  if (domains.length === 0) {
    throw new Error("No valid domains to gather from");
  }

  /** @type {object[]} */
  const domainIntel = [];
  const registrantOrganizations = [];
  const registrarNames = [];
  const registrarIds = [];
  const registrantCountries = [];

  for (const domain of domains) {
    const url = `https://${domain}`;
    const collected = await runIntelligenceGather(url);
    const whois = collected.whois;
    const geo = collected.geo;
    const tls = collected.tls;

    if (whois?.registrantOrg) registrantOrganizations.push(whois.registrantOrg);
    if (whois?.registrar) registrarNames.push(whois.registrar);
    if (whois?.registrarId) registrarIds.push(whois.registrarId);
    if (geo?.country) registrantCountries.push(geo.country);

    domainIntel.push({
      domain,
      whois: whois ?? null,
      tlsSummary: tls
        ? {
            usesHttps: tls.usesHttps,
            issuerLevel: tls.issuerLevel,
            authorized: tls.authorized,
            hostnameMismatch: tls.hostnameMismatch,
          }
        : null,
      geoCountry: geo?.country ?? null,
      gatheredAt: new Date().toISOString(),
    });
  }

  const names = uniq([brandName, ...brandNames, brandId]);
  const expectedCountry = modeCountry(registrantCountries);

  const doc = {
    brandId,
    brandNames: names,
    officialSite,
    officialDomains: domains,
    registrantOrganizations: uniq(registrantOrganizations),
    registrantCountries: uniq(registrantCountries),
    registrarNames: uniq(registrarNames),
    registrarIds: uniq(registrarIds),
    minRegistrationAgeDays: 365,
    expectedCountry,
    logoPath: logoPath || null,
    domainIntel,
  };

  return upsertBrand(doc);
}
