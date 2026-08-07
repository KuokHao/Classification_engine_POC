import { promises as dns } from "node:dns";
import { fileURLToPath } from "url";

const BULLETPROOF_KEYWORDS = ["bulletproof", "offshore", "anonymous-host", "sh3lls"];

/**
 * @typedef {Object} GeoData
 * @property {string|null}  ip           - Primary IP address resolved for the domain
 * @property {string|null}  country      - Country where the IP is hosted
 * @property {string|null}  city         - City where the IP is hosted
 * @property {string|null}  isp          - ISP / hosting provider name
 * @property {string|null}  asn          - ASN string, e.g. "AS8075 Microsoft Corporation"
 * @property {boolean}      isBulletproof - Whether ISP name matches known bulletproof keywords
 */

/**
 * Resolve the primary IP for a domain and look up its geolocation.
 * Returns null on DNS failure, timeout, or API error — callers must handle null gracefully.
 *
 * @param {string} domain  - Bare domain name, e.g. "github.com"
 * @returns {Promise<GeoData|null>}
 */
export async function geolocateIP(domain) {
  let primaryIp;
  try {
    const addresses = await dns.resolve4(domain);
    primaryIp = addresses[0];
    if (!primaryIp) return null;
  } catch {
    return null;
  }

  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 8000);

    const response = await fetch(
      `http://ip-api.com/json/${primaryIp}?fields=status,message,country,city,isp,org,as`,
      { signal: controller.signal },
    );
    clearTimeout(timer);

    const geoData = await response.json();
    if (geoData.status !== "success") return null;

    const ispLower = (geoData.isp ?? "").toLowerCase();
    const isBulletproof = BULLETPROOF_KEYWORDS.some((kw) => ispLower.includes(kw));

    return {
      ip: primaryIp,
      country: geoData.country ?? null,
      city: geoData.city ?? null,
      isp: geoData.isp ?? null,
      asn: geoData.as ?? null,
      isBulletproof,
    };
  } catch {
    return null;
  }
}

// Self-run test block — only executes when run directly: node src/tools/ipgeolocationscraper.js
if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const result = await geolocateIP("github.com");
  if (!result) {
    console.log("\n[ERROR] Geolocation lookup failed.");
  } else {
    console.log(`\n--- Geolocation for ${result.ip} (github.com) ---`);
    console.log("Country :", result.country);
    console.log("City    :", result.city);
    console.log("ISP     :", result.isp);
    console.log("ASN     :", result.asn);
    if (result.isBulletproof) {
      console.log("WARNING: Hosting provider is flagged as bulletproof hosting.");
    }
  }
}
