import { fileURLToPath } from "url";

// Uses RDAP (Registration Data Access Protocol) over HTTPS.
// RDAP is the modern ICANN-standard replacement for WHOIS: structured JSON,
// fast, and works on port 443 — never blocked by firewalls.
const RDAP_BOOTSTRAP = "https://rdap.org/domain";

/**
 * @typedef {Object} WhoisData
 * @property {string|null}   createdDate    - ISO date the domain was registered
 * @property {string|null}   expiresDate    - ISO date the domain expires
 * @property {string|null}   registrar      - Registrar organization name
 * @property {string|null}   registrantOrg  - Registrant org (often privacy-protected)
 * @property {string[]}      domainStatus   - Array of ICANN EPP status codes
 * @property {number|null}   ageInDays      - Days since registration (null if unknown)
 */

/**
 * Look up RDAP/WHOIS data for a domain.
 * Returns null on timeout or lookup failure — callers must handle null gracefully.
 *
 * @param {string} domain  - Bare domain name, e.g. "github.com"
 * @returns {Promise<WhoisData|null>}
 */
export async function lookupWhois(domain) {
  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 8000);

    const res = await fetch(`${RDAP_BOOTSTRAP}/${domain}`, {
      signal: controller.signal,
    });
    clearTimeout(timer);

    if (!res.ok) return null;

    const data = await res.json();

    const events = data.events ?? [];
    const regEvent = events.find((e) => e.eventAction === "registration");
    const expEvent = events.find((e) => e.eventAction === "expiration");
    const createdDate = regEvent?.eventDate ?? null;
    const expiresDate = expEvent?.eventDate ?? null;

    const entities = data.entities ?? [];

    const registrarEntity = entities.find((e) => e.roles?.includes("registrar"));
    const registrar =
      registrarEntity?.vcardArray?.[1]?.find((v) => v[0] === "fn")?.[3] ?? null;

    const registrantEntity = entities.find((e) => e.roles?.includes("registrant"));
    const registrantOrg =
      registrantEntity?.vcardArray?.[1]?.find((v) => v[0] === "org")?.[3] ?? null;

    const domainStatus = data.status ?? [];

    const ageInDays = createdDate
      ? Math.floor((Date.now() - new Date(createdDate).getTime()) / (1000 * 60 * 60 * 24))
      : null;

    return { createdDate, expiresDate, registrar, registrantOrg, domainStatus, ageInDays };
  } catch {
    return null;
  }
}

// Self-run test block — only executes when run directly: node src/tools/whoisscraper.js
if (process.argv[1] === fileURLToPath(import.meta.url)) {
  for (const domain of ["github.com", "google.com"]) {
    const result = await lookupWhois(domain);
    console.log(`\n--- WHOIS/RDAP Data for ${domain} ---`);
    if (!result) {
      console.log("[ERROR] Lookup failed or timed out.");
    } else {
      console.log("Created Date    :", result.createdDate);
      console.log("Expires Date    :", result.expiresDate);
      console.log("Registrar       :", result.registrar);
      console.log("Registrant Org  :", result.registrantOrg ?? "N/A (privacy protected)");
      console.log("Domain Status   :", result.domainStatus.join(", ") || "N/A");
      if (result.ageInDays !== null) {
        if (result.ageInDays < 30) {
          console.log("⚠️  WARNING: Domain is extremely new! High risk of phishing.");
        } else {
          console.log(`Domain Age      : ~${result.ageInDays} days old`);
        }
      }
    }
  }
}
