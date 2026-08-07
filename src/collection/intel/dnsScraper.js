import { promises as dns } from "node:dns";
import { fileURLToPath } from "url";

/**
 * @typedef {Object} DNSData
 * @property {string[]}                                aRecords   - IPv4 A records
 * @property {{ exchange: string, priority: number }[]} mxRecords  - MX records
 * @property {boolean}                                 hasMX      - Whether any MX records exist
 */

/**
 * Check DNS infrastructure for a domain (A records + MX records).
 * Uses Promise.allSettled so a failure on one record type does not mask the other.
 *
 * @param {string} domain  - Bare domain name, e.g. "github.com"
 * @returns {Promise<DNSData>}
 */
export async function checkDNS(domain) {
  const [aResult, mxResult] = await Promise.allSettled([
    dns.resolve4(domain),
    dns.resolveMx(domain),
  ]);

  const aRecords = aResult.status === "fulfilled" ? aResult.value : [];
  const mxRecords = mxResult.status === "fulfilled" ? mxResult.value : [];

  return {
    aRecords,
    mxRecords,
    hasMX: mxRecords.length > 0,
  };
}

// Self-run test block — only executes when run directly: node src/tools/dnsscraper.js
if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const result = await checkDNS("github.com");
  console.log("\n--- Infrastructure Data for github.com ---");
  console.log("Hosting IP Addresses:", result.aRecords);
  console.log("Mail Servers (MX)   :", result.mxRecords);
  if (!result.hasMX) {
    console.log("WARNING: No MX records found. Unlikely to be a legitimate corporate domain.");
  }
}
