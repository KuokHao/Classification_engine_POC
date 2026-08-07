import tls from "tls";
import { fileURLToPath } from "url";

/**
 * @typedef {Object} TLSAnalysis
 * @property {boolean}                       usesHttps       - URL uses HTTPS protocol
 * @property {boolean}                       authorized      - Certificate chain trusted by Node
 * @property {string|null}                   error           - Authorization error message if any
 * @property {string|null}                   subjectCN       - Certificate subject Common Name
 * @property {string|null}                   issuerOrg       - Issuer organization name
 * @property {'EV'|'OV'|'DV'|'unknown'}     issuerLevel     - Certificate validation level
 * @property {string|null}                   validTo         - Certificate expiry date string
 * @property {boolean}                       isExpired       - Whether the certificate is expired
 * @property {boolean}                       hostnameMismatch - Whether hostname does not match cert
 */

/**
 * Analyze the TLS certificate for a URL.
 *
 * Uses rejectUnauthorized: false so expired / self-signed certs can still be
 * inspected rather than just failing — socket.authorized captures the real result.
 *
 * @param {string} targetUrl
 * @returns {Promise<TLSAnalysis>}
 */
export async function analyzeTLS(targetUrl) {
  let parsedUrl;
  try {
    parsedUrl = new URL(targetUrl);
  } catch {
    return makeErrorResult({ usesHttps: false, error: "Invalid URL" });
  }

  if (parsedUrl.protocol !== "https:") {
    return makeErrorResult({ usesHttps: false, error: "URL does not use HTTPS" });
  }

  const hostname = parsedUrl.hostname;
  const port = parseInt(parsedUrl.port, 10) || 443;

  return new Promise((resolve) => {
    const socket = tls.connect(
      {
        host: hostname,
        port,
        servername: hostname,
        timeout: 8000,
        rejectUnauthorized: false,
      },
      () => {
        const authorized = socket.authorized;
        const authError = socket.authorizationError
          ? String(socket.authorizationError)
          : null;
        const cert = socket.getPeerCertificate();
        socket.end();

        if (!cert || !cert.subject) {
          return resolve(
            makeErrorResult({ authorized, error: authError ?? "No certificate returned" }),
          );
        }

        const subjectCN = cert.subject?.CN ?? null;
        const issuerOrg = cert.issuer?.O ?? cert.issuer?.CN ?? null;

        // EV: businessCategory or jurisdictionC set on subject
        // OV: subject.O set (org validated but not EV)
        // DV: domain-only, neither of the above
        let issuerLevel = "DV";
        if (cert.subject.businessCategory || cert.subject.jurisdictionC) {
          issuerLevel = "EV";
        } else if (cert.subject.O) {
          issuerLevel = "OV";
        }

        const validTo = cert.valid_to ?? null;
        const isExpired = validTo ? new Date(validTo) < new Date() : false;

        // Hostname mismatch: check SAN entries first, fall back to CN
        const san = cert.subjectaltname ?? "";
        const sanHosts = san
          .split(",")
          .map((s) => s.trim().replace(/^DNS:/i, "").toLowerCase())
          .filter(Boolean);

        const h = hostname.toLowerCase();
        const matchesSAN = sanHosts.some((sanHost) => {
          if (sanHost.startsWith("*.")) {
            const base = sanHost.slice(2);
            return h === base || h.endsWith(`.${base}`);
          }
          return sanHost === h;
        });
        const matchesCN = subjectCN ? subjectCN.toLowerCase() === h : false;
        // If SANs exist, only SANs count (RFC 6125)
        const hostnameMismatch = sanHosts.length > 0 ? !matchesSAN : !matchesCN;

        resolve({
          usesHttps: true,
          authorized,
          error: authError,
          subjectCN,
          issuerOrg,
          issuerLevel,
          validTo,
          isExpired,
          hostnameMismatch,
        });
      },
    );

    socket.on("timeout", () => {
      socket.destroy();
      resolve(makeErrorResult({ error: "Connection timed out" }));
    });

    socket.on("error", (err) => {
      resolve(makeErrorResult({ error: err.message }));
    });
  });
}

/**
 * Build a failed/unavailable TLS result with safe defaults.
 * @param {{ usesHttps?: boolean, authorized?: boolean, error?: string }} overrides
 * @returns {TLSAnalysis}
 */
function makeErrorResult({ usesHttps = true, authorized = false, error = null } = {}) {
  return {
    usesHttps,
    authorized,
    error,
    subjectCN: null,
    issuerOrg: null,
    issuerLevel: "unknown",
    validTo: null,
    isExpired: false,
    hostnameMismatch: false,
  };
}

// Self-run test block — only executes when run directly: node src/tools/tlsscraper.js
if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const result = await analyzeTLS("https://github.com");
  console.log("\n--- TLS Analysis for github.com ---");
  console.log(JSON.stringify(result, null, 2));

  const result2 = await analyzeTLS("http://example.com");
  console.log("\n--- TLS Analysis for http://example.com ---");
  console.log(JSON.stringify(result2, null, 2));
}
