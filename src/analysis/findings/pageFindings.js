import { parse } from "node-html-parser";
import axios from "axios";
import dns from "node:dns/promises";

// ---------------------------------------------------------------------------
// Trust navigation constants
// ---------------------------------------------------------------------------

const TRUST_CATEGORIES = [
  "privacy",
  "policy",
  "terms",
  "help",
  "security",
  "support",
  "services",
  "contact",
];

const TRUST_PATTERNS = {
  privacy: /\bprivacy(?:\s+policy)?\b/i,
  policy: /\bpolicies?\b/i,
  terms:
    /\bterms(?:\s+(?:of\s+(?:service|use)|and\s+conditions|conditions))?\b/i,
  help: /\bhelp(?:\s+(?:center|centre|desk|page))?\b/i,
  security: /\bsecurity\b/i,
  support: /\bsupport\b/i,
  services: /\bservices?\b/i,
  contact: /\bcontact(?:\s+us)?\b|\bcustomer\s+(?:service|support)\b/i,
};

/** Timeout in milliseconds for each HTTP probe request. */
const PROBE_TIMEOUT_MS = 6000;

const TRUST_PROBE_UA =
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36";

/**
 * Escape special characters so a string is safe inside a RegExp.
 * @param {string} string
 * @returns {string}
 */
function escapeRegExp(string) {
  return String(string).replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

/**
 * Exact brand token match (case-insensitive).
 * Rejects substrings inside other words (`jiuyoumobile`) and domain labels
 * (`umobile.com`) — brand must not be adjacent to letters, digits, `_`, or `.`.
 *
 * @param {string} text
 * @param {string} brandName
 * @returns {boolean}
 */
function containsBrand(text, brandName) {
  if (!text || !brandName) return false;

  const brand = String(brandName).trim();
  if (!brand) return false;

  // (?<![\w.]) brand (?![\w.]) — not glued to a word or a domain label
  const brandRegex = new RegExp(
    `(?<![\\w.])${escapeRegExp(brand)}(?![\\w.])`,
    "i",
  );
  return brandRegex.test(String(text));
}

/** Attributes where a brand claim is meaningful for spoofing / impersonation. */
const BRAND_MARKUP_ATTRS = new Set([
  "alt",
  "aria-label",
  "aria-labelledby",
  "title",
  "content",
  "class",
  "id",
  "name",
  "value",
  "property",
  "href",
  "src",
  "srcset",
  "data-src",
  "action",
  "poster",
]);

/**
 * Brand mention in HTML **markup** (attributes / comments), not body text.
 * Uses {@link containsBrand} so `jiuyoumobile` does not count as `umobile`.
 * Prefer {@link containsBrandName} for visible text.
 *
 * @param {string} htmlString
 * @param {string} brandName
 * @returns {boolean}
 */
function brandInMarkup(htmlString, brandName) {
  if (!htmlString || !brandName) return false;

  const commentRe = /<!--([\s\S]*?)-->/g;
  let cm;
  while ((cm = commentRe.exec(htmlString)) !== null) {
    if (containsBrand(cm[1], brandName)) return true;
  }

  try {
    const root = parse(htmlString, {
      lowerCaseTagName: false,
      comment: false,
      blockTextElements: { script: true, style: true, noscript: true },
    });

    for (const el of root.querySelectorAll("*")) {
      const attribs = el.attributes ?? {};
      for (const [key, val] of Object.entries(attribs)) {
        const keyLower = key.toLowerCase();
        const isTarget =
          BRAND_MARKUP_ATTRS.has(keyLower) || keyLower.startsWith("data-");
        if (!isTarget) continue;

        if (containsBrand(val, brandName) || containsBrand(key, brandName)) {
          return true;
        }
      }
    }

    return false;
  } catch {
    // Keep tags/attrs; drop text nodes between tags
    const markupOnly = String(htmlString).replace(/>([^<]*)</g, "><");
    return containsBrand(markupOnly, brandName);
  }
}

/**
 * Brand mention in visible HTML text content (tags stripped).
 *
 * @param {string} htmlString
 * @param {string} brandName
 * @returns {boolean}
 */
function containsBrandName(htmlString, brandName) {
  if (!htmlString || !brandName) return false;
  const textContent = String(htmlString).replace(/<[^>]*>?/gm, " ");
  return containsBrand(textContent, brandName);
}

/**
 * Brand token as a hostname **label** (or hyphen/underscore part of a label).
 * Exact parts only — `jiuyoumobile.com.cn` does not match `umobile`.
 *
 * @param {string} hostnameOrUrl
 * @param {string} brandName
 * @returns {boolean}
 */
function brandInHostname(hostnameOrUrl, brandName) {
  if (!hostnameOrUrl || !brandName) return false;

  let hostname = String(hostnameOrUrl).toLowerCase();
  try {
    hostname = new URL(
      hostname.includes("://") ? hostnameOrUrl : `https://${hostnameOrUrl}`,
    ).hostname.toLowerCase();
  } catch {
    hostname = hostname.replace(/^https?:\/\//, "").split("/")[0];
  }

  const labels = hostname.split(".").filter(Boolean);
  if (labels.length === 0) return false;

  const tokens = [
    ...new Set(
      String(brandName)
        .toLowerCase()
        .split(/[^a-z0-9]+/)
        .filter((t) => t.length >= 2),
    ),
  ];
  if (tokens.length === 0) return false;

  return tokens.some((token) =>
    labels.some((label) => {
      if (label === token) return true;
      // login-umobile.evil.test → parts include "umobile"
      return label.split(/[-_]+/).some((part) => part === token);
    }),
  );
}

/**
 * Scans an HTML string for inputs related to passwords, usernames, OTPs, financials,
 * and personal identification (passports, national IDs).
 *
 * @param {string} htmlString - The raw HTML string to search through.
 * @returns {object} - An object containing boolean flags for each category found.
 */
function detectSensitiveInputs(htmlString) {
  const results = {
    hasPassword: false,
    hasUsername: false,
    hasOTP: false,
    hasFinancial: false,
    hasIdentity: false, // Added flag for Passport and ID numbers
  };

  if (!htmlString || typeof htmlString !== "string") return results;

  // 1. Match all <input ... > tags in the HTML string
  const inputTagRegex = /<input[^>]*>/gi;
  const inputTags = htmlString.match(inputTagRegex) || [];

  // 2. Loop through each found input tag
  for (const tag of inputTags) {
    const lowerTag = tag.toLowerCase();

    // -- PASSWORD CHECK --
    if (
      /type\s*=\s*['"]?password['"]?/.test(lowerTag) ||
      /(name|id|autocomplete)\s*=\s*['"]?(password|pass|pwd|pin)['"]?/.test(
        lowerTag,
      )
    ) {
      results.hasPassword = true;
    }

    // -- USERNAME / LOGIN CHECK --
    if (
      /(name|id|autocomplete)\s*=\s*['"]?(username|userid|user_name|login|email)['"]?/.test(
        lowerTag,
      )
    ) {
      results.hasUsername = true;
    }

    // -- OTP / 2FA CHECK --
    if (
      /(name|id|autocomplete)\s*=\s*['"]?(otp|mfa|one-time-code|verification_code|2fa|auth_code)['"]?/.test(
        lowerTag,
      )
    ) {
      results.hasOTP = true;
    }

    // -- FINANCIAL CHECK --
    if (
      /(name|id|autocomplete)\s*=\s*['"]?(cc-number|cardnumber|card-number|cvv|cvc|accountnumber|routingnumber|cc-csc|cc-exp|bank_account)['"]?/.test(
        lowerTag,
      )
    ) {
      results.hasFinancial = true;
    }

    // -- IDENTITY & PASSPORT CHECK --
    // Looks for Passports, Social Security Numbers (SSN), National IDs, NRIC, etc.
    if (
      /(name|id|autocomplete)\s*=\s*['"]?(passport|passport_number|passportno|ssn|social_security|national_id|id_number|idcard|nric|identity_number|document_number)['"]?/.test(
        lowerTag,
      )
    ) {
      results.hasIdentity = true;
    }
  }

  return results;
}

/**
 * Scans an HTML string to detect if there is a file upload input.
 *
 * @param {string} htmlString - The raw HTML string to search through.
 * @returns {boolean} - True if a file upload input is found, false otherwise.
 */
function hasFileUpload(htmlString) {
  if (!htmlString || typeof htmlString !== "string") return false;

  // Looks for an <input> tag that contains type="file" anywhere inside it.
  // Handles single quotes, double quotes, no quotes, and varied spacing.
  const fileInputRegex = /<input[^>]*type\s*=\s*['"]?file['"]?[^>]*>/i;

  return fileInputRegex.test(htmlString);
}

/**
 * Analyzes an HTML string to determine if its form actions are pointing
 * to suspicious destinations (potential phishing).
 *
 * @param {string} htmlString - The raw HTML string to analyze.
 * @param {string} expectedDomain - The legitimate domain the user expects to be on (e.g., 'example.com').
 * @returns {object} - An object detailing if the forms are suspicious.
 */
function analyzeFormActions(htmlString, expectedDomain) {
  const results = {
    hasForms: false,
    suspiciousActions: [],
    isLikelyPhishing: false,
  };

  if (!htmlString || !expectedDomain) return results;

  // Clean the expected domain to make comparisons easier (strip www.)
  const cleanExpectedDomain = expectedDomain
    .toLowerCase()
    .replace(/^www\./, "");

  // 1. Find all <form> tags
  const formRegex = /<form[^>]*>/gi;
  const forms = htmlString.match(formRegex) || [];

  if (forms.length > 0) results.hasForms = true;

  // 2. Loop through each form to check its action attribute
  for (const form of forms) {
    const actionMatch = form.match(/action\s*=\s*['"]([^'"]*)['"]/i);

    // If there is no action attribute, it defaults to the current page URL, which is safe.
    if (!actionMatch) continue;

    const actionUrl = actionMatch[1].trim();

    // Relative URLs (e.g., "/login", "?step=2") send data back to the same domain. Safe.
    if (
      actionUrl === "" ||
      actionUrl.startsWith("/") ||
      actionUrl.startsWith("?") ||
      actionUrl.startsWith("#")
    ) {
      continue;
    }

    // Evaluate absolute URLs (e.g., "https://malicious-site.ru/login")
    try {
      const parsedUrl = new URL(actionUrl);
      const actionHostname = parsedUrl.hostname
        .toLowerCase()
        .replace(/^www\./, "");

      // FLAG 1: Cross-Domain Submission
      // The action points to a different domain than expected (not an exact match or valid subdomain).
      if (
        actionHostname !== cleanExpectedDomain &&
        !actionHostname.endsWith(`.${cleanExpectedDomain}`)
      ) {
        results.suspiciousActions.push({
          action: actionUrl,
          reason: "Cross-domain submission (data sent to external site)",
        });
        results.isLikelyPhishing = true;
      }

      // FLAG 2: IP Address Submission
      // Legitimate companies use domain names, not raw IP addresses.
      const isIPAddress = /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/.test(
        actionHostname,
      );
      if (isIPAddress) {
        results.suspiciousActions.push({
          action: actionUrl,
          reason: "Submits to a raw IP address instead of a domain",
        });
        results.isLikelyPhishing = true;
      }
    } catch (error) {
      // URL parsing failed. It could be a javascript: URI or malformed string.
      if (actionUrl.toLowerCase().startsWith("javascript:")) {
        results.suspiciousActions.push({
          action: actionUrl,
          reason: "Uses inline JavaScript execution in the action attribute",
        });
        // We don't automatically flag as phishing, as some older legit sites do this,
        // but it is heavily frowned upon and worth noting.
      }
    }
  }

  return results;
}

/**
 * Checks if a given URL or domain is a valid subdomain of the official domain.
 *
 * @param {string} testString - The URL or domain to test (e.g., 'https://login.paypal.com/auth').
 * @param {string} officialDomain - The legitimate root domain (e.g., 'paypal.com').
 * @returns {boolean} - True if it is the official domain or a valid subdomain, false otherwise.
 */
function isOfficialSubdomain(testString, officialDomain) {
  if (!testString || !officialDomain) return false;

  const getHostname = (input) => {
    try {
      return new URL(input).hostname.toLowerCase();
    } catch (e) {
      try {
        return new URL("http://" + input).hostname.toLowerCase();
      } catch (err) {
        return "";
      }
    }
  };

  const testHost = getHostname(testString);
  let officialHost = getHostname(officialDomain);

  officialHost = officialHost.replace(/^www\./, "");

  if (!testHost || !officialHost) return false;

  if (testHost === officialHost) {
    return true;
  }

  if (testHost.endsWith("." + officialHost)) {
    return true;
  }

  return false;
}

/**
 * Scans an HTML string for a <meta http-equiv="refresh"> tag,
 * which forces the browser to redirect to another URL.
 *
 * @param {string} htmlString - The raw HTML string to analyze.
 * @returns {object} - Details about the redirect if found.
 */
function checkHtmlMetaRedirect(htmlString) {
  const results = {
    hasMetaRedirect: false,
    delaySeconds: 0,
    targetUrl: null,
  };

  if (!htmlString || typeof htmlString !== "string") return results;

  // 1. Look for a meta tag with http-equiv="refresh"
  const metaRefreshRegex =
    /<meta[^>]*http-equiv\s*=\s*['"]?refresh['"]?[^>]*>/i;
  const metaTagMatch = htmlString.match(metaRefreshRegex);

  if (!metaTagMatch) return results;

  const metaTag = metaTagMatch[0];

  // 2. Extract the content attribute which holds the delay and the URL
  // Example: content="0; url=https://malicious-site.com"
  const contentRegex =
    /content\s*=\s*['"]?([0-9]+)\s*;\s*url\s*=\s*([^'"]+)['"]?/i;
  const contentMatch = metaTag.match(contentRegex);

  if (contentMatch) {
    results.hasMetaRedirect = true;
    results.delaySeconds = parseInt(contentMatch[1], 10);
    results.targetUrl = contentMatch[2].trim();
  }

  return results;
}

/**
 * Checks if visiting a specific URL results in an HTTP redirect to another domain.
 * Legitimate subdomains of the official domain are not flagged as cross-domain.
 *
 * @param {string} initialUrl - The URL you want to visit.
 * @param {string} [officialDomain] - Expected root domain (defaults to the initial URL's domain).
 * @returns {Promise<object>} - An object detailing if a redirect occurred.
 */
async function checkDomainRedirect(initialUrl, officialDomain) {
  let baseDomain;

  try {
    baseDomain =
      officialDomain || new URL(initialUrl).hostname.replace(/^www\./, "");
  } catch (error) {
    return {
      error: "Invalid URL.",
      message: "Could not parse initialUrl.",
    };
  }

  try {
    const response = await fetch(initialUrl);
    const finalUrl = response.url;
    const isCrossDomain =
      response.redirected && !isOfficialSubdomain(finalUrl, baseDomain);

    return {
      wasRedirected: response.redirected,
      isCrossDomain,
      initialDomain: baseDomain,
      finalUrl,
    };
  } catch (error) {
    return {
      error:
        "Failed to fetch URL. The domain may not exist, the request timed out, TLS failed, or a redirect target is unreachable.",
      message: error.message,
    };
  }
}

/**
 * Traces a URL for HTTP, Meta, and JavaScript redirects.
 *
 * @param {string} initialUrl - The starting URL.
 * @param {string} [officialDomain] - Expected root domain.
 * @returns {Promise<object>} - A flattened report of the redirect chain.
 */
async function checkRedirects(initialUrl, officialDomain) {
  if (!initialUrl) return { error: "initialUrl is required." };

  // Determine base domain (assumes your isOfficialSubdomain function is available)
  let baseDomain;
  try {
    baseDomain =
      officialDomain || new URL(initialUrl).hostname.replace(/^www\./, "");
  } catch {
    return { error: "Could not parse initialUrl." };
  }

  const result = {
    initialUrl,
    officialDomain: baseDomain,
    wasRedirected: false,
    isCrossDomain: false,
    redirectTypes: [], // Populates with 'http', 'meta', and/or 'javascript'
    targets: [], // A complete list of URLs the user is bounced through
  };

  let currentUrl = initialUrl;
  let html = "";

  try {
    // FIX 1: Track HTTP redirects step-by-step.
    // By intercepting the 3xx status, we capture the Location header BEFORE fetch
    // attempts to hit it. If the target is unreachable, we already have the evidence.
    let response = await fetch(currentUrl, { redirect: "manual" });

    while (response.status >= 300 && response.status < 400) {
      const location = response.headers.get("location");
      if (!location) break;

      result.wasRedirected = true;
      if (!result.redirectTypes.includes("http"))
        result.redirectTypes.push("http");

      // Resolve relative redirects (e.g., Location: /login) against the current URL
      currentUrl = new URL(location, currentUrl).href;
      result.targets.push(currentUrl);

      // Fetch the next hop
      response = await fetch(currentUrl, { redirect: "manual" });
    }

    // Once HTTP redirects are exhausted, grab the final page HTML
    if (response.ok) {
      html = await response.text();
    }
  } catch (error) {
    // If the initial URL is completely dead, fetch throws.
    // However, if an HTTP *redirect target* was dead, we've already logged
    // the malicious URL into result.targets before the loop crashed!
    if (!result.wasRedirected) {
      return { error: `Network error: ${error.message}` };
    }
  }

  // FIX 2: Scan HTML for Meta Refresh AND JavaScript Redirects
  if (html) {
    const clientRedirects = extractClientSideRedirects(html, currentUrl);

    for (const { url, type } of clientRedirects) {
      result.wasRedirected = true;
      result.targets.push(url);
      if (!result.redirectTypes.includes(type)) result.redirectTypes.push(type);
    }
  }

  // Evaluate if ANY target in the chain leaves the official domain
  for (const target of result.targets) {
    if (!isOfficialSubdomain(target, baseDomain)) {
      result.isCrossDomain = true;
      break; // One strike and it's flagged as malicious/cross-domain
    }
  }

  return result;
}

/**
 * Helper function to find Meta tag and JavaScript redirects in an HTML string.
 */
function extractClientSideRedirects(htmlString, currentUrl) {
  const redirects = [];

  // 1. Meta Refresh Check
  const metaRegex =
    /<meta[^>]*http-equiv\s*=\s*['"]?refresh['"]?[^>]*content\s*=\s*['"]?[0-9]+\s*;\s*url\s*=\s*([^'">]+)['"]?/gi;
  let metaMatch;
  while ((metaMatch = metaRegex.exec(htmlString)) !== null) {
    redirects.push({ url: metaMatch[1].trim(), type: "meta" });
  }

  // 2. JavaScript Property Assignment (location.href = "...", window.location = "...")
  const jsAssignRegex =
    /(?:window\.)?location(?:\.href)?\s*=\s*['"]([^'"]+)['"]/gi;
  let jsMatch;
  while ((jsMatch = jsAssignRegex.exec(htmlString)) !== null) {
    redirects.push({ url: jsMatch[1].trim(), type: "javascript" });
  }

  // 3. JavaScript Method Calls (location.replace("..."), location.assign("..."))
  const jsMethodRegex =
    /(?:window\.)?location\.(?:replace|assign)\s*\(\s*['"]([^'"]+)['"]\s*\)/gi;
  while ((jsMatch = jsMethodRegex.exec(htmlString)) !== null) {
    redirects.push({ url: jsMatch[1].trim(), type: "javascript" });
  }

  // Convert extracted relative URLs to absolute URLs safely
  return redirects.map((item) => {
    try {
      return { url: new URL(item.url, currentUrl).href, type: item.type };
    } catch {
      return item; // Fallback to raw string if parsing fails
    }
  });
}

// ---------------------------------------------------------------------------
// Trust navigation (privacy / terms / help / etc.)
// ---------------------------------------------------------------------------

/**
 * @param {string} raw
 * @returns {string}
 */
function normalizeTrustText(raw) {
  return String(raw ?? "")
    .replace(/\s+/g, " ")
    .trim();
}

/**
 * @param {string} text
 * @param {string} [href]
 * @returns {string|null}
 */
function trustCategory(text, href = "") {
  const corpus = `${text} ${href}`;
  for (const category of TRUST_CATEGORIES) {
    if (TRUST_PATTERNS[category].test(corpus)) return category;
  }
  return null;
}

/**
 * @param {string} href
 * @returns {boolean}
 */
function isInertTarget(href) {
  const value = String(href ?? "")
    .trim()
    .toLowerCase();
  return !value || value === "#" || value.startsWith("javascript:");
}

/**
 * True when onclick is absent or a no-op (return false / void(0)).
 * @param {import("node-html-parser").HTMLElement} el
 * @returns {boolean}
 */
function isInertOnclick(el) {
  const handler = (el.getAttribute("onclick") ?? "").trim();
  if (!handler) return true;
  return /^\s*(return\s+false\s*;?|void\s*[\s(]|javascript\s*:\s*void)/i.test(
    handler,
  );
}

/**
 * Pull a navigable URL out of a simple onclick assignment, if present.
 * @param {import("node-html-parser").HTMLElement} el
 * @returns {string}
 */
function hrefFromOnclick(el) {
  const handler = (el.getAttribute("onclick") ?? "").trim();
  if (!handler || isInertOnclick(el)) return "";
  const match =
    /(?:window\.)?location(?:\.href)?\s*=\s*['"]([^'"]+)['"]/i.exec(handler) ||
    /(?:window\.)?location\.(?:assign|replace)\s*\(\s*['"]([^'"]+)['"]\s*\)/i.exec(
      handler,
    );
  return match?.[1]?.trim() ?? "";
}

/**
 * Extract links and trust-labeled controls (anchors, buttons, role=link/button).
 *
 * - `found` — any trust-labeled control exists (including inert / non-navigable)
 * - `candidates` — real hrefs that can be HTTP-probed
 * - `nonFunctional` — trust-labeled but not probeable (inert href, dead button, etc.)
 *
 * @param {string} htmlString - Raw HTML of the page.
 * @returns {{ links: object[], trustNavigation: object }}
 */
function extractTrustNavigation(htmlString) {
  const root = parse(htmlString ?? "", {
    lowerCaseTagName: true,
    comment: false,
    blockTextElements: {
      script: false,
      noscript: false,
      style: false,
      pre: true,
    },
  });

  const links = root.querySelectorAll("a").map((anchor) => {
    const text = normalizeTrustText(anchor.innerText);
    const href = (anchor.getAttribute("href") ?? "").trim();
    return {
      text,
      href,
      trustCategory: trustCategory(text, href),
      inert: isInertTarget(href),
    };
  });

  /** @type {{ text: string, href: string, trustCategory: string }[]} */
  const candidates = [];
  /** @type {{ text: string, trustCategory: string, reason: string }[]} */
  const nonFunctional = [];
  const seenHref = new Set();
  const seenNonFunctional = new Set();

  function pushProbeable(text, href, category) {
    if (!category || isInertTarget(href)) return false;
    const key = href.toLowerCase();
    if (seenHref.has(key)) return true;
    seenHref.add(key);
    candidates.push({ text, href, trustCategory: category });
    return true;
  }

  function pushNonFunctional(text, category, reason) {
    if (!category) return;
    const key = `${category}|${reason}|${(text || "").toLowerCase()}`;
    if (seenNonFunctional.has(key)) return;
    seenNonFunctional.add(key);
    nonFunctional.push({ text: text || category, trustCategory: category, reason });
  }

  // --- Anchors ---
  for (const link of links) {
    if (!link.trustCategory) continue;
    if (link.inert) {
      pushNonFunctional(link.text, link.trustCategory, "inert_href");
      continue;
    }
    pushProbeable(link.text, link.href, link.trustCategory);
  }

  // --- Buttons / submit inputs ---
  for (const control of root.querySelectorAll(
    "button, input[type='button'], input[type='submit']",
  )) {
    const text = normalizeTrustText(
      control.innerText ||
        control.getAttribute("value") ||
        control.getAttribute("aria-label") ||
        "",
    );
    const category = trustCategory(text);
    if (!category) continue;

    const href =
      (control.getAttribute("href") ?? "").trim() || hrefFromOnclick(control);
    if (pushProbeable(text, href, category)) continue;
    pushNonFunctional(
      text,
      category,
      isInertTarget(href) && href
        ? "inert_href"
        : "non_navigable_control",
    );
  }

  // --- role="link" / role="button" ---
  for (const el of root.querySelectorAll("[role='link'], [role='button']")) {
    const text = normalizeTrustText(
      el.innerText || el.getAttribute("aria-label") || "",
    );
    const hrefAttr = (el.getAttribute("href") ?? "").trim();
    const href = hrefAttr || hrefFromOnclick(el);
    const category = trustCategory(text, hrefAttr);
    if (!category) continue;

    if (pushProbeable(text, href, category)) continue;
    pushNonFunctional(
      text,
      category,
      isInertTarget(href) && href ? "inert_href" : "non_navigable_control",
    );
  }

  const found = candidates.length > 0 || nonFunctional.length > 0;

  return {
    links,
    trustNavigation: {
      found,
      candidates,
      nonFunctional,
    },
  };
}

/**
 * Probe trust-link candidates until one returns HTTP 2xx.
 * Off-domain destinations count as working if reachable.
 *
 * @param {Array<{ href?: string, trustCategory?: string|null }>} candidates
 * @param {string} pageUrl
 * @returns {Promise<{ anyWorking: boolean, workingUrl?: string, failures: string[] }>}
 */
async function probeTrustLinks(candidates, pageUrl) {
  /** @type {{ anyWorking: boolean, workingUrl?: string, failures: string[] }} */
  const result = { anyWorking: false, failures: [] };

  let baseOk = true;
  try {
    new URL(pageUrl);
  } catch {
    baseOk = false;
  }

  /** @type {string[]} */
  const urls = [];
  const seen = new Set();
  for (const link of candidates ?? []) {
    if (!link?.href) continue;
    try {
      const resolved = baseOk
        ? new URL(link.href, pageUrl).href
        : new URL(link.href).href;
      if (seen.has(resolved)) continue;
      seen.add(resolved);
      urls.push(resolved);
    } catch {
      result.failures.push(String(link.href));
    }
  }

  if (urls.length === 0) return result;

  /**
   * @param {string} url
   * @returns {Promise<number>}
   */
  async function probeUrl(url) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), PROBE_TIMEOUT_MS);
    try {
      const response = await fetch(url, {
        method: "GET",
        redirect: "follow",
        signal: controller.signal,
        headers: { "User-Agent": TRUST_PROBE_UA },
      });
      return response.status;
    } finally {
      clearTimeout(timer);
    }
  }

  for (const url of urls) {
    try {
      const status = await probeUrl(url);
      if (status >= 200 && status < 300) {
        result.anyWorking = true;
        result.workingUrl = url;
        return result;
      }
      result.failures.push(`${url} (HTTP ${status})`);
    } catch (err) {
      result.failures.push(`${url} (${err?.message ?? "request failed"})`);
    }
  }

  return result;
}

//----------------------------------------------------------------------------
// Legitimate sites signals
//----------------------------------------------------------------------------

/** Flag high-risk when broken share of anchors meets or exceeds this ratio. */
const LINK_HEALTH_DEAD_RATIO = 0.5;
/** Flag when one dead destination accounts for this share of all anchors. */
const LINK_HEALTH_DOMINANT_SHARE = 0.3;
/** Evidence sample size retained per dead-link category. */
const LINK_HEALTH_SAMPLE_LIMIT = 5;

const SOFT_404_KEYWORDS = [
  "product not found",
  "no active numbers",
  "page not found",
];

const AXIOS_PROBE_HEADERS = {
  "User-Agent":
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
};

/**
 * True when the page shows a copyright / rights notice in the footer
 * (or footer-like region). Falls back to cleaned body text so sites without
 * a semantic <footer> are not false-negatives.
 *
 * @param {string} htmlString - Raw HTML of the page.
 * @returns {boolean}
 */
function hasCopyright(htmlString) {
  if (!htmlString || typeof htmlString !== "string") {
    return false;
  }

  const root = parse(htmlString, {
    lowerCaseTagName: false,
    comment: false,
    blockTextElements: { script: true, style: true, noscript: true },
  });
  for (const el of root.querySelectorAll("script, style, noscript, iframe, template, svg")) {
    el.remove();
  }

  // © / entities / (c) / "copyright" / "all rights reserved"
  const copyrightPattern =
    /©|&copy;|&#169;|&#x0*a9;|\(\s*c\s*\)|\bcopyright\b|all\s+rights\s+reserved/i;

  const footerEls = root.querySelectorAll(
    'footer, [role="contentinfo"], .footer, #footer, [class*="footer"], [id*="footer"]',
  );
  const footerText = footerEls
    .map((el) => el.text)
    .join(" ")
    .replace(/\s+/g, " ")
    .trim();

  if (footerText && copyrightPattern.test(footerText)) {
    return true;
  }

  // No footer chrome — check visible page text (scripts/styles already stripped).
  const body = root.querySelector("body");
  const bodyText = (body?.text || root.text || "")
    .replace(/\s+/g, " ")
    .trim();
  return copyrightPattern.test(bodyText);
}

/**
 * @param {string} href
 * @returns {boolean}
 */
function isPlaceholderHref(href) {
  const h = String(href).trim();
  return h === "#" || h.toLowerCase().includes("javascript:void");
}

/**
 * Collect every clickable destination once per occurrence (no dedupe yet).
 * Sources: <a href>, [data-href], [data-url].
 *
 * @param {string} htmlString
 * @param {string} pageUrl
 * @returns {{ placeholders: number, urls: string[] }}
 */
function collectAnchorTargets(htmlString, pageUrl) {
  const root = parse(htmlString ?? "", {
    lowerCaseTagName: false,
    comment: false,
    blockTextElements: { script: true, style: true, noscript: true },
  });
  /** @type {string[]} */
  const urls = [];
  let placeholders = 0;

  const pushRaw = (raw) => {
    const href = String(raw ?? "").trim();
    if (!href) return;

    if (isPlaceholderHref(href)) {
      placeholders++;
      return;
    }

    const lower = href.toLowerCase();
    if (
      lower.startsWith("mailto:") ||
      lower.startsWith("tel:") ||
      lower.startsWith("sms:") ||
      lower.startsWith("data:") ||
      lower.startsWith("blob:")
    ) {
      return;
    }

    try {
      const full = new URL(href, pageUrl).href;
      const protocol = new URL(full).protocol;
      if (protocol === "http:" || protocol === "https:") urls.push(full);
    } catch {
      // ignore malformed
    }
  };

  for (const el of root.querySelectorAll("a[href]")) {
    pushRaw(el.getAttribute("href"));
  }
  for (const el of root.querySelectorAll("[data-href]")) {
    pushRaw(el.getAttribute("data-href"));
  }
  for (const el of root.querySelectorAll("[data-url]")) {
    pushRaw(el.getAttribute("data-url"));
  }

  return { placeholders, urls };
}

/**
 * Probe one URL. Soft-404 keywords are checked even on HTTP 4xx/5xx bodies.
 *
 * @param {string} link
 * @returns {Promise<"alive"|"hard_dead"|"soft_dead"|"network_error">}
 */
async function probeOneLink(link) {
  try {
    const response = await axios.get(link, {
      validateStatus: () => true,
      timeout: 6000,
      maxRedirects: 5,
      headers: AXIOS_PROBE_HEADERS,
      responseType: "text",
      transformResponse: [(data) => data],
    });

    const pageText =
      typeof response.data === "string" ? response.data.toLowerCase() : "";
    const isSoft404 = SOFT_404_KEYWORDS.some((k) => pageText.includes(k));

    if (isSoft404) return "soft_dead";
    if (response.status >= 400) return "hard_dead";
    return "alive";
  } catch {
    return "network_error";
  }
}

/**
 * Scan page clickables for dead / placeholder links (legitimacy signal).
 *
 * Scores **per anchor occurrence** (not unique URL), so 20 CTAs to one dead
 * checkout URL count as 20 broken anchors. Probes each unique URL once.
 * Soft-404 body text is checked even on HTTP 4xx responses.
 *
 * Flags when either:
 * - broken anchor ratio ≥ 50%, or
 * - one destination is ≥30% of anchors and that destination is dead
 *   (`conversionDestinationDead` — hollow storefront CTA pattern).
 *
 * @param {string} htmlString
 * @param {string} pageUrl
 * @param {object} [options]
 * @param {number} [options.threshold=0.5]
 * @returns {Promise<object>}
 */
async function analyzeLinkHealth(htmlString, pageUrl, options = {}) {
  const threshold =
    typeof options.threshold === "number" && options.threshold >= 0
      ? options.threshold
      : LINK_HEALTH_DEAD_RATIO;

  const empty = {
    totalAnchors: 0,
    placeholderCount: 0,
    uniqueLinkCount: 0,
    probedCount: 0,
    aliveCount: 0,
    hardDeadCount: 0,
    softDeadCount: 0,
    networkErrorCount: 0,
    brokenCount: 0,
    evaluableCount: 0,
    brokenRatio: 0,
    threshold,
    exceedsThreshold: false,
    conversionDestinationDead: false,
    dominantUrl: null,
    dominantShare: 0,
    samples: { hardDead: [], softDead: [], networkErrors: [] },
    details: [],
  };

  if (!htmlString || typeof htmlString !== "string" || !pageUrl) {
    return empty;
  }

  try {
    new URL(pageUrl);
  } catch {
    return empty;
  }

  const { placeholders, urls } = collectAnchorTargets(htmlString, pageUrl);
  const totalAnchors = placeholders + urls.length;
  if (totalAnchors === 0) return empty;

  /** @type {Map<string, number>} */
  const freq = new Map();
  for (const u of urls) freq.set(u, (freq.get(u) ?? 0) + 1);
  const uniqueLinks = [...freq.keys()];

  /** @type {Map<string, string>} */
  const statusByUrl = new Map();
  /** @type {{ link: string, status: string, anchors: number }[]} */
  const details = [];
  /** @type {string[]} */
  const hardDeadSamples = [];
  /** @type {string[]} */
  const softDeadSamples = [];
  /** @type {string[]} */
  const networkErrorSamples = [];

  for (const link of uniqueLinks) {
    const status = await probeOneLink(link);
    statusByUrl.set(link, status);
    details.push({ link, status, anchors: freq.get(link) ?? 1 });

    if (status === "hard_dead" && hardDeadSamples.length < LINK_HEALTH_SAMPLE_LIMIT) {
      hardDeadSamples.push(link);
    } else if (status === "soft_dead" && softDeadSamples.length < LINK_HEALTH_SAMPLE_LIMIT) {
      softDeadSamples.push(link);
    } else if (
      status === "network_error" &&
      networkErrorSamples.length < LINK_HEALTH_SAMPLE_LIMIT
    ) {
      networkErrorSamples.push(link);
    }
  }

  // Score by anchor occurrence: each CTA pointing at a dead URL counts once.
  let aliveAnchors = 0;
  let hardDeadAnchors = 0;
  let softDeadAnchors = 0;
  let networkErrorAnchors = 0;

  for (const [link, count] of freq) {
    const status = statusByUrl.get(link);
    if (status === "alive") aliveAnchors += count;
    else if (status === "hard_dead") hardDeadAnchors += count;
    else if (status === "soft_dead") softDeadAnchors += count;
    else networkErrorAnchors += count;
  }

  const probedBroken = hardDeadAnchors + softDeadAnchors + networkErrorAnchors;
  const brokenCount = placeholders + probedBroken;
  const evaluableCount = totalAnchors;
  const brokenRatio = evaluableCount > 0 ? brokenCount / evaluableCount : 0;

  // Dominant destination: most frequent URL; flag if share is high and it is dead.
  let dominantUrl = null;
  let dominantCount = 0;
  for (const [link, count] of freq) {
    if (count > dominantCount) {
      dominantCount = count;
      dominantUrl = link;
    }
  }
  const dominantShare =
    evaluableCount > 0 && dominantUrl ? dominantCount / evaluableCount : 0;
  const dominantStatus = dominantUrl ? statusByUrl.get(dominantUrl) : null;
  const conversionDestinationDead =
    !!dominantUrl &&
    dominantShare >= LINK_HEALTH_DOMINANT_SHARE &&
    dominantStatus !== "alive";

  return {
    totalAnchors,
    placeholderCount: placeholders,
    uniqueLinkCount: uniqueLinks.length,
    probedCount: uniqueLinks.length,
    aliveCount: aliveAnchors,
    hardDeadCount: hardDeadAnchors,
    softDeadCount: softDeadAnchors,
    networkErrorCount: networkErrorAnchors,
    brokenCount,
    evaluableCount,
    brokenRatio: Math.round(brokenRatio * 1000) / 1000,
    threshold,
    exceedsThreshold:
      (evaluableCount > 0 && brokenRatio >= threshold) ||
      conversionDestinationDead,
    conversionDestinationDead,
    dominantUrl,
    dominantShare: Math.round(dominantShare * 1000) / 1000,
    samples: {
      hardDead: hardDeadSamples,
      softDead: softDeadSamples,
      networkErrors: networkErrorSamples,
    },
    details,
  };
}

// ---------------------------------------------------------------------------
// E commerce signals
// ---------------------------------------------------------------------------

/**
 * 1. Checks for inline HTML Microdata schema (Product or Offer)
 *
 * @param {string} htmlString - The raw HTML string.
 * @returns {boolean} - True if e-commerce microdata is found.
 */
function hasMicrodataSchema(htmlString) {
  // Matches itemtype="http://schema.org/Product" or "https://schema.org/Offer"
  const microdataRegex =
    /itemtype\s*=\s*['"]https?:\/\/schema\.org\/(Product|Offer)['"]/i;

  // Also checks for price properties commonly used in Microdata
  const pricePropertyRegex = /itemprop\s*=\s*['"]price['"]/i;

  return microdataRegex.test(htmlString) || pricePropertyRegex.test(htmlString);
}

/**
 * 2. Checks for JSON-LD script tags and parses them for e-commerce types
 *
 * @param {string} htmlString - The raw HTML string.
 * @returns {boolean} - True if e-commerce JSON-LD is found.
 */
function hasJsonLdSchema(htmlString) {
  // Extracts the content between <script type="application/ld+json"> and </script>
  // [\s\S]*? ensures it captures multiline content safely
  const jsonLdRegex =
    /<script[^>]*type\s*=\s*['"]application\/ld\+json['"][^>]*>([\s\S]*?)<\/script>/gi;

  let match;
  while ((match = jsonLdRegex.exec(htmlString)) !== null) {
    try {
      // match[1] contains the raw JSON string
      const jsonContent = JSON.parse(match[1]);

      // JSON-LD can be a single object or an array of objects
      const schemas = Array.isArray(jsonContent) ? jsonContent : [jsonContent];

      for (const schema of schemas) {
        // Check if the @type property indicates a product or an offer
        const type = schema["@type"];
        if (
          type === "Product" ||
          type === "Offer" ||
          (Array.isArray(type) &&
            (type.includes("Product") || type.includes("Offer")))
        ) {
          return true;
        }
      }
    } catch (e) {
      // If the JSON is malformed, we just skip to the next script tag
      continue;
    }
  }

  return false;
}

/**
 * 3. MASTER FUNCTION: Evaluates the HTML for any valid e-commerce schema
 *
 * @param {string} htmlString - The raw HTML string.
 * @returns {object} - A detailed breakdown of the schema found.
 */
function detectEcommerceSchema(htmlString) {
  if (!htmlString || typeof htmlString !== "string") {
    return { hasSchema: false, type: "none" };
  }

  const hasMicrodata = hasMicrodataSchema(htmlString);
  const hasJsonLd = hasJsonLdSchema(htmlString);

  return {
    hasSchema: hasMicrodata || hasJsonLd,
    usesMicrodata: hasMicrodata,
    usesJsonLd: hasJsonLd,
  };
}

/**
 * Scans HTML text for common gambling / betting keywords.
 * Strips tags first, then matches word-boundary terms (bet, slots, casino, etc.).
 * "sports" alone is omitted (too many FPs); sportsbook / sports betting are included.
 *
 * @param {string} htmlString - The raw HTML string.
 * @returns {boolean} True if gambling-related phrases are found.
 */
export function detectGamblingPhrases(htmlString) {
  if (!htmlString || typeof htmlString !== "string") return false;

  const textContent = htmlString.replace(/<[^>]*>?/gm, " ");

  // Word-boundary alternation of common gambling-site vocabulary
  const gamblingPhraseRegex =
    /\b(?:bet(?:ting|s)?|wager(?:s|ing)?|slots?|slot\s*machines?|casino(?:s)?|poker|blackjack|roulette|baccarat|sportsbook|sports\s*bet(?:ting)?|odds|jackpot|bookmaker|bookie|roulette|free\s*spins?|live\s*dealer|scratch\s*cards?|bingo|craps|keno)\b/i;

  return gamblingPhraseRegex.test(textContent);
}

/**
 * Scans an HTML string to detect e-commerce pricing patterns and currencies.
 * Handles variations in placement (prefix/suffix) and international formatting.
 *
 * @param {string} htmlString - The raw HTML string.
 * @returns {boolean} - True if a valid pricing pattern is found.
 */
function hasPricingPatterns(htmlString) {
  if (!htmlString || typeof htmlString !== "string") return false;

  // 1. Strip HTML tags and replace them with a space.
  // This turns <span class="curr">$</span><span class="val">19.99</span> into "$ 19.99"
  const textContent = htmlString.replace(/<[^>]*>?/gm, " ");

  // 2. Define the currency identifiers (Symbols and common ISO codes)
  const currencies = "[$£€¥₹₩₽]|USD|EUR|GBP|MYR|AUD|CAD|JPY|INR|CNY|SGD";

  // 3. Define the number format
  // Matches: 19, 19.99, 1,000.00, 1.000,00 (European), and 1000
  const numberFormat = "\\d{1,3}(?:[.,]\\d{3})*(?:[.,]\\d{1,2})?";

  // Pattern A: Currency comes first (e.g., $19.99, USD 50.00, £ 1,000)
  const prefixRegex = new RegExp(`(?:${currencies})\\s*${numberFormat}`, "i");

  // Pattern B: Currency comes last (e.g., 19.99€, 50 USD, 1.000,00 MYR)
  const suffixRegex = new RegExp(`${numberFormat}\\s*(?:${currencies})`, "i");

  // 4. Test the clean text against both patterns
  return prefixRegex.test(textContent) || suffixRegex.test(textContent);
}

/**
 * Parse a price string in US or European format into a number.
 *
 * US:  $1,299.99  — comma = thousands, dot = decimal
 * EU:  €1.299,99  — dot = thousands, comma = decimal
 * EU:  €49,99     — comma decimal only
 *
 * When both separators appear, the rightmost one is treated as the decimal mark.
 * When only one separator appears, 1–2 trailing digits after it → decimal; otherwise → thousands.
 *
 * @param {string} priceStr
 * @returns {number|null}
 */
export function parsePriceString(priceStr) {
  if (priceStr == null || priceStr === "") return null;

  let s = String(priceStr)
    .trim()
    .replace(/[^\d.,-]/g, "");
  if (!s || /^[.,-]+$/.test(s)) return null;

  const lastComma = s.lastIndexOf(",");
  const lastDot = s.lastIndexOf(".");

  if (lastComma !== -1 && lastDot !== -1) {
    if (lastComma > lastDot) {
      s = s.replace(/\./g, "").replace(",", ".");
    } else {
      s = s.replace(/,/g, "");
    }
  } else if (lastComma !== -1) {
    const afterComma = s.slice(lastComma + 1);
    if (/^\d{1,2}$/.test(afterComma)) {
      s = s.replace(",", ".");
    } else {
      s = s.replace(/,/g, "");
    }
  } else if (lastDot !== -1) {
    const afterDot = s.slice(lastDot + 1);
    if (/^\d{1,2}$/.test(afterDot)) {
      // US-style decimal dot — leave as-is
    } else {
      s = s.replace(/\./g, "");
    }
  }

  const num = parseFloat(s);
  return Number.isFinite(num) && num >= 0 ? num : null;
}

const ORIGINAL_PRICE_SELECTOR = [
  "del",
  "s",
  "strike",
  ".old-price",
  ".original-price",
  ".compare-at",
  ".compare-at-price",
  ".regular-price",
].join(", ");

const SALE_PRICE_SELECTOR = [
  ".sale-price",
  ".special-price",
  ".new-price",
  ".current-price",
  ".price-sale",
  ".discounted-price",
].join(", ");

const PRICE_LOOKALIKE =
  /[\$£€¥₹]\s*\d+|\d+\s*[\$£€¥₹]|USD|EUR|GBP|MYR|AUD|CAD|JPY|INR|CNY|SGD/i;

/**
 * Parses an HTML string to extract paired original and sale prices.
 * Uses node-html-parser (same as the rest of utility.js) — no Cheerio required.
 *
 * Strategy A: walk up to 3 parent containers and find a known sale-price class.
 * Strategy B: scan siblings of the original-price element for currency-like text.
 *
 * Output is ready to feed into detectUnrealisticDiscount().
 *
 * @param {string} htmlString - The raw HTML of the e-commerce page.
 * @returns {Array<{original: string, sale: string}>} Array of extracted price pairs.
 */
export function extractPricePairs(htmlString) {
  if (!htmlString || typeof htmlString !== "string") return [];

  const root = parse(htmlString, {
    lowerCaseTagName: true,
    comment: false,
    blockTextElements: {
      script: false,
      noscript: false,
      style: false,
      pre: true,
    },
  });

  const pricePairs = [];

  for (const el of root.querySelectorAll(ORIGINAL_PRICE_SELECTOR)) {
    const originalPriceStr = (el.innerText ?? el.text ?? "").trim();
    if (!originalPriceStr) continue;

    let salePriceStr = null;

    // STRATEGY A: Traverse upward up to 3 levels to find a known sale class
    let container = el.parentNode;
    for (let depth = 0; depth < 3 && container; depth++) {
      const foundSale = container.querySelector(SALE_PRICE_SELECTOR);
      if (foundSale) {
        salePriceStr = (foundSale.innerText ?? foundSale.text ?? "").trim();
        if (salePriceStr) break;
      }
      container = container.parentNode;
    }

    // STRATEGY B: Fallback — siblings that look like a currency amount
    if (!salePriceStr) {
      const parent = el.parentNode;
      if (parent) {
        for (const sib of parent.childNodes ?? []) {
          if (sib === el || !sib.querySelectorAll) continue;
          const text = (sib.innerText ?? sib.text ?? "").trim();
          if (text && text !== originalPriceStr && PRICE_LOOKALIKE.test(text)) {
            salePriceStr = text;
            break;
          }
        }
      }
    }

    if (originalPriceStr && salePriceStr) {
      pricePairs.push({
        original: originalPriceStr,
        sale: salePriceStr,
      });
    }
  }

  return pricePairs;
}

/**
 * Detects if a significant portion of products have unrealistic discounts.
 *
 * @param {Array<{original: string, sale: string}>} pricePairs - Extracted price strings.
 * @param {number} discountThreshold - The % off considered unrealistic (default: 70% / 0.70).
 * @param {number} densityThreshold - The % of catalog that must meet the discountThreshold (default: 50% / 0.50).
 * @returns {boolean} True if the site exhibits fake-shop discount patterns.
 */
export function detectUnrealisticDiscount(
  pricePairs,
  discountThreshold = 0.7,
  densityThreshold = 0.5,
) {
  if (!Array.isArray(pricePairs) || pricePairs.length === 0) {
    return false;
  }

  let extremeDiscountCount = 0;
  let validPairs = 0;

  for (const pair of pricePairs) {
    const original = parsePriceString(pair.original);
    const sale = parsePriceString(pair.sale);

    if (original && sale && original > 0) {
      validPairs++;
      const discount = (original - sale) / original;

      if (discount >= discountThreshold) {
        extremeDiscountCount++;
      }
    }
  }

  // If we couldn't parse enough valid prices, fail safely
  if (validPairs === 0) return false;

  const extremeDiscountDensity = extremeDiscountCount / validPairs;
  return extremeDiscountDensity >= densityThreshold;
}

// ------------------------------------------------------------
// Parking Site Detection
// ------------------------------------------------------------

/**
 * Queries the NS records for a domain and checks them against a list of known parking providers.
 * Checks name servers for parking domain footprints.
 * @param {string} targetDomain - The domain to analyze (e.g., 'jackcow.com')
 * @returns {Promise<Object>} An object containing the classification result and matched footprints.
 */
async function detectParkedNameServers(targetDomain) {
  // A comprehensive list of known domain parking, marketplace, and monetization name servers
  const parkingNameServers = new Set([
    // GoDaddy & Afternic Network
    "domaincontrol.com",
    "afternic.com",
    "cashparking.com",
    "namefind.com",

    // Sedo
    "sedoparking.com",

    // Bodis
    "bodis.com",

    // ParkingCrew
    "parkingcrew.net",

    // Dan.com / Undeveloped
    "dan.com",
    "undeveloped.com",

    // ParkLogic
    "parklogic.com",

    // Ztomy
    "ztomy.com",

    // Namecheap (Parking defaults)
    "parking.namecheap.com",
    "parkingpage.namecheap.com",

    // Expired Domains
    "expireddomains",

    // Broad Marketplaces & Monetization Networks
    "above.com",
    "alter.com",
    "brandbucket.com",
    "dns-parking.com",
    "domain-for-sale.at",
    "domain-for-sale.se",
    "domainmarket.com",
    "domainrecover.com",
    "dsredirection.com",
    "dsredirects.com",
    "eftydns.com",
    "onamae-expired.com",
    "park.io",
  ]);

  try {
    // 1. Perform the DNS NS lookup
    const nsRecords = await dns.resolveNs(targetDomain);

    // 2. Check if any returned NS record ends with a known parking root domain
    const matchedFootprints = nsRecords.filter((ns) => {
      // Normalize the NS record (lowercase, remove any trailing periods)
      const normalizedNs = ns.toLowerCase().replace(/\.$/, "");

      // Iterate through the Set to find a match
      // We use .contains() to ensure 'ns1.afternic.com' matches 'afternic.com'
      for (const parkingNs of parkingNameServers) {
        if (normalizedNs.includes(parkingNs)) {
          return true;
        }
      }
      return false;
    });

    // 3. Return the classification result
    if (matchedFootprints.length > 0) {
      return {
        isParkingDomain: true,
        matchedFootprints: matchedFootprints,
        allNsRecords: nsRecords,
      };
    }

    return {
      isParkingDomain: false,
      matchedFootprints: [],
      allNsRecords: nsRecords,
    };
  } catch (error) {
    // Handle domains that do not exist, fail to resolve, or have no NS records
    return {
      isParkingDomain: false,
      matchedFootprints: [],
      error: error.message,
    };
  }
}

/**
 * Queries the A records for a domain and checks them against
 * a strict list of known parking infrastructure IP addresses.
 *
 * @param {string} targetDomain - The domain to analyze (e.g., 'example.com')
 * @returns {Promise<Object>} An object containing the classification result and matched IPs.
 */
async function detectParkedIPs(targetDomain) {
  // 1. Define strict, known exact-match parking IPs
  const exactParkingIPs = new Set([
    // GoDaddy Default Parking & CashParking (AWS & Google Cloud nodes)
    "3.33.130.190",
    "15.197.148.33",
    "34.102.136.180",
    "34.98.99.30",

    // Sedo Parking infrastructure
    "64.190.63.222",

    // Confluence Networks (frequently used for parked and holding pages)
    "208.91.197.27",
  ]);

  // 2. Define known parking subnets (using simple string prefixes for /24 blocks)
  // This helps catch providers that cycle through a specific block of IPs.
  const parkingSubnets = [
    "198.54.117.", // Namecheap default parking block footprint
  ];

  try {
    // 3. Resolve the IPv4 (A) records natively
    const aRecords = await dns.resolve4(targetDomain);

    // 4. Filter the resolved IPs against our exact matches and subnet prefixes
    const matchedFootprints = aRecords.filter((ip) => {
      // Check for an exact IP match
      if (exactParkingIPs.has(ip)) return true;

      // Check if the IP falls into a known parking subnet
      for (const subnet of parkingSubnets) {
        if (ip.startsWith(subnet)) return true;
      }

      return false;
    });

    // 5. Evaluate the results to make a classification decision
    if (matchedFootprints.length > 0) {
      return {
        isSuspicious: true,
        matchedFootprints: matchedFootprints,
        allIPs: aRecords,
        decisionEngineFlag: "PARKED_INFRASTRUCTURE",
      };
    }

    return {
      isSuspicious: false,
      matchedFootprints: [],
      allIPs: aRecords,
      decisionEngineFlag: "CLEAN",
    };
  } catch (error) {
    // Handle domains that do not exist, have no A records, or fail to resolve
    return {
      isSuspicious: false,
      matchedFootprints: [],
      error:
        error.code === "ENOTFOUND" ? "Domain does not resolve" : error.message,
      decisionEngineFlag: "UNRESOLVED",
    };
  }
}

/**
 * Scans visible page text for domain parking / for-sale phrases.
 * Gate for DNS parking probes — must not fire on generic "domain" alone.
 *
 * @param {string} htmlString - Raw HTML of the page.
 * @returns {{ isSuspicious: boolean, foundClues: string[] }}
 */
function detectParkingKeywords(htmlString) {
  const root = parse(htmlString ?? "", {
    lowerCaseTagName: false,
    comment: false,
    blockTextElements: { script: true, style: true, noscript: true },
  });
  for (const el of root.querySelectorAll("script, style, noscript")) {
    el.remove();
  }

  const body = root.querySelector("body");
  const visibleText = (body?.text || root.text || "")
    .replace(/\s+/g, " ")
    .toLowerCase();

  /** Parking-specific phrases (aligned with PARKING_PHRASES / marketplace landers). */
  const parkingPhrases = [
    "this domain is for sale",
    "domain is for sale",
    "domain for sale",
    "buy this domain",
    "domain available for purchase",
    "this domain is parked",
    "parked domain",
    "domain is parked",
    "make an offer",
    "lease to own",
    "domain auction",
    "premium domain",
    "aftermarket",
    "website coming soon",
    "site under development",
    "this page is a placeholder",
    "under construction",
    "coming soon",
    "related searches",
    "sponsored listings",
  ];

  const foundClues = parkingPhrases.filter((phrase) =>
    visibleText.includes(phrase),
  );

  if (foundClues.length > 0) {
    return {
      isSuspicious: true,
      foundClues,
    };
  }

  return {
    isSuspicious: false,
    foundClues: [],
  };
}

/**
 * Checks a domain for a Null MX record and a restricted SPF record.
 *
 * @param {string} targetDomain - The domain to analyze (e.g., 'example.com')
 * @returns {Promise<Object>} An object containing the email footprint analysis.
 */
async function checkEmailFootprint(targetDomain) {
  const result = {
    domain: targetDomain,
    hasNullMx: false,
    hasRestrictedSpf: false,
    mxRecords: [],
    spfRecords: [],
    errors: [],
  };

  // 1. Check for Null MX Record (RFC 7505)
  try {
    const mxRecords = await dns.resolveMx(targetDomain);
    result.mxRecords = mxRecords;

    // A standard Null MX setup contains exactly one record with a priority of 0
    // and an exchange pointing to the root "." (Node.js may also parse this as an empty string)
    if (mxRecords.length === 1) {
      const mx = mxRecords[0];
      if (mx.priority === 0 && (mx.exchange === "." || mx.exchange === "")) {
        result.hasNullMx = true;
      }
    }
  } catch (mxError) {
    // Ignore standard "no record found" errors, but log actual network failures
    if (mxError.code !== "ENODATA" && mxError.code !== "ENOTFOUND") {
      result.errors.push(`MX Lookup Error: ${mxError.message}`);
    }
  }

  // 2. Check for Restricted SPF Record
  try {
    const txtRecords = await dns.resolveTxt(targetDomain);

    // Node.js resolveTxt returns an array of arrays (chunked strings).
    // We map over them and join the chunks to reconstruct the full TXT records.
    const joinedTxtRecords = txtRecords.map((chunkedArray) =>
      chunkedArray.join(""),
    );

    // Filter down to only the SPF records
    const spfRecords = joinedTxtRecords.filter((record) =>
      record.toLowerCase().startsWith("v=spf1"),
    );
    result.spfRecords = spfRecords;

    // Evaluate the SPF records for strict restrictions
    for (const spf of spfRecords) {
      // Normalize whitespace for accurate matching
      const normalizedSpf = spf.toLowerCase().replace(/\s+/g, " ").trim();

      // A strictly restricted SPF record has no "include", "a", or "mx" mechanisms.
      // It acts as a hard fail for all incoming connections.
      if (normalizedSpf === "v=spf1 -all") {
        result.hasRestrictedSpf = true;
        break; // Stop checking once we find a restricted record
      }
    }
  } catch (txtError) {
    if (txtError.code !== "ENODATA" && txtError.code !== "ENOTFOUND") {
      result.errors.push(`TXT (SPF) Lookup Error: ${txtError.message}`);
    }
  }

  // 3. Assign a classification flag for your decision engine
  if (result.hasNullMx || result.hasRestrictedSpf) {
    result.decisionEngineFlag = "NO_EMAIL_INFRASTRUCTURE";
  } else {
    result.decisionEngineFlag = "CLEAN_OR_UNVERIFIED";
  }

  return result;
}

/** High-risk shop TLDs often used by disposable fake storefronts. */
const SUSPICIOUS_SHOP_TLDS = new Set([
  "top",
  "shop",
  "xyz",
  "biz",
  "click",
  "gq",
  "tk",
  "ml",
  "ga",
  "cf",
]);

const FREE_WEBMAIL_HOSTS =
  /@(?:gmail|googlemail|yahoo|ymail|hotmail|outlook|live|msn|aol|icloud|mail)\./i;

/**
 * @param {string} hostnameOrUrl
 * @returns {{ isSuspicious: boolean, tld: string|null }}
 */
function detectSuspiciousShopTld(hostnameOrUrl) {
  let host = String(hostnameOrUrl ?? "").trim().toLowerCase();
  if (!host) return { isSuspicious: false, tld: null };
  try {
    if (host.includes("://")) host = new URL(host).hostname;
  } catch {
    // bare hostname
  }
  host = host.replace(/\.$/, "").replace(/^www\./, "");
  const parts = host.split(".").filter(Boolean);
  const tld = parts.length >= 2 ? parts[parts.length - 1] : null;
  if (!tld) return { isSuspicious: false, tld: null };
  return { isSuspicious: SUSPICIOUS_SHOP_TLDS.has(tld), tld };
}

/**
 * Detects support contact emails on free webmail providers.
 * @param {string} htmlString
 * @returns {{ found: boolean, samples: string[] }}
 */
function detectFreeWebmailContact(htmlString) {
  const html = String(htmlString ?? "");
  const samples = [];
  const seen = new Set();

  for (const match of html.matchAll(
    /mailto:([a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,})/gi,
  )) {
    const email = match[1].toLowerCase();
    if (!FREE_WEBMAIL_HOSTS.test(email) || seen.has(email)) continue;
    seen.add(email);
    samples.push(email);
  }

  // Visible text emails (limit to avoid scanning huge documents twice)
  const textSlice = html
    .replace(/<script[\s\S]*?<\/script>/gi, " ")
    .slice(0, 200000);
  for (const match of textSlice.matchAll(
    /\b([a-z0-9._%+-]+@(?:gmail|googlemail|yahoo|ymail|hotmail|outlook|live|msn|aol|icloud|mail)\.[a-z]{2,})\b/gi,
  )) {
    const email = match[1].toLowerCase();
    if (seen.has(email)) continue;
    seen.add(email);
    samples.push(email);
    if (samples.length >= 5) break;
  }

  return { found: samples.length > 0, samples };
}

export {
  escapeRegExp,
  containsBrand,
  containsBrandName,
  brandInHostname,
  brandInMarkup,
  detectSensitiveInputs,
  hasFileUpload,
  analyzeFormActions,
  isOfficialSubdomain,
  checkHtmlMetaRedirect,
  checkDomainRedirect,
  checkRedirects,
  extractClientSideRedirects,
  extractTrustNavigation,
  probeTrustLinks,
  analyzeLinkHealth,
  hasCopyright,
  detectEcommerceSchema,
  hasPricingPatterns,
  detectParkedNameServers,
  detectParkingKeywords,
  detectParkedIPs,
  checkEmailFootprint,
  detectSuspiciousShopTld,
  detectFreeWebmailContact,
};
