import puppeteer from "puppeteer";
import fs from "fs/promises";
import path from "path";
import { fileURLToPath, URL } from "url";

const PROJECT_TEMP_DIR = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "../../../temp",
);

const USER_AGENT =
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36";

const BLOCKED_HOSTS = [
  "doubleclick.net",
  "googlesyndication.com",
  "google-analytics.com",
  "adservice.google.com",
  "connect.facebook.net",
  "quantserve.com",
  "outbrain.com",
  "taboola.com",
  "adnxs.com",
  "intercom.io",
  "drift.com",
  "hs-scripts.com",
  "zendesk.com",
  "onetrust.com",
  "cookiebot.com",
  "trustarc.com",
  "usercentrics.eu",
  "cookielaw.org",
];

const OVERLAY_SELECTOR = [
  '[aria-modal="true"]',
  '[role="dialog"]',
  '[id*="cookie" i]',
  '[class*="cookie" i]',
  '[id*="consent" i]',
  '[class*="consent" i]',
  '[id*="onetrust" i]',
  '[class*="onetrust" i]',
  '[id*="cookiebot" i]',
  '[class*="cookiebot" i]',
  '[id*="popup" i]',
  '[class*="popup" i]',
  '[id*="modal" i]',
  '[class*="modal" i]',
  '[class*="overlay" i]',
  '[id*="overlay" i]',
].join(", ");

const OVERLAY_CSS = `
  ${OVERLAY_SELECTOR},
  iframe[title*="chat" i], [id*="intercom" i], [id*="drift" i] {
    display: none !important;
    visibility: hidden !important;
    opacity: 0 !important;
    pointer-events: none !important;
    z-index: -9999 !important;
  }
  body, html { overflow: auto !important; position: static !important; }
`;

const DISMISS_KEYWORDS = [
  "accept all",
  "accept",
  "agree",
  "allow all",
  "allow",
  "got it",
  "i agree",
  "dismiss",
];

const CONTEXT_LOST =
  /Execution context was destroyed|Target closed|Navigating frame was detached/i;

/**
 * Untrusted / invalid certificate. HTTPS still exists — Chrome may load it
 * (corporate MITM like Fortinet). Puppeteer does not trust that CA by default,
 * so page.goto throws before we ever see HTTP 403.
 */
const CERT_FAIL =
  /ERR_CERT|CERT_AUTHORITY|CERT_DATE|CERT_COMMON_NAME|certificate/i;

/**
 * HTTPS is not usable at all (nothing listening, timeout, broken TLS handshake).
 * These are the only cases that should fall back to HTTP.
 */
const CONNECTION_FAIL =
  /ERR_SSL|SSL_PROTOCOL_ERROR|ERR_CONNECTION_CLOSED|ERR_CONNECTION_RESET|ERR_CONNECTION_REFUSED|ERR_CONNECTION_TIMED_OUT|ERR_TIMED_OUT/i;

const NAV_TIMEOUT_MS = 60000;

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

function normalizeUrl(domain) {
  return /^https?:\/\//i.test(domain) ? domain : `https://${domain}`;
}

function toHttpUrl(url) {
  return url.replace(/^https:\/\//i, "http://");
}

function navErrorSnippet(error) {
  return String(error?.message ?? error).split(" at ")[0];
}

/**
 * Classify an HTTPS navigation failure so we retry the right way.
 * Cert errors must stay on HTTPS (status 403 is only visible there).
 * Connection errors fall back to HTTP.
 *
 * @param {unknown} error
 * @returns {"cert"|"connection"|"other"}
 */
export function classifyHttpsNavError(error) {
  const message = String(error?.message ?? error);
  if (CERT_FAIL.test(message)) return "cert";
  if (CONNECTION_FAIL.test(message)) return "connection";
  return "other";
}

async function gotoUrl(page, url) {
  return page.goto(url, {
    waitUntil: "networkidle2",
    timeout: NAV_TIMEOUT_MS,
  });
}

function navigationResult(url, response) {
  return { url, httpStatus: response?.status() ?? null };
}

/**
 * Tell Chromium to accept untrusted certificates for this page only.
 * Used for Fortinet / self-signed MITM so we can read the real HTTPS status.
 */
async function ignoreCertificateErrors(page) {
  const client = await page.createCDPSession();
  await client.send("Security.setIgnoreCertificateErrors", { ignore: true });
}

/**
 * HTTPS first. On cert failure, retry the same HTTPS URL with certs ignored.
 * Only then (or on connection failure) fall back to HTTP.
 *
 * @returns {Promise<{ url: string, httpStatus: number|null }>}
 */
async function gotoWithFallback(page, url) {
  try {
    return navigationResult(url, await gotoUrl(page, url));
  } catch (error) {
    if (!/^https:/i.test(url)) throw error;

    const kind = classifyHttpsNavError(error);
    if (kind === "other") throw error;

    // Corporate filters (Fortinet) intercept HTTPS with an untrusted CA and
    // often return 403 + a block page. Falling back to HTTP here would miss
    // that status. Retry HTTPS after ignoring the cert.
    if (kind === "cert") {
      console.log(
        `      [Nav] HTTPS cert untrusted (${navErrorSnippet(error)}) — retrying HTTPS with cert errors ignored`,
      );
      try {
        await ignoreCertificateErrors(page);
        return navigationResult(url, await gotoUrl(page, url));
      } catch (certRetryError) {
        if (classifyHttpsNavError(certRetryError) === "other") {
          throw certRetryError;
        }
        console.log(
          `      [Nav] HTTPS still failed after ignoring cert (${navErrorSnippet(certRetryError)}) — retrying HTTP`,
        );
      }
    } else {
      console.log(
        `      [Nav] HTTPS unreachable (${navErrorSnippet(error)}) — retrying HTTP`,
      );
    }

    const httpUrl = toHttpUrl(url);
    return navigationResult(httpUrl, await gotoUrl(page, httpUrl));
  }
}

async function setupDefenses(browser, page) {
  browser.on("targetcreated", async (target) => {
    if (target.type() !== "page") return;
    const newPage = await target.page();
    if (newPage && newPage !== page) {
      console.log(`      [Blocked] Closed secondary tab: ${target.url()}`);
      await newPage.close();
    }
  });

  page.on("dialog", async (dialog) => {
    console.log(`      [Blocked] Dismissed dialog: "${dialog.message()}"`);
    await dialog.dismiss();
  });

  await page.setRequestInterception(true);
  page.on("request", (request) => {
    const url = request.url().toLowerCase();
    const blocked =
      BLOCKED_HOSTS.some((host) => url.includes(host)) ||
      url.includes("popunder") ||
      url.includes("popup.js");
    blocked ? request.abort() : request.continue();
  });
}

/** Wait until the URL stops changing (handles post-load redirects). */
async function waitForSettle(page, quietMs = 1500, timeoutMs = 15000) {
  const deadline = Date.now() + timeoutMs;
  let lastUrl = page.url();

  while (Date.now() < deadline) {
    await sleep(quietMs);
    const url = page.url();
    if (url === lastUrl) return;
    console.log(`      [Nav] Redirected to: ${url}`);
    lastUrl = url;
  }
}

/** True only when a real layered overlay/dialog is visible. */
async function hasVisibleModal(page) {
  return page.evaluate((selector) => {
    const looksLikeOverlay = (el) => {
      const style = getComputedStyle(el);
      if (
        style.display === "none" ||
        style.visibility === "hidden" ||
        Number(style.opacity) === 0
      ) {
        return false;
      }

      const rect = el.getBoundingClientRect();
      if (rect.width < 80 || rect.height < 40) return false;

      if (
        el.getAttribute("aria-modal") === "true" ||
        el.getAttribute("role") === "dialog"
      ) {
        return true;
      }

      const z = Number.parseInt(style.zIndex, 10);
      const layered =
        (style.position === "fixed" || style.position === "absolute") &&
        (!Number.isFinite(z) || z >= 10);
      const large =
        rect.width >= innerWidth * 0.3 && rect.height >= innerHeight * 0.15;

      return layered && large;
    };

    const search = (root) => {
      if (!root) return false;
      for (const el of root.querySelectorAll(selector)) {
        if (looksLikeOverlay(el)) return true;
      }
      for (const el of root.querySelectorAll("*")) {
        if (el.shadowRoot && search(el.shadowRoot)) return true;
      }
      return false;
    };

    return search(document);
  }, OVERLAY_SELECTOR);
}

async function safeHasModal(page) {
  try {
    return await hasVisibleModal(page);
  } catch (error) {
    if (!CONTEXT_LOST.test(error.message)) throw error;
    await waitForSettle(page);
    try {
      return await hasVisibleModal(page);
    } catch {
      return false;
    }
  }
}

/** Click consent buttons + hide overlays. No-op when no modal exists. */
async function dismissDomPopups(page) {
  if (!(await safeHasModal(page))) {
    console.log("      [Popup] None detected — skipping.");
    return;
  }

  console.log("      [Popup] Detected — dismissing...");

  for (let attempt = 1; attempt <= 3; attempt++) {
    try {
      await page.addStyleTag({ content: OVERLAY_CSS });
      await page.evaluate((keywords) => {
        const clickIn = (root) => {
          if (!root) return;
          for (const btn of root.querySelectorAll(
            'button, a, [role="button"]',
          )) {
            const text = (btn.innerText || btn.textContent || "")
              .toLowerCase()
              .trim();
            if (
              text &&
              text.length < 30 &&
              keywords.some((k) => text.includes(k))
            ) {
              try {
                btn.click();
              } catch {
                /* ignore */
              }
            }
          }
          for (const el of root.querySelectorAll("*")) {
            if (el.shadowRoot) clickIn(el.shadowRoot);
          }
        };
        clickIn(document);
      }, DISMISS_KEYWORDS);
      await sleep(1500);
      return;
    } catch (error) {
      if (!CONTEXT_LOST.test(error.message) || attempt === 3) {
        console.log(`      [Popup] Aborted (${error.message}) — continuing.`);
        return;
      }
      console.log(`      [Popup] Navigated during dismiss; retry ${attempt}/3`);
      await waitForSettle(page);
      if (!(await safeHasModal(page))) return;
    }
  }
}

/**
 * Scroll the page so lazy-loaded images / below-fold widgets hydrate.
 * Converts many data-src → src before we serialize HTML.
 *
 * @param {import("puppeteer").Page} page
 */
async function scrollForLazyContent(page) {
  try {
    await page.evaluate(async () => {
      await new Promise((resolve) => {
        const distance = 400;
        const maxSteps = 40;
        let steps = 0;
        let totalHeight = 0;

        const timer = setInterval(() => {
          const scrollHeight = document.body?.scrollHeight ?? 0;
          window.scrollBy(0, distance);
          totalHeight += distance;
          steps += 1;
          if (totalHeight >= scrollHeight || steps >= maxSteps) {
            clearInterval(timer);
            window.scrollTo(0, 0);
            resolve();
          }
        }, 100);
      });
    });
    await sleep(1500);
  } catch (error) {
    if (!CONTEXT_LOST.test(error.message)) {
      console.log(`      [Scroll] Skipped (${error.message})`);
    }
  }
}

/**
 * Read child-frame (iframe) documents via CDP.
 * Cross-origin iframes are reachable here — same-origin contentDocument
 * alone would miss parked-domain / ad safeframe shells (e.g. evergreenfarms).
 *
 * @param {import("puppeteer").Page} page
 * @returns {Promise<{ url: string, html: string, text: string }[]>}
 */
async function extractChildFrames(page) {
  const results = [];

  for (const frame of page.frames()) {
    if (frame === page.mainFrame()) continue;

    const url = frame.url();
    if (!url || url === "about:blank") continue;

    try {
      await frame.waitForSelector("body", { timeout: 8000 }).catch(() => null);

      const html = await frame.content();
      const text = await frame.evaluate(
        () => document.body?.innerText?.replace(/\s+/g, " ").trim() ?? "",
      );

      results.push({ url, html, text });
      console.log(
        `      [iframe] ${url}  text=${text.length} chars  html=${html.length} chars`,
      );
    } catch (error) {
      console.log(`      [iframe] ${url}  skipped (${error.message})`);
      results.push({ url, html: "", text: "" });
    }
  }

  return results;
}

/** Strip script/style so merged iframe HTML stays analyzable DOM, not JS noise. */
function stripNonContentTags(html) {
  return String(html ?? "")
    .replace(/<script\b[^>]*>[\s\S]*?<\/script>/gi, "")
    .replace(/<style\b[^>]*>[\s\S]*?<\/style>/gi, "")
    .replace(/<noscript\b[^>]*>[\s\S]*?<\/noscript>/gi, "")
    .trim();
}

/** Pull inner HTML of <body>, or fall back to full document / plain text. */
function frameBodyHtml(frame) {
  let raw = "";
  if (frame.html) {
    const match = frame.html.match(/<body[^>]*>([\s\S]*)<\/body>/i);
    raw = (match?.[1] ?? frame.html).trim();
  } else if (frame.text) {
    raw = `<p>${frame.text
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")}</p>`;
  }
  return stripNonContentTags(raw);
}

/**
 * Merge child-frame DOM into the main HTML so htmlAnalyzer can see iframe text.
 * Each frame is appended as a <section data-iframe-src="..."> before the
 * document's real </body> (last occurrence — never the first, which often
 * sits inside an ad script string and would bury the merge in <script>).
 *
 * @param {string} mainHtml
 * @param {{ url: string, html: string, text: string }[]} childFrames
 * @returns {string}
 */
export function mergeFramesIntoHtml(mainHtml, childFrames) {
  const sections = [];

  for (const frame of childFrames) {
    const body = frameBodyHtml(frame);
    if (!body) continue;

    const src = frame.url.replace(/&/g, "&amp;").replace(/"/g, "&quot;");
    sections.push(
      `<section data-iframe-src="${src}" data-captured-iframe="true">${body}</section>`,
    );
  }

  if (!sections.length) return mainHtml;

  const block = `\n<!-- captured iframe content -->\n${sections.join("\n")}\n`;
  const closeIdx = mainHtml.toLowerCase().lastIndexOf("</body>");
  if (closeIdx !== -1) {
    return `${mainHtml.slice(0, closeIdx)}${block}${mainHtml.slice(closeIdx)}`;
  }
  return `${mainHtml}${block}`;
}

/**
 * Capture a website: dismiss overlays, merge iframe content, screenshot.
 *
 * @param {string} domain
 * @returns {Promise<{ htmlPath: string, screenshotPath: string, iframePath: string, renderedPath: string, renderedText: string, finalUrl: string, httpStatus: number|null, iframes: object[] } | null>}
 */
export async function captureWebsite(domain) {
  const targetUrl = normalizeUrl(domain);
  let hostname;
  try {
    hostname = new URL(targetUrl).hostname;
  } catch {
    console.error("Error: Invalid domain name provided.");
    return null;
  }

  await fs.mkdir(PROJECT_TEMP_DIR, { recursive: true });
  const htmlPath = path.join(PROJECT_TEMP_DIR, `${hostname}.txt`);
  const iframePath = path.join(PROJECT_TEMP_DIR, `${hostname}.iframes.json`);
  const screenshotPath = path.join(PROJECT_TEMP_DIR, `${hostname}.png`);
  const renderedPath = path.join(PROJECT_TEMP_DIR, `${hostname}.rendered.txt`);
  const captureMetaPath = path.join(PROJECT_TEMP_DIR, `${hostname}.capture.json`);

  console.log(`[1/8] Launching browser for: ${targetUrl}`);
  console.log(`      Output folder: ${PROJECT_TEMP_DIR}`);

  const browser = await puppeteer.launch({
    headless: "new",
    channel: "chrome",
    args: [
      "--no-sandbox",
      "--disable-setuid-sandbox",
      "--disable-popup-blocking=false",
      "--window-size=1920,1080",
    ],
  });

  const page = await browser.newPage();
  await page.setViewport({ width: 1920, height: 1080 });
  await page.setUserAgent(USER_AGENT);
  await setupDefenses(browser, page);

  try {
    console.log("[2/8] Navigating...");
    const navigation = await gotoWithFallback(page, targetUrl);
    const finalUrl = navigation.url;
    const httpStatus = navigation.httpStatus;
    await waitForSettle(page);
    await sleep(2000);

    console.log("[3/8] Checking for pop-ups...");
    await dismissDomPopups(page);

    console.log("[4/8] Scrolling to hydrate lazy content...");
    await scrollForLazyContent(page);

    console.log("[5/8] Extracting child iframes (CDP, incl. cross-origin)...");
    // Give nested safeframes a beat after scroll/settle.
    await sleep(1500);
    const iframes = await extractChildFrames(page);
    console.log(`      Found ${iframes.length} iframe(s)`);

    console.log("[6/8] Saving screenshot...");
    await page.screenshot({ path: screenshotPath, fullPage: true });
    console.log(`      -> ${screenshotPath}`);

    console.log("[7/8] Saving HTML + rendered body text (main + iframes)...");
    // Browser-visible body text for analysisText (preferred over DOM fallback).
    const renderedText = await page.evaluate(
      () => document.body?.innerText?.replace(/\s+/g, " ").trim() ?? "",
    );
    // Serialize main DOM, then splice iframe bodies before the *last* </body>.
    // Do not flatten via contentDocument — that only works same-origin and
    // misses parked-domain safeframes. Do not replace the first </body> —
    // ad scripts often embed HTML strings that contain a fake </body>.
    const mainHtml = await page.content();
    const mergedHtml = mergeFramesIntoHtml(mainHtml, iframes);
    await fs.writeFile(htmlPath, mergedHtml, "utf8");
    await fs.writeFile(renderedPath, renderedText, "utf8");
    // Sidecar so scrape:false reuse still has finalUrl + httpStatus (Access_Denied).
    await fs.writeFile(
      captureMetaPath,
      JSON.stringify({ finalUrl, httpStatus }, null, 2),
      "utf8",
    );
    await fs.writeFile(
      iframePath,
      JSON.stringify(
        iframes.map(({ url, text, html }) => ({
          url,
          text,
          htmlLength: html.length,
          html,
        })),
        null,
        2,
      ),
      "utf8",
    );
    console.log(`      -> ${htmlPath}`);
    console.log(`      -> ${renderedPath}`);
    console.log(`      -> ${iframePath}`);
    console.log(`      -> ${captureMetaPath}`);
    console.log(
      `      Loaded: ${finalUrl}` +
        (httpStatus != null ? ` (HTTP ${httpStatus})` : ""),
    );

    return {
      htmlPath,
      screenshotPath,
      iframePath,
      renderedPath,
      renderedText,
      finalUrl,
      httpStatus,
      iframes,
    };
  } catch (error) {
    console.error(`\nError capturing ${targetUrl}:`, error.message);
    return null;
  } finally {
    console.log("[8/8] Closing browser...");
    await browser.close();
    console.log("Done.\n");
  }
}

// CLI: node src/collection/capture/puppeteerAgent.js [url]
const isDirectRun =
  process.argv[1] &&
  path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);

if (isDirectRun) {
  const target = process.argv[2] || "cpa-umobile.com";
  captureWebsite(target).catch(console.error);
}
