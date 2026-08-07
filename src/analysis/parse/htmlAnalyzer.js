import { parse } from "node-html-parser";

/**
 * HTML structure extractor — formats a raw HTML string into a structured
 * document for downstream analysis. No threat analysis lives here.
 *
 * @typedef {Object} MetaFields
 * @property {string} title          - <title> text
 * @property {string} description    - <meta name="description"> content
 * @property {string} ogTitle        - <meta property="og:title"> content
 * @property {string} ogSiteName     - <meta property="og:site_name"> content
 * @property {string} ogDescription  - <meta property="og:description"> content
 * @property {string} icon           - <link rel="icon"> href
 * @property {string} canonical      - <link rel="canonical"> href
 */

/**
 * @typedef {Object} ImageInfo
 * @property {string} src
 * @property {string} [alt]
 * @property {string} kind - "img" | "icon" | "og" | "srcset" | "lazy" | "css_bg" | "poster" | "svg_image" | "object"
 * @property {string} [rel]
 * @property {string} [className]
 * @property {string} [id]
 */

/**
 * @typedef {{ name: string, value: string }} HiddenField
 */

/**
 * @typedef {{ type: string, name: string, id: string, autocomplete: string }} InputField
 */

/**
 * @typedef {Object} FormInfo
 * @property {string}        action
 * @property {string}        method
 * @property {HiddenField[]} hiddenFields
 * @property {InputField[]}  allInputs
 * @property {number}        inputCount
 */

/**
 * @typedef {Object} LinkInfo
 * @property {string} text
 * @property {string} href
 * @property {string} [rel]
 */

/**
 * @typedef {Object} IframeShell
 * @property {string} src
 * @property {string} title
 */

/**
 * Structured HTML document (structure only — no threat signals).
 *
 * @typedef {Object} HtmlAnalysis
 * @property {MetaFields}     meta
 * @property {string[]}       visibleText     - deduplicated, whitespace-normalised visible strings
 * @property {ImageInfo[]}    images
 * @property {FormInfo[]}     forms
 * @property {LinkInfo[]}     links
 * @property {object}         textZones       - zone-tagged text for chunking / analysis
 * @property {object[]}       structuredData  - parsed JSON-LD objects
 * @property {IframeShell[]}  iframes         - outer <iframe> shells (src/title only)
 */

const VISIBLE_TEXT_SELECTORS = "h1, h2, h3, p, span, div, a, button, label, li";

/**
 * Read an attribute from the first matching element, returning "" when absent.
 * @param {import("node-html-parser").HTMLElement} root
 * @param {string} selector
 * @param {string} attr
 * @returns {string}
 */
function attr(root, selector, attr) {
  const el = root.querySelector(selector);
  return el ? (el.getAttribute(attr) ?? "").trim() : "";
}

/**
 * Pass 1 — extract <meta> and <link> metadata fields.
 * @param {import("node-html-parser").HTMLElement} root
 * @returns {MetaFields}
 */
function extractMeta(root) {
  const titleEl = root.querySelector("title");
  return {
    title: String(titleEl?.innerText ?? "").replace(/\s+/g, " ").trim(),
    description: attr(root, 'meta[name="description"]', "content"),
    ogTitle: attr(root, 'meta[property="og:title"]', "content"),
    ogSiteName: attr(root, 'meta[property="og:site_name"]', "content"),
    ogDescription: attr(root, 'meta[property="og:description"]', "content"),
    icon:
      attr(root, 'link[rel="icon"]', "href") ||
      attr(root, 'link[rel="shortcut icon"]', "href"),
    canonical: attr(root, 'link[rel="canonical"]', "href"),
  };
}

/**
 * True when the element or an ancestor is aria-hidden (cookie chrome, etc.).
 * @param {import("node-html-parser").HTMLElement | null | undefined} el
 * @returns {boolean}
 */
function isAriaHidden(el) {
  let cur = el;
  while (cur && typeof cur.getAttribute === "function") {
    if ((cur.getAttribute("aria-hidden") ?? "").trim().toLowerCase() === "true") {
      return true;
    }
    cur = cur.parentNode;
  }
  return false;
}

/**
 * Pass 2 — collect visible text from semantic/content elements.
 * Deduplicates and discards blank / aria-hidden strings.
 * @param {import("node-html-parser").HTMLElement} root
 * @returns {string[]}
 */
function extractVisibleText(root) {
  const seen = new Set();
  const results = [];

  for (const el of root.querySelectorAll(VISIBLE_TEXT_SELECTORS)) {
    if (isAriaHidden(el)) continue;
    const raw = el.innerText ?? "";
    const normalized = raw.replace(/\s+/g, " ").trim();
    if (normalized && !seen.has(normalized)) {
      seen.add(normalized);
      results.push(normalized);
    }
  }

  return results;
}

/**
 * First URL token from a srcset-like attribute.
 * @param {string} srcset
 * @returns {string}
 */
function firstSrcsetUrl(srcset) {
  const raw = String(srcset ?? "").trim();
  if (!raw) return "";
  const first = raw.split(",")[0]?.trim() ?? "";
  return (first.split(/\s+/)[0] ?? "").trim();
}

/**
 * Extract url(...) values from an inline style string.
 * @param {string} style
 * @returns {string[]}
 */
function urlsFromStyle(style) {
  const out = [];
  const re = /url\(\s*['"]?([^'")]+)['"]?\s*\)/gi;
  let m;
  while ((m = re.exec(String(style ?? ""))) !== null) {
    const u = (m[1] ?? "").trim();
    if (u) out.push(u);
  }
  return out;
}

/**
 * @param {string} src
 * @returns {boolean}
 */
function looksLikeImageSrc(src) {
  const s = String(src ?? "").trim().toLowerCase();
  if (!s || s.startsWith("data:text")) return false;
  if (s.startsWith("data:image/")) return true;
  return /\.(png|jpe?g|gif|webp|svg|ico|avif|bmp)(\?|#|$)/i.test(s);
}

/**
 * Pass 3 — collect image-like assets for logo / image analysis.
 * Includes favicons, OG images, img/lazy/srcset, CSS backgrounds, posters, etc.
 * Dedupes by normalized src string.
 *
 * @param {import("node-html-parser").HTMLElement} root
 * @returns {ImageInfo[]}
 */
function extractImages(root) {
  /** @type {Map<string, ImageInfo>} */
  const bySrc = new Map();

  /**
   * @param {Partial<ImageInfo> & { src?: string }} candidate
   */
  const push = (candidate) => {
    const src = String(candidate.src ?? "").trim();
    if (!src || bySrc.has(src)) return;
    bySrc.set(src, {
      src,
      alt: String(candidate.alt ?? "").trim(),
      kind: candidate.kind || "img",
      rel: candidate.rel ? String(candidate.rel).trim() : undefined,
      className: candidate.className
        ? String(candidate.className).trim()
        : undefined,
      id: candidate.id ? String(candidate.id).trim() : undefined,
    });
  };

  // Favicons / touch icons
  for (const el of root.querySelectorAll("link[rel]")) {
    const rel = (el.getAttribute("rel") ?? "").trim().toLowerCase();
    if (
      !/\bicon\b/.test(rel) &&
      !rel.includes("apple-touch-icon") &&
      !rel.includes("mask-icon")
    ) {
      continue;
    }
    const href = (el.getAttribute("href") ?? "").trim();
    if (!href) continue;
    push({
      src: href,
      kind: "icon",
      rel,
      className: el.getAttribute("class") ?? "",
      id: el.getAttribute("id") ?? "",
    });
  }

  // Open Graph / social / tile images
  const metaImageSelectors = [
    'meta[property="og:image"]',
    'meta[name="og:image"]',
    'meta[name="twitter:image"]',
    'meta[property="twitter:image"]',
    'meta[name="msapplication-TileImage"]',
  ];
  for (const sel of metaImageSelectors) {
    for (const el of root.querySelectorAll(sel)) {
      const content = (el.getAttribute("content") ?? "").trim();
      if (content) push({ src: content, kind: "og" });
    }
  }

  // <img> + lazy + srcset
  for (const img of root.querySelectorAll("img")) {
    const alt = (img.getAttribute("alt") ?? "").trim();
    const className = img.getAttribute("class") ?? "";
    const id = img.getAttribute("id") ?? "";
    const src = (img.getAttribute("src") ?? "").trim();
    if (src) push({ src, alt, kind: "img", className, id });

    for (const lazyAttr of [
      "data-src",
      "data-lazy-src",
      "data-original",
      "loading-src",
    ]) {
      const lazy = (img.getAttribute(lazyAttr) ?? "").trim();
      if (lazy) push({ src: lazy, alt, kind: "lazy", className, id });
    }

    const srcset = firstSrcsetUrl(img.getAttribute("srcset") ?? "");
    if (srcset) push({ src: srcset, alt, kind: "srcset", className, id });
    const dataSrcset = firstSrcsetUrl(img.getAttribute("data-srcset") ?? "");
    if (dataSrcset) {
      push({ src: dataSrcset, alt, kind: "srcset", className, id });
    }
  }

  // <picture> / <source>
  for (const source of root.querySelectorAll("source")) {
    const className = source.getAttribute("class") ?? "";
    const id = source.getAttribute("id") ?? "";
    const src = (source.getAttribute("src") ?? "").trim();
    if (src) push({ src, kind: "srcset", className, id });
    const srcset = firstSrcsetUrl(source.getAttribute("srcset") ?? "");
    if (srcset) push({ src: srcset, kind: "srcset", className, id });
    const dataSrc = (source.getAttribute("data-src") ?? "").trim();
    if (dataSrc) push({ src: dataSrc, kind: "lazy", className, id });
  }

  // Inline CSS background-image
  for (const el of root.querySelectorAll("[style]")) {
    const style = el.getAttribute("style") ?? "";
    if (!/background-image/i.test(style) && !/url\(/i.test(style)) continue;
    for (const u of urlsFromStyle(style)) {
      push({
        src: u,
        kind: "css_bg",
        className: el.getAttribute("class") ?? "",
        id: el.getAttribute("id") ?? "",
        alt: (el.getAttribute("aria-label") ?? el.getAttribute("title") ?? "").trim(),
      });
    }
  }

  // Video posters
  for (const el of root.querySelectorAll("video[poster]")) {
    const poster = (el.getAttribute("poster") ?? "").trim();
    if (poster) {
      push({
        src: poster,
        kind: "poster",
        className: el.getAttribute("class") ?? "",
        id: el.getAttribute("id") ?? "",
      });
    }
  }

  // Inline SVG <image>
  for (const el of root.querySelectorAll("image")) {
    const href =
      (el.getAttribute("href") ?? el.getAttribute("xlink:href") ?? "").trim();
    if (href) {
      push({
        src: href,
        kind: "svg_image",
        className: el.getAttribute("class") ?? "",
        id: el.getAttribute("id") ?? "",
      });
    }
  }

  // <object> / <embed> image-like
  for (const el of root.querySelectorAll("object[data], embed[src]")) {
    const src =
      (el.getAttribute("data") ?? el.getAttribute("src") ?? "").trim();
    if (src && looksLikeImageSrc(src)) {
      push({
        src,
        kind: "object",
        className: el.getAttribute("class") ?? "",
        id: el.getAttribute("id") ?? "",
      });
    }
  }

  return [...bySrc.values()];
}

/**
 * Normalize and deduplicate text entries for a zone.
 * @param {Set<string>} seen
 * @param {string} raw
 * @returns {string | null}
 */
function pushZoneText(seen, raw) {
  const normalized = String(raw ?? "").replace(/\s+/g, " ").trim();
  if (!normalized || seen.has(normalized)) {
    return null;
  }
  seen.add(normalized);
  return normalized;
}

/**
 * Pass 4 — extract zone-tagged text for semantic analysis.
 * @param {import("node-html-parser").HTMLElement} root
 * @returns {object}
 */
function extractTextZones(root) {
  const seen = {
    heading: new Set(),
    button: new Set(),
    link: new Set(),
    label: new Set(),
    placeholder: new Set(),
    paragraph: new Set(),
    footer: new Set(),
    imageAlt: new Set(),
    formNearby: new Set(),
    iframe: new Set(),
  };

  const zones = {
    headingText: [],
    buttonText: [],
    linkText: [],
    labelText: [],
    placeholderText: [],
    paragraphText: [],
    footerText: [],
    imageAltText: [],
    formNearbyText: [],
    iframeText: [],
  };

  const titleEl = root.querySelector("title");
  zones.titleText = pushZoneText(new Set(), titleEl?.innerText ?? "") ?? undefined;
  if (!zones.titleText) {
    zones.titleText = attr(root, 'meta[property="og:title"]', "content") || undefined;
  }

  for (const el of root.querySelectorAll("h1, h2, h3")) {
    const text = pushZoneText(seen.heading, el.innerText ?? "");
    if (text) zones.headingText.push(text);
  }

  for (const el of root.querySelectorAll("button, input[type='submit'], input[type='button']")) {
    const text = pushZoneText(
      seen.button,
      el.innerText || el.getAttribute("value") || ""
    );
    if (text) zones.buttonText.push(text);
  }

  for (const el of root.querySelectorAll("a")) {
    const text = pushZoneText(seen.link, el.innerText ?? "");
    if (text) zones.linkText.push(text);
  }

  for (const el of root.querySelectorAll("label")) {
    const text = pushZoneText(seen.label, el.innerText ?? "");
    if (text) zones.labelText.push(text);
  }

  for (const el of root.querySelectorAll("input, textarea")) {
    const text = pushZoneText(seen.placeholder, el.getAttribute("placeholder") ?? "");
    if (text) zones.placeholderText.push(text);
  }

  for (const el of root.querySelectorAll("p")) {
    const text = pushZoneText(seen.paragraph, el.innerText ?? "");
    if (text) zones.paragraphText.push(text);
  }

  for (const el of root.querySelectorAll("footer, [role='contentinfo']")) {
    const text = pushZoneText(seen.footer, el.innerText ?? "");
    if (text) zones.footerText.push(text);
  }

  for (const el of root.querySelectorAll("img")) {
    const text = pushZoneText(seen.imageAlt, el.getAttribute("alt") ?? "");
    if (text) zones.imageAltText.push(text);
  }

  for (const form of root.querySelectorAll("form")) {
    const formText = pushZoneText(seen.formNearby, form.innerText ?? "");
    if (formText) zones.formNearbyText.push(formText);
  }

  // Captured iframe bodies inlined by puppeteeragent ([data-captured-iframe]).
  for (const el of root.querySelectorAll("[data-captured-iframe]")) {
    const text = pushZoneText(seen.iframe, el.innerText ?? "");
    if (text) zones.iframeText.push(text);
  }

  const visibleParts = extractVisibleText(root);
  zones.visibleText = visibleParts.join(". ");

  return zones;
}

/**
 * Pass 5 — extract form structures (raw fields only).
 * @param {import("node-html-parser").HTMLElement} root
 * @returns {FormInfo[]}
 */
function extractForms(root) {
  return root.querySelectorAll("form").map((form) => {
    const action = (form.getAttribute("action") ?? "").trim();
    const method = (form.getAttribute("method") ?? "get").trim().toUpperCase() || "GET";

    /** @type {InputField[]} */
    const allInputs = form.querySelectorAll("input").map((input) => ({
      type: (input.getAttribute("type") ?? "").trim().toLowerCase(),
      name: (input.getAttribute("name") ?? "").trim(),
      id: (input.getAttribute("id") ?? "").trim(),
      autocomplete: (input.getAttribute("autocomplete") ?? "").trim().toLowerCase(),
    }));

    /** @type {HiddenField[]} */
    const hiddenFields = form
      .querySelectorAll('input[type="hidden"]')
      .map((input) => ({
        name: (input.getAttribute("name") ?? "").trim(),
        value: (input.getAttribute("value") ?? "").trim(),
      }));

    return {
      action,
      method,
      hiddenFields,
      allInputs,
      inputCount: allInputs.length,
    };
  });
}

/**
 * Pass 6 — extract raw anchor links (text + href + rel).
 * @param {import("node-html-parser").HTMLElement} root
 * @returns {LinkInfo[]}
 */
function extractLinks(root) {
  return root.querySelectorAll("a").map((anchor) => ({
    text: String(anchor.innerText ?? "").replace(/\s+/g, " ").trim(),
    href: (anchor.getAttribute("href") ?? "").trim(),
    rel: (anchor.getAttribute("rel") ?? "").trim(),
  }));
}

/**
 * Pass 7 — parse JSON-LD structured data (Organization, Product, etc.).
 * Uses the raw HTML string because script bodies are not always retained as
 * element text under node-html-parser settings.
 *
 * @param {string} htmlString
 * @returns {object[]}
 */
function extractStructuredData(htmlString) {
  /** @type {object[]} */
  const data = [];
  const re =
    /<script[^>]*type\s*=\s*["']application\/ld\+json["'][^>]*>([\s\S]*?)<\/script>/gi;
  let match;
  while ((match = re.exec(String(htmlString ?? ""))) !== null) {
    try {
      const parsed = JSON.parse(match[1].trim());
      if (Array.isArray(parsed)) data.push(...parsed);
      else if (parsed && typeof parsed === "object") data.push(parsed);
    } catch {
      /* malformed JSON-LD — skip */
    }
  }
  return data;
}

/**
 * Pass 8 — inventory outer <iframe> shells (src/title). Full frame bodies are
 * inlined separately by puppeteeragent as [data-captured-iframe].
 *
 * @param {import("node-html-parser").HTMLElement} root
 * @returns {IframeShell[]}
 */
function extractIframeShells(root) {
  return root.querySelectorAll("iframe").map((el) => ({
    src: (el.getAttribute("src") ?? el.getAttribute("data-src") ?? "").trim(),
    title: (el.getAttribute("title") ?? "").trim(),
  }));
}

/**
 * Parse a raw HTML string into a structured document for analysis.
 *
 * @param {string} htmlString - Raw HTML content of a web page.
 * @returns {HtmlAnalysis}
 */
export function analyzeHtml(htmlString) {
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

  return {
    meta: extractMeta(root),
    visibleText: extractVisibleText(root),
    images: extractImages(root),
    forms: extractForms(root),
    links: extractLinks(root),
    textZones: extractTextZones(root),
    structuredData: extractStructuredData(htmlString),
    iframes: extractIframeShells(root),
  };
}

export { extractTextZones };
