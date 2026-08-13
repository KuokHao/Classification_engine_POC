/**
 * Chunk text produced by htmlAnalyzer.
 *
 * Two-level split:
 *   1) Keep each zone string separate (heading vs paragraph never merge).
 *   2) Inside a long zone, slide a word window (default 8 / step 4).
 *
 * Tokenization is whitespace-only. Non-English pages are translated to English
 * upstream (languageTranslator) before chunking.
 */

/** Prefer reading-order zones when textZones is present */
const ZONE_ORDER = [
  ["titleText", "title"],
  ["iframeText", "iframe"], // captured iframe body (often primary page content)
  ["headingText", "heading"],
  ["paragraphText", "paragraph"],
  ["buttonText", "button"],
  ["linkText", "link"],
  ["labelText", "label"],
  ["placeholderText", "placeholder"],
  ["footerText", "footer"],
  ["imageAltText", "imageAlt"],
  ["formNearbyText", "formNearby"],
];

/**
 * @typedef {Object} TextChunk
 * @property {string} text
 * @property {{ zone?: string, [key: string]: unknown }} [metadata]
 */

/**
 * @typedef {Object} ChunkerPayload
 * @property {string[]|string} [visibleText]
 * @property {object} [textZones]
 * @property {string} [text]
 */

/**
 * Python-style truthiness for zone presence (empty list / "" are absent).
 * @param {unknown} value
 */
function pyTruthy(value) {
  if (value == null) return false;
  if (typeof value === "boolean") return value;
  if (typeof value === "number") return value !== 0;
  if (typeof value === "string") return value.length > 0;
  if (Array.isArray(value)) return value.length > 0;
  if (typeof value === "object") return Object.keys(value).length > 0;
  return Boolean(value);
}

/**
 * Sliding window over words (not characters). O(n) in token count.
 *
 * @param {string} text
 * @param {number} [windowSize=8]
 * @param {number} [stepSize=4]
 * @returns {string[]}
 */
export function slidingWindowChunker(text, windowSize = 8, stepSize = 4) {
  if (windowSize < 1 || stepSize < 1) return [];
  if (typeof text !== "string" || !text.trim()) return [];

  const words = text.trim().split(/\s+/);
  if (!words.length) return [];

  if (words.length <= windowSize) {
    return [words.join(" ")];
  }

  const chunks = [];
  for (let i = 0; i < words.length; i += stepSize) {
    chunks.push(words.slice(i, i + windowSize).join(" "));
    if (i + windowSize >= words.length) break;
  }
  return chunks;
}

/**
 * Flatten textZones into (text, metadata) pairs — one unit per element string.
 * @param {Record<string, unknown>} textZones
 * @returns {Array<[string, { zone: string }]>}
 */
function docsFromZones(textZones) {
  /** @type {Array<[string, { zone: string }]>} */
  const docs = [];

  for (const [field, zone] of ZONE_ORDER) {
    const value = textZones[field];
    if (typeof value === "string" && value.trim()) {
      docs.push([value.trim(), { zone }]);
    } else if (Array.isArray(value)) {
      for (const item of value) {
        const piece = String(item).trim();
        if (piece) docs.push([piece, { zone }]);
      }
    }
  }

  return docs;
}

/**
 * Fallback when textZones are missing: one unit per visibleText entry.
 * @param {string[]|string|null|undefined} visibleText
 * @returns {Array<[string, { zone: string }]>}
 */
function docsFromVisibleText(visibleText) {
  /** @type {string[]} */
  let parts;
  if (typeof visibleText === "string") {
    parts = visibleText.trim() ? [visibleText.trim()] : [];
  } else if (Array.isArray(visibleText)) {
    parts = visibleText.map((p) => String(p).trim()).filter(Boolean);
  } else {
    parts = [];
  }
  return parts.map((p) => /** @type {[string, { zone: string }]} */ ([p, { zone: "visibleText" }]));
}

/**
 * Chunk htmlAnalyzer output into embedding-ready pieces.
 *
 * Accepts:
 *   - analyzeHtml() object / { visibleText, textZones }
 *   - a plain string / string list
 *
 * @param {ChunkerPayload|string|string[]} payload
 * @param {number} [windowSize=8]
 * @param {number} [stepSize=4]
 * @returns {TextChunk[]}
 */
export function smartTextChunker(payload, windowSize = 8, stepSize = 4) {
  /** @type {Array<[string, { zone: string }]>} */
  let docs;

  if (typeof payload === "string" || Array.isArray(payload)) {
    docs = docsFromVisibleText(payload);
  } else if (payload && typeof payload === "object") {
    const zones = payload.textZones;
    if (
      zones &&
      typeof zones === "object" &&
      !Array.isArray(zones) &&
      ZONE_ORDER.some(([field]) => pyTruthy(zones[field]))
    ) {
      docs = docsFromZones(zones);
    } else if (Object.prototype.hasOwnProperty.call(payload, "visibleText")) {
      docs = docsFromVisibleText(payload.visibleText);
    } else if (typeof payload.text === "string") {
      docs = docsFromVisibleText(payload.text);
    } else {
      docs = [];
    }
  } else {
    throw new TypeError("payload must be a dict, str, or list of str");
  }

  if (!docs.length) return [];

  /** @type {TextChunk[]} */
  const results = [];
  for (const [text, metadata] of docs) {
    for (const piece of slidingWindowChunker(text, windowSize, stepSize)) {
      results.push({ text: piece, metadata: { ...metadata } });
    }
  }
  return results;
}

/**
 * Chunk htmlAnalyzer output for the classification pipeline.
 *
 * @param {ChunkerPayload|null|undefined} analysis
 * @returns {TextChunk[]}
 */
export function chunkHtmlAnalysis(analysis) {
  return smartTextChunker({
    visibleText: analysis?.visibleText,
    textZones: analysis?.textZones,
  }).filter((c) => c && typeof c.text === "string" && c.text.trim());
}
