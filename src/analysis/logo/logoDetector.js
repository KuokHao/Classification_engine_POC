/**
 * Brand logo detector — scores htmlAnalyzer image candidates against a local
 * reference logo via BytePlus Skylark multimodal embeddings (cosine similarity).
 *
 * Does not parse HTML. Candidates come from htmlAnalyzer.images.
 * Checks likely logos first (icons, brand/logo alt, path/class), then og/rest.
 * A match requires cosine similarity >= 0.80; first hit early-exits.
 * SVG candidates are rasterized to PNG via sharp before embedding.
 */

import fs from "fs";
import path from "path";
import sharp from "sharp";
import { ARK_API_KEY } from "../../../config/config.js";
import {
  cosineSimilarity,
  fetchImageEmbedding as fetchImageEmbeddingRemote,
  MODEL_NAME,
  EMBEDDINGS_URL,
} from "../embeddings/embeddingsClient.js";

const DEFAULT_MAX_CANDIDATES = 15;
const DEFAULT_THRESHOLD = 0.8;

/**
 * @typedef {Object} ImageCandidate
 * @property {string} src
 * @property {string} [alt]
 * @property {string} [kind]
 * @property {string} [rel]
 * @property {string} [className]
 * @property {string} [id]
 */

/**
 * @typedef {Object} LogoMatch
 * @property {string} url
 * @property {number} similarity
 * @property {string} [kind]
 * @property {number} [rank]
 */

/**
 * @param {string[]} brandNames
 * @returns {string[]}
 */
function brandTokens(brandNames) {
  const tokens = new Set();
  for (const name of brandNames ?? []) {
    const normalized = String(name ?? "")
      .toLowerCase()
      .replace(/[^a-z0-9\s]/g, " ")
      .replace(/\s+/g, " ")
      .trim();
    if (!normalized) continue;
    tokens.add(normalized);
    for (const part of normalized.split(" ")) {
      if (part.length >= 2) tokens.add(part);
    }
    const compact = normalized.replace(/\s+/g, "");
    if (compact.length >= 2) tokens.add(compact);
  }
  return [...tokens];
}

/**
 * @param {string} text
 * @param {string[]} tokens
 * @returns {boolean}
 */
function textMentionsBrand(text, tokens) {
  if (!text || tokens.length === 0) return false;
  const hay = String(text).toLowerCase();
  return tokens.some((token) => hay.includes(token));
}

/**
 * @param {string} src
 * @param {string} [baseUrl]
 * @returns {string}
 */
function toAbsoluteUrl(src, baseUrl) {
  const raw = String(src ?? "").trim();
  if (!raw) return "";
  if (raw.startsWith("data:")) return raw;
  try {
    return new URL(raw, baseUrl || undefined).href;
  } catch {
    return raw;
  }
}

/**
 * @param {string} url
 * @returns {boolean}
 */
function isSvgUrl(url) {
  const u = String(url ?? "").toLowerCase();
  if (u.startsWith("data:image/svg")) return true;
  try {
    const parsed = new URL(u);
    return /\.svg(\?|#|$)/i.test(parsed.pathname);
  } catch {
    return /\.svg(\?|#|$)/i.test(u);
  }
}

/**
 * Path/filename only for brand matching (ignore hostname).
 * @param {string} url
 * @param {string[]} tokens
 * @returns {boolean}
 */
function pathMentionsBrandOrLogo(url, tokens) {
  if (/logo/i.test(url)) return true;
  try {
    const parsed = new URL(url);
    return textMentionsBrand(
      decodeURIComponent(`${parsed.pathname}${parsed.search}`),
      tokens,
    );
  } catch {
    return textMentionsBrand(url, tokens);
  }
}

/**
 * Rank analyzer candidates for check order:
 *   0 icons → 1 brand/logo alt → 2 logo/brand path/class → 3 og → 4 rest
 *
 * @param {Array<string | ImageCandidate>} images
 * @param {string[]} brandNames
 * @param {string} [baseUrl]
 * @returns {Array<{ url: string, alt: string, kind: string, rank: number }>}
 */
function prioritizeImages(images, brandNames = [], baseUrl = "") {
  const tokens = brandTokens(brandNames);
  /** @type {Map<string, { url: string, alt: string, kind: string, rank: number }>} */
  const byUrl = new Map();

  for (const item of images ?? []) {
    const src = typeof item === "string" ? item : item?.src;
    const alt = typeof item === "string" ? "" : String(item?.alt ?? "");
    const kind = typeof item === "string" ? "img" : String(item?.kind ?? "img");
    const rel = typeof item === "string" ? "" : String(item?.rel ?? "");
    const className =
      typeof item === "string" ? "" : String(item?.className ?? "");
    const id = typeof item === "string" ? "" : String(item?.id ?? "");
    const url = toAbsoluteUrl(src, baseUrl);
    if (!url || byUrl.has(url)) continue;

    const isIcon =
      kind === "icon" ||
      /\bicon\b/i.test(rel) ||
      /apple-touch-icon/i.test(rel);
    const altHit =
      /\blogo\b/i.test(alt) || textMentionsBrand(alt, tokens);
    const pathHit =
      pathMentionsBrandOrLogo(url, tokens) ||
      textMentionsBrand(`${className} ${id}`, tokens) ||
      /\blogo\b/i.test(`${className} ${id}`);
    const isOg = kind === "og";

    let rank = 4;
    if (isIcon) rank = 0;
    else if (altHit) rank = 1;
    else if (pathHit) rank = 2;
    else if (isOg) rank = 3;

    byUrl.set(url, { url, alt, kind, rank });
  }

  return [...byUrl.values()].sort(
    (a, b) => a.rank - b.rank || a.url.localeCompare(b.url),
  );
}

/**
 * @param {string} logoPath
 * @returns {string}
 */
function logoToDataUrl(logoPath) {
  const ext = path.extname(logoPath).substring(1).toLowerCase();
  const mimeType = ext === "jpg" ? "jpeg" : ext || "png";
  const logoBuffer = fs.readFileSync(logoPath);
  return `data:image/${mimeType};base64,${logoBuffer.toString("base64")}`;
}

/**
 * Fetch image bytes (http/https or data URL).
 * @param {string} imageUrl
 * @returns {Promise<Buffer>}
 */
async function fetchImageBuffer(imageUrl) {
  if (imageUrl.startsWith("data:")) {
    const comma = imageUrl.indexOf(",");
    if (comma < 0) throw new Error("Invalid data URL");
    const meta = imageUrl.slice(0, comma);
    const payload = imageUrl.slice(comma + 1);
    if (/;base64/i.test(meta)) {
      return Buffer.from(payload, "base64");
    }
    return Buffer.from(decodeURIComponent(payload), "utf8");
  }

  const res = await fetch(imageUrl, {
    redirect: "follow",
    headers: {
      "User-Agent":
        "Mozilla/5.0 (compatible; WorkerPOCLogoDetector/1.0)",
    },
  });
  if (!res.ok) {
    throw new Error(`HTTP ${res.status} fetching ${imageUrl}`);
  }
  return Buffer.from(await res.arrayBuffer());
}

/**
 * Prepare an embeddable image URL (rasterize SVG → PNG data URL).
 * @param {string} imageUrl
 * @returns {Promise<string|null>}
 */
async function prepareEmbedUrl(imageUrl) {
  if (!isSvgUrl(imageUrl) && !imageUrl.startsWith("data:image/svg")) {
    return imageUrl;
  }
  try {
    const buf = await fetchImageBuffer(imageUrl);
    const png = await sharp(buf).png().toBuffer();
    return `data:image/png;base64,${png.toString("base64")}`;
  } catch (err) {
    console.warn(
      `[logodetector] SVG rasterize failed: ${imageUrl}`,
      err?.message ?? err,
    );
    return null;
  }
}

/**
 * @param {string} imageUrl
 * @param {string} apiKey
 * @returns {Promise<number[] | null>}
 */
async function fetchImageEmbedding(imageUrl, apiKey) {
  const embedUrl = await prepareEmbedUrl(imageUrl);
  if (!embedUrl) return null;
  return fetchImageEmbeddingRemote(embedUrl, { apiKey, softFail: true });
}

/**
 * Scan htmlAnalyzer image candidates against a local brand logo.
 *
 * @param {string} logoPath
 * @param {Array<string | ImageCandidate>} images
 * @param {object} [options]
 * @param {string} [options.apiKey]
 * @param {string[]} [options.brandNames]
 * @param {string} [options.baseUrl]
 * @param {number} [options.threshold=0.8]
 * @param {number} [options.maxCandidates=15]
 * @returns {Promise<{ logo_detected: boolean, matches: LogoMatch[], candidatesChecked: number, stoppedEarly: boolean }>}
 */
async function detectBrandLogo(logoPath, images, options = {}) {
  const apiKey = options.apiKey ?? process.env.ARK_API_KEY ?? ARK_API_KEY;
  const threshold = options.threshold ?? DEFAULT_THRESHOLD;
  const maxCandidates = options.maxCandidates ?? DEFAULT_MAX_CANDIDATES;
  const brandNames = options.brandNames ?? [];
  const baseUrl = options.baseUrl ?? "";

  if (!apiKey) {
    throw new Error(
      "BytePlus API key missing — set ARK_API_KEY in config/config.js",
    );
  }
  if (!logoPath || !fs.existsSync(logoPath)) {
    throw new Error(`Reference logo not found: ${logoPath}`);
  }

  const candidates = prioritizeImages(images, brandNames, baseUrl).slice(
    0,
    maxCandidates,
  );

  if (candidates.length === 0) {
    return {
      logo_detected: false,
      matches: [],
      candidatesChecked: 0,
      stoppedEarly: false,
    };
  }

  const logoVector = await fetchImageEmbedding(
    logoToDataUrl(logoPath),
    apiKey,
  );
  if (!logoVector) {
    throw new Error(`Failed to embed reference logo: ${logoPath}`);
  }

  /** @type {LogoMatch[]} */
  const matches = [];
  let checked = 0;
  let stoppedEarly = false;

  for (const candidate of candidates) {
    checked += 1;
    const vector = await fetchImageEmbedding(candidate.url, apiKey);
    if (!vector) continue;

    const similarity = cosineSimilarity(logoVector, vector);
    if (similarity < threshold) continue;

    matches.push({
      url: candidate.url,
      similarity: parseFloat(similarity.toFixed(4)),
      kind: candidate.kind,
      rank: candidate.rank,
    });
    stoppedEarly = true;
    break;
  }

  return {
    logo_detected: matches.length > 0,
    matches,
    candidatesChecked: checked,
    stoppedEarly,
  };
}

export {
  detectBrandLogo,
  prioritizeImages,
  cosineSimilarity,
  MODEL_NAME,
  EMBEDDINGS_URL,
  DEFAULT_THRESHOLD,
};
