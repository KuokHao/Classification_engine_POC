/**
 * Brand DAL — local JSON file store for brand profiles (no database).
 *
 * File: <projectRoot>/data/brands.json
 * Shape: { "brands": [ { brandId, brandNames, officialDomains, ... }, ... ] }
 */

import fs from "fs/promises";
import path from "path";
import { fileURLToPath } from "url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const DATA_DIR = path.resolve(__dirname, "../../../data");
const BRANDS_FILE = path.join(DATA_DIR, "brands.json");

/**
 * @returns {Promise<{ brands: object[] }>}
 */
async function readStore() {
  try {
    const raw = await fs.readFile(BRANDS_FILE, "utf8");
    const parsed = JSON.parse(raw);
    if (!parsed || typeof parsed !== "object") {
      return { brands: [] };
    }
    return {
      brands: Array.isArray(parsed.brands) ? parsed.brands : [],
    };
  } catch (err) {
    if (err && (err.code === "ENOENT" || err.name === "SyntaxError")) {
      return { brands: [] };
    }
    throw err;
  }
}

/**
 * @param {{ brands: object[] }} store
 * @returns {Promise<void>}
 */
async function writeStore(store) {
  await fs.mkdir(DATA_DIR, { recursive: true });
  const payload = `${JSON.stringify(store, null, 2)}\n`;
  await fs.writeFile(BRANDS_FILE, payload, "utf8");
}

/**
 * Upsert a brand document by brandId.
 * @param {Record<string, unknown>} doc
 * @returns {Promise<object>}
 */
export async function upsertBrand(doc) {
  const brandId = doc.brandId;
  if (!brandId) {
    throw new Error("upsertBrand requires brandId");
  }

  const store = await readStore();
  const now = new Date().toISOString();
  const idx = store.brands.findIndex(
    (b) => String(b.brandId).toLowerCase() === String(brandId).toLowerCase(),
  );

  /** @type {object} */
  let saved;
  if (idx >= 0) {
    const prev = store.brands[idx];
    saved = {
      ...prev,
      ...doc,
      brandId: String(brandId),
      updatedAt: now,
      createdAt: prev.createdAt ?? now,
    };
    store.brands[idx] = saved;
  } else {
    saved = {
      ...doc,
      brandId: String(brandId),
      createdAt: now,
      updatedAt: now,
    };
    store.brands.push(saved);
  }

  await writeStore(store);
  return saved;
}

/**
 * @param {string} brandId
 * @returns {Promise<object|null>}
 */
export async function findByBrandId(brandId) {
  if (!brandId) return null;
  const needle = String(brandId).trim().toLowerCase();
  if (!needle) return null;

  const store = await readStore();
  return (
    store.brands.find((b) => String(b.brandId ?? "").toLowerCase() === needle) ??
    null
  );
}

/**
 * Case-insensitive exact match on brandId or any brandNames entry.
 * @param {string} name
 * @returns {Promise<object|null>}
 */
export async function findByBrandName(name) {
  if (!name || typeof name !== "string") return null;
  const trimmed = name.trim().toLowerCase();
  if (!trimmed) return null;

  const store = await readStore();
  return (
    store.brands.find((b) => {
      if (String(b.brandId ?? "").toLowerCase() === trimmed) return true;
      const names = Array.isArray(b.brandNames) ? b.brandNames : [];
      return names.some((n) => String(n).trim().toLowerCase() === trimmed);
    }) ?? null
  );
}

/**
 * Absolute path to the brands JSON file (for debugging / CLI messages).
 * @returns {string}
 */
export function getBrandsFilePath() {
  return BRANDS_FILE;
}
