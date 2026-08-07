/**
 * Per-run analysis artifact writer — data/runs/{hostname}_{ISO}/
 */

import fs from "fs/promises";
import path from "path";
import { fileURLToPath } from "url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../..");
const RUNS_DIR = path.join(ROOT, "data", "runs");

/**
 * @param {string} hostname
 * @returns {Promise<string>} Absolute path to the new run directory
 */
export async function createRunDir(hostname) {
  const safeHost = String(hostname || "unknown")
    .replace(/[^a-zA-Z0-9._-]+/g, "_")
    .replace(/^_+|_+$/g, "") || "unknown";
  const stamp = new Date().toISOString().replace(/[:.]/g, "").replace(/Z$/, "Z");
  const runDir = path.join(RUNS_DIR, `${safeHost}_${stamp}`);
  await fs.mkdir(runDir, { recursive: true });
  return runDir;
}

/**
 * Write a pretty-printed stage JSON file into a run directory.
 * @param {string} runDir
 * @param {string} filename
 * @param {unknown} data
 * @returns {Promise<string>} Absolute path written
 */
export async function writeStage(runDir, filename, data) {
  if (!runDir) return "";
  await fs.mkdir(runDir, { recursive: true });
  const filePath = path.join(runDir, filename);
  await fs.writeFile(filePath, `${JSON.stringify(data, null, 2)}\n`, "utf8");
  return filePath;
}

export { RUNS_DIR, ROOT };
