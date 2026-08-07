/**
 * Node wrapper around scripts/chunker.py.
 * Feeds htmlAnalyzer output and returns embedding-ready text chunks.
 */

import { spawn } from "child_process";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(__dirname, "../../..");
const CHUNKER_PY = path.join(ROOT, "scripts", "chunker.py");

/** Prefer project .venv when present. */
function resolvePython() {
  const win = path.join(ROOT, ".venv", "Scripts", "python.exe");
  const unix = path.join(ROOT, ".venv", "bin", "python");
  if (fs.existsSync(win)) return win;
  if (fs.existsSync(unix)) return unix;
  return "python";
}

/**
 * @typedef {Object} TextChunk
 * @property {string} text
 * @property {{ zone?: string, [key: string]: unknown }} [metadata]
 */

/**
 * @typedef {Object} ChunkerPayload
 * @property {string[]|string} [visibleText]
 * @property {object} [textZones]
 */

/**
 * Run the Python text chunker on htmlAnalyzer output.
 *
 * @param {ChunkerPayload} analysis
 * @returns {Promise<TextChunk[]>}
 */
export function chunkHtmlAnalysis(analysis) {
  return new Promise((resolve, reject) => {
    const child = spawn(resolvePython(), [CHUNKER_PY], {
      cwd: ROOT,
      stdio: ["pipe", "pipe", "pipe"],
    });

    let stdout = "";
    let stderr = "";

    child.stdout.on("data", (buf) => {
      stdout += buf.toString();
    });
    child.stderr.on("data", (buf) => {
      stderr += buf.toString();
    });
    child.on("error", reject);
    child.on("close", (code) => {
      if (code !== 0) {
        reject(new Error(stderr || `chunker exited with code ${code}`));
        return;
      }
      try {
        const parsed = JSON.parse(stdout);
        if (!Array.isArray(parsed)) {
          reject(new Error("chunker returned non-array JSON"));
          return;
        }
        resolve(
          parsed.filter(
            (c) => c && typeof c.text === "string" && c.text.trim(),
          ),
        );
      } catch (err) {
        reject(
          new Error(
            `Failed to parse chunker JSON: ${err.message}\n---\n${stdout.slice(0, 500)}`,
          ),
        );
      }
    });

    child.stdin.write(
      JSON.stringify({
        visibleText: analysis?.visibleText,
        textZones: analysis?.textZones,
      }),
    );
    child.stdin.end();
  });
}
