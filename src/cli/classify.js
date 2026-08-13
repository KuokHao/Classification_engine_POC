/**
 * CLI helper for single-job classification from a JSON file or stdin.
 *
 * Usage:
 *   node src/cli/classify.js job.json
 *   echo '{"url":"https://example.com","html":"<html>...</html>"}' | node src/cli/classify.js
 */

import "../../config/loadEnv.js";
import fs from "fs";
import { createNullSemanticAnalyzer } from "../analysis/semanticAnalyzer.js";
import { classifyDomain } from "../analysis/classificationPipeline.js";

async function main() {
  const arg = process.argv[2];
  let raw;

  if (arg && arg !== "-") {
    raw = fs.readFileSync(arg, "utf8");
  } else {
    raw = await readStdin();
  }

  const job = JSON.parse(raw);
  const deps = {
    semanticAnalyzer: createNullSemanticAnalyzer(),
  };

  const result = await classifyDomain(job, deps);
  console.log(JSON.stringify(result, null, 2));
}

function readStdin() {
  return new Promise((resolve, reject) => {
    let data = "";
    process.stdin.setEncoding("utf8");
    process.stdin.on("data", (chunk) => { data += chunk; });
    process.stdin.on("end", () => resolve(data));
    process.stdin.on("error", reject);
  });
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
