/**
 * End-to-end analysis orchestrator.
 *
 * Call as a function:
 *   import { runAnalysis } from "./runAnalysis.js";
 *   await runAnalysis({ domain: "umobile.network", brandId: "umobile", scrape: false });
 *
 * Or edit CONFIG below and run:
 *   node src/cli/runAnalysis.js
 */

import fs from "fs/promises";
import path from "path";
import { fileURLToPath } from "url";
import { registerBrand } from "../collection/brand/brandRegistry.js";
import { findByBrandId } from "../collection/brand/brandRepository.js";
import { captureWebsite } from "../collection/capture/puppeteerAgent.js";
import { classifyDomain } from "../analysis/pipeline/classificationPipeline.js";
import {
  createSemanticAnalyzer,
  createNullSemanticAnalyzer,
} from "../analysis/semantic/semanticAnalyzer.js";
import { createRunDir, writeStage, ROOT } from "../shared/artifacts/runArtifacts.js";

// ---------------------------------------------------------------------------
// Direct-run CONFIG — edit these, then: node src/cli/runAnalysis.js
// ---------------------------------------------------------------------------

const CONFIG = {
  domain: "umobile.network",
  brandId: "umobile",
  registerBrand: false,
  brand: null,
  // Example when registering a new brand:
  // registerBrand: true,
  // brand: {
  //   brandName: "umobile",
  //   officialSite: "u.com.my",
  //   whitelistDomains: ["u.com.my"],
  //   logoPath:
  //     "C:\\Users\\kuokh\\OneDrive\\Documents\\Work\\AI agent\\Worker POC\\temp\\cq5dam.web.1080.1080.jpg",
  //   brandNames: ["umobile"],
  // },
  scrape: false,
  skipSemantic: false,
};

const TEMP_DIR = path.join(ROOT, "temp");

/**
 * Normalize domain input → { hostname, pageUrl }.
 * Accepts bare hostname or full URL.
 * @param {string} domain
 * @returns {{ hostname: string, pageUrl: string }}
 */
function normalizeDomain(domain) {
  const raw = String(domain ?? "").trim();
  if (!raw) throw new Error("runAnalysis requires domain");
  const pageUrl = /^https?:\/\//i.test(raw) ? raw : `https://${raw}`;
  let hostname;
  try {
    hostname = new URL(pageUrl).hostname;
  } catch {
    throw new Error(`Invalid domain: ${domain}`);
  }
  if (!hostname) throw new Error(`Invalid domain: ${domain}`);
  return { hostname, pageUrl };
}

/**
 * Load existing capture from temp/{hostname}.txt (+ optional .png).
 * @param {string} hostname
 */
async function loadTempCapture(hostname) {
  const htmlPath = path.join(TEMP_DIR, `${hostname}.txt`);
  const screenshotPath = path.join(TEMP_DIR, `${hostname}.png`);
  const iframePath = path.join(TEMP_DIR, `${hostname}.iframes.json`);

  let html;
  try {
    html = await fs.readFile(htmlPath, "utf8");
  } catch (err) {
    if (err?.code === "ENOENT") {
      throw new Error(
        `No temp capture found at ${htmlPath}. Set scrape: true or capture first.`,
      );
    }
    throw err;
  }

  let screenshot = null;
  try {
    await fs.access(screenshotPath);
    screenshot = screenshotPath;
  } catch {
    screenshot = null;
  }

  return {
    htmlPath,
    screenshotPath: screenshot,
    iframePath,
    finalUrl: `https://${hostname}`,
    html,
  };
}

/**
 * Full analysis: brand → capture → classify, with stage JSON under data/runs/.
 *
 * @param {Object} opts
 * @param {string} opts.domain - Domain under investigation (hostname or URL)
 * @param {string} [opts.brandId] - Existing brand id when not registering
 * @param {boolean} [opts.registerBrand=false]
 * @param {Object} [opts.brand] - registerBrand payload
 * @param {boolean} [opts.scrape=true] - false → reuse temp/{hostname}.txt
 * @param {boolean} [opts.skipSemantic=false]
 * @returns {Promise<{ result: object, runDir: string, brand: object, capture: object }>}
 */
export async function runAnalysis({
  domain,
  brandId,
  registerBrand: doRegister = false,
  brand: brandInput = null,
  scrape = true,
  skipSemantic = false,
} = {}) {
  const { hostname, pageUrl } = normalizeDomain(domain);
  const runDir = await createRunDir(hostname);

  await writeStage(runDir, "00_meta.json", {
    domain: hostname,
    pageUrl,
    brandId: brandId ?? brandInput?.brandName ?? null,
    registerBrand: Boolean(doRegister),
    scrape: Boolean(scrape),
    skipSemantic: Boolean(skipSemantic),
    startedAt: new Date().toISOString(),
    runDir,
  });

  // --- Brand ---
  let brandDoc;
  if (doRegister) {
    if (!brandInput?.brandName || !brandInput?.officialSite) {
      throw new Error(
        "registerBrand: true requires brand.brandName and brand.officialSite",
      );
    }
    console.log(`[runAnalysis] Registering brand "${brandInput.brandName}"...`);
    brandDoc = await registerBrand(brandInput);
  } else {
    const id = brandId || brandInput?.brandName;
    if (!id) {
      throw new Error("Provide brandId, or set registerBrand: true with brand details");
    }
    console.log(`[runAnalysis] Loading brand "${id}" from data/brands.json...`);
    brandDoc = await findByBrandId(String(id));
    if (!brandDoc) {
      throw new Error(`Brand not found in data/brands.json: ${id}`);
    }
  }
  const resolvedBrandId = brandDoc.brandId;
  await writeStage(runDir, "01_brand.json", brandDoc);

  // --- Capture ---
  /** @type {{ htmlPath: string, screenshotPath: string|null, iframePath?: string, finalUrl: string, html: string }} */
  let capture;
  if (scrape) {
    console.log(`[runAnalysis] Scraping ${hostname}...`);
    const captured = await captureWebsite(domain);
    if (!captured) {
      throw new Error(`captureWebsite failed for ${domain}`);
    }
    const html = await fs.readFile(captured.htmlPath, "utf8");
    capture = {
      htmlPath: captured.htmlPath,
      screenshotPath: captured.screenshotPath ?? null,
      iframePath: captured.iframePath,
      finalUrl: captured.finalUrl || pageUrl,
      html,
    };
  } else {
    console.log(`[runAnalysis] Reusing temp capture for ${hostname}...`);
    capture = await loadTempCapture(hostname);
  }

  await writeStage(runDir, "02_capture.json", {
    htmlPath: capture.htmlPath,
    screenshotPath: capture.screenshotPath,
    iframePath: capture.iframePath ?? null,
    finalUrl: capture.finalUrl,
    htmlBytes: Buffer.byteLength(capture.html, "utf8"),
  });

  // --- Classify ---
  const useNullSemantic =
    skipSemantic || process.env.SKIP_SEMANTIC_MODEL === "true";
  console.log(
    `[runAnalysis] Classifying (semantic=${useNullSemantic ? "off" : "on"})...`,
  );
  const semanticAnalyzer = useNullSemantic
    ? createNullSemanticAnalyzer()
    : await createSemanticAnalyzer();

  const result = await classifyDomain(
    {
      url: capture.finalUrl || pageUrl,
      html: capture.html,
      screenshotPath: capture.screenshotPath || undefined,
      brandId: resolvedBrandId,
      userInput: resolvedBrandId,
      options: {
        artifactDir: runDir,
        skipSemantic: useNullSemantic,
      },
    },
    { semanticAnalyzer },
  );

  console.log(`[runAnalysis] Done → ${runDir}`);
  console.log(
    `[runAnalysis] ${result.abuseType} (${result.confidence}) via ${result.path}`,
  );

  return {
    result,
    runDir,
    brand: brandDoc,
    capture: {
      htmlPath: capture.htmlPath,
      screenshotPath: capture.screenshotPath,
      finalUrl: capture.finalUrl,
    },
  };
}

// ---------------------------------------------------------------------------
// Direct run
// ---------------------------------------------------------------------------

const isDirectRun =
  process.argv[1] &&
  path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);

if (isDirectRun) {
  runAnalysis(CONFIG)
    .then(({ result, runDir }) => {
      const scores = result.stages?.kbs?.classificationScores ?? {};
      const fired = result.stages?.kbs?.firedRules ?? [];
      console.log("\n=== Summary ===");
      console.log(`runDir:     ${runDir}`);
      console.log(`abuseType:  ${result.abuseType}`);
      console.log(`confidence: ${result.confidence}`);
      console.log(`firedRules: ${fired.length}`);
      console.log("scores:", JSON.stringify(scores, null, 2));
    })
    .catch((err) => {
      console.error(err);
      process.exit(1);
    });
}
