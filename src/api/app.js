/**
 * Express application — routes and dependency wiring.
 */

import express from "express";
import { createSemanticAnalyzer, createNullSemanticAnalyzer } from "../analysis/semantic/semanticAnalyzer.js";
import { classifyDomain } from "../analysis/pipeline/classificationPipeline.js";
import { classifyBatch } from "./workers/batchRunner.js";
import { CLASSIFY_CONCURRENCY } from "../../config/classificationConfig.js";

const app = express();
app.use(express.json({ limit: "10mb" }));

/** @type {import("../analysis/semantic/semanticAnalyzer.js").SemanticAnalyzer | null} */
let semanticAnalyzer = null;
let modelLoaded = false;

/**
 * @returns {Promise<import("../analysis/pipeline/classificationPipeline.js").ClassificationDeps>}
 */
async function getDeps() {
  if (!semanticAnalyzer) {
    const skipModel = process.env.SKIP_SEMANTIC_MODEL === "true";
    semanticAnalyzer = skipModel
      ? createNullSemanticAnalyzer()
      : await createSemanticAnalyzer();
    modelLoaded = !skipModel;
  }
  return { semanticAnalyzer };
}

app.get("/health", (_req, res) => {
  res.json({
    status: "ok",
    modelLoaded,
    concurrency: CLASSIFY_CONCURRENCY,
  });
});

app.post("/classify", async (req, res) => {
  try {
    const job = req.body;
    if (!job?.url) {
      res.status(400).json({ error: "Missing required field: url" });
      return;
    }
    const deps = await getDeps();
    const result = await classifyDomain(job, deps);
    res.json(result);
  } catch (err) {
    res.status(500).json({
      error: err instanceof Error ? err.message : String(err),
    });
  }
});

app.post("/classify/batch", async (req, res) => {
  try {
    const { jobs, concurrency } = req.body ?? {};
    if (!Array.isArray(jobs) || jobs.length === 0) {
      res.status(400).json({ error: "Missing or empty jobs array" });
      return;
    }
    for (const job of jobs) {
      if (!job?.url) {
        res.status(400).json({ error: "Each job must include a url" });
        return;
      }
    }
    const deps = await getDeps();
    const results = await classifyBatch(jobs, deps, { concurrency });
    res.json({ results, count: results.length });
  } catch (err) {
    res.status(500).json({
      error: err instanceof Error ? err.message : String(err),
    });
  }
});

export { app };
