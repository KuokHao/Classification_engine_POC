/**
 * Concurrency-limited batch classification runner.
 */

import { classifyDomain } from "../../analysis/pipeline/classificationPipeline.js";
import { CLASSIFY_CONCURRENCY } from "../../../config/classificationConfig.js";

/**
 * Simple semaphore for limiting concurrent async work.
 * @param {number} concurrency
 */
function createLimiter(concurrency) {
  let active = 0;
  /** @type {Array<() => void>} */
  const queue = [];

  /**
   * @template T
   * @param {() => Promise<T>} fn
   * @returns {Promise<T>}
   */
  return function limit(fn) {
    return new Promise((resolve, reject) => {
      const run = () => {
        active++;
        fn()
          .then(resolve, reject)
          .finally(() => {
            active--;
            if (queue.length > 0) {
              queue.shift()();
            }
          });
      };

      if (active < concurrency) {
        run();
      } else {
        queue.push(run);
      }
    });
  };
}

/**
 * @typedef {import("../../analysis/pipeline/classificationPipeline.js").ClassificationJob} ClassificationJob
 * @typedef {import("../../analysis/pipeline/classificationPipeline.js").ClassificationDeps} ClassificationDeps
 * @typedef {import("../../analysis/pipeline/classificationPipeline.js").ClassificationResult} ClassificationResult
 */

/**
 * @typedef {Object} BatchResult
 * @property {number} index
 * @property {ClassificationResult | null} result
 * @property {string | null} error
 */

/**
 * Classify multiple jobs with a concurrency limit.
 *
 * @param {ClassificationJob[]} jobs
 * @param {ClassificationDeps} deps
 * @param {{ concurrency?: number }} [options]
 * @returns {Promise<BatchResult[]>}
 */
export async function classifyBatch(jobs, deps, options = {}) {
  const concurrency = options.concurrency ?? CLASSIFY_CONCURRENCY;
  const limit = createLimiter(concurrency);

  const tasks = jobs.map((job, index) =>
    limit(async () => {
      try {
        const result = await classifyDomain(job, deps);
        return { index, result, error: null };
      } catch (err) {
        return {
          index,
          result: null,
          error: err instanceof Error ? err.message : String(err),
        };
      }
    })
  );

  const results = await Promise.all(tasks);
  return results.sort((a, b) => a.index - b.index);
}
