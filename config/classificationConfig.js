import os from "os";

/** Default batch concurrency for parallel classify jobs. */
export const DEFAULT_CONCURRENCY = Math.min(
  4,
  Math.max(1, os.availableParallelism()),
);

/** HTTP server port. */
export const PORT = Number(process.env.PORT) || 3000;

/** Batch concurrency from env or default. */
export const CLASSIFY_CONCURRENCY =
  Number(process.env.CLASSIFY_CONCURRENCY) || DEFAULT_CONCURRENCY;
