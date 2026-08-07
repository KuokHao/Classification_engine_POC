/**
 * HTTP server bootstrap — listens on PORT.
 */

import { PORT, CLASSIFY_CONCURRENCY } from "../../config/classificationConfig.js";
import { app } from "./app.js";

async function main() {
  app.listen(PORT, () => {
    console.log(`Classification service listening on port ${PORT}`);
    console.log(`Batch concurrency: ${CLASSIFY_CONCURRENCY}`);
    if (process.env.SKIP_SEMANTIC_MODEL === "true") {
      console.log("Semantic model skipped (SKIP_SEMANTIC_MODEL=true)");
    }
  });
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
