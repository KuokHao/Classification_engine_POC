/**
 * CLI: register / refresh a brand profile in the local brand store.
 *
 * Usage:
 *   node src/cli/registerBrand.js '{"brandName":"U Mobile","officialSite":"https://www.u.com.my","whitelistDomains":["u.com.my"]}'
 *   node src/cli/registerBrand.js brand.json
 */

import fs from "fs";
import { registerBrand } from "../collection/brand/brandRegistry.js";
import { getBrandsFilePath } from "../collection/brand/brandRepository.js";

async function main() {
  const arg = process.argv[2];
  if (!arg) {
    console.error(
      'Usage: node src/cli/registerBrand.js \'{"brandName":"...","officialSite":"https://..."}\'',
    );
    process.exit(1);
  }

  const raw = arg.endsWith(".json") ? fs.readFileSync(arg, "utf8") : arg;
  const input = JSON.parse(raw);

  const saved = await registerBrand(input);
  console.log(`Saved brand to ${getBrandsFilePath()}`);
  console.log(JSON.stringify(saved, null, 2));
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
