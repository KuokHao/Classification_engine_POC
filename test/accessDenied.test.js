import test from "node:test";
import assert from "node:assert/strict";

import { classifyDomain } from "../src/analysis/classificationPipeline.js";
import { createNullSemanticAnalyzer } from "../src/analysis/semanticAnalyzer.js";
import { extractInputFacts } from "../src/analysis/factExtractor.js";

test("classifyDomain early-exits Access_Denied on HTTP 403", async () => {
  const result = await classifyDomain(
    {
      url: "https://blocked.example/",
      html: "<html><body>should not matter</body></html>",
      httpStatus: 403,
      options: {
        skipTrustScoring: true,
        skipSemantic: true,
        skipLogoDetection: true,
      },
    },
    { semanticAnalyzer: createNullSemanticAnalyzer() },
  );

  assert.equal(result.abuseType, "Access_Denied");
  assert.equal(result.confidence, "high");
  assert.equal(result.path, "access_denied");
  assert.match(String(result.report?.summary ?? ""), /Access denied/i);
  assert.ok(
    (result.report?.findings ?? []).some((f) => String(f).includes("403")),
  );
});

test("extractInputFacts emits http_access_denied_status for 451", () => {
  const facts = extractInputFacts({ httpStatus: 451 });
  const hit = facts.find((f) => f.signal === "http_access_denied_status");
  assert.ok(hit);
  assert.equal(hit.value, 451);
});

test("extractInputFacts emits dns_sinkhole_detected for 0.0.0.0", () => {
  const facts = extractInputFacts({
    collectedData: {
      tls: null,
      whois: null,
      dns: { aRecords: ["0.0.0.0"], mxRecords: [], hasMX: false },
      geo: null,
    },
  });
  const hit = facts.find((f) => f.signal === "dns_sinkhole_detected");
  assert.ok(hit);
  assert.deepEqual(hit.value, ["0.0.0.0"]);
});
