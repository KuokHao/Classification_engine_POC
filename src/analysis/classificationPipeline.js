/**
 * Classification pipeline — orchestrates trust-scoring → HTML → analysis → semantic → KBS → LLM.
 *
 * Stage 0: Live intelligence gather + weighted trust scoring.
 *   - OFFICIAL_SITE   → return immediately (brand whitelist hit only)
 *   - TRUSTED_INFRA   → continue; seed trusted_infra for KBS Official/content-only path
 *   - REJECTED / FLAGGED_SUSPICIOUS → continue; full KBS abuse path (skip Official phase)
 *
 * Stage 1–6: HTML structure → page findings (pageFindings.js) → chunker → semantic → KBS → LLM.
 */

import { evaluateDomainTrust, getBrandConfig } from "../collection/trust/heuristic.js";
import { analyzeHtml } from "./htmlAnalyzer.js";
import {
  containsBrandName,
  brandInMarkup,
  detectSensitiveInputs,
  hasFileUpload,
  analyzeFormActions,
  isOfficialSubdomain,
  checkRedirects,
  extractTrustNavigation,
  probeTrustLinks,
  analyzeLinkHealth,
  hasCopyright,
  detectEcommerceSchema,
  hasPricingPatterns,
  extractPricePairs,
  detectUnrealisticDiscount,
  detectGamblingLanguage,
  detectAdultLanguage,
  detectAdultAgeGate,
  detectAdultTld,
  detectDenseMediaGallery,
  detectParkingKeywords,
  detectParkedNameServers,
  detectParkedIPs,
  checkEmailFootprint,
  detectSuspiciousShopTld,
  detectFreeWebmailContact,
  detectOffplatformChatContact,
} from "./pageFindings.js";
import { chunkHtmlAnalysis } from "./textChunker.js";
import { ensureEnglishHtmlAnalysis } from "./languageTranslator.js";
import { detectBrandLogo } from "./logoDetector.js";
import { runKBS } from "./kbs.js";
import { runLlmAnalyzer } from "./llmAnalyzer.js";
import { normalizeAbuseType } from "../shared/constants/abuse.constant.js";
import { writeStage } from "../shared/artifacts/runArtifacts.js";
import {
  HTTP_ACCESS_DENIED_STATUSES,
  findSinkholeIps,
} from "./factExtractor.js";

/**
 * @typedef {import("../collection/trust/heuristic.js").ScanData} ScanData
 * @typedef {import("./semanticAnalyzer.js").SemanticAnalyzer} SemanticAnalyzer
 */

/**
 * Presence-only bag of raw tool outputs for factExtractor.
 *
 * @typedef {Object} PageFindings
 * @property {true} [brandNamePresent]
 * @property {true} [brandImageDetected]
 * @property {true} [brandInMarkup]
 * @property {{ hasPassword?: true, hasUsername?: true, hasOTP?: true, hasFinancial?: true, hasIdentity?: true }} [sensitiveInputs]
 * @property {true} [hasFileUpload]
 * @property {{ hasForms?: boolean, suspiciousActions?: object[], isLikelyPhishing?: boolean }} [formActions]
 * @property {true} [isOfficialSubdomain]
 * @property {object} [redirects]
 * @property {object} [trustNavigation]
 * @property {object[]} [links]
 * @property {{ brokenRatio: number, brokenCount: number, evaluableCount: number, placeholderCount: number, conversionDestinationDead?: boolean, dominantUrl?: string|null, dominantShare?: number, samples?: object }} [linkHealth]
 * @property {true} [hasCopyright]
 * @property {true} [missingCopyright]
 * @property {{ usesMicrodata: boolean, usesJsonLd: boolean }} [ecommerceSchema]
 * @property {true} [hasPricingPatterns]
 * @property {true} [unrealisticDiscountDetected]
 * @property {string} [suspiciousShopTld]
 * @property {string[]} [freeWebmailContact]
 * @property {string[]} [offplatformChatContact]
 * @property {{ definitiveMatches?: string[], strongMatches?: string[], weakMatches?: string[], definitiveCount?: number, strongCount?: number, weakCount?: number }} [gamblingLanguage]
 * @property {{ definitiveMatches?: string[], strongMatches?: string[], weakMatches?: string[], definitiveCount?: number, strongCount?: number, weakCount?: number }} [adultLanguage]
 * @property {true} [adultAgeGateDetected]
 * @property {string} [adultTld]
 * @property {{ imageCount?: number, hasVideo?: boolean }} [denseMediaGallery]
 * @property {true} [parkingKeywordsPresent]
 * @property {string[]} [parkingKeywordClues]
 * @property {{ matchedFootprints: string[] }} [parkedNameServers]
 * @property {{ matchedFootprints: string[] }} [parkedIps]
 * @property {true} [noEmailInfrastructure]
 */

/**
 * @typedef {Object} ClassificationJobOptions
 * @property {boolean} [skipSemantic]
 * @property {boolean} [skipTrustScoring]  - Skip Stage 0 (useful for testing)
 * @property {boolean} [skipLogoDetection]
 * @property {string}  [logoPath] - Local path to official brand logo (overrides brandConfig.logoPath)
 * @property {string}  [artifactDir] - If set, write stage JSON files into this directory
 */

/**
 * @typedef {Object} ClassificationJob
 * @property {string}  url
 * @property {string}  [html]
 * @property {string}  [renderedText] - Optional browser body.innerText from capture
 * @property {ScanData} [scanData]
 * @property {string}  [userInput]
 * @property {string}  [brandId]
 * @property {string}  [screenshotPath] - Full-page screenshot for LLM vision
 * @property {number}  [httpStatus] - Main-document HTTP status from capture
 * @property {ClassificationJobOptions} [options]
 */

/**
 * @typedef {Object} ClassificationDeps
 * @property {SemanticAnalyzer} semanticAnalyzer
 */

/**
 * @typedef {Object} ClassificationResult
 * @property {string}                              abuseType
 * @property {"high"|"medium"|"low"}               confidence
 * @property {"trust"|"kbs"|"unresolved"|"access_denied"} path
 * @property {Record<string, unknown>}             report
 * @property {import("./llmAnalyzer.js").LlmAnalysis|null} [llmAnalysis]
 * @property {Object}                              stages
 * @property {Object|null}                         stages.trust
 * @property {Object|null}                         stages.htmlAnalysis
 * @property {PageFindings|null}                   stages.pageFindings
 * @property {Object|null}                         stages.logoDetection
 * @property {Object|null}                         stages.chunks
 * @property {Object|null}                         stages.semantic
 * @property {import("./kbs.js").KBSResult|null}   stages.kbs
 */

/**
 * @param {string} pageUrl
 * @param {string[]} officialDomains
 * @returns {string | null}
 */
function resolveOfficialDomain(pageUrl, officialDomains) {
  if (Array.isArray(officialDomains) && officialDomains.length > 0) {
    return officialDomains[0];
  }
  try {
    return new URL(pageUrl).hostname.replace(/^www\./, "");
  } catch {
    return null;
  }
}

/**
 * Call pageFindings.js helpers and build a presence-only findings bag.
 *
 * @param {Object} opts
 * @param {string} opts.html
 * @param {import("./htmlAnalyzer.js").HtmlAnalysis | null} [opts.htmlDocument]
 * @param {string} opts.pageUrl
 * @param {string} [opts.brandName]
 * @param {string[]} [opts.officialDomains]
 * @returns {Promise<PageFindings>}
 */
async function buildPageFindingsFromUtility({
  html,
  htmlDocument = null,
  pageUrl,
  brandName = "",
  officialDomains = [],
}) {
  /** @type {PageFindings} */
  const findings = {};

  if (brandName && containsBrandName(html, brandName)) {
    findings.brandNamePresent = true;
  }

  if (brandName && brandInMarkup(html, brandName)) {
    findings.brandInMarkup = true;
  }

  const sensitive = detectSensitiveInputs(html);
  /** @type {NonNullable<PageFindings["sensitiveInputs"]>} */
  const sensitivePresent = {};
  if (sensitive.hasPassword) sensitivePresent.hasPassword = true;
  if (sensitive.hasUsername) sensitivePresent.hasUsername = true;
  if (sensitive.hasOTP) sensitivePresent.hasOTP = true;
  if (sensitive.hasFinancial) sensitivePresent.hasFinancial = true;
  if (sensitive.hasIdentity) sensitivePresent.hasIdentity = true;
  if (Object.keys(sensitivePresent).length > 0) {
    findings.sensitiveInputs = sensitivePresent;
  }

  if (hasFileUpload(html)) {
    findings.hasFileUpload = true;
  }

  const domains = Array.isArray(officialDomains) ? officialDomains : [];
  for (const domain of domains) {
    if (isOfficialSubdomain(pageUrl, domain)) {
      findings.isOfficialSubdomain = true;
      break;
    }
  }

  const officialDomain = resolveOfficialDomain(pageUrl, officialDomains);

  if (officialDomain) {
    const formActions = analyzeFormActions(html, officialDomain);
    if (
      formActions.isLikelyPhishing ||
      (formActions.suspiciousActions?.length ?? 0) > 0
    ) {
      findings.formActions = {
        hasForms: formActions.hasForms,
        suspiciousActions: formActions.suspiciousActions,
        isLikelyPhishing: formActions.isLikelyPhishing,
      };
    }
  }

  if (pageUrl && officialDomain) {
    try {
      const redirects = await checkRedirects(pageUrl, officialDomain);
      if (
        redirects &&
        !redirects.error &&
        (redirects.wasRedirected ||
          redirects.isCrossDomain ||
          (redirects.redirectTypes?.length ?? 0) > 0)
      ) {
        findings.redirects = redirects;
      }
    } catch (err) {
      console.warn(
        "[classificationPipeline] checkRedirects failed:",
        err?.message ?? err,
      );
    }
  }

  try {
    const { links, trustNavigation } = extractTrustNavigation(html ?? "");
    findings.links = links;

    if (!trustNavigation.found) {
      trustNavigation.status = "missing";
    } else {
      // Trust-labeled controls exist. Working = at least one probeable href returns 2xx.
      // Inert links / non-navigable buttons count as broken when nothing works.
      const failures = [];
      for (const item of trustNavigation.nonFunctional ?? []) {
        failures.push(
          `"${item.text}" (${item.trustCategory}, ${item.reason})`,
        );
      }

      if ((trustNavigation.candidates ?? []).length === 0) {
        trustNavigation.status = "broken";
        trustNavigation.failures = failures;
      } else {
        try {
          const probe = await probeTrustLinks(
            trustNavigation.candidates,
            pageUrl,
          );
          if (probe.anyWorking) {
            trustNavigation.status = "ok";
            trustNavigation.workingUrl = probe.workingUrl;
            // Keep non-functional notes only for debugging when something else works
            if (failures.length) trustNavigation.failures = failures;
          } else {
            trustNavigation.status = "broken";
            trustNavigation.failures = [
              ...failures,
              ...(probe.failures ?? []),
            ];
          }
        } catch (err) {
          console.warn(
            "[classificationPipeline] probeTrustLinks failed:",
            err?.message ?? err,
          );
          trustNavigation.status = "broken";
          trustNavigation.failures = failures;
        }
      }
    }

    findings.trustNavigation = trustNavigation;
  } catch (err) {
    console.warn(
      "[classificationPipeline] extractTrustNavigation failed:",
      err?.message ?? err,
    );
  }

  // Page-wide dead/placeholder link density — hollow impersonation sites often
  // exceed ~50% broken anchors, or funnel CTAs into one dead checkout URL.
  if (pageUrl && html) {
    try {
      const linkHealth = await analyzeLinkHealth(html, pageUrl);
      if (linkHealth.exceedsThreshold) {
        findings.linkHealth = {
          brokenRatio: linkHealth.brokenRatio,
          brokenCount: linkHealth.brokenCount,
          evaluableCount: linkHealth.evaluableCount,
          placeholderCount: linkHealth.placeholderCount,
          conversionDestinationDead: linkHealth.conversionDestinationDead,
          dominantUrl: linkHealth.dominantUrl,
          dominantShare: linkHealth.dominantShare,
          samples: linkHealth.samples,
        };
      }
    } catch (err) {
      console.warn(
        "[classificationPipeline] analyzeLinkHealth failed:",
        err?.message ?? err,
      );
    }
  }

  const ecommerceSchema = detectEcommerceSchema(html ?? "");
  if (ecommerceSchema.hasSchema) {
    findings.ecommerceSchema = {
      usesMicrodata: ecommerceSchema.usesMicrodata,
      usesJsonLd: ecommerceSchema.usesJsonLd,
    };
  }

  // Footer copyright scan — hollow impersonation pages often omit © / rights notices.
  // Presence-only: set hasCopyright or missingCopyright (never both).
  if (html) {
    if (hasCopyright(html)) {
      findings.hasCopyright = true;
    } else {
      findings.missingCopyright = true;
    }
  }

  if (hasPricingPatterns(html ?? "")) {
    findings.hasPricingPatterns = true;
  }

  if (pageUrl) {
    const tldHit = detectSuspiciousShopTld(pageUrl);
    if (tldHit.isSuspicious && tldHit.tld) {
      findings.suspiciousShopTld = tldHit.tld;
    }
  }

  if (html) {
    const webmail = detectFreeWebmailContact(html);
    if (webmail.found && webmail.samples.length > 0) {
      findings.freeWebmailContact = webmail.samples;
    }
    const chat = detectOffplatformChatContact(html);
    if (chat.found && chat.samples.length > 0) {
      findings.offplatformChatContact = chat.samples;
    }
  }

  // Extreme-discount check is expensive (DOM walk over price pairs).
  // Only run when the page already looks like a shop: currency/price text
  // OR Product/Offer schema. Presence-only — set the flag only when density
  // of extreme discounts crosses the detector threshold.
  if (findings.ecommerceSchema || findings.hasPricingPatterns) {
    const pairs = extractPricePairs(html ?? ""); // original vs sale text pairs
    if (detectUnrealisticDiscount(pairs)) {
      findings.unrealisticDiscountDetected = true;
    }
  }

  // Tiered gambling keywords on htmlAnalyzer.analysisText (meta + body + extras)
  const analysisCorpus =
    (typeof htmlDocument?.analysisText === "string" &&
      htmlDocument.analysisText.trim()) ||
    (typeof htmlDocument?.bodyText === "string" && htmlDocument.bodyText.trim()) ||
    "";
  const gambling = detectGamblingLanguage(analysisCorpus);
  if (
    gambling.definitiveCount > 0 ||
    gambling.strongCount > 0 ||
    gambling.weakCount > 0
  ) {
    findings.gamblingLanguage = {
      definitiveMatches: gambling.definitiveMatches,
      strongMatches: gambling.strongMatches,
      weakMatches: gambling.weakMatches,
      definitiveCount: gambling.definitiveCount,
      strongCount: gambling.strongCount,
      weakCount: gambling.weakCount,
    };
  }

  // Tiered adult / pornography keywords (Gambling-shaped)
  const adult = detectAdultLanguage(analysisCorpus);
  if (
    adult.definitiveCount > 0 ||
    adult.strongCount > 0 ||
    adult.weakCount > 0
  ) {
    findings.adultLanguage = {
      definitiveMatches: adult.definitiveMatches,
      strongMatches: adult.strongMatches,
      weakMatches: adult.weakMatches,
      definitiveCount: adult.definitiveCount,
      strongCount: adult.strongCount,
      weakCount: adult.weakCount,
    };
  }

  const ageGate = detectAdultAgeGate(analysisCorpus);
  if (ageGate.detected) {
    findings.adultAgeGateDetected = true;
  }

  const adultTldHit = detectAdultTld(pageUrl);
  if (adultTldHit.isAdultTld && adultTldHit.tld) {
    findings.adultTld = adultTldHit.tld;
  }

  const gallery = detectDenseMediaGallery(htmlDocument, html ?? "");
  if (gallery.detected) {
    findings.denseMediaGallery = {
      imageCount: gallery.imageCount,
      hasVideo: gallery.hasVideo,
    };
  }

  // Parking gate: "domain" / "domain name" in analysis corpus; probes only when open
  const parkingKeywords = detectParkingKeywords(analysisCorpus);
  if (parkingKeywords.isSuspicious) {
    findings.parkingKeywordsPresent = true;
    if (parkingKeywords.foundClues?.length) {
      findings.parkingKeywordClues = parkingKeywords.foundClues;
    }

    let hostname = "";
    try {
      hostname = new URL(pageUrl).hostname.replace(/\.$/, "");
    } catch {
      hostname = "";
    }

    if (hostname) {
      try {
        const [nsResult, ipResult] = await Promise.all([
          detectParkedNameServers(hostname),
          detectParkedIPs(hostname),
        ]);

        if (nsResult?.isParkingDomain) {
          findings.parkedNameServers = {
            matchedFootprints: nsResult.matchedFootprints ?? [],
          };
        }
        if (ipResult?.isSuspicious) {
          findings.parkedIps = {
            matchedFootprints: ipResult.matchedFootprints ?? [],
          };
        }

        if (!findings.parkedNameServers && !findings.parkedIps) {
          const emailResult = await checkEmailFootprint(hostname);
          if (
            emailResult?.decisionEngineFlag === "NO_EMAIL_INFRASTRUCTURE" ||
            emailResult?.hasNullMx ||
            emailResult?.hasRestrictedSpf
          ) {
            findings.noEmailInfrastructure = true;
          }
        }
      } catch (err) {
        console.warn(
          "[classificationPipeline] parking DNS probes failed:",
          err?.message ?? err,
        );
      }
    }
  }

  return findings;
}

/**
 * @param {ClassificationJob} job
 * @param {ClassificationDeps} deps
 * @returns {Promise<ClassificationResult>}
 */
export async function classifyDomain(job, deps) {
  const artifactDir = job.options?.artifactDir || null;
  /** @param {string} name @param {unknown} data */
  const save = async (name, data) => {
    if (artifactDir) await writeStage(artifactDir, name, data);
  };

  const userInput = job.userInput ?? "";
  const httpStatus =
    job.httpStatus ??
    (typeof job.scanData?.httpStatus === "number"
      ? job.scanData.httpStatus
      : null);
  let scanData = {
    ...(job.scanData ?? {}),
    ...(job.brandId ? { brandId: job.brandId } : {}),
    ...(job.url ? { hostname: safeHostname(job.url) } : {}),
    ...(httpStatus != null ? { httpStatus } : {}),
  };

  // Brand resolution from local store (required when userInput / brandId is provided)
  const brandRequested = Boolean(
    (userInput && userInput.trim()) || scanData.brandId,
  );
  let brand = null;
  if (brandRequested) {
    try {
      brand = await getBrandConfig(userInput, scanData);
    } catch (err) {
      console.warn(
        "[classificationPipeline] brand lookup failed:",
        err?.message ?? err,
      );
      const unresolved = buildBrandUnresolvedResult(
        job.url,
        `Brand lookup failed: ${err?.message ?? err}`,
      );
      await save("10_result.json", stripStages(unresolved));
      return unresolved;
    }
    if (!brand) {
      const unresolved = buildBrandUnresolvedResult(
        job.url,
        `Brand profile not found for "${userInput || scanData.brandId}"`,
      );
      await save("10_result.json", stripStages(unresolved));
      return unresolved;
    }
    scanData = { ...scanData, brandConfig: brand };
  }

  // Access_Denied: HTTP deny status — early exit before trust/HTML/LLM
  if (
    httpStatus != null &&
    HTTP_ACCESS_DENIED_STATUSES.has(Number(httpStatus))
  ) {
    const denied = buildAccessDeniedResult(job.url, {
      reason: `http_status_${httpStatus}`,
      httpStatus: Number(httpStatus),
      trustResult: null,
    });
    await save("10_result.json", stripStages(denied));
    return denied;
  }

  // Stage 0: Live intelligence gather + weighted trust scoring
  let trustResult = null;
  if (!job.options?.skipTrustScoring && job.url) {
    const whitelistedDomains = brand?.officialDomains ?? [];

    trustResult = await evaluateDomainTrust(job.url, { whitelistedDomains });
    await save("03_heuristic.json", {
      status: trustResult.status,
      score: trustResult.score,
      reason: trustResult.reason,
      flags: trustResult.flags,
      collectedData: trustResult.collectedData,
    });

    if (trustResult.status === "OFFICIAL_SITE") {
      const official = {
        abuseType: normalizeAbuseType("Official"),
        confidence: "high",
        path: "trust",
        report: buildTrustOfficialReport(job.url, trustResult),
        llmAnalysis: null,
        stages: {
          trust: trustResult,
          htmlAnalysis: null,
          pageFindings: null,
          logoDetection: null,
          chunks: null,
          semantic: null,
          kbs: null,
        },
      };
      await save("10_result.json", stripStages(official));
      return official;
    }

    // Access_Denied: DNS sinkhole from trust DNS — early exit
    const sinkholeIps = findSinkholeIps(
      trustResult.collectedData?.dns?.aRecords,
    );
    if (sinkholeIps.length > 0) {
      const denied = buildAccessDeniedResult(job.url, {
        reason: "dns_sinkhole",
        sinkholeIps,
        trustResult,
      });
      await save("10_result.json", stripStages(denied));
      return denied;
    }

    // REJECTED / FLAGGED_SUSPICIOUS: attach tool outputs so KBS can score with page evidence.
    scanData = {
      ...scanData,
      collectedData: trustResult.collectedData,
      brandConfig: brand ?? undefined,
    };
  }

  // Stage 1: HTML structure (no threat analysis)
  const html = job.html ?? "";
  if (!html.trim()) {
    const empty = buildEmptyHtmlResult(job.url, trustResult);
    await save("10_result.json", stripStages(empty));
    return empty;
  }

  const htmlAnalysis = analyzeHtml(html, {
    renderedText: job.renderedText ?? null,
  });
  await save("04_html.json", htmlAnalysis);

  // Stage 1b: Translate visibleText/textZones only when confidently non-English.
  // Page findings / logo / KBS structure keep original htmlAnalysis.
  const { analysis: semanticHtmlAnalysis, language } =
    await ensureEnglishHtmlAnalysis(htmlAnalysis, html);
  await save("04b_language.json", language);

  // Stage 2: Page findings via pageFindings.js helpers
  const brandName =
    userInput || scanData.brandConfig?.brandNames?.[0] || "";
  const officialDomains = scanData.brandConfig?.officialDomains ?? [];

  let pageFindings = {};
  try {
    pageFindings = await buildPageFindingsFromUtility({
      html,
      htmlDocument: htmlAnalysis,
      pageUrl: job.url,
      brandName,
      officialDomains,
    });
  } catch (err) {
    console.warn(
      "[classificationPipeline] page findings failed:",
      err?.message ?? err,
    );
  }

  scanData = { ...scanData, pageFindings };

  // Stage 2b: Brand logo detection (optional — requires a local reference logo)
  let logoDetection = null;
  const logoPath =
    job.options?.logoPath ||
    scanData.logoPath ||
    scanData.brandConfig?.logoPath ||
    null;
  const brandNames =
    scanData.brandConfig?.brandNames ??
    (brandName ? [brandName] : []);

  if (
    !job.options?.skipLogoDetection &&
    logoPath &&
    brandNames.length > 0 &&
    (htmlAnalysis.images?.length ?? 0) > 0
  ) {
    try {
      logoDetection = await detectBrandLogo(logoPath, htmlAnalysis.images, {
        brandNames,
        baseUrl: job.url,
      });
      if (logoDetection.logo_detected) {
        pageFindings = { ...pageFindings, brandImageDetected: true };
        scanData = { ...scanData, pageFindings };
      }
    } catch (err) {
      console.warn(
        "[classificationPipeline] logo detection failed:",
        err?.message ?? err,
      );
      logoDetection = { error: err?.message ?? String(err) };
    }
  }

  await save("05_page.json", { pageFindings, logoDetection });

  // Stage 3: Chunk htmlAnalyzer text via textChunker
  // Use English text when languageTranslator ran; otherwise original analysis.
  const chunks = await chunkHtmlAnalysis(semanticHtmlAnalysis);
  await save("06_chunks.json", { chunks, count: chunks.length });

  // Stage 4: Semantic analysis (embed chunks vs phrase libraries)
  const semanticOutput = job.options?.skipSemantic
    ? { scores: {}, derivedFacts: [], evidence: [] }
    : await deps.semanticAnalyzer.analyze({ chunks });
  await save("07_semantic.json", semanticOutput);

  // Stage 5: KBS inference — pageFindings + collectedData seed via factExtractor
  const kbsResult = runKBS(htmlAnalysis, job.url, semanticOutput, scanData);
  const kbsResolved = resolveKbsClassification(kbsResult);
  await save("08_kbs.json", {
    classifiedAs: kbsResult.classifiedAs,
    classificationScores: kbsResult.classificationScores,
    firedRules: kbsResult.firedRules,
    scoreBreakdown: kbsResult.scoreBreakdown,
    signals: kbsResult.signals,
  });

  // Stage 6: LLM vision analysis (comparison layer — does not overwrite KBS)
  const screenshotPath =
    job.screenshotPath ||
    (typeof scanData.screenshotPath === "string"
      ? scanData.screenshotPath
      : null);

  let llmAnalysis = null;
  try {
    const llmResult = await runLlmAnalyzer({
      url: job.url,
      kbsResult,
      scanData,
      userInput,
      screenshotPath,
    });
    llmAnalysis = llmResult?.llmAnalysis ?? null;
    if (llmResult?.error) {
      console.warn(
        "[classificationPipeline] runLlmAnalyzer failed:",
        llmResult.error,
      );
    }
  } catch (err) {
    console.warn(
      "[classificationPipeline] runLlmAnalyzer threw:",
      err?.message ?? err,
    );
  }
  await save("09_llm.json", llmAnalysis);

  const finalResult = {
    abuseType: kbsResolved.abuseType,
    confidence: kbsResolved.confidence,
    path: "kbs",
    report: buildFallbackReport(job.url, kbsResult, llmAnalysis),
    llmAnalysis,
    stages: {
      trust: trustResult,
      htmlAnalysis,
      pageFindings,
      logoDetection,
      chunks,
      semantic: semanticOutput,
      kbs: kbsResult,
    },
  };
  await save("10_result.json", stripStages(finalResult));
  return finalResult;
}

/**
 * Final artifact without the large nested stages blob (already written per-stage).
 * @param {ClassificationResult} result
 */
function stripStages(result) {
  return {
    abuseType: result.abuseType,
    confidence: result.confidence,
    path: result.path,
    report: result.report,
    llmAnalysis: result.llmAnalysis,
  };
}

// ---------------------------------------------------------------------------
// Report builders
// ---------------------------------------------------------------------------

/**
 * @param {string} url
 * @param {import("./heuristic.js").TrustResult} trustResult
 */
function buildTrustOfficialReport(url, trustResult) {
  return {
    summary: `Domain classified as official: ${trustResult.reason}`,
    key_domains_reviewed: [safeHostname(url) ?? url],
    findings: [
      `Trust score: ${trustResult.score}/100`,
      `Reason: ${trustResult.reason}`,
      ...trustResult.flags.map((f) => `Signal: ${f}`),
    ],
    trust_score: trustResult.score,
    trust_flags: trustResult.flags,
  };
}

/**
 * @param {string} url
 * @param {import("./kbs.js").KBSResult} kbsResult
 * @param {import("./llmAnalyzer.js").LlmAnalysis|null} [llmAnalysis]
 */
function buildFallbackReport(url, kbsResult, llmAnalysis = null) {
  const signalNames = kbsResult.signals.map((s) => s.name);
  return {
    summary: llmAnalysis?.summary
      ? llmAnalysis.summary
      : "KBS signals collected; LLM analysis unavailable or not yet run.",
    key_domains_reviewed: [safeHostname(url) ?? url],
    findings: signalNames.map((n) => `KBS signal: ${n}`),
    kbs_classified_as: kbsResult.classifiedAs,
    kbs_classification_scores: kbsResult.classificationScores,
    llm_risk_category: llmAnalysis?.riskCategory ?? null,
    llm_risk_level: llmAnalysis?.riskLevel ?? null,
  };
}

/**
 * @param {string} url
 * @param {{
 *   reason: string,
 *   httpStatus?: number,
 *   sinkholeIps?: string[],
 *   trustResult?: import("../collection/trust/heuristic.js").TrustResult|null,
 * }} opts
 * @returns {ClassificationResult}
 */
function buildAccessDeniedResult(url, opts) {
  const findings = [];
  if (opts.httpStatus != null) {
    findings.push(`HTTP status ${opts.httpStatus} (access denied / unavailable)`);
  }
  if (Array.isArray(opts.sinkholeIps) && opts.sinkholeIps.length > 0) {
    findings.push(
      `DNS sinkhole A record(s): ${opts.sinkholeIps.join(", ")}`,
    );
  }
  return {
    abuseType: normalizeAbuseType("Access_Denied"),
    confidence: "high",
    path: "access_denied",
    report: {
      summary: `Access denied — content unavailable (${opts.reason}).`,
      key_domains_reviewed: [safeHostname(url) ?? url],
      findings,
    },
    llmAnalysis: null,
    stages: {
      trust: opts.trustResult ?? null,
      htmlAnalysis: null,
      pageFindings: null,
      logoDetection: null,
      chunks: null,
      semantic: null,
      kbs: null,
    },
  };
}

/**
 * @param {string} url
 * @param {import("./heuristic.js").TrustResult|null} trustResult
 * @returns {ClassificationResult}
 */
function buildEmptyHtmlResult(url, trustResult) {
  return {
    abuseType: "Unresolved",
    confidence: "low",
    path: "unresolved",
    report: {
      summary: "No HTML content available for analysis.",
      key_domains_reviewed: [safeHostname(url) ?? url],
      findings: ["HTML payload was empty or missing."],
    },
    llmAnalysis: null,
    stages: {
      trust: trustResult,
      htmlAnalysis: null,
      pageFindings: null,
      logoDetection: null,
      chunks: null,
      semantic: null,
      kbs: null,
    },
  };
}

/**
 * Brand profile missing from the local store.
 * @param {string} url
 * @param {string} reason
 * @returns {ClassificationResult}
 */
function buildBrandUnresolvedResult(url, reason) {
  return {
    abuseType: "Unresolved",
    confidence: "low",
    path: "unresolved",
    report: {
      summary: reason,
      key_domains_reviewed: [safeHostname(url) ?? url],
      findings: [reason],
    },
    llmAnalysis: null,
    stages: {
      trust: null,
      htmlAnalysis: null,
      pageFindings: null,
      logoDetection: null,
      chunks: null,
      semantic: null,
      kbs: null,
    },
  };
}

/**
 * @param {string} url
 * @returns {string | null}
 */
function safeHostname(url) {
  try {
    return new URL(url).hostname;
  } catch {
    return null;
  }
}

/**
 * Pick primary abuse type from KBS promoted classifications.
 *
 * @param {import("./kbs.js").KBSResult|null|undefined} kbsResult
 * @returns {{ abuseType: string, confidence: "high"|"medium"|"low" }}
 */
function resolveKbsClassification(kbsResult) {
  const classified = Array.isArray(kbsResult?.classifiedAs)
    ? kbsResult.classifiedAs
    : [];
  const scores = kbsResult?.classificationScores ?? {};

  if (classified.length === 0) {
    return { abuseType: normalizeAbuseType("Other_Site"), confidence: "low" };
  }

  let best = classified[0];
  let bestScore = Number(scores[best] ?? 0);
  for (const name of classified) {
    const s = Number(scores[name] ?? 0);
    if (s > bestScore) {
      best = name;
      bestScore = s;
    }
  }

  const confidence =
    bestScore >= 0.7 ? "high" : bestScore >= 0.45 ? "medium" : "low";

  return {
    abuseType: normalizeAbuseType(best),
    confidence,
  };
}
