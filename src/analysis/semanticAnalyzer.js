/**
 * Semantic Analyzer — BytePlus embedding matcher for threat classification.
 *
 * Embeds chunker.py text chunks and scores them against phrase libraries.
 * Produces flat category scores (max across chunks), derived semantic facts,
 * and evidence for the KBS.
 *
 * Usage:
 *   const analyzer = await createSemanticAnalyzer();
 *   const result   = await analyzer.analyze({ chunks });
 *
 * Low-cost / test mode (no model load):
 *   const analyzer = createNullSemanticAnalyzer();
 *   const result   = await analyzer.analyze(input);  // empty output, instant
 */

import { fileURLToPath } from "url";
import { PHRASE_LIBRARIES } from "../../config/phraseLibraries.js";
import {
  SEMANTIC_THRESHOLDS,
  DERIVED_FACT_RULES,
  AGGREGATE_FACT_RULES,
} from "../../config/semanticConfig.js";
import {
  cosineSimilarity,
  fetchTextEmbeddings,
} from "./embeddingsClient.js";

// ---------------------------------------------------------------------------
// JSDoc typedefs
// ---------------------------------------------------------------------------

/**
 * @typedef {Object} TextChunk
 * @property {string} text
 * @property {{ zone?: string, [key: string]: unknown }} [metadata]
 */

/**
 * @typedef {Object} SemanticAnalyzerInput
 * @property {TextChunk[]} chunks
 */

/**
 * @typedef {Object} SemanticScores
 * @property {number} [accountVerificationScore]
 * @property {number} [credentialLoginScore]
 * @property {number} [passwordResetScore]
 * @property {number} [otpVerificationScore]
 * @property {number} [shoppingScore]
 * @property {number} [checkoutScore]
 * @property {number} [paymentScore]
 * @property {number} [recruitmentScore]
 * @property {number} [recruitmentFeeScore]
 * @property {number} [investmentScamScore]
 * @property {number} [feeCollectionScore]
 * @property {number} [supportPaymentScamScore]
 * @property {number} [rewardOrGrantScamScore]
 * @property {number} [gamblingScore]
 * @property {number} [adultContentScore]
 * @property {number} [parkingScore]
 * @property {number} [legitSiteBoilerplateScore]
 * @property {number} [urgencyScore]
 */

/**
 * @typedef {Object} EvidenceItem
 * @property {string} fact
 * @property {string} concept
 * @property {number} score
 * @property {string} matchedChunk
 * @property {string} matchedReferencePhrase
 * @property {string} zone
 */

/**
 * @typedef {Object} SemanticAnalyzerOutput
 * @property {SemanticScores} scores
 * @property {string[]}       derivedFacts
 * @property {EvidenceItem[]} evidence
 */

/**
 * @typedef {Object} SemanticAnalyzer
 * @property {(input: SemanticAnalyzerInput) => Promise<SemanticAnalyzerOutput>} analyze
 */

/**
 * @typedef {{ category: string, phrase: string, score: number, chunkText: string, zone: string }} ChunkMatch
 */

// ---------------------------------------------------------------------------
// SemanticMatcher
// ---------------------------------------------------------------------------

/**
 * Caches library embeddings and scores vectors against them.
 */
export class SemanticMatcher {
  /**
   * @param {Record<string, string[]>} library
   */
  constructor(library) {
    this.library = library;
    /** @type {{ category: string, phrase: string, vector: number[] }[]} */
    this.cachedLibraryEmbeddings = [];
    this.isReady = false;
  }

  /**
   * Embeds all library phrases and caches them. Call once at startup.
   * @returns {Promise<void>}
   */
  async initialize() {
    const allPhrases = [];
    const mapping = [];

    for (const [category, phrases] of Object.entries(this.library)) {
      for (const phrase of phrases) {
        allPhrases.push(phrase);
        mapping.push({ category, phrase });
      }
    }

    console.log(
      `[SemanticMatcher] Initializing cache for ${allPhrases.length} phrases...`,
    );
    const vectors = await fetchTextEmbeddings(allPhrases);

    this.cachedLibraryEmbeddings = mapping.map((meta, index) => ({
      ...meta,
      vector: vectors[index],
    }));

    this.isReady = true;
    console.log(`[SemanticMatcher] Cache ready.`);
  }

  /**
   * Score a precomputed embedding against the cached library.
   * Returns best match per category above threshold.
   *
   * @param {number[]} inputVector
   * @param {number} [threshold]
   * @returns {{ category: string, phrase: string, score: number }[]}
   */
  scoreVector(inputVector, threshold = SEMANTIC_THRESHOLDS.medium) {
    if (!this.isReady) {
      throw new Error("SemanticMatcher must be initialized first.");
    }

    /** @type {Record<string, { category: string, phrase: string, score: number }>} */
    const bestByCategory = {};

    for (const cached of this.cachedLibraryEmbeddings) {
      const score = Number(
        cosineSimilarity(inputVector, cached.vector).toFixed(4),
      );
      if (score < threshold) continue;
      const prev = bestByCategory[cached.category];
      if (!prev || prev.score < score) {
        bestByCategory[cached.category] = {
          category: cached.category,
          phrase: cached.phrase,
          score,
        };
      }
    }

    return Object.values(bestByCategory).sort((a, b) => b.score - a.score);
  }

  /**
   * Embed input text and match against the cached library.
   *
   * @param {string} input
   * @param {number} [threshold]
   * @returns {Promise<{ category: string, phrase: string, score: number }[]>}
   */
  async match(input, threshold = SEMANTIC_THRESHOLDS.medium) {
    const [inputVector] = await fetchTextEmbeddings([input]);
    return this.scoreVector(inputVector, threshold);
  }

  /**
   * Embed many chunks and return max-per-category matches with winning chunk.
   *
   * @param {TextChunk[]} chunks
   * @param {number} [threshold]
   * @returns {Promise<ChunkMatch[]>}
   */
  async matchChunks(chunks, threshold = SEMANTIC_THRESHOLDS.medium) {
    if (!this.isReady) {
      throw new Error("SemanticMatcher must be initialized first.");
    }

    const texts = chunks.map((c) => c.text);
    const vectors = await fetchTextEmbeddings(texts);

    /** @type {Map<string, ChunkMatch>} */
    const bestByCategory = new Map();

    for (let i = 0; i < chunks.length; i++) {
      const chunk = chunks[i];
      const zone =
        typeof chunk.metadata?.zone === "string" && chunk.metadata.zone
          ? chunk.metadata.zone
          : "chunk";
      const matches = this.scoreVector(vectors[i], threshold);

      for (const m of matches) {
        const prev = bestByCategory.get(m.category);
        if (!prev || prev.score < m.score) {
          bestByCategory.set(m.category, {
            category: m.category,
            phrase: m.phrase,
            score: m.score,
            chunkText: chunk.text,
            zone,
          });
        }
      }
    }

    return [...bestByCategory.values()].sort((a, b) => b.score - a.score);
  }
}

// ---------------------------------------------------------------------------
// Fact derivation & evidence
// ---------------------------------------------------------------------------

/**
 * @returns {SemanticAnalyzerOutput}
 */
function emptyOutput() {
  return { scores: {}, derivedFacts: [], evidence: [] };
}

/**
 * @param {ChunkMatch[]} matches
 * @returns {SemanticScores}
 */
function buildScores(matches) {
  /** @type {SemanticScores} */
  const scores = {};
  for (const m of matches) {
    scores[/** @type {keyof SemanticScores} */ (m.category)] = m.score;
  }
  return scores;
}

/**
 * @param {SemanticScores} scores
 * @returns {string[]}
 */
function deriveSemanticFacts(scores) {
  const facts = new Set();

  for (const rule of DERIVED_FACT_RULES) {
    const threshold = SEMANTIC_THRESHOLDS[rule.threshold] ?? 0;
    if ((scores[rule.concept] ?? 0) >= threshold) {
      facts.add(rule.fact);
    }
  }

  for (const rule of AGGREGATE_FACT_RULES) {
    const threshold = SEMANTIC_THRESHOLDS[rule.threshold] ?? 0;
    if (rule.operator === "any") {
      if (rule.concepts.some((c) => (scores[c] ?? 0) >= threshold)) {
        facts.add(rule.fact);
      }
    }
  }

  return [...facts];
}

/**
 * @param {string[]} derivedFacts
 * @param {SemanticScores} scores
 * @param {Map<string, ChunkMatch>} bestByCategory
 * @returns {EvidenceItem[]}
 */
function buildEvidence(derivedFacts, scores, bestByCategory) {
  /** @type {Map<string, string>} */
  const factConceptMap = new Map();

  for (const rule of DERIVED_FACT_RULES) {
    if (!factConceptMap.has(rule.fact)) {
      factConceptMap.set(rule.fact, rule.concept);
    }
  }
  for (const rule of AGGREGATE_FACT_RULES) {
    if (!factConceptMap.has(rule.fact)) {
      const best = rule.concepts.reduce((a, b) =>
        (scores[a] ?? 0) >= (scores[b] ?? 0) ? a : b,
      );
      factConceptMap.set(rule.fact, best);
    }
  }

  /** @type {EvidenceItem[]} */
  const evidence = [];
  for (const fact of derivedFacts) {
    const concept = factConceptMap.get(fact);
    if (!concept) continue;
    const match = bestByCategory.get(concept);
    if (!match || match.score === 0) continue;
    evidence.push({
      fact,
      concept,
      score: match.score,
      matchedChunk: match.chunkText,
      matchedReferencePhrase: match.phrase,
      zone: match.zone,
    });
  }
  return evidence;
}

/**
 * @param {unknown} input
 * @returns {TextChunk[]}
 */
function normalizeChunks(input) {
  const raw = input && typeof input === "object" ? input.chunks : null;
  if (!Array.isArray(raw)) return [];
  return raw.filter(
    (c) => c && typeof c.text === "string" && c.text.trim(),
  );
}

// ---------------------------------------------------------------------------
// Factories
// ---------------------------------------------------------------------------

/**
 * @returns {Promise<SemanticAnalyzer>}
 */
export async function createSemanticAnalyzer() {
  const matcher = new SemanticMatcher(PHRASE_LIBRARIES);
  await matcher.initialize();

  return {
    /**
     * @param {SemanticAnalyzerInput} input
     * @returns {Promise<SemanticAnalyzerOutput>}
     */
    async analyze(input) {
      const chunks = normalizeChunks(input);
      if (!chunks.length) {
        return emptyOutput();
      }

      const matches = await matcher.matchChunks(
        chunks,
        SEMANTIC_THRESHOLDS.medium,
      );
      const scores = buildScores(matches);

      /** @type {Map<string, ChunkMatch>} */
      const bestByCategory = new Map();
      for (const m of matches) {
        bestByCategory.set(m.category, m);
      }

      const derivedFacts = deriveSemanticFacts(scores);
      const evidence = buildEvidence(derivedFacts, scores, bestByCategory);

      return {
        scores,
        derivedFacts,
        evidence,
      };
    },
  };
}

/**
 * @returns {SemanticAnalyzer}
 */
export function createNullSemanticAnalyzer() {
  return {
    async analyze() {
      return emptyOutput();
    },
  };
}

// ---------------------------------------------------------------------------
// Self-run test block
// ---------------------------------------------------------------------------
if (process.argv[1] === fileURLToPath(import.meta.url)) {
  (async () => {
    try {
      const analyzer = await createSemanticAnalyzer();
      const sample =
        "unauthorized login attempt detected, reset your password now";
      const result = await analyzer.analyze({
        chunks: [{ text: sample, metadata: { zone: "test" } }],
      });
      console.log("chunk:", sample);
      console.log("scores:", result.scores);
      console.log("derivedFacts:", result.derivedFacts);
      console.log("evidence count:", result.evidence.length);
    } catch (error) {
      console.error("Execution failed:", error);
    }
  })();
}
