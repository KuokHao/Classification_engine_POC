import "./loadEnv.js";

/** BytePlus Ark API key — set via .env (ARK_API_KEY=...). */
export const ARK_API_KEY = process.env.ARK_API_KEY || "";
/** Alias used by llmAnalyzer / older callers. */
export const EMBEDDING_MODEL_API_KEY = ARK_API_KEY;

// ---------------------------------------------------------------------------
// Models & endpoints — edit these for teammates (keys stay in .env)
// ---------------------------------------------------------------------------

/** BytePlus Ark Responses API (vision LLM + Seed Translation). */
export const ARK_RESPONSES_URL =
  "https://ark.ap-southeast.bytepluses.com/api/v3/responses";

/** Vision / classification LLM (llmAnalyzer). */
export const LLM_MODEL = "dola-seed-2-1-turbo-260628";

/** Seed Translation model (languageTranslator). */
export const TRANSLATION_MODEL = "seed-translation-250915";

/** Multimodal embeddings endpoint (semantic + logo). */
export const EMBEDDINGS_URL =
  "https://ark.ap-southeast.bytepluses.com/api/v3/embeddings/multimodal";

/** Multimodal embedding model (semanticAnalyzer + logoDetector). */
export const EMBEDDING_MODEL = "skylark-embedding-vision-251215";
