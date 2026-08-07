/**
 * Shared BytePlus Ark multimodal embeddings client.
 * Used by semantic analysis (text) and logo detection (images).
 */

import { ARK_API_KEY } from "../../../config/config.js";

export const EMBEDDINGS_URL =
  "https://ark.ap-southeast.bytepluses.com/api/v3/embeddings/multimodal";
export const MODEL_NAME = "skylark-embedding-vision-251215";

/**
 * @returns {string}
 */
function getApiKey() {
  return process.env.ARK_API_KEY || ARK_API_KEY || "";
}

/**
 * Cosine similarity between two equal-length vectors.
 * @param {number[]} vecA
 * @param {number[]} vecB
 * @returns {number}
 */
export function cosineSimilarity(vecA, vecB) {
  let dotProduct = 0;
  let normA = 0;
  let normB = 0;
  for (let i = 0; i < vecA.length; i++) {
    dotProduct += vecA[i] * vecB[i];
    normA += vecA[i] * vecA[i];
    normB += vecB[i] * vecB[i];
  }
  if (normA === 0 || normB === 0) return 0;
  return dotProduct / (Math.sqrt(normA) * Math.sqrt(normB));
}

/**
 * Fetch a single text embedding.
 * @param {string} text
 * @param {{ apiKey?: string }} [opts]
 * @returns {Promise<number[]>}
 */
export async function fetchTextEmbedding(text, opts = {}) {
  const apiKey = opts.apiKey ?? getApiKey();
  const response = await fetch(EMBEDDINGS_URL, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${apiKey}`,
    },
    body: JSON.stringify({
      model: MODEL_NAME,
      input: [{ type: "text", text }],
    }),
  });

  const result = await response.json();
  if (!response.ok || !result.data?.embedding) {
    console.error(
      "[embeddingsClient] Unexpected text embedding response:",
      JSON.stringify(result),
    );
    throw new Error(
      `BytePlus API Error (${response.status}): ${JSON.stringify(result)}`,
    );
  }

  return result.data.embedding;
}

/**
 * Fetch text embeddings in sequential batches to avoid rate-limiting.
 * @param {string[]} texts
 * @param {number} [batchSize=10]
 * @param {{ apiKey?: string }} [opts]
 * @returns {Promise<number[][]>}
 */
export async function fetchTextEmbeddings(texts, batchSize = 10, opts = {}) {
  const results = [];
  for (let i = 0; i < texts.length; i += batchSize) {
    const batch = texts.slice(i, i + batchSize);
    const batchResults = await Promise.all(
      batch.map((text) => fetchTextEmbedding(text, opts)),
    );
    results.push(...batchResults);
  }
  return results;
}

/**
 * Fetch a single image embedding from a URL or data URL.
 * Returns null on soft failures (caller may skip the candidate).
 * @param {string} imageUrl
 * @param {{ apiKey?: string, softFail?: boolean }} [opts]
 * @returns {Promise<number[] | null>}
 */
export async function fetchImageEmbedding(imageUrl, opts = {}) {
  const apiKey = opts.apiKey ?? getApiKey();
  const softFail = opts.softFail !== false;

  const response = await fetch(EMBEDDINGS_URL, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${apiKey}`,
    },
    body: JSON.stringify({
      model: MODEL_NAME,
      input: [{ type: "image_url", image_url: { url: imageUrl } }],
    }),
  });

  const responseData = await response.json();

  if (!response.ok) {
    if (softFail) {
      console.warn(
        `[embeddingsClient] skip image (${response.status}): ${imageUrl}`,
        responseData?.error?.message ?? JSON.stringify(responseData),
      );
      return null;
    }
    throw new Error(
      `BytePlus API Error (${response.status}): ${JSON.stringify(responseData)}`,
    );
  }

  const vector = responseData?.data?.embedding ?? responseData?.data?.dense;
  if (!Array.isArray(vector)) {
    if (softFail) {
      console.warn(`[embeddingsClient] missing embedding for: ${imageUrl}`);
      return null;
    }
    throw new Error(`Missing embedding for: ${imageUrl}`);
  }

  return vector;
}
