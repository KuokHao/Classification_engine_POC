/**
 * Semantic analyzer configuration.
 *
 * SEMANTIC_THRESHOLDS — named threshold levels used by derived fact rules.
 * DERIVED_FACT_RULES  — single-concept threshold rules.
 * AGGREGATE_FACT_RULES — multi-concept OR rules that produce aggregate facts.
 */

/**
 * Named cosine similarity thresholds.
 * @type {{ weak: number, medium: number, strong: number }}
 */
export const SEMANTIC_THRESHOLDS = {
  weak: 0.55,
  medium: 0.63,
  strong: 0.78,
};

/**
 * @typedef {Object} SingleConceptRule
 * @property {string} fact       - derived fact key to assert
 * @property {string} concept    - score key from SemanticScores
 * @property {string} threshold  - key into SEMANTIC_THRESHOLDS ("weak"|"medium"|"strong")
 */

/**
 * @typedef {Object} MultiConceptRule
 * @property {string}   fact      - derived fact key to assert
 * @property {string[]} concepts  - score keys, checked with operator
 * @property {string}   threshold - key into SEMANTIC_THRESHOLDS
 * @property {"any"}    operator  - "any" = fire if at least one concept passes
 */

/**
 * Individual derived fact rules — one concept, one threshold.
 * Processed in order; all matching rules fire.
 * @type {(SingleConceptRule)[]}
 */
export const DERIVED_FACT_RULES = [
  {
    fact: "semantic_account_verification_language_detected",
    concept: "accountVerificationScore",
    threshold: "medium",
  },
  {
    fact: "semantic_strong_account_verification_language_detected",
    concept: "accountVerificationScore",
    threshold: "strong",
  },
  {
    fact: "semantic_credential_login_language_detected",
    concept: "credentialLoginScore",
    threshold: "medium",
  },
  {
    fact: "semantic_password_reset_language_detected",
    concept: "passwordResetScore",
    threshold: "medium",
  },
  {
    fact: "semantic_otp_verification_language_detected",
    concept: "otpVerificationScore",
    threshold: "medium",
  },
  {
    fact: "semantic_recruitment_language_detected",
    concept: "recruitmentScore",
    threshold: "medium",
  },
  {
    fact: "semantic_recruitment_fee_language_detected",
    concept: "recruitmentFeeScore",
    threshold: "medium",
  },
  {
    fact: "semantic_investment_scam_language_detected",
    concept: "investmentScamScore",
    threshold: "medium",
  },
  {
    fact: "semantic_fee_collection_language_detected",
    concept: "feeCollectionScore",
    threshold: "medium",
  },
  {
    fact: "semantic_support_payment_scam_language_detected",
    concept: "supportPaymentScamScore",
    threshold: "medium",
  },
  {
    fact: "semantic_reward_or_grant_scam_language_detected",
    concept: "rewardOrGrantScamScore",
    threshold: "medium",
  },
  {
    fact: "semantic_gambling_language_detected",
    concept: "gamblingScore",
    threshold: "medium",
  },
  {
    fact: "semantic_adult_content_language_detected",
    concept: "adultContentScore",
    threshold: "medium",
  },
  {
    fact: "semantic_parking_language_detected",
    concept: "parkingScore",
    threshold: "medium",
  },
  {
    fact: "semantic_official_brand_tone_detected",
    concept: "brandOfficialToneScore",
    threshold: "medium",
  },
  {
    fact: "semantic_urgency_language_detected",
    concept: "urgencyScore",
    threshold: "medium",
  },
];

/**
 * Aggregate derived fact rules — fire when ANY listed concept passes the threshold.
 * Processed after DERIVED_FACT_RULES.
 * @type {MultiConceptRule[]}
 */
export const AGGREGATE_FACT_RULES = [
  {
    fact: "semantic_phishing_language_detected",
    concepts: [
      "accountVerificationScore",
      "credentialLoginScore",
      "passwordResetScore",
      "otpVerificationScore",
    ],
    threshold: "medium",
    operator: "any",
  },
  {
    fact: "semantic_scam_language_detected",
    concepts: [
      "investmentScamScore",
      "feeCollectionScore",
      "supportPaymentScamScore",
      "rewardOrGrantScamScore",
      "recruitmentFeeScore",
    ],
    threshold: "medium",
    operator: "any",
  },
  {
    fact: "semantic_transaction_language_detected",
    concepts: ["shoppingScore", "checkoutScore", "paymentScore"],
    threshold: "medium",
    operator: "any",
  },
  {
    fact: "semantic_ecommerce_language_detected",
    concepts: ["shoppingScore", "checkoutScore"],
    threshold: "medium",
    operator: "any",
  },
];
