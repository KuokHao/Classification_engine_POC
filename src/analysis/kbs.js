/**
 * Knowledge-Based System — forward-chaining engine for domain threat classification.
 *
 * All evidence is unified under a single Signal concept (no separate facts/tags).
 * Rules fire when their conditions are met; each rule can contribute score deltas
 * to multiple classifications simultaneously. Classifications promote themselves
 * independently when their cumulative score crosses a threshold.
 *
 * Decision order (see RULES preamble + ForwardChainingEngine.run):
 *   0) access_denied (HTTP deny status / DNS sinkhole) — stop if promoted
 *   1) official (only when trusted_infra) — brand org identity → Official
 *   2) brand_independent content (Gambling / Pornography / Parking_Site)
 *   3) brand_dependent threats — skipped when trusted_infra
 *   4) residual Other_Site when nothing else promoted
 *
 * Do not gate on brand_name_present (text): the brand may appear only in images/logos.
 */

import { extractInputFacts, assertExtractedSignals } from "./factExtractor.js";

// ---------------------------------------------------------------------------
// Classification thresholds
// ---------------------------------------------------------------------------

/** Minimum cumulative score for a classification to be promoted into WM. */
const CLASSIFICATION_THRESHOLDS = {
  Impersonation: 0.6,
  Phishing: 0.5,
  Scam: 0.5,
  Fake_Shop: 0.45,
  Recruitment_Fraud: 0.5,
  Gambling: 0.6,
  Pornography: 0.6,
  Social_Profile_Redirection: 0.4,
  Parking_Site: 0.4,
  Access_Denied: 0.4,
  Official: 0.7,
  Other_Site: 0.4,
};

// ---------------------------------------------------------------------------
// Signal
// ---------------------------------------------------------------------------

/**
 * @typedef {Object} Signal
 * @property {string}    name      - Unique signal identifier, e.g. "brand_mismatch"
 * @property {string}    group     - Logical group, e.g. "identity", "phishing", "content"
 * @property {number}    strength  - 0–1 confidence that this signal is present
 * @property {unknown}   [value]   - Optional primitive value (boolean, string, number)
 * @property {string[]}  evidence  - Human-readable reasons this signal was asserted
 */

// ---------------------------------------------------------------------------
// WorkingMemory
// ---------------------------------------------------------------------------

class WorkingMemory {
  constructor() {
    /** @type {Map<string, Signal>} */
    this.signals = new Map();

    /**
     * Per-classification accumulated score.
     * @type {Map<string, { score: number, contributions: Array<{ delta: number, signalName: string, ruleId: string }> }>}
     */
    this.classificationScores = new Map();

    /** Classifications whose cumulative score has crossed their threshold. */
    this.assertedClassifications = new Set();

    /** Rule IDs that have already fired — prevents re-firing. */
    this.firedRules = new Set();
  }

  /**
   * Assert or update a signal in working memory.
   * Presence-only convention: callers should only assert detected/positive facts
   * (or explicit negative signals like insecure_connection). Absence means undetected.
   *
   * If the signal already exists, it is overwritten only if the new strength is higher.
   *
   * @param {string} name
   * @param {{ group: string, strength: number, value?: unknown, evidence: string[] }} opts
   */
  assertSignal(name, { group, strength, value, evidence }) {
    const existing = this.signals.get(name);
    if (existing && existing.strength >= strength) return;
    this.signals.set(name, {
      name,
      group,
      strength: Math.min(1, Math.max(0, strength)),
      value,
      evidence: Array.isArray(evidence) ? evidence : [String(evidence)],
    });
  }

  /**
   * @param {string} name
   * @returns {boolean}
   */
  hasSignal(name) {
    return this.signals.has(name);
  }

  /**
   * @param {string} name
   * @returns {Signal | undefined}
   */
  getSignal(name) {
    return this.signals.get(name);
  }

  /**
   * @param {string} classification
   * @returns {boolean}
   */
  classificationAsserted(classification) {
    return this.assertedClassifications.has(classification);
  }
}

// ---------------------------------------------------------------------------
// ClassificationScorer
// ---------------------------------------------------------------------------

class ClassificationScorer {
  constructor() {
    /**
     * @type {Map<string, { score: number, contributions: Array<{ delta: number, signalName: string, ruleId: string }> }>}
     */
    this.scores = new Map();

    for (const type of Object.keys(CLASSIFICATION_THRESHOLDS)) {
      this.scores.set(type, { score: 0, contributions: [] });
    }
  }

  /**
   * Add a score delta to a classification.
   *
   * @param {string} classification
   * @param {number} delta          - Value to add (0–1 range, uncapped here; capped at getScore())
   * @param {string} signalName     - Which signal triggered this contribution
   * @param {string} ruleId         - Which rule produced it
   */
  addScore(classification, delta, signalName, ruleId) {
    if (!this.scores.has(classification)) return;
    const entry = this.scores.get(classification);
    entry.score += delta;
    entry.contributions.push({ delta, signalName, ruleId });
  }

  /**
   * @param {string} classification
   * @returns {number} Capped at 1.0
   */
  getScore(classification) {
    return Math.min(1, this.scores.get(classification)?.score ?? 0);
  }

  /**
   * Check every classification against its threshold and promote any that qualify.
   * Called after each rule fires. Newly promoted classifications may satisfy other
   * rules' conditions on the next engine loop iteration.
   *
   * @param {WorkingMemory} wm
   */
  checkThresholds(wm) {
    for (const [type, threshold] of Object.entries(CLASSIFICATION_THRESHOLDS)) {
      if (
        !wm.assertedClassifications.has(type) &&
        this.getScore(type) >= threshold
      ) {
        wm.assertedClassifications.add(type);
      }
    }
  }

  /**
   * @returns {Record<string, number>}
   */
  getScores() {
    /** @type {Record<string, number>} */
    const out = {};
    for (const [type] of this.scores) {
      out[type] = this.getScore(type);
    }
    return out;
  }

  /**
   * Per-classification contribution list (ruleId / signalName / delta).
   * @returns {Record<string, Array<{ delta: number, signalName: string, ruleId: string }>>}
   */
  getScoreBreakdown() {
    /** @type {Record<string, Array<{ delta: number, signalName: string, ruleId: string }>>} */
    const out = {};
    for (const [type, entry] of this.scores) {
      out[type] = [...(entry.contributions ?? [])];
    }
    return out;
  }
}

// ---------------------------------------------------------------------------
// Rules
// ---------------------------------------------------------------------------

/**
 * @typedef {Object} Rule
 * @property {string}   id
 * @property {"official"|"brand_independent"|"brand_dependent"} phase
 * @property {string}   group
 * @property {(wm: WorkingMemory) => boolean} conditions
 * @property {(wm: WorkingMemory, scorer: ClassificationScorer) => void} action
 */

/**
 * Impersonation scorers require a prior gate and no commentary/third-party exemption.
 * @param {WorkingMemory} wm
 * @returns {boolean}
 */
function isImpersonationScorable(wm) {
  return (
    wm.hasSignal("impersonation_candidate") &&
    !wm.hasSignal("impersonation_exempt")
  );
}

/**
 * Any brand claim on the page — text, logo, or markup attributes/paths.
 * Used for Impersonation candidacy (`impersonation_gate`) and for
 * brand-protection scorers via `isBrandAbuseScorable`.
 * @param {WorkingMemory} wm
 * @returns {boolean}
 */
function hasBrandClaim(wm) {
  return (
    wm.hasSignal("brand_name_present") ||
    wm.hasSignal("brand_image_detected") ||
    wm.hasSignal("brand_in_markup")
  );
}

/**
 * Strong enough to score identity traps: visible text or detected logo.
 * Markup-only hits are excluded — attribute/path tokens alone must not open strong scoring.
 * @param {WorkingMemory} wm
 * @returns {boolean}
 */
function hasStrongBrandClaim(wm) {
  return (
    wm.hasSignal("brand_name_present") || wm.hasSignal("brand_image_detected")
  );
}

/**
 * Shared brand-present check for non-Impersonation brand-protection scorers
 * (Phishing / Scam / Fake_Shop / Recruitment). Equals `hasBrandClaim`; does not
 * assert a derived signal (no `brand_abuse_candidate`).
 * @param {WorkingMemory} wm
 * @returns {boolean}
 */
function isBrandAbuseScorable(wm) {
  return hasBrandClaim(wm);
}

/**
 * Phishing scorers require the watched brand on the page (text, logo, or markup).
 * Does not use `impersonation_candidate` / `impersonation_exempt`.
 * @param {WorkingMemory} wm
 * @returns {boolean}
 */
function isPhishingScorable(wm) {
  return isBrandAbuseScorable(wm);
}

/**
 * Fake_Shop checklist scorers: brand claim, storefront context, and not scam_exempt.
 * @param {WorkingMemory} wm
 * @returns {boolean}
 */
function isFakeShopScorable(wm) {
  return (
    isBrandAbuseScorable(wm) &&
    wm.hasSignal("shop_storefront_context") &&
    !wm.hasSignal("scam_exempt")
  );
}

/**
 * Structural risk context for gated Scam scoring (infra + trust hollow).
 * Dead-link signals live in Extraction, not here.
 * @param {WorkingMemory} wm
 * @returns {boolean}
 */
function hasScamRiskContext(wm) {
  return (
    wm.hasSignal("is_newly_registered") ||
    wm.hasSignal("young_domain") ||
    wm.hasSignal("is_short_term_registration") ||
    wm.hasSignal("has_hidden_registrant") ||
    wm.hasSignal("is_hosted_on_bulletproof") ||
    wm.hasSignal("no_email_capability") ||
    wm.hasSignal("missing_trust_navigation") ||
    wm.hasSignal("error_trust_navigation") ||
    wm.hasSignal("missing_copyright")
  );
}

/**
 * Extraction / monetization channel for brand-protection scams.
 * Forms (financial/identity/file) are Phishing-only — not Scam extraction.
 * @param {WorkingMemory} wm
 * @returns {boolean}
 */
function hasScamExtraction(wm) {
  return (
    wm.hasSignal("semantic_fee_collection_language_detected") ||
    wm.hasSignal("semantic_support_payment_scam_language_detected") ||
    wm.hasSignal("semantic_recruitment_fee_language_detected") ||
    wm.hasSignal("offplatform_chat_contact") ||
    wm.hasSignal("free_webmail_contact") ||
    wm.hasSignal("conversion_destination_dead") ||
    wm.hasSignal("excessive_dead_links")
  );
}

/**
 * Weak optional lure (semantics / brand). Never required for Scam promote.
 * @param {WorkingMemory} wm
 * @returns {boolean}
 */
function hasScamLure(wm) {
  return (
    wm.hasSignal("semantic_investment_scam_language_detected") ||
    wm.hasSignal("semantic_reward_or_grant_scam_language_detected") ||
    wm.hasSignal("semantic_official_brand_tone_detected") ||
    (isImpersonationScorable(wm) && hasStrongBrandClaim(wm))
  );
}

/**
 * Credential / login capture cues — gates Phishing deltas from hollow trust priors.
 * @param {WorkingMemory} wm
 * @returns {boolean}
 */
function hasCredentialCaptureCue(wm) {
  return (
    wm.hasSignal("has_password_input") ||
    wm.hasSignal("has_otp_input") ||
    wm.hasSignal("has_username_input") ||
    wm.hasSignal("semantic_credential_login_language_detected") ||
    wm.hasSignal("semantic_credential_capture_language_detected")
  );
}

/**
 * Scam / Recruitment_Fraud checklist scorers require brand on page and not scam_exempt.
 * Aged domain or enterprise TLS (OV/EV) zeros checklist scoring; hooks may still assert.
 *
 * @param {WorkingMemory} wm
 * @returns {boolean}
 */
function isScamScorable(wm) {
  return isBrandAbuseScorable(wm) && !wm.hasSignal("scam_exempt");
}

/**
 * Parking scorers skip when the page looks like an active credential-capture site
 * (shared parking NS/IP must not override a clear phishing/login portal).
 * @param {WorkingMemory} wm
 * @returns {boolean}
 */
function isParkingScorable(wm) {
  return !(
    wm.hasSignal("has_password_input") &&
    wm.hasSignal("semantic_credential_login_language_detected")
  );
}

/**
 * Rule base — ordered and tagged by phase (see preamble inside RULES).
 * Engine: official (trusted only) → brand_independent → brand_dependent (untrusted) → Other_Site.
 *
 * Score contribution pattern inside action():
 *   wm.assertSignal("signal_name", { group, strength, value, evidence });
 *   scorer.addScore("Classification", delta, "signal_name", rule.id);
 *
 * @type {Rule[]}
 */
const RULES = [
  // ===========================================================================
  // Decision order (matches ForwardChainingEngine.run phases):
  //   Phase official — only when trusted_infra (heuristic score ≥ 60)
  //   Phase access_denied — HTTP 451/403/410 or DNS sinkhole
  //   Phase brand_independent — Gambling / Pornography / Parking_Site
  //   Phase brand_dependent — skipped when trusted_infra
  //   Residual Other_Site if still nothing promoted
  // ===========================================================================

  // ===========================================================================
  // PHASE access_denied — content unavailable (deny status / DNS sinkhole)
  // ===========================================================================

  {
    id: "access_denied_http_status",
    phase: "access_denied",
    group: "structural",
    conditions: (wm) => wm.hasSignal("http_access_denied_status"),
    action: (_wm, scorer) => {
      scorer.addScore(
        "Access_Denied",
        0.8,
        "http_access_denied_status",
        "access_denied_http_status",
      );
    },
  },

  {
    id: "access_denied_dns_sinkhole",
    phase: "access_denied",
    group: "infrastructure",
    conditions: (wm) => wm.hasSignal("dns_sinkhole_detected"),
    action: (_wm, scorer) => {
      scorer.addScore(
        "Access_Denied",
        0.8,
        "dns_sinkhole_detected",
        "access_denied_dns_sinkhole",
      );
    },
  },

  // ===========================================================================
  // PHASE official — brand ownership via TLS subject org / WHOIS registrant
  // Runs only on trusted_infra hosts. Never promotes from trust score alone.
  // ===========================================================================

  {
    id: "official_tls_org_identity",
    phase: "official",
    group: "identity",
    // OV/EV subject.O matches brand fingerprint → Official.
    conditions: (wm) =>
      wm.hasSignal("trusted_infra") &&
      wm.hasSignal("brand_tls_org_match") &&
      wm.hasSignal("has_enterprise_tls"),
    action: (wm, scorer) => {
      wm.assertSignal("official_brand_identity", {
        group: "identity",
        strength: 1,
        value: true,
        evidence: [
          "TLS subject organization matches brand fingerprint on a structurally trusted host",
        ],
      });
      scorer.addScore(
        "Official",
        0.8,
        "brand_tls_org_match",
        "official_tls_org_identity",
      );
    },
  },

  {
    id: "official_registrant_org_identity",
    phase: "official",
    group: "identity",
    // WHOIS registrant matches brand + enterprise TLS or aged domain → Official.
    conditions: (wm) =>
      wm.hasSignal("trusted_infra") &&
      wm.hasSignal("brand_registrant_org_match") &&
      (wm.hasSignal("has_enterprise_tls") ||
        wm.hasSignal("established_domain")),
    action: (wm, scorer) => {
      wm.assertSignal("official_brand_identity", {
        group: "identity",
        strength: 1,
        value: true,
        evidence: [
          "WHOIS registrant organization matches brand fingerprint on a structurally trusted host",
        ],
      });
      scorer.addScore(
        "Official",
        0.75,
        "brand_registrant_org_match",
        "official_registrant_org_identity",
      );
    },
  },

  {
    id: "official_brand_logo",
    phase: "official",
    group: "identity",
    // Detected brand logo on a trusted host — prior (alone cannot cross 0.7).
    conditions: (wm) =>
      wm.hasSignal("trusted_infra") && wm.hasSignal("brand_image_detected"),
    action: (wm, scorer) => {
      wm.assertSignal("official_brand_logo_claim", {
        group: "identity",
        strength: 1,
        value: true,
        evidence: ["Brand logo/image detected on a structurally trusted host"],
      });
      scorer.addScore(
        "Official",
        0.4,
        "brand_image_detected",
        "official_brand_logo",
      );
    },
  },

  {
    id: "official_brand_name_text",
    phase: "official",
    group: "identity",
    // Visible brand name on a trusted host — prior (alone cannot cross 0.7).
    conditions: (wm) =>
      wm.hasSignal("trusted_infra") && wm.hasSignal("brand_name_present"),
    action: (wm, scorer) => {
      wm.assertSignal("official_brand_name_claim", {
        group: "identity",
        strength: 1,
        value: true,
        evidence: [
          "Brand name present in page text on a structurally trusted host",
        ],
      });
      scorer.addScore(
        "Official",
        0.4,
        "brand_name_present",
        "official_brand_name_text",
      );
    },
  },

  {
    id: "official_brand_in_markup",
    phase: "official",
    group: "identity",
    // Brand token in HTML attributes/paths on a trusted host — prior (alone cannot cross 0.7).
    conditions: (wm) =>
      wm.hasSignal("trusted_infra") && wm.hasSignal("brand_in_markup"),
    action: (wm, scorer) => {
      wm.assertSignal("official_brand_markup_claim", {
        group: "identity",
        strength: 1,
        value: true,
        evidence: [
          "Brand token found in HTML markup attributes/paths on a structurally trusted host",
        ],
      });
      scorer.addScore(
        "Official",
        0.4,
        "brand_in_markup",
        "official_brand_in_markup",
      );
    },
  },

  // ===========================================================================
  // PHASE brand_independent — content classes
  // ===========================================================================

  // ---------------------------------------------------------------------------
  // Group: "content"
  // Signals about regulated or adult content categories.
  // Contributes exclusively to Gambling or Pornography.
  // Thresholds: Gambling 0.6, Pornography 0.6
  //
  // Gambling input facts (tiered):
  //   definitive_gambling_language — near-certain keywords (+0.7 terminal)
  //   strong_gambling_language     — high-precision keywords (+0.45 / +0.65)
  //   weak_gambling_language       — ambiguous (+0.15, never alone)
  //   semantic_gambling_language_detected — embedding path (+0.65)
  // ---------------------------------------------------------------------------

  // ---------------------------------------------------------------------------
  // Pornography — tiered language + structural buddies (Gambling-shaped)
  // Threshold 0.6. Weak / age-gate / TLD / gallery alone never promote.
  // ---------------------------------------------------------------------------
  {
    id: "adult_definitive_keywords",
    phase: "brand_independent",
    group: "content",
    conditions: (wm) => wm.hasSignal("definitive_adult_language"),
    action: (_wm, scorer) => {
      scorer.addScore(
        "Pornography",
        0.7,
        "definitive_adult_language",
        "adult_definitive_keywords",
      );
    },
  },
  {
    id: "adult_content_language",
    phase: "brand_independent",
    group: "content",
    conditions: (wm) =>
      wm.hasSignal("semantic_adult_content_language_detected"),
    action: (_wm, scorer) => {
      scorer.addScore(
        "Pornography",
        0.7,
        "semantic_adult_content_language_detected",
        "adult_content_language",
      );
    },
  },
  {
    id: "adult_strong_keywords",
    phase: "brand_independent",
    group: "content",
    conditions: (wm) => wm.hasSignal("strong_adult_language"),
    action: (wm, scorer) => {
      const value = wm.getSignal("strong_adult_language")?.value;
      const strongCount =
        (typeof value === "object" && value != null
          ? value.strongCount ?? value.count
          : null) ?? 1;
      const delta = strongCount >= 2 ? 0.65 : 0.45;
      scorer.addScore(
        "Pornography",
        delta,
        "strong_adult_language",
        "adult_strong_keywords",
      );
    },
  },
  {
    id: "adult_weak_prior",
    phase: "brand_independent",
    group: "content",
    conditions: (wm) => wm.hasSignal("weak_adult_language"),
    action: (_wm, scorer) => {
      scorer.addScore(
        "Pornography",
        0.15,
        "weak_adult_language",
        "adult_weak_prior",
      );
    },
  },
  {
    id: "adult_age_gate",
    phase: "brand_independent",
    group: "content",
    conditions: (wm) => wm.hasSignal("adult_age_gate_detected"),
    action: (_wm, scorer) => {
      scorer.addScore(
        "Pornography",
        0.25,
        "adult_age_gate_detected",
        "adult_age_gate",
      );
    },
  },
  {
    id: "adult_tld",
    phase: "brand_independent",
    group: "content",
    conditions: (wm) => wm.hasSignal("adult_tld_detected"),
    action: (_wm, scorer) => {
      scorer.addScore(
        "Pornography",
        0.35,
        "adult_tld_detected",
        "adult_tld",
      );
    },
  },
  {
    id: "adult_dense_gallery",
    phase: "brand_independent",
    group: "content",
    conditions: (wm) => wm.hasSignal("dense_media_gallery"),
    action: (_wm, scorer) => {
      scorer.addScore(
        "Pornography",
        0.2,
        "dense_media_gallery",
        "adult_dense_gallery",
      );
    },
  },

  // ---------------------------------------------------------------------------
  // Gambling — tiered language leaves (definitive / semantic / strong / weak)
  // Threshold 0.6. Weak alone never promotes. No scam_exempt.
  // ---------------------------------------------------------------------------
  {
    id: "gambling_definitive_keywords",
    phase: "brand_independent",
    group: "content",
    conditions: (wm) => wm.hasSignal("definitive_gambling_language"),
    action: (_wm, scorer) => {
      scorer.addScore(
        "Gambling",
        0.7,
        "definitive_gambling_language",
        "gambling_definitive_keywords",
      ); // TODO: tune weight — terminal definitive
    },
  },
  {
    id: "gambling_semantic",
    phase: "brand_independent",
    group: "content",
    conditions: (wm) => wm.hasSignal("semantic_gambling_language_detected"),
    action: (_wm, scorer) => {
      scorer.addScore(
        "Gambling",
        0.65,
        "semantic_gambling_language_detected",
        "gambling_semantic",
      ); // TODO: tune weight — paraphrase path
    },
  },
  {
    id: "gambling_strong_keywords",
    phase: "brand_independent",
    group: "content",
    conditions: (wm) => wm.hasSignal("strong_gambling_language"),
    action: (wm, scorer) => {
      const value = wm.getSignal("strong_gambling_language")?.value;
      const strongCount =
        (typeof value === "object" && value != null
          ? value.strongCount ?? value.count
          : null) ?? 1;
      const delta = strongCount >= 2 ? 0.65 : 0.45;
      scorer.addScore(
        "Gambling",
        delta,
        "strong_gambling_language",
        "gambling_strong_keywords",
      ); // TODO: tune weight — density rule
    },
  },
  {
    id: "gambling_weak_prior",
    phase: "brand_independent",
    group: "content",
    conditions: (wm) => wm.hasSignal("weak_gambling_language"),
    action: (_wm, scorer) => {
      scorer.addScore(
        "Gambling",
        0.15,
        "weak_gambling_language",
        "gambling_weak_prior",
      ); // TODO: tune weight — never alone
    },
  },

  // ---------------------------------------------------------------------------
  // Group: "structural" — Parking_Site (threshold 0.4)
  // Gate: "domain" / "domain name" → parking_keywords_present → parking_candidate
  // High-confidence: parking_candidate + semantic_parking_language (+0.7)
  // Infra / no-email / transaction are secondary buddies after the gate.
  // Gate tokens alone never score. NS/IP are not terminal hard-confirms.
  // ---------------------------------------------------------------------------

  {
    id: "parking_candidate_gate",
    phase: "brand_independent",
    group: "structural",
    conditions: (wm) => wm.hasSignal("parking_keywords_present"),
    action: (wm) => {
      wm.assertSignal("parking_candidate", {
        group: "structural",
        strength: 1,
        value: true,
        evidence: [
          "Page mentions domain / domain name — parking evaluation enabled",
        ],
      });
    },
  },

  {
    // Gate + semantic parking: near-certain Parking_Site (clears 0.4 alone)
    id: "parking_semantic_primary",
    phase: "brand_independent",
    group: "structural",
    conditions: (wm) =>
      isParkingScorable(wm) &&
      wm.hasSignal("parking_candidate") &&
      wm.hasSignal("semantic_parking_language_detected"),
    action: (_wm, scorer) => {
      scorer.addScore(
        "Parking_Site",
        0.7,
        "semantic_parking_language_detected",
        "parking_semantic_primary",
      ); // TODO: tune weight — high-confidence gate+semantic path
    },
  },

  {
    // Stronger IP promote; candidate+IP crosses threshold (IP more specific than NS)
    id: "parking_infra_ip",
    phase: "brand_independent",
    group: "structural",
    conditions: (wm) =>
      isParkingScorable(wm) &&
      wm.hasSignal("parking_candidate") &&
      wm.hasSignal("parked_ip_detected"),
    action: (_wm, scorer) => {
      scorer.addScore(
        "Parking_Site",
        0.45,
        "parked_ip_detected",
        "parking_infra_ip",
      ); // TODO: tune weight
    },
  },

  {
    // Strong NS promote; alone with candidate does not cross 0.4
    id: "parking_infra_ns",
    phase: "brand_independent",
    group: "structural",
    conditions: (wm) =>
      isParkingScorable(wm) &&
      wm.hasSignal("parking_candidate") &&
      wm.hasSignal("parked_nameservers_detected"),
    action: (_wm, scorer) => {
      scorer.addScore(
        "Parking_Site",
        0.3,
        "parked_nameservers_detected",
        "parking_infra_ns",
      ); // TODO: tune weight
    },
  },

  {
    id: "parking_no_email",
    phase: "brand_independent",
    group: "structural",
    conditions: (wm) =>
      isParkingScorable(wm) &&
      wm.hasSignal("parking_candidate") &&
      (wm.hasSignal("no_email_infrastructure") ||
        wm.hasSignal("no_email_capability")),
    action: (wm, scorer) => {
      const signalName = wm.hasSignal("no_email_infrastructure")
        ? "no_email_infrastructure"
        : "no_email_capability";
      scorer.addScore("Parking_Site", 0.2, signalName, "parking_no_email"); // TODO: tune weight
    },
  },

  {
    id: "parking_transaction_buddy",
    phase: "brand_independent",
    group: "structural",
    conditions: (wm) =>
      isParkingScorable(wm) &&
      wm.hasSignal("parking_candidate") &&
      wm.hasSignal("semantic_transaction_language_detected"),
    action: (_wm, scorer) => {
      scorer.addScore(
        "Parking_Site",
        0.2,
        "semantic_transaction_language_detected",
        "parking_transaction_buddy",
      ); // TODO: tune weight
    },
  },

  // ===========================================================================
  // PHASE 2 — brand_dependent (always runs after content classes)
  // Brand text may be absent when the brand appears only in images/logos.
  // ===========================================================================

  // ---------------------------------------------------------------------------
  // Group: "identity" — Impersonation (gate → exemptions → scorers)
  // brand_name_present remains a positive cue when text is found; absence alone
  // must not skip this whole phase (logo-only pages still need threat scoring).
  // ---------------------------------------------------------------------------

  {
    id: "impersonation_gate",
    phase: "brand_dependent",
    group: "identity",
    // hasBrandClaim asserts impersonation_candidate only (Impersonation path).
    // Phishing/Scam/Fake_Shop/Recruitment use isBrandAbuseScorable separately.
    conditions: (wm) => hasBrandClaim(wm),
    action: (wm) => {
      wm.assertSignal("impersonation_candidate", {
        group: "identity",
        strength: 1,
        value: true,
        evidence: [
          "Brand name, brand image, or brand markup present — impersonation evaluation enabled",
        ],
      });
    },
  },

  {
    id: "commentary_exemption",
    phase: "brand_dependent",
    group: "identity",
    // Incidental brand mention: no capture / urgency — not posing as the brand.
    // Logo presence alone does not revoke this (news/reviews often embed logos).
    // Logo-only pages never hit this rule (requires brand_name_present).
    conditions: (wm) =>
      wm.hasSignal("brand_name_present") &&
      !wm.hasSignal("has_password_input") &&
      !wm.hasSignal("has_otp_input") &&
      !wm.hasSignal("has_financial_input") &&
      !wm.hasSignal("semantic_urgency_language_detected"),
    action: (wm) => {
      wm.assertSignal("impersonation_exempt", {
        group: "identity",
        strength: 1,
        value: true,
        evidence: [
          "Brand mentioned without credentials, financial capture, or urgency — incidental / commentary mention",
        ],
      });
    },
  },

  {
    id: "established_third_party",
    phase: "brand_dependent",
    group: "identity",
    // Aged + enterprise TLS third party. Logo does not revoke — partners/media often show brand marks.
    conditions: (wm) =>
      (wm.hasSignal("brand_name_present") ||
        wm.hasSignal("brand_image_detected") ||
        wm.hasSignal("brand_in_markup")) &&
      wm.hasSignal("established_domain") &&
      wm.hasSignal("has_enterprise_tls"),
    action: (wm) => {
      wm.assertSignal("impersonation_exempt", {
        group: "identity",
        strength: 1,
        value: true,
        evidence: [
          "Brand mentioned on an aged domain with enterprise TLS — likely legitimate third party",
        ],
      });
    },
  },

  {
    id: "visual_brand_claim_prior",
    phase: "brand_dependent",
    group: "identity",
    // Logo detected off official domain — base Impersonation prior (alone cannot cross 0.6).
    conditions: (wm) =>
      isImpersonationScorable(wm) && wm.hasSignal("brand_image_detected"),
    action: (wm, scorer) => {
      wm.assertSignal("visual_brand_claim", {
        group: "identity",
        strength: 1,
        value: true,
        evidence: [
          "Brand logo/image detected off official domain — visual brand claim",
        ],
      });
      scorer.addScore(
        "Impersonation",
        0.3,
        "visual_brand_claim",
        "visual_brand_claim_prior",
      ); // TODO: tune weight
    },
  },

  {
    id: "deceptive_subdomain_spoof",
    phase: "brand_dependent",
    group: "identity",
    // Subdomains alone are common; only score with a capture/lure cue.
    // Brand-in-hostname is not used — scraped targets already contain brand tokens in the domain.
    conditions: (wm) =>
      isImpersonationScorable(wm) &&
      wm.hasSignal("is_subdomain") &&
      (wm.hasSignal("has_password_input") ||
        wm.hasSignal("has_otp_input") ||
        wm.hasSignal("semantic_credential_login_language_detected")),
    action: (wm, scorer) => {
      wm.assertSignal("deceptive_subdomain", {
        group: "identity",
        strength: 1,
        value: true,
        evidence: [
          "Credential/OTP capture or login language on a subdomain off the official domain",
        ],
      });
      scorer.addScore(
        "Impersonation",
        0.7,
        "deceptive_subdomain",
        "deceptive_subdomain_spoof",
      ); // TODO: tune weight
    },
  },

  {
    id: "stolen_face_tls_mismatch",
    phase: "brand_dependent",
    group: "identity",
    conditions: (wm) =>
      isImpersonationScorable(wm) &&
      hasStrongBrandClaim(wm) &&
      wm.hasSignal("tls_identity_mismatch"),
    action: (wm, scorer) => {
      wm.assertSignal("stolen_face_tls", {
        group: "identity",
        strength: 1,
        value: true,
        evidence: [
          "Brand claimed on page but TLS certificate identity does not match hostname",
        ],
      });
      scorer.addScore(
        "Impersonation",
        0.7,
        "stolen_face_tls",
        "stolen_face_tls_mismatch",
      ); // TODO: tune weight
    },
  },

  {
    id: "the_phishing_trap",
    phase: "brand_dependent",
    group: "identity",
    conditions: (wm) =>
      isImpersonationScorable(wm) &&
      hasStrongBrandClaim(wm) &&
      (wm.hasSignal("has_password_input") ||
        wm.hasSignal("has_otp_input") ||
        wm.hasSignal("semantic_credential_login_language_detected")),
    action: (wm, scorer) => {
      wm.assertSignal("phishing_trap", {
        group: "identity",
        strength: 1,
        value: true,
        evidence: [
          "Brand claimed off official domain while collecting credentials/OTP or using login language",
        ],
      });
      scorer.addScore(
        "Impersonation",
        0.45,
        "phishing_trap",
        "the_phishing_trap",
      ); // TODO: tune weight
      scorer.addScore("Phishing", 0.4, "phishing_trap", "the_phishing_trap"); // TODO: tune weight
    },
  },

  {
    id: "the_burner_corporation",
    phase: "brand_dependent",
    group: "identity",
    // Brand claimed on disposable / privacy-shielded infra (boilerplate is not brand identity).
    conditions: (wm) =>
      isImpersonationScorable(wm) &&
      hasStrongBrandClaim(wm) &&
      (wm.hasSignal("is_newly_registered") ||
        wm.hasSignal("young_domain") ||
        wm.hasSignal("is_short_term_registration")) &&
      wm.hasSignal("has_hidden_registrant"),
    action: (wm, scorer) => {
      wm.assertSignal("burner_corporation", {
        group: "identity",
        strength: 1,
        value: true,
        evidence: [
          "Brand mentioned on a young/short-term domain with hidden WHOIS registrant",
        ],
      });
      scorer.addScore(
        "Impersonation",
        0.55,
        "burner_corporation",
        "the_burner_corporation",
      ); // TODO: tune weight
    },
  },

  {
    id: "geographic_imposter",
    phase: "brand_dependent",
    group: "identity",
    conditions: (wm) =>
      isImpersonationScorable(wm) &&
      hasStrongBrandClaim(wm) &&
      (wm.hasSignal("country_mismatch") ||
        wm.hasSignal("is_hosted_on_bulletproof")),
    action: (wm, scorer) => {
      wm.assertSignal("geographic_imposter", {
        group: "identity",
        strength: 1,
        value: true,
        evidence: [
          "Brand claimed off official domain with country mismatch or bulletproof hosting",
        ],
      });
      scorer.addScore(
        "Impersonation",
        0.5,
        "geographic_imposter",
        "geographic_imposter",
      ); // TODO: tune weight
    },
  },

  // ---------------------------------------------------------------------------
  // Group: "phishing"
  // Credential/OTP harvesting mechanics. Scorers require brand on page via
  // isPhishingScorable (not impersonation_candidate / impersonation_exempt).
  // Forms (financial/identity/file) → Phishing, not Scam extraction.
  // ---------------------------------------------------------------------------
  //credential capture (login/OTP — not financial/identity/file)
  {
    id: "credential_capture",
    phase: "brand_dependent",
    group: "phishing",
    conditions: (wm) =>
      isPhishingScorable(wm) &&
      (wm.hasSignal("has_password_input") ||
        wm.hasSignal("has_otp_input") ||
        wm.hasSignal("has_username_input") ||
        wm.hasSignal("has_email_input") ||
        wm.hasSignal("semantic_credential_login_language_detected") ||
        wm.hasSignal("semantic_credential_capture_language_detected")),
    action: (_wm, scorer) => {
      scorer.addScore(
        "Phishing",
        0.4,
        "credential_capture",
        "credential_capture",
      ); // TODO: tune weight
    },
  },
  {
    id: "phishing_sensitive_inputs",
    phase: "brand_dependent",
    group: "phishing",
    conditions: (wm) =>
      isPhishingScorable(wm) &&
      (wm.hasSignal("has_financial_input") ||
        wm.hasSignal("has_identity_input") ||
        wm.hasSignal("has_file_upload")),
    action: (wm, scorer) => {
      const signalName = wm.hasSignal("has_financial_input")
        ? "has_financial_input"
        : wm.hasSignal("has_identity_input")
          ? "has_identity_input"
          : "has_file_upload";
      scorer.addScore(
        "Phishing",
        0.3,
        signalName,
        "phishing_sensitive_inputs",
      ); // TODO: tune weight
    },
  },
  //disabled autocomplete
  {
    id: "disabled_autocomplete",
    phase: "brand_dependent",
    group: "phishing",
    conditions: (wm) =>
      isPhishingScorable(wm) &&
      wm.hasSignal("has_password_input") &&
      wm.hasSignal("disabled_autocomplete"),
    action: (_wm, scorer) => {
      scorer.addScore(
        "Phishing",
        0.4,
        "disabled_autocomplete",
        "disabled_autocomplete",
      ); // TODO: tune weight
    },
  },
  //external form submission
  {
    id: "external_form_submission",
    phase: "brand_dependent",
    group: "phishing",
    conditions: (wm) =>
      isPhishingScorable(wm) && wm.hasSignal("external_form_submission"),
    action: (_wm, scorer) => {
      scorer.addScore(
        "Phishing",
        0.4,
        "external_form_submission",
        "external_form_submission",
      ); // TODO: tune weight
    },
  },

  {
    id: "urgency_account_lure",
    phase: "brand_dependent",
    group: "phishing",
    conditions: (wm) =>
      isPhishingScorable(wm) &&
      (wm.hasSignal("semantic_coercive_urgency_language_detected") ||
        wm.hasSignal("semantic_credential_capture_language_detected")) &&
      (wm.hasSignal("semantic_account_verification_language_detected") ||
        wm.hasSignal("semantic_password_reset_language_detected") ||
        wm.hasSignal("semantic_account_lockout_language_detected")),
    action: (_wm, scorer) => {
      scorer.addScore(
        "Phishing",
        0.4,
        "urgency_account_lure",
        "urgency_account_lure",
      ); // TODO: tune weight
    },
  },
  //account verification language
  {
    id: "account_verification_language",
    phase: "brand_dependent",
    group: "phishing",
    conditions: (wm) =>
      isPhishingScorable(wm) &&
      (wm.hasSignal("semantic_account_verification_language_detected") ||
        wm.hasSignal("semantic_credential_capture_language_detected")),
    action: (_wm, scorer) => {
      scorer.addScore(
        "Phishing",
        0.4,
        "account_verification_language",
        "account_verification_language",
      ); // TODO: tune weight
      scorer.addScore(
        "Phishing",
        0.4,
        "credential_capture",
        "credential_capture",
      ); // TODO: tune weight
    },
  },
  //password reset language
  {
    id: "password_reset_language",
    phase: "brand_dependent",
    group: "phishing",
    conditions: (wm) =>
      isPhishingScorable(wm) &&
      wm.hasSignal("semantic_password_reset_language_detected"),
    action: (_wm, scorer) => {
      scorer.addScore(
        "Phishing",
        0.4,
        "password_reset_language",
        "password_reset_language",
      ); // TODO: tune weight
    },
  },

  // ---------------------------------------------------------------------------
  // Group: "scam" — gated additive (brand protection)
  //   Brand      — isScamScorable requires hasBrandClaim (via isBrandAbuseScorable)
  //   Exemption  — scam_exempt (established domain OR enterprise TLS)
  //   Lure       — weak optional semantics / brand (never required)
  //   Extraction — fee/support lang, offplatform chat, free webmail, dead links
  //   Risk       — young/hidden/bulletproof/no-email + trust hollow
  // Two buckets required (mutual gates). Forms → Phishing, not Scam.
  // Threshold: Scam >= 0.5
  // ---------------------------------------------------------------------------

  {
    id: "legitimate_business_exemption",
    phase: "brand_dependent",
    group: "scam",
    conditions: (wm) =>
      wm.hasSignal("established_domain") || wm.hasSignal("has_enterprise_tls"),
    action: (wm) => {
      wm.assertSignal("scam_exempt", {
        group: "scam",
        strength: 1,
        value: true,
        evidence: [
          "Host has established domain age or enterprise TLS (OV/EV) — structural history trusted over semantic lure",
        ],
      });
    },
  },

  // --- Lure (weak; score only with risk or extraction) ---
  {
    id: "scam_investment_language",
    phase: "brand_dependent",
    group: "scam",
    conditions: (wm) =>
      isScamScorable(wm) &&
      wm.hasSignal("semantic_investment_scam_language_detected") &&
      (hasScamRiskContext(wm) || hasScamExtraction(wm)),
    action: (_wm, scorer) => {
      scorer.addScore(
        "Scam",
        0.05,
        "semantic_investment_scam_language_detected",
        "scam_investment_language",
      ); // TODO: tune weight — weakest lure
    },
  },

  {
    id: "scam_reward_language",
    phase: "brand_dependent",
    group: "scam",
    conditions: (wm) =>
      isScamScorable(wm) &&
      wm.hasSignal("semantic_reward_or_grant_scam_language_detected") &&
      (hasScamRiskContext(wm) || hasScamExtraction(wm)),
    action: (_wm, scorer) => {
      scorer.addScore(
        "Scam",
        0.1,
        "semantic_reward_or_grant_scam_language_detected",
        "scam_reward_language",
      ); // TODO: tune weight
    },
  },

  {
    id: "scam_brand_claim",
    phase: "brand_dependent",
    group: "scam",
    conditions: (wm) =>
      isScamScorable(wm) &&
      isImpersonationScorable(wm) &&
      hasStrongBrandClaim(wm) &&
      (hasScamRiskContext(wm) || hasScamExtraction(wm)),
    action: (_wm, scorer) => {
      scorer.addScore(
        "Scam",
        0.1,
        "brand_impersonation_scam_lure",
        "scam_brand_claim",
      ); // TODO: tune weight
    },
  },

  {
    id: "scam_official_tone_boost",
    phase: "brand_dependent",
    group: "scam",
    conditions: (wm) =>
      isScamScorable(wm) &&
      wm.hasSignal("semantic_official_brand_tone_detected") &&
      !wm.hasSignal("has_enterprise_tls") &&
      (hasScamRiskContext(wm) || hasScamExtraction(wm)),
    action: (_wm, scorer) => {
      scorer.addScore(
        "Scam",
        0.1,
        "semantic_official_brand_tone_detected",
        "scam_official_tone_boost",
      ); // TODO: tune weight
    },
  },

  // --- Extraction (score only with risk context) ---
  {
    id: "scam_fee_language",
    phase: "brand_dependent",
    group: "scam",
    conditions: (wm) =>
      isScamScorable(wm) &&
      hasScamRiskContext(wm) &&
      (wm.hasSignal("semantic_fee_collection_language_detected") ||
        wm.hasSignal("semantic_recruitment_fee_language_detected")),
    action: (wm, scorer) => {
      const signalName = wm.hasSignal(
        "semantic_fee_collection_language_detected",
      )
        ? "semantic_fee_collection_language_detected"
        : "semantic_recruitment_fee_language_detected";
      scorer.addScore("Scam", 0.15, signalName, "scam_fee_language"); // TODO: tune weight
    },
  },

  {
    id: "scam_support_payment",
    phase: "brand_dependent",
    group: "scam",
    conditions: (wm) =>
      isScamScorable(wm) &&
      hasScamRiskContext(wm) &&
      wm.hasSignal("semantic_support_payment_scam_language_detected"),
    action: (_wm, scorer) => {
      scorer.addScore(
        "Scam",
        0.15,
        "semantic_support_payment_scam_language_detected",
        "scam_support_payment",
      ); // TODO: tune weight
    },
  },

  {
    id: "scam_offplatform_chat",
    phase: "brand_dependent",
    group: "scam",
    conditions: (wm) =>
      isScamScorable(wm) &&
      hasScamRiskContext(wm) &&
      wm.hasSignal("offplatform_chat_contact"),
    action: (_wm, scorer) => {
      scorer.addScore(
        "Scam",
        0.25,
        "offplatform_chat_contact",
        "scam_offplatform_chat",
      ); // TODO: tune weight
    },
  },

  {
    id: "scam_free_webmail",
    phase: "brand_dependent",
    group: "scam",
    conditions: (wm) =>
      isScamScorable(wm) &&
      hasScamRiskContext(wm) &&
      wm.hasSignal("free_webmail_contact"),
    action: (_wm, scorer) => {
      scorer.addScore(
        "Scam",
        0.15,
        "free_webmail_contact",
        "scam_free_webmail",
      ); // TODO: tune weight
    },
  },

  {
    id: "scam_conversion_destination_dead",
    phase: "brand_dependent",
    group: "scam",
    conditions: (wm) =>
      isScamScorable(wm) &&
      hasScamRiskContext(wm) &&
      wm.hasSignal("conversion_destination_dead"),
    action: (_wm, scorer) => {
      scorer.addScore(
        "Scam",
        0.15,
        "conversion_destination_dead",
        "scam_conversion_destination_dead",
      ); // TODO: tune weight
    },
  },

  {
    id: "scam_excessive_dead_links",
    phase: "brand_dependent",
    group: "scam",
    conditions: (wm) =>
      isScamScorable(wm) &&
      hasScamRiskContext(wm) &&
      wm.hasSignal("excessive_dead_links"),
    action: (_wm, scorer) => {
      scorer.addScore(
        "Scam",
        0.15,
        "excessive_dead_links",
        "scam_excessive_dead_links",
      ); // TODO: tune weight
    },
  },

  // --- Risk (score only with extraction or lure) ---
  {
    id: "scam_young_domain",
    phase: "brand_dependent",
    group: "scam",
    conditions: (wm) =>
      isScamScorable(wm) &&
      (hasScamExtraction(wm) || hasScamLure(wm)) &&
      (wm.hasSignal("is_newly_registered") ||
        wm.hasSignal("young_domain") ||
        wm.hasSignal("is_short_term_registration")),
    action: (wm, scorer) => {
      const signalName = wm.hasSignal("is_newly_registered")
        ? "is_newly_registered"
        : wm.hasSignal("young_domain")
          ? "young_domain"
          : "is_short_term_registration";
      scorer.addScore("Scam", 0.15, signalName, "scam_young_domain"); // TODO: tune weight
    },
  },

  {
    id: "scam_hidden_registrant",
    phase: "brand_dependent",
    group: "scam",
    conditions: (wm) =>
      isScamScorable(wm) &&
      (hasScamExtraction(wm) || hasScamLure(wm)) &&
      wm.hasSignal("has_hidden_registrant"),
    action: (_wm, scorer) => {
      scorer.addScore(
        "Scam",
        0.15,
        "has_hidden_registrant",
        "scam_hidden_registrant",
      ); // TODO: tune weight
    },
  },

  {
    id: "scam_bulletproof",
    phase: "brand_dependent",
    group: "scam",
    conditions: (wm) =>
      isScamScorable(wm) &&
      (hasScamExtraction(wm) || hasScamLure(wm)) &&
      wm.hasSignal("is_hosted_on_bulletproof"),
    action: (_wm, scorer) => {
      scorer.addScore(
        "Scam",
        0.1,
        "is_hosted_on_bulletproof",
        "scam_bulletproof",
      ); // TODO: tune weight
    },
  },

  {
    id: "scam_no_email",
    phase: "brand_dependent",
    group: "scam",
    conditions: (wm) =>
      isScamScorable(wm) &&
      (hasScamExtraction(wm) || hasScamLure(wm)) &&
      wm.hasSignal("no_email_capability"),
    action: (_wm, scorer) => {
      scorer.addScore("Scam", 0.1, "no_email_capability", "scam_no_email"); // TODO: tune weight
    },
  },

  // --- Impersonation cross-bleed (brand + scam lure language) ---
  {
    id: "impersonation_scam_fee_trap",
    phase: "brand_dependent",
    group: "scam",
    conditions: (wm) =>
      isImpersonationScorable(wm) &&
      hasStrongBrandClaim(wm) &&
      (wm.hasSignal("semantic_fee_collection_language_detected") ||
        wm.hasSignal("semantic_reward_or_grant_scam_language_detected") ||
        wm.hasSignal("semantic_investment_scam_language_detected") ||
        wm.hasSignal("semantic_support_payment_scam_language_detected")),
    action: (_wm, scorer) => {
      scorer.addScore(
        "Impersonation",
        0.25,
        "impersonation_scam_fee_trap",
        "impersonation_scam_fee_trap",
      ); // TODO: tune weight
    },
  },

  // ---------------------------------------------------------------------------
  // Group: "fake_shop"
  // Anatomy of a fake shopfront:
  //   Context   — shop_storefront_context (schema / prices / shop-or-checkout language)
  //   Checklist — additive risk cues gated by isFakeShopScorable
  //               (brand claim AND storefront context AND !scam_exempt)
  // Threshold: Fake_Shop promotes at cumulative score >= 0.45
  // Schema/pricing/language open context only — they do not score Fake_Shop.
  // Hollow trust is scored once via fake_shop_trust_hollow (not trust-group branches).
  // ---------------------------------------------------------------------------

  // ---------------------------------------------------------------------------
  // Shop storefront context (signal-only) — Context
  // Intent: mark that this page looks like a storefront before scoring cues.
  // IF: Product/Offer schema OR currency/prices OR ecommerce OR transaction language
  // THEN: assert shop_storefront_context (no score)
  // Why: avoids classifying random pages that only fail trust nav as Fake_Shop.
  // ---------------------------------------------------------------------------
  {
    id: "shop_storefront_context",
    phase: "brand_dependent",
    group: "fake_shop",
    conditions: (wm) =>
      wm.hasSignal("ecommerce_schema_present") ||
      wm.hasSignal("pricing_patterns_present") ||
      wm.hasSignal("semantic_transaction_language_detected"),
    action: (wm) => {
      wm.assertSignal("shop_storefront_context", {
        group: "fake_shop",
        strength: 1,
        value: true,
        evidence: [
          "Page shows storefront cues (schema, prices, and/or shop/checkout language)",
        ],
      });
    },
  },

  {
    id: "fake_shop_suspicious_tld",
    phase: "brand_dependent",
    group: "fake_shop",
    conditions: (wm) =>
      isFakeShopScorable(wm) && wm.hasSignal("suspicious_shop_tld"),
    action: (_wm, scorer) => {
      scorer.addScore(
        "Fake_Shop",
        0.15,
        "suspicious_shop_tld",
        "fake_shop_suspicious_tld",
      ); // TODO: tune weight
    },
  },

  {
    id: "fake_shop_urgency",
    phase: "brand_dependent",
    group: "fake_shop",
    conditions: (wm) =>
      isFakeShopScorable(wm) &&
      wm.hasSignal("semantic_urgency_language_detected"),
    action: (_wm, scorer) => {
      scorer.addScore(
        "Fake_Shop",
        0.15,
        "semantic_urgency_language_detected",
        "fake_shop_urgency",
      ); // TODO: tune weight
    },
  },

  {
    id: "fake_shop_free_webmail",
    phase: "brand_dependent",
    group: "fake_shop",
    conditions: (wm) =>
      isFakeShopScorable(wm) && wm.hasSignal("free_webmail_contact"),
    action: (_wm, scorer) => {
      scorer.addScore(
        "Fake_Shop",
        0.2,
        "free_webmail_contact",
        "fake_shop_free_webmail",
      ); // TODO: tune weight
    },
  },

  {
    id: "fake_shop_no_https",
    phase: "brand_dependent",
    group: "fake_shop",
    conditions: (wm) => isFakeShopScorable(wm) && wm.hasSignal("no_https"),
    action: (_wm, scorer) => {
      scorer.addScore("Fake_Shop", 0.2, "no_https", "fake_shop_no_https"); // TODO: tune weight
    },
  },

  {
    id: "fake_shop_trust_hollow",
    phase: "brand_dependent",
    group: "fake_shop",
    // Fact layer: missing | broken (error covers inert + probe failures).
    conditions: (wm) =>
      isFakeShopScorable(wm) &&
      (wm.hasSignal("missing_trust_navigation") ||
        wm.hasSignal("error_trust_navigation")),
    action: (wm, scorer) => {
      const signalName = wm.hasSignal("missing_trust_navigation")
        ? "missing_trust_navigation"
        : "error_trust_navigation";
      scorer.addScore("Fake_Shop", 0.25, signalName, "fake_shop_trust_hollow"); // TODO: tune weight
    },
  },

  {
    id: "fake_shop_unrealistic_discount",
    phase: "brand_dependent",
    group: "fake_shop",
    conditions: (wm) =>
      isFakeShopScorable(wm) && wm.hasSignal("unrealistic_discount_detected"),
    action: (_wm, scorer) => {
      scorer.addScore(
        "Fake_Shop",
        0.25,
        "unrealistic_discount_detected",
        "fake_shop_unrealistic_discount",
      ); // TODO: tune weight
      scorer.addScore(
        "Scam",
        0.1,
        "unrealistic_discount_detected",
        "fake_shop_unrealistic_discount",
      ); // TODO: tune weight — light Scam bleed
    },
  },

  {
    id: "fake_shop_young_domain",
    phase: "brand_dependent",
    group: "fake_shop",
    conditions: (wm) =>
      isFakeShopScorable(wm) &&
      (wm.hasSignal("is_newly_registered") ||
        wm.hasSignal("young_domain") ||
        wm.hasSignal("is_short_term_registration")),
    action: (wm, scorer) => {
      const signalName = wm.hasSignal("is_newly_registered")
        ? "is_newly_registered"
        : wm.hasSignal("young_domain")
          ? "young_domain"
          : "is_short_term_registration";
      scorer.addScore("Fake_Shop", 0.2, signalName, "fake_shop_young_domain"); // TODO: tune weight
    },
  },

  // ---------------------------------------------------------------------------
  // Group: "recruitment"
  // Anatomy (additive checklist):
  //   Gate     — isScamScorable (brand claim AND !scam_exempt)
  //   Checklist — language prior + advance-fee + PII harvest + hollow portal
  // FP/FN: language-only + hollow without trap < 0.5; trap + young clears 0.5
  // Threshold: Recruitment_Fraud >= 0.5
  // ---------------------------------------------------------------------------

  {
    id: "recruitment_language_prior",
    phase: "brand_dependent",
    group: "recruitment",
    conditions: (wm) =>
      isScamScorable(wm) &&
      wm.hasSignal("semantic_recruitment_language_detected"),
    action: (_wm, scorer) => {
      scorer.addScore(
        "Recruitment_Fraud",
        0.15,
        "semantic_recruitment_language_detected",
        "recruitment_language_prior",
      ); // TODO: tune weight — prior 0.15
    },
  },

  {
    id: "recruitment_advance_fee",
    phase: "brand_dependent",
    group: "recruitment",
    conditions: (wm) =>
      isScamScorable(wm) &&
      wm.hasSignal("semantic_recruitment_language_detected") &&
      (wm.hasSignal("semantic_recruitment_fee_language_detected") ||
        wm.hasSignal("semantic_fee_collection_language_detected") ||
        wm.hasSignal("has_financial_input")),
    action: (wm, scorer) => {
      wm.assertSignal("advance_fee_recruitment_trap", {
        group: "recruitment",
        strength: 1,
        value: true,
        evidence: [
          "Job/recruitment language combined with fee demand or financial capture fields",
        ],
      });
      scorer.addScore(
        "Recruitment_Fraud",
        0.35,
        "advance_fee_recruitment_trap",
        "recruitment_advance_fee",
      ); // TODO: tune weight — was 0.30; compensates removed scam_advance_fee RF bleed
      scorer.addScore(
        "Scam",
        0.15,
        "advance_fee_recruitment_trap",
        "recruitment_advance_fee",
      ); // TODO: tune weight — light Scam bleed
    },
  },

  {
    id: "recruitment_pii_harvest",
    phase: "brand_dependent",
    group: "recruitment",
    conditions: (wm) =>
      isScamScorable(wm) &&
      wm.hasSignal("semantic_recruitment_language_detected") &&
      (wm.hasSignal("has_identity_input") || wm.hasSignal("has_file_upload")) &&
      (wm.hasSignal("is_newly_registered") ||
        wm.hasSignal("young_domain") ||
        wm.hasSignal("is_short_term_registration")),
    action: (wm, scorer) => {
      wm.assertSignal("excessive_identity_harvesting", {
        group: "recruitment",
        strength: 1,
        value: true,
        evidence: [
          "Recruitment language with identity/file capture on a newly registered, young, or short-term domain",
        ],
      });
      scorer.addScore(
        "Recruitment_Fraud",
        0.3,
        "excessive_identity_harvesting",
        "recruitment_pii_harvest",
      ); // TODO: tune weight
    },
  },

  {
    id: "recruitment_hollow_portal",
    phase: "brand_dependent",
    group: "recruitment",
    conditions: (wm) =>
      isScamScorable(wm) &&
      wm.hasSignal("semantic_recruitment_language_detected") &&
      hasStrongBrandClaim(wm) &&
      (wm.hasSignal("no_email_capability") ||
        wm.hasSignal("missing_trust_navigation") ||
        wm.hasSignal("error_trust_navigation")),
    action: (wm, scorer) => {
      wm.assertSignal("hollow_recruiter_portal", {
        group: "recruitment",
        strength: 1,
        value: true,
        evidence: [
          "Brand-associated recruitment page off official domain with no email capability or broken/missing trust navigation",
        ],
      });
      scorer.addScore(
        "Recruitment_Fraud",
        0.2,
        "hollow_recruiter_portal",
        "recruitment_hollow_portal",
      ); // TODO: tune weight
    },
  },

  {
    id: "recruitment_brand_impersonation",
    phase: "brand_dependent",
    group: "recruitment",
    conditions: (wm) =>
      isScamScorable(wm) &&
      wm.hasSignal("hollow_recruiter_portal") &&
      (wm.hasSignal("advance_fee_recruitment_trap") ||
        wm.hasSignal("excessive_identity_harvesting")),
    action: (wm, scorer) => {
      wm.assertSignal("recruitment_brand_impersonation", {
        group: "recruitment",
        strength: 1,
        value: true,
        evidence: [
          "Hollow brand recruitment portal combined with advance-fee or identity-harvest trap",
        ],
      });
      scorer.addScore(
        "Impersonation",
        0.35,
        "recruitment_brand_impersonation",
        "recruitment_brand_impersonation",
      ); // TODO: tune weight — Impersonation bleed only (RF from checklist)
    },
  },

  // ---------------------------------------------------------------------------
  // Group: "trust"
  // Fact layer emits only missing_trust_navigation | error_trust_navigation.
  // Scam risk hollow: missing/error/copyright (gated by extraction|lure + isScamScorable).
  // Phishing trust bleeds require isPhishingScorable (brand on page).
  // Recruitment trust bleeds reuse isScamScorable (brand + not scam_exempt).
  // excessive_dead_links / conversion_destination_dead → Scam Extraction only.
  // ---------------------------------------------------------------------------

  {
    id: "trust_nav_missing",
    phase: "brand_dependent",
    group: "trust",
    conditions: (wm) => wm.hasSignal("missing_trust_navigation"),
    action: (wm, scorer) => {
      if (
        isScamScorable(wm) &&
        (hasScamExtraction(wm) || hasScamLure(wm))
      ) {
        scorer.addScore(
          "Scam",
          0.15,
          "missing_trust_navigation",
          "trust_nav_missing",
        ); // TODO: tune weight — risk hollow
      }
      if (isImpersonationScorable(wm)) {
        scorer.addScore(
          "Impersonation",
          0.25,
          "missing_trust_navigation",
          "trust_nav_missing",
        ); // TODO: tune weight
      }
      // Credential cue alone must not score Phishing without brand on page.
      if (
        isPhishingScorable(wm) &&
        (hasCredentialCaptureCue(wm) || isImpersonationScorable(wm))
      ) {
        scorer.addScore(
          "Phishing",
          0.2,
          "missing_trust_navigation",
          "trust_nav_missing",
        ); // TODO: tune weight
      }
      // Recruitment reuses Scam brand + scam_exempt gate.
      if (
        isScamScorable(wm) &&
        wm.hasSignal("semantic_recruitment_language_detected")
      ) {
        scorer.addScore(
          "Recruitment_Fraud",
          0.15,
          "missing_trust_navigation",
          "trust_nav_missing",
        ); // TODO: tune weight
      }
    },
  },

  {
    id: "trust_nav_error",
    phase: "brand_dependent",
    group: "trust",
    conditions: (wm) => wm.hasSignal("error_trust_navigation"),
    action: (wm, scorer) => {
      if (
        isScamScorable(wm) &&
        (hasScamExtraction(wm) || hasScamLure(wm))
      ) {
        scorer.addScore(
          "Scam",
          0.1,
          "error_trust_navigation",
          "trust_nav_error",
        ); // TODO: tune weight — risk hollow
      }
      if (isImpersonationScorable(wm)) {
        scorer.addScore(
          "Impersonation",
          0.2,
          "error_trust_navigation",
          "trust_nav_error",
        ); // TODO: tune weight
      }
      // Credential cue alone must not score Phishing without brand on page.
      if (
        isPhishingScorable(wm) &&
        (hasCredentialCaptureCue(wm) || isImpersonationScorable(wm))
      ) {
        scorer.addScore(
          "Phishing",
          0.15,
          "error_trust_navigation",
          "trust_nav_error",
        ); // TODO: tune weight
      }
      // Recruitment reuses Scam brand + scam_exempt gate.
      if (
        isScamScorable(wm) &&
        wm.hasSignal("semantic_recruitment_language_detected")
      ) {
        scorer.addScore(
          "Recruitment_Fraud",
          0.1,
          "error_trust_navigation",
          "trust_nav_error",
        ); // TODO: tune weight
      }
    },
  },

  {
    id: "missing_copyright_prior",
    phase: "brand_dependent",
    group: "trust",
    conditions: (wm) => wm.hasSignal("missing_copyright"),
    action: (wm, scorer) => {
      if (
        isScamScorable(wm) &&
        (hasScamExtraction(wm) || hasScamLure(wm))
      ) {
        scorer.addScore(
          "Scam",
          0.1,
          "missing_copyright",
          "missing_copyright_prior",
        ); // TODO: tune weight — risk hollow
      }
      if (isImpersonationScorable(wm)) {
        scorer.addScore(
          "Impersonation",
          0.2,
          "missing_copyright",
          "missing_copyright_prior",
        ); // TODO: tune weight
      }
    },
  },

  {
    id: "excessive_dead_links_prior",
    phase: "brand_dependent",
    group: "trust",
    // Scam scored via scam_excessive_dead_links (Extraction); Impersonation/Phishing here.
    conditions: (wm) => wm.hasSignal("excessive_dead_links"),
    action: (wm, scorer) => {
      if (isImpersonationScorable(wm)) {
        scorer.addScore(
          "Impersonation",
          0.25,
          "excessive_dead_links",
          "excessive_dead_links_prior",
        ); // TODO: tune weight
      }
      // Credential cue alone must not score Phishing without brand on page.
      if (
        isPhishingScorable(wm) &&
        (hasCredentialCaptureCue(wm) || isImpersonationScorable(wm))
      ) {
        scorer.addScore(
          "Phishing",
          0.15,
          "excessive_dead_links",
          "excessive_dead_links_prior",
        ); // TODO: tune weight
      }
    },
  },

  {
    id: "conversion_destination_dead_prior",
    phase: "brand_dependent",
    group: "trust",
    // Scam scored via scam_conversion_destination_dead (Extraction).
    conditions: (wm) => wm.hasSignal("conversion_destination_dead"),
    action: (wm, scorer) => {
      if (isImpersonationScorable(wm)) {
        scorer.addScore(
          "Impersonation",
          0.2,
          "conversion_destination_dead",
          "conversion_destination_dead_prior",
        ); // TODO: tune weight
      }
    },
  },
];

// ---------------------------------------------------------------------------
// ForwardChainingEngine
// ---------------------------------------------------------------------------

class ForwardChainingEngine {
  /**
   * @param {Rule[]} rules
   */
  constructor(rules) {
    this.rules = rules;
  }

  /**
   * Run one phase to fixpoint (only rules whose phase matches).
   * @param {WorkingMemory} wm
   * @param {ClassificationScorer} scorer
   * @param {"official"|"brand_independent"|"brand_dependent"} phase
   */
  runPhase(wm, scorer, phase) {
    let progress = true;
    while (progress) {
      progress = false;
      for (const rule of this.rules) {
        if (rule.phase !== phase) continue;
        if (wm.firedRules.has(rule.id)) continue;
        if (!rule.conditions(wm)) continue;

        rule.action(wm, scorer);
        wm.firedRules.add(rule.id);
        scorer.checkThresholds(wm);
        progress = true;
      }
    }
  }

  /**
   * Decision order:
   *   0) access_denied — HTTP deny / DNS sinkhole; stop if Access_Denied promotes
   *   1) official — only when trusted_infra; stop if Official promotes
   *   2) brand_independent (Gambling / Pornography / Parking_Site)
   *   3) brand_dependent — skipped when trusted_infra
   *   4) residual Other_Site if still nothing promoted
   *
   * @param {WorkingMemory} wm
   * @param {ClassificationScorer} scorer
   */
  run(wm, scorer) {
    const trusted = wm.hasSignal("trusted_infra");

    // Access denied (HTTP deny status / DNS sinkhole) — before content/abuse
    this.runPhase(wm, scorer, "access_denied");
    if (wm.assertedClassifications.has("Access_Denied")) {
      return;
    }

    // Official phase: only for structurally trusted hosts.
    if (trusted) {
      this.runPhase(wm, scorer, "official");
      if (wm.assertedClassifications.has("Official")) {
        return;
      }
    }

    // Content classes (gambling / adult / parking)
    this.runPhase(wm, scorer, "brand_independent");

    // Brand-dependent abuse: skip on trusted_infra (unlikely brand abuse).
    if (!trusted) {
      this.runPhase(wm, scorer, "brand_dependent");
    }

    // Residual when nothing promoted
    if (wm.assertedClassifications.size === 0) {
      scorer.addScore(
        "Other_Site",
        1.0,
        "residual_fallback",
        "other_site_fallback",
      );
      scorer.checkThresholds(wm);
    }
  }
}

// ---------------------------------------------------------------------------
// Input signal extraction
// ---------------------------------------------------------------------------

/**
 * Seed working memory from factExtractor (sole translation layer for initial facts).
 *
 * @param {WorkingMemory} wm
 * @param {Object} inputs
 * @param {import("./htmlAnalyzer.js").HtmlAnalysis} inputs.htmlAnalysis
 * @param {string} inputs.pageUrl
 * @param {import("./semanticAnalyzer.js").SemanticAnalyzerOutput} inputs.semanticOutput
 * @param {Record<string, unknown> | null} inputs.scanData
 */
function assertInputSignals(
  wm,
  { htmlAnalysis, pageUrl, semanticOutput, scanData },
) {
  const facts = extractInputFacts({
    collectedData: scanData?.collectedData ?? null,
    pageFindings: scanData?.pageFindings ?? null,
    htmlDocument: htmlAnalysis ?? null,
    pageUrl: pageUrl ?? "",
    derivedFacts: semanticOutput?.derivedFacts ?? [],
    expectedCountry: scanData?.brandConfig?.expectedCountry ?? null,
    brandConfig: scanData?.brandConfig ?? null,
    trustStatus: scanData?.trustStatus ?? null,
    httpStatus: scanData?.httpStatus ?? null,
  });
  assertExtractedSignals(wm, facts);
}

// ---------------------------------------------------------------------------
// Output builder
// ---------------------------------------------------------------------------

/**
 * @typedef {Object} KBSResult
 * @property {Signal[]}             signals               - All asserted signals (unified fact+tag)
 * @property {Record<string,number>} classificationScores  - Cumulative score per classification type
 * @property {string[]}             classifiedAs           - Classifications that crossed their threshold
 * @property {string[]}             firedRules             - Rule IDs that fired during inference
 * @property {Record<string, Array<{ delta: number, signalName: string, ruleId: string }>>} scoreBreakdown
 */

/**
 * @param {WorkingMemory} wm
 * @param {ClassificationScorer} scorer
 * @returns {KBSResult}
 */
function buildKBSResult(wm, scorer) {
  return {
    signals: [...wm.signals.values()],
    classificationScores: scorer.getScores(),
    classifiedAs: [...wm.assertedClassifications],
    firedRules: [...wm.firedRules],
    scoreBreakdown: scorer.getScoreBreakdown(),
  };
}

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

/**
 * Run the KBS inference engine.
 *
 * @param {import("./htmlAnalyzer.js").HtmlAnalysis} htmlAnalysis
 * @param {string} pageUrl
 * @param {import("./semanticAnalyzer.js").SemanticAnalyzerOutput} semanticOutput
 * @param {Record<string, unknown> | null} scanData
 * @returns {KBSResult}
 */
export function runKBS(htmlAnalysis, pageUrl, semanticOutput, scanData) {
  const wm = new WorkingMemory();
  const scorer = new ClassificationScorer();

  assertInputSignals(wm, { htmlAnalysis, pageUrl, semanticOutput, scanData });

  const engine = new ForwardChainingEngine(RULES);
  engine.run(wm, scorer);

  return buildKBSResult(wm, scorer);
}
