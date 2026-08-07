/**
 * Knowledge-Based System — forward-chaining engine for domain threat classification.
 *
 * All evidence is unified under a single Signal concept (no separate facts/tags).
 * Rules fire when their conditions are met; each rule can contribute score deltas
 * to multiple classifications simultaneously. Classifications promote themselves
 * independently when their cumulative score crosses a threshold.
 *
 * Decision order (see RULES preamble + ForwardChainingEngine.run):
 *   0) official (only when trusted_infra) — brand org identity → Official
 *   1) brand_independent content (Gambling / Pornography / Parking_Site)
 *   2) brand_dependent threats — skipped when trusted_infra
 *   3) residual Other_Site when nothing else promoted
 *
 * Do not gate on brand_name_present (text): the brand may appear only in images/logos.
 */

import { extractInputFacts, assertExtractedSignals } from "../facts/factExtractor.js";

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
 * Opens the impersonation gate (candidacy).
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
 * Fake_Shop checklist scorers: storefront context present and not scam_exempt.
 * @param {WorkingMemory} wm
 * @returns {boolean}
 */
function isFakeShopScorable(wm) {
  return (
    wm.hasSignal("shop_storefront_context") && !wm.hasSignal("scam_exempt")
  );
}

/**
 * Scam hook or disposable-infra cue — gates Scam deltas from hollow trust priors.
 * @param {WorkingMemory} wm
 * @returns {boolean}
 */
function hasScamHookOrEvasion(wm) {
  return (
    wm.hasSignal("advance_fee_hook") ||
    wm.hasSignal("fraudulent_investment_hook") ||
    wm.hasSignal("identity_fee_hook") ||
    wm.hasSignal("hollow_business_lure") ||
    wm.hasSignal("scam_evasion_infrastructure") ||
    wm.hasSignal("is_newly_registered") ||
    wm.hasSignal("young_domain") ||
    wm.hasSignal("is_short_term_registration") ||
    wm.hasSignal("has_hidden_registrant")
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
 * Scam terminal scorers may fire only when the host is not structurally trusted.
 * Mirrors isImpersonationScorable: hooks/evasion may still assert, but addScore is suppressed
 * when scam_exempt is present (aged domain or enterprise TLS).
 *
 * @param {WorkingMemory} wm
 * @returns {boolean}
 */
function isScamScorable(wm) {
  return !wm.hasSignal("scam_exempt");
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
  //   Phase brand_independent — Gambling / Pornography / Parking_Site
  //   Phase brand_dependent — skipped when trusted_infra
  //   Residual Other_Site if still nothing promoted
  // ===========================================================================

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
  // Input facts:
  //   semantic_adult_content_language_detected — adultContentScore phrases
  //   semantic_gambling_language_detected      — gamblingScore phrases
  //   gambling_phrases_present                 — HTML keyword scan (utility.js)
  // ---------------------------------------------------------------------------

  // ---------------------------------------------------------------------------
  // Adult / pornographic language — Prior / terminal (single-signal path)
  // Intent: promote Pornography when explicit adult content language is detected.
  // IF: semantic_adult_content_language_detected
  // THEN: Pornography +0.7 (alone crosses threshold 0.6)
  // Why: for a passive scrape, phrase embeddings are the main adult-content cue;
  //      no structural exemption needed (OV/aged adult sites are still adult content).
  // ---------------------------------------------------------------------------
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
      ); // TODO: tune weight — high 0.7
    },
  },

  // ---------------------------------------------------------------------------
  // Gambling language / phrases — Prior / terminal
  // Intent: promote Gambling when keyword scan OR semantic gambling language fires.
  // IF: gambling_phrases_present OR semantic_gambling_language_detected
  // THEN: Gambling +0.7 (alone crosses threshold 0.6)
  // Why: regex catches obvious casino vocabulary even when embeddings miss;
  //      semantic path covers paraphrases. No scam_exempt (legal casinos still Gambling).
  // ---------------------------------------------------------------------------
  {
    id: "gambling_content_language",
    phase: "brand_independent",
    group: "content",
    conditions: (wm) =>
      wm.hasSignal("gambling_phrases_present") ||
      wm.hasSignal("semantic_gambling_language_detected"),
    action: (wm, scorer) => {
      // Prefer evidence name based on which signal is present (first match wins for reporting)
      const signalName = wm.hasSignal("gambling_phrases_present")
        ? "gambling_phrases_present"
        : "semantic_gambling_language_detected";
      scorer.addScore("Gambling", 0.7, signalName, "gambling_content_language"); // TODO: tune weight — high 0.7
    },
  },

  // ---------------------------------------------------------------------------
  // Group: "structural"
  // Signals about page structure and parking / for-sale landers.
  // Contributes to Parking_Site (threshold 0.4). NS/IP are strong promoters,
  // not terminal hard-confirms (shared registrar infra can host live sites).
  // ---------------------------------------------------------------------------

  // ---------------------------------------------------------------------------
  // Group: "structural"
  // Signals about page structure and parking / for-sale landers.
  // Contributes to Parking_Site (threshold 0.4). NS/IP are strong promoters,
  // not terminal hard-confirms (shared registrar infra can host live sites).
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
          "Parking / for-sale keywords present — parking evaluation enabled",
        ],
      });
    },
  },

  {
    // Strong NS promote; alone with keywords does not cross 0.4
    id: "parking_infra_ns",
    phase: "brand_independent",
    group: "structural",
    conditions: (wm) =>
      isParkingScorable(wm) &&
      wm.hasSignal("parking_keywords_present") &&
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
    // Stronger IP promote; keywords+IP crosses threshold (IP more specific than NS)
    id: "parking_infra_ip",
    phase: "brand_independent",
    group: "structural",
    conditions: (wm) =>
      isParkingScorable(wm) &&
      wm.hasSignal("parking_keywords_present") &&
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
    id: "parking_keyword_listing",
    phase: "brand_independent",
    group: "structural",
    conditions: (wm) =>
      isParkingScorable(wm) &&
      wm.hasSignal("parking_keywords_present") &&
      (wm.hasSignal("semantic_parking_language_detected") ||
        wm.hasSignal("semantic_transaction_language_detected")),
    action: (wm, scorer) => {
      const signalName = wm.hasSignal("semantic_parking_language_detected")
        ? "semantic_parking_language_detected"
        : "semantic_transaction_language_detected";
      scorer.addScore(
        "Parking_Site",
        0.25,
        signalName,
        "parking_keyword_listing",
      ); // TODO: tune weight
    },
  },

  {
    id: "parking_keyword_no_email",
    phase: "brand_independent",
    group: "structural",
    conditions: (wm) =>
      isParkingScorable(wm) &&
      wm.hasSignal("parking_keywords_present") &&
      wm.hasSignal("no_email_infrastructure"),
    action: (_wm, scorer) => {
      scorer.addScore(
        "Parking_Site",
        0.2,
        "no_email_infrastructure",
        "parking_keyword_no_email",
      ); // TODO: tune weight
    },
  },

  {
    id: "parking_semantic_listing",
    phase: "brand_independent",
    group: "structural",
    conditions: (wm) =>
      isParkingScorable(wm) &&
      wm.hasSignal("semantic_parking_language_detected") &&
      wm.hasSignal("semantic_transaction_language_detected"),
    action: (_wm, scorer) => {
      scorer.addScore(
        "Parking_Site",
        0.2,
        "semantic_parking_language_detected",
        "parking_semantic_listing",
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
    // hasBrandClaim (text, logo, or markup) opens impersonation scoring.
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
  // Signals about credential/OTP harvesting mechanics.
  // Contributes heavily to Phishing; partially to Scam.
  // ---------------------------------------------------------------------------

  // ---------------------------------------------------------------------------
  // Group: "phishing"
  // Signals about credential/OTP harvesting mechanics.
  // Contributes heavily to Phishing; partially to Scam.
  //
  // Examples to implement:
  //   credential_capture              — password input field present
  //   otp_capture                     — OTP / verification code input present
  //   external_form_submission        — form POSTs to a different domain
  //   coercive_urgency                — language pressuring immediate action
  //   disabled_credential_autocomplete — autocomplete="off" on password field
  //   account_verification_language   — semantic fact for account verify flow
  // ---------------------------------------------------------------------------
  //credential capture
  {
    id: "credential_capture",
    phase: "brand_dependent",
    group: "phishing",
    conditions: (wm) =>
      wm.hasSignal("has_password_input") ||
      wm.hasSignal("has_otp_input") ||
      wm.hasSignal("has_username_input") ||
      wm.hasSignal("has_email_input") ||
      wm.hasSignal("has_financial_input") ||
      wm.hasSignal("semantic_credential_login_language_detected") ||
      wm.hasSignal("semantic_credential_capture_language_detected"),
    action: (_wm, scorer) => {
      scorer.addScore(
        "Phishing",
        0.4,
        "credential_capture",
        "credential_capture",
      ); // TODO: tune weight
    },
  },
  //disabled autocomplete
  {
    id: "disabled_autocomplete",
    phase: "brand_dependent",
    group: "phishing",
    conditions: (wm) =>
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
    conditions: (wm) => wm.hasSignal("external_form_submission"),
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
      wm.hasSignal("semantic_account_verification_language_detected") ||
      wm.hasSignal("semantic_credential_capture_language_detected"),
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
  // Group: "scam"
  // Anatomy of a scam site (phases):
  //   Exemption — trust structural history over semantic lure (scam_exempt)
  //   Lure      — emotion/greed/hope language (semantic_* facts)
  //   Hook      — extraction mechanism (fees, financial inputs, identity harvest)
  //   Illusion  — thin legitimacy (missing/inert trust nav; free TLS not used as a hard condition)
  //   Evasion   — anonymity / disposable infra (hidden WHOIS, new/short-term, bulletproof)
  //   Terminal  — hook + evasion, gated by isScamScorable → Scam / Recruitment_Fraud scores
  // Intermediate hooks assert signals only; terminals alone cross classification thresholds.
  // ---------------------------------------------------------------------------

  // ---------------------------------------------------------------------------
  // Group: "scam"
  // Anatomy of a scam site (phases):
  //   Exemption — trust structural history over semantic lure (scam_exempt)
  //   Lure      — emotion/greed/hope language (semantic_* facts)
  //   Hook      — extraction mechanism (fees, financial inputs, identity harvest)
  //   Illusion  — thin legitimacy (missing/inert trust nav; free TLS not used as a hard condition)
  //   Evasion   — anonymity / disposable infra (hidden WHOIS, new/short-term, bulletproof)
  //   Terminal  — hook + evasion, gated by isScamScorable → Scam / Recruitment_Fraud scores
  // Intermediate hooks assert signals only; terminals alone cross classification thresholds.
  // ---------------------------------------------------------------------------

  // ---------------------------------------------------------------------------
  // Legitimate business exemption — Exemption
  // Intent: kill FPs on real brokers/agencies that match investment or job language.
  // IF: domain age > ~5 years OR OV/EV TLS
  // THEN: assert scam_exempt (no score) — terminal scam scorers will not fire
  // Why: scammers rarely afford aged domains or corporate-validated certificates;
  //      Fidelity / Robert Half will trigger semantic flags but pass this gate.
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

  // ---------------------------------------------------------------------------
  // Advance-fee hook (signal-only) — Lure + Hook
  // Intent: detect job/reward offers that demand an upfront fee or deposit.
  // IF: recruitment OR reward/grant language
  // AND: recruitment-fee OR fee-collection language
  // THEN: assert advance_fee_hook (no score — needs evasion + !scam_exempt to classify)
  // Why: alone this FPs on real agencies; terminal rules apply infrastructure check.
  // ---------------------------------------------------------------------------
  {
    id: "advance_fee_hook",
    phase: "brand_dependent",
    group: "scam",
    conditions: (wm) =>
      (wm.hasSignal("semantic_recruitment_language_detected") ||
        wm.hasSignal("semantic_reward_or_grant_scam_language_detected")) &&
      (wm.hasSignal("semantic_recruitment_fee_language_detected") ||
        wm.hasSignal("semantic_fee_collection_language_detected")),
    action: (wm) => {
      wm.assertSignal("advance_fee_hook", {
        group: "scam",
        strength: 1,
        value: true,
        evidence: [
          "Job/reward lure combined with upfront fee or deposit language — classic advance-fee pattern",
        ],
      });
    },
  },

  // ---------------------------------------------------------------------------
  // Fraudulent investment hook (signal-only) — Lure + Hook
  // Intent: detect high-yield / scam investment copy with an urgent fund-capture UI.
  // IF: investment-scam OR aggregate scam language
  // AND: financial/payment input present
  // AND: urgency language present
  // THEN: assert fraudulent_investment_hook (no score until evasion + !scam_exempt)
  // Why: legitimate brokers also say “invest”; urgency + card/bank fields on weak infra is the tell.
  // ---------------------------------------------------------------------------
  {
    id: "fraudulent_investment_hook",
    phase: "brand_dependent",
    group: "scam",
    conditions: (wm) =>
      (wm.hasSignal("semantic_investment_scam_language_detected") ||
        wm.hasSignal("semantic_scam_language_detected")) &&
      wm.hasSignal("has_financial_input") &&
      wm.hasSignal("semantic_urgency_language_detected"),
    action: (wm) => {
      wm.assertSignal("fraudulent_investment_hook", {
        group: "scam",
        strength: 1,
        value: true,
        evidence: [
          "Investment/scam language with financial capture fields and urgency — fraudulent investment lure",
        ],
      });
    },
  },

  // ---------------------------------------------------------------------------
  // Scam evasion infrastructure (signal-only) — Evasion
  // Intent: mark hosts that hide identity and use disposable/abuse-tolerant infra.
  // IF: WHOIS registrant is privacy-shielded
  // AND: newly registered OR short-term registration OR bulletproof hosting
  // THEN: assert scam_evasion_infrastructure (no score by itself)
  // Why: real firms can use privacy WHOIS, but rarely combined with newborn/short-term/bulletproof.
  // ---------------------------------------------------------------------------
  {
    id: "scam_evasion_infrastructure",
    phase: "brand_dependent",
    group: "scam",
    conditions: (wm) =>
      wm.hasSignal("has_hidden_registrant") &&
      (wm.hasSignal("is_newly_registered") ||
        wm.hasSignal("is_hosted_on_bulletproof") ||
        wm.hasSignal("is_short_term_registration")),
    action: (wm) => {
      wm.assertSignal("scam_evasion_infrastructure", {
        group: "scam",
        strength: 1,
        value: true,
        evidence: [
          "Hidden registrant plus newly registered, short-term registration, or bulletproof hosting — anonymity / disposable infrastructure",
        ],
      });
    },
  },

  // ---------------------------------------------------------------------------
  // Identity-fee hook (signal-only) — Hook
  // Intent: catch “activation fee” variants that harvest ID without job-offer copy.
  // IF: identity / passport / national-ID input present
  // AND: fee-collection OR recruitment-fee language
  // THEN: assert identity_fee_hook (no score until evasion + !scam_exempt)
  // Why: reduces FNs where lure is weak but ID + fee demand is explicit.
  // ---------------------------------------------------------------------------
  {
    id: "identity_fee_hook",
    phase: "brand_dependent",
    group: "scam",
    conditions: (wm) =>
      wm.hasSignal("has_identity_input") &&
      (wm.hasSignal("semantic_fee_collection_language_detected") ||
        wm.hasSignal("semantic_recruitment_fee_language_detected")),
    action: (wm) => {
      wm.assertSignal("identity_fee_hook", {
        group: "scam",
        strength: 1,
        value: true,
        evidence: [
          "Identity document capture combined with fee/deposit language — activation-fee / ID-harvest pattern",
        ],
      });
    },
  },

  // ---------------------------------------------------------------------------
  // Hollow business lure (signal-only) — Lure + Illusion of a real business
  // Intent: flag “company” lures that lack basic email infrastructure on a young domain.
  // IF: investment OR recruitment OR reward/grant language
  // AND: no MX / email capability
  // AND: newly registered OR young domain
  // THEN: assert hollow_business_lure (no score until trust-nav failure + !scam_exempt)
  // Why: a claimed business without mail on a newborn domain is a strong FN-reduction cue.
  // ---------------------------------------------------------------------------
  {
    id: "hollow_business_lure",
    phase: "brand_dependent",
    group: "scam",
    conditions: (wm) =>
      (wm.hasSignal("semantic_investment_scam_language_detected") ||
        wm.hasSignal("semantic_recruitment_language_detected") ||
        wm.hasSignal("semantic_reward_or_grant_scam_language_detected")) &&
      wm.hasSignal("no_email_capability") &&
      (wm.hasSignal("is_newly_registered") || wm.hasSignal("young_domain")),
    action: (wm) => {
      wm.assertSignal("hollow_business_lure", {
        group: "scam",
        strength: 1,
        value: true,
        evidence: [
          "Investment/job/reward lure on a young domain with no email (MX) capability — hollow business front",
        ],
      });
    },
  },

  // ---------------------------------------------------------------------------
  // High-confidence task / employment scam — Terminal
  // Intent: promote Scam (+ Recruitment_Fraud) when advance-fee hook meets evasion infra.
  // IF: advance_fee_hook AND scam_evasion_infrastructure AND isScamScorable
  // THEN: assert task_employment_scam; Scam +0.75 (high), Recruitment_Fraud +0.6
  // Why: lure+fee alone FPs; adding anonymity/disposable infra is high confidence.
  // ---------------------------------------------------------------------------
  {
    id: "high_confidence_task_scam",
    phase: "brand_dependent",
    group: "scam",
    conditions: (wm) =>
      isScamScorable(wm) &&
      wm.hasSignal("advance_fee_hook") &&
      wm.hasSignal("scam_evasion_infrastructure"),
    action: (wm, scorer) => {
      wm.assertSignal("task_employment_scam", {
        group: "scam",
        strength: 1,
        value: true,
        evidence: [
          "Advance-fee job/reward hook on evasion infrastructure without legitimate-business exemption",
        ],
      });
      scorer.addScore(
        "Scam",
        0.75,
        "task_employment_scam",
        "high_confidence_task_scam",
      ); // TODO: tune weight — high 0.75
      scorer.addScore(
        "Recruitment_Fraud",
        0.6,
        "task_employment_scam",
        "high_confidence_task_scam",
      ); // TODO: tune weight
    },
  },

  // ---------------------------------------------------------------------------
  // High-confidence investment scam — Terminal
  // Intent: promote Scam when fraudulent investment hook meets evasion infra.
  // IF: fraudulent_investment_hook AND scam_evasion_infrastructure AND isScamScorable
  // THEN: assert investment_scam; Scam +0.75 (high)
  // Why: urgency + financial capture on anonymous/new infra is the classic crypto/yield scam.
  // ---------------------------------------------------------------------------
  {
    id: "high_confidence_investment_scam",
    phase: "brand_dependent",
    group: "scam",
    conditions: (wm) =>
      isScamScorable(wm) &&
      wm.hasSignal("fraudulent_investment_hook") &&
      wm.hasSignal("scam_evasion_infrastructure"),
    action: (wm, scorer) => {
      wm.assertSignal("investment_scam", {
        group: "scam",
        strength: 1,
        value: true,
        evidence: [
          "Fraudulent investment hook on evasion infrastructure without legitimate-business exemption",
        ],
      });
      scorer.addScore(
        "Scam",
        0.75,
        "investment_scam",
        "high_confidence_investment_scam",
      ); // TODO: tune weight — high 0.75
    },
  },

  // ---------------------------------------------------------------------------
  // Medium-confidence tech-support extortion — Terminal
  // Intent: catch support-payment scams that lack form inputs (call-now / pay-to-unlock).
  // IF: support-payment scam language AND missing trust navigation
  // AND: scam_evasion_infrastructure AND isScamScorable
  // THEN: assert tech_support_scam; Scam +0.55 (medium — may also stack with trust_nav_missing)
  // Why: these pages are structurally empty; language + missing trust + evasion substitutes for inputs.
  // ---------------------------------------------------------------------------
  {
    id: "medium_confidence_tech_support_scam",
    phase: "brand_dependent",
    group: "scam",
    conditions: (wm) =>
      isScamScorable(wm) &&
      wm.hasSignal("semantic_support_payment_scam_language_detected") &&
      wm.hasSignal("missing_trust_navigation") &&
      wm.hasSignal("scam_evasion_infrastructure"),
    action: (wm, scorer) => {
      wm.assertSignal("tech_support_scam", {
        group: "scam",
        strength: 1,
        value: true,
        evidence: [
          "Tech-support payment language with missing trust navigation on evasion infrastructure",
        ],
      });
      scorer.addScore(
        "Scam",
        0.55,
        "tech_support_scam",
        "medium_confidence_tech_support_scam",
      ); // TODO: tune weight — medium 0.55
    },
  },

  // ---------------------------------------------------------------------------
  // High-confidence identity-fee scam — Terminal
  // Intent: promote Scam when ID harvest + fee demand sits on evasion infra.
  // IF: identity_fee_hook AND scam_evasion_infrastructure AND isScamScorable
  // THEN: assert identity_fee_scam; Scam +0.7 (high)
  // Why: closes FN gap for activation-fee pages without recruitment lure wording.
  // ---------------------------------------------------------------------------
  {
    id: "high_confidence_identity_fee_scam",
    phase: "brand_dependent",
    group: "scam",
    conditions: (wm) =>
      isScamScorable(wm) &&
      wm.hasSignal("identity_fee_hook") &&
      wm.hasSignal("scam_evasion_infrastructure"),
    action: (wm, scorer) => {
      wm.assertSignal("identity_fee_scam", {
        group: "scam",
        strength: 1,
        value: true,
        evidence: [
          "Identity capture plus fee language on evasion infrastructure without legitimate-business exemption",
        ],
      });
      scorer.addScore(
        "Scam",
        0.7,
        "identity_fee_scam",
        "high_confidence_identity_fee_scam",
      ); // TODO: tune weight — high 0.7
    },
  },

  // ---------------------------------------------------------------------------
  // Medium-confidence hollow-lure scam — Terminal
  // Intent: promote Scam when a hollow business lure also lacks working trust navigation.
  // IF: hollow_business_lure AND (missing OR inert trust nav) AND isScamScorable
  // THEN: assert hollow_lure_scam; Scam +0.55 (medium)
  // Why: no-MX young domain + broken/absent trust pages is medium confidence without full evasion stack.
  // ---------------------------------------------------------------------------
  {
    id: "medium_confidence_hollow_lure_scam",
    phase: "brand_dependent",
    group: "scam",
    conditions: (wm) =>
      isScamScorable(wm) &&
      wm.hasSignal("hollow_business_lure") &&
      (wm.hasSignal("missing_trust_navigation") ||
        wm.hasSignal("inert_trust_navigation")),
    action: (wm, scorer) => {
      wm.assertSignal("hollow_lure_scam", {
        group: "scam",
        strength: 1,
        value: true,
        evidence: [
          "Hollow business lure with missing or inert trust navigation and no legitimate-business exemption",
        ],
      });
      scorer.addScore(
        "Scam",
        0.55,
        "hollow_lure_scam",
        "medium_confidence_hollow_lure_scam",
      ); // TODO: tune weight — medium 0.55
    },
  },

  // ---------------------------------------------------------------------------
  // Group: "fake_shop"
  // Anatomy of a fake shopfront:
  //   Context   — shop_storefront_context (schema / prices / shop-or-checkout language)
  //   Checklist — additive risk cues gated by isFakeShopScorable
  //               (storefront context AND !scam_exempt)
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
      wm.hasSignal("semantic_ecommerce_language_detected") ||
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
    conditions: (wm) =>
      isFakeShopScorable(wm) &&
      (wm.hasSignal("missing_trust_navigation") ||
        wm.hasSignal("inert_trust_navigation") ||
        wm.hasSignal("error_trust_navigation")),
    action: (wm, scorer) => {
      const signalName = wm.hasSignal("missing_trust_navigation")
        ? "missing_trust_navigation"
        : wm.hasSignal("inert_trust_navigation")
          ? "inert_trust_navigation"
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
  // Anatomy of recruitment fraud (phases):
  //   Intermediates — advance-fee trap, PII harvest, hollow brand portal (signal-only)
  //   Prior         — weak Recruitment_Fraud score from job language alone
  //   Terminals     — gated by isScamScorable (reuse scam_exempt; no separate recruitment_exempt)
  // Threshold: Recruitment_Fraud promotes at cumulative score >= 0.5
  // ---------------------------------------------------------------------------

  // ---------------------------------------------------------------------------
  // Group: "recruitment"
  // Anatomy of recruitment fraud (phases):
  //   Intermediates — advance-fee trap, PII harvest, hollow brand portal (signal-only)
  //   Prior         — weak Recruitment_Fraud score from job language alone
  //   Terminals     — gated by isScamScorable (reuse scam_exempt; no separate recruitment_exempt)
  // Threshold: Recruitment_Fraud promotes at cumulative score >= 0.5
  // Related scam-group rules (advance_fee_hook, high_confidence_task_scam) still contribute
  // Scam + Recruitment_Fraud when full evasion infrastructure is present — complementary.
  // ---------------------------------------------------------------------------

  // ---------------------------------------------------------------------------
  // Advance-fee recruitment trap (signal-only) — Intermediate
  // Intent: job offer language combined with upfront fee / payment capture.
  // IF: recruitment language
  // AND: recruitment-fee OR fee-collection language OR financial input fields
  // THEN: assert advance_fee_recruitment_trap (no score — terminal scores Recruitment_Fraud)
  // Why: legitimate ATS rarely charges candidates; financial_input catches deposit UIs
  //      without fee *copy*. Distinct from scam advance_fee_hook (which also allows reward lure).
  // ---------------------------------------------------------------------------
  {
    id: "advance_fee_recruitment_trap",
    phase: "brand_dependent",
    group: "recruitment",
    conditions: (wm) =>
      wm.hasSignal("semantic_recruitment_language_detected") &&
      (wm.hasSignal("semantic_recruitment_fee_language_detected") ||
        wm.hasSignal("semantic_fee_collection_language_detected") ||
        wm.hasSignal("has_financial_input")),
    action: (wm) => {
      wm.assertSignal("advance_fee_recruitment_trap", {
        group: "recruitment",
        strength: 1,
        value: true,
        evidence: [
          "Job/recruitment language combined with fee demand or financial capture fields",
        ],
      });
    },
  },

  // ---------------------------------------------------------------------------
  // Excessive identity harvesting (signal-only) — Intermediate
  // Intent: unverified career pages that demand government ID or uploads on young domains.
  // IF: recruitment language
  // AND: identity input OR file upload
  // AND: newly registered OR young domain OR short-term registration
  // THEN: assert excessive_identity_harvesting (no score until terminal)
  // Why: drop free/automated TLS (ubiquitous LE FPs); age is the durable infrastructure cue.
  // ---------------------------------------------------------------------------
  {
    id: "excessive_identity_harvesting",
    phase: "brand_dependent",
    group: "recruitment",
    conditions: (wm) =>
      wm.hasSignal("semantic_recruitment_language_detected") &&
      (wm.hasSignal("has_identity_input") || wm.hasSignal("has_file_upload")) &&
      (wm.hasSignal("is_newly_registered") ||
        wm.hasSignal("young_domain") ||
        wm.hasSignal("is_short_term_registration")),
    action: (wm) => {
      wm.assertSignal("excessive_identity_harvesting", {
        group: "recruitment",
        strength: 1,
        value: true,
        evidence: [
          "Recruitment language with identity/file capture on a newly registered, young, or short-term domain",
        ],
      });
    },
  },

  // ---------------------------------------------------------------------------
  // Hollow recruiter portal (signal-only) — Intermediate
  // Intent: brand-spoofed career page lacking corporate mail or working trust links.
  // IF: recruitment language
  // AND: brand name on page or detected logo
  // AND: no MX OR missing trust nav OR inert trust nav
  // THEN: assert hollow_recruiter_portal (no score until combined with a trap)
  // Why: brand alone is commentary; hollow infra is the tell for impersonated careers pages.
  // ---------------------------------------------------------------------------
  {
    id: "hollow_recruiter_portal",
    phase: "brand_dependent",
    group: "recruitment",
    conditions: (wm) =>
      wm.hasSignal("semantic_recruitment_language_detected") &&
      hasStrongBrandClaim(wm) &&
      (wm.hasSignal("no_email_capability") ||
        wm.hasSignal("missing_trust_navigation") ||
        wm.hasSignal("inert_trust_navigation")),
    action: (wm) => {
      wm.assertSignal("hollow_recruiter_portal", {
        group: "recruitment",
        strength: 1,
        value: true,
        evidence: [
          "Brand-associated recruitment page off official domain with no email capability or broken/missing trust navigation",
        ],
      });
    },
  },

  // ---------------------------------------------------------------------------
  // Recruitment language prior — Prior
  // Intent: weak score when job/career language is present.
  // IF: semantic_recruitment_language_detected
  // THEN: Recruitment_Fraud +0.2 (alone cannot cross 0.5)
  // Why: many legitimate career pages match phrases; terminals/exemption do the heavy lifting.
  // ---------------------------------------------------------------------------
  {
    id: "recruitment_language_prior",
    phase: "brand_dependent",
    group: "recruitment",
    conditions: (wm) => wm.hasSignal("semantic_recruitment_language_detected"),
    action: (_wm, scorer) => {
      scorer.addScore(
        "Recruitment_Fraud",
        0.2,
        "semantic_recruitment_language_detected",
        "recruitment_language_prior",
      ); // TODO: tune weight — prior 0.2
    },
  },

  // ---------------------------------------------------------------------------
  // High-confidence advance-fee recruitment fraud — Terminal
  // Intent: promote Recruitment_Fraud when fee trap sits on disposable/anonymous infra.
  // IF: advance_fee_recruitment_trap
  // AND: newly registered OR young domain OR hidden registrant
  // AND: isScamScorable (!scam_exempt)
  // THEN: assert recruitment_advance_fee_fraud; Recruitment_Fraud +0.65 (high)
  // Why: looser than scam_evasion_infrastructure (any one age/privacy cue) to catch FNs.
  // ---------------------------------------------------------------------------
  {
    id: "high_confidence_advance_fee_recruitment",
    phase: "brand_dependent",
    group: "recruitment",
    conditions: (wm) =>
      isScamScorable(wm) &&
      wm.hasSignal("advance_fee_recruitment_trap") &&
      (wm.hasSignal("is_newly_registered") ||
        wm.hasSignal("young_domain") ||
        wm.hasSignal("has_hidden_registrant")),
    action: (wm, scorer) => {
      wm.assertSignal("recruitment_advance_fee_fraud", {
        group: "recruitment",
        strength: 1,
        value: true,
        evidence: [
          "Advance-fee recruitment trap on a young, newly registered, or privacy-shielded domain without legitimate-business exemption",
        ],
      });
      scorer.addScore(
        "Recruitment_Fraud",
        0.65,
        "recruitment_advance_fee_fraud",
        "high_confidence_advance_fee_recruitment",
      ); // TODO: tune weight — high 0.65
    },
  },

  // ---------------------------------------------------------------------------
  // High-confidence recruitment PII harvest — Terminal
  // Intent: promote Recruitment_Fraud for ID/resume harvest on young off-official hosts.
  // IF: excessive_identity_harvesting AND isScamScorable
  // THEN: assert recruitment_pii_harvest; Recruitment_Fraud +0.6 (high)
  // Why: no fee language required — covers “upload passport to apply” identity-theft portals.
  // ---------------------------------------------------------------------------
  {
    id: "high_confidence_recruitment_pii",
    phase: "brand_dependent",
    group: "recruitment",
    conditions: (wm) =>
      isScamScorable(wm) && wm.hasSignal("excessive_identity_harvesting"),
    action: (wm, scorer) => {
      wm.assertSignal("recruitment_pii_harvest", {
        group: "recruitment",
        strength: 1,
        value: true,
        evidence: [
          "Excessive identity/file harvesting on a recruitment page without legitimate-business exemption",
        ],
      });
      scorer.addScore(
        "Recruitment_Fraud",
        0.6,
        "recruitment_pii_harvest",
        "high_confidence_recruitment_pii",
      ); // TODO: tune weight — high 0.6
    },
  },

  // ---------------------------------------------------------------------------
  // High-confidence brand recruitment impersonation — Terminal
  // Intent: brand-hollow career portal plus a fee or PII trap.
  // IF: hollow_recruiter_portal
  // AND: advance_fee_recruitment_trap OR excessive_identity_harvesting
  // AND: isScamScorable
  // THEN: assert recruitment_brand_impersonation; Recruitment_Fraud +0.7, Impersonation +0.35
  // Why: brand mention alone never promotes; requires hollow infra plus an extraction trap.
  // ---------------------------------------------------------------------------
  {
    id: "high_confidence_brand_recruitment_impersonation",
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
        "Recruitment_Fraud",
        0.7,
        "recruitment_brand_impersonation",
        "high_confidence_brand_recruitment_impersonation",
      ); // TODO: tune weight — high 0.7
      scorer.addScore(
        "Impersonation",
        0.35,
        "recruitment_brand_impersonation",
        "high_confidence_brand_recruitment_impersonation",
      ); // TODO: tune weight
    },
  },

  // ---------------------------------------------------------------------------
  // Group: "trust"
  // Hollow-site cues (missing/broken trust nav, copyright, dead links).
  // Impersonation deltas require isImpersonationScorable (brand on page + not exempt).
  // Fake_Shop / Scam deltas require shop or scam context — alone they do not promote threats.
  // ---------------------------------------------------------------------------

  // ---------------------------------------------------------------------------

  // ---------------------------------------------------------------------------
  // Group: "trust"
  // Signals about the presence, functionality, and reachability of trust links
  // (privacy, policy, terms, help, security, support, services, contact).
  //
  // Each rule contributes to multiple classification types because missing or
  // broken trust navigation is a cross-cutting indicator of deceptive sites.
  // Weights are intentionally left as placeholders — tune after evaluation.
  // ---------------------------------------------------------------------------

  {
    id: "trust_nav_missing",
    phase: "brand_dependent",
    group: "trust",
    conditions: (wm) => wm.hasSignal("missing_trust_navigation"),
    action: (wm, scorer) => {
      // Hollow cue only — score each class when matching context exists.
      if (isScamScorable(wm) && hasScamHookOrEvasion(wm)) {
        scorer.addScore(
          "Scam",
          0.3,
          "missing_trust_navigation",
          "trust_nav_missing",
        ); // TODO: tune weight
      }
      if (isImpersonationScorable(wm)) {
        scorer.addScore(
          "Impersonation",
          0.25,
          "missing_trust_navigation",
          "trust_nav_missing",
        ); // TODO: tune weight
      }
      if (hasCredentialCaptureCue(wm) || isImpersonationScorable(wm)) {
        scorer.addScore(
          "Phishing",
          0.2,
          "missing_trust_navigation",
          "trust_nav_missing",
        ); // TODO: tune weight
      }
      // Fake_Shop hollow trust scored once via fake_shop_trust_hollow
      if (wm.hasSignal("semantic_recruitment_language_detected")) {
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
    id: "trust_nav_inert",
    phase: "brand_dependent",
    group: "trust",
    conditions: (wm) => wm.hasSignal("inert_trust_navigation"),
    action: (wm, scorer) => {
      if (isScamScorable(wm) && hasScamHookOrEvasion(wm)) {
        scorer.addScore(
          "Scam",
          0.25,
          "inert_trust_navigation",
          "trust_nav_inert",
        ); // TODO: tune weight
      }
      if (isImpersonationScorable(wm)) {
        scorer.addScore(
          "Impersonation",
          0.2,
          "inert_trust_navigation",
          "trust_nav_inert",
        ); // TODO: tune weight
      }
      if (hasCredentialCaptureCue(wm) || isImpersonationScorable(wm)) {
        scorer.addScore(
          "Phishing",
          0.15,
          "inert_trust_navigation",
          "trust_nav_inert",
        ); // TODO: tune weight
      }
      // Fake_Shop hollow trust scored once via fake_shop_trust_hollow
      if (wm.hasSignal("semantic_recruitment_language_detected")) {
        scorer.addScore(
          "Recruitment_Fraud",
          0.1,
          "inert_trust_navigation",
          "trust_nav_inert",
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
      if (isScamScorable(wm) && hasScamHookOrEvasion(wm)) {
        scorer.addScore(
          "Scam",
          0.25,
          "error_trust_navigation",
          "trust_nav_error",
        ); // TODO: tune weight
      }
      if (isImpersonationScorable(wm)) {
        scorer.addScore(
          "Impersonation",
          0.2,
          "error_trust_navigation",
          "trust_nav_error",
        ); // TODO: tune weight
      }
      if (hasCredentialCaptureCue(wm) || isImpersonationScorable(wm)) {
        scorer.addScore(
          "Phishing",
          0.15,
          "error_trust_navigation",
          "trust_nav_error",
        ); // TODO: tune weight
      }
      // Fake_Shop hollow trust scored once via fake_shop_trust_hollow
      if (wm.hasSignal("semantic_recruitment_language_detected")) {
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
    // Cross-domain redirect on a trust link is stronger for impersonation when brand is claimed.
    id: "trust_nav_redirect",
    phase: "brand_dependent",
    group: "trust",
    conditions: (wm) => wm.hasSignal("redirect_trust_navigation"),
    action: (wm, scorer) => {
      if (isScamScorable(wm) && hasScamHookOrEvasion(wm)) {
        scorer.addScore(
          "Scam",
          0.15,
          "redirect_trust_navigation",
          "trust_nav_redirect",
        ); // TODO: tune weight
      }
      if (isImpersonationScorable(wm)) {
        scorer.addScore(
          "Impersonation",
          0.2,
          "redirect_trust_navigation",
          "trust_nav_redirect",
        ); // TODO: tune weight
      }
      if (hasCredentialCaptureCue(wm) || isImpersonationScorable(wm)) {
        scorer.addScore(
          "Phishing",
          0.15,
          "redirect_trust_navigation",
          "trust_nav_redirect",
        ); // TODO: tune weight
      }
      if (wm.hasSignal("semantic_recruitment_language_detected")) {
        scorer.addScore(
          "Recruitment_Fraud",
          0.1,
          "redirect_trust_navigation",
          "trust_nav_redirect",
        ); // TODO: tune weight
      }
    },
  },

  // ---------------------------------------------------------------------------
  // Missing copyright — seeded by hasCopyright via factExtractor.
  // Soft hollow-site prior: many throwaway impersonation pages omit footer legal.
  // ---------------------------------------------------------------------------
  {
    id: "missing_copyright_prior",
    phase: "brand_dependent",
    group: "trust",
    // Soft hollow cue — never promotes alone; requires brand/shop/scam context.
    conditions: (wm) => wm.hasSignal("missing_copyright"),
    action: (wm, scorer) => {
      if (isScamScorable(wm) && hasScamHookOrEvasion(wm)) {
        scorer.addScore(
          "Scam",
          0.15,
          "missing_copyright",
          "missing_copyright_prior",
        ); // TODO: tune weight
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

  // ---------------------------------------------------------------------------
  // Excessive dead links — seeded by analyzeLinkHealth via factExtractor.
  // Per-anchor broken ratio ≥50% (placeholders + hard/soft/network failures).
  // Cross-cutting hollow-site cue: Fake_Shop / Impersonation / Scam stack.
  // ---------------------------------------------------------------------------
  {
    id: "excessive_dead_links_prior",
    phase: "brand_dependent",
    group: "trust",
    // Hollow cue — gate Impersonation/Scam/Fake_Shop/Phishing by context.
    conditions: (wm) => wm.hasSignal("excessive_dead_links"),
    action: (wm, scorer) => {
      if (isScamScorable(wm) && hasScamHookOrEvasion(wm)) {
        scorer.addScore(
          "Scam",
          0.3,
          "excessive_dead_links",
          "excessive_dead_links_prior",
        ); // TODO: tune weight
      }
      if (isImpersonationScorable(wm)) {
        scorer.addScore(
          "Impersonation",
          0.25,
          "excessive_dead_links",
          "excessive_dead_links_prior",
        ); // TODO: tune weight
      }
      if (hasCredentialCaptureCue(wm) || isImpersonationScorable(wm)) {
        scorer.addScore(
          "Phishing",
          0.15,
          "excessive_dead_links",
          "excessive_dead_links_prior",
        ); // TODO: tune weight
      }
    },
  },

  // ---------------------------------------------------------------------------
  // Conversion destination dead — many CTAs share one unreachable checkout URL.
  // Classic hollow reseller / fake-shop pattern (e.g. wspp.my soft/hard 404).
  // ---------------------------------------------------------------------------
  {
    id: "conversion_destination_dead_prior",
    phase: "brand_dependent",
    group: "trust",
    // Hollow reseller pattern — Fake_Shop covered by checklist (trust_hollow / young / discount).
    conditions: (wm) => wm.hasSignal("conversion_destination_dead"),
    action: (wm, scorer) => {
      if (isScamScorable(wm) && hasScamHookOrEvasion(wm)) {
        scorer.addScore(
          "Scam",
          0.25,
          "conversion_destination_dead",
          "conversion_destination_dead_prior",
        ); // TODO: tune weight
      }
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
   *   0) official — only when trusted_infra; stop if Official promotes
   *   1) brand_independent (Gambling / Pornography / Parking_Site)
   *   2) brand_dependent — skipped when trusted_infra
   *   3) residual Other_Site if still nothing promoted
   *
   * @param {WorkingMemory} wm
   * @param {ClassificationScorer} scorer
   */
  run(wm, scorer) {
    const trusted = wm.hasSignal("trusted_infra");

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
