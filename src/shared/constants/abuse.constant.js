/** Canonical abuse/infringement labels for domain classification reports. */
const ABUSE_TYPES = [
  "Phishing",
  "Scam",
  "Impersonation",
  "Fake_Shop",
  "Recruitment_Fraud",
  "Social_Profile_Redirection",
  "Gambling",
  "Pornography",
  "Other_Site",
  "Parking_Site",
  "Redirect_to_Official",
  "Official",
];

const DEFAULT_ABUSE_TYPE = "Other_Site";

/** Short descriptions for LLM prompts — keep keys in sync with ABUSE_TYPES. */
const ABUSE_TYPE_DESCRIPTIONS = {
  Social_Profile_Redirection:
    "Redirect to social profiles (LinkedIn, Facebook, etc.)",
  Phishing: "Credential, financial, or sensitive data harvesting",
  Scam:
    "Brand misuse with financial fraud / payment / investment / support scam",
  Impersonation: "Brand or IP-profile impersonation",
  Fake_Shop: "Fake products / hollow e-commerce using the brand",
  Recruitment_Fraud: "Job-related fraud using brand identity",
  Gambling: "Casino / illegal slots",
  Pornography: "Adult content",
  Other_Site:
    "Friendly / non-infringing (incl. hard interstitial when content cannot be judged)",
  Parking_Site: "For sale, ads, parked",
  Redirect_to_Official: "Redirects to official brand property",
  Official: "Official brand site",
};

/** Legacy label -> current label remap for historical reads. Keys are lowercased. */
const LEGACY_ALIASES = new Map([
  ["other site", "Other_Site"],
  ["fake shop", "Fake_Shop"],
  ["affiliated partnership", "Affiliated_Partnership"],
  ["affiliate partnership", "Affiliated_Partnership"],
  ["authorized dealer", "Affiliated_Partnership"],
  ["licensed reseller", "Affiliated_Partnership"],
  ["recruitment fraud", "Recruitment_Fraud"],
  ["parking site", "Parking_Site"],
  ["cybersquatting", "Impersonation"],
]);

/**
 * @param {unknown} value
 * @returns {typeof ABUSE_TYPES[number]}
 */
function normalizeAbuseType(value) {
  if (typeof value !== "string") {
    return DEFAULT_ABUSE_TYPE;
  }
  const trimmed = value.trim();
  if (ABUSE_TYPES.includes(trimmed)) {
    return trimmed;
  }
  const lower = trimmed.toLowerCase();
  const legacyMatch = LEGACY_ALIASES.get(lower);
  if (legacyMatch) {
    return legacyMatch;
  }
  const caseMatch = ABUSE_TYPES.find((t) => t.toLowerCase() === lower);
  return caseMatch ?? DEFAULT_ABUSE_TYPE;
}

export {
  ABUSE_TYPES,
  ABUSE_TYPE_DESCRIPTIONS,
  DEFAULT_ABUSE_TYPE,
  normalizeAbuseType,
};
