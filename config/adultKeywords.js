/**
 * Tiered adult / pornography keyword inventory for detectAdultLanguage().
 * Definitive → terminal promote; strong → needs density/buddy; weak → never alone.
 * Do not add minor-related terms.
 */

/** @type {string[]} */
export const DEFINITIVE_ADULT_KEYWORDS = [
  // Longer phrases first so they mask before short tokens
  "xxx videos",
  "xxx video",
  "adult video",
  "porn tube",
  "sex cam",
  "cam girl",
  "pornstar",
  "onlyfans",
  "hentai",
  "porno",
  "nsfw",
  "porn",
];

/** @type {string[]} */
export const STRONG_ADULT_KEYWORDS = [
  "18+ content",
  "explicit video",
  "webcam show",
  "live cam",
  "sex chat",
  "escort",
  "erotic",
  "nude",
  "naked",
];

/** @type {string[]} */
export const WEAK_ADULT_KEYWORDS = [
  "adults only",
  "mature content",
  "dating",
  "18+",
];

/**
 * Non-adult contexts where "adult" / related words must not score.
 * Masked before tier matching (same idea as gambling "Limited Slots").
 */
export const ADULT_CONTEXT_VETOES = [
  "adult supervision",
  "adult education",
  "young adult",
  "adult learner",
  "adult learning",
  "adult daycare",
  "adult day care",
];
