/**
 * Reference phrase libraries for semantic threat classification.
 *
 * Each named array contains representative phrases for a single threat concept.
 * PHRASE_LIBRARIES maps concept score keys (as used in SemanticAnalyzerOutput)
 * to their phrase arrays — this is the only place to add, edit, or remove phrases.
 */

export const ACCOUNT_VERIFICATION_PHRASES = [
  "verify your account",
  "confirm your identity",
  "your account has been suspended",
  "your account will be closed",
  "security check required",
  "unusual login activity detected",
  "sign in to continue",
  "update your account information",
  "account verification required",
  "verify your email address",
  "confirm your account details",
  "your account has been locked",
  "authenticate your account",
  "complete account verification",
];

export const CREDENTIAL_LOGIN_PHRASES = [
  "enter your username and password",
  "sign in with your email and password",
  "log in to your account",
  "continue to login",
  "access your account",
  "member login",
  "customer login",
  "enter your credentials",
  "username and password",
  "sign in to continue",
  "login with your account",
  "enter email and password",
];

export const PASSWORD_RESET_PHRASES = [
  "reset your password",
  "change your password",
  "recover your account",
  "forgot password",
  "create a new password",
  "password recovery",
  "reset password link",
  "enter your new password",
  "password reset request",
  "update your password",
  "set a new password",
];

export const OTP_PHRASES = [
  "Enter verification code",
  "Enter your OTP",
  "Verify your OTP",
  "Enter one-time password",
  "Enter authentication code",
  "Enter security code",
  "Enter the code",
  "Input verification code",
  "Submit verification code",
  "Confirm verification code",
  "Verify your identity",
  "Code sent to phone",
  "Code sent via SMS",
  "Check your messages",
  "Resend verification code",
];

export const SHOPPING_PHRASES = [
  // Hero Banners & Seasonal Announcements
  "shop our latest collection",
  "shop new arrivals now",
  "explore our best sellers",
  "limited time storewide sale",
  "shop new season styles",
  "clearance sale shop now",

  // Homepage Value Propositions & Trust Bars
  "free shipping all orders",
  "free returns on orders",
  "easy thirty day returns",
  "twenty four seven support",
  "secure online checkout guaranteed",

  // Featured Product Rails & Grid Headers
  "trending products this week",
  "featured collections shop now",
  "shop deals of week",
  "top rated customer favorites",
  "shop customer favorite picks",
  "save on featured items",
  "discover featured store brands",

  // Category & Navigation CTAs
  "shop by category now",
  "shop all categories now",
  "exclusive online store deals",

  // Newsletter Lead Gen & Rewards (Popups / Top Bars)
  "sign up get discount",
  "subscribe for store updates",
  "join store rewards program",
  "get special promo offers",

  // Store Utilities & Footer Highlights
  "buy online pick up",
  "shop our gift cards",
  "find a store location",
  "track your order online",
  "customer support help center",
];

export const CHECKOUT_PHRASES = [
  "proceed to checkout",
  "checkout securely",
  "complete your order",
  "shipping address",
  "billing address",
  "payment method",
  "order summary",
  "place order",
  "review your order",
  "confirm your order",
  "enter shipping details",
  "select delivery option",
  "apply coupon code",
];

export const PAYMENT_PHRASES = [
  "enter your card details",
  "credit card payment",
  "bank transfer",
  "payment confirmation",
  "pay now",
  "complete payment",
  "submit payment",
  "payment instructions",
  "card number",
  "expiry date",
  "CVV code",
  "billing information",
  "secure payment",
  "payment gateway",
];

export const RECRUITMENT_PHRASES = [
  // Job Search & Filters (Candidate Side)
  "search open job positions",
  "find your next role",
  "search jobs by location",
  "search jobs by category",
  "search remote job openings",
  "browse current job vacancies",
  "explore open career opportunities",
  "browse jobs by industry",
  "browse positions by department",
  "featured job opportunities today",

  // Candidate Actions & Application UI
  "upload your resume today",
  "upload CV or resume",
  "submit your job application",
  "create a job alert",
  "quick apply with linkedin",
  "save this job posting",
  "view all open positions",
  "join our talent network",
  "view open career vacancies",
  "connect with top employers",

  // Employment Types & Compensation Tools
  "full time employment opportunities",
  "part time job openings",
  "internship and entry level",
  "salary ranges for jobs",
  "competitive salary and benefits",

  // Employer & Hiring Manager Tools
  "post a job opening",
  "hire top talent today",
  "post job listings online",
  "search candidate resume database",
  "employer hiring solutions dashboard",
];

export const RECRUITMENT_FEE_PHRASES = [
  "pay a training fee",
  "pay a processing fee for your application",
  "visa processing fee",
  "work permit fee",
  "send payment before interview",
  "onboarding fee",
  "recruitment fee",
  "background check fee",
  "application processing payment",
  "document processing fee",
  "registration fee before joining",
  "security deposit required for employment",
  "Earn commission for every investor you recruit",
  "Invite more members to increase your earnings",
  "Build a team and earn passive income",
  "Recruit investors to unlock higher returns",
  "Guaranteed income from every referral",
  "Upgrade your package to earn more commission",
  "Purchase an investment package to start earning",
  "Earn daily returns from your membership package",
];

export const INVESTMENT_SCAM_PHRASES = [
  // High-Yield & Guaranteed Promises (The Biggest Red Flags)
  "guaranteed return on investment",
  "zero risk high reward",
  "earn daily passive income",
  "hundred percent guaranteed profits",
  "secure daily interest payouts",
  "massive returns on investment",
  "guaranteed weekly cash payouts",
  "completely risk free opportunity",

  // Automation & "Secret" Systems
  "fully automated trading bot",
  "AI driven trading algorithm",
  "exclusive insider trading secrets",
  "secret wealth building system",
  "game changing investment technology",
  "proven risk free strategy",

  // Ease of Use & Low Barrier to Entry
  "no trading experience needed",
  "start earning money today",
  "make thousands from home",
  "minimum deposit maximum returns",
  "financial freedom made easy",

  // Trust, Operations & Affiliates (Often stolen from legit sites)
  "withdraw your profits instantly",
  "regulated and licensed platform",
  "no hidden fees ever",
  "trusted by expert investors",
  "invite friends earn commission",
  "offshore tax free investments",

  // Crypto & Fast Wealth Overtones
  "double your crypto fast",
  "multiply your assets quickly",
  "consistent daily profit margins",
  "join our elite investors",
  "unlimited daily earning potential",
];

export const FEE_COLLECTION_PHRASES = [
  "pay a processing fee",
  "activation fee required",
  "release fee",
  "clearance fee",
  "administrative fee",
  "pay before receiving funds",
  "unlock your funds",
  "claim fee",
  "transfer fee required",
  "insurance fee to release funds",
  "payment to receive your money",
  "pay to unlock your reward",
];

export const SUPPORT_PAYMENT_SCAM_PHRASES = [
  "contact support agent on WhatsApp",
  "pay support fee",
  "technical support payment",
  "remote support fee",
  "account recovery fee",
  "agent will assist payment",
  "support payment required",
  "pay to speak to an agent",
  "contact us to resolve your issue for a fee",
  "chat with support to recover account",
  "support team payment request",
];

export const REWARD_GRANT_SCAM_PHRASES = [
  // Fake Government Grants & Relief (Highly specific to scams)
  "approved for government grant",
  "claim unclaimed hardship funds",
  "federal relief grant approved",
  "guaranteed government cash subsidy",
  "claim your stimulus payout",
  "free government relief money",

  // Fake Sweepstakes & Unsolicited Prizes
  "randomly selected for payout",
  "selected as lucky winner",
  "congratulations you won cash",
  "claim exclusive prize money",
  "claim your lottery winnings",
  "spin to claim prize",
  "immediate cash prize payout",
  "unlock your mystery prize",
  "special cash gift waiting",
  "claim uncollected cash prize",

  // Fake Compensation & Beneficiary Scams (The "Nigerian Prince" evolution)
  "unclaimed beneficiary fund ready",
  "claim your compensation fund",
  "victim compensation fund approved",
  "your pending refund available",
  "withdraw your pending funds",

  // High-Urgency Phishing Hooks (Used to steal banking details)
  "claim reward before expiration",
  "action required claim cash",
  "confirm details to claim",
  "verify identity to withdraw",
  "transfer pending to account",
  "account credited pending verification",
  "claim guaranteed cash payout",
  "approve your withdrawal request",
  "secure your financial payout",
];

export const GAMBLING_PHRASES = [
  // Core Sportsbook & Betting
  "live sports betting odds",
  "in-play sports betting",
  "bet on live sports",
  "best sports betting odds",
  "online sportsbook sign bonus",
  "sportsbook welcome bonus offer",
  "sportsbook promo code offer",
  "sportsbook deposit match bonus",

  // Bet Types & Mechanics
  "moneyline sports betting odds",
  "point spread betting odds",
  "over under sports bets",
  "handicap sports betting odds",
  "parlay sports bet builder",
  "sports bet accumulator parlay",
  "cash out sports bet",
  "sports betting free bets",
  "prop bets sports odds",
  "free sports betting picks",

  // Specific Sports & Leagues
  "betting on football matches",
  "premier league betting odds",
  "soccer match betting odds",
  "FIFA World Cup betting",
  "basketball point spread bets",
  "live tennis match betting",
  "ufc live round betting",

  // Racing & Digital Sports
  "horse racing betting odds",
  "esports betting",
  "esports live match betting",
  "virtual sports betting action",
  "live dealer sportsbook casino",

  // Slots & Jackpots
  "play online slot machines",
  "progressive jackpot slot game",
  "free spins deposit bonus",
  "megaways video slots online",

  // Blackjack & Baccarat
  "real money live blackjack",
  "play blackjack online dealer",
  "baccarat table games online",
  "dragon tiger casino game",

  // Poker & Card Games
  "texas holdem poker tournament",
  "omaha poker real money",
  "three card poker table",
  "pai gow poker online",
  "video poker jackpot games",
  "caribbean stud poker table",

  // Roulette & Dice
  "european roulette wheel bets",
  "american roulette live dealer",
  "craps online dice game",
  "sic bo online casino",

  // Specialty, Lottery & Arcade
  "online keno numbers draw",
  "bingo room cash prizes",
  "online scratch cards instant",
  "wheel of fortune casino",
  "plinko online gambling game",
  "crash gambling game multiplier",

  // General & Live Casino
  "live dealer casino games",
  "no deposit casino bonus",
];

export const ADULT_CONTENT_PHRASES = [
  // Age Verification & Compliance
  "18 plus age verification",
  "restricted to adults only",
  "warning adult explicit content",
  "enter adult content site",
  "must be legal age",

  // Video & Streaming Terminology
  "full length adult video",
  "free adult video streaming",
  "hd adult video clip",
  "watch adult video online",
  "free adult movie stream",
  "uncensored adult video stream",
  "high definition adult streaming",

  // Site Navigation & Categories
  "top rated adult videos",
  "popular adult video categories",
  "trending adult content creators",
  "adult tube video search",
  "daily updated adult gallery",
  "exclusive adult content channel",

  // Live Cam & Interactive Features
  "live adult cam chat",
  "free live webcam show",
  "private adult cam room",
  "interactive adult live stream",
  "virtual adult entertainment show",

  // Membership & Network Footprints
  "adult site premium membership",
  "join adult content network",
  "unlimited adult video downloads",
  "verified adult content creator",

  // Promotional & Affiliate Signals
  "adult dating chat hookup",
  "meet local adult singles",
  "adult affiliate network offer",
];

export const PARKING_PHRASES = [
  // Direct Sales & Offers
  "this domain is for sale",
  "buy this domain name",
  "make an offer now",
  "inquire about this domain",
  "domain name for sale",

  // Registration & Registrar Defaults
  "this domain is registered",
  "parked free courtesy of",
  "register your domain today",
  "domain registered with godaddy",
  "domain is temporarily parked",

  // Under Construction & Placeholders
  "welcome to the homepage",
  "site is under construction",
  "pending future website development",
  "looking for this domain",
  "domain may be available",

  // Domain Brokering & Acquisition
  "contact the domain owner",
  "submit domain inquiry form",
  "domain broker service team",
  "see estimated domain value",
  "domain name acquisition inquiry",

  // Transactions & Escrow
  "get this domain today",
  "lease to own options",
  "buy now pay later",
  "secure escrow transaction process",
  "start lease to own",

  // Ad-Monetized Parking Pages
  "related searches and links",
  "search related domain names",
  "check domain availability now",
  "buy now for instant",
  "domain parked with bodis",
];

export const BRAND_OFFICIAL_TONE_PHRASES = [
  "official website",
  "official customer support",
  "secure account center",
  "help center",
  "privacy policy",
  "terms and conditions",
  "copyright all rights reserved",
  "customer service portal",
  "account center",
  "contact official support",
  "our official page",
  "verified account",
  "trusted by millions",
  "secure and protected",
];

export const URGENCY_PHRASES = [
  // Fake Tech Support & Virus Alerts (Often hidden in full-screen overlays)
  "virus detected act immediately",
  "device infected scan now",
  "critical security alert warning",
  "computer locked call immediately",
  "do not close page",
  "system alert act immediately",
  "hacker detected act immediately",
  "prevent data loss now",

  // Account Takeover & Phishing Threats
  "account suspended verify now",
  "prevent permanent account deletion",
  "verify identity immediately now",
  "login to prevent closure",
  "unauthorized login attempt detected",
  "update payment method immediately",
  "account locked action required",
  "confirm before account closure",
  "urgent message regarding account",
  "act now before deletion",

  // High-Pressure Action Triggers
  "immediate action required now",
  "failure to act immediately",
  "final warning act now",
  "critical system update required",
  "urgent system notification alert",

  // Crypto, Wallet, & Fake Transfer Deadlines
  "offer expires in seconds",
  "claim before time expires",
  "claim before timer ends",
  "last chance to claim",
  "pending transfer expires soon",
  "withdraw your funds immediately",
  "wallet connection expires soon",
];

/**
 * Maps concept score keys (used in SemanticAnalyzerOutput.scores) to their phrase arrays.
 * Edit phrase arrays above; reference them here.
 */
export const PHRASE_LIBRARIES = {
  accountVerificationScore: ACCOUNT_VERIFICATION_PHRASES,
  credentialLoginScore: CREDENTIAL_LOGIN_PHRASES,
  passwordResetScore: PASSWORD_RESET_PHRASES,
  otpVerificationScore: OTP_PHRASES,
  shoppingScore: SHOPPING_PHRASES,
  checkoutScore: CHECKOUT_PHRASES,
  paymentScore: PAYMENT_PHRASES,
  recruitmentScore: RECRUITMENT_PHRASES,
  recruitmentFeeScore: RECRUITMENT_FEE_PHRASES,
  investmentScamScore: INVESTMENT_SCAM_PHRASES,
  feeCollectionScore: FEE_COLLECTION_PHRASES,
  supportPaymentScamScore: SUPPORT_PAYMENT_SCAM_PHRASES,
  rewardOrGrantScamScore: REWARD_GRANT_SCAM_PHRASES,
  gamblingScore: GAMBLING_PHRASES,
  adultContentScore: ADULT_CONTENT_PHRASES,
  parkingScore: PARKING_PHRASES,
  brandOfficialToneScore: BRAND_OFFICIAL_TONE_PHRASES,
  urgencyScore: URGENCY_PHRASES,
};
