//! Pure, network-free name → identity derivation.
//!
//! Extended NAMINT port:
//!   * **Login permutations** — ~60 handle shapes plus phonetic/nickname alias
//!     variants (`michael` → `mike`/`mick`, `sean` → `shawn`/`shaun`, etc.)
//!     and per-part shapes for hyphenated surnames (`Smith-Jones` → `smith`,
//!     `jones`, `smithjones`).
//!   * **Email permutations** — handle shapes × 38-provider set (global
//!     mass-market, large regional RU/CN/JP, privacy-focused, European ISP)
//!     ranked by `P(handle) × P(provider)`, capped so a name never floods the
//!     graph.
//!   * **Gravatar avatars** — MD5-over-email primitive.
//!   * **Search-query pivots** — 30 platforms: Google dorks (web/face/email/
//!     phone/docs/pastes/public-records), Bing, DuckDuckGo, Yandex, LinkedIn,
//!     Facebook, X, TikTok, GitHub, Reddit, Pinterest, Webmii plus handle-gated
//!     Instagram, WhatsMyName, Snapchat, Twitch, YouTube, Telegram, Reddit
//!     profile, and email-gated Epieos.
//!   * **Suffix / honorific stripping** — Dr., Prof., Mr., Mrs., Jr., Sr.,
//!     III, PhD, MD, Esq. removed before handle derivation.
//!   * **Hyphenated surname** — "Smith-Jones" yields merged and per-part shapes.

use url::form_urlencoded::byte_serialize;

// ── Output caps ──────────────────────────────────────────────────────────────
pub(super) const MAX_USERNAMES: usize = 48;
pub(super) const MAX_EMAILS: usize = 20;
pub(super) const MAX_PIVOTS: usize = 30;

// ── Confidence weights ───────────────────────────────────────────────────────
const W_PRIMARY: f64 = 0.38;
const W_SECONDARY: f64 = 0.30;
const W_MIDDLE: f64 = 0.28;
const W_YEAR: f64 = 0.30;
/// Phonetic / nickname alias substitution — below all structural shapes.
const W_ALIAS: f64 = 0.26;

pub(super) const EMAIL_CONF: f64 = 0.30;
pub(super) const PIVOT_CONF: f64 = 0.20;
pub(super) const SUBJECT_CONF: f64 = 0.60;

// ── Provider set ─────────────────────────────────────────────────────────────
const DEFAULT_DOMAINS: &[&str] = &[
    // Tier 1 — global mass-market
    "gmail.com",
    "outlook.com",
    "hotmail.com",
    "yahoo.com",
    "icloud.com",
    "live.com",
    "aol.com",
    "proton.me",
    // Tier 2 — large regional
    "gmx.com",
    "gmx.net",
    "mail.com",
    "yandex.ru",
    "mail.ru", // Russia / CIS
    "qq.com",
    "163.com",     // China
    "yahoo.co.jp", // Japan
    "yahoo.co.uk",
    "yahoo.com.au",
    "yahoo.ca",
    "yahoo.fr",
    "yahoo.de",
    // Tier 3 — privacy / productivity
    "fastmail.com",
    "protonmail.com",
    "pm.me",
    "tutanota.com",
    "mailfence.com",
    "posteo.de",
    "startmail.com",
    "zoho.com",
    "hey.com",
    // Tier 4 — European ISP / legacy aliases
    "web.de",
    "gmx.de",
    "libero.it",
    "orange.fr",
    "sfr.fr",
    "msn.com",
    "rocketmail.com",
    "ymail.com",
    "googlemail.com",
];

/// Consumer-mailbox share weights. Existing arms are preserved verbatim so
/// that unit-test assertions on exact `f64` values remain stable.
fn provider_weight(domain: &str) -> f64 {
    match domain {
        // ── Existing arms (unchanged) ──────────────────────────────────────
        "gmail.com" | "googlemail.com" => 1.0,
        "outlook.com" | "hotmail.com" | "live.com" | "msn.com" => 0.6,
        "yahoo.com" | "ymail.com" => 0.5,
        "icloud.com" | "me.com" | "mac.com" => 0.45,
        "aol.com" => 0.4,
        "gmx.com" | "gmx.net" | "mail.com" => 0.35,
        "proton.me" | "protonmail.com" | "pm.me" | "tutanota.com" => 0.3,
        // ── Regional (new) ────────────────────────────────────────────────
        "yandex.ru" | "yandex.com" => 0.35,
        "rocketmail.com" => 0.35,
        "mail.ru" => 0.32,
        "yahoo.co.jp" | "yahoo.co.uk" | "yahoo.com.au" | "yahoo.ca" | "yahoo.fr" | "yahoo.de" => {
            0.38
        }
        "qq.com" | "163.com" => 0.28,
        // ── Privacy / productivity (new) ──────────────────────────────────
        "fastmail.com" => 0.32,
        "web.de" | "gmx.de" => 0.32,
        "mailfence.com" | "posteo.de" | "startmail.com" => 0.22,
        "zoho.com" => 0.28,
        "libero.it" => 0.28,
        "orange.fr" | "sfr.fr" | "free.fr" | "laposte.net" => 0.25,
        "hey.com" => 0.20,
        // ── Neutral fallback ──────────────────────────────────────────────
        _ => 0.4,
    }
}

// ── Honorific / suffix tables ─────────────────────────────────────────────────

/// Leading honorifics stripped from the first token before handle derivation.
/// Matched against the clean-token lowercased form (dots already removed by
/// `clean_display_token`).
const HONORIFICS: &[&str] = &[
    "dr", "prof", "mr", "mrs", "ms", "miss", "rev", "sir", "lord", "lady", "capt", "sgt", "lt",
    "det", "insp", "cpl",
];

/// Trailing generational / professional suffixes stripped from the last token.
const GEN_SUFFIXES: &[&str] = &[
    "jr", "sr", "ii", "iii", "iv", "v", "vi", "esq", "phd", "md", "dds", "jd", "mba", "rn", "np",
    "do", "psyd",
];

// ── Phonetic / nickname alias table ──────────────────────────────────────────

/// Maximum aliases used per first name to keep the handle budget bounded.
const MAX_ALIAS_FIRST: usize = 3;

/// Maps canonical (ASCII-folded lowercase) first names to common informal /
/// phonetic alternates. Applied only to `first`; surnames are not aliased.
static NICKNAME_MAP: &[(&str, &[&str])] = &[
    ("alexander", &["alex", "xander", "sasha", "al"]),
    ("alex", &["alexander", "xander"]),
    ("alfred", &["alf", "fred", "alfie"]),
    ("andrew", &["andy", "drew"]),
    ("andy", &["andrew", "drew"]),
    ("anthony", &["tony", "ant"]),
    ("barbara", &["barb", "babs"]),
    ("benjamin", &["ben", "benny", "benji"]),
    ("ben", &["benjamin", "benny"]),
    ("catherine", &["cathy", "cate", "kate", "kat"]),
    ("katherine", &["kathy", "kate", "kat", "cathy"]),
    ("cathy", &["catherine", "katherine"]),
    ("kathy", &["kathleen", "katherine"]),
    ("kate", &["katherine", "catherine", "katy"]),
    ("charles", &["charlie", "chuck", "chas"]),
    ("charlie", &["charles"]),
    ("christopher", &["chris", "kit"]),
    ("chris", &["christopher"]),
    ("daniel", &["dan", "danny"]),
    ("dan", &["daniel", "danny"]),
    ("david", &["dave", "davey"]),
    ("dave", &["david"]),
    ("dorothy", &["dot", "dottie", "dora"]),
    ("edward", &["ed", "eddie", "ned", "ted"]),
    (
        "elizabeth",
        &["liz", "beth", "eliza", "betty", "ellie", "ella"],
    ),
    ("emily", &["em", "emmy"]),
    ("eric", &["erik"]),
    ("erik", &["eric"]),
    ("frederick", &["fred", "freddy", "rick"]),
    ("fred", &["frederick", "freddy"]),
    ("george", &["georgie"]),
    ("harold", &["harry", "hal"]),
    ("harry", &["harold", "hal"]),
    ("henry", &["harry", "hank"]),
    ("james", &["jim", "jimmy", "jamie"]),
    ("jim", &["james", "jimmy"]),
    ("jennifer", &["jen", "jenny"]),
    ("jen", &["jennifer", "jenny"]),
    ("jessica", &["jess", "jessie"]),
    ("jess", &["jessica"]),
    ("john", &["johnny", "jon", "jack"]),
    ("jon", &["john", "jonathan"]),
    ("jonathan", &["jon", "john", "nate"]),
    ("joseph", &["joe", "joey"]),
    ("joe", &["joseph", "joey"]),
    ("joshua", &["josh"]),
    ("josh", &["joshua"]),
    ("kathleen", &["kathy", "kath", "kate"]),
    ("kevin", &["kev"]),
    ("laura", &["laurie", "lori"]),
    ("margaret", &["meg", "maggie", "marge", "peggy"]),
    ("mark", &["marc"]),
    ("marc", &["mark"]),
    ("matthew", &["matt", "matty"]),
    ("matt", &["matthew"]),
    ("michael", &["mike", "mick", "mickey", "mikey"]),
    ("mike", &["michael", "mick"]),
    ("mick", &["michael", "mike"]),
    ("nicholas", &["nick", "nico", "nicky"]),
    ("nick", &["nicholas", "nico"]),
    ("patricia", &["pat", "tricia", "trish", "patty"]),
    ("paul", &["paulie"]),
    ("peter", &["pete", "petey"]),
    ("pete", &["peter"]),
    ("phillip", &["phil"]),
    ("philip", &["phil"]),
    ("phil", &["phillip", "philip"]),
    ("rachel", &["rach"]),
    ("rebecca", &["bec", "becca", "becky"]),
    ("richard", &["rick", "rich", "richie", "ricky"]),
    ("rick", &["richard"]),
    ("robert", &["rob", "bob", "robbie", "bert"]),
    ("rob", &["robert"]),
    ("bob", &["robert"]),
    ("samuel", &["sam", "sammy"]),
    ("sam", &["samuel"]),
    ("sarah", &["sara", "sally"]),
    ("sara", &["sarah"]),
    ("sean", &["shawn", "shaun"]),
    ("shawn", &["sean", "shaun"]),
    ("shaun", &["sean", "shawn"]),
    ("stephen", &["steve", "steven"]),
    ("steven", &["steve", "stephen"]),
    ("steve", &["stephen", "steven"]),
    ("susan", &["sue", "susie", "suzy"]),
    ("sue", &["susan"]),
    ("thomas", &["tom", "tommy"]),
    ("tom", &["thomas", "tommy"]),
    ("timothy", &["tim", "timmy"]),
    ("tim", &["timothy"]),
    ("victoria", &["vicky", "vicki", "tori"]),
    ("william", &["will", "bill", "billy", "liam"]),
    ("will", &["william"]),
    ("bill", &["william"]),
    ("liam", &["william"]),
    ("zachary", &["zach", "zack"]),
    ("zach", &["zachary"]),
];

fn first_aliases(name: &str) -> &'static [&'static str] {
    for &(canonical, aliases) in NICKNAME_MAP {
        if canonical == name {
            return aliases;
        }
    }
    &[]
}

// ── ParsedName ───────────────────────────────────────────────────────────────

/// A parsed personal name plus an optional trailing number (e.g. a birth year).
///
/// `first`/`middle`/`last` are ASCII-folded lowercased handle tokens. `last_parts`
/// holds per-component tokens for hyphenated surnames (e.g. "Smith-Jones" →
/// `["smith", "jones"]`). `display_words` preserves original capitalisation for
/// search-query construction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedName {
    pub first: String,
    pub middle: Option<String>,
    pub last: String,
    /// Non-empty only when the display last name contained a hyphen.
    pub last_parts: Option<Vec<String>>,
    pub number: Option<String>,
    pub display_words: Vec<String>,
}

impl ParsedName {
    /// The full name in natural order with original capitalisation, e.g.
    /// `"Jane Mary Smith"` — the subject string for `"…"`-quoted search pivots.
    pub fn display_full(&self) -> String {
        self.display_words.join(" ")
    }
    /// The first display word (given name), or `""` if somehow empty.
    pub fn display_first(&self) -> &str {
        self.display_words.first().map_or("", String::as_str)
    }
    /// The last display word (surname), or `""` if somehow empty.
    pub fn display_last(&self) -> &str {
        self.display_words.last().map_or("", String::as_str)
    }
    fn display_hyphen(&self) -> String {
        self.display_words.join("-")
    }
    fn plain_handle(&self) -> String {
        format!("{}{}", self.first, self.last)
    }
}

/// A derived handle paired with its base confidence.
pub struct ScoredHandle {
    pub handle: String,
    pub weight: f64,
}

/// A ready-to-click investigation lead.
pub struct Pivot {
    pub platform: &'static str,
    pub url: String,
}

// ── parse() ──────────────────────────────────────────────────────────────────

/// Remove parenthetical / bracketed annotations — nicknames, maiden names, notes
/// — that records and social display names append, e.g. `"William (Bill) Gates"`
/// or `"Jane Smith (Jones)"`. Without this they leak in as spurious name tokens
/// and shift first/middle/last (`"Ali Kareem (Ali)"` parsed to middle="kareem",
/// last="ali"). Nested and mixed `()[]{}` are handled; a stray unmatched closer
/// is ignored. The known-nickname expansion still recovers a canonical first
/// name's aliases, so dropping the annotation costs nothing for the common case.
fn strip_bracketed(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    let mut depth: u32 = 0;
    for c in raw.chars() {
        match c {
            '(' | '[' | '{' => depth += 1,
            ')' | ']' | '}' => depth = depth.saturating_sub(1),
            _ if depth == 0 => out.push(c),
            _ => {}
        }
    }
    out
}

/// Detect the **"Last, First \[Middle…\]"** convention — the bibliographic /
/// records / sorted-list order that electoral rolls, court records, CSV exports
/// and citations emit — and return the display tokens reordered into natural
/// **"First \[Middle…\] Last"** order. Returns `None` (so [`parse`] falls back to
/// a plain split) when the comma is *not* a surname separator:
///   * no comma, or a side that cleans to nothing;
///   * the forename side is only a title — `"Ali Kareem, PhD"`, `"Kareem, Jr"` —
///     where the comma introduces a suffix, not a given name.
///
/// A leading honorific on either side (`"Dr. Kareem, Ali"`, `"Kareem, Dr Ali"`)
/// and any trailing generational/professional suffix on the forename side
/// (`"Kareem, Ali Jr"`) are dropped, mirroring the stripping [`parse`] already
/// applies to the plain form, so only real name tokens drive the reorder.
fn reorder_comma_name(raw: &str) -> Option<Vec<String>> {
    let (surname_side, forename_side) = raw.split_once(',')?;
    let mut surname: Vec<String> = surname_side
        .split_whitespace()
        .filter_map(clean_display_token)
        .collect();
    let mut forename: Vec<String> = forename_side
        .split_whitespace()
        .filter_map(clean_display_token)
        .collect();
    let is_honorific = |t: &str| HONORIFICS.contains(&t.to_ascii_lowercase().as_str());
    let is_suffix = |t: &str| GEN_SUFFIXES.contains(&t.to_ascii_lowercase().as_str());

    if surname.len() >= 2 && surname.first().is_some_and(|t| is_honorific(t)) {
        surname.remove(0);
    }
    if forename.first().is_some_and(|t| is_honorific(t)) {
        forename.remove(0);
    }
    while forename.last().is_some_and(|t| is_suffix(t)) {
        forename.pop();
    }

    // A surname separator only when real name tokens survive on both sides:
    // "Ali Kareem, PhD" collapses the forename side to empty here, leaving the
    // suffix for parse()'s plain-split path to strip.
    if surname.is_empty() || forename.is_empty() {
        return None;
    }
    forename.extend(surname); // First [Middle…] Last
    Some(forename)
}

/// Parse a free-form name string into [`ParsedName`].
///
/// Returns `None` when fewer than two alphabetic tokens survive cleaning. Leading
/// honorifics (Dr., Prof., Mr., …) and trailing generational/professional suffixes
/// (Jr., Sr., III, PhD, …) are stripped so they never appear in handle tokens.
/// An optional 2–4 digit run is captured as `number`.
pub fn parse(raw: &str) -> Option<ParsedName> {
    // A trailing/parenthetical number (a birth year) is still read from the raw
    // string; only the name *tokens* drop bracketed annotations.
    let number = extract_number(raw);
    let cleaned = strip_bracketed(raw);

    // "Last, First" records order is reordered to natural order first; otherwise
    // the comma is just another token separator.
    let mut display_words: Vec<String> = reorder_comma_name(&cleaned).unwrap_or_else(|| {
        cleaned
            .split(|c: char| c.is_whitespace() || c == ',')
            .filter_map(clean_display_token)
            .collect()
    });

    // Strip leading honorific when ≥ 3 words remain (so we keep ≥ 2 after).
    if display_words.len() > 2 {
        let tok = display_words[0].to_ascii_lowercase();
        if HONORIFICS.contains(&tok.as_str()) {
            display_words.remove(0);
        }
    }

    // Strip trailing generational/professional suffix when ≥ 3 words remain.
    if display_words.len() > 2 {
        let tok = display_words
            .last()
            .map(|s| s.to_ascii_lowercase())
            .unwrap_or_default();
        if GEN_SUFFIXES.contains(&tok.as_str()) {
            display_words.pop();
        }
    }

    if display_words.len() < 2 {
        return None;
    }

    let first = sanitize(display_words.first().map_or("", String::as_str));
    let last_display = display_words.last().map_or("", String::as_str);
    let last = sanitize(last_display);
    let middle = if display_words.len() >= 3 {
        let m = sanitize(display_words.get(1).map_or("", String::as_str));
        (!m.is_empty()).then_some(m)
    } else {
        None
    };

    // Hyphenated surname: "Smith-Jones" → last_parts = ["smith", "jones"].
    let last_parts = if last_display.contains('-') {
        let parts: Vec<String> = last_display
            .split('-')
            .map(sanitize)
            .filter(|p| !p.is_empty())
            .collect();
        if parts.len() >= 2 { Some(parts) } else { None }
    } else {
        None
    };

    Some(ParsedName {
        first,
        middle,
        last,
        last_parts,
        number,
        display_words,
    })
}

// ── email_domains() ──────────────────────────────────────────────────────────

/// The provider set used for email permutation.
///
/// Reads `HUNTSMAN_EMAIL_DOMAINS` (comma-separated) as an operator override —
/// each entry is lowercased, `@`-stripped, and kept only if it looks like a
/// domain (`contains('.')`) — falling back to the built-in
/// [`DEFAULT_DOMAINS`] set when the var is unset, blank, or yields no valid
/// entry. So a misconfigured override degrades to the default rather than
/// emitting nothing.
pub fn email_domains() -> Vec<String> {
    match std::env::var("HUNTSMAN_EMAIL_DOMAINS") {
        Ok(v) if !v.trim().is_empty() => {
            let parsed: Vec<String> = v
                .split(',')
                .map(|d| d.trim().trim_start_matches('@').to_ascii_lowercase())
                .filter(|d| d.contains('.') && !d.is_empty())
                .collect();
            if parsed.is_empty() {
                default_domains()
            } else {
                parsed
            }
        }
        _ => default_domains(),
    }
}

fn default_domains() -> Vec<String> {
    DEFAULT_DOMAINS
        .iter()
        .map(std::string::ToString::to_string)
        .collect()
}

// ── usernames() ──────────────────────────────────────────────────────────────

/// Generate scored username permutations, deduplicated and capped at
/// [`MAX_USERNAMES`], ordered best-first.
pub fn usernames(p: &ParsedName) -> Vec<ScoredHandle> {
    if p.first.is_empty() || p.last.is_empty() {
        return Vec::new();
    }
    let f = p.first.as_str();
    let l = p.last.as_str();
    let fi = initial(f);
    let li = initial(l);

    let mut raw: Vec<(String, f64)> = Vec::new();

    // Primary — shapes dominating real-world account handles.
    raw.extend(
        [
            format!("{f}.{l}"),
            format!("{f}{l}"),
            format!("{fi}{l}"),
            format!("{f}_{l}"),
            format!("{f}{li}"),
        ]
        .map(|h| (h, W_PRIMARY)),
    );

    // Secondary — reversed, alternate-joined, and initial-blend variants.
    raw.extend(
        [
            format!("{l}.{f}"),
            format!("{l}{f}"),
            format!("{l}{fi}"),
            format!("{f}.{li}"),
            format!("{l}_{f}"),
            format!("{f}-{l}"),
            format!("{l}-{f}"),
            format!("{fi}.{l}"),
            format!("{l}.{fi}"),
            format!("{fi}_{l}"),
            format!("{fi}-{l}"),
            // Additional real-world shapes not in the original set.
            format!("{l}_{fi}"),  // meyers_j
            format!("{f}_{li}"),  // jordan_m  (distinct from f+li = jordanm)
            format!("{fi}.{li}"), // j.m        (dot-joined initials)
        ]
        .map(|h| (h, W_SECONDARY)),
    );

    // Middle-name blends.
    if let Some(m) = p.middle.as_deref() {
        let mi = initial(m);
        raw.extend(
            [
                format!("{f}{m}{l}"),
                format!("{l}{f}{m}"),
                format!("{f}{mi}{l}"),
                format!("{fi}{mi}{l}"),
                format!("{l}{fi}{mi}"),
                format!("{m}{l}"),
                format!("{l}{m}"),
                m.to_string(),
                format!("{f}.{mi}.{l}"), // first.M.last (formal/corporate)
                format!("{f}_{mi}_{l}"), // first_M_last
            ]
            .map(|h| (h, W_MIDDLE)),
        );
    }

    // Year/number-suffixed shapes (NAMINT appends the number to logins).
    if let Some(n) = p.number.as_deref() {
        let mut suffixed = vec![
            format!("{f}.{l}{n}"),
            format!("{f}{l}{n}"),
            format!("{fi}{l}{n}"),
            format!("{f}{n}"),
            format!("{l}{n}"),
        ];
        if let Some(m) = p.middle.as_deref() {
            suffixed.push(format!("{f}{m}{l}{n}"));
        }
        raw.extend(suffixed.into_iter().map(|h| (h, W_YEAR)));
    }

    // Hyphenated-surname per-part shapes: "Smith-Jones" → shapes with each part.
    if let Some(ref parts) = p.last_parts {
        for part in parts {
            if !part.is_empty() && part != l {
                raw.push((format!("{f}.{part}"), W_SECONDARY));
                raw.push((format!("{f}{part}"), W_SECONDARY));
                raw.push((format!("{fi}{part}"), W_SECONDARY));
            }
        }
    }

    // Phonetic/nickname alias variants for the first name.
    for &alias in first_aliases(f).iter().take(MAX_ALIAS_FIRST) {
        if alias.is_empty() {
            continue;
        }
        let ai = initial(alias);
        raw.extend(
            [
                format!("{alias}.{l}"),
                format!("{alias}{l}"),
                format!("{alias}_{l}"),
                format!("{ai}{l}"),
            ]
            .map(|h| (h, W_ALIAS)),
        );
    }

    dedup_top(raw, MAX_USERNAMES)
}

// ── emails() ─────────────────────────────────────────────────────────────────

/// Generate speculative emails: handle shapes × `domains`, ranked by
/// P(handle) × P(provider), capped at [`MAX_EMAILS`].
pub fn emails(p: &ParsedName, domains: &[String]) -> Vec<String> {
    if p.first.is_empty() || p.last.is_empty() {
        return Vec::new();
    }
    let f = p.first.as_str();
    let l = p.last.as_str();
    let fi = initial(f);
    let li = initial(l);

    let mut logins: Vec<(String, f64)> = vec![
        (format!("{f}.{l}"), 1.00),
        (format!("{f}{l}"), 0.95),
        (format!("{fi}{l}"), 0.70),
        (format!("{f}_{l}"), 0.60),
        (format!("{f}{li}"), 0.45),
        (format!("{l}.{f}"), 0.40),
    ];
    if let Some(m) = p.middle.as_deref() {
        logins.push((format!("{f}{m}{l}"), 0.50));
    }
    if let Some(n) = p.number.as_deref() {
        logins.push((format!("{f}.{l}{n}"), 0.45));
        logins.push((format!("{f}{l}{n}"), 0.42));
    }

    let mut scored: Vec<(f64, String)> = Vec::with_capacity(logins.len() * domains.len());
    let mut seen = std::collections::HashSet::new();
    for (login, hw) in &logins {
        for dom in domains {
            let addr = format!("{login}@{dom}");
            if seen.insert(addr.clone()) {
                scored.push((hw * provider_weight(dom), addr));
            }
        }
    }
    scored.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap_or(std::cmp::Ordering::Equal));
    scored
        .into_iter()
        .take(MAX_EMAILS)
        .map(|(_, addr)| addr)
        .collect()
}

// ── gravatar_url() ────────────────────────────────────────────────────────────

/// The Gravatar avatar URL for `email` — MD5 over the trimmed, lowercased
/// address per the Gravatar spec. `d=404` makes a missing avatar return HTTP
/// 404 (so a probe can tell "no Gravatar" from a default placeholder),
/// requesting a 200px image.
pub fn gravatar_url(email: &str) -> String {
    use md5::{Digest, Md5};
    let mut h = Md5::new();
    h.update(email.trim().to_ascii_lowercase().as_bytes());
    format!(
        "https://www.gravatar.com/avatar/{}?d=404&s=200",
        hex::encode(h.finalize())
    )
}

// ── pivots() ─────────────────────────────────────────────────────────────────

/// Build the ordered set of search-query / people-search pivots, capped at
/// [`MAX_PIVOTS`]. `top_email` unlocks the Epieos pivot.
pub fn pivots(p: &ParsedName, top_email: Option<&str>) -> Vec<Pivot> {
    let name = p.display_full();
    let qn = q(&format!("\"{name}\""));
    let first = q(p.display_first());
    let last = q(p.display_last());
    let handle = p.plain_handle();
    let has_handle = !handle.is_empty();
    let fb = q(&p.display_hyphen());
    let qname = q(&name);

    let mut out: Vec<Pivot> = vec![
        pv(
            "Google — web",
            format!("https://www.google.com/search?q={qn}"),
        ),
        pv(
            "Google — face images",
            format!("https://www.google.com/search?q={qn}&tbm=isch&tbs=itp:face"),
        ),
        pv(
            "Google — email exposure",
            format!(
                "https://www.google.com/search?q={}",
                q(&format!("\"{name}\" (email OR contact OR \"@\")"))
            ),
        ),
        pv(
            "Google — phone exposure",
            format!(
                "https://www.google.com/search?q={}",
                q(&format!("\"{name}\" (phone OR mobile OR tel OR contact)"))
            ),
        ),
        pv(
            "Google — documents",
            format!(
                "https://www.google.com/search?q={}",
                q(&format!(
                    "\"{name}\" filetype:pdf OR filetype:docx OR filetype:xlsx"
                ))
            ),
        ),
        pv(
            "Google — pastes",
            format!(
                "https://www.google.com/search?q={}",
                q(&format!("\"{name}\" site:pastebin.com OR site:throwbin.io"))
            ),
        ),
        pv(
            "Google — public records",
            format!(
                "https://www.google.com/search?q={}",
                q(&format!(
                    "\"{name}\" (address OR \"date of birth\" OR court OR arrest OR obituary)"
                ))
            ),
        ),
        pv("Bing — web", format!("https://www.bing.com/search?q={qn}")),
        pv(
            "DuckDuckGo — web",
            format!("https://duckduckgo.com/?q={qn}"),
        ),
        pv(
            "Yandex — face images",
            format!("https://yandex.com/images/search?text={qn}&type=face"),
        ),
        pv(
            "LinkedIn — people",
            format!("https://www.linkedin.com/pub/dir?firstName={first}&lastName={last}"),
        ),
        pv(
            "Facebook — public",
            format!("https://www.facebook.com/public/{fb}"),
        ),
        pv(
            "X / Twitter — people",
            format!("https://x.com/search?q={qn}&f=user"),
        ),
        pv(
            "TikTok — people",
            format!("https://www.tiktok.com/search/user?q={qname}"),
        ),
        pv(
            "GitHub — users",
            format!("https://github.com/search?q={}&type=users", q(&name)),
        ),
        pv(
            "Reddit — user search",
            format!("https://www.reddit.com/search/?q={qn}&type=user"),
        ),
        pv(
            "Pinterest — people",
            format!("https://www.pinterest.com/search/users/?q={qname}"),
        ),
        pv(
            "Webmii — people",
            format!("https://webmii.com/people?n={}", q(&name)),
        ),
    ];

    if has_handle {
        out.push(pv(
            "Instagram — handle",
            format!("https://www.instagram.com/{handle}/"),
        ));
        out.push(pv(
            "WhatsMyName — username",
            format!("https://whatsmyname.app/?q={handle}"),
        ));
        out.push(pv(
            "Reddit — profile",
            format!("https://www.reddit.com/user/{handle}"),
        ));
        out.push(pv(
            "Snapchat — profile",
            format!("https://www.snapchat.com/add/{handle}"),
        ));
        out.push(pv(
            "Twitch — channel",
            format!("https://www.twitch.tv/{handle}"),
        ));
        out.push(pv(
            "YouTube — handle",
            format!("https://www.youtube.com/@{handle}"),
        ));
        out.push(pv("Telegram — username", format!("https://t.me/{handle}")));
    }

    if let Some(email) = top_email {
        out.push(pv(
            "Epieos — email lookup",
            format!("https://epieos.com/?q={}", q(email)),
        ));
    }

    out.truncate(MAX_PIVOTS);
    out
}

// ── Internal helpers ──────────────────────────────────────────────────────────

fn pv(platform: &'static str, url: String) -> Pivot {
    Pivot { platform, url }
}

fn initial(s: &str) -> char {
    s.chars().next().unwrap_or('x')
}

fn q(s: &str) -> String {
    byte_serialize(s.as_bytes()).collect()
}

fn extract_number(raw: &str) -> Option<String> {
    let mut runs: Vec<String> = Vec::new();
    let mut run = String::new();
    for c in raw.chars() {
        if c.is_ascii_digit() {
            run.push(c);
        } else {
            if (2..=4).contains(&run.len()) {
                runs.push(std::mem::take(&mut run));
            }
            run.clear();
        }
    }
    if (2..=4).contains(&run.len()) {
        runs.push(run);
    }
    runs.iter()
        .find(|r| r.len() == 4)
        .or_else(|| runs.first())
        .cloned()
}

fn clean_display_token(tok: &str) -> Option<String> {
    let kept: String = tok
        .chars()
        .filter(|c| c.is_alphabetic() || *c == '-' || *c == '\'')
        .collect();
    let kept = kept.trim_matches(|c| c == '-' || c == '\'').to_string();
    if kept.is_empty() {
        None
    } else {
        Some(titlecase(&kept))
    }
}

fn titlecase(s: &str) -> String {
    let mut chars = s.chars();
    match chars.next() {
        Some(first) => first.to_uppercase().collect::<String>() + chars.as_str(),
        None => String::new(),
    }
}

fn sanitize(s: &str) -> String {
    crate::util::str_util::fold_ascii_lower(s)
}

fn dedup_top(raw: Vec<(String, f64)>, cap: usize) -> Vec<ScoredHandle> {
    use std::collections::HashMap;
    let mut best: HashMap<String, f64> = HashMap::new();
    for (h, w) in raw {
        if h.is_empty() {
            continue;
        }
        best.entry(h)
            .and_modify(|cur| {
                if w > *cur {
                    *cur = w;
                }
            })
            .or_insert(w);
    }
    let mut v: Vec<ScoredHandle> = best
        .into_iter()
        .map(|(handle, weight)| ScoredHandle { handle, weight })
        .collect();
    v.sort_by(|a, b| {
        b.weight
            .partial_cmp(&a.weight)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| a.handle.cmp(&b.handle))
    });
    v.truncate(cap);
    v
}

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
