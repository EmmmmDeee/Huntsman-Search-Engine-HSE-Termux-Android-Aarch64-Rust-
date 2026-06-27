//! Breach-source → sector classification.
//!
//! Works *backwards from the real data*. Two source-DB naming conventions show
//! up in the pools HSE queries:
//!
//!   * **snusbase / see-know**: a structured token,
//!     `<id>_<NAME>_<TLD>_<SIZE>_<CATEGORY>_<MMYYYY>` — e.g.
//!     `0645_ZYNGA_COM_202M_GAMING_092019`, `1769_AITYPE_COM_75M_TECH_122017`
//!     (both real values from the "Ali Kareem" combined-search dump). The
//!     **category is embedded** as the second-from-last segment when the last is
//!     a date, so it can be read straight out.
//!   * **oathnet**: a bare site/domain — e.g. `pureincubation.com` (a B2B data
//!     broker, *not* real estate — the classifier must correctly decline it).
//!
//! [`source_sector`] returns a normalised sector slug for a source DB name, or
//! `None` when it can't be placed. Shared by every breach/stealer pool so a hit
//! can be filtered by sector — the answer to "show me only the breached
//! **real-estate** data" is `sector:real-estate`, a tag, not a separate feed.

/// Real-estate / property brands, portals, CRMs and conveyancing platforms
/// (Australian emphasis, with the major international portals). Substring-matched
/// against the lower-cased source, so `realestate.com.au`, `PropertyTree` and a
/// `…_REALESTATE_…` token all resolve. Kept specific enough that a non-property
/// source can't trip it (no bare `domain`, no bare `rent`).
const REAL_ESTATE: &[&str] = &[
    "realestate",
    "realty",
    "realtor",
    "property",
    "rentberry",
    "1form",
    "flatmates",
    "propertytree",
    "harcourts",
    "ljhooker",
    "raywhite",
    "century21",
    "raineandhorne",
    "onthehouse",
    "homely",
    "allhomes",
    "domain.com.au",
    "pexa",
    "corelogic",
    "rpdata",
    "pricefinder",
    "zillow",
    "redfin",
    "trulia",
    "conveyanc",
];

/// Known breach **brands / source domains** → sector, keyed by a distinctive
/// lower-case token. The needle is matched against the source's `[a-z0-9]+`
/// segments (so `neopets.com`, a structured `…_NEOPETS_…` token and a bare
/// `neopets` tag all resolve) rather than by substring — a needle can never
/// bleed across an unrelated token (`game` won't trip `gamestop`).
///
/// Seeded by working *backwards from the real corpus* HSE surfaces: the live
/// "Ali Kareem" graph is dominated by **gaming** sources whose bare domain
/// names (`neopets.com`, `dlh.net`, `zynga`) carry no embedded category, so the
/// structured-token reader alone left them — and the whole sector signal — at
/// `None`. Every entry is a verifiable industry fact about a real, high-frequency
/// breach source, never a guess; ambiguous or sub-4-char tokens are omitted so a
/// mapping can only ever add a correct tag.
const KNOWN_SOURCE_SECTORS: &[(&str, &str)] = &[
    // Gaming — the bulk of the real corpus (and the global breach long tail).
    ("zynga", "gaming"),
    ("neopets", "gaming"),
    ("tunngle", "gaming"),
    ("revora", "gaming"),
    ("joygames", "gaming"),
    ("gamesprite", "gaming"),
    ("xpgamesaves", "gaming"),
    ("r2games", "gaming"),
    ("gogames", "gaming"),
    ("freegame2017", "gaming"),
    ("xbox", "gaming"),
    ("playstation", "gaming"),
    ("roblox", "gaming"),
    ("minecraft", "gaming"),
    ("epicgames", "gaming"),
    ("steam", "gaming"), // dlh.net etc. aggregate Steam data (real corpus)
    ("dlh", "gaming"),   // dlh.net — gaming news/cheats site (real corpus)
    ("riot", "gaming"),  // Riot Games (League of Legends)
    ("blizzard", "gaming"),
    ("gametop", "gaming"),
    ("gamefaqs", "gaming"),
    ("nexusmods", "gaming"),
    ("twitch", "media"), // also streaming; gaming community angle but sector=media fits better
    // Social / forums / dating (structured_category folds dating→social).
    ("tumblr", "social"),
    ("twitter", "social"),
    ("myspace", "social"),
    ("disqus", "social"),
    ("younow", "social"),
    ("imesh", "social"),
    ("badoo", "social"),
    ("mate1", "social"),
    ("ipmart", "social"),
    ("facebook", "social"),
    ("instagram", "social"),
    ("reddit", "social"),
    ("discord", "social"),
    ("snapchat", "social"),
    ("tinder", "social"),
    ("bumble", "social"),
    ("hinge", "social"),
    ("grindr", "social"),
    ("meetme", "social"),
    ("tagged", "social"),
    ("wattpad", "social"),
    ("quora", "social"),
    // Tech / professional / SaaS / developer.
    ("linkedin", "tech"),
    ("adobe", "tech"),
    ("canva", "tech"),
    ("dropbox", "tech"),
    ("eyeem", "tech"),
    ("evermotion", "tech"),
    ("gsmhosting", "tech"),
    ("aptoide", "tech"),
    ("gravatar", "tech"),
    ("github", "tech"),
    ("slack", "tech"),
    ("zoom", "tech"),
    ("atlassian", "tech"),
    ("trello", "tech"),
    ("bitbucket", "tech"),
    ("gitlab", "tech"),
    ("stackoverflow", "tech"),
    ("hubspot", "tech"),
    ("mailchimp", "tech"),
    ("sendgrid", "tech"),
    // Music / media / streaming.
    ("deezer", "media"),
    ("funimation", "media"),
    ("mefeedia", "media"),
    ("spotify", "media"),
    ("soundcloud", "media"),
    ("netflix", "media"),
    ("hulu", "media"),
    ("lastfm", "media"),
    ("vimeo", "media"),
    ("dailymotion", "media"),
    // Health / fitness.
    ("myfitnesspal", "health"),
    ("jefit", "health"),
    ("fitbit", "health"),
    ("strava", "health"),
    ("garmin", "health"),
    ("peloton", "health"),
    ("noom", "health"),
    ("medibank", "health"), // AU private health insurer (2022, 9.7M, published)
    // Adult.
    ("fling", "adult"),
    ("myvidster", "adult"),
    ("adultfriendfinder", "adult"),
    ("ashleymadison", "adult"),
    ("onlyfans", "adult"),
    ("pornhub", "adult"),
    ("xvideos", "adult"),
    ("fetlife", "adult"),
    // Education.
    ("edmodo", "education"),
    ("chegg", "education"),
    ("coursera", "education"),
    ("udemy", "education"),
    ("duolingo", "education"),
    ("khan", "education"),
    // Retail / e-commerce.
    ("kixify", "retail"),
    ("ebay", "retail"),
    ("etsy", "retail"),
    ("bestbuy", "retail"),
    ("walmart", "retail"),
    ("newegg", "retail"),
    ("shopify", "retail"),
    ("lazada", "retail"),
    ("zalando", "retail"),
    // Finance / crypto.
    ("paypal", "finance"),
    ("coinbase", "finance"),
    ("binance", "finance"),
    ("kraken", "finance"),
    ("robinhood", "finance"),
    ("revolut", "finance"),
    ("etoro", "finance"),
    ("latitudefinancial", "finance"), // Latitude AU (2023, 14M — largest AU breach)
    // Travel / hospitality.
    ("expedia", "travel"),
    ("airbnb", "travel"),
    ("booking", "travel"),
    ("tripadvisor", "travel"),
    ("kayak", "travel"),
    ("hotels", "travel"),
    ("marriott", "travel"),
    ("hilton", "travel"),
    // Telecom — major telco breaches (Australian emphasis).
    ("optus", "telecom"), // Optus AU (2022, ~10M customers, names/DOB/ID numbers)
];

/// Sector for a source whose name is a known breach **brand / domain**, matched
/// as a whole alnum token (never a substring). `None` when no brand is present.
fn known_brand_sector(lower: &str) -> Option<&'static str> {
    let tokens: Vec<&str> = lower
        .split(|c: char| !c.is_ascii_alphanumeric())
        .filter(|s| !s.is_empty())
        .collect();
    KNOWN_SOURCE_SECTORS
        .iter()
        .find(|(needle, _)| tokens.contains(needle))
        .map(|(_, sector)| *sector)
}

/// Normalised sector for a breach **source database name**, or `None` when it
/// can't be placed (the conservative default — an unknown source is left
/// untagged rather than mislabelled).
///
/// Resolution order, most authoritative first: real-estate brand/keyword (so it
/// resolves whether the source is a domain or a structured token), then the
/// category embedded in a structured snusbase token, then the known-brand table
/// (the recall path for the bare domain names every non-structured pool emits).
#[must_use]
pub fn source_sector(dbname: &str) -> Option<&'static str> {
    let d = dbname.trim();
    if d.is_empty() {
        return None;
    }
    let lower = d.to_lowercase();
    if REAL_ESTATE.iter().any(|k| lower.contains(k)) {
        return Some("real-estate");
    }
    structured_category(&lower).or_else(|| known_brand_sector(&lower))
}

/// Read the sector from a structured snusbase-style source name: the
/// second-from-last `_`-segment, but only when the last segment is a date
/// (4–8 digits) — otherwise a bare domain like `pureincubation.com` (no
/// underscores, no trailing date) correctly yields `None`.
fn structured_category(lower: &str) -> Option<&'static str> {
    let parts: Vec<&str> = lower.split('_').collect();
    if parts.len() < 3 {
        return None;
    }
    let last = parts[parts.len() - 1];
    let looks_like_date = (4..=8).contains(&last.len()) && last.bytes().all(|b| b.is_ascii_digit());
    if !looks_like_date {
        return None;
    }
    let category = parts[parts.len() - 2];
    Some(match category {
        "realestate" | "real-estate" | "property" | "housing" | "rental" | "rentals" => {
            "real-estate"
        }
        "gaming" | "games" | "game" | "gambling" => "gaming",
        "tech" | "technology" | "it" | "software" | "saas" => "tech",
        "finance" | "financial" | "banking" | "bank" | "crypto" | "fintech" => "finance",
        "health" | "medical" | "healthcare" | "pharma" => "health",
        "gov" | "government" | "military" | "defence" | "defense" => "government",
        "retail" | "ecommerce" | "shopping" | "commerce" => "retail",
        "social" | "dating" | "forum" | "forums" => "social",
        "media" | "music" | "streaming" | "entertainment" => "media",
        "adult" | "porn" | "xxx" => "adult",
        "education" | "edu" | "academic" | "university" => "education",
        "travel" | "hospitality" | "airline" | "hotel" => "travel",
        "telecom" | "telco" | "isp" | "mobile" => "telecom",
        "auto" | "automotive" | "vehicle" => "automotive",
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
