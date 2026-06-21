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

/// Normalised sector for a breach **source database name**, or `None` when it
/// can't be placed (the conservative default — an unknown source is left
/// untagged rather than mislabelled).
///
/// Real estate is recognised first (by brand/keyword), so it resolves whether
/// the source is a domain (`harcourts.com.au`) or a structured token carrying a
/// `REALESTATE` category; other sectors come from the structured category.
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
    structured_category(&lower)
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
