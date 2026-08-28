//! Pure, offline WiFi-name classification.
//!
//! Sits in `util` rather than in the WiGLE module because two very different
//! layers need the SAME answer to "is this network name one a person chose, or
//! a vendor/carrier default?":
//!
//! - `modules::wigle` consults it BEFORE issuing an SSID search, so a generic
//!   name never costs a request.
//! - `core::engine::ranking` consults it before letting an SSID seed an
//!   autonomous scan, so a `NETGEAR` observed in passing can never become a
//!   scan target.
//!
//! `core` must never import `crate::modules` (asserted in
//! `tests/architecture.rs`), so a shared home in `util` is what lets both call
//! one implementation instead of drifting copies. Dependency-free: two curated
//! const tables and one cached `aho-corasick` pass over a lowercased copy — no
//! I/O, no state, no upward dependencies. The exact counterpart of
//! [`crate::util::oui`], which answers the same question for a BSSID.

/// True when an SSID is a default/carrier/generic name rather than one a person
/// chose — the names whose WiGLE observations belong to strangers' routers, not
/// the subject's.
///
/// Two matchers, because the terms fall into two very different classes.
///
/// Distinctive vendor and carrier strings ([`GENERIC_SSID_BRANDS`]) match as
/// **substrings**: real defaults concatenate them (`xfinitywifi`, `NETGEAR47`,
/// `TelstraFDA3B2`), and the strings are long and specific enough that they do
/// not turn up inside ordinary words.
///
/// Short English words ([`GENERIC_SSID_WORDS`]) match only as **whole tokens**.
/// Substring-matching these silently destroyed the module's flagship
/// capability: `att`, `free`, `open` and `test` occur inside perfectly ordinary
/// surnames, so `Seattle-Cafe`, `Freeman-Family`, `Openshaw-House` and
/// `Testa-Household` were all classified generic — and because
/// the WiGLE module's `ssid_search` consults this before issuing any request, those
/// subjects were never looked up at all. A whole-token test keeps
/// `Free Public WiFi` generic while letting `Freeman-Family` through.
pub fn is_generic_ssid(s: &str) -> bool {
    let lower = s.to_lowercase();

    // One cached `aho-corasick` pass via `util::scan` (SOL-F1). Case-sensitive
    // over the Unicode-lowercased string (the patterns are lowercase), so it
    // preserves the exact `to_lowercase()` fold, unlike an ASCII-CI matcher.
    static BRANDS: std::sync::LazyLock<crate::util::scan::MatchSet> =
        std::sync::LazyLock::new(|| crate::util::scan::MatchSet::new(GENERIC_SSID_BRANDS));
    if BRANDS.is_match(&lower) {
        return true;
    }

    ssid_tokens(&lower).any(|tok| GENERIC_SSID_WORDS.contains(&tok))
}

/// Split an SSID into comparable word tokens: separated on any non-alphanumeric
/// character and at every letter↔digit boundary, so `ATT4G-Home` yields
/// `att`, `4`, `g`, `home` and the carrier prefix is recognised without
/// substring-matching `att` inside `Seattle`.
fn ssid_tokens(lower: &str) -> impl Iterator<Item = &str> {
    lower
        .split(|c: char| !c.is_alphanumeric())
        .flat_map(|part| {
            let mut tokens = Vec::new();
            let mut start = 0;
            let mut prev: Option<char> = None;
            for (idx, ch) in part.char_indices() {
                if let Some(p) = prev
                    && p.is_numeric() != ch.is_numeric()
                {
                    tokens.push(&part[start..idx]);
                    start = idx;
                }
                prev = Some(ch);
            }
            if start < part.len() {
                tokens.push(&part[start..]);
            }
            tokens
        })
        .filter(|t| !t.is_empty())
}

/// Vendor/carrier strings distinctive enough to match anywhere in the name —
/// defaults routinely concatenate them with hex or digits.
pub const GENERIC_SSID_BRANDS: &[&str] = &[
    "linksys", "netgear", "dlink", "tp-link", "tplink", "xfinity", "spectrum", "optimum",
    "telstra", "optus", "vodafone", "iinet", "eduroam", "android", "iphone", "galaxy", "unnamed",
    "unknown", "hidden",
];

/// Short, common words that must match as a WHOLE TOKEN. Every one of these
/// occurs inside ordinary surnames and place names; see [`is_generic_ssid`].
/// `wifi`/`wlan` are deliberately absent: they are descriptive suffixes people
/// append to their own names (`Smith-WiFi`), so treating them as generic would
/// re-create the very false-positive class this split exists to remove.
pub const GENERIC_SSID_WORDS: &[&str] = &[
    "default", "asus", "att", "cox", "nbn", "guest", "free", "public", "open", "pixel", "setup",
    "config", "admin", "test",
];

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
