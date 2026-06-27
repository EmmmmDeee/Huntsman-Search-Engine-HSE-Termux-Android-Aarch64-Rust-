//! Search-engine helpers — entity extraction and construction from result text.
//!
//! Reaches the other helper groups and shared imports through `use super::*`.

use super::*;

mod extractors;
pub(in crate::modules::search_engines) use extractors::{
    extract_abn_acn_from_text, extract_addresses_from_text, extract_emails_from_text,
    extract_organisations_from_text, extract_phones_from_text,
};

/// Score how strongly a discovered username is connected to the target.
/// Uses multiple independent signals — a username that shares no terms
/// with the seed can still be validated through co-occurrence, people-
/// search provenance, or search-engine contextual linking.
///
/// Returns (score, confidence):
///   score ≥ 3 → strong: 0.55 confidence (PROBABLE tier)
///   score 1-2 → weak:   0.30 confidence (CANDIDATE tier)
///   score 0   → drop:   not emitted
pub(in crate::modules::search_engines) fn score_username(
    username: &str,
    host: &str,
    terms: &[String],
    result: &SearchResult,
) -> (u8, f64) {
    let mut score: u8 = 0;

    // Signal 1: direct overlap on the DISTINCTIVE token (strongest). Lowercase
    // once and borrow the resulting `&str` parts — they are only
    // compared/substring-tested, never retained, so no per-part `String`
    // allocation is needed.
    //
    // For a multi-part NAME the surname (last significant term) is the identity
    // anchor: a shared FIRST name alone cross-attributes different people (target
    // "Jordan Meyers" must not claim a stranger's "jordan_blake"), the same reason
    // `url_matches_target` requires the surname in a path. A single-token target
    // (email handle, one-word name, bare username) IS its own anchor, so any
    // overlap counts. Given names still corroborate through the weaker signals
    // below — landing a first-name-only hit at CANDIDATE, not PROBABLE.
    let username_lower = username.to_lowercase();
    let parts: Vec<&str> = username_lower
        .split(|c: char| !c.is_alphanumeric())
        .filter(|w| w.len() >= 3)
        .collect();
    let part_matches = |t: &str| {
        parts
            .iter()
            .any(|p| *p == t || p.contains(t) || t.contains(*p))
    };
    let signal1 = match terms.split_last() {
        None => false,
        Some((anchor, _given)) => part_matches(anchor.as_str()),
    };
    if signal1 {
        score += 3;
    }

    // Signal 2: people-search provenance — the site specialises in
    // linking identities, so any username it connects to the target
    // has high implicit credibility
    let people_search = [
        "peekyou.com",
        "spokeo.com",
        "nuwber.com",
        "whitepages.com",
        "thatsthem.com",
        "whitepages.com.au",
        "locatefamily.com",
        "peoplefinder.com.au",
        "ancestry.com.au",
    ];
    // Match the host itself or a subdomain of it — `host.ends_with(ps)` alone
    // would also fire on `myspokeo.com` / `notwhitepages.com`. Same dot-boundary
    // predicate used for the aggregator check above.
    let people_search_hit = people_search
        .iter()
        .any(|ps| crate::util::domains::is_or_subdomain_of(host, ps));
    if people_search_hit {
        score += 3;
    }

    // Signal 3: co-occurrence — a target term (≥4 chars) appears
    // in the same snippet/title as this username, meaning the search
    // engine's result page explicitly associates both
    let text = format!("{} {}", result.title, result.snippet).to_lowercase();
    if terms
        .iter()
        .filter(|t| t.len() >= 4)
        .any(|t| text.contains(t.as_str()))
    {
        score += 2;
    }

    // Signal 4: platform-targeted query — the query used site:
    // for this exact platform, meaning the engine specifically
    // matched the target to this profile on this platform
    let ql = result.query.to_lowercase();
    let host_base = host
        .trim_start_matches("www.")
        .trim_start_matches("m.")
        .trim_start_matches("mobile.");
    if ql.contains(&format!("site:{host_base}")) {
        score += 1;
    }

    // Signal 5: handle similarity — the candidate is structurally a VARIANT of
    // the seed handle, which separates a likely alias of the SAME person from an
    // unrelated username that merely co-occurred on the result page. Two matches:
    //  - shared alphabetic STEM: seed "kylo4kylo" → stem "kylo" → "kylocool630".
    //    Bigram overlap alone misses this (~0.2 < 0.25 because the digits/suffix
    //    dilute it), so also test substring-containment of any ≥4-char alpha run
    //    of the seed; and
    //  - bigram overlap ("jaydes" ↔ "jdespal") for transposed/abbreviated aliases.
    // Unlike the old `score == 0` fallback this BOOSTS, so a seed-resembling
    // handle that ALSO co-occurs reaches PROBABLE (0.55) while pure co-occurrence
    // stays CANDIDATE (0.30) — the precision lift that keeps alias variants ahead
    // of co-occurrence noise.
    let cand = username_lower.as_str();
    let stem_match = terms
        .iter()
        .flat_map(|t| t.split(|c: char| c.is_ascii_digit()))
        .any(|s| s.len() >= 4 && cand.contains(s));
    let seed = terms.first().map_or("", String::as_str);
    if stem_match || bigram_similarity(cand, seed) >= 0.25 {
        score += 2;
    }

    // Precision gate (mirrors `url_matches_target`): for a multi-part NAME the
    // surname is the identity anchor. A handle that matches only the GIVEN name —
    // however much it co-occurs (Signal 3) or resembles the seed stem (Signal 5) —
    // is a stranger risk ("jordan_blake" for "Jordan Meyers"), so first-name
    // evidence alone cannot reach the PROBABLE tier: only a surname-anchor hit
    // (Signal 1) or people-search provenance (Signal 2, where the site itself
    // asserts the identity) clears the cap. Single-token targets are their own
    // anchor and are never capped.
    let multi_part_name = terms.len() >= 2;
    let anchored = signal1 || people_search_hit;
    let score = if multi_part_name && !anchored {
        score.min(2)
    } else {
        score
    };

    let confidence = if score >= 3 { 0.55 } else { 0.30 };
    (score, confidence)
}

/// Normalize an address for fuzzy dedup: lowercased, state abbreviations
/// expanded, common punctuation and whitespace collapsed. This catches
/// "Gatton, QLD" ≡ "Gatton, Queensland" ≡ "gatton queensland".
pub(in crate::modules::search_engines) fn normalise_address_key(addr: &str) -> String {
    let mut s = addr.to_lowercase();
    let expansions = [
        ("qld", "queensland"),
        ("nsw", "new south wales"),
        ("vic", "victoria"),
        ("tas", "tasmania"),
        ("act", "australian capital territory"),
        ("sa", "south australia"),
        ("wa", "western australia"),
        ("nt", "northern territory"),
    ];
    for (abbr, full) in &expansions {
        if s.contains(abbr) && !s.contains(full) {
            s = s.replace(abbr, full);
        }
    }
    s.retain(|c| c.is_alphanumeric() || c == ' ');
    // Drop trailing postcode token(s) so "City, STATE" and "City, STATE 2582"
    // (one locality, two granularities) share a dedup key and collapse into a
    // single Address entity — even when each form arrives from a different
    // search result. A postcode is a 4-(AU)/5-(US) digit run; it is always
    // trailing, so a leading street number (also numeric) is never stripped.
    let mut tokens: Vec<&str> = s.split_whitespace().collect();
    while tokens.len() > 1
        && tokens
            .last()
            .is_some_and(|t| (4..=5).contains(&t.len()) && t.bytes().all(|b| b.is_ascii_digit()))
    {
        tokens.pop();
    }
    tokens.join(" ")
}

// ─── Entity building ────────────────────────────────────────────────────────

pub(in crate::modules::search_engines) fn known_city_coords(addr: &str) -> Option<(f64, f64)> {
    crate::util::city_coords::city_coords(addr)
}

/// Build a clean, structured evidence entry from a search result.
/// Every evidence entry includes the full navigable URL so the user
/// can click through to verify the finding.
pub(in crate::modules::search_engines) fn build_search_evidence(r: &SearchResult) -> Evidence {
    // Display/preview caps are deliberately generous so a finding can be
    // verified from the evidence alone. When the source content is longer than
    // the cap we keep the preview *and* record the true length plus a
    // `*_truncated` flag, so the logs/UI never silently imply the snippet was
    // complete. The key-phrase is extracted from the FULL snippet (not the
    // truncated preview) so a relevant clause past the cap is not lost.
    const TITLE_CAP: usize = 4000;
    const SNIPPET_CAP: usize = 32768;
    let title_len = r.title.chars().count();
    let snippet_len = r.snippet.chars().count();
    let title_clean: String = r.title.chars().take(TITLE_CAP).collect();
    let snippet_clean: String = r.snippet.chars().take(SNIPPET_CAP).collect();

    let summary = if !title_clean.is_empty() {
        format!("[{}] {} — {}", r.engine, title_clean.trim(), r.url)
    } else {
        format!("[{}] {}", r.engine, r.url)
    };

    let mut ev = Evidence::new(SRC, summary)
        .with_attr("url", &r.url)
        .with_attr("engine", r.engine)
        .with_attr("query", &r.query);
    if !title_clean.is_empty() {
        ev = ev.with_attr("page_title", title_clean.trim());
        if title_len > TITLE_CAP {
            ev = ev
                .with_attr("page_title_truncated", "true")
                .with_attr("page_title_full_len", title_len.to_string());
        }
    }
    if !snippet_clean.is_empty() {
        ev = ev.with_attr("snippet", snippet_clean.trim());
        if snippet_len > SNIPPET_CAP {
            ev = ev
                .with_attr("snippet_truncated", "true")
                .with_attr("snippet_full_len", snippet_len.to_string());
            tracing::debug!(
                target: "hse::parser",
                url = %r.url,
                engine = r.engine,
                full_len = snippet_len,
                cap = SNIPPET_CAP,
                "search snippet exceeded preview cap — preview stored, full length recorded"
            );
        }
    }

    // Extract the key phrase from the full snippet so a query-relevant clause
    // beyond the preview cap is still surfaced.
    let kp = extract_key_phrase(&r.snippet, &r.query);
    if !kp.is_empty() {
        ev = ev.with_attr("key_phrase", &kp);
    }
    ev
}

pub(in crate::modules::search_engines) fn is_valid_abn(s: &str) -> bool {
    // Shared, checksum-validated implementation (see `util::abn`).
    crate::util::abn::is_valid_abn(s)
}

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
