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

    // Signal 1: direct term overlap (strongest). Lowercase once and borrow the
    // resulting `&str` parts — they are only compared/substring-tested, never
    // retained, so no per-part `String` allocation is needed.
    let username_lower = username.to_lowercase();
    let parts: Vec<&str> = username_lower
        .split(|c: char| !c.is_alphanumeric())
        .filter(|w| w.len() >= 3)
        .collect();
    if terms.iter().any(|t| {
        parts
            .iter()
            .any(|p| *p == t.as_str() || p.contains(t.as_str()) || t.contains(*p))
    }) {
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
    if people_search
        .iter()
        .any(|ps| crate::util::domains::is_or_subdomain_of(host, ps))
    {
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

#[allow(dead_code)]
fn _placeholder_cities_tombstone() {
    const _CITIES: &[(&str, f64, f64)] = &[
        // Australian capitals + major cities
        ("brisbane", -27.4698, 153.0251),
        ("sydney", -33.8688, 151.2093),
        ("melbourne", -37.8136, 144.9631),
        ("perth", -31.9505, 115.8605),
        ("adelaide", -34.9285, 138.6007),
        ("canberra", -35.2809, 149.1300),
        ("hobart", -42.8821, 147.3272),
        ("darwin", -12.4634, 130.8456),
        ("gold coast", -28.0167, 153.4000),
        ("sunshine coast", -26.6500, 153.0667),
        ("cairns", -16.9186, 145.7781),
        ("townsville", -19.2590, 146.8169),
        ("toowoomba", -27.5598, 151.9507),
        ("rockhampton", -23.3791, 150.5100),
        // QLD suburbs + regional
        ("gatton", -27.5567, 152.2767),
        ("laidley", -27.6333, 152.3833),
        ("lockyer valley", -27.5567, 152.2767),
        ("helidon", -27.5500, 152.1167),
        ("plainland", -27.5667, 152.4167),
        ("forest hill", -27.5833, 152.3500),
        ("nundah", -27.4017, 153.0600),
        ("redcliffe", -27.2289, 153.1050),
        ("caboolture", -27.0847, 152.9511),
        ("chermside", -27.3861, 153.0331),
        ("aspley", -27.3650, 153.0167),
        ("strathpine", -27.3050, 152.9900),
        ("north lakes", -27.2281, 153.0019),
        ("ipswich", -27.6167, 152.7667),
        ("logan", -27.6389, 153.1092),
        ("springfield", -27.6667, 152.9167),
        ("surfers paradise", -28.0029, 153.4300),
        ("broadbeach", -28.0264, 153.4307),
        ("robina", -28.0744, 153.3842),
        ("coolangatta", -28.1667, 153.5333),
        ("nerang", -27.9897, 153.3372),
        ("bundaberg", -24.8661, 152.3489),
        ("hervey bay", -25.2881, 152.8411),
        ("gladstone", -23.8488, 151.2673),
        ("mount isa", -20.7264, 139.4928),
        ("mackay", -21.1411, 149.1861),
        ("maryborough", -25.5411, 152.7028),
        ("warwick", -28.2167, 152.0333),
        ("dalby", -27.1833, 151.2667),
        ("kingaroy", -26.5400, 151.8400),
        ("stanthorpe", -28.6567, 151.9333),
        ("goondiwindi", -28.5500, 150.3000),
        ("chinchilla", -26.7333, 150.6333),
        ("morayfield", -27.1167, 152.9667),
        ("burpengary", -27.1667, 152.9667),
        ("narangba", -27.2000, 152.9667),
        ("kallangur", -27.2667, 152.9833),
        ("petrie", -27.2667, 152.9833),
        ("bracken ridge", -27.3333, 153.0333),
        ("sandgate", -27.3239, 153.0672),
        ("shorncliffe", -27.3300, 153.0800),
        ("deagon", -27.3500, 153.0667),
        ("fortitude valley", -27.4570, 153.0320),
        ("new farm", -27.4661, 153.0510),
        ("teneriffe", -27.4556, 153.0444),
        ("woolloongabba", -27.4939, 153.0333),
        ("south brisbane", -27.4800, 153.0200),
        ("west end", -27.4800, 153.0133),
        ("kangaroo point", -27.4833, 153.0400),
        ("spring hill", -27.4600, 153.0233),
        ("paddington", -27.4600, 152.9900),
        ("milton", -27.4667, 152.9833),
        ("toowong", -27.4833, 152.9833),
        ("indooroopilly", -27.5000, 152.9667),
        ("st lucia", -27.4986, 153.0036),
        ("taringa", -27.5000, 152.9833),
        ("beenleigh", -27.7167, 153.2000),
        ("capalaba", -27.5167, 153.2000),
        ("cleveland", -27.5333, 153.2667),
        ("wynnum", -27.4333, 153.1667),
        ("tweed heads", -28.1781, 153.5506),
        ("withcott", -27.5667, 152.2167),
        ("caboolture south", -27.1167, 152.9667),
        // NT
        ("alice springs", -23.6980, 133.8807),
        ("katherine", -14.4650, 132.2635),
        ("nhulunbuy", -12.1811, 136.7756),
        // SA
        ("mount gambier", -37.8307, 140.7828),
        ("whyalla", -33.0350, 137.5667),
        ("port augusta", -32.4939, 137.7650),
        ("port pirie", -33.1858, 138.0178),
        ("victor harbor", -35.5572, 138.6172),
        // WA
        ("fremantle", -32.0569, 115.7439),
        ("mandurah", -32.5264, 115.7239),
        ("bunbury", -33.3258, 115.6397),
        ("albany", -35.0269, 117.8836),
        ("geraldton", -28.7744, 114.6153),
        ("kalgoorlie", -30.7490, 121.4658),
        // TAS
        ("launceston", -41.4388, 147.1347),
        ("devonport", -41.1769, 146.3506),
        ("burnie", -41.0553, 145.9058),
        // NSW regional
        ("newcastle", -32.9283, 151.7817),
        ("wollongong", -34.4278, 150.8931),
        ("central coast", -33.3000, 151.3500),
        ("tamworth", -31.0833, 150.9167),
        ("wagga wagga", -35.1083, 147.3598),
        ("albury", -36.0737, 146.9135),
        ("orange", -33.2833, 149.1000),
        ("bathurst", -33.4167, 149.5833),
        ("dubbo", -32.2569, 148.6011),
        // VIC regional
        ("geelong", -38.1499, 144.3617),
        ("ballarat", -37.5622, 143.8503),
        ("bendigo", -36.7570, 144.2794),
        ("shepparton", -36.3833, 145.3833),
        // US cities (expanded)
        ("new york", 40.7128, -74.0060),
        ("los angeles", 33.9425, -118.2551),
        ("chicago", 41.8781, -87.6298),
        ("houston", 29.7604, -95.3698),
        ("phoenix", 33.4484, -111.9490),
        ("san francisco", 37.7749, -122.4194),
        ("seattle", 47.6062, -122.3321),
        ("denver", 39.7392, -104.9903),
        ("colorado springs", 38.8339, -104.8214),
        ("colo springs", 38.8339, -104.8214),
        ("philadelphia", 39.9526, -75.1652),
        ("san antonio", 29.4241, -98.4936),
        ("dallas", 32.7767, -96.7970),
        ("san jose", 37.3382, -121.8863),
        ("austin", 30.2672, -97.7431),
        ("jacksonville", 30.3322, -81.6557),
        ("columbus", 39.9612, -82.9988),
        ("miami", 25.7617, -80.1918),
        ("boston", 42.3601, -71.0589),
        ("atlanta", 33.7490, -84.3880),
        ("portland", 45.5152, -122.6784),
        ("las vegas", 36.1699, -115.1398),
        ("nashville", 36.1627, -86.7816),
        ("minneapolis", 44.9778, -93.2650),
        // UK cities (expanded)
        ("london", 51.5074, -0.1278),
        ("manchester", 53.4808, -2.2426),
        ("birmingham", 52.4862, -1.8904),
        ("leeds", 53.8008, -1.5491),
        ("glasgow", 55.8642, -4.2518),
        ("liverpool", 53.4084, -2.9916),
        ("edinburgh", 55.9533, -3.1883),
        ("bristol", 51.4545, -2.5879),
        // NZ cities
        ("auckland", -36.8485, 174.7633),
        ("wellington", -41.2865, 174.7762),
        ("christchurch", -43.5321, 172.6362),
    ];
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
    const TITLE_CAP: usize = 500;
    const SNIPPET_CAP: usize = 4000;
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
