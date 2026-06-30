//! Free-text identifier extractors for search-engine result text.
//!
//! The leaf text-mining functions split out of the `entity` parent so the
//! entity-construction / scoring / evidence code stays readable. Each is a pure
//! function of its input text (plus, for organisations, the seed terms) and is
//! unit-tested via the parent's `tests` module. Reaches shared imports through
//! `use super::*` exactly as the parent does.

use super::*;

/// Extract "City, State" patterns from text for geolocation.
/// Only matches when a comma-separated city name precedes a known
/// state/territory name, and the city portion starts with an uppercase
/// letter (filters out random sentence fragments).
pub(in crate::modules::search_engines) fn extract_addresses_from_text(text: &str) -> Vec<String> {
    const STATES: &[&str] = &[
        "Queensland",
        "New South Wales",
        "Victoria",
        "Tasmania",
        "South Australia",
        "Western Australia",
        "Northern Territory",
        "NSW",
        "QLD",
        "VIC",
        "TAS",
        "ACT",
        "Alabama",
        "Alaska",
        "Arizona",
        "Arkansas",
        "California",
        "Colorado",
        "Connecticut",
        "Delaware",
        "Florida",
        "Georgia",
        "Hawaii",
        "Idaho",
        "Illinois",
        "Indiana",
        "Iowa",
        "Kansas",
        "Kentucky",
        "Louisiana",
        "Maine",
        "Maryland",
        "Massachusetts",
        "Michigan",
        "Minnesota",
        "Mississippi",
        "Missouri",
        "Montana",
        "Nebraska",
        "Nevada",
        "New Hampshire",
        "New Jersey",
        "New Mexico",
        "New York",
        "North Carolina",
        "North Dakota",
        "Ohio",
        "Oklahoma",
        "Oregon",
        "Pennsylvania",
        "Rhode Island",
        "South Carolina",
        "South Dakota",
        "Tennessee",
        "Texas",
        "Utah",
        "Vermont",
        "Virginia",
        "Washington",
        "West Virginia",
        "Wisconsin",
        "Wyoming",
    ];

    let mut addrs = Vec::new();
    for state in STATES {
        let mut search_from = 0;
        while let Some(pos) = text[search_from..].find(state) {
            let abs = search_from + pos;
            search_from = abs + state.len();

            // Need ", State" — check for comma before the state name
            let before = text[..abs].trim_end();
            if !before.ends_with(',') {
                continue;
            }
            // Extract the city name between the nearest prior comma
            // (or start of text) and the comma before the state name.
            // "Jerome Despal, Nundah, Queensland" → "Nundah"
            // "lives in Houston, Texas" → "Houston"
            let pre_comma = before.trim_end_matches(',').trim();
            let (last_segment, from_comma) = match pre_comma.rfind(',') {
                Some(i) => (pre_comma[i + 1..].trim(), true),
                None => {
                    let words: Vec<&str> = pre_comma.split_whitespace().collect();
                    let mut n = 0;
                    for w in words.iter().rev() {
                        if w.starts_with(|c: char| c.is_ascii_uppercase()) {
                            n += 1;
                        } else {
                            break;
                        }
                    }
                    if n == 0 {
                        continue;
                    }
                    let start_idx = words.len() - n;
                    (
                        &pre_comma[pre_comma.find(words[start_idx]).unwrap_or(0)..],
                        false,
                    )
                }
            };
            let mut city = last_segment.trim();
            // Cross-address state bleed (comma path only): a run-on listing two
            // places — "Los Angeles, California Dallas, Texas" — makes `rfind`
            // grab "California Dallas" as the city for "Texas", because the
            // leading "California" is really the STATE of the preceding
            // "Los Angeles, California". When the city begins with a state name
            // that DIFFERS from this address's own state, strip that bled-over
            // token to recover the true city ("Dallas"). The differ-from-`state`
            // guard keeps genuine state-named cities intact — "Virginia Beach,
            // Virginia" and "Oklahoma City, Oklahoma" match their own state, so
            // nothing is stripped — and the comma-path restriction leaves
            // word-path cities like "Kansas City, Missouri" untouched.
            if from_comma {
                for bled in STATES {
                    if !bled.eq_ignore_ascii_case(state)
                        && let Some(rest) = city.strip_prefix(bled)
                        && let Some(stripped) = rest.strip_prefix(' ')
                    {
                        city = stripped.trim_start();
                        break;
                    }
                }
            }
            if city.len() < 2
                || city.len() > 40
                || !city.starts_with(|c: char| c.is_ascii_uppercase())
            {
                continue;
            }
            if !city
                .chars()
                .all(|c| c.is_alphanumeric() || c == ' ' || c == '-')
            {
                continue;
            }
            // A "city" that is itself one or more US state names ("Arizona",
            // "Florida and Texas") is NOT a City, State address — it's a
            // generic-text false positive (a news headline or list enumerating
            // states). A real scan flooded 18 such pairs and drove bogus
            // geolocation correlations. Reject when every conjunct is a state.
            // (Legit multi-word cities like "Kansas City" survive: "City" is not
            // a state, so the all-states test fails and the address is kept.)
            let all_states = city
                .split([',', '&'])
                .flat_map(|p| p.split(" and "))
                .map(str::trim)
                .filter(|p| !p.is_empty())
                .all(|part| STATES.iter().any(|s| s.eq_ignore_ascii_case(part)));
            if all_states {
                continue;
            }
            let addr = format!("{city}, {state}");
            addrs.push(addr);
        }
    }

    // Second pass: AU city + state context detection
    const AU_PLACES: &[&str] = &[
        // Capital cities
        "Brisbane",
        "Sydney",
        "Melbourne",
        "Perth",
        "Adelaide",
        "Canberra",
        "Hobart",
        "Darwin",
        // Major regional
        "Gold Coast",
        "Newcastle",
        "Wollongong",
        "Geelong",
        "Sunshine Coast",
        "Central Coast",
        // Queensland suburbs/cities
        "Cairns",
        "Townsville",
        "Toowoomba",
        "Rockhampton",
        "Mackay",
        "Bundaberg",
        "Hervey Bay",
        "Gladstone",
        "Mount Isa",
        "Nundah",
        "Redcliffe",
        "Caboolture",
        "Chermside",
        "Aspley",
        "Sandgate",
        "Shorncliffe",
        "Deagon",
        "Bracken Ridge",
        "Strathpine",
        "Petrie",
        "Kallangur",
        "Narangba",
        "Morayfield",
        "Burpengary",
        "North Lakes",
        "Fortitude Valley",
        "New Farm",
        "Teneriffe",
        "Woolloongabba",
        "South Brisbane",
        "West End",
        "Kangaroo Point",
        "Spring Hill",
        "Paddington",
        "Milton",
        "Toowong",
        "Indooroopilly",
        "St Lucia",
        "Taringa",
        "Logan",
        "Ipswich",
        "Springfield",
        // Lockyer Valley region
        "Gatton",
        "Laidley",
        "Helidon",
        "Plainland",
        "Forest Hill",
        "Lockyer Valley",
        "Withcott",
        // Western Downs / Darling Downs
        "Dalby",
        "Warwick",
        "Kingaroy",
        "Stanthorpe",
        "Goondiwindi",
        "Chinchilla",
        // Moreton Bay
        "Maryborough",
        "Beenleigh",
        "Capalaba",
        "Cleveland",
        "Wynnum",
        "Manly",
        "Surfers Paradise",
        "Broadbeach",
        "Robina",
        "Nerang",
        "Coolangatta",
        "Tweed Heads",
        // NSW
        "Parramatta",
        "Blacktown",
        "Penrith",
        "Liverpool",
        "Bondi",
        "Manly",
        "Cronulla",
        "Bankstown",
        // VIC
        "St Kilda",
        "Richmond",
        "Fitzroy",
        "Collingwood",
        "South Yarra",
        "Prahran",
        "Carlton",
        "Brunswick",
    ];

    // Lowercase the text once; the AU-place scan below only reads it.
    let lower = text.to_lowercase();
    // Track lowercased addresses already emitted so the dedup check below is an
    // O(1) set lookup instead of a fresh `to_lowercase()` over every prior addr
    // on each candidate. Seeded with the first-pass (STATES) results.
    let mut seen_addr_keys: std::collections::HashSet<String> =
        addrs.iter().map(|a| a.to_lowercase()).collect();
    for place in AU_PLACES {
        let place_lower = place.to_lowercase();
        if let Some(pos) = lower.find(&place_lower) {
            let after = &lower[pos + place_lower.len()..];
            let context: String = after.chars().take(60).collect();
            // Walk back to a char boundary; UTF-8 multi-byte chars
            // (e.g. '>' substitutes spanning 3 bytes) must not be split.
            let mut before_start = pos.saturating_sub(60);
            while before_start > 0 && !lower.is_char_boundary(before_start) {
                before_start -= 1;
            }
            let before: String = lower[before_start..pos].chars().collect();
            let combined = format!("{before} {context}");
            // Whole-word state detection. The window is free prose, so a bare
            // substring scan mis-reads ordinary words as a state abbreviation
            // ("ser{vic}e" → VIC, "{act}ed" → ACT, "fan{tas}tic" → TAS), fabricating
            // a wrong jurisdiction that then feeds the AU-056 cross-check and
            // geo-divergence logic. Match the 2–3 letter abbreviations as whole
            // tokens — mirroring `address_au::locality_key`, which never substrings a
            // state — while the unambiguous full names stay a plain `contains`.
            let toks: std::collections::HashSet<&str> = combined
                .split(|c: char| !c.is_alphanumeric())
                .filter(|t| !t.is_empty())
                .collect();
            let has_tok = |t: &str| toks.contains(t);
            if combined.contains("australia")
                || has_tok("qld")
                || has_tok("nsw")
                || has_tok("vic")
                || combined.contains("queensland")
                || combined.contains("new south wales")
                || combined.contains("victoria")
            {
                let state_tag = if has_tok("qld") || combined.contains("queensland") {
                    "QLD"
                } else if has_tok("nsw") || combined.contains("new south wales") {
                    "NSW"
                } else if has_tok("vic") || combined.contains("victoria") {
                    "VIC"
                } else if has_tok("wa") || combined.contains("western australia") {
                    "WA"
                } else if has_tok("sa") || combined.contains("south australia") {
                    "SA"
                } else if has_tok("tas") || combined.contains("tasmania") {
                    "TAS"
                } else if has_tok("nt") || combined.contains("northern territory") {
                    "NT"
                } else if has_tok("act") || combined.contains("australian capital territory") {
                    "ACT"
                } else {
                    "Australia"
                };
                let addr = format!("{place}, {state_tag}");
                let addr_lower = addr.to_lowercase();
                if seen_addr_keys.insert(addr_lower) {
                    addrs.push(addr);
                }
            }
        }
    }

    // Third pass: Australian postcodes (4 digits after a place name)
    let postcode_re_like = |s: &str| -> Option<String> {
        let bytes = s.as_bytes();
        let len = bytes.len();
        let mut i = 0;
        while i + 3 < len {
            if bytes[i].is_ascii_digit()
                && bytes[i + 1].is_ascii_digit()
                && bytes[i + 2].is_ascii_digit()
                && bytes[i + 3].is_ascii_digit()
                && (i + 4 >= len || !bytes[i + 4].is_ascii_digit())
                && (i == 0 || !bytes[i - 1].is_ascii_digit())
            {
                let pc = &s[i..i + 4];
                let first = pc.as_bytes()[0];
                // AU postcodes: 2xxx (NSW/ACT), 3xxx (VIC), 4xxx (QLD),
                // 5xxx (SA), 6xxx (WA), 7xxx (TAS), 08xx (NT).
                // NT postcodes start with '0' and must be 08xx or 09xx.
                let is_au_postcode = (b'2'..=b'7').contains(&first)
                    || (first == b'0' && pc.len() == 4 && matches!(pc.as_bytes()[1], b'8' | b'9'));
                if is_au_postcode {
                    return Some(pc.to_string());
                }
            }
            i += 1;
        }
        None
    };

    // Append the postcode that follows a "City, STATE" as a more-specific
    // variant. The bare and postcode-qualified forms are ONE locality, so they
    // must not become two Address entities — `normalise_address_key` strips the
    // trailing postcode, collapsing them to a single dedup key at emission
    // (build.rs), which is where addresses across multiple search results are
    // already merged. (Emitting both strings here is harmless given that dedup,
    // and avoids guessing whether a trailing 4-digit run is a postcode or, say,
    // a year — "Houston, Texas since 2020".)
    // An AU postcode only attaches to an AU-STATE address. Without this gate a
    // US "City, State" picked up a trailing 4-digit YEAR as if it were an AU
    // postcode — a live name-scan produced "Ames, Iowa 2011" at high confidence.
    // Match the state SEGMENT whole (after the last comma), never as a suffix:
    // "Ames, Iowa" ends with "wa" but its state is "iowa", not Western Australia.
    const AU_STATES: &[&str] = &[
        "nsw",
        "qld",
        "vic",
        "tas",
        "act",
        "sa",
        "wa",
        "nt",
        "new south wales",
        "queensland",
        "victoria",
        "tasmania",
        "australian capital territory",
        "south australia",
        "western australia",
        "northern territory",
        "australia",
    ];
    // Collect postcode-qualified variants while only borrowing `addrs`
    // immutably, then append them afterwards — this replaces the previous
    // whole-vector `.clone()` taken to dodge the borrow conflict.
    let mut pc_additions: Vec<String> = Vec::new();
    for r in &addrs {
        let r = r.as_str();
        let state_seg = r.rsplit(',').next().unwrap_or("").trim().to_lowercase();
        if !AU_STATES.contains(&state_seg.as_str()) {
            continue;
        }
        // Anchor the postcode-lookahead window on where the address actually
        // occurs. If `r` isn't a literal substring of `text` (e.g. it was
        // normalised upstream), there's no valid position to read a trailing
        // postcode from — skip it. The previous `text.find(r).unwrap_or(0)`
        // fallback produced a byte index (`r.len()`) unrelated to `text`, which
        // on a multi-byte char — an en-dash in a page title like
        // "SOHO Galleries – Sydney Art Gallery" — sliced mid-codepoint and
        // panicked. `char_window` clamps both ends to char boundaries.
        let Some(found) = text.find(r) else {
            continue;
        };
        let after_idx = found + r.len();
        let snippet = crate::util::str_util::char_window(text, after_idx, after_idx + 20);
        if let Some(pc) = postcode_re_like(snippet) {
            let with_pc = format!("{r} {pc}");
            // Preserve the original "not already present" dedup: a variant must
            // be absent from both the existing addresses and the ones queued.
            if !addrs.contains(&with_pc) && !pc_additions.contains(&with_pc) {
                pc_additions.push(with_pc);
            }
        }
    }
    addrs.extend(pc_additions);

    addrs
}

/// Extract Australian Business Numbers (11 digits) and Australian
/// Company Numbers (9 digits) from text. ABNs are formatted as
/// "XX XXX XXX XXX" or "XXXXXXXXXXX"; ACNs as "XXX XXX XXX".
/// Returns (value, kind_label) pairs.
pub(in crate::modules::search_engines) fn extract_abn_acn_from_text(
    text: &str,
) -> Vec<(String, &'static str)> {
    let mut results = Vec::new();
    let bytes = text.as_bytes();
    let len = bytes.len();
    let mut i = 0;

    while i < len {
        if !bytes[i].is_ascii_digit() {
            i += 1;
            continue;
        }
        let start = i;
        let mut digits = Vec::new();
        while i < len && (bytes[i].is_ascii_digit() || bytes[i] == b' ') {
            if bytes[i].is_ascii_digit() {
                digits.push(bytes[i]);
            }
            i += 1;
        }
        if digits.len() == 11 {
            let num: String = digits.iter().map(|&b| b as char).collect();
            if is_valid_abn(&num) {
                let before = text[..start].to_lowercase();
                let trimmed = before.trim_end();
                if trimmed.ends_with("abn")
                    || trimmed.ends_with("abn:")
                    || trimmed.ends_with("a.b.n.")
                    || trimmed.ends_with("business number")
                    || trimmed.ends_with("business number:")
                {
                    results.push((num, "ABN"));
                    if results.len() >= 10 {
                        break;
                    }
                }
            }
        } else if digits.len() == 9 {
            let num: String = digits.iter().map(|&b| b as char).collect();
            let before = text[..start].to_lowercase();
            let trimmed = before.trim_end();
            let has_context = trimmed.ends_with("acn")
                || trimmed.ends_with("acn:")
                || trimmed.ends_with("a.c.n.")
                || trimmed.ends_with("company number")
                || trimmed.ends_with("company number:");
            // Require the ASIC check-digit too (symmetric with the ABN path) so a
            // random 9-digit number next to the word "acn" is rejected.
            if has_context && crate::util::abn::is_valid_acn(&num) {
                results.push((num, "ACN"));
                if results.len() >= 10 {
                    break;
                }
            }
        }
    }
    results
}

/// Extract organisation names from text. Looks for patterns like
/// "Pty Ltd", "Inc", "LLC", "Corporation" near the target context.
pub(in crate::modules::search_engines) fn extract_organisations_from_text(
    text: &str,
    terms: &[String],
) -> Vec<String> {
    let suffixes = [
        " Pty Ltd",
        " Pty. Ltd.",
        " Pty Limited",
        " Inc.",
        " Inc",
        " LLC",
        " Ltd",
        " Ltd.",
        " Limited",
        " Corporation",
        " Corp.",
        " Corp",
        " Co.",
    ];
    let mut orgs = Vec::new();
    let bytes = text.as_bytes();
    for suffix in &suffixes {
        // Case-insensitive search over the ORIGINAL `text`. We deliberately do
        // NOT index `text` with byte offsets taken from `text.to_lowercase()`:
        // to_lowercase() is not length-preserving (İ→i̇ 2→3 bytes, ẞ→ß), so such
        // offsets can overshoot the end of `text` or split a code point — a
        // `str` index panic, which under `panic="abort"` takes down the whole
        // `serve` process on a hostile SERP snippet. The suffix is ASCII and
        // begins with a space, so a match position `i` and its end are always
        // valid char boundaries in `text`.
        let sfx = suffix.as_bytes();
        let mut i = 0;
        while i + sfx.len() <= bytes.len() {
            if !bytes[i..i + sfx.len()].eq_ignore_ascii_case(sfx) {
                i += 1;
                continue;
            }
            let end = i + sfx.len();
            // Walk backwards to the start of the org name.
            let before = &text[..i];
            let mut name_start = before
                .rfind([',', '.', ';', '(', '\n'])
                .map_or(i.saturating_sub(60), |d| d + 1);
            // The `i-60` fallback may land mid-code-point; snap forward to a
            // boundary so the slice below is always valid.
            while name_start < i && !text.is_char_boundary(name_start) {
                name_start += 1;
            }
            let org = text[name_start..end].trim();
            if org.len() >= 5 && org.starts_with(|c: char| c.is_ascii_uppercase()) {
                // Lowercase once per candidate rather than once per term.
                let org_lower = org.to_lowercase();
                if terms.iter().any(|t| org_lower.contains(t.as_str())) {
                    orgs.push(org.to_string());
                }
            }
            i = end;
        }
    }
    orgs
}

pub(in crate::modules::search_engines) fn extract_emails_from_text(text: &str) -> Vec<String> {
    // Canonical mining lives in `util::extract::page_emails` (deduped, asset- and
    // web-script-fragment-filtered — the `viewtopic.php…@…` guard now lives there
    // and so also protects au_people). This wrapper keeps the search-context cap so
    // a pathological results page can't mint an unbounded mailbox list, warning
    // when it bites so dropped addresses stay visible in the logs.
    let mut emails = crate::util::extract::page_emails(text);
    if emails.len() > 500 {
        tracing::warn!(
            target: "hse::parser",
            cap = 500,
            text_len = text.len(),
            "extract_emails_from_text hit cap — additional mailboxes in this text were not extracted"
        );
        emails.truncate(500);
    }
    emails
}

pub(in crate::modules::search_engines) fn extract_phones_from_text(text: &str) -> Vec<String> {
    // Canonical mining lives in `util::extract::phones` (deduped, with the E.164
    // country-digit gate that rejects `+0…`). This wrapper keeps the search-context
    // cap + warning.
    let mut phones = crate::util::extract::phones(text);
    if phones.len() > 300 {
        tracing::warn!(
            target: "hse::parser",
            cap = 300,
            text_len = text.len(),
            "extract_phones_from_text hit cap — additional numbers in this text were not extracted"
        );
        phones.truncate(300);
    }
    phones
}

/// Extract `http(s)` URLs embedded in a free-text snippet/title body.
///
/// A SERP snippet frequently names the subject's OTHER profiles ("also on
/// `https://github.com/alice`") that the result URL itself doesn't carry. This
/// scans for each `http://`/`https://` occurrence, takes the following run of
/// non-delimiter characters, and trims trailing sentence punctuation. The caller
/// filters the hosts (e.g. to social platforms) and applies its own
/// relevance/username gates — this only finds the candidate URLs. De-duplicated,
/// first-seen order, bounded to `MAX_SNIPPET_URLS` so a link-stuffed snippet
/// can't balloon allocation. Pure.
pub(in crate::modules::search_engines) fn extract_urls_from_text(text: &str) -> Vec<String> {
    const MAX_SNIPPET_URLS: usize = 12;
    let mut out: Vec<String> = Vec::new();
    let mut rest = text;
    while let Some(pos) = rest.find("http") {
        let cand = &rest[pos..];
        if cand.starts_with("http://") || cand.starts_with("https://") {
            // Stop at whitespace or a delimiter that never appears mid-URL.
            let end = cand
                .find(|c: char| {
                    c.is_whitespace()
                        || matches!(
                            c,
                            '"' | '\'' | '<' | '>' | '|' | '\\' | '^' | '`' | '{' | '}'
                        )
                })
                .unwrap_or(cand.len());
            // Trim trailing punctuation that commonly abuts a URL in prose.
            let url = cand[..end].trim_end_matches(|c: char| {
                matches!(c, '.' | ',' | ')' | ']' | '!' | '?' | ';' | ':')
            });
            // Longer than the bare scheme, and not already collected.
            if url.len() > "https://".len() && !out.iter().any(|u| u == url) {
                out.push(url.to_string());
                if out.len() >= MAX_SNIPPET_URLS {
                    break;
                }
            }
            rest = &cand[end..];
        } else {
            // "http" not followed by "://" — step past it and keep scanning.
            rest = &cand[4..];
        }
    }
    out
}
