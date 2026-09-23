//! Free-text identifier extractors for search-engine result text.
//!
//! The leaf text-mining functions split out of the `entity` parent so the
//! entity-construction / scoring / evidence code stays readable. Each is a pure
//! function of its input text (plus, for organisations, the seed terms) and is
//! unit-tested via the parent's `tests` module. Reaches shared imports through
//! `use super::*` exactly as the parent does.

use super::*;

/// Leading words that make a `<Word> <Surname>` run a PLACE, not a person —
/// `Port Douglas`, `Mount Isa`, `Lake Macquarie` — so a place named like the
/// subject survives [`surname_bearer_locality`].
const PLACE_PREFIXES: &[&str] = &[
    "port", "mount", "mt", "lake", "fort", "point", "cape", "glen", "saint", "st", "east", "west",
    "north", "south", "new", "upper", "lower", "old", "little", "great",
];

/// Words that may FOLLOW a surname inside a real place name — `Box Hill North`,
/// `Castle Hill Heights`, `Thorpe Bay` — so a suburb that carries the subject's
/// surname mid-name survives [`surname_bearer_locality`].
const PLACE_SUFFIXES: &[&str] = &[
    "north", "south", "east", "west", "central", "heights", "beach", "bay", "valley", "vale",
    "creek", "springs", "junction", "village", "downs", "waters", "ridge", "lake", "lakes",
    "grove", "estate",
];

/// The locality an extracted `"City, State"` may keep on a name scan for the
/// scanned `surname` — the address itself when its "city" is a place, the
/// place a surname-bearer is said to be `in` when that is all it names, or
/// `None` when the "city" names a PERSON carrying the surname (a people-search
/// listing title) or a THING named after one (a venue, a business).
///
/// [`extract_addresses_from_text`]'s word path takes the capitalised run before
/// `", <State>"` as the city, and its comma path takes the whole segment since
/// the previous comma. Three shapes of text reach it on a name scan:
///
/// - a people-search listing title — `"Ian Thorpe, North Carolina"` from
///   `spokeo.com/Ian-Thorpe/North-Carolina`. A real "Ian Thorpe" scan emitted
///   fourteen such Addresses (Bill, Carol, David, Donald, Ian, William Thorpe,
///   … each "in" a US state); Photon then geocoded four different names to one
///   arbitrary North Carolina point, and the audit reported the resulting
///   spread as geo-divergence (REQ-SEARCH-ADDR-001). The surname ENDS the
///   city: `None`.
/// - a venue named after a surname-bearer — the LinkedIn job title "…
///   Exercise Physiologist NSW, Ian Thorpe Aquatic Centre in Ultimo, New South
///   Wales, Australia" became the Address `"Ian Thorpe Aquatic Centre in
///   Ultimo, New South Wales"`. The result "named the subject" only because
///   the venue does. Photon then geocoded the real pool correctly at house
///   grain (40 m), and that one point, at 5x fusion weight, pinned AU-059 and
///   the headline best location fix (0.97) to a public swimming pool
///   (REQ-SEARCH-ADDR-002). Words that are not a place's own suffix follow
///   the surname (`Aquatic Centre`, `Plumbing`): `None`, wholesale — the
///   venue's suburb is the venue's, not the subject's.
/// - a statement locating the bearer — `"Swim coach, Ian Thorpe in Ultimo,
///   New South Wales"` yields the segment `"Ian Thorpe in Ultimo"`. Nothing
///   but `in` follows the surname, so the place after it is what the text
///   locates: `Some("Ultimo, New South Wales")` (REQ-SEARCH-ADDR-003).
///
/// A surname followed only by place suffixes ([`PLACE_SUFFIXES`]) is a place:
/// `"Box Hill North, Victoria"` survives a scan for a Hill. The REQ-SEARCH-ADDR-002
/// rule dropped every multi-word city with the surname after its first word,
/// which lost that suburb and the `in <Place>` statement with it
/// (REQ-SEARCH-ADDR-003). The surname counts only as a whole word AFTER the
/// first word, not led by a place word ([`PLACE_PREFIXES`]): a city that
/// STARTS with the surname names a place (`"Thorpe Bay, Essex"`), and a single
/// word that IS the surname (`"Lawnton, QLD"` for a Lawnton) is a real suburb
/// and is kept — that collision is capped, not dropped, by the caller. A
/// two-word suburb ending in the surname (`"Box Hill"` for a Hill) is
/// indistinguishable from a listing title and is dropped: the conservative
/// side, since a wrong locality is worse than a missed one. Words and surname
/// are compared diacritic-folded ([`crate::core::scan::fold_name_text`]).
/// **Pure.**
pub(in crate::modules::search_engines) fn surname_bearer_locality(
    addr: &str,
    surname: &str,
) -> Option<String> {
    let Some((city, state)) = addr.rsplit_once(',') else {
        return Some(addr.to_string());
    };
    // Both sides through the identity gate's name fold: the caller's surname
    // comes from `person_surname`, which is diacritic-folded (`"nguyen"`), so
    // a raw comparison would miss the `"Nguyễn"` the listing prints.
    let surname = crate::core::scan::fold_name_text(surname.trim());
    if surname.is_empty() {
        return Some(addr.to_string());
    }
    let words: Vec<&str> = city.split_whitespace().collect();
    let place_led = words.first().is_some_and(|w| {
        PLACE_PREFIXES
            .iter()
            .any(|p| w.trim_end_matches('.').eq_ignore_ascii_case(p))
    });
    let Some(at) = words
        .iter()
        .skip(1)
        .position(|w| crate::core::scan::fold_name_text(w) == surname)
        .map(|p| p + 1)
        .filter(|_| !place_led)
    else {
        return Some(addr.to_string());
    };
    let after = &words[at + 1..];
    let is = |w: &str, set: &[&str]| set.iter().any(|s| w.eq_ignore_ascii_case(s));
    match after {
        // "Ian Thorpe, North Carolina": a person.
        [] => None,
        // "Box Hill North, Victoria": a place carrying the surname.
        _ if after.iter().all(|w| is(w, PLACE_SUFFIXES)) => Some(addr.to_string()),
        // "Ian Thorpe in Ultimo": the place the text locates the bearer in.
        [first, place @ ..] if *first == "in" && !place.is_empty() => {
            Some(format!("{},{state}", place.join(" ")))
        }
        // "Ian Thorpe Aquatic Centre in Ultimo", "Jamie Thorpe Plumbing": a
        // thing named after a surname-bearer.
        _ => None,
    }
}

/// Extract AU location strings from free text for geolocation, in three passes:
/// (1) a comma-separated "City, State" where the city starts with an uppercase
/// letter (filters random sentence fragments); (2) a known AU place name with
/// state context nearby (no comma required); (3) an AU postcode following a place
/// name, appended as a more-specific variant of a matched "City, STATE".
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
    // Lowercased dedup key for every address already pushed, by EITHER pass —
    // a "City, State" mention frequently repeats within one page's combined
    // title+snippet text (the same locality named in both the title and the
    // body, or quoted in two adjacent sentence fragments), and without this
    // the STATES pass below would push the identical string once per repeat.
    // A real scan's evidence chain showed exactly this: the same search result
    // recorded as its own "corroboration" of an address it had just emitted,
    // because this pass alone provided two identical strings for one result.
    let mut seen_addr_keys: std::collections::HashSet<String> = std::collections::HashSet::new();
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
            if seen_addr_keys.insert(addr.to_lowercase()) {
                addrs.push(addr);
            }
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
    // `seen_addr_keys` already carries every address the first (STATES) pass
    // pushed, so it needs no re-seeding here — it's the same dedup set, shared
    // across both passes.
    for place in AU_PLACES {
        // `lower` is already fully lowercased and every AU_PLACES entry is ASCII,
        // so an ASCII-case-insensitive scan for `place` finds the identical
        // leftmost offset that `lower.find(&place.to_lowercase())` did — but
        // without allocating a fresh lowercased String for each of the 97 places
        // on every call, and with a NEON-accelerated scan instead of a naive one.
        if let Some(pos) = crate::util::str_util::find_ascii_ci(&lower, place) {
            let after = &lower[pos + place.len()..];
            let context: String = after.chars().take(60).collect();
            // Walk back to a char boundary; UTF-8 multi-byte chars
            // (e.g. '>' substitutes spanning 3 bytes) must not be split. This is
            // the module's canonical safe-slicing primitive rather than a
            // hand-rolled boundary walk.
            let before_start =
                crate::util::str_util::floor_char_boundary(&lower, pos.saturating_sub(60));
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
            }
        }
    }
    // Checksum-validated, context-prefixed ABN/ACN are high-value business
    // identifiers, so every one is kept rather than silently dropped past a low
    // inline break. Bounded + WARNED (as the email/phone extractors are) only to
    // guard against a pathological identifier-stuffed page.
    const ABN_ACN_CAP: usize = 200;
    if results.len() > ABN_ACN_CAP {
        tracing::warn!(
            found = results.len(),
            cap = ABN_ACN_CAP,
            "extract_abn_acn_from_text hit cap — additional ABN/ACN in this text were not extracted"
        );
        results.truncate(ABN_ACN_CAP);
    }
    results
}

/// Extract organisation names from text. Looks for patterns like
/// "Pty Ltd", "Inc", "LLC", "Corporation" near the target context.
///
/// One title span yields at most one organisation, bounded to the company name
/// itself (REQ-SEARCH-010). Live scan 7258fc07 ("Ian Thorpe") showed three faults
/// in the earlier per-suffix scan:
///   * the overlapping variants (` Inc.` / ` Inc`, ` Pty Ltd` / ` Ltd`) each
///     matched the same span, so one LinkedIn title minted both "Ian Thorpe -
///     Thorpedo Inc" and "… Inc." — the suffixes are now tried longest-first and
///     a suffix occurrence overlapping one already claimed is the same span;
///   * the backward walk stopped only at `, . ; ( \n`, never at a SERP title
///     separator (` - `, ` – `, ` — `, ` | `, ` · `, `•`, `›`), so the person's
///     name and page boilerplate were glued onto the company ("Megan Thorpe Email
///     & Phone Number | Covalent Lithium Pty Ltd") — it now also stops at those
///     and at the end of the previous organisation in the text;
///   * the subject-term filter then ran on that glued string, so the PERSON's
///     name, not the company's, satisfied it and a namesake's employer was filed
///     as a scan organisation.
///
/// A separator bound alone did not close the third fault: snippet PROSE has no
/// separator, so `"… Ian Thorpe is the managing director of Harbour Holdings
/// Pty Ltd"` still walked back across the person's name, and — with the old
/// 60-byte cap replaced by the separator bound — even across the title/snippet
/// join (REQ-SEARCH-013). The name is therefore the run of NAME WORDS directly
/// before the suffix: capitalised or digit-led words, `&`, and the connectors
/// `and`/`of`/`the`/`for` between them (`Bank of Queensland Limited`), with a
/// leading connector trimmed. Lowercase prose (`is the managing director`)
/// ends it; a separator, `, . ; ( \n`, the previous organisation's end and a
/// 60-byte floor still bound it (an all-caps title is all "capitalised").
///
/// The term filter then runs on that name alone, and matches a term only at
/// the START of one of its words: a raw substring test let the given name
/// `"ian"` admit `"Australian Unity Limited"`. A word-start match, not a
/// whole-word one, because a company named from its founder's name keeps the
/// name as a word stem (`Thorpedo Inc.` for Ian Thorpe). So a company is kept
/// only when its own name carries a subject term.
pub(in crate::modules::search_engines) fn extract_organisations_from_text(
    text: &str,
    terms: &[String],
) -> Vec<String> {
    // Longest variant first within each family, so the dotted / longer form
    // claims a span before the shorter form inside it can.
    let suffixes = [
        " Pty. Ltd.",
        " Pty Limited",
        " Pty Ltd",
        " Corporation",
        " Limited",
        " Inc.",
        " Ltd.",
        " Corp.",
        " Co.",
        " Inc",
        " Ltd",
        " Corp",
        " LLC",
    ];
    // SERP title separators: what sits before one is another field of the
    // title (a person's name, "Email & Phone Number"), never the company name.
    const TITLE_SEPARATORS: [&str; 7] = [" - ", " – ", " — ", " | ", " · ", "•", "›"];
    let bytes = text.as_bytes();
    // Phase 1: the suffix occurrences, one per span, as `(start, end)` byte
    // ranges. A Vec scanned linearly and sorted afterwards — deterministic, and
    // a page carries a handful of suffixes at most.
    let mut spans: Vec<(usize, usize)> = Vec::new();
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
            // The suffix must fall at a word boundary. Without this, " Inc"
            // matches inside "including"/"Incorporated", " Co" inside
            // "corporate", " Ltd" inside "Ltda", etc. — minting a garbage
            // organisation from a prose fragment. A live username scan
            // (`rhino.ryno23`) produced the org "…Repco inc" from a Yahoo
            // snippet reading "…Repco including pioneer platforms…". Advance by
            // one (not to `end`) so a genuine later suffix can still match.
            if bytes.get(end).is_some_and(u8::is_ascii_alphanumeric) {
                i += 1;
                continue;
            }
            // A shorter variant inside a span a longer one already claimed
            // (` Inc` in ` Inc.`, ` Ltd` in ` Pty Ltd`) is that same span.
            if !spans.iter().any(|&(s, e)| i < e && s < end) {
                spans.push((i, end));
            }
            i = end;
        }
    }
    spans.sort_unstable();
    // Phase 2: walk each span back over the run of name words before it.
    // Joiners a company name can carry between its capitalised words; never its
    // first word (a leading one is trimmed below).
    const CONNECTORS: [&str; 5] = ["&", "and", "of", "the", "for"];
    let is_name_word = |w: &str| {
        CONNECTORS.contains(&w) || w.starts_with(|c: char| c.is_uppercase() || c.is_ascii_digit())
    };
    let mut orgs: Vec<String> = Vec::new();
    let mut prev_end = 0;
    for (i, end) in spans {
        let before = &text[..i];
        let punct = before.rfind([',', '.', ';', '(', '\n']).map(|d| d + 1);
        // Every separator is a complete UTF-8 sequence, so `d + sep.len()` is a
        // char boundary.
        let separator = TITLE_SEPARATORS
            .iter()
            .filter_map(|sep| before.rfind(sep).map(|d| d + sep.len()))
            .max();
        // The `i-60` floor may land mid-code-point; snap forward to a boundary
        // with the canonical primitive so every slice below is valid. `i` is an
        // ASCII (space) boundary and the floor is `<= i`, so the snap never
        // overshoots `i`.
        let floor = crate::util::str_util::ceil_char_boundary(
            text,
            punct
                .max(separator)
                .unwrap_or(0)
                .max(prev_end)
                .max(i.saturating_sub(60)),
        );
        prev_end = end;
        // Word by word back from the suffix while each word is a name word.
        // `name_start` only ever moves to the start of a whole word, so a word
        // the floor cuts through is never taken.
        let mut name_start = i;
        loop {
            let head = &text[floor..name_start];
            let trimmed = head.trim_end();
            // Past the first step a word must be whitespace-separated from the
            // one after it (a `-`/`'` inside a word is part of the word).
            if name_start != i && trimmed.len() == head.len() {
                break;
            }
            let word_at = trimmed.rfind(char::is_whitespace).map_or(0, |d| {
                d + trimmed[d..].chars().next().map_or(1, char::len_utf8)
            });
            let word = &trimmed[word_at..];
            if word.is_empty()
                || !is_name_word(word)
                || (word_at == 0 && floor > 0 && {
                    // The floor cut into a word (no whitespace between the floor
                    // and it): only a bound that ends at a word edge admits it.
                    text[..floor].ends_with(|c: char| c.is_alphanumeric())
                })
            {
                break;
            }
            name_start = floor + word_at;
        }
        let mut org = text[name_start..end].trim();
        // A connector opens no company name (`of Harbour Holdings Pty Ltd`).
        while let Some((first, rest)) = org.split_once(char::is_whitespace)
            && CONNECTORS.contains(&first)
        {
            org = rest.trim_start();
        }
        if org.len() >= 5 && org.starts_with(|c: char| c.is_ascii_uppercase()) {
            // Lowercase once per candidate rather than once per term.
            let org_lower = org.to_lowercase();
            let names_a_term = |t: &String| {
                org_lower
                    .split(|c: char| !c.is_alphanumeric())
                    .any(|w| !t.is_empty() && w.starts_with(t.as_str()))
            };
            if terms.iter().any(names_a_term) && !orgs.iter().any(|o| o == org) {
                orgs.push(org.to_string());
            }
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
            target: "huntsman::parser",
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
    // `util::extract::phones` is E.164-shaped, so AU DOMESTIC formats a SERP
    // snippet routinely carries — `04xx xxx xxx` mobiles, `0x xxxx xxxx` area
    // numbers, and `1300`/`1800` service lines — are silently dropped (they have
    // no `+NN` prefix). Union in `util::address_au::extract_phones`, which
    // recognises exactly those, so an AU subject's phone in a result snippet
    // becomes a Phone entity instead of being lost. E.164 numbers stay FIRST
    // (foreign `+NN` coverage unchanged); only AU numbers not already present
    // are appended, preserving dedup + first-seen order.
    for au in crate::util::address_au::extract_phones(text) {
        if !phones.contains(&au) {
            phones.push(au);
        }
    }
    if phones.len() > 300 {
        tracing::warn!(
            target: "huntsman::parser",
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
/// Trim trailing prose punctuation from a URL lifted out of free text, while
/// keeping a trailing `)`/`]` that is BALANCED within the URL.
///
/// Sentence punctuation (`. , ! ? ; :`) and a DANGLING close bracket (a `)` with
/// no matching `(` inside the candidate — the `(see https://x/y)` prose case) are
/// stripped. A MATCHED close bracket is kept, so Wikipedia-style paths like
/// `/wiki/Rust_(programming_language)` survive intact instead of being truncated
/// to a broken `…_(programming_language` duplicate. Standard linkifier rule
/// (GitHub/autolink use the same balance test). Pure.
fn trim_trailing_url_punct(s: &str) -> &str {
    let mut end = s.len();
    loop {
        let sub = &s[..end];
        let Some(last) = sub.chars().next_back() else {
            break;
        };
        let strip = match last {
            '.' | ',' | '!' | '?' | ';' | ':' => true,
            ')' => sub.matches(')').count() > sub.matches('(').count(),
            ']' => sub.matches(']').count() > sub.matches('[').count(),
            _ => false,
        };
        if strip {
            end -= last.len_utf8();
        } else {
            break;
        }
    }
    &s[..end]
}

pub(in crate::modules::search_engines) fn extract_urls_from_text(text: &str) -> Vec<String> {
    const MAX_SNIPPET_URLS: usize = 12;
    let mut out: Vec<String> = Vec::new();
    let mut rest = text;
    while let Some(pos) = rest.find("http") {
        let cand = &rest[pos..];
        if crate::util::url_util::is_absolute_http_url(cand) {
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
            // Trim trailing punctuation that commonly abuts a URL in prose,
            // but keep a trailing `)`/`]` that is BALANCED inside the URL —
            // Wikipedia-style paths (`/wiki/Rust_(programming_language)`,
            // `_(disambiguation)`, `_(film)`) legitimately end in `)`. A blanket
            // strip truncated those to a broken duplicate node.
            let url = trim_trailing_url_punct(&cand[..end]);
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
