use super::*;
use std::collections::HashSet;

fn cands(domain: &str) -> HashSet<String> {
    permutations(domain, 1000)
        .into_iter()
        .map(|(d, _)| d)
        .collect()
}

#[test]
fn generates_classic_typo_classes() {
    let c = cands("example.com");
    // omission, transposition, repetition, homoglyph, hyphenation, tld-swap.
    assert!(c.contains("exmple.com"), "omission");
    assert!(c.contains("examlpe.com"), "transposition (pl→lp)");
    assert!(c.contains("eexample.com"), "repetition");
    assert!(c.contains("exampl3.com"), "homoglyph e→3");
    assert!(c.contains("ex-ample.com"), "hyphenation");
    assert!(c.contains("example.net"), "tld-swap");
    assert!(c.contains("example.com.au"), "au tld-swap");
}

#[test]
fn never_returns_the_original_and_all_valid() {
    let perms = permutations("example.com", 1000);
    for (d, _) in &perms {
        assert_ne!(d, "example.com", "must not emit the original");
        // Every candidate's first label is a valid LDH label, or an `xn--` ACE
        // label (validated by the punycode layer, whose internal `--` the
        // stricter `is_valid_label` rejects).
        let (label, _) = d.split_once('.').unwrap();
        assert!(
            is_valid_label(label) || label.starts_with("xn--"),
            "invalid label in {d}"
        );
    }
    // Deduplicated.
    let set: HashSet<_> = perms.iter().map(|(d, _)| d).collect();
    assert_eq!(set.len(), perms.len(), "candidates must be unique");
}

#[test]
fn handles_au_second_level_suffix() {
    // For a .com.au target, the registrable suffix is com.au and the label
    // is permuted against it; tld-swap still offers other suffixes.
    let c = cands("acme.com.au");
    assert!(c.contains("acm.com.au"), "omission keeps com.au suffix");
    assert!(c.contains("acme.com"), "tld-swap to .com");
    assert!(!c.contains("acme.com.au"), "original excluded");
}

#[test]
fn respects_cap_and_handles_degenerate_input() {
    assert!(permutations("example.com", 5).len() <= 5);
    assert!(permutations("", 100).is_empty());
    assert!(
        permutations("localhost", 100).is_empty(),
        "no dot → no suffix"
    );
}

#[test]
fn bitsquat_only_yields_valid_chars() {
    // Every bitsquat candidate must still be a valid label (the filter drops
    // bit-flips that land on punctuation/control bytes).
    for (d, tech) in permutations("example.com", 1000) {
        if tech == "bitsquat" {
            let (label, _) = d.split_once('.').unwrap();
            assert!(is_valid_label(label), "invalid bitsquat label {label}");
        }
    }
}

#[test]
fn keyboard_neighbors_maps_qwerty_adjacency() {
    assert_eq!(keyboard_neighbors('a'), "qwsz");
    assert_eq!(keyboard_neighbors('s'), "awedxz");
    assert_eq!(keyboard_neighbors('q'), "wa");
    assert_eq!(keyboard_neighbors('p'), "ol");
    assert_eq!(keyboard_neighbors('z'), "asx");
}

#[test]
fn keyboard_neighbors_unknown_char_is_empty() {
    // Anything outside the lowercase QWERTY table falls through to "".
    assert_eq!(keyboard_neighbors('1'), "");
    assert_eq!(keyboard_neighbors('.'), "");
    assert_eq!(keyboard_neighbors('A'), "");
}

#[test]
fn homoglyphs_maps_ascii_lookalikes() {
    assert_eq!(homoglyphs('o'), ['0'].as_slice());
    assert_eq!(homoglyphs('0'), ['o'].as_slice());
    assert_eq!(homoglyphs('l'), ['1', 'i'].as_slice());
    assert_eq!(homoglyphs('i'), ['1', 'l'].as_slice());
    assert_eq!(homoglyphs('e'), ['3'].as_slice());
}

#[test]
fn homoglyphs_unknown_char_is_empty_slice() {
    let empty: &[char] = &[];
    assert_eq!(homoglyphs('x'), empty);
    assert_eq!(homoglyphs('.'), empty);
}

#[test]
fn covers_the_full_dnstwist_grade_fuzzer_set() {
    let techniques: HashSet<&'static str> = permutations("example.com", 5000)
        .into_iter()
        .map(|(_, t)| t)
        .collect();
    for t in [
        "homoglyph-idn",
        "homoglyph",
        "omission",
        "transposition",
        "repetition",
        "vowel-swap",
        "keyboard",
        "insertion",
        "bitsquat",
        "hyphenation",
        "addition",
        "tld-swap",
    ] {
        assert!(techniques.contains(t), "missing fuzzer: {t}");
    }
}

#[test]
fn idn_homoglyph_is_emitted_as_punycode() {
    // The Cyrillic-'е' (U+0435) lookalike of "example" encodes to xn--xample-2of
    // (proven against the canonical Punycode vectors in punycode::tests).
    let c = cands("example.com");
    assert!(
        c.contains("xn--xample-2of.com"),
        "Cyrillic-е homoglyph must be emitted in its registrable xn-- form"
    );
    // Every homoglyph-idn candidate is an `xn--` ACE label on the original suffix
    // — never a raw Unicode hostname no resolver would accept.
    for (d, tech) in permutations("example.com", 5000) {
        if tech == "homoglyph-idn" {
            let (label, suffix) = d.split_once('.').unwrap();
            assert!(label.starts_with("xn--"), "ACE label expected, got {d}");
            assert!(label.is_ascii(), "ACE label must be ASCII, got {d}");
            assert_eq!(suffix, "com");
        }
    }
}

#[test]
fn new_typo_classes_are_generated() {
    let c = cands("example.com");
    assert!(c.contains("exomple.com"), "vowel-swap a→o");
    assert!(c.contains("examples.com"), "addition (append s)");
    assert!(c.contains("example1.com"), "addition (append digit)");
    assert!(c.contains("wexample.com"), "insertion (keyboard-adjacent w before e)");
}

#[test]
fn candidates_are_ranked_most_similar_first() {
    let perms = permutations("example.com", 1000);
    let pos = |needle: &str| perms.iter().position(|(d, _)| d == needle);
    // A one-edit omission must rank ahead of a far-off TLD swap.
    let close = pos("exmple.com").expect("omission present"); // distance 1
    let far = pos("example.online").expect("tld-swap present"); // com→online, far
    assert!(
        close < far,
        "distance-1 omission ({close:?}) must rank before a distant TLD swap ({far:?})"
    );
}

#[test]
fn confusables_are_non_ascii_and_curated() {
    // Each confusable is a genuine non-ASCII lookalike (so it forces punycode),
    // and the table carries no duplicates within a key.
    for ascii in 'a'..='z' {
        let set = confusables(ascii);
        for &g in set {
            assert!(!g.is_ascii(), "{ascii}: confusable {g:?} must be non-ASCII");
        }
        let unique: HashSet<char> = set.iter().copied().collect();
        assert_eq!(unique.len(), set.len(), "{ascii}: duplicate confusable");
    }
}

#[test]
fn levenshtein_matches_known_distances() {
    assert_eq!(levenshtein("example", "example"), 0);
    assert_eq!(levenshtein("example", "exmple"), 1); // omission
    assert_eq!(levenshtein("example", "exapmle"), 2); // transposition = 2 subs
    // A single Cyrillic-for-Latin swap is distance 1 (scalar, not byte, compare).
    assert_eq!(levenshtein("example", "\u{0435}xample"), 1);
}

// -- is_genuine_no_record / all_candidates_failed_transport (T2.163) --------
//
// T2.163 regression: the spawned task's `_ => None` catch-all previously
// collapsed EVERY NetError kind (Timeout, Io, Busy, NoConnections, an
// unrelated ResponseCode) into the same outcome as a genuine NXDOMAIN "not
// registered" answer, so a total DNS-transport outage during a scan produced
// zero findings indistinguishable from "none of the 128 lookalikes are
// registered". Constructed against real hickory_resolver::net types — no
// live DNS (Rule 3).

#[test]
fn is_genuine_no_record_false_for_real_transport_and_protocol_failures() {
    use hickory_resolver::net::NetError;
    for e in [
        NetError::Timeout,
        NetError::Busy,
        NetError::NoConnections,
        NetError::Message("synthetic proto failure"),
    ] {
        assert!(
            !is_genuine_no_record(&e),
            "{e:?} is a real resolution failure, not a genuine 'not registered' answer"
        );
    }
}

#[test]
fn is_genuine_no_record_true_for_nxdomain_and_no_records_found() {
    use hickory_resolver::net::{DnsError, NetError, NoRecords};
    use hickory_resolver::proto::op::{Query, ResponseCode};
    use hickory_resolver::proto::rr::{Name, RecordType};

    let query = Query::query(Name::root(), RecordType::A);
    let nxdomain = NetError::Dns(DnsError::NoRecordsFound(NoRecords::new(
        query.clone(),
        ResponseCode::NXDomain,
    )));
    assert!(
        is_genuine_no_record(&nxdomain),
        "a genuine NXDOMAIN must read as 'not registered', not a failure"
    );

    let no_records = NetError::Dns(DnsError::NoRecordsFound(NoRecords::new(
        query,
        ResponseCode::NoError,
    )));
    assert!(
        is_genuine_no_record(&no_records),
        "a NoError/no-records answer must also read as 'not registered'"
    );
}

#[test]
fn is_genuine_no_record_false_for_an_unrelated_response_code() {
    use hickory_resolver::net::{DnsError, NetError};
    use hickory_resolver::proto::op::ResponseCode;

    let servfail = NetError::Dns(DnsError::ResponseCode(ResponseCode::ServFail));
    assert!(
        !is_genuine_no_record(&servfail),
        "a SERVFAIL response code must not read as 'not registered'"
    );
}

#[test]
fn all_candidates_failed_transport_only_on_total_outage_with_no_hits() {
    assert!(all_candidates_failed_transport(128, 128, 0));
    // Mixed: some candidates genuinely answered NXDOMAIN, not a total outage.
    assert!(!all_candidates_failed_transport(10, 128, 0));
    // Any real hit, even alongside transport failures, is not an outage.
    assert!(!all_candidates_failed_transport(127, 128, 1));
    // The vacuous case (no candidates generated) must never be a false outage.
    assert!(!all_candidates_failed_transport(0, 0, 0));
}
