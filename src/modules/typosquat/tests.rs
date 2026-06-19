use super::*;
use std::collections::HashSet;

fn cands(domain: &str) -> HashSet<String> {
    permutations(domain, 2000)
        .into_iter()
        .map(|(d, _)| d)
        .collect()
}

fn cands_with_tech(domain: &str) -> Vec<(String, &'static str)> {
    permutations(domain, 2000)
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
fn combo_squat_generates_brand_plus_word() {
    // Combo-squatting is the #1 real-world phishing pattern.
    // loginexample.com, examplelogin.com, example-login.com, login-example.com
    let c = cands("example.com");
    assert!(c.contains("examplelogin.com"), "label+word");
    assert!(c.contains("loginexample.com"), "word+label");
    assert!(c.contains("example-login.com"), "label-word hyphenated");
    assert!(c.contains("login-example.com"), "word-label hyphenated");
    assert!(c.contains("examplesecure.com"), "secure combo");
    assert!(c.contains("exampleverify.com"), "verify combo");
}

#[test]
fn vowel_swap_generates_plausible_confusables() {
    // "paypal" → peypal, piypal, etc.
    let c = cands("paypal.com");
    // 'a' at index 1 → other vowels
    assert!(c.contains("peypal.com"), "a→e vowel swap");
    assert!(c.contains("piypal.com"), "a→i vowel swap");
    assert!(c.contains("poypal.com"), "a→o vowel swap");
    assert!(c.contains("puypal.com"), "a→u vowel swap");
}

#[test]
fn addition_generates_insert_variants() {
    // Insert a keyboard-adjacent char at each position.
    // "acme": insert 'q' (adjacent to 'a') at position 0 → "qacme"
    let c = cands("acme.com");
    // 'a' neighbors are "qwsz" so 'q' inserted at pos 0 → "qacme"
    assert!(
        c.iter().any(|d| d.starts_with('q') || d.starts_with('w')),
        "addition variants present"
    );
}

#[test]
fn never_returns_the_original_and_all_valid() {
    let perms = permutations("example.com", 2000);
    for (d, _) in &perms {
        assert_ne!(d, "example.com", "must not emit the original");
        // Every candidate is a dotted hostname with a valid first label.
        let (label, _) = d.split_once('.').unwrap();
        assert!(is_valid_label(label), "invalid label in {d}");
    }
    // Deduplicated.
    let set: HashSet<_> = perms.iter().map(|(d, _)| d).collect();
    assert_eq!(set.len(), perms.len(), "candidates must be unique");
}

#[test]
fn handles_au_second_level_suffix() {
    let c = cands("acme.com.au");
    assert!(c.contains("acm.com.au"), "omission keeps com.au suffix");
    assert!(c.contains("acme.com"), "tld-swap to .com");
    assert!(!c.contains("acme.com.au"), "original excluded");
    // Combo-squat should work on the .com.au suffix too.
    assert!(c.contains("acmelogin.com.au"), "combo-squat on .com.au");
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
    for (d, tech) in permutations("example.com", 2000) {
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
fn combo_squat_sorts_before_lower_signal_techniques() {
    // Combo-squat is highest-threat and should appear first in the output
    // before omission/transposition so that the cap retains it under pressure.
    let perms = cands_with_tech("example.com");
    let first_combo = perms.iter().position(|(_, t)| *t == "combo-squat");
    let first_omission = perms.iter().position(|(_, t)| *t == "omission");
    assert!(
        first_combo < first_omission,
        "combo-squat must precede omission (cap ordering)"
    );
}

#[test]
fn technique_confidence_tiers_are_ordered() {
    // combo-squat > homoglyph > keyboard > vowel-swap > bitsquat.
    assert!(technique_confidence("combo-squat") > technique_confidence("homoglyph"));
    assert!(technique_confidence("homoglyph") > technique_confidence("keyboard"));
    assert!(technique_confidence("keyboard") > technique_confidence("vowel-swap"));
    assert!(technique_confidence("vowel-swap") > technique_confidence("bitsquat"));
}

#[test]
fn technique_confidence_in_valid_range() {
    for tech in &[
        "combo-squat", "homoglyph", "keyboard", "vowel-swap",
        "transposition", "omission", "repetition", "addition",
        "hyphenation", "tld-swap", "bitsquat",
    ] {
        let c = technique_confidence(tech);
        assert!(
            (0.0..=1.0).contains(&c),
            "technique {tech} confidence {c} out of range"
        );
    }
}

#[test]
fn no_vowel_swap_for_no_vowel_label() {
    // "brk" has no vowels — vowel-swap should produce no candidates.
    let perms = cands_with_tech("brk.com");
    assert!(
        perms.iter().all(|(_, t)| *t != "vowel-swap"),
        "no vowel-swap candidates for vowel-free label"
    );
}

#[test]
fn combo_word_coverage_includes_key_phishing_terms() {
    // Guard against accidentally removing high-signal words from COMBO_WORDS.
    for word in &["login", "secure", "account", "verify", "bank", "pay"] {
        assert!(
            COMBO_WORDS.contains(word),
            "COMBO_WORDS must include high-signal phishing term: {word}"
        );
    }
}

#[test]
fn tld_swap_covers_au_suffixes() {
    let c = cands("example.com");
    assert!(c.contains("example.com.au"), "com.au in swap list");
    assert!(c.contains("example.net.au"), "net.au in swap list");
    assert!(c.contains("example.org.au"), "org.au in swap list");
}

#[tokio::test]
async fn module_metadata() {
    let m = Typosquat;
    assert!(m.accepts(&Target::new(TargetKind::Domain, "example.com")));
    assert!(!m.accepts(&Target::new(TargetKind::Email, "x@example.com")));
    assert!(m.max_timeout_ms() >= 45_000, "timeout must cover full DNS + MX sweep");
}
