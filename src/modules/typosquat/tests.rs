use super::*;
use std::collections::{HashMap, HashSet};

/// Collect all candidates for `domain` (up to 2000) as a set of FQDNs.
fn cands(domain: &str) -> HashSet<String> {
    permutations(domain, 2000)
        .into_iter()
        .map(|(d, _)| d)
        .collect()
}

/// Collect candidates tagged by technique.
fn cands_by_technique(domain: &str) -> HashMap<&'static str, Vec<String>> {
    let mut map: HashMap<&'static str, Vec<String>> = HashMap::new();
    for (d, tech) in permutations(domain, 2000) {
        map.entry(tech).or_default().push(d);
    }
    map
}

// ── Regression: classic technique classes still present ──────────────────────

#[test]
fn generates_classic_typo_classes() {
    let c = cands("example.com");
    assert!(c.contains("exmple.com"), "omission");
    assert!(c.contains("examlpe.com"), "transposition (pl→lp)");
    assert!(c.contains("eexample.com"), "repetition");
    assert!(c.contains("exampl3.com"), "homoglyph e→3");
    assert!(c.contains("ex-ample.com"), "hyphenation");
    assert!(c.contains("example.net"), "tld-swap");
    assert!(c.contains("example.com.au"), "au tld-swap");
}

#[test]
fn never_returns_original_and_all_valid() {
    let perms = permutations("example.com", 2000);
    for (d, _) in &perms {
        assert_ne!(d, "example.com", "must not emit the original");
        let (label, _) = d.split_once('.').unwrap();
        assert!(is_valid_label(label), "invalid label in {d}");
    }
    let set: HashSet<_> = perms.iter().map(|(d, _)| d).collect();
    assert_eq!(set.len(), perms.len(), "candidates must be unique");
}

#[test]
fn handles_au_second_level_suffix() {
    let c = cands("acme.com.au");
    assert!(c.contains("acm.com.au"), "omission keeps com.au suffix");
    assert!(c.contains("acme.com"), "tld-swap to .com");
    assert!(!c.contains("acme.com.au"), "original excluded");
}

#[test]
fn respects_cap_and_handles_degenerate_input() {
    assert!(permutations("example.com", 5).len() <= 5);
    assert!(permutations("", 100).is_empty());
    assert!(permutations("localhost", 100).is_empty(), "no dot → no suffix");
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

// ── New techniques ────────────────────────────────────────────────────────────

#[test]
fn addition_generates_keyword_variants() {
    let c = cands("example.com");
    // Prefix without hyphen
    assert!(c.contains("loginexample.com"), "prefix no-sep");
    assert!(c.contains("myexample.com"), "prefix 'my' no-sep");
    // Prefix with hyphen
    assert!(c.contains("login-example.com"), "prefix with hyphen");
    assert!(c.contains("my-example.com"), "prefix 'my' with hyphen");
    // Suffix without hyphen
    assert!(c.contains("examplelogin.com"), "suffix 'login' no-sep");
    assert!(c.contains("examplesecure.com"), "suffix 'secure' no-sep");
    // Suffix with hyphen
    assert!(c.contains("example-login.com"), "suffix 'login' with hyphen");
    assert!(c.contains("example-secure.com"), "suffix 'secure' with hyphen");
}

#[test]
fn addition_is_highest_priority_in_cap() {
    // With a cap of 1 we must get an addition candidate.
    let top1 = permutations("example.com", 1);
    assert_eq!(top1.len(), 1);
    assert_eq!(top1[0].1, "addition", "addition should be technique #1 under cap");
}

#[test]
fn vowel_swap_produces_all_substitutions() {
    // 'example' has vowels at: e(0), a(2), e(6)
    // e→{a,i,o,u} · a→{e,i,o,u} · e→{a,i,o,u}
    let c = cands("example.com");
    // e(pos 0) swapped
    assert!(c.contains("axample.com"), "e→a at pos 0");
    assert!(c.contains("ixample.com"), "e→i at pos 0");
    assert!(c.contains("oxample.com"), "e→o at pos 0");
    assert!(c.contains("uxample.com"), "e→u at pos 0");
    // a(pos 2) swapped: e,x,[vowel],m,p,l,e
    assert!(c.contains("exemple.com"), "a→e vowel swap");
    assert!(c.contains("exomple.com"), "a→o vowel swap");
    assert!(c.contains("exumple.com"), "a→u vowel swap");
    assert!(c.contains("eximple.com"), "a→i vowel swap");
    // e(pos 6) swapped: exampl[vowel]
    assert!(c.contains("exampla.com"), "e→a at pos 6");
    assert!(c.contains("examplo.com"), "e→o at pos 6");
}

#[test]
fn digraph_rn_to_m_substitution() {
    // 'barn.com' has 'rn' → should produce 'bam.com' via digraph contraction
    let c = cands("barn.com");
    assert!(c.contains("bam.com"), "rn→m contraction");
}

#[test]
fn digraph_m_to_rn_expansion() {
    // 'flame.com' has 'm' → should produce 'flarne.com' via digraph expansion
    let c = cands("flame.com");
    assert!(c.contains("flarne.com"), "m→rn expansion");
}

#[test]
fn digraph_w_to_vv_and_vv_to_w() {
    // 'swift.com' has 'w' → 'svvift.com'
    let c = cands("swift.com");
    assert!(c.contains("svvift.com"), "w→vv expansion");

    // 'savvy.com' has 'vv' (positions 2,3) → 'sawy.com'
    let c2 = cands("savvy.com");
    assert!(c2.contains("sawy.com"), "vv→w contraction");
}

#[test]
fn digraph_cl_to_d_and_d_to_cl() {
    // 'cloud.com' has 'cl' → 'doud.com'
    let c = cands("cloud.com");
    assert!(c.contains("doud.com"), "cl→d contraction");

    // 'node.com' has 'd' → 'nocle.com'
    let c2 = cands("node.com");
    assert!(c2.contains("nocle.com"), "d→cl expansion");
}

#[test]
fn insertion_covers_all_positions() {
    // For 'ab.com' (2 chars), positions 0,1,2 × 26 letters = 78 insertion variants
    // Verify a few representative ones.
    let c = cands("ab.com");
    assert!(c.contains("aab.com"), "insert 'a' at pos 0");
    assert!(c.contains("aab.com") || c.contains("bab.com"), "some insertion at pos 0");
    assert!(c.contains("azb.com"), "insert 'z' between a and b");
    assert!(c.contains("abz.com"), "insert 'z' at end");
}

#[test]
fn insertion_technique_label() {
    let by_tech = cands_by_technique("ab.com");
    let insertions = by_tech.get("insertion").expect("insertion technique present");
    // 3 positions × 26 letters = 78; dedup may remove a few near other techniques
    assert!(
        insertions.len() >= 70,
        "expected ≥70 insertion variants, got {}",
        insertions.len()
    );
}

#[test]
fn hyphen_removal_strips_hyphens() {
    // 'pay-pal.com' has one hyphen → 'paypal.com'
    let c = cands("pay-pal.com");
    assert!(c.contains("paypal.com"), "single hyphen removed");
}

#[test]
fn hyphen_removal_multi_hyphen() {
    // 'a-b-c.com' has two hyphens
    let c = cands("a-b-c.com");
    // Remove first hyphen: 'ab-c.com'
    assert!(c.contains("abc.com") || c.contains("ab-c.com"), "at least one hyphen removed");
    // Remove all: 'abc.com'
    assert!(c.contains("abc.com"), "all hyphens removed");
}

#[test]
fn plural_add_and_remove_s() {
    // 'example.com' → 'examples.com'
    let c = cands("example.com");
    assert!(c.contains("examples.com"), "trailing 's' added");

    // 'apps.com' → 'app.com'
    let c2 = cands("apps.com");
    assert!(c2.contains("app.com"), "trailing 's' removed");
}

#[test]
fn combo_homoglyph_applies_two_substitutions() {
    // 'example' has homoglyphs at: e(0)→3, a(2)→4, l(5)→1/i, e(6)→3
    // Combo (0,2): e→3 and a→4 → '3x4mple.com'
    let c = cands("example.com");
    assert!(c.contains("3x4mple.com"), "combo e→3 and a→4");
    // Combo (0,6): e→3 and e→3 → '3xampl3.com'
    assert!(c.contains("3xampl3.com"), "combo e→3 and e→3");
}

#[test]
fn combo_homoglyph_not_generated_with_one_position() {
    // 'fxyz.com': f/x/y have no homoglyphs; only z→2 → one homoglyph position → no combo
    let by_tech = cands_by_technique("fxyz.com");
    assert!(
        !by_tech.contains_key("combo-homoglyph"),
        "combo-homoglyph should not fire with only 1 homoglyph position"
    );
}

#[test]
fn expanded_tld_list_covers_phishing_favourites() {
    let c = cands("example.com");
    // New ccTLDs in the expanded list
    assert!(c.contains("example.cn"), "cn TLD");
    assert!(c.contains("example.ru"), "ru TLD");
    assert!(c.contains("example.info"), "info TLD");
    assert!(c.contains("example.biz"), "biz TLD");
    assert!(c.contains("example.pw"), "pw TLD");
    assert!(c.contains("example.co.uk"), "co.uk TLD");
    assert!(c.contains("example.eu"), "eu TLD");
}

#[test]
fn expanded_homoglyph_table() {
    let c = cands("test.com");
    // t→7 (new entry)
    assert!(c.contains("7est.com"), "t→7");
    // u↔v (new entries) — 'test' has no u/v, use 'value.com'
    let c2 = cands("value.com");
    assert!(c2.contains("valae.com") || c2.contains("valoe.com"), "vowel swap in 'value'");
    assert!(c2.contains("valaue.com") || c2.contains("valvue.com"), "u→v or similar in value");
}

#[test]
fn homoglyph_u_v_bidirectional() {
    // 'uver.com': u→v → 'vver.com'
    let c = cands("uver.com");
    assert!(c.contains("vver.com"), "u→v");
    // 'ever.com': v→u is not in 'ever' (no v). Use 'vibe.com'
    let c2 = cands("vibe.com");
    assert!(c2.contains("uibe.com"), "v→u");
}

#[test]
fn homoglyph_reverse_digit_to_letter() {
    // '3com.com': 3→e → 'ecom.com'
    let c = cands("3com.com");
    assert!(c.contains("ecom.com"), "3→e");
    // '5pa.com': 5→s → 'spa.com'
    let c2 = cands("5pa.com");
    assert!(c2.contains("spa.com"), "5→s");
}

#[test]
fn technique_confidence_ordering() {
    // addition > homoglyph > keyboard > bitsquat
    assert!(
        technique_confidence("addition", false) > technique_confidence("homoglyph", false),
        "addition > homoglyph"
    );
    assert!(
        technique_confidence("homoglyph", false) > technique_confidence("keyboard", false),
        "homoglyph > keyboard"
    );
    assert!(
        technique_confidence("keyboard", false) > technique_confidence("bitsquat", false),
        "keyboard > bitsquat"
    );
}

#[test]
fn mx_only_reduces_confidence() {
    for tech in &[
        "addition",
        "homoglyph",
        "keyboard",
        "omission",
        "bitsquat",
    ] {
        let a = technique_confidence(tech, false);
        let mx = technique_confidence(tech, true);
        assert!(mx < a, "mx-only confidence must be lower than A-record for {tech}");
        assert!(mx >= 0.45, "mx-only confidence floor 0.45 for {tech}");
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
fn homoglyphs_maps_expanded_ascii_lookalikes() {
    assert_eq!(homoglyphs('o'), ['0'].as_slice());
    assert_eq!(homoglyphs('0'), ['o'].as_slice());
    assert_eq!(homoglyphs('l'), ['1', 'i'].as_slice());
    assert_eq!(homoglyphs('i'), ['1', 'l'].as_slice());
    assert_eq!(homoglyphs('e'), ['3'].as_slice());
    assert_eq!(homoglyphs('3'), ['e'].as_slice());
    assert_eq!(homoglyphs('t'), ['7'].as_slice());
    assert_eq!(homoglyphs('7'), ['t'].as_slice());
    assert_eq!(homoglyphs('u'), ['v'].as_slice());
    assert_eq!(homoglyphs('v'), ['u'].as_slice());
    assert_eq!(homoglyphs('g'), ['9', 'q'].as_slice());
}

#[test]
fn homoglyphs_unknown_char_is_empty_slice() {
    let empty: &[char] = &[];
    assert_eq!(homoglyphs('x'), empty);
    assert_eq!(homoglyphs('.'), empty);
    assert_eq!(homoglyphs('A'), empty);
}

#[test]
fn is_valid_label_accepts_valid_and_rejects_invalid() {
    assert!(is_valid_label("example"));
    assert!(is_valid_label("pay-pal"));
    assert!(is_valid_label("a1b2c3"));
    assert!(!is_valid_label(""), "empty");
    assert!(!is_valid_label("-bad"), "leading hyphen");
    assert!(!is_valid_label("bad-"), "trailing hyphen");
    assert!(!is_valid_label("ba--d"), "double hyphen");
    assert!(!is_valid_label("BAD"), "uppercase");
    assert!(!is_valid_label("b.d"), "contains dot");
    assert!(!is_valid_label(&"a".repeat(64)), "too long");
    assert!(is_valid_label(&"a".repeat(63)), "exactly 63 ok");
}

#[test]
fn all_techniques_produce_valid_fqdns() {
    for (d, tech) in permutations("paypal.com", 2000) {
        let (label, _) = d
            .split_once('.')
            .unwrap_or_else(|| panic!("no dot in candidate '{d}' (technique={tech})"));
        assert!(
            is_valid_label(label),
            "invalid label '{label}' from technique '{tech}' → '{d}'"
        );
    }
}

#[test]
fn candidate_count_grows_with_techniques() {
    // With 15 techniques, 'example.com' (7 chars) should produce far more
    // than the old ~130-candidate set.  With cap=2000 we should see 350+
    // after deduplication (bitsquat/vowel-swap/keyboard/insertion collisions
    // account for ~20-25 fewer unique entries than raw generation count).
    let perms = permutations("example.com", 2000);
    assert!(
        perms.len() >= 350,
        "expected ≥350 candidates for 7-char domain, got {}",
        perms.len()
    );
}

#[test]
fn techniques_represented_in_output() {
    // 'example.com' covers all 13 testable techniques:
    // - digraph fires because 'm' expands to 'rn'
    // - hyphen-removal is skipped here (no hyphens); tested in dedicated tests
    let by_tech = cands_by_technique("example.com");
    for required in &[
        "addition",
        "homoglyph",
        "digraph",
        "vowel-swap",
        "keyboard",
        "omission",
        "transposition",
        "repetition",
        "bitsquat",
        "hyphenation",
        "plural",
        "insertion",
        "tld-swap",
    ] {
        assert!(
            by_tech.contains_key(*required),
            "technique '{required}' missing from example.com permutations"
        );
    }
}
