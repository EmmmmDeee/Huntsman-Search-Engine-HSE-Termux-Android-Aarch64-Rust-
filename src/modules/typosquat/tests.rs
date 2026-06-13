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
        // Every candidate is a dotted hostname with valid labels.
        let (label, _) = d.split_once('.').unwrap();
        assert!(is_valid_label(label), "invalid label in {d}");
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
