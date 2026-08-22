// Tests for the embedded IEEE registry tier.
//
// Plain `//` rather than `//!`: `include!`d into a `mod tests` block.

use super::*;

#[test]
fn the_blob_is_well_formed_and_substantial() {
    // A blob that failed validation degrades silently to "no IEEE tier", which
    // would look exactly like the 0.3%-coverage state this tier exists to fix.
    // Assert it actually loaded.
    let n = registry_len();
    assert!(
        n > 30_000,
        "the registry should hold tens of thousands of assignments, got {n}"
    );
}

#[test]
fn the_prefix_table_is_sorted_which_the_binary_search_depends_on() {
    // An unsorted table does not error — it silently returns the wrong vendor
    // or a spurious miss, which is the worst possible failure for attribution.
    let l = layout().expect("blob is valid");
    let mut prev = 0u32;
    for i in 0..l.count {
        let p = le_u32(l.prefixes + i * 4).expect("in bounds");
        assert!(
            p > prev || i == 0,
            "prefixes must ascend strictly; index {i} has {p:06X} after {prev:06X}"
        );
        assert!(p <= 0x00FF_FFFF, "an OUI is 24 bits, got {p:08X}");
        prev = p;
    }
}

#[test]
fn every_vendor_string_is_valid_utf8_and_non_empty() {
    // Walked in full rather than sampled: a single bad offset yields `None` at
    // lookup time, which reads as "unregistered" and is indistinguishable from
    // a genuine miss.
    let l = layout().expect("blob is valid");
    let mut resolved = 0usize;
    for i in 0..l.count {
        let p = le_u32(l.prefixes + i * 4).expect("in bounds");
        let v = vendor_for(p).unwrap_or_else(|| panic!("index {i} ({p:06X}) failed to resolve"));
        assert!(!v.is_empty(), "index {i} ({p:06X}) has an empty vendor");
        resolved += 1;
    }
    assert_eq!(resolved, l.count, "every assignment must resolve");
}

#[test]
fn known_assignments_resolve_to_their_registered_holder() {
    // Spot-checks against well-known allocations. These are stable public
    // registry facts, so a change here means the blob was regenerated from
    // something other than the IEEE MA-L list.
    let apple = vendor_for(0x00_1451).expect("Apple allocation is registered");
    assert!(
        apple.to_lowercase().contains("apple"),
        "00:14:51 is an Apple allocation, got {apple:?}"
    );
    let cisco = vendor_for(0x00_000C).expect("Cisco allocation is registered");
    assert!(
        cisco.to_lowercase().contains("cisco"),
        "00:00:0C is a Cisco allocation, got {cisco:?}"
    );
}

#[test]
fn an_unassigned_prefix_is_a_clean_miss() {
    // The registry is sparse; a gap must return None rather than the
    // neighbouring entry, which is the classic off-by-one in a hand-written
    // binary search.
    // `10:10:10` and `20:20:20` are in no IEEE registry. `00:00:00` is NOT a
    // valid negative case despite looking like one — it is a genuine Xerox
    // allocation, which is exactly the sort of assumption this tier exists to
    // stop the codebase making.
    assert_eq!(vendor_for(0x10_1010), None, "not an allocation");
    assert_eq!(vendor_for(0x20_2020), None, "not an allocation");
    assert!(vendor_for(0x00_0000).is_some(), "00:00:00 IS assigned");
}

#[test]
fn the_search_finds_the_first_and_last_entries() {
    // The two indices a binary search is most likely to miss.
    let l = layout().expect("blob is valid");
    let first = le_u32(l.prefixes).expect("in bounds");
    let last = le_u32(l.prefixes + (l.count - 1) * 4).expect("in bounds");
    assert!(vendor_for(first).is_some(), "first entry {first:06X}");
    assert!(vendor_for(last).is_some(), "last entry {last:06X}");
}

#[test]
fn lookup_is_a_pure_function_of_its_input() {
    // The layout is memoised in a OnceLock; a first call that poisoned or
    // mis-initialised it would show up as a differing second answer.
    let a = vendor_for(0x00_000C);
    let b = vendor_for(0x00_000C);
    assert_eq!(a, b);
    assert!(a.is_some());
}

#[test]
fn coverage_against_real_capture_prefixes_is_not_marginal() {
    // The measurement that motivated this tier. These are OUIs taken from a
    // genuine wardriving capture whose fixed-address devices the curated table
    // resolved at 0.3%. Each is a real IEEE allocation, so a working registry
    // tier must name every one of them.
    const OBSERVED: &[u32] = &[
        0x74_FECE,
        0x60_45E8,
        0x7C_D4A8,
        0xA0_0460,
        0x30_3A4A,
        0x7C_5E98,
        0x00_6FF2,
        0x2C_8D48,
        0xA8_42A1,
    ];
    let named = OBSERVED.iter().filter(|p| vendor_for(**p).is_some()).count();
    assert_eq!(
        named,
        OBSERVED.len(),
        "every real allocation from the capture must resolve; {named}/{} did",
        OBSERVED.len()
    );

    // One address from that same capture resolves nowhere, and it is worth
    // pinning rather than quietly omitting: `58:E5:72` appears in NONE of the
    // three IEEE registries — not MA-L, not MA-M (28-bit), not MA-S (36-bit),
    // each checked directly. So it is either an allocation newer than this
    // blob or a non-compliant address, and reporting it as unregistered is the
    // correct answer rather than a coverage failure.
    assert_eq!(vendor_for(0x58_E572), None);
}
