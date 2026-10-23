//! Evidence exports must never score a broken hash chain, even when each
//! individual claim declares a verified status and a valid technique binding.
use huntsman_recon::ledger::{Claim, LedgerEntry, admitted_with, append, chain_intact, seal};
use huntsman_recon::navigator::layer_with;
use huntsman_recon::stage::{EvidenceLevel, Status};
use huntsman_recon::stix::bundle_with;

const BINDINGS: &[(&str, &str)] = &[("src/check.rs", "T1595")];

fn claim(label: &str) -> Claim {
    Claim {
        claim: label.to_owned(),
        source: "tests/interop_chain_integrity".into(),
        component: "src/check.rs".into(),
        technique_id: Some("T1595".into()),
        status: Status::Verified,
        evidence_level: EvidenceLevel::DirectObservation,
        does_not_show: "does not authenticate any subscriber".into(),
    }
}

fn intact_two_entries() -> [LedgerEntry; 2] {
    let first = seal(&claim("first confirmed observation"));
    let second = append(&first.hash, &claim("second confirmed observation"));
    [first, second]
}

fn assert_rejected(entries: &[LedgerEntry]) {
    assert!(!chain_intact(entries), "fixture must be a broken chain");
    assert_eq!(admitted_with(entries, BINDINGS).count(), 0);
    assert!(
        bundle_with(entries, BINDINGS)["objects"]
            .as_array()
            .expect("STIX objects")
            .is_empty(),
        "STIX must not contain any indicators from a broken chain"
    );
    assert!(
        layer_with(entries, BINDINGS)["techniques"]
            .as_array()
            .expect("Navigator techniques")
            .is_empty(),
        "Navigator must not score any techniques from a broken chain"
    );
}

#[test]
fn verified_chain_still_exports_and_empty_bindings_admit_nothing() {
    let entries = intact_two_entries();
    assert!(chain_intact(&entries));
    assert_eq!(admitted_with(&entries, BINDINGS).count(), 2);
    assert_eq!(
        bundle_with(&entries, BINDINGS)["objects"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
    assert_eq!(
        layer_with(&entries, BINDINGS)["techniques"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
    assert_eq!(admitted_with(&entries, &[]).count(), 0);
}

#[test]
fn mutating_only_claim_content_cannot_score_any_entry() {
    let mut entries = intact_two_entries();
    entries[1].claim.claim.push_str(" changed after sealing");
    assert_rejected(&entries);
}

#[test]
fn mutating_a_plausible_hex_digest_cannot_score_otherwise_verified_claims() {
    let mut entries = intact_two_entries();
    entries[0].hash = "a".repeat(64);
    assert_rejected(&entries);
}

#[test]
fn reordering_or_dropping_the_genesis_prefix_rejects_entire_export() {
    let entries = intact_two_entries();
    assert_rejected(&[entries[1].clone(), entries[0].clone()]);
    assert_rejected(&[entries[1].clone()]);
}

#[test]
fn corrupting_a_middle_link_rejects_the_entire_chain_not_just_that_entry() {
    let mut entries = intact_two_entries();
    entries[1].prev = "b".repeat(64);
    assert_rejected(&entries);
}
