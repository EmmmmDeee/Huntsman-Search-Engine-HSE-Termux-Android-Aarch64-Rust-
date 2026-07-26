//! Tests for the GLEIF **Level 2** corporate-family layer.
//!
//! Kept separate from `tests.rs` (which covers the Level-1 transform) because
//! what is under test here is different in kind: not "does the field map across"
//! but "does the module state honestly what a consolidation edge means, and does
//! it refuse to overclaim". The grading rule, the caveat, the de-duplication of a
//! two-level group, the truncation note and the URL-injection gate are all
//! reachable without a network round trip precisely so they can be pinned here.

use super::family::{KIN_CONFIDENCE, Kinship, build_relative, is_same_entity, note_child_coverage};
use super::helpers::{family_url, is_lei};
use super::level2::MAX_CHILDREN;
use super::transform::exact_seeds;
use super::types::{GleifRecord, GleifResp};
use super::{MAX_FAMILY_SEEDS, ORG_EXACT};
use crate::core::{confidence, entity::EntityKind};

/// One Level-2 record as GLEIF returns it inside `{"data": …}`.
fn record(lei: &str, name: &str, jurisdiction: &str, status: &str) -> GleifRecord {
    let raw = format!(
        r#"{{"attributes": {{"lei": "{lei}", "entity": {{
            "legalName": {{"name": "{name}"}},
            "jurisdiction": "{jurisdiction}", "status": "{status}",
            "registeredAs": "12345"
        }}}}}}"#
    );
    serde_json::from_str(&raw).expect("should succeed")
}

const SEED_LEI: &str = "549300E6M4LEUAOX4S43";
const PARENT_LEI: &str = "5493001KJTIIGC8Y1R12";

// ---------------------------------------------------------------- grading ---

#[test]
fn a_relative_grades_between_the_expansion_floor_and_the_seed_that_found_it() {
    // The whole design argument for the walk, asserted on a real entity rather
    // than on the bare constants (those are already pinned at compile time in
    // `family.rs`): a relative is one inferential hop out from the seed, so it
    // must grade BELOW the seed — but above the noisy-OR expansion floor, or the
    // family would be inert and the walk decorative.
    let rec = record(PARENT_LEI, "ACME HOLDINGS LIMITED", "AU", "ACTIVE");
    let e = build_relative(&rec, SEED_LEI, "ACME PTY LTD", Kinship::DirectParent, "s").expect("should succeed");
    assert!(
        e.confidence < ORG_EXACT,
        "a relative must not outrank the exact match it was reached through"
    );
    assert!(
        e.confidence > confidence::MEDIUM,
        "a corporate parent below the expansion floor would never be enriched"
    );
}

#[test]
fn direct_parent_becomes_an_organisation_carrying_the_edge_it_came_from() {
    let rec = record(PARENT_LEI, "ACME HOLDINGS LIMITED", "AU", "ACTIVE");
    let e = build_relative(&rec, SEED_LEI, "ACME PTY LTD", Kinship::DirectParent, "s")
        .expect("a named record is a finding");

    assert_eq!(e.kind, EntityKind::Organisation);
    assert_eq!(e.value, "ACME HOLDINGS LIMITED");
    assert!((e.confidence - KIN_CONFIDENCE).abs() < f64::EPSILON);
    for want in [
        "gleif_lei",
        "gleif",
        "lei",
        "corporate-family",
        "corporate-parent",
        "country:AU",
        "active",
    ] {
        assert!(e.tags.iter().any(|t| t == want), "missing tag {want}");
    }

    // The edge must be reconstructable from the entity alone: which relationship,
    // in which direction, reached through which organisation.
    let a = &e.evidence[0].attributes;
    assert_eq!(
        a.get("relationship").map(String::as_str),
        Some("IS_DIRECTLY_CONSOLIDATED_BY")
    );
    assert_eq!(
        a.get("relationship_role").map(String::as_str),
        Some("corporate-parent")
    );
    assert_eq!(a.get("via_org").map(String::as_str), Some("ACME PTY LTD"));
    assert_eq!(a.get("via_lei").map(String::as_str), Some(SEED_LEI));
    assert_eq!(a.get("lei").map(String::as_str), Some(PARENT_LEI));
    assert!(a.get("register").is_some_and(|r| r.contains("Level 2")));
}

#[test]
fn ultimate_parent_is_graded_alike_but_labelled_differently() {
    let rec = record(PARENT_LEI, "ACME GLOBAL INC", "US", "ACTIVE");
    let e = build_relative(&rec, SEED_LEI, "ACME PTY LTD", Kinship::UltimateParent, "s").expect("should succeed");

    // Same tier — both are separately reported RR-CDF records, so the difference
    // is in meaning, not in a number.
    assert!((e.confidence - KIN_CONFIDENCE).abs() < f64::EPSILON);
    assert!(e.tags.iter().any(|t| t == "ultimate-parent"));
    assert_eq!(
        e.evidence[0]
            .attributes
            .get("relationship")
            .map(String::as_str),
        Some("IS_ULTIMATELY_CONSOLIDATED_BY")
    );
}

#[test]
fn a_child_edge_states_the_direction_the_right_way_round() {
    // The seed consolidates the child, not the other way about. Getting this
    // backwards in a dossier inverts the entire ownership claim.
    let rec = record(PARENT_LEI, "ACME SUBSIDIARY PTY LTD", "AU", "ACTIVE");
    let e = build_relative(&rec, SEED_LEI, "ACME PTY LTD", Kinship::DirectChild, "s").expect("should succeed");

    let summary = &e.evidence[0].summary;
    let seed_at = summary.find("ACME PTY LTD").expect("seed named");
    let child_at = summary
        .find("ACME SUBSIDIARY PTY LTD")
        .expect("child named");
    assert!(
        seed_at < child_at,
        "the consolidating entity must lead the sentence: {summary}"
    );
    assert!(e.tags.iter().any(|t| t == "corporate-subsidiary"));
}

#[test]
fn a_dissolved_relative_is_downgraded_and_tagged_like_a_level_one_hit() {
    let rec = record(PARENT_LEI, "DEFUNCT HOLDINGS LIMITED", "GB", "INACTIVE");
    let e = build_relative(&rec, SEED_LEI, "ACME PTY LTD", Kinship::DirectParent, "s").expect("should succeed");
    assert!(e.tags.iter().any(|t| t == "inactive"));
    assert!(
        e.confidence < KIN_CONFIDENCE,
        "an inactive entity must not grade as a live one"
    );
    assert_eq!(
        e.evidence[0]
            .attributes
            .get("entity_status")
            .map(String::as_str),
        Some("INACTIVE")
    );
}

#[test]
fn a_nameless_record_is_dropped_rather_than_given_a_placeholder() {
    // No-fabrication: a relative with no legal name is not a finding, and
    // inventing "Unknown entity (LEI …)" would put a manufactured organisation
    // into the graph.
    let blank: GleifRecord =
        serde_json::from_str(r#"{"attributes": {"lei": "X", "entity": {}}}"#).expect("should succeed");
    assert!(build_relative(&blank, SEED_LEI, "ACME PTY LTD", Kinship::DirectParent, "s").is_none());

    let empty: GleifRecord = serde_json::from_str(r#"{}"#).expect("should succeed");
    assert!(build_relative(&empty, SEED_LEI, "ACME PTY LTD", Kinship::DirectChild, "s").is_none());
}

// ----------------------------------------------------------- the caveat -----

#[test]
fn every_relative_carries_the_coverage_caveat_in_its_own_evidence() {
    // The caveat has to travel with the data, not live only in module docs the
    // operator never opens — a consolidation edge read as an ownership
    // percentage, or a missing edge read as independence, are both confident
    // false findings.
    for kin in [
        Kinship::DirectParent,
        Kinship::UltimateParent,
        Kinship::DirectChild,
    ] {
        let rec = record(PARENT_LEI, "ACME HOLDINGS LIMITED", "AU", "ACTIVE");
        let e = build_relative(&rec, SEED_LEI, "ACME PTY LTD", kin, "s").expect("should succeed");
        let coverage = e.evidence[0]
            .attributes
            .get("coverage")
            .unwrap_or_else(|| panic!("{kin:?} relative shipped with no coverage caveat"));
        assert!(
            coverage.contains("ACCOUNTING-CONSOLIDATION"),
            "the caveat must say what the edge actually is: {coverage}"
        );
        assert!(
            coverage.contains("NOT a statement of any ownership percentage"),
            "the caveat must refuse the ownership reading: {coverage}"
        );
        assert!(
            coverage.contains("ABSENCE of an edge is NOT"),
            "the caveat must refuse the negative-finding reading: {coverage}"
        );
    }
}

// ------------------------------------------------------------ de-duping -----

#[test]
fn a_two_level_group_is_one_organisation_holding_both_roles() {
    // GLEIF answers /direct-parent and /ultimate-parent with the SAME record when
    // the group is two levels deep. Treating that as two relatives would
    // double-count one organisation and inflate the apparent size of the family.
    let rec = record(PARENT_LEI, "ACME HOLDINGS LIMITED", "AU", "ACTIVE");
    assert!(is_same_entity(&rec, Some(PARENT_LEI)));

    // A genuinely taller group: distinct LEIs are two distinct findings.
    assert!(!is_same_entity(&rec, Some(SEED_LEI)));
    // Nothing to compare against (no direct parent, or no LEI on either side) is
    // never a match — it must not collapse two entities on absent evidence.
    assert!(!is_same_entity(&rec, None));
    let no_lei: GleifRecord =
        serde_json::from_str(r#"{"attributes": {"entity": {"legalName": {"name": "X"}}}}"#)
            .expect("should succeed");
    assert!(!is_same_entity(&no_lei, Some(PARENT_LEI)));
}

// -------------------------------------------------------- no silent caps ----

#[test]
fn child_coverage_records_the_true_total_and_flags_a_partial_walk() {
    let rec = record(PARENT_LEI, "ACME SUBSIDIARY PTY LTD", "AU", "ACTIVE");
    let mut e = build_relative(&rec, SEED_LEI, "ACME PTY LTD", Kinship::DirectChild, "s").expect("should succeed");
    note_child_coverage(&mut e, 50, 480);

    let a = &e.evidence[0].attributes;
    assert_eq!(
        a.get("subsidiaries_emitted").map(String::as_str),
        Some("50")
    );
    assert_eq!(a.get("subsidiaries_total").map(String::as_str), Some("480"));
    let note = a
        .get("subsidiaries_truncated")
        .expect("a bounded walk must announce itself");
    assert!(note.contains("480") && note.contains("50"), "{note}");
    assert!(
        note.contains("NOT retrieved"),
        "the note must be unambiguous that results are missing: {note}"
    );
}

#[test]
fn a_complete_walk_claims_no_truncation() {
    let rec = record(PARENT_LEI, "ACME SUBSIDIARY PTY LTD", "AU", "ACTIVE");
    let mut e = build_relative(&rec, SEED_LEI, "ACME PTY LTD", Kinship::DirectChild, "s").expect("should succeed");
    note_child_coverage(&mut e, 3, 3);

    let a = &e.evidence[0].attributes;
    assert_eq!(a.get("subsidiaries_total").map(String::as_str), Some("3"));
    assert!(
        !a.contains_key("subsidiaries_truncated"),
        "a complete enumeration must not be marked partial"
    );
}

#[test]
fn the_walk_caps_are_bounded_and_ordered_sensibly() {
    // Both caps exist so one invocation can't become hundreds of requests on a
    // phone; neither may be zero, which would disable the feature silently.
    assert!((1..=10).contains(&MAX_FAMILY_SEEDS));
    assert!((1..=200).contains(&MAX_CHILDREN));
}

// ------------------------------------------------------- the URL gate -------

#[test]
fn is_lei_accepts_only_the_iso_17442_alphabet() {
    assert!(is_lei(SEED_LEI));
    assert!(is_lei("WZE1WSENV6JSZFK0JC28"));
    // Wrong length either way.
    assert!(!is_lei(""));
    assert!(!is_lei("549300E6M4LEUAOX4S4"));
    assert!(!is_lei("549300E6M4LEUAOX4S433"));
    // Right length, wrong alphabet.
    assert!(
        !is_lei("549300e6m4leuaox4s43"),
        "lowercase is not ISO 17442"
    );
}

#[test]
fn family_url_refuses_an_lei_that_could_redirect_the_request() {
    // An LEI arrives from a remote JSON document and is interpolated into a URL
    // PATH segment, so this is a security gate rather than a tidiness check.
    // Every one of these is exactly 20 chars, i.e. length alone does not save us.
    for hostile in [
        "../../../../evil/xxxx", // path traversal
        "AAAAAAAA/../../evilxx", // traversal mid-segment
        "AAAAAAAAAAAA?a=b&c=d",  // query injection
        "AAAAAAAAAAAAAAAA#fra",  // fragment
        "AAAA AAAAAAAAAAAAAAA",  // whitespace
        "AAAAAAAAAAAAAAAA%2Fx",  // pre-escaped separator
        "AAAAAAAAAAAAAAAA\nxx",  // header/log injection
        "AAAAAAAA.evil.exampl",  // host-ish
    ] {
        assert!(
            family_url(hostile, "direct-parent").is_none(),
            "family_url accepted a hostile LEI: {hostile:?}"
        );
    }

    let url = family_url(SEED_LEI, "direct-parent").expect("a well-formed LEI builds a URL");
    assert_eq!(
        url,
        format!("https://api.gleif.org/api/v1/lei-records/{SEED_LEI}/direct-parent")
    );
}

#[test]
fn kinship_paths_match_the_gleif_relationship_links() {
    assert_eq!(Kinship::DirectParent.path(), "direct-parent");
    assert_eq!(Kinship::UltimateParent.path(), "ultimate-parent");
    assert_eq!(Kinship::DirectChild.path(), "direct-children");
}

// ------------------------------------------------------- seed selection -----

fn search_resp() -> GleifResp {
    let raw = r#"{
        "meta": {"pagination": {"total": 3}},
        "data": [
            {"attributes": {"lei": "WZE1WSENV6JSZFK0JC28", "entity": {
                "legalName": {"name": "BHP GROUP LIMITED"}, "jurisdiction": "AU", "status": "ACTIVE"
            }}},
            {"attributes": {"lei": "894500OGEMX4F6STBR39", "entity": {
                "legalName": {"name": "RIO TINTO LIMITED"}, "jurisdiction": "AU", "status": "ACTIVE"
            }}},
            {"attributes": {"entity": {
                "legalName": {"name": "BHP GROUP LIMITED"}, "jurisdiction": "GB", "status": "ACTIVE"
            }}}
        ]
    }"#;
    serde_json::from_str(raw).expect("should succeed")
}

#[test]
fn only_exact_name_matches_with_an_lei_are_walked() {
    let seeds = exact_seeds(&search_resp(), "BHP Group Limited");
    // Row 2 is a different company entirely; row 3 matches the name but has no
    // LEI, so there is nothing to walk from.
    assert_eq!(
        seeds,
        vec![(
            "WZE1WSENV6JSZFK0JC28".to_string(),
            "BHP GROUP LIMITED".to_string()
        )]
    );
}

#[test]
fn a_loose_name_match_never_earns_a_corporate_family() {
    // The expensive failure mode this guards: a fuzzy match manufactures a
    // confident ownership graph around the WRONG company, and every downstream
    // adverse-register hit then lands on an innocent party.
    assert!(exact_seeds(&search_resp(), "BHP Group Holdings International").is_empty());
    assert!(exact_seeds(&search_resp(), "Totally Unrelated Pty Ltd").is_empty());
}
