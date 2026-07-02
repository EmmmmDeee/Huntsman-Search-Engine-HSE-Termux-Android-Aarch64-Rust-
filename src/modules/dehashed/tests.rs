use super::DeHashed;
use super::build::{balance_str, build_breach_entity, db_names, extract_records, selector_for};
use super::types::DehashedResp;
use crate::core::{
    entity::{Entity, EntityKind},
    module::{Module, ModuleCost, ModuleResult},
    scan::{Target, TargetKind},
    tags,
};
use serde_json::{Value, json};
use std::collections::HashSet;

/// A record carrying only a `database_name`, for the aggregate-builder tests.
fn entry(db: Value) -> Value {
    json!({ "database_name": db })
}

fn attr<'a>(e: &'a Entity, k: &str) -> Option<&'a str> {
    e.evidence[0].attributes.get(k).map(String::as_str)
}

fn has(result: &ModuleResult, kind: EntityKind, value: &str) -> bool {
    result
        .entities
        .iter()
        .any(|e| e.kind == kind && e.value == value)
}

#[test]
fn accepts_six_kinds() {
    let m = DeHashed;
    for k in [
        TargetKind::Email,
        TargetKind::Username,
        TargetKind::Phone,
        TargetKind::IpAddress,
        TargetKind::Domain,
    ] {
        assert!(m.accepts(&Target::new(k, "x")));
    }
    assert!(m.accepts(&Target::new(TargetKind::FullName, "Jane Doe")));
}

#[test]
fn cost_is_paid() {
    assert!(matches!(DeHashed.cost(), ModuleCost::Paid));
}

#[test]
fn selector_covers_every_accepted_kind() {
    for k in [
        TargetKind::Email,
        TargetKind::Username,
        TargetKind::Phone,
        TargetKind::FullName,
        TargetKind::IpAddress,
        TargetKind::Domain,
    ] {
        assert!(DeHashed.accepts(&Target::new(k, "x")));
        assert!(selector_for(k).is_some(), "no selector for {k:?}");
    }
    assert_eq!(selector_for(TargetKind::Email), Some("email"));
    assert_eq!(selector_for(TargetKind::FullName), Some("name"));
    assert_eq!(selector_for(TargetKind::IpAddress), Some("ip_address"));
    assert_eq!(selector_for(TargetKind::Url), None);
}

#[test]
fn db_names_flattens_string_array_and_skips_non_strings() {
    assert_eq!(db_names(&json!("Collection1")), vec!["Collection1"]);
    assert_eq!(db_names(&json!(["A", "B"])), vec!["A", "B"]);
    assert!(db_names(&json!(null)).is_empty());
    assert!(db_names(&json!(42)).is_empty());
    assert_eq!(db_names(&json!(["A", 1, "B"])), vec!["A", "B"]);
}

#[test]
fn balance_str_renders_number_and_string_only() {
    assert_eq!(balance_str(&Some(json!(500))), Some("500".to_string()));
    assert_eq!(balance_str(&Some(json!("498"))), Some("498".to_string()));
    assert_eq!(balance_str(&Some(json!("  12 "))), Some("12".to_string()));
    assert_eq!(balance_str(&Some(json!(null))), None);
    assert_eq!(balance_str(&Some(json!(""))), None);
    assert_eq!(balance_str(&None), None);
}

#[test]
fn aggregates_hits_top_databases_and_balance_from_v2_arrays() {
    let entries = [
        entry(json!(["Collection#1"])),
        entry(json!(["Collection#1"])),
        entry(json!("LinkedIn")),
    ];
    let e = build_breach_entity(
        EntityKind::Email,
        "a@b.com",
        "email",
        &entries,
        900,
        Some("498"),
        "s",
    );
    assert_eq!(e.kind, EntityKind::Email);
    assert!(e.has_tag(tags::BREACH) && e.has_tag("dehashed"));
    assert!((e.confidence - 0.88).abs() < 1e-9);
    assert_eq!(attr(&e, "hits"), Some("900")); // server total, not len
    assert_eq!(attr(&e, "returned"), Some("3"));
    assert_eq!(attr(&e, "selector"), Some("email"));
    assert_eq!(
        attr(&e, "top_databases"),
        Some("Collection#1×2, LinkedIn×1")
    );
    assert_eq!(attr(&e, "credit_balance"), Some("498"));
}

#[test]
fn count_only_response_omits_optional_aggregates() {
    let e = build_breach_entity(EntityKind::Domain, "x.com", "domain", &[], 42, None, "s");
    assert!(e.has_tag(tags::BREACH));
    assert_eq!(attr(&e, "hits"), Some("42"));
    assert_eq!(attr(&e, "returned"), Some("0"));
    assert_eq!(attr(&e, "top_databases"), None);
    assert_eq!(attr(&e, "credit_balance"), None);
}

#[test]
fn v2_record_surfaces_identity_and_hash_for_entity_linking() {
    // A real v2 entry wraps every field in an array. The extractor must surface
    // the identity AND the credential secret — the password hash DeHashed exists
    // to provide — as first-class entities, and carry the hash on each entity's
    // evidence as `hashed_password` (the attribute AU-105 groups on for hash-reuse
    // identity linking). This is the inverse of the former no-credentials policy.
    let raw = r#"{
        "success": true,
        "total": 2,
        "balance": 498,
        "entries": [
            {
                "id": "1",
                "email": ["a@b.com"],
                "username": ["alice"],
                "password": ["hunter2"],
                "hashed_password": ["5f4dcc3b5aa765d61d8327deb882cf99"],
                "database_name": ["Collection#1"]
            }
        ]
    }"#;
    let r: DehashedResp = serde_json::from_str(raw).unwrap();
    let entries = r.entries.unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(db_names(&entries[0]["database_name"]), vec!["Collection#1"]);

    let mut seen = HashSet::new();
    let mut result = ModuleResult::new();
    // Target matches the record's email → first-class (not quarantined).
    extract_records(
        &entries,
        "a@b.com",
        "dehashed:1f8…16f2",
        "s",
        &mut seen,
        &mut result,
    );

    // Identity + both credential representations are surfaced, nothing dropped.
    assert!(has(&result, EntityKind::Email, "a@b.com"));
    assert!(has(&result, EntityKind::Username, "alice"));
    assert!(has(
        &result,
        EntityKind::Password,
        "5f4dcc3b5aa765d61d8327deb882cf99"
    ));
    assert!(has(&result, EntityKind::Password, "hunter2"));

    // The hash entity carries the `password-hash` tag; none of these are quarantined.
    let hash_ent = result
        .entities
        .iter()
        .find(|e| e.kind == EntityKind::Password && e.value.starts_with("5f4"))
        .unwrap();
    assert!(hash_ent.has_tag("password-hash"));
    assert!(result.entities.iter().all(|e| !e.has_tag(tags::CANDIDATE)));

    // The hash rides on the email entity's evidence (flattened from the array) as
    // the exact key AU-105 reads — the bare digest, so it matches the same hash
    // from another provider, not `["5f4d…"]`.
    let email_ent = result
        .entities
        .iter()
        .find(|e| e.kind == EntityKind::Email)
        .unwrap();
    assert_eq!(
        attr(email_ent, "hashed_password"),
        Some("5f4dcc3b5aa765d61d8327deb882cf99")
    );
}

#[test]
fn non_target_stranger_record_is_quarantined_not_dropped() {
    // A broad `name` search returns a same-name stranger whose identifiers are NOT
    // the subject. Their entities (incl. the hash) must be RETAINED — the
    // operator's data is never silently dropped — but demoted to quarantined
    // candidate leads so they never masquerade as the subject.
    let entries = vec![json!({
        "email": ["stranger@x.com"],
        "hashed_password": ["deadbeefdeadbeefdeadbeefdeadbeef"],
        "database_name": ["Collection#1"]
    })];
    let mut seen = HashSet::new();
    let mut result = ModuleResult::new();
    extract_records(&entries, "Jane Doe", "fp", "s", &mut seen, &mut result);

    assert!(has(&result, EntityKind::Email, "stranger@x.com"));
    assert!(has(
        &result,
        EntityKind::Password,
        "deadbeefdeadbeefdeadbeefdeadbeef"
    ));
    assert!(
        result.entities.iter().all(|e| e.has_tag(tags::CANDIDATE)),
        "a non-target record's entities must be quarantined"
    );
}

#[test]
fn record_evidence_stamps_canonical_dbname_for_au105() {
    // AU-105 (credential reuse across breaches) groups records by the `dbname`
    // evidence attribute, falling back to the Evidence `source` FIELD (the module
    // name "dehashed") when it is absent. DeHashed must therefore stamp the breach
    // name under `dbname`, not only the `source` attribute — otherwise every
    // DeHashed record collapses to one pseudo-breach and cross-breach reuse among
    // a subject's DeHashed hits can never fire.
    let entries = vec![json!({
        "email": ["a@b.com"],
        "password": ["reused-secret-1"],
        "database_name": ["Collection#1"]
    })];
    let mut seen = HashSet::new();
    let mut result = ModuleResult::new();
    extract_records(&entries, "a@b.com", "fp", "s", &mut seen, &mut result);

    let email = result
        .entities
        .iter()
        .find(|e| e.kind == EntityKind::Email && e.value == "a@b.com")
        .expect("the subject email entity");
    assert_eq!(
        attr(email, "dbname"),
        Some("Collection#1"),
        "the breach name must be on the canonical `dbname` attr AU-105 reads"
    );
    // The `source` attribute is retained for existing consumers.
    assert_eq!(attr(email, "source"), Some("Collection#1"));
}

#[test]
fn weak_hash_is_cracked_offline_to_its_plaintext() {
    // hashed_password is md5("password") — the offline reverse-lookup recovers the
    // plaintext, surfaces it as a first-class node, and tags the hash entity with
    // its algorithm, crackability, and `cracked`. No network, no GPU.
    let entries = vec![json!({
        "email": ["a@b.com"],
        "hashed_password": ["5f4dcc3b5aa765d61d8327deb882cf99"],
        "database_name": ["X"]
    })];
    let mut seen = HashSet::new();
    let mut result = ModuleResult::new();
    extract_records(&entries, "a@b.com", "fp", "s", &mut seen, &mut result);
    // The recovered plaintext is a first-class Password node.
    assert!(has(&result, EntityKind::Password, "password"));
    let hash_ent = result
        .entities
        .iter()
        .find(|e| e.kind == EntityKind::Password && e.value == "5f4dcc3b5aa765d61d8327deb882cf99")
        .unwrap();
    assert!(hash_ent.has_tag("cracked"));
    assert!(hash_ent.has_tag("hash:md5"));
    assert!(hash_ent.has_tag("crackable:fast"));
}

#[test]
fn multi_value_fields_surface_every_value() {
    // v2 can return several emails/passwords in one record's arrays; each must
    // become its own entity, none collapsed to the first.
    let entries = vec![json!({
        "email": ["a@b.com", "a.b@work.com"],
        "password": ["hunter2", "letmein99"],
        "database_name": ["Collection#1"]
    })];
    let mut seen = HashSet::new();
    let mut result = ModuleResult::new();
    extract_records(&entries, "a@b.com", "fp", "s", &mut seen, &mut result);
    assert!(has(&result, EntityKind::Email, "a@b.com"));
    assert!(has(&result, EntityKind::Email, "a.b@work.com"));
    assert!(has(&result, EntityKind::Password, "hunter2"));
    assert!(has(&result, EntityKind::Password, "letmein99"));
}
