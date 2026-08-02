use super::DeHashed;
use super::build::{balance_str, build_breach_entity, db_names, extract_records, selector_for};
use super::types::DehashedResp;
use crate::core::{
    confidence,
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

/// A record carrying a `name` (for target-match gating) and a `database_name`.
fn entry_named(name: &str, db: Value) -> Value {
    json!({ "name": name, "database_name": db })
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
fn cache_ttl_is_24h_so_repeat_scans_dont_re_spend_a_paid_lookup() {
    use crate::core::module::Module;
    // Immutable breach dumps ⇒ the inter-scan cache serves a repeat scan for
    // free; a 0 (trait default) would disable it, so pin the window.
    assert_eq!(DeHashed.cache_ttl_secs(), 86_400);
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
fn attack_techniques_reflect_the_full_shared_breach_rich_extraction() {
    use crate::core::attack;
    let t = DeHashed.attack_techniques();
    // Each claimed technique is backed by a concrete extractor: credentials,
    // emails, employee names (this file), IP addresses (this file), and —
    // via the shared `breach_rich` catch-all this module runs — physical
    // locations, business relationships, host fingerprints, and social
    // media handles.
    for id in [
        "T1589.001",
        "T1589.002",
        "T1589.003",
        "T1590.005",
        "T1591.001",
        "T1591.002",
        "T1592",
        "T1593.001",
        "T1597.002",
    ] {
        assert!(t.contains(&id), "dehashed must claim {id}, got {t:?}");
        assert!(attack::technique(id).is_some(), "{id} must be catalogued");
    }
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
    )
    .expect("exact `email` selector with a positive total emits a headline");
    assert_eq!(e.kind, EntityKind::Email);
    assert!(e.has_tag(tags::BREACH) && e.has_tag("dehashed"));
    assert!((e.confidence - confidence::EXPERT).abs() < 1e-9);
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
    // `domain` is identity-exact, so a count-only response (server total, no rows)
    // is a genuine signal for that exact value and still emits the headline.
    let e = build_breach_entity(EntityKind::Domain, "x.com", "domain", &[], 42, None, "s")
        .expect("exact `domain` selector with a positive count emits a headline");
    assert!(e.has_tag(tags::BREACH));
    assert_eq!(attr(&e, "hits"), Some("42"));
    assert_eq!(attr(&e, "returned"), Some("0"));
    assert_eq!(attr(&e, "top_databases"), None);
    assert_eq!(attr(&e, "credit_balance"), None);
}

#[test]
fn name_headline_is_gated_on_a_real_subject_match() {
    // A broad `name:` search returns same-name STRANGERS. The confidence::EXPERT breach-presence
    // headline merges onto the engine's pre-seeded subject anchor, so it must NOT
    // be minted off a page that contains no record actually matching the subject
    // — nor off a bare count with no rows to verify (`oathnet_pro`'s gate). The
    // per-record `extract_records` still quarantines the strangers separately.
    let strangers = [
        entry_named("John Smith", json!("Collection#1")),
        entry_named("John A. Smith", json!("LinkedIn")),
    ];
    // Server reports a large count, but not one returned row is the subject.
    assert!(
        build_breach_entity(
            EntityKind::Person,
            "Jane Doe",
            "name",
            &strangers,
            500,
            None,
            "s",
        )
        .is_none(),
        "a name page of strangers must not mint a subject breach headline"
    );
    // Count-only name response (no rows to verify) is unattributable → None.
    assert!(
        build_breach_entity(EntityKind::Person, "Jane Doe", "name", &[], 500, None, "s").is_none(),
        "a bare `name:` count with no rows must not mint a headline"
    );

    // When the subject DOES appear, the headline is emitted and counts only the
    // matching rows — not the strangers, not the inflated server total.
    let mixed = [
        entry_named("Jane Doe", json!("Collection#1")),
        entry_named("John Smith", json!("LinkedIn")),
        entry_named("Jane Doe", json!("Collection#1")),
    ];
    let e = build_breach_entity(
        EntityKind::Person,
        "Jane Doe",
        "name",
        &mixed,
        500,
        None,
        "s",
    )
    .expect("a matching subject row emits the headline");
    assert_eq!(
        attr(&e, "hits"),
        Some("2"),
        "counts matching rows, not total"
    );
    assert_eq!(attr(&e, "returned"), Some("3"));
    // Aggregates fold over the matching rows only (both from Collection#1).
    assert_eq!(attr(&e, "top_databases"), Some("Collection#1×2"));
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
    let r: DehashedResp = serde_json::from_str(raw).expect("should succeed");
    let entries = r.entries.expect("should succeed");
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
        .expect("should succeed");
    assert!(hash_ent.has_tag("password-hash"));
    assert!(result.entities.iter().all(|e| !e.has_tag(tags::CANDIDATE)));

    // The hash rides on the email entity's evidence (flattened from the array) as
    // the exact key AU-105 reads — the bare digest, so it matches the same hash
    // from another provider, not `["5f4d…"]`.
    let email_ent = result
        .entities
        .iter()
        .find(|e| e.kind == EntityKind::Email)
        .expect("should succeed");
    assert_eq!(
        attr(email_ent, "hashed_password"),
        Some("5f4dcc3b5aa765d61d8327deb882cf99")
    );
}

#[test]
fn email_in_the_password_slot_is_recovered_as_an_email_lead() {
    // Stealer/breach dumps frequently mis-store an email in the `password` field.
    // Minting it as a Password would forge a reused-secret link; DeHashed used to
    // silently DROP it (only the Secret arm existed). It must instead recover it
    // into the email pipeline, as oathnet_pro / see_know already do.
    let raw = r#"{
        "success": true,
        "total": 1,
        "entries": [
            {
                "id": "1",
                "email": ["a@b.com"],
                "password": ["leaked@corp.com"],
                "database_name": ["Collection#1"]
            }
        ]
    }"#;
    let r: DehashedResp = serde_json::from_str(raw).expect("should succeed");
    let entries = r.entries.expect("should succeed");
    let mut seen = HashSet::new();
    let mut result = ModuleResult::new();
    extract_records(
        &entries,
        "a@b.com",
        "dehashed:t",
        "s",
        &mut seen,
        &mut result,
    );

    // Recovered as an Email lead, NOT minted as a Password.
    assert!(
        has(&result, EntityKind::Email, "leaked@corp.com"),
        "an email in the password slot must be recovered as an Email lead"
    );
    assert!(
        !has(&result, EntityKind::Password, "leaked@corp.com"),
        "an email in the password slot must NOT be minted as a Password"
    );
    let recovered = result
        .entities
        .iter()
        .find(|e| e.kind == EntityKind::Email && e.value == "leaked@corp.com")
        .expect("should succeed");
    assert!(recovered.has_tag("recovered-from-password"));
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
        .expect("should succeed");
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

#[test]
fn username_derived_name_is_not_minted_as_person() {
    // A DeHashed record whose `name` is a doubled username
    // ("rhino-ryno23 rhino-ryno23") clears the space + non-sentinel checks yet is
    // a fabricated Person — the same pattern guarded for oathnet_pro/see_know. It
    // must never be minted as an EntityKind::Person.
    let entries = vec![entry_named(
        "rhino-ryno23 rhino-ryno23",
        json!("Collection#1"),
    )];
    let mut seen = HashSet::new();
    let mut result = ModuleResult::new();
    extract_records(
        &entries,
        "rhino-ryno23 rhino-ryno23",
        "fp",
        "s",
        &mut seen,
        &mut result,
    );
    assert!(
        !has(&result, EntityKind::Person, "rhino-ryno23 rhino-ryno23"),
        "a username-derived name must never be minted as a Person"
    );
}
