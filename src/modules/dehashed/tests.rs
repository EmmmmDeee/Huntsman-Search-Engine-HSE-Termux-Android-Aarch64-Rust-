use super::build::{balance_str, build_breach_entity, db_names, selector_for};
use super::types::{DehashedResp, Entry};
use super::DeHashed;
use crate::core::{
    entity::{Entity, EntityKind},
    module::{Module, ModuleCost},
    scan::{Target, TargetKind},
    tags,
};
use serde_json::json;

fn entry(db: serde_json::Value) -> Entry {
    Entry { database_name: db }
}

fn attr<'a>(e: &'a Entity, k: &str) -> Option<&'a str> {
    e.evidence[0].attributes.get(k).map(String::as_str)
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
    // selector_for must answer for exactly the kinds accepts() admits.
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
    // A kind the module does not search.
    assert_eq!(selector_for(TargetKind::Url), None);
}

#[test]
fn db_names_flattens_string_array_and_skips_non_strings() {
    assert_eq!(db_names(&json!("Collection1")), vec!["Collection1"]);
    assert_eq!(db_names(&json!(["A", "B"])), vec!["A", "B"]);
    assert!(db_names(&json!(null)).is_empty());
    assert!(db_names(&json!(42)).is_empty());
    // A mixed array keeps only the string members.
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
    // v2 returns database_name as arrays; counts fold across entries, and a
    // bare scalar is tolerated too.
    let entries = [
        entry(json!(["Collection#1"])),
        entry(json!(["Collection#1"])),
        entry(json!("LinkedIn")),
    ];
    // total (900) exceeds the returned/truncated rows (3).
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
    // Collection#1 (2) ranks above the scalar LinkedIn (1).
    assert_eq!(
        attr(&e, "top_databases"),
        Some("Collection#1×2, LinkedIn×1")
    );
    assert_eq!(attr(&e, "credit_balance"), Some("498"));
    // v2 carries no per-record timestamps, so no created range is surfaced.
    assert_eq!(attr(&e, "earliest_record"), None);
    assert_eq!(attr(&e, "latest_record"), None);
}

#[test]
fn count_only_response_omits_optional_aggregates() {
    // total known but no entry rows + no balance (a bare count response).
    let e = build_breach_entity(EntityKind::Domain, "x.com", "domain", &[], 42, None, "s");
    assert!(e.has_tag(tags::BREACH));
    assert_eq!(attr(&e, "hits"), Some("42"));
    assert_eq!(attr(&e, "returned"), Some("0"));
    assert_eq!(attr(&e, "top_databases"), None);
    assert_eq!(attr(&e, "credit_balance"), None);
}

#[test]
fn resp_parses_v2_shape_and_drops_credential_fields() {
    // The no-credentials invariant, structurally: a real v2 entry carries
    // password / hashed_password, but `Entry` binds only database_name, so
    // serde silently drops the rest — they can never reach evidence. Also
    // proves the v2 wire shape (array fields, top-level balance/total)
    // deserialises, which the inactive-subscription account blocks us from
    // observing live.
    let raw = r#"{
        "success": true,
        "total": 2,
        "balance": 498,
        "took": "5ms",
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
    assert_eq!(r.total, Some(2));
    let entries = r.entries.unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(db_names(&entries[0].database_name), vec!["Collection#1"]);
    assert_eq!(balance_str(&r.balance), Some("498".to_string()));

    // Fold it through the builder: only aggregate metadata surfaces; no
    // password/hash attribute exists anywhere on the entity.
    let e = build_breach_entity(
        EntityKind::Email,
        "a@b.com",
        "email",
        &entries,
        r.total.unwrap(),
        balance_str(&r.balance).as_deref(),
        "s",
    );
    let all_attr_vals: String = e.evidence[0]
        .attributes
        .values()
        .cloned()
        .collect::<Vec<_>>()
        .join("|");
    assert!(!all_attr_vals.contains("hunter2"));
    assert!(!all_attr_vals.contains("5f4dcc3b"));
    assert_eq!(attr(&e, "top_databases"), Some("Collection#1×1"));
}
