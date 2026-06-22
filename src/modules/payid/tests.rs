use super::*;
use std::collections::HashMap;

fn ctx() -> ModuleContext {
    let (bus, _rx) = tokio::sync::broadcast::channel(8);
    ModuleContext {
        scan_id: "t".into(),
        bus,
        http: crate::util::http::build_client(),
        keys: HashMap::default(),
        cancel: crate::core::cancel::CancelHandle::new(),
        proxy_pool: std::sync::Arc::new(crate::util::proxy::ProxyPool::new()),
    }
}

#[test]
fn accepts_only_payid_eligible_kinds() {
    let m = PayId;
    assert!(m.accepts(&Target::new(TargetKind::Email, "a@b.com")));
    assert!(m.accepts(&Target::new(TargetKind::Phone, "0410 959 140")));
    assert!(m.accepts(&Target::new(TargetKind::AbnAcn, "51824753556")));
    assert!(!m.accepts(&Target::new(TargetKind::Domain, "example.com")));
    assert!(!m.accepts(&Target::new(TargetKind::Username, "alice")));
}

#[test]
fn recognises_email_payid_lowercased() {
    let r = recognise(&Target::new(TargetKind::Email, "Alice@Example.com")).unwrap();
    assert_eq!(r.kind, EntityKind::Email);
    assert_eq!(r.canonical, "alice@example.com");
    assert_eq!(r.kind_label, "email");
    assert!(!r.registry_resolvable, "an email PayID name needs a banking app");
}

#[test]
fn rejects_email_fragment() {
    assert!(recognise(&Target::new(TargetKind::Email, "matt@")).is_none());
    assert!(recognise(&Target::new(TargetKind::Email, "@gmail")).is_none());
}

#[test]
fn recognises_phone_payid_as_e164() {
    let r = recognise(&Target::new(TargetKind::Phone, "0410 959 140")).unwrap();
    assert_eq!(r.kind, EntityKind::Phone);
    assert_eq!(r.canonical, "+61410959140");
    assert_eq!(r.kind_label, "phone");
    assert!(!r.registry_resolvable);
}

#[test]
fn rejects_unparseable_phone() {
    assert!(recognise(&Target::new(TargetKind::Phone, "not-a-number")).is_none());
}

#[test]
fn recognises_abn_payid_as_registry_resolvable() {
    // ATO worked-example ABN, spaced as a user would paste it.
    let r = recognise(&Target::new(TargetKind::AbnAcn, "51 824 753 556")).unwrap();
    assert_eq!(r.kind, EntityKind::AbnAcn);
    assert_eq!(r.canonical, "51824753556");
    assert_eq!(r.kind_label, "abn");
    assert!(
        r.registry_resolvable,
        "the ABN PayID holder name is the registered entity name (public register)"
    );
}

#[test]
fn rejects_invalid_abn() {
    assert!(recognise(&Target::new(TargetKind::AbnAcn, "51824753557")).is_none()); // bad checksum
    assert!(recognise(&Target::new(TargetKind::AbnAcn, "123")).is_none()); // too short
}

#[tokio::test]
async fn process_annotates_email_with_payid_tags_and_pivot() {
    let out = PayId
        .process(&Target::new(TargetKind::Email, "alice@example.com"), &ctx())
        .await
        .unwrap();
    let e = &out.entities[0];
    assert_eq!(e.kind, EntityKind::Email);
    assert!(e.tags.iter().any(|t| t == "payid"));
    assert!(e.tags.iter().any(|t| t == "payid:email"));
    // The confirm-payee pivot guidance is attached as evidence.
    let ev = &e.evidence[0];
    assert_eq!(ev.source, "payid");
    assert!(ev.attributes.contains_key("pivot"));
    // `payid` is enrichment-only: it must NOT corroborate the identifier (that
    // would let mere PayID-shape inflate any email to a confirmed PII).
    assert!(crate::core::entity::is_non_corroborating_source("payid"));
}

#[tokio::test]
async fn process_flags_abn_payid_registry_resolvable() {
    let out = PayId
        .process(&Target::new(TargetKind::AbnAcn, "51824753556"), &ctx())
        .await
        .unwrap();
    let e = &out.entities[0];
    assert!(e.tags.iter().any(|t| t == "payid:abn"));
    assert!(e.tags.iter().any(|t| t == "payid:registry-resolvable"));
    assert!(
        e.evidence[0].attributes.contains_key("name_resolution"),
        "the register-resolution path is recorded for the ABN PayID"
    );
}

#[tokio::test]
async fn process_emits_nothing_for_invalid_abn() {
    let out = PayId
        .process(&Target::new(TargetKind::AbnAcn, "00000000000"), &ctx())
        .await
        .unwrap();
    assert!(out.entities.is_empty());
}
