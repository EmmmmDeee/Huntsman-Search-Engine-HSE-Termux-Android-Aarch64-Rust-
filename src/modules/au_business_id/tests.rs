use super::*;

/// Minimal offline `ModuleContext` — this module never touches the network, so
/// the client/keys/proxy fields are inert.
fn ctx() -> ModuleContext {
    let (bus, _rx) = tokio::sync::broadcast::channel(1);
    ModuleContext {
        scan_id: "test".into(),
        bus,
        http: reqwest::Client::new(),
        keys: std::collections::HashMap::new(),
        cancel: crate::core::cancel::CancelHandle::new(),
        proxy_pool: Default::default(),
    }
}

fn digits(s: &str) -> String {
    s.chars().filter(char::is_ascii_digit).collect()
}

#[test]
fn metadata_and_accepts_gate() {
    let m = AuBusinessId;
    assert_eq!(m.name(), "au_business_id");
    assert!(m.is_passive());
    assert!(matches!(m.cost(), crate::core::module::ModuleCost::Free));
    assert!(!m.description().trim().is_empty());
    assert!(!m.attack_techniques().is_empty());
    assert!(m.produces().contains(&EntityKind::AbnAcn));
    // Only ABN/ACN targets dispatch here.
    assert!(m.accepts(&Target::new(TargetKind::AbnAcn, "53004085616")));
    assert!(!m.accepts(&Target::new(TargetKind::FullName, "Haigen Bamford")));
    assert!(!m.accepts(&Target::new(TargetKind::Email, "a@b.com")));
}

#[test]
fn format_acn_groups_nine_digits() {
    assert_eq!(format_acn("004085616"), "004 085 616");
    assert_eq!(format_acn("12345"), "12345"); // wrong length → passthrough
    assert_eq!(format_acn("abcdefghi"), "abcdefghi"); // non-digit → passthrough
}

#[tokio::test]
async fn company_abn_classified_and_acn_pivot_emitted() {
    // 53004085616 is a checksum-valid company ABN embedding ACN 004085616.
    let r = AuBusinessId
        .process(&Target::new(TargetKind::AbnAcn, "53004085616"), &ctx())
        .await
        .expect("offline decode must not error");

    // The ABN entity is classified as a company.
    let abn = r
        .entities
        .iter()
        .find(|e| e.kind == EntityKind::AbnAcn && digits(&e.value) == "53004085616")
        .expect("ABN entity present");
    assert!(abn.has_tag("abn-valid"));
    assert!(abn.has_tag("au-company"));
    assert!(!abn.has_tag("au-non-company"));

    // The embedded ACN is surfaced as a derived pivot entity.
    let acn = r
        .entities
        .iter()
        .find(|e| e.kind == EntityKind::AbnAcn && digits(&e.value) == "004085616")
        .expect("derived ACN entity present");
    assert!(acn.has_tag("acn-valid"));
    assert!(acn.has_tag("au-company"));
    assert!(acn.has_tag("derived"));
    assert!(
        acn.evidence
            .iter()
            .any(|ev| ev.attributes.get("source_abn").map(String::as_str) == Some("53004085616")),
        "derived ACN must record the ABN it came from"
    );
}

#[tokio::test]
async fn non_company_abn_classified_without_acn() {
    // 51824753556 (ATO's own ABN) is valid but its tail is not a valid ACN.
    let r = AuBusinessId
        .process(&Target::new(TargetKind::AbnAcn, "51824753556"), &ctx())
        .await
        .expect("offline decode must not error");

    let abn = r
        .entities
        .iter()
        .find(|e| e.kind == EntityKind::AbnAcn && digits(&e.value) == "51824753556")
        .expect("ABN entity present");
    assert!(abn.has_tag("abn-valid"));
    assert!(abn.has_tag("au-non-company"));
    assert!(!abn.has_tag("au-company"));
    // No derived ACN — a non-company ABN embeds none.
    assert!(
        !r.entities.iter().any(|e| e.has_tag("derived")),
        "non-company ABN must not derive an ACN"
    );
}

#[tokio::test]
async fn bare_acn_classified_as_company_no_abn_invented() {
    let r = AuBusinessId
        .process(&Target::new(TargetKind::AbnAcn, "004085616"), &ctx())
        .await
        .expect("offline decode must not error");

    let acn = r
        .entities
        .iter()
        .find(|e| e.kind == EntityKind::AbnAcn && digits(&e.value) == "004085616")
        .expect("ACN entity present");
    assert!(acn.has_tag("acn-valid"));
    assert!(acn.has_tag("au-company"));
    // The ABN is not derivable from an ACN — exactly one entity, no fabricated ABN.
    assert_eq!(r.entities.len(), 1, "a bare ACN yields only itself");
}

#[tokio::test]
async fn invalid_identifier_yields_nothing() {
    // 53004085617 flips the last digit → invalid ABN and invalid ACN.
    let r = AuBusinessId
        .process(&Target::new(TargetKind::AbnAcn, "53004085617"), &ctx())
        .await
        .expect("offline decode must not error");
    assert!(
        r.entities.is_empty(),
        "a checksum-invalid identifier must produce no entities"
    );
}
