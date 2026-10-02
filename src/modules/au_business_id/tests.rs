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

// ── REQ-AUBUSINESSID-001: a re-derivation is not a second opinion ────────────

#[test]
fn this_modules_evidence_never_counts_as_independent_corroboration() {
    // The harm, stated at the boundary that causes it. This module reads the
    // ABN's own check digits — it observes nothing. When a live register has
    // already confirmed the same identifier, the arithmetic agreeing with the
    // digits it was computed from is not a second source, and counting it as
    // one inflates `source_count` → `c_effective` → every correlator rule and
    // dispatch gate keyed on cross-correlation.
    let mut e = Entity::new(
        EntityKind::AbnAcn,
        "51824753556",
        confidence::MEDIUM_HIGH,
        "s",
    );
    e.add_evidence(Evidence::new(
        "abn_lookup",
        "ABR confirms the ABN is registered and active",
    ));
    e.add_evidence(Evidence::new(
        SRC,
        "Checksum-valid company ABN; embeds ACN 824753556 (decoded offline)",
    ));

    assert_eq!(
        e.corroborating_sources().len(),
        1,
        "one live register plus an offline re-derivation is ONE source, got {:?}",
        e.corroborating_sources()
    );
    assert_eq!(e.source_count(), 1, "the count must agree with the set");

    // Control: the full evidence set is retained for display — the fix excludes
    // this source from CORROBORATION, it does not hide the finding.
    assert!(
        e.evidence_sources().contains(SRC),
        "the derivation must still be visible as evidence"
    );
    assert_eq!(e.evidence_sources().len(), 2);
}

#[test]
fn a_live_register_and_a_second_live_register_still_corroborate() {
    // The control that keeps the exclusion from swallowing real corroboration:
    // two genuine observers of the same ABN must still count as two.
    let mut e = Entity::new(
        EntityKind::AbnAcn,
        "51824753556",
        confidence::MEDIUM_HIGH,
        "s",
    );
    e.add_evidence(Evidence::new("abn_lookup", "ABR record"));
    e.add_evidence(Evidence::new("asic_business_names", "ASIC register record"));
    assert_eq!(e.corroborating_sources().len(), 2);
}

#[test]
fn the_module_declares_itself_a_derivation() {
    // Both halves of the declaration, asserted here as well as in the
    // architecture guard. `derivation_modules_are_exactly_the_enrichment_only_sources`
    // checks that the trait method and `ENRICHMENT_ONLY_SOURCES` AGREE — which
    // it did before this fix, because this module was absent from both. Two
    // declarations agreeing does not make them right, so the module states the
    // fact directly rather than only relative to the list.
    assert!(
        AuBusinessId.is_derivation(),
        "this module's output is a deterministic transform of its input"
    );
    assert!(
        crate::core::entity::is_enrichment_source(SRC),
        "the runtime exclusion is keyed on the source STRING, not the trait — \
         `hse_core::ENRICHMENT_ONLY_SOURCES` must name this module too"
    );
    // A derivation observes nothing, so it is necessarily passive.
    assert!(AuBusinessId.is_passive());
}
