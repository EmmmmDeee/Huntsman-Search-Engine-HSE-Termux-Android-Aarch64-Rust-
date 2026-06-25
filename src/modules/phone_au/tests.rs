use super::*;

// ── Pure classifier (no I/O) ──────────────────────────────────────────────────

#[test]
fn classifies_mobile() {
    let l = classify_au_phone("412345678").unwrap();
    assert_eq!(l.line_type, LineType::Mobile);
    assert!(l.region.is_none());
}

#[test]
fn classifies_fixed_line_regions() {
    // 02 → Central East (NSW, ACT)
    let nsw = classify_au_phone("298765432").unwrap();
    assert_eq!(nsw.line_type, LineType::FixedLine);
    assert_eq!(nsw.region, Some("central-east"));
    assert_eq!(nsw.states, Some("NSW, ACT"));
    assert_eq!(nsw.area_code, Some('2'));

    // 03 → South East (VIC, TAS)
    let vic = classify_au_phone("398765432").unwrap();
    assert_eq!(vic.region, Some("south-east"));
    assert_eq!(vic.states, Some("VIC, TAS"));

    // 07 → North East (QLD)
    let qld = classify_au_phone("730001234").unwrap();
    assert_eq!(qld.region, Some("north-east"));
    assert_eq!(qld.states, Some("QLD"));

    // 08 → Central and West (SA, WA, NT)
    let saw = classify_au_phone("881234567").unwrap();
    assert_eq!(saw.region, Some("central-west"));
    assert_eq!(saw.states, Some("SA, WA, NT"));
}

#[test]
fn classifies_service_numbers_with_correct_precedence() {
    // 1800 freephone — must win over the bare `1`/`13` checks.
    assert_eq!(
        classify_au_phone("1800123456").unwrap().line_type,
        LineType::Freephone
    );
    // 1300 local-rate — must win over the `13` shortcode check.
    assert_eq!(
        classify_au_phone("1300123456").unwrap().line_type,
        LineType::LocalRate
    );
    // 13 XX XX shortcode local-rate.
    assert_eq!(
        classify_au_phone("131234").unwrap().line_type,
        LineType::LocalRate
    );
    // 190x premium.
    assert_eq!(
        classify_au_phone("1900123456").unwrap().line_type,
        LineType::Premium
    );
    // 05 VoIP/digital.
    assert_eq!(
        classify_au_phone("512345678").unwrap().line_type,
        LineType::Voip
    );
}

#[test]
fn rejects_out_of_range_and_non_digit() {
    assert!(classify_au_phone("12345").is_none()); // too short
    assert!(classify_au_phone("12345678901").is_none()); // too long
    assert!(classify_au_phone("4abc56789").is_none()); // non-digit
    assert!(classify_au_phone("").is_none());
}

#[test]
fn unknown_leading_digit_is_classified_unknown_not_dropped() {
    // A `6…` national number is not a standard AU prefix, but it's still a +61
    // number — keep it as Unknown rather than silently dropping it.
    let l = classify_au_phone("612345678").unwrap();
    assert_eq!(l.line_type, LineType::Unknown);
    assert!(l.region.is_none());
}

// ── National-number extraction (AU detection across input shapes) ──────────────

#[test]
fn extracts_national_from_international_and_local_forms() {
    // International E.164.
    assert_eq!(au_national("+61 2 9876 5432").as_deref(), Some("298765432"));
    // ITU 00 international prefix.
    assert_eq!(
        au_national("0061 412 345 678").as_deref(),
        Some("412345678")
    );
    // AU local trunk-0 forms (via to_e164_au).
    assert_eq!(au_national("0298765432").as_deref(), Some("298765432"));
    assert_eq!(au_national("(02) 9876 5432").as_deref(), Some("298765432"));
    assert_eq!(au_national("0412 345 678").as_deref(), Some("412345678"));
}

#[test]
fn rejects_non_au_numbers() {
    // A foreign E.164 number is not ours.
    assert!(au_national("+1 555 123 4567").is_none());
    assert!(au_national("+44 20 7183 8750").is_none());
    // A bare national number with no country marker is ambiguous → not claimed.
    assert!(au_national("202-555-0100").is_none());
}

// ── End-to-end module behaviour ───────────────────────────────────────────────

fn test_ctx() -> ModuleContext {
    let (bus, _rx) = tokio::sync::broadcast::channel(8);
    ModuleContext {
        scan_id: "test".into(),
        bus,
        http: reqwest::Client::new(),
        keys: Default::default(),
        cancel: Default::default(),
        proxy_pool: Default::default(),
    }
}

#[test]
fn accepts_only_phone() {
    let m = PhoneAu;
    assert!(m.accepts(&Target::new(TargetKind::Phone, "+61298765432")));
    assert!(!m.accepts(&Target::new(TargetKind::Email, "x@y.com")));
    assert!(!m.accepts(&Target::new(TargetKind::Coordinates, "-33.0,151.0")));
}

#[tokio::test]
async fn enriches_fixed_line_with_region_tags_and_evidence() {
    let m = PhoneAu;
    let target = Target::new(TargetKind::Phone, "+61 2 9876 5432");
    let r = m.process(&target, &test_ctx()).await.unwrap();
    let e = r
        .entities
        .iter()
        .find(|e| e.kind == EntityKind::Phone)
        .expect("a Phone entity");
    // Canonical E.164, and AU region intelligence as tags.
    assert_eq!(e.value, "+61298765432");
    assert!(e.has_tag("au-phone"));
    assert!(e.has_tag("line:fixed-line"));
    assert!(e.has_tag("au-region:central-east"));
    assert!(e.has_tag("geographic"));
    // The region facts ride on the evidence for the dossier.
    let ev = e.evidence.first().expect("evidence");
    assert_eq!(
        ev.attributes.get("au_region_states").map(String::as_str),
        Some("NSW, ACT")
    );
    assert_eq!(
        ev.attributes.get("area_code").map(String::as_str),
        Some("02")
    );
}

#[tokio::test]
async fn enriches_mobile_without_region() {
    let m = PhoneAu;
    let target = Target::new(TargetKind::Phone, "0412 345 678");
    let r = m.process(&target, &test_ctx()).await.unwrap();
    let e = r
        .entities
        .iter()
        .find(|e| e.kind == EntityKind::Phone)
        .unwrap();
    assert_eq!(e.value, "+61412345678");
    assert!(e.has_tag("line:mobile"));
    assert!(e.has_tag("mobile"));
    // A mobile is non-geographic — no region tag must be asserted.
    assert!(!e.tags.iter().any(|t| t.starts_with("au-region:")));
    assert!(!e.has_tag("geographic"));
}

#[tokio::test]
async fn flags_freephone_as_non_geographic_org_signal() {
    let m = PhoneAu;
    let target = Target::new(TargetKind::Phone, "+61 1800 123 456");
    let r = m.process(&target, &test_ctx()).await.unwrap();
    let e = r
        .entities
        .iter()
        .find(|e| e.kind == EntityKind::Phone)
        .unwrap();
    assert!(e.has_tag("line:freephone"));
    assert!(e.has_tag("non-geographic"));
    assert!(!e.has_tag("geographic"));
}

#[tokio::test]
async fn non_au_phone_yields_nothing() {
    let m = PhoneAu;
    let target = Target::new(TargetKind::Phone, "+1 555 123 4567");
    let r = m.process(&target, &test_ctx()).await.unwrap();
    assert!(
        r.entities.is_empty(),
        "a non-AU number must not be claimed by phone_au"
    );
}
