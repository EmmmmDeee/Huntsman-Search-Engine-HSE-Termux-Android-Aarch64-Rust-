use super::*;

// Real record shape (the company name carries a non-breaking space, as ASIC's
// export does, to exercise the normalisation).
const REC: &str = "{\"BD_ORG_ACN\":\"081402379\",\
  \"BD_ORG_NAME\":\"AUSTRALIAN BUSINESS INSURANCE ADVISERS (ABIA)\u{a0}PTY LTD\",\
  \"BD_ORG_TYPE\":\"Australian Financial Services banning\",\
  \"BD_ORG_START_DT\":\"07/11/2006\",\"BD_ORG_END_DT\":\"07/11/2008\",\
  \"BD_ORG_COMMENT\":\"No comment made\"}";

fn rec(json: &str) -> Map<String, Value> {
    serde_json::from_str(json).expect("should succeed")
}

/// An epoch-day count while `REC`'s ban (07/11/2006 – 07/11/2008) was still
/// current, for tests whose focus is structural (org/ACN emission), not
/// currency — pinning "today" mid-ban keeps them unaffected by the passage
/// of real time or by the currency behaviour covered separately below.
fn mid_ban_today() -> i64 {
    crate::core::timeline::days_from_civil(2007, 1, 1)
}

#[test]
fn emits_adverse_org_and_acn() {
    let mut r = ModuleResult::new();
    emit_banned_org(&rec(REC), "scan", mid_ban_today(), &mut r);
    let e = &r.entities;

    let org = e
        .iter()
        .find(|x| x.kind == EntityKind::Organisation)
        .expect("organisation");
    assert!(org.value.contains("ABIA") && org.value.contains("PTY LTD"));
    assert!(!org.value.contains('\u{a0}'), "nbsp must be normalised to a space");
    assert!(org.has_tag("asic-banned") && org.has_tag("regulatory-action"));
    assert!(!org.has_tag("ban-expired"), "the ban was still current at `mid_ban_today`");
    assert!(org.evidence.iter().any(|ev| ev
        .attributes
        .get("ban_type")
        .is_some_and(|v| v.contains("Financial Services"))));

    let acn = e
        .iter()
        .find(|x| x.kind == EntityKind::AbnAcn)
        .expect("acn");
    assert_eq!(
        acn.value.chars().filter(char::is_ascii_digit).collect::<String>(),
        "081402379"
    );
}

#[test]
fn checksum_invalid_acn_is_not_emitted_as_a_pivot() {
    // "111111111" has the right digit count (9) but fails the ASIC check-digit
    // checksum (util::abn::is_valid_acn) — ASIC's own export can carry a
    // data-entry typo, and a mere digit count must not be trusted as a real
    // ACN pivot.
    let bad = rec(&REC.replace("081402379", "111111111"));
    let mut r = ModuleResult::new();
    emit_banned_org(&bad, "scan", mid_ban_today(), &mut r);
    assert!(
        !r.entities.iter().any(|x| x.kind == EntityKind::AbnAcn),
        "a checksum-invalid ACN must not be emitted as a pivot"
    );
    // The organisation finding itself is unaffected.
    assert!(r.entities.iter().any(|x| x.kind == EntityKind::Organisation));
}

#[test]
fn name_matching_requires_all_tokens() {
    assert!(record_name_matches(&rec(REC), "Australian Business Insurance"));
    assert!(!record_name_matches(&rec(REC), "Acme Roofing"));
}

#[test]
fn name_matching_is_whole_word_not_substring() {
    // Regression: two query tokens could each land as a SUBSTRING inside a
    // DIFFERENT unrelated word of an otherwise-unrelated banned entity —
    // "cotton"/"on" both land inside "sCOTTONi"/"cONstruction" — attributing
    // that real company's ASIC ban to an unrelated business.
    let scottoni = rec(r#"{"BD_ORG_NAME":"SCOTTONI CONSTRUCTION PTY LTD"}"#);
    assert!(
        !record_name_matches(&scottoni, "Cotton On"),
        "\"cotton\"/\"on\" must not match as substrings of \"SCOTTONI\"/\"CONSTRUCTION\""
    );
}

// ── Ban-currency: an expired ban must not present identically to a current one ──

#[test]
fn parse_au_date_reads_ddmmyyyy_and_rejects_junk() {
    assert_eq!(
        parse_au_date("07/11/2008"),
        Some(crate::core::timeline::days_from_civil(2008, 11, 7))
    );
    assert_eq!(parse_au_date("Permanent banning"), None);
    assert_eq!(parse_au_date(""), None);
    assert_eq!(parse_au_date("31/13/2020"), None, "month 13 is not real");
    assert_eq!(parse_au_date("07/11/1899"), None, "outside the plausible year bound");
}

#[test]
fn ban_is_expired_only_for_a_genuine_past_date() {
    let today = crate::core::timeline::days_from_civil(2026, 8, 31);
    assert!(ban_is_expired(Some("07/11/2008"), today), "18 years past end date");
    assert!(
        !ban_is_expired(Some("04/10/2027"), today),
        "end date still in the future"
    );
    assert!(!ban_is_expired(None, today), "no end date (open-ended) is never expired");
    assert!(
        !ban_is_expired(Some("Permanent banning"), today),
        "unparseable free text must not be treated as expired"
    );
}

#[test]
fn emit_banned_org_demotes_and_tags_an_expired_ban() {
    // The exact live-reproduced case: a ban that ended in 2008, evaluated as
    // of a "today" long after — must read as historical, not current.
    let today = crate::core::timeline::days_from_civil(2026, 8, 31);
    let mut r = ModuleResult::new();
    emit_banned_org(&rec(REC), "scan", today, &mut r);
    let org = r
        .entities
        .iter()
        .find(|x| x.kind == EntityKind::Organisation)
        .expect("organisation");
    assert!(org.has_tag("ban-expired"));
    assert!(
        org.confidence < confidence::MEDIUM_PLUS,
        "an expired ban must rank below a current one: {}",
        org.confidence
    );
    assert!(
        org.evidence[0].summary.contains("ban expired"),
        "evidence text must read past tense: {}",
        org.evidence[0].summary
    );
}

#[test]
fn is_free_keyless_corporate_module() {
    let m = AsicBannedOrgs;
    assert!(matches!(m.cost(), crate::core::module::ModuleCost::Free));
    assert_eq!(m.category(), ModuleCategory::Corporate);
    assert!(!m.attack_techniques().is_empty());
    assert!(m.accepts(&Target::new(TargetKind::Organisation, "Acme Pty Ltd")));
    assert!(!m.accepts(&Target::new(TargetKind::FullName, "Jane Citizen")));
}

/// Live end-to-end proof against the REAL ASIC dataset — no mock. Run with
/// `cargo test -p huntsman-search-engine asic_banned_orgs_live -- --ignored --nocapture`.
#[tokio::test]
#[ignore = "hits the live data.gov.au ASIC datastore; run manually"]
async fn asic_banned_orgs_live_finds_a_banned_org() {
    let (bus, _rx) = tokio::sync::broadcast::channel(1);
    let ctx = ModuleContext {
        scan_id: "live".into(),
        bus,
        http: reqwest::Client::new(),
        keys: std::collections::HashMap::new(),
        cancel: crate::core::cancel::CancelHandle::new(),
    };
    let r = AsicBannedOrgs
        .process(
            &Target::new(TargetKind::Organisation, "Australian Business Insurance Advisers"),
            &ctx,
        )
        .await
        .expect("live ASIC query must not error");
    eprintln!("asic_banned_orgs live: {} entities", r.entities.len());
    assert!(
        r.entities
            .iter()
            .any(|e| e.kind == EntityKind::Organisation && e.has_tag("asic-banned")),
        "expected the banned-organisation finding from the live register"
    );
}
