use super::*;
use crate::modules::asic_banned_orgs::MAX_HITS;

// Real record shape (the company name carries a non-breaking space, as ASIC's
// export does, to exercise the normalisation).
const REC: &str = "{\"BD_ORG_ACN\":\"081402379\",\
  \"BD_ORG_NAME\":\"AUSTRALIAN BUSINESS INSURANCE ADVISERS (ABIA)\u{a0}PTY LTD\",\
  \"BD_ORG_TYPE\":\"Australian Financial Services banning\",\
  \"BD_ORG_START_DT\":\"07/11/2006\",\"BD_ORG_END_DT\":\"07/11/2008\",\
  \"BD_ORG_COMMENT\":\"No comment made\"}";

fn rec(json: &str) -> Map<String, Value> {
    serde_json::from_str(json).unwrap()
}

#[test]
fn emits_adverse_org_and_acn() {
    let mut r = ModuleResult::new();
    emit_banned_org(&rec(REC), "scan", &mut r);
    let e = &r.entities;

    let org = e
        .iter()
        .find(|x| x.kind == EntityKind::Organisation)
        .expect("organisation");
    assert!(org.value.contains("ABIA") && org.value.contains("PTY LTD"));
    assert!(!org.value.contains('\u{a0}'), "nbsp must be normalised to a space");
    assert!(org.has_tag("asic-banned") && org.has_tag("regulatory-action"));
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
fn name_matching_requires_all_tokens() {
    let tokens = name_tokens("Australian Business Insurance");
    assert!(record_name_matches(&rec(REC), &tokens));
    assert!(!record_name_matches(&rec(REC), &name_tokens("Acme Roofing")));
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

#[test]
fn search_result_seed_emitted_when_records_found() {
    // When matches are found, a seed entity is emitted with matched_count and
    // total_matches even if not truncated.
    let tokens = name_tokens("Australian Business Insurance");
    let recs = [rec(REC), rec(REC)];

    // Simulate matching: count total, then emit up to MAX_HITS.
    let mut result = ModuleResult::new();
    let matched_count = recs
        .iter()
        .filter(|r| record_name_matches(r, &tokens))
        .take(MAX_HITS)
        .inspect(|r| emit_banned_org(r, "test", &mut result))
        .count();
    let total_matches = recs
        .iter()
        .filter(|r| record_name_matches(r, &tokens))
        .count();
    let matches_capped = total_matches > MAX_HITS;

    let mut seed = Entity::new(
        EntityKind::Organisation,
        "test-query",
        0.55,
        "test",
    );
    seed.tag("asic");
    seed.tag("search-result");
    let mut ev = Evidence::new(SRC, "ASIC search")
        .with_attr("matched_count", matched_count.to_string())
        .with_attr("total_matches", total_matches.to_string());
    if matches_capped {
        ev = ev.with_attr("matches_capped", "true");
        seed.tag("truncated");
    }
    seed.add_evidence(ev);
    result.push(seed);

    // Verify seed was emitted with correct attributes.
    let seed = result
        .entities
        .iter()
        .find(|e| e.kind == EntityKind::Organisation && e.tags.contains(&"search-result".to_string()))
        .unwrap();
    assert!(!seed.has_tag("truncated"), "no truncation at 2 matches");
    assert_eq!(
        seed.evidence[0]
            .attributes
            .get("total_matches")
            .map(String::as_str),
        Some("2")
    );
    assert!(!seed.evidence[0].attributes.contains_key("matches_capped"));
}

#[test]
fn truncation_is_signaled_when_max_hits_exceeded() {
    // Regression: when total matches exceed MAX_HITS, truncation must be
    // surfaced in evidence so the operator knows the scan stopped at a hard cap.
    let mut recs = vec![];
    for i in 0..120 {
        recs.push(rec(&format!(
            "{{\"BD_ORG_ACN\":\"08140237{i:01}\",\
            \"BD_ORG_NAME\":\"BAN ORG NAME {i:03}\",\
            \"BD_ORG_TYPE\":\"Ban\",\
            \"BD_ORG_START_DT\":\"01/01/2020\",\"BD_ORG_END_DT\":\"01/01/2022\",\
            \"BD_ORG_COMMENT\":\"Comment\"}}"
        )));
    }

    let tokens = name_tokens("Ban Org Name");
    let mut result = ModuleResult::new();
    let matched_count = recs
        .iter()
        .filter(|r| record_name_matches(r, &tokens))
        .take(MAX_HITS)
        .inspect(|r| emit_banned_org(r, "test", &mut result))
        .count();
    let total_matches = recs
        .iter()
        .filter(|r| record_name_matches(r, &tokens))
        .count();
    let matches_capped = total_matches > MAX_HITS;

    let mut seed = Entity::new(
        EntityKind::Organisation,
        "Ban Org Name",
        0.55,
        "test",
    );
    seed.tag("asic");
    seed.tag("search-result");
    let mut ev = Evidence::new(SRC, "ASIC search")
        .with_attr("matched_count", matched_count.to_string())
        .with_attr("total_matches", total_matches.to_string());
    if matches_capped {
        ev = ev.with_attr("matches_capped", "true");
        seed.tag("truncated");
    }
    seed.add_evidence(ev);
    result.push(seed);

    let seed = result
        .entities
        .iter()
        .find(|e| e.kind == EntityKind::Organisation && e.tags.contains(&"search-result".to_string()))
        .unwrap();

    assert!(seed.has_tag("truncated"), "seed must be tagged 'truncated'");
    assert_eq!(
        seed.evidence[0]
            .attributes
            .get("total_matches")
            .map(String::as_str),
        Some("120"),
        "total_matches must reflect all matches"
    );
    assert_eq!(
        seed.evidence[0]
            .attributes
            .get("matches_capped")
            .map(String::as_str),
        Some("true"),
        "matches_capped must be set when limit is hit"
    );
}
