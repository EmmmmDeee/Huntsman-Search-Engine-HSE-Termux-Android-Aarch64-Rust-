use super::*;
use crate::core::scan::TargetKind;

#[test]
fn accepts_expected_kinds() {
    let m = NiamonX;
    assert!(m.accepts(&Target::new(TargetKind::Email, "x@y.com")));
    assert!(m.accepts(&Target::new(TargetKind::Username, "alice")));
    assert!(m.accepts(&Target::new(TargetKind::IpAddress, "1.1.1.1")));
    assert!(m.accepts(&Target::new(TargetKind::Domain, "example.com")));
    assert!(!m.accepts(&Target::new(TargetKind::Phone, "+61400000000")));
}

#[test]
fn pbs_v1_skips_not_found_status() {
    let resp = PbsV1Response {
        success: true,
        data: Some(PbsV1Data {
            status: Some("not_found".to_string()),
            error: None,
            meta: Some(PbsV1Meta {
                blocks_total: 0,
                emails: None,
                names: None,
                first_seen: None,
                last_seen: None,
            }),
            risk: Some(PbsV1Risk {
                score: 0,
                level: "Low".to_string(),
            }),
            blocks: None,
            rate: None,
        }),
    };
    let target = Target::new(TargetKind::Email, "x@y.com");
    let mut entity = target.to_entity(0.80, "s");
    let mut result = ModuleResult::new();
    emit_pbs_v1(resp, &mut entity, &mut result, "x@y.com", "s");
    assert!(!entity.has_tag("breach"));
    assert!(entity.evidence.is_empty());
}

#[test]
fn pbs_v1_found_with_blocks_tags_breach_and_pivots_names() {
    // A real hit: positive status "found" (NOT "ok"), breach blocks, and
    // corroborating names. Must tag breach and emit a Person pivot.
    let resp = PbsV1Response {
        success: true,
        data: Some(PbsV1Data {
            status: Some("found".to_string()),
            error: None,
            meta: Some(PbsV1Meta {
                blocks_total: 2,
                emails: Some(vec!["other@example.com".to_string()]),
                names: Some(vec!["Jane Roe".to_string()]),
                first_seen: Some("2019-01-01".to_string()),
                last_seen: Some("2023-06-01".to_string()),
            }),
            risk: None,
            blocks: Some(vec![PbsV1Block {
                title: Some("ExampleLeak".to_string()),
                description: Some("leak".to_string()),
            }]),
            rate: None,
        }),
    };
    let target = Target::new(TargetKind::Email, "x@y.com");
    let mut entity = target.to_entity(0.80, "s");
    let mut result = ModuleResult::new();
    emit_pbs_v1(resp, &mut entity, &mut result, "x@y.com", "s");
    assert!(entity.has_tag("breach"));
    assert!(entity.has_tag("niamonx:breach:exampleleak"));
    // One Email pivot + one Person pivot.
    assert!(
        result
            .entities
            .iter()
            .any(|e| e.kind == EntityKind::Person && e.value == "Jane Roe")
    );
    assert!(
        result
            .entities
            .iter()
            .any(|e| e.kind == EntityKind::Email && e.value == "other@example.com")
    );
}

#[test]
fn ulp_emits_stealer_tag_and_pivots() {
    let resp = UlpResponse {
        success: true,
        data: Some(UlpData {
            error: None,
            stats: Some(UlpStats {
                total: 1,
                unique_hosts: 1,
                with_password: 1,
            }),
            records: Some(vec![UlpRecord {
                url: Some("https://bank.example.com/login".to_string()),
                host: Some("bank.example.com".to_string()),
                login: Some("other@example.com".to_string()),
            }]),
        }),
    };
    let target = Target::new(TargetKind::Email, "victim@example.com");
    let mut entity = target.to_entity(0.80, "s");
    let mut result = ModuleResult::new();
    emit_ulp(
        resp,
        TargetKind::Email,
        &mut entity,
        &mut result,
        "victim@example.com",
        "s",
    );
    assert!(entity.has_tag("stealer-log"));
    assert!(entity.has_tag("infostealer"));
    // login differs from query and target is Email → pivot emitted
    assert_eq!(result.entities.len(), 1);
    assert_eq!(result.entities[0].kind, EntityKind::Email);
}
