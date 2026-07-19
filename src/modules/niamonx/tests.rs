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
    // The breach-block evidence carries the canonical `breach_date` key AU-019's
    // temporal breach-cluster rule reads (mirroring the PBS-v2 path), taken from
    // `first_seen` — without it a PBS-v1 hit could never date-cluster.
    let block_ev = entity
        .evidence
        .iter()
        .find(|e| e.attributes.contains_key("blocks_total"))
        .expect("PBS-v1 breach-block evidence must be present");
    assert_eq!(
        block_ev.attributes.get("breach_date").map(String::as_str),
        Some("2019-01-01")
    );
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
    emit_ulp(resp, &mut entity, &mut result, "victim@example.com", "s");
    assert!(entity.has_tag("stealer-log"));
    assert!(entity.has_tag("infostealer"));
    // login differs from query → pivot emitted
    assert_eq!(result.entities.len(), 1);
    assert_eq!(result.entities[0].kind, EntityKind::Email);
}

#[test]
fn ulp_recovers_the_login_on_username_and_ip_scans() {
    // Full-fidelity: a stealer-log login that differs from the query is a genuinely
    // new identity (a username scan's login `jsmith@gmail.com`, an IP scan's
    // compromised account). It was silently dropped on Username/IpAddress scans
    // (the old Email/Domain-only gate) — neither a pivot nor stamped on evidence.
    for (kind, query) in [
        (TargetKind::Username, "jsmith"),
        (TargetKind::IpAddress, "203.0.113.10"),
    ] {
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
                    url: Some("https://mail.example.com/login".to_string()),
                    host: Some("mail.example.com".to_string()),
                    login: Some("jsmith@gmail.com".to_string()),
                }]),
            }),
        };
        let target = Target::new(kind, query);
        let mut entity = target.to_entity(0.80, "s");
        let mut result = ModuleResult::new();
        emit_ulp(resp, &mut entity, &mut result, query, "s");
        // The differing login is now promoted to a first-class Email pivot…
        assert!(
            result
                .entities
                .iter()
                .any(|e| e.kind == EntityKind::Email && e.value == "jsmith@gmail.com"),
            "the ULP login must surface as a pivot on a {kind:?} scan"
        );
        // …and is preserved on the record evidence regardless (full fidelity).
        assert!(
            entity
                .evidence
                .iter()
                .any(|ev| ev.attributes.get("login").map(String::as_str) == Some("jsmith@gmail.com")),
            "the ULP login must be stamped on the record evidence on a {kind:?} scan"
        );
    }
}

#[test]
fn module_metadata() {
    let m = NiamonX;
    assert_eq!(m.name(), "niamonx");
    assert!(!m.description().is_empty());
    assert_eq!(m.cost(), crate::core::module::ModuleCost::KeyGated);
    assert!(!m.attack_techniques().is_empty());
    assert!(m.produces().contains(&EntityKind::Email));
}

#[test]
fn attack_techniques_include_employee_names_for_the_pbs_v1_name_pivot() {
    use crate::core::attack;
    let t = NiamonX.attack_techniques();
    // The Breach-category default (Credentials + Email Addresses) omits
    // Employee Names, but PBS v1's meta.names corroboration mints Person
    // entities (process()'s name-pivot loop) — the same pattern
    // dehashed/see_know/oathnet_pro declare T1589.003 for.
    for id in ["T1589.001", "T1589.002", "T1589.003"] {
        assert!(t.contains(&id), "niamonx must claim {id}, got {t:?}");
        assert!(attack::technique(id).is_some(), "{id} must be catalogued");
    }
}

#[test]
fn pbs_v2_found_with_records_tags_breach() {
    let resp = PbsV2Response {
        success: true,
        data: Some(PbsV2Data {
            niamonx_success: true,
            error: None,
            stats: Some(PbsV2Stats {
                found: 1,
                with_passwords: 1,
                unique_sources: 1,
            }),
            records: Some(vec![PbsV2Record {
                source: Some(PbsV2Source {
                    name: Some("LeakSite".to_string()),
                    breach_date: Some("2022-03-01".to_string()),
                    compilation: Some(0),
                }),
                email: Some("other@example.com".to_string()),
                username: None,
                phone: None,
                fields: None,
            }]),
        }),
    };
    let target = Target::new(TargetKind::Email, "victim@example.com");
    let mut entity = target.to_entity(0.80, "s");
    let mut result = ModuleResult::new();
    emit_pbs_v2(resp, &mut entity, &mut result, "victim@example.com", "s");
    assert!(entity.has_tag("breach"), "breach tag must be set on hit");
    assert!(entity.has_tag("niamonx:breach:leaksite"));
    // The alternate email pivot is emitted.
    assert!(result.entities.iter().any(|e| e.kind == EntityKind::Email && e.value == "other@example.com"));
}

#[test]
fn pbs_v2_zero_found_is_quiet() {
    let resp = PbsV2Response {
        success: true,
        data: Some(PbsV2Data {
            niamonx_success: true,
            error: None,
            stats: Some(PbsV2Stats {
                found: 0,
                with_passwords: 0,
                unique_sources: 0,
            }),
            records: None,
        }),
    };
    let target = Target::new(TargetKind::Email, "clean@example.com");
    let mut entity = target.to_entity(0.80, "s");
    let mut result = ModuleResult::new();
    emit_pbs_v2(resp, &mut entity, &mut result, "clean@example.com", "s");
    assert!(!entity.has_tag("breach"));
    assert!(result.entities.is_empty());
}
