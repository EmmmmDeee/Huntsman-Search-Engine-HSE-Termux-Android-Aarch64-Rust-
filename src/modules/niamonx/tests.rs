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
    let resp = Envelope::from_parts(
        true,
        Some(PbsV1Data {
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
    );
    let target = Target::new(TargetKind::Email, "x@y.com");
    let mut entity = target.to_entity(confidence::HIGH_PLUSPLUS, "s");
    let mut result = ModuleResult::new();
    let mut seen = std::collections::HashSet::new();
    emit_pbs_v1(
        payload("pbs_v1", resp).expect("fixture is a real answer"), &mut entity, &mut result, "x@y.com", "s", &mut seen);
    assert!(!entity.has_tag("breach"));
    assert!(entity.evidence.is_empty());
}

#[test]
fn pbs_v1_found_with_blocks_tags_breach_and_pivots_names() {
    // A real hit: positive status "found" (NOT "ok"), breach blocks, and
    // corroborating names. Must tag breach and emit a Person pivot.
    let resp = Envelope::from_parts(
        true,
        Some(PbsV1Data {
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
    );
    let target = Target::new(TargetKind::Email, "x@y.com");
    let mut entity = target.to_entity(confidence::HIGH_PLUSPLUS, "s");
    let mut result = ModuleResult::new();
    let mut seen = std::collections::HashSet::new();
    emit_pbs_v1(
        payload("pbs_v1", resp).expect("fixture is a real answer"), &mut entity, &mut result, "x@y.com", "s", &mut seen);
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
    // Regression: every pivot must carry its own evidence, not just the
    // shared seed entity — a pivot with zero evidence is invisible to any
    // evidence-based dossier view or correlator despite claiming corroboration.
    assert!(
        result.entities.iter().all(|e| !e.evidence.is_empty()),
        "every PBS v1 pivot must carry evidence: {:?}",
        result.entities
    );
}

#[test]
fn pbs_v1_suppresses_username_derived_name_pivots() {
    // A breach `meta.names` entry that is a doubled/slug username
    // ("rhino-ryno23 rhino-ryno23") is not a real person and must never be minted
    // as a Person pivot — the shared `is_username_derived_name` guard (also used
    // by see_know/oathnet_pro) suppresses it. A genuine hit is still present
    // (blocks_total > 0), so the guard is what drops the pivot, not an empty hit.
    let resp = Envelope::from_parts(
        true,
        Some(PbsV1Data {
            status: Some("found".to_string()),
            error: None,
            meta: Some(PbsV1Meta {
                blocks_total: 1,
                emails: None,
                names: Some(vec!["rhino-ryno23 rhino-ryno23".to_string()]),
                first_seen: None,
                last_seen: None,
            }),
            risk: None,
            blocks: None,
            rate: None,
        }),
    );
    let target = Target::new(TargetKind::Email, "x@y.com");
    let mut entity = target.to_entity(0.80, "s");
    let mut result = ModuleResult::new();
    let mut seen = std::collections::HashSet::new();
    emit_pbs_v1(
        payload("pbs_v1", resp).expect("fixture is a real answer"), &mut entity, &mut result, "x@y.com", "s", &mut seen);
    assert!(
        !result.entities.iter().any(|e| e.kind == EntityKind::Person),
        "a username-derived meta.names entry must not mint a Person pivot"
    );
}

#[test]
fn ulp_emits_stealer_tag_and_pivots() {
    let resp = Envelope::from_parts(
        true,
        Some(UlpData {
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
    );
    let target = Target::new(TargetKind::Email, "victim@example.com");
    let mut entity = target.to_entity(confidence::HIGH_PLUSPLUS, "s");
    let mut result = ModuleResult::new();
    let mut seen = std::collections::HashSet::new();
    emit_ulp(
        payload("ulp_search", resp).expect("fixture is a real answer"), &mut entity, &mut result, "victim@example.com", "s", &mut seen);
    assert!(entity.has_tag("stealer-log"));
    assert!(entity.has_tag("infostealer"));
    // login differs from query → Email pivot emitted, plus the login-URL Url pivot.
    assert_eq!(result.entities.len(), 2);
    assert!(
        result
            .entities
            .iter()
            .any(|e| e.kind == EntityKind::Email && e.value == "other@example.com")
    );
    assert!(
        result
            .entities
            .iter()
            .any(|e| e.kind == EntityKind::Url && e.value == "https://bank.example.com/login")
    );
}

#[test]
fn ulp_promotes_the_login_url_to_a_first_class_url_pivot() {
    // Gap fix: the captured login `url` — the page where credentials were stolen —
    // was previously only ever stamped on evidence text/attrs, never minted as its
    // own pivot entity, unlike the sibling oathnet_pro stealer extractor which mints
    // exactly this field as EntityKind::Url. It must now surface as a real Url pivot
    // so downstream modules (wayback/cert/dns) can chase the credential-capture page.
    let resp = Envelope::from_parts(
        true,
        Some(UlpData {
            error: None,
            stats: Some(UlpStats {
                total: 1,
                unique_hosts: 1,
                with_password: 1,
            }),
            records: Some(vec![UlpRecord {
                url: Some("https://bank.example.com/login".to_string()),
                host: Some("bank.example.com".to_string()),
                login: Some("victim@example.com".to_string()),
            }]),
        }),
    );
    // Login equals the query, so no Email/Username pivot fires — isolating the
    // Url pivot as the only entity this record can produce.
    let target = Target::new(TargetKind::Email, "victim@example.com");
    let mut entity = target.to_entity(confidence::HIGH_PLUSPLUS, "s");
    let mut result = ModuleResult::new();
    let mut seen = std::collections::HashSet::new();
    emit_ulp(
        payload("ulp_search", resp).expect("fixture is a real answer"), &mut entity, &mut result, "victim@example.com", "s", &mut seen);
    let url_pivot = result
        .entities
        .iter()
        .find(|e| e.kind == EntityKind::Url)
        .expect("the ULP login url must surface as a first-class Url pivot");
    assert_eq!(url_pivot.value, "https://bank.example.com/login");
    assert!(url_pivot.has_tag("ulp-pivot"));
    assert!(url_pivot.has_tag("credential-url"));
    // The record's host is deliberately NOT also minted as a Domain (matches
    // oathnet_pro's rationale: a stealer host is a third-party service, not
    // something the subject owns).
    assert!(
        !result
            .entities
            .iter()
            .any(|e| e.kind == EntityKind::Domain && e.value == "bank.example.com")
    );
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
        let resp = Envelope::from_parts(
            true,
            Some(UlpData {
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
        );
        let target = Target::new(kind, query);
        let mut entity = target.to_entity(confidence::HIGH_PLUSPLUS, "s");
        let mut result = ModuleResult::new();
        let mut seen = std::collections::HashSet::new();
        emit_ulp(
        payload("ulp_search", resp).expect("fixture is a real answer"), &mut entity, &mut result, query, "s", &mut seen);
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
    let resp = Envelope::from_parts(
        true,
        Some(PbsV2Data {
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
    );
    let target = Target::new(TargetKind::Email, "victim@example.com");
    let mut entity = target.to_entity(confidence::HIGH_PLUSPLUS, "s");
    let mut result = ModuleResult::new();
    let mut seen = std::collections::HashSet::new();
    emit_pbs_v2(
        payload("pbs_v2", resp).expect("fixture is a real answer"), &mut entity, &mut result, "victim@example.com", "s", &mut seen);
    assert!(entity.has_tag("breach"), "breach tag must be set on hit");
    assert!(entity.has_tag("niamonx:breach:leaksite"));
    // The alternate email pivot is emitted.
    assert!(result.entities.iter().any(|e| e.kind == EntityKind::Email && e.value == "other@example.com"));
}

#[test]
fn a_formatted_and_a_bare_spelling_of_the_same_phone_dedup_to_one_entity() {
    // Regression: a bare `.to_lowercase()` case-folds but does not strip the
    // punctuation formatting the way `Entity::new` does internally via
    // `core::entity::normalise`'s Phone arm, so two PBS v2 records spelling
    // the same number with different formatting each earned their own `seen`
    // slot and minted a duplicate Phone entity — even though both collapse
    // onto the same uid once constructed.
    let resp = Envelope::from_parts(
        true,
        Some(PbsV2Data {
            niamonx_success: true,
            error: None,
            stats: Some(PbsV2Stats {
                found: 2,
                with_passwords: 0,
                unique_sources: 1,
            }),
            records: Some(vec![
                PbsV2Record {
                    source: Some(PbsV2Source {
                        name: Some("LeakSite".to_string()),
                        breach_date: Some("2022-03-01".to_string()),
                        compilation: Some(0),
                    }),
                    email: None,
                    username: None,
                    phone: Some("5551234567".to_string()),
                    fields: None,
                },
                PbsV2Record {
                    source: Some(PbsV2Source {
                        name: Some("LeakSite".to_string()),
                        breach_date: Some("2022-03-01".to_string()),
                        compilation: Some(0),
                    }),
                    email: None,
                    username: None,
                    phone: Some("(555) 123-4567".to_string()),
                    fields: None,
                },
            ]),
        }),
    );
    let target = Target::new(TargetKind::Email, "victim@example.com");
    let mut entity = target.to_entity(confidence::HIGH_PLUSPLUS, "s");
    let mut result = ModuleResult::new();
    let mut seen = std::collections::HashSet::new();
    emit_pbs_v2(
        payload("pbs_v2", resp).expect("fixture is a real answer"), &mut entity, &mut result, "victim@example.com", "s", &mut seen);
    let phones: Vec<&Entity> = result
        .entities
        .iter()
        .filter(|e| e.kind == EntityKind::Phone)
        .collect();
    assert_eq!(
        phones.len(),
        1,
        "a formatted and a bare spelling of the same number must dedup to one entity: {phones:?}"
    );
}

#[test]
fn a_sigil_prefixed_and_a_bare_spelling_of_the_same_pbs_v2_username_dedup_to_one_entity() {
    // Regression: a bare `.to_lowercase()` case-folds but does not strip a
    // leading `@` handle sigil the way `Entity::new` does internally via
    // `core::entity::normalise`'s Username arm, so two PBS v2 records spelling
    // the same handle with/without the sigil each earned their own `seen`
    // slot and minted a duplicate Username entity — even though both collapse
    // onto the same uid once constructed.
    let resp = Envelope::from_parts(
        true,
        Some(PbsV2Data {
            niamonx_success: true,
            error: None,
            stats: Some(PbsV2Stats {
                found: 2,
                with_passwords: 0,
                unique_sources: 1,
            }),
            records: Some(vec![
                PbsV2Record {
                    source: Some(PbsV2Source {
                        name: Some("LeakSite".to_string()),
                        breach_date: Some("2022-03-01".to_string()),
                        compilation: Some(0),
                    }),
                    email: None,
                    username: Some("jordan_m".to_string()),
                    phone: None,
                    fields: None,
                },
                PbsV2Record {
                    source: Some(PbsV2Source {
                        name: Some("LeakSite".to_string()),
                        breach_date: Some("2022-03-01".to_string()),
                        compilation: Some(0),
                    }),
                    email: None,
                    username: Some("@jordan_m".to_string()),
                    phone: None,
                    fields: None,
                },
            ]),
        }),
    );
    let target = Target::new(TargetKind::Email, "victim@example.com");
    let mut entity = target.to_entity(confidence::HIGH_PLUSPLUS, "s");
    let mut result = ModuleResult::new();
    let mut seen = std::collections::HashSet::new();
    emit_pbs_v2(
        payload("pbs_v2", resp).expect("fixture is a real answer"), &mut entity, &mut result, "victim@example.com", "s", &mut seen);
    let unames: Vec<&Entity> = result
        .entities
        .iter()
        .filter(|e| e.kind == EntityKind::Username)
        .collect();
    assert_eq!(
        unames.len(),
        1,
        "a sigil-prefixed and a bare spelling of the same handle must dedup to one entity: {unames:?}"
    );
}

#[test]
fn a_quote_wrapped_and_a_clean_spelling_of_the_same_ulp_login_dedup_to_one_entity() {
    // Regression: `login.to_lowercase()` doesn't strip a wrapping quote (a
    // CSV/SQL-dump export artifact) the way `core::entity::normalise`'s
    // Username arm does. A leading-quote fixture is used, not a leading `@`
    // one: `login.contains('@')` decides Email vs Username kind, and `@` would
    // flip this fixture to the Email branch instead of exercising Username.
    let resp = Envelope::from_parts(
        true,
        Some(UlpData {
            error: None,
            stats: Some(UlpStats {
                total: 2,
                unique_hosts: 1,
                with_password: 0,
            }),
            records: Some(vec![
                UlpRecord {
                    url: Some("https://bank.example.com/login".to_string()),
                    host: Some("bank.example.com".to_string()),
                    login: Some("jordan_m".to_string()),
                },
                UlpRecord {
                    url: Some("https://bank.example.com/login2".to_string()),
                    host: Some("bank.example.com".to_string()),
                    login: Some("\"jordan_m".to_string()),
                },
            ]),
        }),
    );
    let target = Target::new(TargetKind::Email, "victim@example.com");
    let mut entity = target.to_entity(confidence::HIGH_PLUSPLUS, "s");
    let mut result = ModuleResult::new();
    let mut seen = std::collections::HashSet::new();
    emit_ulp(
        payload("ulp_search", resp).expect("fixture is a real answer"), &mut entity, &mut result, "victim@example.com", "s", &mut seen);
    let unames: Vec<&Entity> = result
        .entities
        .iter()
        .filter(|e| e.kind == EntityKind::Username)
        .collect();
    assert_eq!(
        unames.len(),
        1,
        "a quote-wrapped and a clean spelling of the same login must dedup to one entity: {unames:?}"
    );
}

#[test]
fn pbs_v2_zero_found_is_quiet() {
    let resp = Envelope::from_parts(
        true,
        Some(PbsV2Data {
            niamonx_success: true,
            error: None,
            stats: Some(PbsV2Stats {
                found: 0,
                with_passwords: 0,
                unique_sources: 0,
            }),
            records: None,
        }),
    );
    let target = Target::new(TargetKind::Email, "clean@example.com");
    let mut entity = target.to_entity(confidence::HIGH_PLUSPLUS, "s");
    let mut result = ModuleResult::new();
    let mut seen = std::collections::HashSet::new();
    emit_pbs_v2(
        payload("pbs_v2", resp).expect("fixture is a real answer"), &mut entity, &mut result, "clean@example.com", "s", &mut seen);
    assert!(!entity.has_tag("breach"));
    assert!(result.entities.is_empty());
}

#[test]
fn a_shared_seen_set_dedups_the_same_email_restated_across_pbs_v1_and_pbs_v2() {
    // Regression: PBS v1 and PBS v2 are independent endpoints over the SAME
    // underlying NiamonX provider, and commonly restate the same
    // corroborating email. Without a dedup guard spanning both calls, this
    // minted two separate Email pivots for one restated fact instead of one.
    let v1 = Envelope::from_parts(
        true,
        Some(PbsV1Data {
            status: Some("found".to_string()),
            error: None,
            meta: Some(PbsV1Meta {
                blocks_total: 1,
                emails: Some(vec!["Other@Example.com".to_string()]),
                names: None,
                first_seen: None,
                last_seen: None,
            }),
            risk: None,
            blocks: None,
            rate: None,
        }),
    );
    let v2 = Envelope::from_parts(
        true,
        Some(PbsV2Data {
            niamonx_success: true,
            error: None,
            stats: Some(PbsV2Stats {
                found: 1,
                with_passwords: 0,
                unique_sources: 1,
            }),
            records: Some(vec![PbsV2Record {
                source: Some(PbsV2Source {
                    name: Some("LeakSite".to_string()),
                    breach_date: Some("2022-03-01".to_string()),
                    compilation: Some(0),
                }),
                // Same address, different case — restated by the other endpoint.
                email: Some("other@example.com".to_string()),
                username: None,
                phone: None,
                fields: None,
            }]),
        }),
    );
    let target = Target::new(TargetKind::Email, "victim@example.com");
    let mut entity = target.to_entity(confidence::HIGH_PLUSPLUS, "s");
    let mut result = ModuleResult::new();
    let mut seen = std::collections::HashSet::new();
    emit_pbs_v1(
        payload("pbs_v1", v1).expect("fixture is a real answer"), &mut entity, &mut result, "victim@example.com", "s", &mut seen);
    emit_pbs_v2(
        payload("pbs_v2", v2).expect("fixture is a real answer"), &mut entity, &mut result, "victim@example.com", "s", &mut seen);
    let email_count = result
        .entities
        .iter()
        .filter(|e| e.kind == EntityKind::Email)
        .count();
    assert_eq!(
        email_count, 1,
        "the same email restated by PBS v1 and PBS v2 must not double-emit: {:?}",
        result.entities
    );
}

#[test]
fn produces_includes_the_seed_kinds_for_every_accepted_target_kind() {
    // Regression: the enriched seed entity re-affirms the queried identity as
    // Domain/IpAddress too (accepts() admits both), not just Email/Username.
    let m = NiamonX;
    assert!(m.produces().contains(&EntityKind::Domain));
    assert!(m.produces().contains(&EntityKind::IpAddress));
}

// ── REQ-NIAMONX-001: a failed call is not an empty answer ───────────────────
//
// The over-correction controls for these are the miss tests ABOVE, and they
// need no new code: every fixture in this file now reaches its emitter through
// `payload(...).expect("fixture is a real answer")`, so if this change had
// turned a genuine no-results reply into an error,
// `pbs_v1_skips_not_found_status` (success:true + status "not_found"),
// `ulp_*` (stats.total == 0) and the `niamonx_success: false` v2 cases would
// panic on that `expect` instead of quietly passing. "Fail closed" is only a
// fix while an honest miss still succeeds.

/// LOCK. `success: false` is the provider saying the CALL failed. It must reach
/// the caller as an error so `process`'s existing machinery can see it — the
/// `hard_failure` path that `ModuleResult::or_hard_failure` reports, and the
/// key cascade that rotates a burned key when all three endpoints fail. Before
/// this, each emitter opened with `if !resp.success { return; }` and returned
/// `()`, so the failure could not be reported even in principle: the module
/// answered "no findings" for a call the provider had already said did not
/// work.
#[test]
fn a_success_false_body_is_an_error_not_an_empty_answer() {
    for endpoint in ["pbs_v1", "pbs_v2", "ulp_search"] {
        let err = payload(
            endpoint,
            Envelope::from_parts(false, Some(())),
        )
            .expect_err("success:false must not read as an answer");
        let msg = err.to_string();
        assert!(
            msg.contains(endpoint) && msg.contains("success:false"),
            "the error must name the endpoint and the flag so a wrong firing is \
             diagnosable from one log line: {msg}"
        );
    }
}

/// LOCK. `success: true` with no `data` object is malformed, not empty. It hit
/// the emitters' second silent return (`let Some(data) = resp.data else
/// { return }`) and produced the same "no findings" as a real miss.
#[test]
fn a_body_with_no_data_object_is_an_error_not_an_empty_answer() {
    let err = payload(
        "pbs_v1",
        Envelope::<()>::from_parts(true, None),
    )
        .expect_err("success:true with no data is malformed");
    assert!(
        err.to_string().contains("no `data` object"),
        "{}",
        err
    );
}

/// CONTROL for the two locks above, at the seam itself: a real answer passes
/// through untouched. Without this, `payload` could satisfy both locks by
/// erroring unconditionally.
#[test]
fn a_real_answer_passes_through_the_seam() {
    assert_eq!(
        payload(
            "pbs_v1",
            Envelope::from_parts(true, Some(42)),
        ).expect("a real answer is not an error"),
        42
    );
}
