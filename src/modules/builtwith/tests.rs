use crate::core::scan::{Target, TargetKind};

use super::*;

fn sample() -> BwResp {
    BwResp {
        results: vec![BwResult {
            result: Some(BwResultInner {
                paths: vec![BwPath {
                    technologies: vec![
                        BwTech {
                            name: Some("nginx".to_string()),
                        },
                        BwTech {
                            name: Some("Google Analytics".to_string()),
                        },
                        // Duplicate + empty — must be deduplicated / skipped.
                        BwTech {
                            name: Some("nginx".to_string()),
                        },
                        BwTech {
                            name: Some("  ".to_string()),
                        },
                    ],
                }],
            }),
            meta: Some(BwMeta {
                company_name: Some("Acme Pty Ltd".to_string()),
                emails: Some(vec![
                    // Role desk — the registrant contact block is full of these,
                    // and they are the registrar/provider's automation, not the
                    // subject. Must be gated out (see the module's filter).
                    "info@acme.com".to_string(),
                    "INFO@acme.com".to_string(), // case-dup of the role desk
                    // A real, individual mailbox on the same domain: the gate
                    // must NOT be so broad that it takes this with it.
                    "j.smith@acme.com".to_string(),
                    "J.Smith@acme.com".to_string(), // case-dup
                    "x".to_string(),                // too short / no @
                ]),
                telephones: Some(vec![
                    "+61 2 9000 0000".to_string(),
                    "123".to_string(), // too few digits
                ]),
                names: None,
            }),
        }],
        errors: None,
    }
}

#[test]
fn accepts_only_domain_targets() {
    let m = BuiltWith;
    assert!(m.accepts(&Target::new(TargetKind::Domain, "acme.com")));
    assert!(!m.accepts(&Target::new(TargetKind::IpAddress, "1.2.3.4")));
    assert!(!m.accepts(&Target::new(TargetKind::Email, "a@b.com")));
}

#[test]
fn build_entities_emits_tech_domain_and_contacts() {
    let resp = sample();
    let result = build_entities(&resp, "acme.com", "test-scan");

    let dom = result
        .entities
        .iter()
        .find(|e| e.kind == EntityKind::Domain)
        .expect("domain entity");
    // Evidence carries the deduplicated technology list.
    let ev = dom.evidence.first().expect("domain evidence");
    let techs = ev
        .attributes
        .get("technologies")
        .expect("technologies attr");
    assert!(techs.contains("nginx"));
    assert!(techs.contains("Google Analytics"));
    // Deduplicated: "nginx" appears once, blank dropped → count == 2.
    assert_eq!(
        ev.attributes.get("technology_count").map(String::as_str),
        Some("2")
    );

    assert!(
        result
            .entities
            .iter()
            .any(|e| e.kind == EntityKind::Organisation && e.value == "Acme Pty Ltd")
    );
    // A registrant contact block is dominated by role/automation desks. Emitting
    // those as Email attributes the registrar's helpdesk to the person under
    // investigation — the leakage #351 removed from cert_intel, crtsh,
    // ip_registry and doh_resolver. This module reads the same class of data
    // from a different provider, so it takes the same gate.
    assert!(
        !result
            .entities
            .iter()
            .any(|e| e.kind == EntityKind::Email && e.value == "info@acme.com"),
        "a role desk must not be emitted as the subject's email"
    );
    // ...and the gate must not be so broad it swallows a real individual mailbox
    // on the very same domain, which would trade a leak for silent data loss.
    assert!(
        result
            .entities
            .iter()
            .any(|e| e.kind == EntityKind::Email && e.value == "j.smith@acme.com"),
        "a personal mailbox must survive the role/infra gate"
    );
    // One email survives, case-duplicate collapsed.
    assert_eq!(
        result
            .entities
            .iter()
            .filter(|e| e.kind == EntityKind::Email)
            .count(),
        1
    );
    assert!(result.entities.iter().any(|e| e.kind == EntityKind::Phone));
}

#[test]
fn build_entities_skips_short_org_and_bad_contacts() {
    let resp = BwResp {
        results: vec![BwResult {
            result: None,
            meta: Some(BwMeta {
                company_name: Some("AB".to_string()), // < 3 chars → skipped
                emails: Some(vec!["notanemail".to_string()]),
                telephones: Some(vec!["12".to_string()]),
                names: None,
            }),
        }],
        errors: None,
    };
    let result = build_entities(&resp, "x.com", "test-scan");
    assert!(result.entities.is_empty());
}

#[test]
fn build_entities_falls_back_to_first_name_for_org() {
    let resp = BwResp {
        results: vec![BwResult {
            result: None,
            meta: Some(BwMeta {
                company_name: None,
                emails: None,
                telephones: None,
                names: Some(vec![BwName {
                    name: Some("Jane Roe Holdings".to_string()),
                }]),
            }),
        }],
        errors: None,
    };
    let result = build_entities(&resp, "x.com", "test-scan");
    assert!(
        result
            .entities
            .iter()
            .any(|e| e.kind == EntityKind::Organisation && e.value == "Jane Roe Holdings")
    );
}

#[test]
fn build_entities_empty_response_is_empty() {
    let resp = BwResp::default();
    let result = build_entities(&resp, "x.com", "test-scan");
    assert!(result.entities.is_empty());
}
