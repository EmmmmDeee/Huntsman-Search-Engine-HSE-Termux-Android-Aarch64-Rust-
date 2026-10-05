use crate::core::scan::{Target, TargetKind};

use super::*;

fn sample() -> BwResp {
    BwResp {
        results: vec![BwResult {
            lookup: Some("acme.com".to_string()),
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
            lookup: Some("x.com".to_string()),
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
            lookup: Some("x.com".to_string()),
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
fn build_entities_rejects_a_result_whose_lookup_names_a_different_domain() {
    // Regression: `Results[]` entries never had their own `Lookup` field
    // checked against the queried domain, so a mismatched entry (a
    // redirect/canonicalization/API anomaly) would silently attach its
    // Organisation/tech-profile data to the queried domain's entity graph.
    let resp = BwResp {
        results: vec![BwResult {
            lookup: Some("evil.example".to_string()),
            result: Some(BwResultInner {
                paths: vec![BwPath {
                    technologies: vec![BwTech {
                        name: Some("nginx".to_string()),
                    }],
                }],
            }),
            meta: Some(BwMeta {
                company_name: Some("Unrelated Org".to_string()),
                emails: None,
                telephones: None,
                names: None,
            }),
        }],
        errors: None,
    };
    let result = build_entities(&resp, "acme.com", "test-scan");
    assert!(
        result.entities.is_empty(),
        "a Lookup mismatch must yield nothing: {:?}",
        result.entities
    );
}

#[test]
fn build_entities_trusts_a_result_with_no_lookup_field_at_all() {
    // `Lookup` is optional in our model — its absence must not itself
    // reject an otherwise-valid entry (only a present, mismatched one does).
    let resp = BwResp {
        results: vec![BwResult {
            lookup: None,
            result: None,
            meta: Some(BwMeta {
                company_name: Some("Acme Pty Ltd".to_string()),
                emails: None,
                telephones: None,
                names: None,
            }),
        }],
        errors: None,
    };
    let result = build_entities(&resp, "acme.com", "test-scan");
    assert!(
        result
            .entities
            .iter()
            .any(|e| e.kind == EntityKind::Organisation && e.value == "Acme Pty Ltd"),
        "a result with no Lookup field must still be trusted: {:?}",
        result.entities
    );
}

#[test]
fn build_entities_empty_response_is_empty() {
    let resp = BwResp::default();
    let result = build_entities(&resp, "x.com", "test-scan");
    assert!(result.entities.is_empty());
}

#[test]
fn a_wrong_key_or_exhausted_credits_error_is_a_key_error_not_a_clean_miss() {
    // BuiltWith's documented (api.builtwith.com/errorCodes) key-class errors
    // arrive on HTTP 200 in `Errors[]`; before this fix they were logged and
    // folded into Ok(empty), so a dead or credit-less key read as "no tech
    // profile" on every scan and the pool was never told.
    let body = |json: &str| serde_json::from_str::<BwResp>(json).expect("fixture");
    for raw in [
        r#"{"Errors":[{"Message":"API Key is wrong - it needs to be a Guid.","Code":-2}]}"#,
        r#"{"Errors":[{"Message":"You've run out of API Credits.","Code":-3}]}"#,
        r#"{"Errors":[{"Message":"Plan upgrade needed as maximum technologies reached.","Code":-5}]}"#,
        // Message text alone (the provider says the text cannot be guaranteed;
        // the code may be absent in an older/edge response).
        r#"{"Errors":[{"Message":"You've run out of API Credits."}]}"#,
        // Code alone.
        r#"{"Errors":[{"Code":-2}]}"#,
    ] {
        let b = body(raw);
        let errors = b.errors.as_deref().expect("Errors present");
        assert!(
            builtwith_key_error(errors).is_some(),
            "{raw} must classify as a key/credit/plan failure"
        );
    }
    // A per-lookup error is a clean miss for this target, not a key problem.
    let b =
        body(r#"{"Errors":[{"Message":"Invalid root domain name or unsupported.","Code":-8}]}"#);
    assert!(builtwith_key_error(b.errors.as_deref().unwrap()).is_none());
    assert!(builtwith_key_error(&[]).is_none());
}

/// Build a Meta-only response with the given registrant fields, so the
/// privacy-proxy gate is exercised without the tech-profile noise.
fn meta_only(
    company_name: Option<&str>,
    names: Option<Vec<&str>>,
    emails: Option<Vec<&str>>,
) -> BwResp {
    BwResp {
        results: vec![BwResult {
            lookup: Some("acme.com".to_string()),
            result: None,
            meta: Some(BwMeta {
                company_name: company_name.map(str::to_string),
                emails: emails.map(|v| v.into_iter().map(str::to_string).collect()),
                telephones: None,
                names: names.map(|v| {
                    v.into_iter()
                        .map(|n| BwName {
                            name: Some(n.to_string()),
                        })
                        .collect()
                }),
            }),
        }],
        errors: None,
    }
}

fn orgs(r: &crate::core::module::ModuleResult) -> Vec<&str> {
    r.entities
        .iter()
        .filter(|e| e.kind == EntityKind::Organisation)
        .map(|e| e.value.as_str())
        .collect()
}

/// REQ-BUILTWITH-001. A WHOIS privacy proxy is registrar boilerplate, never
/// the domain owner — but BuiltWith's `CompanyName` is a registrant field, so
/// it is exactly where those brands land. They were minted as
/// `confidence::HIGH` Organisation entities: an attribution of the proxy
/// service's corporate identity to the subject under investigation.
///
/// Every brand is checked and survivors are collected, so a partial gate (one
/// marker wired, the rest missed) is named rather than masked by the first
/// failure.
#[test]
fn a_privacy_proxy_is_never_the_registrant_organisation() {
    let mut minted: Vec<(&str, Vec<String>)> = Vec::new();
    for brand in [
        "Domains By Proxy, LLC",
        "DomainsByProxy.com",
        "REDACTED FOR PRIVACY",
        "Whoisguard, Inc.",
        "Contact Privacy Inc. Customer 0123456789",
        "Withheld for Privacy ehf",
        "Identity Protection Service",
        "Private Registration",
        "Statutory Masking Enabled",
        "GDPR Masked",
        "Data Protected",
        "Domain Protection Services, Inc.",
    ] {
        let r = build_entities(&meta_only(Some(brand), None, None), "acme.com", "t");
        let got = orgs(&r);
        if !got.is_empty() {
            minted.push((brand, got.iter().map(|s| (*s).to_string()).collect()));
        }
    }
    assert!(
        minted.is_empty(),
        "privacy-proxy brands minted as the registrant Organisation: {minted:?}"
    );
}

/// The gate lives inside the selection, not after it. WHOIS routinely carries
/// the proxy as `CompanyName` while the genuine party survives as a `Name`
/// entry; a post-filter would have thrown both away and reported no registrant
/// at all, trading one wrong answer for no answer.
#[test]
fn a_proxy_company_name_does_not_shadow_a_real_registrant_name() {
    let r = build_entities(
        &meta_only(
            Some("Domains By Proxy, LLC"),
            Some(vec!["Domains By Proxy, LLC", "Acme Pty Ltd"]),
            None,
        ),
        "acme.com",
        "t",
    );
    assert_eq!(
        orgs(&r),
        vec!["Acme Pty Ltd"],
        "the real registrant behind the proxy must still surface"
    );
}

/// REQ-BUILTWITH-001, the email half. The proxy brands are deliberately NOT in
/// `INFRA_PROVIDER_ROOTS` / `INFRA_MAIL_ONLY` — those hold CDN, cloud and
/// registrar control-plane roots — so a proxy mailbox whose local part is not a
/// role desk cleared `is_infrastructure_email` on its own and was emitted as
/// the subject's own mail at `MEDIUM_PLUS`.
#[test]
fn a_proxy_registrant_mailbox_is_not_the_subjects_email() {
    let personal_looking = [
        "jane.doe@domainsbyproxy.com",
        "k.nguyen@whoisguard.com",
        "customer0123456789@contactprivacy.com",
    ];
    // Vacuity guard: these must NOT already be caught by the pre-existing
    // infrastructure-email check, or this test would pass on the baseline and
    // prove nothing about the placeholder half of the gate.
    for e in personal_looking {
        assert!(
            !crate::util::domains::is_infrastructure_email(e),
            "{e} is already infra-mail; pick a case that isolates the placeholder check"
        );
    }
    let r = build_entities(
        &meta_only(None, None, Some(personal_looking.to_vec())),
        "acme.com",
        "t",
    );
    let emails: Vec<&str> = r
        .entities
        .iter()
        .filter(|e| e.kind == EntityKind::Email)
        .map(|e| e.value.as_str())
        .collect();
    assert!(
        emails.is_empty(),
        "privacy-proxy mailboxes attributed to the subject: {emails:?}"
    );
}

/// The control, and the reason the gate is safe to assert: a genuine registrant
/// company, a genuine registrant name and a genuine individual mailbox all
/// still come through. This passes on the baseline and on the fix.
#[test]
fn genuine_registrant_details_still_survive_the_proxy_gate() {
    let r = build_entities(
        &meta_only(
            Some("Acme Pty Ltd"),
            None,
            Some(vec!["j.smith@acme.com", "info@acme.com"]),
        ),
        "acme.com",
        "t",
    );
    assert_eq!(orgs(&r), vec!["Acme Pty Ltd"]);
    let emails: Vec<&str> = r
        .entities
        .iter()
        .filter(|e| e.kind == EntityKind::Email)
        .map(|e| e.value.as_str())
        .collect();
    assert_eq!(
        emails,
        vec!["j.smith@acme.com"],
        "the individual mailbox stays; only the role desk is gated"
    );
    // And the Names[] fallback still works when there is no company name.
    let r2 = build_entities(
        &meta_only(None, Some(vec!["Jane Roe Holdings"]), None),
        "acme.com",
        "t",
    );
    assert_eq!(orgs(&r2), vec!["Jane Roe Holdings"]);
}
