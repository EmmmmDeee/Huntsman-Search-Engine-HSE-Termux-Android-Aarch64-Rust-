use super::{BreachRecord, DomainBreachResp, SRC, XposedOrNotDomain, build_result, confidence_for};
use crate::core::{
    confidence,
    entity::EntityKind,
    module::Module,
    scan::{Target, TargetKind},
};

fn record(domain: &str, breach_id: &str, verified: bool, records: u64) -> BreachRecord {
    BreachRecord {
        breach_id: Some(breach_id.into()),
        breached_date: Some("2026-08-01T00:00:00+00:00".into()),
        domain: Some(domain.into()),
        industry: Some("Information Technology".into()),
        password_risk: Some("unknown".into()),
        verified: Some(verified),
        exposed_data: Some(vec!["Email addresses".into(), "Names".into()]),
        exposed_records: Some(records),
        exposure_description: Some("A description.".into()),
        reference_url: Some("https://example.com/ref".into()),
    }
}

#[test]
fn accepts_domain_only() {
    let m = XposedOrNotDomain;
    assert!(m.accepts(&Target::new(TargetKind::Domain, "adobe.com")));
    assert!(!m.accepts(&Target::new(TargetKind::Email, "x@adobe.com")));
    assert!(!m.accepts(&Target::new(TargetKind::Username, "bob")));
    assert!(!m.accepts(&Target::new(TargetKind::Organisation, "Adobe Inc")));
}

#[test]
fn module_name_is_stable() {
    assert_eq!(XposedOrNotDomain.name(), "xposed_or_not_domain");
    assert_eq!(XposedOrNotDomain.name(), SRC);
}

#[test]
fn clean_not_found_yields_no_entity() {
    let resp = DomainBreachResp {
        status: Some("Not Found".into()),
        exposed_breaches: None,
    };
    let target = Target::new(TargetKind::Domain, "never-breached-xyz123.com");
    let r = build_result(&resp, &target, "scan-1").expect("clean negative is Ok");
    assert_eq!(r.entities.len(), 0);
}

#[test]
fn empty_breaches_array_on_success_yields_no_entity() {
    let resp = DomainBreachResp {
        status: Some("success".into()),
        exposed_breaches: Some(vec![]),
    };
    let target = Target::new(TargetKind::Domain, "never-breached-xyz123.com");
    let r = build_result(&resp, &target, "s").expect("empty success is Ok");
    assert_eq!(r.entities.len(), 0);
}

#[test]
fn unexpected_status_propagates_not_collapsed() {
    // An unrecognised status text with no records is a genuine ambiguity —
    // it must surface, never read as a clean exoneration (fail-closed).
    let resp = DomainBreachResp {
        status: Some("Too Many Requests".into()),
        exposed_breaches: None,
    };
    let target = Target::new(TargetKind::Domain, "adobe.com");
    let err = build_result(&resp, &target, "s").expect_err("unexpected status must be an error");
    assert!(format!("{err}").contains("Too Many Requests"));
}

#[test]
fn empty_body_is_an_error_not_a_clean_negative() {
    // `{}` — both fields absent. Neither documented shape (`status:
    // "success"` + present `exposedBreaches`, or `status: "Not Found"` +
    // absent `exposedBreaches`) matches, so this must be a real error, not
    // a silently swallowed "clean" (a Copilot-review-caught regression:
    // `unwrap_or(&[])` previously treated this identically to a genuine
    // clean miss).
    let resp = DomainBreachResp {
        status: None,
        exposed_breaches: None,
    };
    let target = Target::new(TargetKind::Domain, "adobe.com");
    build_result(&resp, &target, "s").expect_err("an empty body must be an error");
}

#[test]
fn success_status_with_no_breaches_key_is_an_error() {
    // `{"status":"success"}` — success claimed, but the array the hit shape
    // requires is entirely absent (not even an empty array). This is not
    // the documented empty-array success shape, so it must error rather
    // than silently read as "searched, found nothing".
    let resp = DomainBreachResp {
        status: Some("success".into()),
        exposed_breaches: None,
    };
    let target = Target::new(TargetKind::Domain, "adobe.com");
    build_result(&resp, &target, "s").expect_err("success with no breaches key must be an error");
}

#[test]
fn non_success_status_with_records_never_mints_a_hit() {
    // A non-"success" status carrying records anyway (e.g. stale data
    // riding along with a throttle response) must not be read as a
    // trustworthy hit — the documented hit shape requires `status:
    // "success"`, and minting entities from records the provider itself
    // did not vouch for under that status would fabricate a finding.
    let resp = DomainBreachResp {
        status: Some("Too Many Requests".into()),
        exposed_breaches: Some(vec![record("adobe.com", "Adobe", true, 152_403_035)]),
    };
    let target = Target::new(TargetKind::Domain, "adobe.com");
    let err = build_result(&resp, &target, "s")
        .expect_err("records under a non-success status must error");
    assert!(format!("{err}").contains("Too Many Requests"));
}

#[test]
fn populated_response_yields_breach_tagged_domain() {
    let resp = DomainBreachResp {
        status: Some("success".into()),
        exposed_breaches: Some(vec![record("adobe.com", "Adobe", true, 152_403_035)]),
    };
    let target = Target::new(TargetKind::Domain, "adobe.com");
    let r = build_result(&resp, &target, "scan-1").expect("hit is Ok");

    assert_eq!(r.entities.len(), 1);
    let e = &r.entities[0];
    assert_eq!(e.kind, EntityKind::Domain);
    assert_eq!(e.value, "adobe.com");
    assert!(e.has_tag("breach"));
    assert!(e.has_tag(SRC));
    assert!(e.has_tag("breach:adobe"));
    assert!(e.has_tag("high-exposure"));

    assert_eq!(e.evidence.len(), 1);
    assert_eq!(e.evidence[0].source, SRC);
    assert_eq!(
        e.evidence[0].attributes.get("breach").map(String::as_str),
        Some("Adobe")
    );
    assert_eq!(
        e.evidence[0]
            .attributes
            .get("exposed_records")
            .map(String::as_str),
        Some("152403035")
    );
    assert_eq!(
        e.evidence[0].attributes.get("verified").map(String::as_str),
        Some("true")
    );
    let classes = e.evidence[0]
        .attributes
        .get("exposed_data_classes")
        .expect("exposed_data_classes present");
    assert!(classes.contains("Email addresses"));
}

#[test]
fn unrelated_catalogue_entries_are_filtered_out() {
    // Regression lock for the module doc comment's empty-`domain=` hazard:
    // even if the response somehow carried records for OTHER companies (the
    // shape the live endpoint returns for a missing/empty domain parameter),
    // only the record whose own `domain` matches the queried domain may ever
    // become an entity.
    let resp = DomainBreachResp {
        status: Some("success".into()),
        exposed_breaches: Some(vec![
            record("baxter.com", "BaxterInternational", true, 488_992),
            record(
                "magairports.com",
                "ManchesterAirportsGroup",
                true,
                8_379_476,
            ),
            record("adobe.com", "Adobe", true, 152_403_035),
        ]),
    };
    let target = Target::new(TargetKind::Domain, "adobe.com");
    let r = build_result(&resp, &target, "s").expect("hit is Ok");
    assert_eq!(r.entities.len(), 1);
    assert_eq!(r.entities[0].value, "adobe.com");
}

#[test]
fn subdomain_of_breached_apex_still_matches() {
    let resp = DomainBreachResp {
        status: Some("success".into()),
        exposed_breaches: Some(vec![record("adobe.com", "Adobe", true, 152_403_035)]),
    };
    let target = Target::new(TargetKind::Domain, "accounts.adobe.com");
    let r = build_result(&resp, &target, "s").expect("hit is Ok");
    assert_eq!(r.entities.len(), 1);
}

#[test]
fn unrelated_domain_target_matches_nothing() {
    let resp = DomainBreachResp {
        status: Some("success".into()),
        exposed_breaches: Some(vec![record("adobe.com", "Adobe", true, 152_403_035)]),
    };
    let target = Target::new(TargetKind::Domain, "example.com");
    let r = build_result(&resp, &target, "s").expect("no match is still Ok");
    assert_eq!(r.entities.len(), 0);
}

#[test]
fn low_record_count_is_not_high_exposure() {
    let resp = DomainBreachResp {
        status: Some("success".into()),
        exposed_breaches: Some(vec![record("smallco.com", "SmallCo", false, 500)]),
    };
    let target = Target::new(TargetKind::Domain, "smallco.com");
    let r = build_result(&resp, &target, "s").expect("hit is Ok");
    assert!(!r.entities[0].has_tag("high-exposure"));
}

#[test]
fn confidence_reflects_verified_flag() {
    assert!((confidence_for(true) - confidence::VERY_HIGH_PLUS).abs() < 1e-9);
    assert!((confidence_for(false) - confidence::HIGH_PLUSPLUS).abs() < 1e-9);
}
