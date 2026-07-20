use super::XposedOrNot;
use super::build::{NOTABLE_BREACHES, build_result, confidence_for_count};
use super::types::{AnalyticsBreaches, AnalyticsResp, BreachDetail};
use crate::core::{
    confidence,
    entity::EntityKind,
    module::Module,
    scan::{Target, TargetKind},
};

#[test]
fn accepts_email_only() {
    let m = XposedOrNot;
    assert!(m.accepts(&Target::new(TargetKind::Email, "x@y.com")));
    assert!(!m.accepts(&Target::new(TargetKind::Domain, "y.com")));
    assert!(!m.accepts(&Target::new(TargetKind::IpAddress, "1.1.1.1")));
}

#[test]
fn module_name_matches_correlator_breach_list() {
    assert_eq!(XposedOrNot.name(), "xposed_or_not");
}

#[test]
fn empty_breaches_yields_no_entity() {
    let target = Target::new(TargetKind::Email, "clean@example.com");
    let r = build_result(&[], None, &target, "scan-1");
    assert_eq!(r.entities.len(), 0);
}

#[test]
fn populated_response_yields_breach_tagged_email() {
    let breaches = vec!["MyFitnessPal".into(), "Quizlet".into(), "LinkedIn".into()];
    let target = Target::new(TargetKind::Email, "pwned@example.com");
    let r = build_result(&breaches, None, &target, "scan-1");

    assert_eq!(r.entities.len(), 1);
    let e = &r.entities[0];
    assert_eq!(e.kind, EntityKind::Email);
    assert_eq!(e.value, "pwned@example.com");
    assert!(e.has_tag("breach"));
    assert!(e.has_tag("breach:linkedin"));
    assert!(e.has_tag("breach:myfitnesspal"));

    assert_eq!(e.evidence.len(), 1);
    assert_eq!(e.evidence[0].source, "xposed_or_not");
    assert_eq!(e.evidence[0].attributes.get("count").unwrap(), "3");
}

#[test]
fn confidence_scales_with_breach_count() {
    assert!((confidence_for_count(1) - confidence::HIGH_PLUSPLUS).abs() < 1e-9);
    assert!((confidence_for_count(4) - confidence::HIGH_PLUSPLUS_PLUS).abs() < 1e-9);
    assert!((confidence_for_count(8) - 0.92).abs() < 1e-9);
    assert!((confidence_for_count(10) - confidence::VERY_HIGH_PLUSPLUS).abs() < 1e-9);
}

#[test]
fn high_exposure_tagged_at_five_breaches() {
    let breaches: Vec<String> = (0..6).map(|i| format!("breach_{i}")).collect();
    let target = Target::new(TargetKind::Email, "many@example.com");
    let r = build_result(&breaches, None, &target, "s");
    assert!(r.entities[0].has_tag("high-exposure"));
}

#[test]
fn analytics_surfaces_breach_summaries_and_descriptions() {
    let breaches = vec!["LinkedIn".into()];
    let analytics = AnalyticsResp {
        exposed_breaches: Some(AnalyticsBreaches {
            breaches_details: Some(vec![BreachDetail {
                breach: Some("LinkedIn".into()),
                xposed_data: Some("Emails;Passwords".into()),
                xposed_records: Some(117_000_000),
                xposure_desc: Some("LinkedIn suffered a data breach in 2012".into()),
                xposed_date: Some("2012-06-05".into()),
                password_risk: Some("none".into()),
            }]),
        }),
        pastes_summary: None,
    };
    let target = Target::new(TargetKind::Email, "a@b.com");
    let r = build_result(&breaches, Some(&analytics), &target, "s");

    let ev = &r.entities[0].evidence[0];
    let summaries = ev.attributes.get("breach_summaries").unwrap();
    assert!(summaries.contains("LinkedIn"));
    assert!(summaries.contains("2012"));
    assert!(summaries.contains("117M records"));
    assert!(summaries.contains("Emails;Passwords"));

    let descs = ev.attributes.get("breach_descriptions").unwrap();
    assert!(descs.contains("LinkedIn: LinkedIn suffered a data breach in 2012"));
}

#[test]
fn analytics_without_desc_omits_descriptions_attr() {
    let breaches = vec!["SomeService".into()];
    let analytics = AnalyticsResp {
        exposed_breaches: Some(AnalyticsBreaches {
            breaches_details: Some(vec![BreachDetail {
                breach: Some("SomeService".into()),
                xposed_data: Some("Emails".into()),
                xposed_records: Some(500),
                xposure_desc: None,
                xposed_date: None,
                password_risk: None,
            }]),
        }),
        pastes_summary: None,
    };
    let target = Target::new(TargetKind::Email, "a@b.com");
    let r = build_result(&breaches, Some(&analytics), &target, "s");

    let ev = &r.entities[0].evidence[0];
    let summaries = ev.attributes.get("breach_summaries").unwrap();
    assert!(summaries.contains("SomeService"));
    assert!(summaries.contains("500 records"));
    assert!(!ev.attributes.contains_key("breach_descriptions"));
}

#[test]
fn analytics_surfaces_the_earliest_full_iso_breach_date() {
    // Across three breaches the earliest full YYYY-MM-DD date is the subject's
    // first-known compromise; a bare-year value must not win (it is not a full
    // date and would sort before any real date).
    let breaches = vec!["A".into(), "B".into(), "C".into()];
    let detail = |name: &str, date: Option<&str>| BreachDetail {
        breach: Some(name.into()),
        xposed_data: Some("Emails".into()),
        xposed_records: Some(1000),
        xposure_desc: None,
        xposed_date: date.map(String::from),
        password_risk: None,
    };
    let analytics = AnalyticsResp {
        exposed_breaches: Some(AnalyticsBreaches {
            breaches_details: Some(vec![
                detail("A", Some("2015-03-10")),
                detail("B", Some("2012-06-05")),
                detail("C", Some("2019")), // bare year — not a full date, ignored
            ]),
        }),
        pastes_summary: None,
    };
    let target = Target::new(TargetKind::Email, "a@b.com");
    let r = build_result(&breaches, Some(&analytics), &target, "s");
    let ev = &r.entities[0].evidence[0];
    assert_eq!(
        ev.attributes
            .get("earliest_breach_date")
            .map(String::as_str),
        Some("2012-06-05"),
        "the earliest full ISO date wins; a bare year is ignored"
    );
}

// Keep NOTABLE_BREACHES referenced so the import is used
#[test]
fn notable_breaches_non_empty() {
    assert!(!NOTABLE_BREACHES.is_empty());
}
