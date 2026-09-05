use super::{LeakCheckPublic, PublicResp, SRC, Source, build_result, confidence_for_sources};
use crate::core::{
    confidence,
    entity::EntityKind,
    module::Module,
    scan::{Target, TargetKind},
};

fn src(name: &str, date: &str) -> Source {
    Source {
        name: Some(name.into()),
        date: (!date.is_empty()).then(|| date.into()),
    }
}

#[test]
fn accepts_email_only() {
    let m = LeakCheckPublic;
    assert!(m.accepts(&Target::new(TargetKind::Email, "x@y.com")));
    assert!(!m.accepts(&Target::new(TargetKind::Domain, "y.com")));
    assert!(!m.accepts(&Target::new(TargetKind::Username, "bob")));
}

#[test]
fn module_name_is_stable() {
    assert_eq!(LeakCheckPublic.name(), "leakcheck_public");
    assert_eq!(LeakCheckPublic.name(), SRC);
}

#[test]
fn clean_not_found_yields_no_entity() {
    let resp = PublicResp {
        success: false,
        found: None,
        fields: None,
        sources: None,
        error: Some("Not found".into()),
    };
    let target = Target::new(TargetKind::Email, "clean@example.com");
    let r = build_result(&resp, &target, "scan-1").expect("clean negative is Ok");
    assert_eq!(r.entities.len(), 0);
}

#[test]
fn empty_sources_on_success_yields_no_entity() {
    let resp = PublicResp {
        success: true,
        found: Some(0),
        fields: None,
        sources: Some(vec![]),
        error: None,
    };
    let target = Target::new(TargetKind::Email, "clean@example.com");
    let r = build_result(&resp, &target, "s").expect("empty success is Ok");
    assert_eq!(r.entities.len(), 0);
}

#[test]
fn throttle_error_propagates_not_collapsed() {
    // A non-"Not found" error is a real failure — it must surface, never read
    // as a clean exoneration (fail-closed).
    let resp = PublicResp {
        success: false,
        found: None,
        fields: None,
        sources: None,
        error: Some("Too many requests, please wait".into()),
    };
    let target = Target::new(TargetKind::Email, "x@y.com");
    let err = build_result(&resp, &target, "s").expect_err("throttle must be an error");
    assert!(format!("{err}").contains("Too many requests"));
}

#[test]
fn populated_response_yields_breach_tagged_email() {
    let resp = PublicResp {
        success: true,
        found: Some(1366),
        fields: Some(vec!["password".into(), "username".into(), "ip".into()]),
        sources: Some(vec![
            src("Collection 1", "2019-01"),
            src("Hautelook.com", "2018-08"),
            src("Stealer Logs", ""),
        ]),
        error: None,
    };
    let target = Target::new(TargetKind::Email, "pwned@example.com");
    let r = build_result(&resp, &target, "scan-1").expect("hit is Ok");

    assert_eq!(r.entities.len(), 1);
    let e = &r.entities[0];
    assert_eq!(e.kind, EntityKind::Email);
    assert_eq!(e.value, "pwned@example.com");
    assert!(e.has_tag("breach"));
    assert!(e.has_tag(SRC));
    assert!(e.has_tag("breach:collection 1"));
    assert!(e.has_tag("breach:hautelook.com"));

    assert_eq!(e.evidence.len(), 1);
    assert_eq!(e.evidence[0].source, SRC);
    assert_eq!(
        e.evidence[0]
            .attributes
            .get("sources_count")
            .map(String::as_str),
        Some("3")
    );
    assert_eq!(
        e.evidence[0].attributes.get("records").map(String::as_str),
        Some("1366")
    );
    // The exposed data-classes are the field TYPE names, never a value.
    let classes = e.evidence[0]
        .attributes
        .get("exposed_data_classes")
        .expect("exposed_data_classes present");
    assert!(classes.contains("password"));
    assert!(classes.contains("username"));
    // Earliest full YYYY-MM date wins; the undated "Stealer Logs" is ignored.
    assert_eq!(
        e.evidence[0]
            .attributes
            .get("earliest_breach_date")
            .map(String::as_str),
        Some("2018-08")
    );
}

#[test]
fn high_exposure_tagged_at_five_sources() {
    let sources: Vec<Source> = (0..6).map(|i| src(&format!("breach_{i}"), "")).collect();
    let resp = PublicResp {
        success: true,
        found: Some(6),
        fields: None,
        sources: Some(sources),
        error: None,
    };
    let target = Target::new(TargetKind::Email, "many@example.com");
    let r = build_result(&resp, &target, "s").expect("hit is Ok");
    assert!(r.entities[0].has_tag("high-exposure"));
}

#[test]
fn confidence_scales_with_source_count() {
    assert!((confidence_for_sources(1) - confidence::HIGH_PLUSPLUS).abs() < 1e-9);
    assert!((confidence_for_sources(3) - confidence::HIGH_PLUSPLUS_PLUS).abs() < 1e-9);
    assert!((confidence_for_sources(7) - confidence::VERY_HIGH_PLUS).abs() < 1e-9);
    assert!((confidence_for_sources(20) - confidence::VERY_HIGH_PLUSPLUS).abs() < 1e-9);
}

#[test]
fn clean_no_results_found_yields_no_entity() {
    // Pin the SECOND clean-negative signal: `success:false` with a
    // case-insensitive "No results found" is an ordinary clean miss, never a
    // ModuleError. Untested before; deleting that clause would flip a legitimate
    // live clean response to a spurious failure.
    for err in ["No results found", "NO RESULTS FOUND"] {
        let resp = PublicResp {
            success: false,
            found: None,
            fields: None,
            sources: None,
            error: Some(err.into()),
        };
        let target = Target::new(TargetKind::Email, "clean@example.com");
        let r = build_result(&resp, &target, "s").expect("no-results-found is a clean Ok");
        assert_eq!(r.entities.len(), 0);
    }
}

#[test]
fn malformed_source_date_is_filtered_from_earliest() {
    // Pin the `len==7 && byte[4]=='-'` date filter. The malformed "2010/01" is
    // 7 chars but byte[4] is '/', and is lexically SMALLER than the valid
    // "2018-08" ("2010" < "2018"), so if the byte-4 guard were dropped it would
    // wrongly win `.min()` — this falsifies that regression.
    let resp = PublicResp {
        success: true,
        found: Some(2),
        fields: None,
        sources: Some(vec![
            src("Good Corp", "2018-08"),
            src("Bad Corp", "2010/01"),
        ]),
        error: None,
    };
    let target = Target::new(TargetKind::Email, "pwned@example.com");
    let r = build_result(&resp, &target, "s").expect("hit is Ok");
    assert_eq!(
        r.entities[0].evidence[0]
            .attributes
            .get("earliest_breach_date")
            .map(String::as_str),
        Some("2018-08")
    );
}
