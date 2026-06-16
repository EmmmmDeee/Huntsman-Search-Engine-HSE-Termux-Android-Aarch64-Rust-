use super::*;

#[test]
fn accepts_email_only() {
    let m = OsintCat;
    assert!(m.accepts(&Target::new(TargetKind::Email, "x@y.com")));
    assert!(!m.accepts(&Target::new(TargetKind::Domain, "y.com")));
}

#[test]
fn emit_breach_tags_entity() {
    let br = OcBreachResponse {
        results_count: 2,
        breach_data: vec![
            serde_json::json!({"source": "ExampleLeak", "breach_date": "2021-01-01"}),
        ],
    };
    let target = Target::new(TargetKind::Email, "x@y.com");
    let mut entity = target.to_entity(0.75, "s");
    emit_breach(&br, &mut entity);
    assert!(entity.has_tag("breach"));
    assert!(entity.has_tag("osintcat:breach:exampleleak"));
    assert!(!entity.evidence.is_empty());
}

#[test]
fn emit_breach_noop_on_zero() {
    let br = OcBreachResponse {
        results_count: 0,
        breach_data: vec![],
    };
    let target = Target::new(TargetKind::Email, "x@y.com");
    let mut entity = target.to_entity(0.75, "s");
    emit_breach(&br, &mut entity);
    assert!(!entity.has_tag("breach"));
    assert!(entity.evidence.is_empty());
}
