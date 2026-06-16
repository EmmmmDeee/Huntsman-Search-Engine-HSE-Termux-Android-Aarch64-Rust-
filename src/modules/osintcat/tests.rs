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

#[test]
fn module_metadata() {
    let m = OsintCat;
    assert_eq!(m.name(), "osintcat");
    assert_eq!(m.cost(), crate::core::module::ModuleCost::KeyGated);
    assert!(!m.description().is_empty());
    assert!(!m.attack_techniques().is_empty());
}

#[test]
fn emit_breach_tags_multiple_sources() {
    // Two distinct breach sources → two separate per-source tags.
    let br = OcBreachResponse {
        results_count: 3,
        breach_data: vec![
            serde_json::json!({"source": "LeakA", "breach_date": "2020-01-01"}),
            serde_json::json!({"source": "LeakB", "breach_date": "2021-06-15"}),
        ],
    };
    let target = Target::new(TargetKind::Email, "x@y.com");
    let mut entity = target.to_entity(0.75, "s");
    emit_breach(&br, &mut entity);
    assert!(entity.has_tag("breach"));
    assert!(entity.has_tag("osintcat:breach:leaka"));
    assert!(entity.has_tag("osintcat:breach:leakb"));
}
