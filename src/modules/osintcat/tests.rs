use crate::core::confidence;
use super::*;
use serde_json::json;

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
    let mut entity = target.to_entity(confidence::VERY_HIGH, "s");
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
    let mut entity = target.to_entity(confidence::VERY_HIGH, "s");
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
    let mut entity = target.to_entity(confidence::VERY_HIGH, "s");
    emit_breach(&br, &mut entity);
    assert!(entity.has_tag("breach"));
    assert!(entity.has_tag("osintcat:breach:leaka"));
    assert!(entity.has_tag("osintcat:breach:leakb"));
}

#[test]
fn emit_footprint_noop_on_zero_registrations() {
    let fp: OcFootprintResponse = serde_json::from_value(json!({
        "stats": {"total_checked": 50, "registered_count": 0},
        "results": []
    }))
    .expect("should succeed");
    let target = Target::new(TargetKind::Email, "x@y.com");
    let mut entity = target.to_entity(confidence::VERY_HIGH, "s");
    let mut result = ModuleResult::new();
    emit_footprint(&fp, &mut entity, &mut result);
    assert!(entity.evidence.is_empty(), "zero registrations → no evidence");
    assert!(result.is_empty());
}

#[test]
fn emit_footprint_tags_taken_platform() {
    let fp: OcFootprintResponse = serde_json::from_value(json!({
        "stats": {"total_checked": 50, "registered_count": 1},
        "results": [
            {"domain": "github.com", "taken": true},
            {"domain": "twitter.com", "taken": false}
        ]
    }))
    .expect("should succeed");
    let target = Target::new(TargetKind::Email, "x@y.com");
    let mut entity = target.to_entity(confidence::VERY_HIGH, "s");
    let mut result = ModuleResult::new();
    emit_footprint(&fp, &mut entity, &mut result);
    assert!(!entity.evidence.is_empty(), "registrations → evidence");
    assert!(entity.has_tag("osintcat:registered:github-com"));
    assert!(!entity.has_tag("osintcat:registered:twitter-com"), "not taken");
}

#[test]
fn emit_email_osint_skips_nulls_and_adds_non_null_fields() {
    let raw = json!({"score": 42, "null_field": null, "label": "risky"});
    let target = Target::new(TargetKind::Email, "x@y.com");
    let mut entity = target.to_entity(0.5, "s");
    emit_email_osint(&raw, &mut entity);
    assert_eq!(entity.evidence.len(), 1);
    let ev = &entity.evidence[0];
    assert!(ev.attributes.contains_key("score"));
    assert!(ev.attributes.contains_key("label"));
    assert!(!ev.attributes.contains_key("null_field"), "null fields skipped");
}
