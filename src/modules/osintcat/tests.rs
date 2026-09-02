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
fn emit_breach_count_reflects_the_array_actually_iterated_not_the_self_reported_total() {
    // Regression: `results_count` is the API's self-reported total, but the
    // per-source tags/evidence are only generated for entries actually
    // present in `breach_data`. If the two diverge, the evidence must not
    // overstate how many records are backing those per-source tags.
    let br = OcBreachResponse {
        results_count: 2,
        breach_data: vec![serde_json::json!({"source": "ExampleLeak", "breach_date": "2021-01-01"})],
    };
    let target = Target::new(TargetKind::Email, "x@y.com");
    let mut entity = target.to_entity(confidence::VERY_HIGH, "s");
    emit_breach(&br, &mut entity);
    let ev = &entity.evidence[0];
    assert_eq!(
        ev.attributes.get("breach_count").map(String::as_str),
        Some("1"),
        "breach_count must reflect the one record actually iterated, not the self-reported 2"
    );
    assert!(ev.summary.contains("1 breach record(s)"));
    // The divergence itself is surfaced as supplementary evidence (not
    // trusted for logic) so an operator can notice a provider under/over-
    // reporting, rather than the discrepancy being silently discarded.
    assert_eq!(
        ev.attributes.get("reported_results_count").map(String::as_str),
        Some("2")
    );
}

#[test]
fn emit_breach_omits_reported_results_count_when_it_matches() {
    // No divergence → no noise: the supplementary attribute only appears
    // when the self-reported total actually disagrees with the ground truth.
    let br = OcBreachResponse {
        results_count: 1,
        breach_data: vec![serde_json::json!({"source": "ExampleLeak", "breach_date": "2021-01-01"})],
    };
    let target = Target::new(TargetKind::Email, "x@y.com");
    let mut entity = target.to_entity(confidence::VERY_HIGH, "s");
    emit_breach(&br, &mut entity);
    let ev = &entity.evidence[0];
    assert!(!ev.attributes.contains_key("reported_results_count"));
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
fn emit_breach_noop_when_results_count_is_nonzero_but_breach_data_is_empty() {
    // Regression: `breach_data` is the sole source of truth (the per-source
    // tags/evidence are built from it, not `results_count`), so the
    // early-return guard must match — a `results_count > 0` with an empty
    // `breach_data` array must stay a clean no-op, not tag the entity
    // `breach` with evidence claiming "0 breach record(s)".
    let br = OcBreachResponse {
        results_count: 5,
        breach_data: vec![],
    };
    let target = Target::new(TargetKind::Email, "x@y.com");
    let mut entity = target.to_entity(confidence::VERY_HIGH, "s");
    emit_breach(&br, &mut entity);
    assert!(
        !entity.has_tag("breach"),
        "a nonzero results_count with no actual records must not tag breach"
    );
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
fn emit_footprint_extra_data_scalar_becomes_evidence_without_raw_json_quoting() {
    // Regression: `Value`'s `Display` impl renders a JSON string WITH its
    // surrounding quotes (`serde_json::to_string`), so naively interpolating
    // `v` (rather than the underlying Rust string) into Evidence text used to
    // leave literal `"..."` quoting baked into `Evidence.summary` and the
    // `value` attribute — raw JSON syntax leaking into what is supposed to be
    // normalized evidence text.
    let fp: OcFootprintResponse = serde_json::from_value(json!({
        "stats": {"total_checked": 50, "registered_count": 1},
        "results": [
            {"domain": "github.com", "taken": true, "ExtraData": {"location": "New York"}}
        ]
    }))
    .expect("should succeed");
    let target = Target::new(TargetKind::Email, "x@y.com");
    let mut entity = target.to_entity(confidence::VERY_HIGH, "s");
    let mut result = ModuleResult::new();
    emit_footprint(&fp, &mut entity, &mut result);
    let ev = entity
        .evidence
        .iter()
        .find(|e| e.attributes.get("key").map(String::as_str) == Some("location"))
        .expect("location ExtraData should become evidence");
    assert_eq!(ev.attributes.get("value").map(String::as_str), Some("New York"));
    // Assert the exact summary text rather than a bare "no quotes anywhere"
    // check — a legitimate value could itself contain a double quote (e.g. a
    // `5'11" tall` bio field), so the precise regression signal is that THIS
    // key/value pair renders without the JSON-string quoting `Value`'s
    // `Display` impl would have added, not an absence of `"` in general.
    assert_eq!(ev.summary, "[github.com] location: New York");
}

#[test]
fn emit_footprint_skips_nested_object_and_array_extra_data_values() {
    // A nested structure is not a scalar attribute value — stringifying it
    // (e.g. via `Display`) would dump raw JSON into Evidence text rather than
    // a normalized fact, so it must be skipped entirely, not stringified.
    let fp: OcFootprintResponse = serde_json::from_value(json!({
        "stats": {"total_checked": 50, "registered_count": 1},
        "results": [
            {
                "domain": "github.com",
                "taken": true,
                "ExtraData": {
                    "nested_obj": {"a": 1},
                    "nested_arr": [1, 2, 3]
                }
            }
        ]
    }))
    .expect("should succeed");
    let target = Target::new(TargetKind::Email, "x@y.com");
    let mut entity = target.to_entity(confidence::VERY_HIGH, "s");
    let mut result = ModuleResult::new();
    emit_footprint(&fp, &mut entity, &mut result);
    // The one always-added "Found on N/M platforms checked" summary is
    // present; neither `nested_obj` nor `nested_arr` added a second entry.
    assert_eq!(
        entity.evidence.len(),
        1,
        "nested object/array ExtraData values must not become evidence: {:?}",
        entity.evidence
    );
}

#[test]
fn emit_footprint_skips_absent_marker_extra_data_values() {
    // A provider redaction placeholder or SQL NULL sentinel is absence, not
    // data — it must never mint Evidence (two unrelated hits both reporting
    // "REDACTED" for the same key must not look like corroborating evidence).
    let fp: OcFootprintResponse = serde_json::from_value(json!({
        "stats": {"total_checked": 50, "registered_count": 1},
        "results": [
            {
                "domain": "github.com",
                "taken": true,
                "ExtraData": {"bio": "REDACTED", "location": "\\N"}
            }
        ]
    }))
    .expect("should succeed");
    let target = Target::new(TargetKind::Email, "x@y.com");
    let mut entity = target.to_entity(confidence::VERY_HIGH, "s");
    let mut result = ModuleResult::new();
    emit_footprint(&fp, &mut entity, &mut result);
    // The one always-added "Found on N/M platforms checked" summary is
    // present; neither `bio` nor `location` added a second entry.
    assert_eq!(
        entity.evidence.len(),
        1,
        "absent-marker ExtraData values must not become evidence: {:?}",
        entity.evidence
    );
}

#[test]
fn emit_footprint_skips_overlong_extra_data_values() {
    // A blob far past any genuine platform attribute's length (a base64
    // payload, stringified nested JSON) must not be allowed to make one
    // footprint hit dominate an entity's evidence list.
    let long = "x".repeat(MAX_EXTRA_VALUE_LEN + 1);
    let fp: OcFootprintResponse = serde_json::from_value(json!({
        "stats": {"total_checked": 50, "registered_count": 1},
        "results": [
            {"domain": "github.com", "taken": true, "ExtraData": {"blob": long}}
        ]
    }))
    .expect("should succeed");
    let target = Target::new(TargetKind::Email, "x@y.com");
    let mut entity = target.to_entity(confidence::VERY_HIGH, "s");
    let mut result = ModuleResult::new();
    emit_footprint(&fp, &mut entity, &mut result);
    // The one always-added "Found on N/M platforms checked" summary is
    // present; the overlong `blob` did not add a second entry.
    assert_eq!(
        entity.evidence.len(),
        1,
        "overlong ExtraData values must not become evidence"
    );
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
