use super::*;
use serde_json::json;

fn map_from_value(v: Value) -> Map<String, Value> {
    v.as_object().unwrap().clone()
}

#[test]
fn accepts_fullname_and_org() {
    let m = AuUnclaimed;
    assert!(m.accepts(&Target::new(TargetKind::FullName, "Haigen Bamford")));
    assert!(m.accepts(&Target::new(TargetKind::Organisation, "Acme Pty Ltd")));
    assert!(!m.accepts(&Target::new(TargetKind::Email, "a@b.com")));
    assert!(!m.accepts(&Target::new(TargetKind::FullName, "Ha"))); // too short
}

#[test]
fn surname_extracts_last_token() {
    assert_eq!(surname("Haigen Bamford"), "Bamford");
    assert_eq!(surname("Mary Jane Watson"), "Watson");
    assert_eq!(surname("Solo"), "Solo");
}

#[test]
fn owner_matches_all_tokens_case_insensitive() {
    let rec = map_from_value(json!({"OWNER_NAME": "BAMFORD, HAIGEN J"}));
    assert!(owner_matches(&rec, "OWNER_NAME", "Haigen Bamford"));
    assert!(!owner_matches(&rec, "OWNER_NAME", "Jane Smith"));
}

#[test]
fn record_to_entities_emits_address_and_coords() {
    let reg = &REGISTERS[0]; // NSW
    let record = map_from_value(json!({
        "OWNER_NAME": "BAMFORD HAIGEN",
        "POSTCODE": "2000",
        "SUBURB": "Sydney",
    }));
    let ents = record_to_entities(&record, reg, "Haigen Bamford", "s");
    let addr = ents.iter().find(|e| e.kind == EntityKind::Address).unwrap();
    assert!(addr.value.contains("NSW"));
    assert!(addr.has_tag("au-state:NSW") && addr.has_tag("country:AU"));
}

#[test]
fn record_to_entities_missing_postcode_returns_empty() {
    let reg = &REGISTERS[0];
    let record = map_from_value(json!({"OWNER_NAME": "BAMFORD HAIGEN"}));
    let ents = record_to_entities(&record, reg, "Haigen Bamford", "s");
    assert!(ents.is_empty(), "no postcode → no entities");
}

#[test]
fn module_metadata() {
    let m = AuUnclaimed;
    assert_eq!(m.name(), "au_unclaimed");
    assert!(m.attack_techniques().contains(&"T1591.001"));
    assert_eq!(m.cost(), ModuleCost::Free);
}
