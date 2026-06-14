use serde_json::Value;

/// Coordinate location from P625 as `(lat, lon)`, or `None` if absent/malformed.
pub(super) fn claim_p625(entity: &Value) -> Option<(f64, f64)> {
    let val = entity.pointer("/claims/P625/0/mainsnak/datavalue/value")?;
    let lat = val.get("latitude").and_then(Value::as_f64)?;
    let lon = val.get("longitude").and_then(Value::as_f64)?;
    if crate::util::geo::is_valid_coords(lat, lon) {
        Some((lat, lon))
    } else {
        None
    }
}

/// String-valued claims for a property (e.g. P856 website, P2037 github handle).
pub(super) fn claim_strings(entity: &Value, pid: &str) -> Vec<String> {
    entity
        .get("claims")
        .and_then(|c| c.get(pid))
        .and_then(Value::as_array)
        .map(|arr| {
            arr.iter()
                .filter_map(|c| {
                    c.pointer("/mainsnak/datavalue/value")
                        .and_then(Value::as_str)
                        .map(str::to_string)
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Entity-id-valued claims for a property (e.g. P31 instance-of → `["Q5", …]`).
pub(super) fn claim_entity_ids(entity: &Value, pid: &str) -> Vec<String> {
    entity
        .get("claims")
        .and_then(|c| c.get(pid))
        .and_then(Value::as_array)
        .map(|arr| {
            arr.iter()
                .filter_map(|c| {
                    c.pointer("/mainsnak/datavalue/value/id")
                        .and_then(Value::as_str)
                        .map(str::to_string)
                })
                .collect()
        })
        .unwrap_or_default()
}

/// `labels`/`descriptions` English value for an entity body.
pub(super) fn en_text(entity: &Value, section: &str) -> Option<String> {
    entity
        .get(section)
        .and_then(|s| s.get("en"))
        .and_then(|e| e.get("value"))
        .and_then(Value::as_str)
        .map(str::to_string)
}
