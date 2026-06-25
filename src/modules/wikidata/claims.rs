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

/// Time-valued claims for a property (e.g. P569 birth, P570 death).
///
/// Wikidata stores times as `"+YYYY-MM-DDT00:00:00Z"` (with a leading `+` or
/// `-` signum). We strip the signum and return the calendar-date portion only
/// (`YYYY-MM-DD`), which is what AU-073 and other date correlators expect.
/// Precision < day (century/decade/year) is returned as-is up to the available
/// digits rather than being silently dropped.
pub(super) fn claim_time(entity: &Value, pid: &str) -> Option<String> {
    let path = format!("/claims/{pid}/0/mainsnak/datavalue/value");
    let val = entity.pointer(&path)?;
    let time_str = val.get("time").and_then(Value::as_str)?;
    // Strip leading sign character; take at most 10 chars (YYYY-MM-DD).
    let stripped = time_str.trim_start_matches('+').trim_start_matches('-');
    let date = stripped.get(..10).unwrap_or(stripped);
    if date.is_empty() {
        return None;
    }
    Some(date.to_string())
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
