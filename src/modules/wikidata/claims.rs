use serde_json::Value;

/// True when Wikidata itself marks this statement **deprecated**.
///
/// A statement with no `rank` is treated as `normal`. The live API always sets
/// the field, so this only matters for a trimmed body or a test fixture — and
/// the safe reading of a missing rank is "ordinary", never "discard".
fn is_deprecated(statement: &Value) -> bool {
    statement.get("rank").and_then(Value::as_str) == Some("deprecated")
}

/// Every statement of `pid` that Wikidata does **not** mark deprecated, in
/// document order.
///
/// `deprecated` is the source's own marker for a statement known to be wrong or
/// superseded — a figure later found erroneous, a former name kept for
/// provenance. Wikidata keeps such statements visible on purpose; reading one
/// back as current fact republishes an error the source has already retracted.
///
/// `preferred` statements are deliberately **not** filtered to here. P31, P106
/// and P27 are genuinely multi-valued — a person really does hold several
/// occupations and citizenships — so keeping only the preferred value would
/// discard true ones. Rank narrowing belongs to [`best_statement`], which is
/// used where exactly one value is wanted.
fn live_statements<'a>(entity: &'a Value, pid: &str) -> impl Iterator<Item = &'a Value> + 'a {
    entity
        .get("claims")
        .and_then(|c| c.get(pid))
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or_default()
        .iter()
        .filter(|st| !is_deprecated(st))
}

/// The one statement to read where a single value is wanted (a coordinate, a
/// date of birth): the first `preferred`-ranked if the item has any, else the
/// first non-deprecated in document order.
///
/// This is what `preferred` is for — Wikidata sets it to say "when you need a
/// single value, use this one", which is how an item records that its earlier
/// coordinate or date has been superseded without deleting the history. The
/// readers below previously indexed `claims/<pid>/0`, i.e. whichever statement
/// happened to serialize first, so a superseded value could win outright.
fn best_statement<'a>(entity: &'a Value, pid: &str) -> Option<&'a Value> {
    live_statements(entity, pid)
        .find(|st| st.get("rank").and_then(Value::as_str) == Some("preferred"))
        .or_else(|| live_statements(entity, pid).next())
}

/// Coordinate location from P625 as `(lat, lon)`, or `None` if absent/malformed.
pub(super) fn claim_p625(entity: &Value) -> Option<(f64, f64)> {
    let val = best_statement(entity, "P625")?.pointer("/mainsnak/datavalue/value")?;
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
    live_statements(entity, pid)
        .filter_map(|st| {
            st.pointer("/mainsnak/datavalue/value")
                .and_then(Value::as_str)
                .map(str::to_string)
        })
        .collect()
}

/// Entity-id-valued claims for a property (e.g. P31 instance-of → `["Q5", …]`).
pub(super) fn claim_entity_ids(entity: &Value, pid: &str) -> Vec<String> {
    live_statements(entity, pid)
        .filter_map(|st| {
            st.pointer("/mainsnak/datavalue/value/id")
                .and_then(Value::as_str)
                .map(str::to_string)
        })
        .collect()
}

/// Time-valued claims for a property (e.g. P569 birth, P570 death).
///
/// Wikidata stores times as `"+YYYY-MM-DDT00:00:00Z"` (with a leading `+` or
/// `-` signum). We strip the signum and return the calendar-date portion only
/// (`YYYY-MM-DD`), which is what AU-073 and other date correlators expect.
/// Precision < day (century/decade/year) is returned as-is up to the available
/// digits rather than being silently dropped.
pub(super) fn claim_time(entity: &Value, pid: &str) -> Option<String> {
    let val = best_statement(entity, pid)?.pointer("/mainsnak/datavalue/value")?;
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
