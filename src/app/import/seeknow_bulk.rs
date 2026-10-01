//! SeekNow / LeakOSINT bulk JSON export.
//!
//! Shape (the download named like `bulk-*.json`):
//!
//! ```json
//! { "id": "…", "targets": ["…"], "results": [ { "target": "…", "rows": [ { "_source": "SeekNow • Snusbase", "email": "…" } ] } ] }
//! ```
//!
//! `_source` (and a dataset `title` such as `PeopleData`) names the breach site.
//! Those labels are stripped on ingest and never become entities or evidence.
//! Identity fields on the row are kept.

use super::*;

/// Content sniff for the bulk envelope. Cheap on purpose: `{`-bodies are
/// otherwise all routed to the OathNet JSON parser, which does not know this
//! shape and would import nothing.
pub(super) fn looks_like_seeknow_bulk(body: &str) -> bool {
    let head = body.trim_start_matches('\u{feff}').trim_start();
    head.starts_with('{')
        && body.contains("\"targets\"")
        && body.contains("\"rows\"")
        && body.contains("\"_source\"")
}

/// Parse a bulk export. Source and breach-site labels are dropped before any
/// entity is built.
pub(super) fn parse_seeknow_bulk(
    doc: &serde_json::Value,
    sid: &str,
) -> (Vec<crate::core::entity::Entity>, ImportStats) {
    use crate::core::confidence;
    use crate::core::entity::{Entity, EntityKind, Evidence};

    let mut entities: Vec<Entity> = Vec::new();
    let mut stats = ImportStats::default();
    let export_id = doc.get("id").and_then(|v| v.as_str()).unwrap_or("");

    let Some(results) = doc.get("results").and_then(|v| v.as_array()) else {
        return (entities, stats);
    };

    for result in results {
        let target = result
            .get("target")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .trim();
        if !target.is_empty() {
            push_person(&mut entities, &mut stats, sid, target, export_id, "bulk target");
        }
        let Some(rows) = result.get("rows").and_then(|v| v.as_array()) else {
            continue;
        };
        for row in rows {
            stats.breach_records += 1;
            let Some(obj) = row.as_object() else {
                stats.malformed_lines += 1;
                continue;
            };
            ingest_row(obj, sid, export_id, &mut entities, &mut stats);
        }
    }

    (entities, stats)
}

fn ingest_row(
    obj: &serde_json::Map<String, serde_json::Value>,
    sid: &str,
    export_id: &str,
    entities: &mut Vec<crate::core::entity::Entity>,
    stats: &mut ImportStats,
) {
    use crate::core::confidence;
    use crate::core::entity::{Entity, EntityKind, Evidence};

    let field = |keys: &[&str]| -> Option<String> {
        for key in keys {
            if let Some(value) = obj.get(*key).and_then(|v| v.as_str()) {
                let trimmed = value.trim().trim_end_matches('\r');
                if !trimmed.is_empty() {
                    return Some(trimmed.to_string());
                }
            }
        }
        None
    };

    if let Some(email) = field(&["email"]) {
        if email.contains('@') && !email.contains(' ') {
            let mut e = Entity::new(EntityKind::Email, &email, confidence::VERY_HIGH, sid);
            e.tag("import");
            e.tag("seeknow-bulk");
            e.add_evidence(evidence(export_id, format!("email {email}")));
            entities.push(e);
            stats.emails += 1;
        }
    }

    if let Some(phone) = field(&["phone", "mobile", "tel"]) {
        let digits = phone.chars().filter(|c| c.is_ascii_digit()).count();
        if digits >= 8 {
            let mut e = Entity::new(EntityKind::Phone, &phone, confidence::HIGH, sid);
            e.tag("import");
            e.tag("seeknow-bulk");
            e.add_evidence(evidence(export_id, format!("phone {phone}")));
            entities.push(e);
            stats.phones += 1;
        }
    }

    let person = field(&["full_name"]).or_else(|| {
        match (field(&["name"]), field(&["surname"])) {
            (Some(name), Some(surname)) if !name.eq_ignore_ascii_case(&surname) => {
                Some(format!("{name} {surname}"))
            }
            (Some(name), _) => Some(name),
            (None, Some(surname)) => Some(surname),
            _ => None,
        }
    });
    if let Some(name) = person {
        push_person(entities, stats, sid, &name, export_id, "row name");
        if let Some(dob) = field(&["birthdate", "date_of_birth"]) {
            if let Some(last) = entities.last_mut() {
                last.add_evidence(
                    Evidence::new("import:seeknow-bulk", format!("date of birth {dob}"))
                        .with_attr("dob", dob),
                );
            }
        }
    }

    for key in ["username", "nick"] {
        if let Some(user) = field(&[key]) {
            if user.contains('@') {
                continue;
            }
            if user.len() < 2 {
                continue;
            }
            let mut e = Entity::new(EntityKind::Username, &user, confidence::HIGH, sid);
            e.tag("import");
            e.tag("seeknow-bulk");
            e.add_evidence(evidence(export_id, format!("username {user}")));
            entities.push(e);
            stats.usernames += 1;
        }
    }

    let address = assemble_address(obj);
    if !address.is_empty() {
        let mut e = Entity::new(EntityKind::Address, &address, confidence::HIGH, sid);
        e.tag("import");
        e.tag("seeknow-bulk");
        e.add_evidence(evidence(export_id, format!("address {address}")));
        entities.push(e);
        stats.addresses += 1;
    }

    if let Some(url) = field(&["url"]) {
        if url.starts_with("http://") || url.starts_with("https://") {
            let mut e = Entity::new(EntityKind::Url, &url, confidence::MEDIUM_HIGH, sid);
            e.tag("import");
            e.tag("seeknow-bulk");
            e.add_evidence(evidence(export_id, format!("url {url}")));
            entities.push(e);
            stats.urls += 1;
        }
    }

    if let Some(geo) = field(&["geolocation"]) {
        if let Some((lat, lon)) = split_lat_lon(&geo) {
            let value = format!("{lat},{lon}");
            let mut e = Entity::new(EntityKind::Coordinates, &value, confidence::MEDIUM, sid);
            e.tag("import");
            e.tag("seeknow-bulk");
            e.add_evidence(evidence(export_id, format!("coordinates {value}")));
            entities.push(e);
            stats.coordinates += 1;
        }
    }

    // Hash material only. The breach site that produced the hash is not kept.
    if let Some(hash) = field(&["hash", "encrypted_password"]) {
        if hash.len() >= 16 {
            let mut e = Entity::new(EntityKind::Credential, &hash, confidence::MEDIUM, sid);
            e.tag("import");
            e.tag("seeknow-bulk");
            e.tag("hash");
            e.add_evidence(evidence(export_id, "credential hash (breach site stripped)"));
            entities.push(e);
            stats.credentials += 1;
        }
    }

    // A free-text related name (sample field `description`), not a source label.
    if let Some(related) = field(&["description"]) {
        if related.contains(' ') && !related.contains("•") && !related.contains('@') {
            push_person(entities, stats, sid, &related, export_id, "related name");
        }
    }
}

fn push_person(
    entities: &mut Vec<crate::core::entity::Entity>,
    stats: &mut ImportStats,
    sid: &str,
    name: &str,
    export_id: &str,
    why: &str,
) {
    use crate::core::confidence;
    use crate::core::entity::{Entity, EntityKind};

    let name = name.trim();
    if name.len() < 2 {
        return;
    }
    let mut e = Entity::new(EntityKind::Person, name, confidence::HIGH, sid);
    e.tag("import");
    e.tag("seeknow-bulk");
    e.add_evidence(evidence(export_id, format!("{why}: {name}")));
    entities.push(e);
    stats.persons += 1;
}

fn evidence(export_id: &str, summary: impl Into<String>) -> crate::core::entity::Evidence {
    use crate::core::entity::Evidence;
    let mut ev = Evidence::new("import:seeknow-bulk", summary);
    if !export_id.is_empty() {
        ev = ev.with_attr("export_id", export_id);
    }
    ev
}

fn assemble_address(obj: &serde_json::Map<String, serde_json::Value>) -> String {
    let part = |key: &str| -> Option<String> {
        obj.get(key)
            .and_then(|v| v.as_str())
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
    };
    let mut parts: Vec<String> = Vec::new();
    if let Some(street) = part("address") {
        parts.push(street);
    }
    if let Some(suburb) = part("suburb") {
        parts.push(suburb);
    }
    if let Some(state) = part("stat").or_else(|| part("australian_state")) {
        parts.push(state);
    }
    if let Some(post) = part("postal_code") {
        parts.push(post);
    }
    if parts.is_empty() {
        return String::new();
    }
    parts.join(", ")
}

fn split_lat_lon(raw: &str) -> Option<(f64, f64)> {
    let (lat, lon) = raw.split_once(',')?;
    let lat: f64 = lat.trim().parse().ok()?;
    let lon: f64 = lon.trim().parse().ok()?;
    if !lat.is_finite() || !lon.is_finite() {
        return None;
    }
    if !(-90.0..=90.0).contains(&lat) || !(-180.0..=180.0).contains(&lon) {
        return None;
    }
    Some((lat, lon))
}

/// CLI entry for `hse import` once the detector (or `--input-format seeknow-bulk`)
/// has selected this format.
pub(super) async fn cmd_import_seeknow_bulk(body: &str, _path: &str, output: &str) -> Result<()> {
    let doc: serde_json::Value =
        serde_json::from_str(body).map_err(|e| Error::Other(format!("invalid JSON: {e}")))?;
    let target = doc
        .get("targets")
        .and_then(|v| v.as_array())
        .and_then(|a| a.first())
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");
    note(
        output,
        format!(
            "Importing SeekNow bulk export: target=\"{target}\" (source and breach-site labels stripped)"
        ),
    );
    let sid = import_scan_id("seeknow-bulk");
    let (mut entities, stats) = parse_seeknow_bulk(&doc, &sid);
    deduplicate_by_uid(&mut entities);
    print_import_stats(&stats, entities.len(), output);
    persist_and_report(&sid, &entities, output).await;
    render_import_entities(&entities, output);
    Ok(())
}
