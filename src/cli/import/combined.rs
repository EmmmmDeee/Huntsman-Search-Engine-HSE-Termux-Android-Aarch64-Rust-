//! Parser for the "Combined Search" breach-aggregator TXT export (Snusbase and
//! other sources merged into one indented report). Lets an operator ingest a
//! paid combined breach search into HSE keyless, turning each result record's
//! leaked fields into correlated entities. Shared helpers live in `super`.
//!
//! Shape: numbered records (`[N]`) of `Label:` / value pairs — the value either
//! inline (`Label: value`, as in the header) or on the following line
//! (`Label:` then the indented value). Module-metadata blocks (`Source Type:`,
//! `Status:`, `Count:`) carry no identity fields, so they parse to empty records
//! and emit nothing — no special-casing of the report scaffolding needed.

use super::*;

use crate::core::entity::{Entity, EntityKind, Evidence};

/// Detect the Combined Search export — by its module banner or by its
/// structural fingerprint (numbered records + a source/db field + identity
/// fields), so a renamed banner still parses.
pub(crate) fn looks_like_combined_search(body: &str) -> bool {
    body.contains("Combined Search")
        || (body.contains("\n      [")
            && (body.contains("Source:") || body.contains("Dbname:"))
            && (body.contains("Email:") || body.contains("Username:")))
}

/// A `[N]` record marker line, e.g. `   [12]`.
fn is_record_marker(line: &str) -> bool {
    let t = line.trim();
    t.len() >= 3
        && t.starts_with('[')
        && t.ends_with(']')
        && t[1..t.len() - 1].chars().all(|c| c.is_ascii_digit())
}

/// Split the report into records of `(label_lower, value)` pairs. A new record
/// begins at each `[N]` marker; a `Label:` takes its inline value, else the next
/// non-label/non-marker line.
fn split_records(body: &str) -> Vec<Vec<(String, String)>> {
    let lines: Vec<&str> = body.lines().collect();
    let mut records: Vec<Vec<(String, String)>> = Vec::new();
    let mut current: Vec<(String, String)> = Vec::new();
    let mut i = 0;

    while i < lines.len() {
        let line = lines[i];
        if is_record_marker(line) {
            if !current.is_empty() {
                records.push(std::mem::take(&mut current));
            }
            i += 1;
            continue;
        }
        if let Some((label, inline)) = line.split_once(':') {
            let label = label.trim().to_ascii_lowercase();
            // A label is a short alphanumeric tag, never a sentence/URL fragment.
            if label.is_empty()
                || label.len() > 24
                || !label
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == ' ' || c == '_')
            {
                i += 1;
                continue;
            }
            let inline = inline.trim();
            if !inline.is_empty() {
                current.push((label, inline.to_string()));
                i += 1;
                continue;
            }
            // Value on the following line, unless that line is another label or a
            // record marker (i.e. this label had no value).
            if let Some(next) = lines.get(i + 1) {
                let nt = next.trim();
                let next_is_label = next
                    .split_once(':')
                    .is_some_and(|(l, v)| v.trim().is_empty() && l.trim().len() <= 24);
                if !nt.is_empty() && !is_record_marker(next) && !next_is_label {
                    current.push((label, nt.to_string()));
                    i += 2;
                    continue;
                }
            }
        }
        i += 1;
    }
    if !current.is_empty() {
        records.push(current);
    }
    records
}

/// Parse a Combined Search export into individualised, correlated breach
/// entities (one evidence record per result, carrying the full leaked row and
/// its source database). Pure — unit-tested. Credentials are emitted per record
/// and not value-deduped, preserving cross-account reuse (AU-047).
pub(super) fn parse_combined_search(body: &str, sid: &str) -> (Vec<Entity>, ImportStats) {
    let mut entities = Vec::new();
    let mut stats = ImportStats::default();
    let mut seen = std::collections::HashSet::new();

    for rec in split_records(body) {
        let get = |want: &str| -> Option<&str> {
            rec.iter()
                .find(|(l, _)| l == want)
                .map(|(_, v)| v.trim())
                .filter(|v| !v.is_empty())
        };
        let email = get("email").map(str::to_ascii_lowercase);
        let source = get("source")
            .or_else(|| get("dbname"))
            .unwrap_or("Combined Search");
        // Only treat a block with at least one identity/credential field as a
        // result; metadata blocks (Source Type/Status/Count) yield nothing.
        let is_result = email.is_some()
            || [
                "username",
                "name",
                "full name",
                "password",
                "hash",
                "password hash",
                "phone",
            ]
            .iter()
            .any(|k| get(k).is_some());
        if !is_result {
            continue;
        }

        let label = email
            .as_deref()
            .or_else(|| get("name").or_else(|| get("full name")))
            .or_else(|| get("username"))
            .unwrap_or("breach record");
        let mut ev = Evidence::new(
            "import:combined",
            format!("Combined Search record ({source}) — {label}"),
        )
        .with_attr("source", source)
        .with_attr("importer", "combined-search");
        for (l, v) in &rec {
            // Carry every field except raw secrets (surfaced as their own entities).
            if !matches!(l.as_str(), "password" | "hash" | "password hash" | "salt") {
                ev = ev.with_attr(l.replace(' ', "_"), v);
            }
        }

        let mut push = |mut e: Entity, tag: &str| {
            e.tag("import");
            e.tag("combined-search");
            e.tag("breach");
            e.tag(tag);
            e.add_evidence(ev.clone());
            entities.push(e);
        };

        if let Some(em) = &email
            && em.contains('@')
            && !crate::core::validation::is_fragment_value(&EntityKind::Email, em)
            && seen.insert(format!("em:{em}"))
        {
            push(Entity::new(EntityKind::Email, em, 0.72, sid), "breach");
            stats.emails += 1;
        }
        if let Some(un) = get("username")
            && un.len() >= 2
            && !un.contains('@')
            && seen.insert(format!("un:{}", un.to_lowercase()))
        {
            push(Entity::new(EntityKind::Username, un, 0.60, sid), "breach");
            stats.usernames += 1;
        }
        if let Some(nm) = get("name").or_else(|| get("full name"))
            && nm.split_whitespace().count() >= 2
            && !crate::core::validation::is_placeholder_entity(&EntityKind::Person, nm)
            && seen.insert(format!("pn:{}", nm.to_lowercase()))
        {
            push(Entity::new(EntityKind::Person, nm, 0.62, sid), "breach");
            stats.persons += 1;
        }
        if let Some(pw) = get("password")
            && pw.chars().count() >= 4
        {
            if seen.insert(format!("cr:{pw}")) {
                stats.credentials += 1;
            }
            push(
                Entity::new(EntityKind::Credential, pw, 0.58, sid),
                "plaintext-credential",
            );
        }
        for hl in ["hash", "password hash"] {
            if let Some(h) = get(hl)
                && h.len() >= 8
            {
                if seen.insert(format!("cr:{h}")) {
                    stats.credentials += 1;
                }
                push(
                    Entity::new(EntityKind::Credential, h, 0.60, sid),
                    "password-hash",
                );
            }
        }
        for ipl in ["ip", "lastip"] {
            if let Some(ip) = get(ipl)
                && ip.parse::<std::net::IpAddr>().is_ok()
                && !crate::core::validation::is_bogus_ip(ip)
                && seen.insert(format!("ip:{ip}"))
            {
                push(Entity::new(EntityKind::IpAddress, ip, 0.62, sid), "breach");
                stats.ips += 1;
            }
        }
        if let Some(ph) = get("phone").and_then(crate::core::validation::to_e164_au)
            && seen.insert(format!("ph:{ph}"))
        {
            push(Entity::new(EntityKind::Phone, &ph, 0.62, sid), "breach");
            stats.phones += 1;
        }
        if let Some(u) = get("url")
            && u.starts_with("http")
            && seen.insert(format!("u:{u}"))
        {
            push(Entity::new(EntityKind::Url, u, 0.55, sid), "breach");
            stats.urls += 1;
        }

        stats.breach_records += 1;
    }

    // Any WiFi BSSID / MAC in the report → a geolocation seed.
    push_macs(body, sid, "combined-search", &mut entities);
    (entities, stats)
}

/// CLI entry: parse a Combined Search export and persist it as a completed scan.
pub(super) async fn cmd_import_combined(body: &str, output: &str) -> Result<()> {
    note(output, "Importing Combined Search export...");
    let sid = format!("import-combined-{}", crate::core::entity::unix_now());
    let (mut entities, stats) = parse_combined_search(body, &sid);
    deduplicate_by_uid(&mut entities);
    print_import_stats(&stats, entities.len(), output);
    persist_and_report(&sid, &entities, output).await;
    render_import_entities(&entities, output);
    Ok(())
}
