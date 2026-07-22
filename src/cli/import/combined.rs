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

/// Parse a Combined Search TXT export into individualised, correlated breach
/// entities (one evidence record per result, carrying the full leaked row and
/// its source database), then mine the raw report for embedded secrets. Pure —
/// unit-tested. Credentials are emitted per record and not value-deduped,
/// preserving cross-account reuse (AU-047).
pub(super) fn parse_combined_search(body: &str, sid: &str) -> (Vec<Entity>, ImportStats) {
    let (mut entities, stats) = emit_combined_records(split_records(body), sid);
    // BSSID → geo seed; wallet → chain seed; leaked API key → first-class finding.
    push_macs(body, sid, "combined-search", &mut entities);
    push_crypto(body, sid, "combined-search", &mut entities);
    push_api_keys(body, sid, "combined-search", &mut entities);
    push_ibans(body, sid, "combined-search", &mut entities);
    push_ssids(body, sid, "combined-search", &mut entities);
    (entities, stats)
}

/// Emit correlated breach entities from already-split `(label, value)` records —
/// the shared core of BOTH the text ([`parse_combined_search`]) and the JSON
/// ([`parse_combined_search_json`]) Combined Search parsers, so the two can never
/// drift on which leaked field becomes which entity. Credentials are emitted per
/// record and not value-deduped, preserving cross-account reuse (AU-047).
fn emit_combined_records(
    records: Vec<Vec<(String, String)>>,
    sid: &str,
) -> (Vec<Entity>, ImportStats) {
    let mut entities = Vec::new();
    let mut stats = ImportStats::default();
    let mut seen = std::collections::HashSet::new();
    // A real-world aggregator export echoes every module's results TWICE: once
    // nested under "Modules:", again verbatim under a separate top-level
    // "Results:" section keyed off the same underlying per-module data.
    // Per-field entity dedup (`seen`, below) already keeps a repeated record
    // from producing duplicate entities, but without this, `stats.breach_records`
    // — and the operator-facing "N breach" summary line it feeds — would
    // silently double-count every record in that common export shape. Keyed
    // on identity fields only (not the raw record), because the LAST record
    // in each occurrence absorbs whatever incidental trailing metadata
    // (attempt/retry/cooldown counters) happens to precede the next `[N]`
    // marker or EOF — which can differ in content between the two otherwise-
    // identical copies, even though the record IS the same one.
    let mut seen_records = std::collections::HashSet::new();

    for rec in records {
        let get = |want: &str| -> Option<&str> {
            rec.iter()
                .find(|(l, _)| l == want)
                .map(|(_, v)| v.trim())
                .filter(|v| !v.is_empty())
        };
        let email = get("email").map(str::to_ascii_lowercase);
        // A JSON export names the origin database in any of several fields; fall
        // through them so a record still carries its source. Inert for the text
        // path, whose records only ever carry `source`/`dbname`.
        let source = get("source")
            .or_else(|| get("dbname"))
            .or_else(|| get("breach"))
            .or_else(|| get("leak_site"))
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
        // Skip a record whose identity fields exactly match one already
        // processed — an aggregator's echoed "Results:" section repeats each
        // module's records verbatim, so an identical identity signature is
        // the whole record being repeated, not a coincidentally-similar new one.
        let signature: Vec<Option<String>> = [
            "email",
            "username",
            "name",
            "full name",
            "password",
            "hash",
            "password hash",
            "phone",
            "ip",
            "lastip",
            "url",
            "source",
        ]
        .iter()
        .map(|k| get(k).map(str::to_string))
        .collect();
        if !seen_records.insert(signature) {
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

    (entities, stats)
}

/// Parse the JSON form of a Combined Search export — the breach-aggregator API
/// response `{ "modules": [ { "results": [ { "email": …, "password": …, … }, … ] } ] }`
/// (Snusbase / LeakCheck / OathNet / SEON / … merged into one document). Shares
/// [`emit_combined_records`] with the text parser, so a JSON record and the
/// equivalent text record produce the same entities. `doc` is the already-parsed
/// top-level value the JSON import entry ([`super::json::parse_oathnet_json`])
/// hands us on detecting the combined shape.
///
/// Before this path existed, a combined-search JSON — which, being a `{`-leading
/// body, is routed to the OathNet-native JSON parser — matched none of that
/// parser's `searchResults` / `stealerData` / `osintData` pointers and imported
/// as zero entities, silently discarding every result of a paid multi-source
/// breach search (CLI and Termux web upload alike).
pub(super) fn parse_combined_search_json(
    doc: &serde_json::Value,
    sid: &str,
) -> (Vec<Entity>, ImportStats) {
    let (mut entities, stats) = emit_combined_records(combined_json_records(doc), sid);
    // Mine the serialized document for embedded secrets exactly as the text path
    // mines the raw report: a leaked API key / wallet / BSSID / IBAN / SSID sitting
    // in any field value is still surfaced as its own first-class finding.
    let flat = doc.to_string();
    push_macs(&flat, sid, "combined-search", &mut entities);
    push_crypto(&flat, sid, "combined-search", &mut entities);
    push_api_keys(&flat, sid, "combined-search", &mut entities);
    push_ibans(&flat, sid, "combined-search", &mut entities);
    push_ssids(&flat, sid, "combined-search", &mut entities);
    (entities, stats)
}

/// Flatten a Combined Search JSON response into the same `(label, value)` record
/// shape [`split_records`] produces for the text export, so both feed the one
/// shared emitter. Walks `modules[].results[]`; each result object becomes one
/// record. Heterogeneous JSON value types are coerced rather than dropped — a
/// string verbatim, a number/bool stringified, an array of scalars joined — so a
/// `source`/`breach` that arrives as an integer (`2844`) or a `dbname` that
/// arrives as an array (`["A.com","B.com"]`) is preserved instead of silently
/// lost. Nested objects (e.g. SEON's `details`) and nulls carry no leaf field and
/// are skipped. An error stub whose only field is non-identity (e.g. `{"0":"…"}`)
/// still produces a record; the emitter's identity-field gate then drops it, so it
/// contributes no entities.
fn combined_json_records(doc: &serde_json::Value) -> Vec<Vec<(String, String)>> {
    let mut out = Vec::new();
    let Some(modules) = doc.get("modules").and_then(|v| v.as_array()) else {
        return out;
    };
    for module in modules {
        let Some(results) = module.get("results").and_then(|v| v.as_array()) else {
            continue;
        };
        for result in results {
            let Some(obj) = result.as_object() else {
                continue;
            };
            let mut rec: Vec<(String, String)> = Vec::new();
            for (key, val) in obj {
                let Some(text) = json_field_to_string(val) else {
                    continue;
                };
                let text = text.trim();
                if !text.is_empty() {
                    rec.push((normalize_combined_label(key), text.to_string()));
                }
            }
            if !rec.is_empty() {
                out.push(rec);
            }
        }
    }
    out
}

/// Coerce a JSON leaf (or array of leaves) to one string; `None` for objects and
/// null (no single leaf value). An array joins its scalar members with `", "` so
/// a multi-source `dbname`/`source` array reads as one label.
fn json_field_to_string(v: &serde_json::Value) -> Option<String> {
    match v {
        serde_json::Value::Array(items) => {
            let parts: Vec<String> = items.iter().filter_map(json_scalar).collect();
            (!parts.is_empty()).then(|| parts.join(", "))
        }
        other => json_scalar(other),
    }
}

/// A single JSON scalar as a string; `None` for array/object/null.
fn json_scalar(v: &serde_json::Value) -> Option<String> {
    match v {
        serde_json::Value::String(s) => Some(s.clone()),
        serde_json::Value::Number(n) => Some(n.to_string()),
        serde_json::Value::Bool(b) => Some(b.to_string()),
        _ => None,
    }
}

/// Fold a JSON field name onto the canonical record label the shared emitter
/// reads. JSON exports spell some fields with underscores (`full_name`,
/// `password_hash`, `last_ip`) where the emitter branches on the spaced/short
/// forms (`full name`, `password hash`, `lastip`); map those across. Every other
/// key passes through lowercased, so `email` / `username` / `password` / `hash` /
/// `ip` / `source` / `dbname` / … already line up.
fn normalize_combined_label(key: &str) -> String {
    match key.trim().to_ascii_lowercase().as_str() {
        "full_name" | "fullname" | "profile_name" => "full name".to_string(),
        "password_hash" | "passwordhash" | "pwd_hash" => "password hash".to_string(),
        "last_ip" | "login_ip" => "lastip".to_string(),
        "ip_address" | "ipaddress" => "ip".to_string(),
        other => other.to_string(),
    }
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
