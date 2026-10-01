//! SeekNow / LeakOSINT bulk JSON export.
//!
//! Shape (the download named like `bulk-*.json`):
//!
//! ```json
//! { "id": "…", "targets": ["…"], "results": [ { "target": "…", "rows": [ { "_source": "SeekNow • Snusbase", "email": "…" } ] } ] }
//! ```
//!
//! `_source` names the breach site that produced the row. Ingest keeps it
//! (evidence attribute `breach_source`). It is not a query term. A later stage
//! turns the file's targets and identity fields into a SeekNow bulk query
//! (`POST /api/v1/search` bodies) via [`bulk_query_from_doc`].

use super::*;

/// Content sniff for the bulk envelope. Cheap on purpose: `{`-bodies are
/// otherwise all routed to the OathNet JSON parser, which does not know this
/// shape and would import nothing.
pub(super) fn looks_like_seeknow_bulk(body: &str) -> bool {
    let head = body.trim_start_matches('\u{feff}').trim_start();
    head.starts_with('{')
        && body.contains("\"targets\"")
        && body.contains("\"rows\"")
        && body.contains("\"_source\"")
}

/// Parse a bulk export. Breach-site labels stay on the evidence; they are not
/// query terms and they are not dropped.
pub(super) fn parse_seeknow_bulk(
    doc: &serde_json::Value,
    sid: &str,
) -> (Vec<crate::core::entity::Entity>, ImportStats) {
    use crate::core::entity::Entity;

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
            push_person(
                &mut entities,
                &mut stats,
                sid,
                target,
                export_id,
                "bulk target",
            );
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
            let breach_source = obj
                .get("_source")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .trim()
                .to_string();
            ingest_row(
                obj,
                sid,
                export_id,
                &breach_source,
                &mut entities,
                &mut stats,
            );
        }
    }

    (entities, stats)
}

fn ingest_row(
    obj: &serde_json::Map<String, serde_json::Value>,
    sid: &str,
    export_id: &str,
    breach_source: &str,
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

    if let Some(email) = field(&["email"])
        && email.contains('@')
        && !email.contains(' ')
    {
        let mut e = Entity::new(EntityKind::Email, &email, confidence::VERY_HIGH, sid);
        e.tag("import");
        e.tag("seeknow-bulk");
        e.add_evidence(evidence_sourced(
            export_id,
            breach_source,
            format!("email {email}"),
        ));
        entities.push(e);
        stats.emails += 1;
    }

    if let Some(phone) = field(&["phone", "mobile", "tel"]) {
        let digits = phone.chars().filter(char::is_ascii_digit).count();
        if digits >= 8 {
            let mut e = Entity::new(EntityKind::Phone, &phone, confidence::HIGH, sid);
            e.tag("import");
            e.tag("seeknow-bulk");
            e.add_evidence(evidence_sourced(
                export_id,
                breach_source,
                format!("phone {phone}"),
            ));
            entities.push(e);
            stats.phones += 1;
        }
    }

    let person = field(&["full_name"]).or_else(|| match (field(&["name"]), field(&["surname"])) {
        (Some(name), Some(surname)) if !name.eq_ignore_ascii_case(&surname) => {
            Some(format!("{name} {surname}"))
        }
        (Some(name), _) => Some(name),
        (None, Some(surname)) => Some(surname),
        _ => None,
    });
    if let Some(name) = person {
        push_person(entities, stats, sid, &name, export_id, "row name");
        if let Some(dob) = field(&["birthdate", "date_of_birth"])
            && let Some(last) = entities.last_mut()
        {
            let mut ev = Evidence::new("import:seeknow-bulk", format!("date of birth {dob}"))
                .with_attr("dob", dob);
            if !breach_source.is_empty() {
                ev = ev.with_attr("breach_source", breach_source);
            }
            last.add_evidence(ev);
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
            e.add_evidence(evidence_sourced(
                export_id,
                breach_source,
                format!("username {user}"),
            ));
            entities.push(e);
            stats.usernames += 1;
        }
    }

    let address = assemble_address(obj);
    if !address.is_empty() {
        let mut e = Entity::new(EntityKind::Address, &address, confidence::HIGH, sid);
        e.tag("import");
        e.tag("seeknow-bulk");
        e.add_evidence(evidence_sourced(
            export_id,
            breach_source,
            format!("address {address}"),
        ));
        entities.push(e);
        stats.addresses += 1;
    }

    if let Some(url) = field(&["url"])
        && crate::util::url_util::is_absolute_http_url(&url)
    {
        let mut e = Entity::new(EntityKind::Url, &url, confidence::MEDIUM_HIGH, sid);
        e.tag("import");
        e.tag("seeknow-bulk");
        e.add_evidence(evidence_sourced(
            export_id,
            breach_source,
            format!("url {url}"),
        ));
        entities.push(e);
        stats.urls += 1;
    }

    if let Some(geo) = field(&["geolocation"])
        && let Some((lat, lon)) = split_lat_lon(&geo)
    {
        let value = format!("{lat},{lon}");
        let mut e = Entity::new(EntityKind::Coordinates, &value, confidence::MEDIUM, sid);
        e.tag("import");
        e.tag("seeknow-bulk");
        e.add_evidence(evidence_sourced(
            export_id,
            breach_source,
            format!("coordinates {value}"),
        ));
        entities.push(e);
        stats.coordinates += 1;
    }

    // Hash material only. The breach site that produced the hash is not kept.
    if let Some(hash) = field(&["hash", "encrypted_password"])
        && hash.len() >= 16
    {
        let mut e = Entity::new(EntityKind::Credential, &hash, confidence::MEDIUM, sid);
        e.tag("import");
        e.tag("seeknow-bulk");
        e.tag("hash");
        e.add_evidence(evidence_sourced(
            export_id,
            breach_source,
            "credential hash",
        ));
        entities.push(e);
        stats.credentials += 1;
    }

    // A free-text related name (sample field `description`), not a source label.
    if let Some(related) = field(&["description"])
        && related.contains(' ')
        && !related.contains("•")
        && !related.contains('@')
    {
        push_person(entities, stats, sid, &related, export_id, "related name");
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
    evidence_sourced(export_id, "", summary)
}

fn evidence_sourced(
    export_id: &str,
    breach_source: &str,
    summary: impl Into<String>,
) -> crate::core::entity::Evidence {
    use crate::core::entity::Evidence;
    let mut ev = Evidence::new("import:seeknow-bulk", summary);
    if !export_id.is_empty() {
        ev = ev.with_attr("export_id", export_id);
    }
    if !breach_source.is_empty() {
        ev = ev.with_attr("breach_source", breach_source);
    }
    ev
}

/// One `POST /api/v1/search` body, plus the row origins the later submit stage
/// still has. `origin` is the file's `_source` values, joined. It is not sent
/// as the query.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SeeknowSearchQuery {
    pub query: String,
    pub query_type: String,
    pub origin: String,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum IdClass {
    Binding,
    Supporting,
    Annotation,
}

#[derive(Clone)]
struct Ident {
    class: IdClass,
    query_type: &'static str,
    value: String,
    origin: String,
}

/// Graph resolution for one bulk file.
///
/// Binding identifiers (email, phone, profile URL) are the only edges that
/// open or extend a component. Username and hash attach inside a component
/// and do not bridge two people. Name, address, and date of birth annotate
/// and never create a component. Breach-site labels stay on the component
/// as origins.
#[derive(Debug)]
pub(crate) struct IdentityCluster {
    pub bindings: Vec<(String, String)>,
    pub supporting: Vec<(String, String)>,
    pub annotations: Vec<(String, String)>,
    pub origins: Vec<String>,
}

pub(crate) fn resolve_identity_clusters(doc: &serde_json::Value) -> Vec<IdentityCluster> {
    fn find(parent: &mut [usize], mut i: usize) -> usize {
        while parent[i] != i {
            parent[i] = parent[parent[i]];
            i = parent[i];
        }
        i
    }
    fn unite(parent: &mut [usize], a: usize, b: usize) {
        let ra = find(parent, a);
        let rb = find(parent, b);
        if ra != rb {
            parent[rb] = ra;
        }
    }
    let grouped = collect_row_idents(doc);
    let mut flat: Vec<Ident> = Vec::new();
    let mut row_of: Vec<usize> = Vec::new();
    for (row_i, row) in grouped.iter().enumerate() {
        for ident in row {
            row_of.push(row_i);
            flat.push(ident.clone());
        }
    }
    let mut parent: Vec<usize> = (0..flat.len()).collect();
    let mut binding_at: std::collections::HashMap<(String, String), usize> =
        std::collections::HashMap::new();
    let mut bindings_in_row: Vec<Vec<usize>> = vec![Vec::new(); grouped.len()];
    for (idx, ident) in flat.iter().enumerate() {
        if ident.class != IdClass::Binding {
            continue;
        }
        let key = (
            ident.query_type.to_string(),
            ident.value.to_ascii_lowercase(),
        );
        if let Some(prev) = binding_at.insert(key, idx) {
            unite(&mut parent, prev, idx);
        }
        bindings_in_row[row_of[idx]].push(idx);
    }
    for row in &bindings_in_row {
        if let Some(first) = row.first() {
            for other in row.iter().skip(1) {
                unite(&mut parent, *first, *other);
            }
        }
    }
    let mut clusters: std::collections::BTreeMap<usize, IdentityCluster> =
        std::collections::BTreeMap::new();
    for (idx, ident) in flat.iter().enumerate() {
        let root = if ident.class == IdClass::Binding {
            find(&mut parent, idx)
        } else if let Some(bind) = bindings_in_row[row_of[idx]].first() {
            find(&mut parent, *bind)
        } else {
            idx
        };
        let cluster = clusters.entry(root).or_insert_with(|| IdentityCluster {
            bindings: Vec::new(),
            supporting: Vec::new(),
            annotations: Vec::new(),
            origins: Vec::new(),
        });
        let pair = (ident.query_type.to_string(), ident.value.clone());
        let slot = match ident.class {
            IdClass::Binding => &mut cluster.bindings,
            IdClass::Supporting => &mut cluster.supporting,
            IdClass::Annotation => &mut cluster.annotations,
        };
        if !slot.contains(&pair) {
            slot.push(pair);
        }
        if !ident.origin.is_empty() && !cluster.origins.iter().any(|o| o == &ident.origin) {
            cluster.origins.push(ident.origin.clone());
        }
    }
    clusters.into_values().collect()
}

fn collect_row_idents(doc: &serde_json::Value) -> Vec<Vec<Ident>> {
    let mut rows_out = Vec::new();
    let Some(results) = doc.get("results").and_then(|v| v.as_array()) else {
        return rows_out;
    };
    for result in results {
        let Some(rows) = result.get("rows").and_then(|v| v.as_array()) else {
            continue;
        };
        for row in rows {
            let Some(obj) = row.as_object() else {
                continue;
            };
            let origin = obj
                .get("_source")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .trim()
                .to_string();
            let mut idents = Vec::new();
            let mut push = |class, query_type: &'static str, value: &str| {
                let value = value.trim().trim_end_matches('\r');
                if value.len() < 2 {
                    return;
                }
                idents.push(Ident {
                    class,
                    query_type,
                    value: value.to_string(),
                    origin: origin.clone(),
                });
            };
            if let Some(email) = obj.get("email").and_then(|v| v.as_str())
                && email.contains('@')
                && !email.contains(' ')
            {
                push(IdClass::Binding, "email", email);
            }
            if let Some(phone) = obj
                .get("phone")
                .or_else(|| obj.get("mobile"))
                .and_then(|v| v.as_str())
            {
                let digits = phone.chars().filter(char::is_ascii_digit).count();
                if digits >= 8 {
                    push(IdClass::Binding, "phone", phone);
                }
            }
            if let Some(url) = obj.get("url").and_then(|v| v.as_str())
                && crate::util::url_util::is_absolute_http_url(url)
            {
                push(IdClass::Binding, "url", url);
            }
            for key in ["username", "nick"] {
                if let Some(user) = obj.get(key).and_then(|v| v.as_str())
                    && !user.contains('@')
                {
                    push(IdClass::Supporting, "username", user);
                }
            }
            if let Some(hash) = obj
                .get("hash")
                .or_else(|| obj.get("encrypted_password"))
                .and_then(|v| v.as_str())
                && hash.len() >= 16
            {
                push(IdClass::Supporting, "hash", hash);
            }
            if let Some(name) = obj.get("full_name").and_then(|v| v.as_str()) {
                push(IdClass::Annotation, "name", name);
            } else if let Some(name) = obj.get("name").and_then(|v| v.as_str()) {
                push(IdClass::Annotation, "name", name);
            }
            if let Some(addr) = obj.get("address").and_then(|v| v.as_str()) {
                push(IdClass::Annotation, "address", addr);
            }
            if let Some(dob) = obj
                .get("birthdate")
                .or_else(|| obj.get("date_of_birth"))
                .and_then(|v| v.as_str())
            {
                push(IdClass::Annotation, "dob", dob);
            }
            if !idents.is_empty() {
                rows_out.push(idents);
            }
        }
    }
    rows_out
}

/// Build the SeekNow bulk query this file will be submitted as.
///
/// Terms are the resolved binding identifiers (email, phone, profile URL) and
/// supporting usernames, one each. The operator's `targets` are included as
/// name queries. Row names, addresses, hashes, and breach-site labels are not
/// query terms. Origins are kept on each item.
pub(crate) fn bulk_query_from_doc(doc: &serde_json::Value) -> Vec<SeeknowSearchQuery> {
    let mut out = Vec::new();
    let mut seen = std::collections::HashSet::new();
    let mut push = |query: &str, query_type: &str, origin: &str| {
        let query = query.trim().trim_end_matches('\r');
        if query.len() < 2 {
            return;
        }
        let key = (query_type.to_string(), query.to_ascii_lowercase());
        if seen.insert(key) {
            out.push(SeeknowSearchQuery {
                query: query.to_string(),
                query_type: query_type.to_string(),
                origin: origin.trim().to_string(),
            });
        }
    };
    if let Some(targets) = doc.get("targets").and_then(|v| v.as_array()) {
        for target in targets {
            if let Some(value) = target.as_str() {
                push(value, "name", "");
            }
        }
    }
    for cluster in resolve_identity_clusters(doc) {
        let origin = cluster.origins.join(" | ");
        for (kind, value) in cluster.bindings.iter().chain(cluster.supporting.iter()) {
            if kind == "hash" {
                continue;
            }
            push(value, kind, &origin);
        }
    }
    out
}

/// JSON document the later submit stage posts, one `/api/v1/search` body per term.
#[expect(
    dead_code,
    reason = "consumed by the later SeekNow bulk submit stage, which is not wired yet"
)]
pub(crate) fn bulk_query_document(doc: &serde_json::Value) -> serde_json::Value {
    let clusters = resolve_identity_clusters(doc);
    let queries: Vec<serde_json::Value> = bulk_query_from_doc(doc)
        .into_iter()
        .map(|q| {
            serde_json::json!({
                "endpoint": "/api/v1/search",
                "body": { "query": q.query, "type": q.query_type, "limit": 500 },
                "origin": q.origin,
            })
        })
        .collect();
    let cluster_view: Vec<serde_json::Value> = clusters
        .iter()
        .map(|c| {
            serde_json::json!({
                "bindings": c.bindings,
                "supporting": c.supporting.iter().filter(|(k, _)| k != "hash").collect::<Vec<_>>(),
                "annotations": c.annotations,
                "origins": c.origins,
            })
        })
        .collect();
    serde_json::json!({
        "provider": "seeknow",
        "clusters": cluster_view,
        "queries": queries,
    })
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
    let queries = bulk_query_from_doc(&doc);
    note(
        output,
        format!(
            "Importing SeekNow bulk export: target=\"{target}\" ({} resolved search bodies for a later SeekNow bulk submit; breach-site labels kept on cluster origins)",
            queries.len()
        ),
    );
    if output != "json" {
        for q in &queries {
            println!(
                "  seeknow bulk query: type={} query={}",
                q.query_type, q.query
            );
        }
    }
    let sid = import_scan_id("seeknow-bulk");
    let (mut entities, stats) = parse_seeknow_bulk(&doc, &sid);
    deduplicate_by_uid(&mut entities);
    print_import_stats(&stats, entities.len(), output);
    persist_and_report(&sid, &entities, output).await;
    render_import_entities(&entities, output);
    Ok(())
}
