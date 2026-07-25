//! Parser for the "OATHNET SEARCH REPORT" export (`oathnet.org`) — the
//! human-readable report variant, distinct from both the OathNet stealer-log TXT
//! (`txt.rs`) and the `• key: value` breach dossier (`dossier.rs`). Its body is a
//! `=== DATABASE LOGS ===` section of `Entry N:` blocks, each a run of plain
//! `key: value` fields (`full name:` / `email:` / `phone number:` / `ip:` /
//! `password hash:` / `address street:` / `latitude:` …), followed by an
//! `=== OSINT ENRICHMENT DATA ===` section of per-IP geolocation blocks (shared
//! with `txt.rs` via `super::parse_osint_enrichment`). Shared helpers live in
//! `super`.

use super::*;

use crate::core::entity::{Entity, EntityKind, Evidence};

/// Detect the OathNet SEARCH REPORT — by its banner or its `=== DATABASE LOGS ===`
/// section header, so a reformatted banner still parses.
pub(crate) fn looks_like_oathnet_report(body: &str) -> bool {
    body.contains("OATHNET SEARCH REPORT")
        || body.contains("=== DATABASE LOGS ===")
        || (body.contains("\nEntry 1:") && body.contains("\ndbname:"))
}

/// True for an `Entry N:` block header (no `#`, distinguishing it from the
/// dossier's `Entry #N:`).
fn is_entry_header(trimmed: &str) -> bool {
    trimmed
        .strip_prefix("Entry ")
        .and_then(|rest| rest.strip_suffix(':'))
        .is_some_and(|n| !n.is_empty() && n.chars().all(|c| c.is_ascii_digit()))
}

/// Parse an OathNet SEARCH REPORT into correlated breach entities. Each `Entry N:`
/// block yields a Person/Email/Username/Phone/IpAddress/Coordinates/Credential/
/// Address cluster, all carrying one shared evidence record (the full leaked row
/// and its source `dbname`) so they stay correlated and verifiable. The trailing
/// OSINT IP-enrichment section is geolocated by the helper shared with `txt.rs`.
/// Pure (no I/O) so it is unit-testable.
pub(super) fn parse_oathnet_report(body: &str, sid: &str) -> (Vec<Entity>, ImportStats) {
    let body = body.strip_prefix('\u{feff}').unwrap_or(body);
    let mut entities = Vec::new();
    let mut stats = ImportStats::default();
    let mut seen = std::collections::HashSet::new();
    let mut entry: Vec<(String, String)> = Vec::new();
    // The DATABASE LOGS section ends where OSINT ENRICHMENT begins; stop feeding
    // `Entry`/`key: value` lines there so an enrichment `key: value` (e.g. `org:`)
    // can't be mistaken for a breach field.
    let logs_end = body.find("=== OSINT ENRICHMENT").map_or(body.len(), |i| i);

    for raw in body[..logs_end].lines() {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            continue;
        }
        // A new `Entry N:` block (or any `=== … ===` / `[ … ]` section header)
        // flushes the accumulated entry.
        if is_entry_header(trimmed) || trimmed.starts_with("===") || trimmed.starts_with('[') {
            emit_oathnet_entry(&mut entry, sid, &mut entities, &mut stats, &mut seen);
            continue;
        }
        if let Some((k, v)) = trimmed.split_once(':') {
            let key = k.trim().to_ascii_lowercase();
            let val = v.trim();
            // A field key is a short alphanumeric tag (with spaces), never a prose
            // sentence or a URL fragment — mirrors the Combined Search guard.
            let key_ok = !key.is_empty()
                && key.len() <= 24
                && key
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == ' ' || c == '_');
            if key_ok && !val.is_empty() {
                entry.push((key, val.to_string()));
            }
        }
    }
    emit_oathnet_entry(&mut entry, sid, &mut entities, &mut stats, &mut seen);

    // The OSINT enrichment section: per-IP geolocation → Coordinates + Address.
    parse_osint_enrichment(body, sid, &mut entities, &mut stats);

    // Mine the body for the synergistic seeds every importer recovers.
    push_macs(body, sid, "oathnet", &mut entities);
    push_crypto(body, sid, "oathnet", &mut entities);
    push_api_keys(body, sid, "oathnet", &mut entities);
    push_ibans(body, sid, "oathnet", &mut entities);
    push_ssids(body, sid, "oathnet", &mut entities);
    (entities, stats)
}

/// Emit the correlated entities for one accumulated `Entry N` record. The full
/// record (minus raw secrets) is attached as evidence to each entity so the
/// email, person, phone and IP stay tied to the same breach row.
fn emit_oathnet_entry(
    entry: &mut Vec<(String, String)>,
    sid: &str,
    entities: &mut Vec<Entity>,
    stats: &mut ImportStats,
    seen: &mut std::collections::HashSet<String>,
) {
    use crate::core::validation::{
        is_fragment_value, is_placeholder_entity, is_specific_residence,
    };
    if entry.is_empty() {
        return;
    }
    let get = |k: &str| -> Option<&str> {
        entry
            .iter()
            .find(|(kk, _)| kk == k)
            .map(|(_, v)| v.as_str())
            .filter(|v| !v.is_empty())
    };

    let full_name = get("full name").map(str::to_string).or_else(|| {
        match (get("first name"), get("last name")) {
            (Some(f), Some(l)) => Some(format!("{f} {l}")),
            _ => None,
        }
    });
    let source = get("dbname").unwrap_or("OathNet breach");

    // Treat a block as a result only if it carries an identity/credential field —
    // a metadata-only block emits nothing.
    let has_identity = get("email").is_some()
        || get("username").is_some()
        || full_name.is_some()
        || get("password").is_some()
        || get("password hash").is_some();
    if !has_identity {
        entry.clear();
        return;
    }

    let label = get("email")
        .or(full_name.as_deref())
        .or_else(|| get("username"))
        .unwrap_or("breach entry");
    let mut ev = Evidence::new(
        "import:oathnet",
        format!("OathNet breach record ({source}) — {label}"),
    )
    .with_attr("source", source)
    .with_attr("importer", "oathnet-report");
    for (k, v) in entry.iter() {
        // Don't echo raw secrets into a benign attribute; they surface (or not) as
        // their own Credential entities below.
        if !matches!(
            k.as_str(),
            "password" | "password hash" | "password md5" | "salt" | "ssn"
        ) {
            ev = ev.with_attr(k.replace(' ', "_"), v);
        }
    }

    let mut push = |mut e: Entity, tag: &str| {
        e.tag("import");
        e.tag("oathnet");
        e.tag("breach");
        e.tag(tag);
        e.add_evidence(ev.clone());
        entities.push(e);
    };

    if let Some(em) = get("email").map(str::to_ascii_lowercase)
        && em.contains('@')
        && !is_fragment_value(&EntityKind::Email, &em)
        && seen.insert(format!("em:{em}"))
    {
        push(Entity::new(EntityKind::Email, &em, 0.72, sid), "breach");
        stats.emails += 1;
    }
    if let Some(un) = get("username")
        && un.len() >= 2
        && !un.contains('@')
        && seen.insert(format!("un:{}", un.to_lowercase()))
    {
        push(Entity::new(EntityKind::Username, un, 0.58, sid), "breach");
        stats.usernames += 1;
    }
    if let Some(nm) = &full_name {
        // A real person name: ≥2 words, not a placeholder, and not a single token
        // echoed twice (OathNet pads unknown names as "Query Query", e.g.
        // "Rhino Rhino" — never a real identity).
        let words: Vec<&str> = nm.split_whitespace().collect();
        let all_same = words.windows(2).all(|w| w[0].eq_ignore_ascii_case(w[1]));
        if words.len() >= 2
            && !all_same
            && !is_placeholder_entity(&EntityKind::Person, nm)
            && seen.insert(format!("pn:{}", nm.to_lowercase()))
        {
            push(Entity::new(EntityKind::Person, nm, 0.60, sid), "breach");
            stats.persons += 1;
        }
    }
    for hl in ["password hash", "password md5"] {
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
    if let Some(pw) = get("password")
        && pw.chars().count() >= 4
    {
        if seen.insert(format!("cr:{pw}")) {
            stats.credentials += 1;
        }
        push(
            Entity::new(EntityKind::Credential, pw, 0.55, sid),
            "plaintext-credential",
        );
    }
    // Phones: any field that canonicalises to E.164 (AU local/intl kept, bare
    // foreign-national dropped — exactly the AU-focused `to_e164_au` policy).
    for pl in [
        "phone number",
        "phone national",
        "mobile",
        "phone number2",
        "phone national2",
    ] {
        if let Some(ph) = get(pl).and_then(crate::core::validation::to_e164_au)
            && seen.insert(format!("ph:{ph}"))
        {
            push(Entity::new(EntityKind::Phone, &ph, 0.62, sid), "breach");
            stats.phones += 1;
        }
    }
    if let Some(ip) = get("ip")
        && ip.parse::<std::net::IpAddr>().is_ok()
        && !crate::core::validation::is_bogus_ip(ip)
        && seen.insert(format!("ip:{ip}"))
    {
        push(Entity::new(EntityKind::IpAddress, ip, 0.62, sid), "breach");
        stats.ips += 1;
    }
    // Entry-level coordinates (the breach row's own lat/lon, not the OSINT
    // enrichment) — a direct geolocation of the subject.
    if let (Some(la), Some(lo)) = (
        get("latitude").and_then(|s| s.parse::<f64>().ok()),
        get("longitude").and_then(|s| s.parse::<f64>().ok()),
    ) && la.abs() > 0.01
        && lo.abs() > 0.01
    {
        let coords = format!("{la:.4},{lo:.4}");
        if seen.insert(format!("co:{coords}")) {
            let mut ce = Entity::new(EntityKind::Coordinates, &coords, 0.62, sid);
            ce.tag("geoint");
            push(ce, "breach");
            stats.coordinates += 1;
        }
    }
    // Residential address — composed from the street/city/state/postcode/country
    // fields, but only when a real street NUMBER is present (so the noise rows
    // that repeat the query as a "street" don't fabricate a household pivot).
    if let Some(street) = get("address street")
        && street.chars().any(|c| c.is_ascii_digit())
    {
        let mut parts = vec![street.to_string()];
        if let Some(s2) = get("address street2") {
            parts.push(s2.to_string());
        }
        let locality: Vec<&str> = ["city", "state"].iter().filter_map(|k| get(k)).collect();
        if !locality.is_empty() {
            parts.push(locality.join(" "));
        }
        if let Some(pc) = get("postal code")
            .or_else(|| get("zip"))
            .or_else(|| get("zipcode"))
        {
            parts.push(pc.to_string());
        }
        if let Some(c) = get("country") {
            parts.push(c.to_string());
        }
        let addr = parts.join(", ");
        if is_specific_residence(&addr) && seen.insert(format!("ad:{}", addr.to_ascii_lowercase()))
        {
            push(Entity::new(EntityKind::Address, &addr, 0.58, sid), "breach");
            stats.addresses += 1;
        }
    }

    stats.breach_records += 1;
    entry.clear();
}

/// CLI entry: parse an OathNet SEARCH REPORT and persist it as a completed scan.
pub(super) async fn cmd_import_oathnet_report(body: &str, output: &str) -> Result<()> {
    note(output, "Importing OathNet SEARCH REPORT export...");
    let sid = format!("import-oathnet-{}", crate::core::entity::unix_now());
    let (mut entities, stats) = parse_oathnet_report(body, &sid);
    deduplicate_by_uid(&mut entities);
    print_import_stats(&stats, entities.len(), output);
    if stats.api_keys > 0 {
        crate::secrets::key_pool::save_pool_best_effort(&crate::secrets::key_pool::global_pool());
    }
    persist_and_report(&sid, &entities, output).await;
    render_import_entities(&entities, output);
    Ok(())
}
