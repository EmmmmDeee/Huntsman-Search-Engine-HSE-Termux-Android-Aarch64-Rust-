//! Parser for the DeHashed breach-search **CSV** export. Lets an operator who
//! ran a paid DeHashed search ingest the result into HSE as a first-class scan —
//! no DeHashed API key needed — so every leaked field (email, username, real
//! name, plaintext + hashed passwords, address, phone, source database) becomes
//! a correlated entity that then flows through HSE's relation/correlation graph
//! and the AU enrichment stack. Shared helpers (`ImportStats`, persistence,
//! dedup) live in `super` and are reached via `use super::*`.
//!
//! The DeHashed CSV header is `id,email,username,hashed_password.1..N,name,
//! database_name,highlights.*,url,password,address,phone`; columns are matched
//! by name, so a column being absent or reordered is handled gracefully.
//!
//! This module also round-trips **HSE's own** entity CSV export
//! (`kind,value,raw_value,confidence,…`) so a prior scan can be re-ingested —
//! merge two scans, share a scan, or re-import after editing.

use super::*;

use crate::core::entity::{Entity, EntityKind, Evidence};

/// Detect a DeHashed-style breach CSV from its header row: an identity column
/// plus the DeHashed hallmark (`database_name` or `hashed_password*`). Strict
/// enough not to swallow an arbitrary CSV.
pub(crate) fn looks_like_dehashed_csv(body: &str) -> bool {
    let Some(first) = body.lines().next() else {
        return false;
    };
    let cols: Vec<String> = parse_csv(first)
        .into_iter()
        .next()
        .unwrap_or_default()
        .into_iter()
        .map(|c| c.trim().to_ascii_lowercase())
        .collect();
    let has = |name: &str| {
        cols.iter()
            .any(|c| c == name || c.starts_with(&format!("{name}.")))
    };
    (has("email") || has("username")) && (has("database_name") || has("hashed_password"))
}

/// Parse a DeHashed CSV into individualised, correlated breach entities. Every
/// field of a row is attached as one evidence record to *each* entity the row
/// yields, so the email, username, person and credentials stay tied to the same
/// leaked record (and its source database). Pure (no I/O) so it is unit-testable;
/// `cmd_import_csv` does the output. Credentials are emitted per row and **not**
/// value-deduplicated here, so a password reused across rows survives to the
/// uid-merge as a cross-account link (AU-047) rather than being collapsed.
pub(super) fn parse_dehashed_csv(body: &str, sid: &str) -> (Vec<Entity>, ImportStats) {
    let mut entities = Vec::new();
    let mut stats = ImportStats::default();
    let mut seen = std::collections::HashSet::new();

    let rows = parse_csv(body);
    let Some((header, data)) = rows.split_first() else {
        return (entities, stats);
    };
    let cols: Vec<String> = header
        .iter()
        .map(|c| c.trim().to_ascii_lowercase())
        .collect();
    let idx = |name: &str| cols.iter().position(|c| c == name);
    let hashed_idxs: Vec<usize> = cols
        .iter()
        .enumerate()
        .filter(|(_, c)| c.starts_with("hashed_password"))
        .map(|(i, _)| i)
        .collect();
    let (email_i, user_i, name_i) = (idx("email"), idx("username"), idx("name"));
    let (pass_i, addr_i, phone_i) = (idx("password"), idx("address"), idx("phone"));
    let (url_i, db_i) = (idx("url"), idx("database_name"));

    for row in data {
        let get = |i: Option<usize>| -> Option<&str> {
            i.and_then(|i| row.get(i))
                .map(|s| s.trim())
                .filter(|s| !s.is_empty())
        };

        let db = get(db_i).unwrap_or("DeHashed");
        let email = get(email_i).map(str::to_ascii_lowercase);
        let label = email
            .as_deref()
            .or_else(|| get(name_i))
            .or_else(|| get(user_i))
            .unwrap_or("breach record");

        // One evidence record per row, carrying every non-credential field.
        let mut ev = Evidence::new(
            "import:dehashed",
            format!("DeHashed breach record ({db}) — {label}"),
        )
        .with_attr("database_name", db)
        .with_attr("source", "dehashed-csv");
        for (lbl, i) in [
            ("email", email_i),
            ("username", user_i),
            ("name", name_i),
            ("address", addr_i),
            ("phone", phone_i),
            ("url", url_i),
        ] {
            if let Some(v) = get(i) {
                ev = ev.with_attr(lbl, v);
            }
        }

        let mut push = |mut e: Entity, tag: &str| {
            e.tag("import");
            e.tag("dehashed");
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
        if let Some(un) = get(user_i)
            && un.len() >= 2
            && !un.contains('@')
            && seen.insert(format!("un:{}", un.to_lowercase()))
        {
            push(Entity::new(EntityKind::Username, un, 0.60, sid), "breach");
            stats.usernames += 1;
        }
        if let Some(nm) = get(name_i)
            && nm.split_whitespace().count() >= 2
            && !crate::core::validation::is_placeholder_entity(&EntityKind::Person, nm)
            && seen.insert(format!("pn:{}", nm.to_lowercase()))
        {
            push(Entity::new(EntityKind::Person, nm, 0.62, sid), "breach");
            stats.persons += 1;
        }
        // Plaintext password — a cross-account reuse join-key; emit per row.
        if let Some(pw) = get(pass_i)
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
        // Each hashed password column.
        for hi in &hashed_idxs {
            if let Some(h) = get(Some(*hi))
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
        if let Some(ph) = get(phone_i).and_then(crate::core::validation::to_e164_au)
            && seen.insert(format!("ph:{ph}"))
        {
            push(Entity::new(EntityKind::Phone, &ph, 0.62, sid), "breach");
            stats.phones += 1;
        }
        if let Some(addr) = get(addr_i)
            && crate::core::validation::is_specific_residence(addr)
            && seen.insert(format!("ad:{}", addr.to_ascii_lowercase()))
        {
            push(Entity::new(EntityKind::Address, addr, 0.58, sid), "breach");
            stats.addresses += 1;
        }
        if let Some(u) = get(url_i)
            && u.starts_with("http")
            && seen.insert(format!("u:{u}"))
        {
            push(Entity::new(EntityKind::Url, u, 0.55, sid), "breach");
            stats.urls += 1;
        }

        stats.breach_records += 1;
    }

    // A leaked password field is sometimes itself a wallet/API key, and a row
    // can carry a router BSSID — scan the whole table for all three.
    push_macs(body, sid, "dehashed", &mut entities);
    push_crypto(body, sid, "dehashed", &mut entities);
    push_api_keys(body, sid, "dehashed", &mut entities);
    push_ibans(body, sid, "dehashed", &mut entities);
    (entities, stats)
}

/// Minimal RFC-4180 CSV reader: splits `body` into rows of fields, honouring
/// double-quoted fields (which may contain commas, newlines and `""`-escaped
/// quotes). Dependency-free — HSE pulls in no `csv` crate.
fn parse_csv(body: &str) -> Vec<Vec<String>> {
    let mut rows = Vec::new();
    let mut row: Vec<String> = Vec::new();
    let mut field = String::new();
    let mut in_quotes = false;
    let mut chars = body.chars().peekable();

    while let Some(c) = chars.next() {
        if in_quotes {
            if c == '"' {
                if chars.peek() == Some(&'"') {
                    field.push('"');
                    chars.next();
                } else {
                    in_quotes = false;
                }
            } else {
                field.push(c);
            }
        } else {
            match c {
                '"' => in_quotes = true,
                ',' => row.push(std::mem::take(&mut field)),
                '\r' => {}
                '\n' => {
                    row.push(std::mem::take(&mut field));
                    rows.push(std::mem::take(&mut row));
                }
                _ => field.push(c),
            }
        }
    }
    // Trailing field/row when the body has no final newline.
    if !field.is_empty() || !row.is_empty() {
        row.push(field);
        rows.push(row);
    }
    rows
}

/// CLI entry: parse a DeHashed CSV and persist it as a completed scan, mirroring
/// the other import formats.
pub(super) async fn cmd_import_csv(body: &str, output: &str) -> Result<()> {
    note(output, "Importing DeHashed CSV export...");
    let sid = format!("import-dehashed-{}", crate::core::entity::unix_now());
    let (mut entities, stats) = parse_dehashed_csv(body, &sid);
    deduplicate_by_uid(&mut entities);
    print_import_stats(&stats, entities.len(), output);
    persist_and_report(&sid, &entities, output).await;
    render_import_entities(&entities, output);
    Ok(())
}

// ─── HSE's own CSV export (round-trip) ────────────────────────────────────────

/// Detect HSE's own entity CSV export by its exact, unambiguous header — so a
/// prior scan's `hse export … --format csv` can be re-ingested (merge two scans,
/// share a scan, re-import after editing) without being mistaken for a DeHashed
/// breach table.
pub(crate) fn looks_like_hse_csv(body: &str) -> bool {
    body.lines().next().is_some_and(|h| {
        h.trim_start()
            .starts_with("kind,value,raw_value,confidence,c_effective")
    })
}

/// Inverse of [`crate::core::entity::EntityKind`]'s `Display` — the exact
/// lower-case tokens HSE writes in the CSV's `kind` column.
fn kind_from_str(s: &str) -> Option<EntityKind> {
    use EntityKind::*;
    Some(match s.trim() {
        "person" => Person,
        "email" => Email,
        "phone" => Phone,
        "username" => Username,
        "credential" => Credential,
        "api_key" => ApiKey,
        "password" => Password,
        "ip_address" => IpAddress,
        "domain" => Domain,
        "url" => Url,
        "asn" => Asn,
        "cidr" => Cidr,
        "address" => Address,
        "coordinates" => Coordinates,
        "organisation" => Organisation,
        "abn_acn" => AbnAcn,
        "mac_address" => MacAddress,
        "device_id" => DeviceId,
        "tracking_id" => TrackingId,
        "crypto_address" => CryptoAddress,
        other => Other(other.strip_prefix("other:")?.to_string()),
    })
}

/// Reconstruct entities from HSE's own CSV export, faithfully restoring each
/// row's kind, value, confidence, tags, and evidence (the `[source] summary`
/// trail). Pure — unit-tested. The `import`/`hse-csv` tags mark the provenance
/// without erasing the original tags.
pub(super) fn parse_hse_csv(body: &str, sid: &str) -> (Vec<Entity>, ImportStats) {
    let mut entities = Vec::new();
    let mut stats = ImportStats::default();

    let rows = parse_csv(body);
    let Some((header, data)) = rows.split_first() else {
        return (entities, stats);
    };
    let col = |name: &str| header.iter().position(|h| h.trim() == name);
    let (k_i, v_i) = (col("kind"), col("value"));
    let (conf_i, ev_i, tags_i) = (col("confidence"), col("evidence"), col("tags"));

    for row in data {
        let get = |i: Option<usize>| i.and_then(|i| row.get(i)).map(String::as_str);
        let (Some(kind_s), Some(value)) = (get(k_i), get(v_i)) else {
            continue;
        };
        let value = value.trim();
        let Some(kind) = kind_from_str(kind_s) else {
            continue;
        };
        if value.is_empty() {
            continue;
        }
        let conf = get(conf_i)
            .and_then(|c| c.trim().parse::<f64>().ok())
            .unwrap_or(0.55);

        let mut e = Entity::new(kind.clone(), value, conf, sid);
        e.tag("import");
        e.tag("hse-csv");
        if let Some(tags) = get(tags_i) {
            for t in tags.split('|').map(str::trim).filter(|t| !t.is_empty()) {
                e.tag(t);
            }
        }
        // Rebuild the `[source] summary || …` evidence trail.
        let mut had_ev = false;
        if let Some(ev_blob) = get(ev_i) {
            for chunk in ev_blob
                .split(" || ")
                .map(str::trim)
                .filter(|c| !c.is_empty())
            {
                let (source, summary) = chunk
                    .strip_prefix('[')
                    .and_then(|r| r.split_once(']'))
                    .map_or(("import:hse-csv", chunk), |(s, rest)| (s, rest.trim()));
                e.add_evidence(Evidence::new(source.to_string(), summary.to_string()));
                had_ev = true;
            }
        }
        if !had_ev {
            e.add_evidence(Evidence::new(
                "import:hse-csv",
                format!("Re-imported {kind_s} from an HSE CSV export"),
            ));
        }

        tally(&kind, &mut stats);
        entities.push(e);
    }

    (entities, stats)
}

/// Increment the per-kind import counters used by the summary line.
fn tally(kind: &EntityKind, stats: &mut ImportStats) {
    match kind {
        EntityKind::Email => stats.emails += 1,
        EntityKind::Phone => stats.phones += 1,
        EntityKind::Username => stats.usernames += 1,
        EntityKind::Person => stats.persons += 1,
        EntityKind::IpAddress => stats.ips += 1,
        EntityKind::Domain => stats.domains += 1,
        EntityKind::Url => stats.urls += 1,
        EntityKind::Address => stats.addresses += 1,
        EntityKind::Coordinates => stats.coordinates += 1,
        EntityKind::Credential | EntityKind::Password => stats.credentials += 1,
        EntityKind::ApiKey => stats.api_keys += 1,
        _ => {}
    }
}

/// CLI entry: re-ingest an HSE CSV export as a completed scan.
pub(super) async fn cmd_import_hse_csv(body: &str, output: &str) -> Result<()> {
    note(output, "Re-importing HSE CSV export...");
    let sid = format!("import-hsecsv-{}", crate::core::entity::unix_now());
    let (mut entities, stats) = parse_hse_csv(body, &sid);
    deduplicate_by_uid(&mut entities);
    print_import_stats(&stats, entities.len(), output);
    persist_and_report(&sid, &entities, output).await;
    render_import_entities(&entities, output);
    Ok(())
}
