//! `hse import` — ingest OathNet JSON/HTML/stealer-TXT exports and breach/
//! dossier compilations as first-class scans. This module holds the format
//! dispatcher, the web-upload entry point and the shared persistence /
//! stats / entity-construction helpers; one submodule per file format owns
//! its parser, reaching the shared helpers through `use super::*`.

use crate::core::error::{Error, Result};

mod combined;
mod csv;
mod dossier;
mod html;
mod json;
mod oathnet_report;
mod stealer;
#[cfg(test)]
mod tests;
mod txt;

// Format parsers live in the per-format submodules; pull their entry points
// into scope for the dispatcher, the web-upload router and the tests.
use combined::{cmd_import_combined, looks_like_combined_search, parse_combined_search};
use csv::{
    cmd_import_csv, cmd_import_hse_csv, looks_like_dehashed_csv, looks_like_hse_csv,
    parse_dehashed_csv, parse_hse_csv,
};
use dossier::{cmd_import_dossier, parse_dossier};
use html::{cmd_import_html, parse_oathnet_html};
use json::{import_json_output, parse_oathnet_json};
use oathnet_report::{cmd_import_oathnet_report, looks_like_oathnet_report, parse_oathnet_report};
use stealer::{cmd_import_stealerlogs, looks_like_stealerlogs, parse_stealerlogs};
use txt::{cmd_import_txt, parse_oathnet_txt};

pub(super) async fn cmd_import(path: &str, output: &str) -> Result<()> {
    // File-size cap before read_to_string — mirrors MAX_UPLOAD_BYTES in the API
    // upload handler (16 MB) so both paths enforce the same memory bound.
    const MAX_IMPORT_BYTES: u64 = 16 * 1024 * 1024;
    let meta =
        std::fs::metadata(path).map_err(|e| Error::Other(format!("cannot stat {path}: {e}")))?;
    if meta.len() > MAX_IMPORT_BYTES {
        return Err(Error::Other(format!(
            "file too large ({} bytes > 16 MB): {path}",
            meta.len()
        )));
    }
    let body = std::fs::read_to_string(path)
        .map_err(|e| Error::Other(format!("cannot read {path}: {e}")))?;

    let is_html = path.ends_with(".html")
        || body.trim_start().starts_with("<!")
        || body.trim_start().starts_with("<html");
    let is_txt = path.ends_with(".txt") && !is_html;

    if is_html {
        return cmd_import_html(&body, output).await;
    }
    if is_txt {
        // A Combined Search breach-aggregator export (`[N]` records of
        // `Label:`/value pairs) is its own shape — route it first.
        if looks_like_combined_search(&body) {
            return cmd_import_combined(&body, output).await;
        }
        // A breach/dossier compilation (`Entry #N:` blocks of `• key: value`
        // fields, plus `USERNAMES:`/`EMAILS:`/`PASSWORDS:` `-> value` lists) is a
        // different shape from the OathNet stealer-log TXT — route it to the
        // dossier parser, which correlates each entry's fields into individualised
        // entities carrying the full record (name, birthdate, country, hash, …).
        if looks_like_dossier(&body) {
            return cmd_import_dossier(&body, output).await;
        }
        // A Stealerlogs victim export (`Module: Stealerlogs` / `Victims:` / `[N]`
        // blocks of `Credentials:` + `Domains:`) — the victim-centric stealer
        // format, routed before the catch-all TXT which can't parse its nested
        // `[N]` structure.
        if looks_like_stealerlogs(&body) {
            return cmd_import_stealerlogs(&body, output).await;
        }
        // An OathNet SEARCH REPORT (`=== DATABASE LOGS ===` of `Entry N:` plain
        // `key: value` blocks) — distinct from the OathNet stealer-log TXT, and
        // routed before it because both carry the `=== OSINT ENRICHMENT` marker
        // the TXT catch-all keys on.
        if looks_like_oathnet_report(&body) {
            return cmd_import_oathnet_report(&body, output).await;
        }
        return cmd_import_txt(&body, output).await;
    }

    // HSE's own CSV export (round-trip) — checked first, before the generic
    // `.csv` → DeHashed routing, by its exact header.
    if looks_like_hse_csv(&body) {
        return cmd_import_hse_csv(&body, output).await;
    }
    // A DeHashed CSV export (by extension or by its header columns) — a breach
    // table, not OathNet JSON.
    if path.ends_with(".csv") || looks_like_dehashed_csv(&body) {
        return cmd_import_csv(&body, output).await;
    }

    let doc: serde_json::Value =
        serde_json::from_str(&body).map_err(|e| Error::Other(format!("invalid JSON: {e}")))?;

    let export_info = doc.get("exportInfo").and_then(|v| v.as_object());
    let query = export_info
        .and_then(|ei| ei.get("query"))
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");
    let date = export_info
        .and_then(|ei| ei.get("exportDate"))
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");

    note(
        output,
        format!("Importing OathNet JSON export: query=\"{query}\", date={date}"),
    );

    let sid = format!("import-{}", &crate::core::entity::unix_now().to_string());
    let (mut entities, stats) = parse_oathnet_json(&doc, &sid).await;
    deduplicate_by_uid(&mut entities);
    print_import_stats(&stats, entities.len(), output);
    persist_and_report(&sid, &entities, output).await;
    import_json_output(&entities, &stats, query, date, path, output)
}

/// Render parsed import entities to stdout for the text-import paths (HTML / TXT
/// / breach-dossier), which all share the `{ "entities": [...] }` JSON shape: one
/// JSON document under `--output json` (so `| jq` works), else a 50-row
/// human-readable table with an "… and N more" footer. One definition so the
/// JSON shape and the table format can't drift between the three callers.
fn render_import_entities(entities: &[crate::core::entity::Entity], output: &str) {
    if output == "json" {
        let out = serde_json::json!({ "entities": entities });
        println!("{}", serde_json::to_string_pretty(&out).unwrap_or_default());
    } else {
        for e in entities.iter().take(50) {
            println!(
                "  [{:.2}] {:15} {}",
                e.confidence,
                e.kind.to_string(),
                crate::util::str_util::truncate_safe(&e.value, 70)
            );
        }
        if entities.len() > 50 {
            println!("  ... and {} more", entities.len() - 50);
        }
    }
}

/// Heuristic: does this text look like a breach/dossier compilation (the
/// `Entry #N:` + `• key: value` + `USERNAMES:`/`EMAILS:`/`PASSWORDS:` format)
/// rather than an OathNet stealer-log TXT? Any one strong marker is enough.
pub(crate) fn looks_like_dossier(body: &str) -> bool {
    body.contains("Entry #")
        || body.contains('\u{2022}') // the `•` bullet that prefixes entry fields
        || ((body.contains("USERNAMES:")
            || body.contains("EMAILS:")
            || body.contains("PASSWORDS:"))
            && body.contains("->"))
}

/// Detect an uploaded file's format from its CONTENT and parse it into finalised
/// (deduplicated, evidence/tag-canonicalised) entities for `sid`, returning the
/// entities plus a format label. This is the single entry the WEB upload uses,
/// so EVERY import format the CLI supports — OathNet JSON/HTML/stealer-TXT and
/// the breach/dossier compilation — is reachable from the Termux UI, parsed by
/// the exact same `parse_*` functions the CLI calls (they can never drift).
/// `async` because the JSON path opportunistically validates discovered keys.
pub(crate) async fn entities_from_upload(
    body: &str,
    sid: &str,
) -> Result<(Vec<crate::core::entity::Entity>, &'static str)> {
    let head = body.trim_start();
    let (mut entities, label) = if head.starts_with("<!") || head.starts_with("<html") {
        (parse_oathnet_html(body, sid), "oathnet-html")
    } else if head.starts_with('{') {
        let doc: serde_json::Value =
            serde_json::from_str(body).map_err(|e| Error::Other(format!("invalid JSON: {e}")))?;
        (parse_oathnet_json(&doc, sid).await.0, "oathnet-json")
    } else if looks_like_combined_search(body) {
        (parse_combined_search(body, sid).0, "combined-search")
    } else if looks_like_dossier(body) {
        (parse_dossier(body, sid).0, "dossier")
    } else if looks_like_stealerlogs(body) {
        (parse_stealerlogs(body, sid).0, "stealerlogs")
    } else if looks_like_oathnet_report(body) {
        (parse_oathnet_report(body, sid).0, "oathnet-report")
    } else if looks_like_hse_csv(body) {
        (parse_hse_csv(body, sid).0, "hse-csv")
    } else if looks_like_dehashed_csv(body) {
        (parse_dehashed_csv(body, sid).0, "dehashed-csv")
    } else {
        // The catch-all text format: an OathNet stealer-log TXT.
        (parse_oathnet_txt(body, sid).0, "oathnet-txt")
    };
    deduplicate_by_uid(&mut entities);
    for e in &mut entities {
        e.canonicalize_order();
    }
    Ok((entities, label))
}

#[derive(Default)]
struct ImportStats {
    breach_records: usize,
    stealer_docs: usize,
    victim_records: usize,
    emails: usize,
    phones: usize,
    ips: usize,
    domains: usize,
    subdomains: usize,
    urls: usize,
    usernames: usize,
    coordinates: usize,
    addresses: usize,
    holehe: usize,
    machines: usize,
    device_users: usize,
    hwids: usize,
    discord_ids: usize,
    admin_paths: usize,
    api_keys: usize,
    api_keys_valid: usize,
    persons: usize,
    organisations: usize,
    credentials: usize,
    date_range: String,
}

pub(crate) fn deduplicate_by_uid(entities: &mut Vec<crate::core::entity::Entity>) {
    // Shared finalization step for all three import parsers (JSON/HTML/TXT).
    // Drop documentation/reserved IPs (192.0.2.x / 198.51.100.x / 203.0.113.x /
    // 0.x / 240.0.0.0/4 / 2001:db8::/32) lifted out of exported data — they can
    // never be real hosts and would otherwise pollute the graph and fire
    // correlations. This mirrors the scan path's admission guard
    // (engine::finalise_module_result) for the import path, which builds
    // entities directly. RFC1918 private / loopback are intentionally kept —
    // they can be genuine local findings in a stealer log.
    //
    // Combined with the domain check below into a single retain pass (the two
    // predicates apply to disjoint entity kinds, so this is behaviour-identical)
    // to avoid a second full traversal + element shift on large imports.
    //
    // Domain branch: drop IP literals mis-classified as domains — the HTML/TXT
    // parsers' domain regex matches dotted-decimal IPs (8.8.8.8, 192.0.2.1) and
    // emits them as Domain entities, which both duplicates the real ip_address
    // entity and smuggles bogus documentation IPs past the IP-kind filter. A real
    // domain never parses as an IP address, so this has no false positives.
    entities.retain(|e| {
        // Mirror the scan-path admission guard for EVERY importer in one place:
        // drop documentation/template placeholders (example.com,
        // firstname@gmail.com, John Doe) and truncated fragments (@gmail, a
        // dotless "gmail" domain). Most parsers already filter these at
        // construction, but the HTML/JSON parsers did not, so a centralised pass
        // keeps them from leaking in. Both predicates exempt secrets internally,
        // so a real password/API-key/credential value is never dropped here.
        if crate::core::validation::is_placeholder_entity(&e.kind, &e.value)
            || crate::core::validation::is_fragment_value(&e.kind, &e.value)
        {
            return false;
        }
        if e.kind == crate::core::entity::EntityKind::IpAddress {
            !crate::core::validation::is_bogus_ip(&e.value)
        } else if e.kind == crate::core::entity::EntityKind::Domain {
            e.value.parse::<std::net::IpAddr>().is_err()
        } else {
            true
        }
    });
    // Fold duplicate-uid entities together — MERGE their evidence (GREATEST
    // semantics), don't drop the later ones. A record that recurs across breach
    // entries — most importantly one reused password hash appearing under several
    // different emails — must retain EVERY record it appeared in, or the
    // cross-account reuse signal (the link that connects separate accounts,
    // AU-047) is silently discarded. First-seen order is preserved.
    let mut order: Vec<String> = Vec::new();
    let mut by_uid: std::collections::HashMap<String, crate::core::entity::Entity> =
        std::collections::HashMap::new();
    for e in entities.drain(..) {
        match by_uid.get_mut(&e.uid) {
            Some(existing) => existing.merge(e),
            None => {
                order.push(e.uid.clone());
                by_uid.insert(e.uid.clone(), e);
            }
        }
    }
    *entities = order
        .into_iter()
        .filter_map(|uid| by_uid.remove(&uid))
        .collect();
}

/// Persist a parsed import as a completed scan in the default store — the CLI
/// counterpart to the web `scan_import` handler — so `hse import` is no longer a
/// print-and-discard: the imported scan appears in `hse list`, every view/export
/// (entities, dossier, debug bundle, GEXF) works on it, and expansion seeds can
/// later re-scan its pivots. Derives the deterministic entity relations and runs
/// the correlator, exactly as the live scan finalise does, so an imported dossier
/// carries the same graph a live scan would. Best-effort on relations and
/// correlations: an import whose entities already persisted must not fail on a
/// hiccup there. Returns `(relations, correlations)` persisted, for the summary.
async fn persist_import(
    sid: &str,
    entities: &[crate::core::entity::Entity],
) -> Result<(usize, usize)> {
    use crate::core::StoragePort;
    use crate::core::entity::{EntityKind, unix_now};
    use crate::core::scan::{Scan, ScanStatus, Target, TargetKind};
    use std::sync::Arc;

    // A readable scan label: the strongest identity in the file, else generic —
    // matches the web upload handler so the two paths label imports identically.
    let label = entities
        .iter()
        .find(|e| e.kind == EntityKind::Person)
        .or_else(|| entities.iter().find(|e| e.kind == EntityKind::Email))
        .map_or_else(|| "imported dossier".to_string(), |e| e.value.clone());

    // Offline geospatial enrichment, exactly as the live scan finalise does:
    // parse each Address, geohash/timezone/country-tag each Coordinates, and
    // derive Coordinates from any Address whose city resolves offline — so an
    // imported dossier's addresses feed the geo-correlation stack (AU-014/017/
    // 032/056/057/085, co-location) instead of sitting inert. Deterministic, no
    // network; runs before relations/correlations so the derived fixes are
    // persisted, related and correlated in this same pass.
    let mut entities = entities.to_vec();
    crate::core::engine::enrich_offline_geo(&mut entities, sid);
    let entities = &entities[..];

    let store: Arc<dyn StoragePort> =
        Arc::new(crate::storage::Store::open(&crate::default_db_path())?);

    let mut scan = Scan::new(sid.to_string(), Target::new(TargetKind::FullName, label));
    scan.status = ScanStatus::Complete;
    scan.finished_at = Some(unix_now());
    scan.entity_count = entities.len();
    store.upsert_scan(&scan)?;
    store.upsert_entities_batch(entities)?;

    let mut relations = 0usize;
    for r in &crate::core::relation::derive_all(entities, sid) {
        if store.upsert_relation(r).is_ok() {
            relations += 1;
        }
    }

    let mut correlations = 0usize;
    let correlator = crate::core::correlator::Correlator::new(Arc::clone(&store));
    if let Ok(hits) = correlator.run(sid) {
        for c in &hits {
            if store.upsert_correlation(c).is_ok() {
                correlations += 1;
            }
        }
    }

    Ok((relations, correlations))
}

/// Persist a parsed import and emit a one-line summary on the appropriate stream.
/// Shared tail for every CLI import path so persistence and its reporting can't
/// drift between formats. A persistence failure is surfaced as a warning, never
/// fatal — the entities were already rendered to the operator.
async fn persist_and_report(sid: &str, entities: &[crate::core::entity::Entity], output: &str) {
    match persist_import(sid, entities).await {
        Ok((relations, correlations)) => note(
            output,
            format!(
                "  Stored:    scan {sid} ({} entities, {relations} relations, {correlations} correlations) — view with `hse list`",
                entities.len()
            ),
        ),
        Err(e) => note(
            output,
            format!("  Warning:   could not persist import: {e}"),
        ),
    }
}

fn detect_and_create_api_key_entity(
    pw: &str,
    sid: &str,
    source_label: &str,
) -> Option<(&'static str, crate::core::entity::Entity)> {
    use crate::core::entity::{Entity, EntityKind, Evidence};
    use crate::modules::oathnet_pro::key_harvest::identify_api_key;

    let (service, _key_val) = identify_api_key(pw)?;

    let char_len = pw.chars().count();
    let prefix: String = pw.chars().take(8).collect();
    let suffix: String = pw.chars().skip(char_len.saturating_sub(4)).collect();
    let display = format!("{service}:{prefix}...{suffix}");
    let mut e = Entity::new(EntityKind::ApiKey, &display, 0.80, sid);
    e.tag("api-key");
    e.tag(format!("service:{service}"));
    e.tag("import");
    e.add_evidence(
        Evidence::new(
            source_label,
            format!("API key pattern ({service}) in stealer data"),
        )
        .with_attr("service", service)
        .with_attr("key_length", pw.len().to_string()),
    );
    Some((service, e))
}

/// Extract WiFi BSSIDs / MAC addresses from `text` and push them as
/// `MacAddress` entities — a victim's router BSSID lifted from a stealer log or
/// breach record becomes a geolocation seed that `mylnikov` / `wigle` can turn
/// into coordinates. Capped so a hostile blob can't flood the graph. Returns the
/// number emitted.
fn push_macs(
    text: &str,
    sid: &str,
    source_tag: &str,
    entities: &mut Vec<crate::core::entity::Entity>,
) -> usize {
    use crate::core::entity::{Entity, EntityKind, Evidence};
    let mut n = 0;
    for mac in crate::util::extract::macs(text).into_iter().take(50) {
        let mut e = Entity::new(EntityKind::MacAddress, &mac, 0.55, sid);
        e.tag("import");
        e.tag(source_tag);
        e.tag("bssid");
        e.add_evidence(
            Evidence::new(
                "import:mac",
                format!("WiFi BSSID / MAC `{mac}` — geolocatable via mylnikov/wigle"),
            )
            .with_attr("mac", &mac),
        );
        entities.push(e);
        n += 1;
    }
    n
}

/// Extract validated crypto wallet addresses from `text` and push them as
/// `CryptoAddress` entities — stealer logs and breach dumps routinely carry a
/// victim's BTC/ETH/… wallets, and a recovered address is a chain-analysis seed
/// (`chain_intel`). Every candidate token is checksum-validated by
/// [`crate::core::crypto::classify_crypto_address`], so noise (hashes, API keys)
/// is rejected. Capped at 50/import. Returns the number emitted.
fn push_crypto(
    text: &str,
    sid: &str,
    source_tag: &str,
    entities: &mut Vec<crate::core::entity::Entity>,
) -> usize {
    use crate::core::entity::{Entity, EntityKind, Evidence};
    let mut seen = std::collections::HashSet::new();
    let mut n = 0;
    for raw in text.split(|c: char| c.is_whitespace() || "\"',;:|<>()[]{}=".contains(c)) {
        let tok = raw.trim_matches(|c: char| !c.is_ascii_alphanumeric());
        if !(26..=64).contains(&tok.len()) {
            continue;
        }
        let Some(chain) = crate::core::crypto::classify_crypto_address(tok) else {
            continue;
        };
        if !seen.insert(tok.to_string()) {
            continue;
        }
        let coin = chain.strip_prefix("crypto_").unwrap_or(chain);
        let mut e = Entity::new(EntityKind::CryptoAddress, tok, 0.70, sid);
        e.tag("import");
        e.tag(source_tag);
        e.tag("crypto-address");
        e.tag(format!("chain:{coin}"));
        e.add_evidence(
            Evidence::new(
                "import:crypto",
                format!(
                    "{} wallet address `{tok}` in {source_tag} data",
                    crate::core::crypto::chain_label(chain)
                ),
            )
            .with_attr("chain", chain),
        );
        entities.push(e);
        n += 1;
        if n >= 50 {
            break;
        }
    }
    n
}

/// Scan `text` for leaked API keys / tokens anywhere in a breach or stealer
/// dump — not just in a recognised `service: key` field — and emit each as an
/// `ApiKey` entity (masked display, full key stashed in the key pool for
/// reuse/validation). Every candidate is gated by the canonical
/// `identify_api_key`, so only real vendor-key shapes (AWS `AKIA…`, GitHub
/// `ghp_…`, Slack `xox…`, Stripe `sk_live_…`, Google `AIza…`, …) are kept.
/// Capped at 50/import. Returns the number emitted.
fn push_api_keys(
    text: &str,
    sid: &str,
    source_tag: &str,
    entities: &mut Vec<crate::core::entity::Entity>,
) -> usize {
    let label = format!("import:{source_tag}");
    let mut seen = std::collections::HashSet::new();
    let mut n = 0;
    for raw in text.split(|c: char| c.is_whitespace() || "\"',;|<>(){}[]".contains(c)) {
        let tok = raw.trim_matches(|c: char| matches!(c, '\'' | '"' | '`' | '='));
        if !(16..=240).contains(&tok.len()) || !seen.insert(tok.to_string()) {
            continue;
        }
        if let Some((service, mut e)) = detect_and_create_api_key_entity(tok, sid, &label) {
            e.tag(source_tag);
            entities.push(e);
            store_key_in_pool(
                service,
                tok,
                format!("{source_tag} import: leaked {service} key"),
            );
            n += 1;
            if n >= 50 {
                break;
            }
        }
    }
    n
}

/// Extract checksum-valid IBANs (international bank accounts) from `text` and
/// push them as `Other("iban")` financial-intel entities — a victim's bank
/// account recovered from a breach/stealer dump. Capped at 50/import.
fn push_ibans(
    text: &str,
    sid: &str,
    source_tag: &str,
    entities: &mut Vec<crate::core::entity::Entity>,
) -> usize {
    use crate::core::entity::{Entity, EntityKind, Evidence};
    let mut n = 0;
    for iban in crate::util::extract::ibans(text).into_iter().take(50) {
        let mut e = Entity::new(EntityKind::Other("iban".into()), &iban, 0.62, sid);
        e.tag("import");
        e.tag(source_tag);
        e.tag("iban");
        e.tag("financial");
        e.add_evidence(
            Evidence::new(
                "import:iban",
                format!("Bank account (IBAN) `{iban}` in {source_tag} data"),
            )
            .with_attr("iban", &iban),
        );
        entities.push(e);
        n += 1;
    }
    n
}

/// Extract labelled WiFi SSIDs from `text` and push them as `Ssid` entities —
/// a victim's network names from a stealer log. A *unique* SSID then dispatches
/// to `wigle`'s SSID search, which returns where the network was observed,
/// placing the owner. Capped at 50/import.
fn push_ssids(
    text: &str,
    sid: &str,
    source_tag: &str,
    entities: &mut Vec<crate::core::entity::Entity>,
) -> usize {
    use crate::core::entity::{Entity, EntityKind, Evidence};
    let mut n = 0;
    for ssid in crate::util::extract::labeled_ssids(text)
        .into_iter()
        .take(50)
    {
        let mut e = Entity::new(EntityKind::Ssid, &ssid, 0.60, sid);
        e.tag("import");
        e.tag(source_tag);
        e.tag("wifi-network");
        e.add_evidence(
            Evidence::new(
                "import:ssid",
                format!("WiFi network `{ssid}` in {source_tag} data — geolocatable via WiGLE"),
            )
            .with_attr("ssid", &ssid),
        );
        entities.push(e);
        n += 1;
    }
    n
}

fn store_key_in_pool(service: &str, key: &str, notes: String) {
    let pool = crate::util::key_pool::global_pool();
    let mut entry = crate::util::key_pool::KeyEntry::new(key);
    // Provenance: record that this key was found inside an imported dump (not
    // operator-provisioned) for reporting/attribution. Visibility metadata only
    // — it does not gate selection.
    entry.discovered_by = Some("import".to_string());
    entry.discovered_at = Some(crate::core::entity::unix_now());
    entry.notes = Some(notes);
    pool.add(service, entry);
}

struct GeoFields<'a> {
    ip: &'a str,
    lat: Option<f64>,
    lon: Option<f64>,
    city: &'a str,
    region: &'a str,
    country: &'a str,
    isp: &'a str,
}

fn create_geolocation_entities(
    geo: &GeoFields<'_>,
    sid: &str,
    entities: &mut Vec<crate::core::entity::Entity>,
    stats: &mut ImportStats,
) {
    use crate::core::entity::{Entity, EntityKind, Evidence};

    if let (Some(la), Some(lo)) = (geo.lat, geo.lon)
        && la.abs() > 0.01
        && lo.abs() > 0.01
    {
        let coords = format!("{la:.4},{lo:.4}");
        let mut ce = Entity::new(EntityKind::Coordinates, &coords, 0.70, sid);
        ce.tag("geoint");
        ce.tag("import");
        ce.add_evidence(Evidence::new(
            "import:oathnet",
            format!(
                "IP {}: {}, {}, {} ({})",
                geo.ip, geo.city, geo.region, geo.country, geo.isp
            ),
        ));
        entities.push(ce);
        stats.coordinates += 1;
    }
    if !geo.city.is_empty() {
        let addr = format!("{}, {}, {}", geo.city, geo.region, geo.country);
        let mut ae = Entity::new(EntityKind::Address, &addr, 0.65, sid);
        ae.tag("import");
        entities.push(ae);
        stats.addresses += 1;
    }
}

/// Parse the `=== OSINT ENRICHMENT ===` IP-geolocation section that the OathNet
/// stealer-log TXT and the OathNet SEARCH REPORT both carry — a run of `IP:` /
/// `lat:` / `lon:` / `city:` / `regionName:` / `country:` / `isp:` blocks — into
/// `Coordinates` + `Address` entities. Shared by `txt.rs` and
/// `oathnet_report.rs` so the two formats geolocate identically and the block
/// can never drift between them. A no-op when the section is absent.
fn parse_osint_enrichment(
    body: &str,
    sid: &str,
    entities: &mut Vec<crate::core::entity::Entity>,
    stats: &mut ImportStats,
) {
    let Some(os) = body.find("=== OSINT ENRICHMENT") else {
        return;
    };
    let osint_section = &body[os..];
    let mut current_ip = String::new();
    let mut lat: Option<f64> = None;
    let mut lon: Option<f64> = None;
    let mut city = String::new();
    let mut region = String::new();
    let mut country = String::new();
    let mut isp = String::new();

    for line in osint_section.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("IP: ") {
            if !current_ip.is_empty() {
                create_geolocation_entities(
                    &GeoFields {
                        ip: &current_ip,
                        lat,
                        lon,
                        city: &city,
                        region: &region,
                        country: &country,
                        isp: &isp,
                    },
                    sid,
                    entities,
                    stats,
                );
            }
            current_ip = rest.trim().to_string();
            lat = None;
            lon = None;
            city.clear();
            region.clear();
            country.clear();
            isp.clear();
        } else if let Some(rest) = trimmed.strip_prefix("lat: ") {
            lat = rest.trim().parse().ok();
        } else if let Some(rest) = trimmed.strip_prefix("lon: ") {
            lon = rest.trim().parse().ok();
        } else if let Some(rest) = trimmed.strip_prefix("city: ") {
            city = rest.trim().to_string();
        } else if let Some(rest) = trimmed.strip_prefix("regionName: ") {
            region = rest.trim().to_string();
        } else if let Some(rest) = trimmed.strip_prefix("country: ") {
            country = rest.trim().to_string();
        } else if let Some(rest) = trimmed.strip_prefix("isp: ") {
            isp = rest.trim().to_string();
        }
    }
    if !current_ip.is_empty() {
        create_geolocation_entities(
            &GeoFields {
                ip: &current_ip,
                lat,
                lon,
                city: &city,
                region: &region,
                country: &country,
                isp: &isp,
            },
            sid,
            entities,
            stats,
        );
    }
}

/// Emit a human-readable progress/summary line on the stream appropriate to the
/// output mode: stderr under `--output json` (so stdout stays pure JSON for
/// `| jq`), stdout otherwise (where the summary IS the operator-facing output).
fn note(output: &str, line: impl AsRef<str>) {
    if output == "json" {
        eprintln!("{}", line.as_ref());
    } else {
        println!("{}", line.as_ref());
    }
}

fn print_import_stats(stats: &ImportStats, entity_count: usize, output: &str) {
    // Route every line through `note` so a `--output json` run keeps stdout free
    // of this summary (it goes to stderr); a table run prints it to stdout.
    macro_rules! row {
        ($($a:tt)*) => { note(output, format!($($a)*)) };
    }
    row!("Imported {} entities:", entity_count);
    row!(
        "  Identity:  {} emails, {} phones, {} usernames, {} persons, {} orgs, {} device users, {} Discord IDs",
        stats.emails,
        stats.phones,
        stats.usernames,
        stats.persons,
        stats.organisations,
        stats.device_users,
        stats.discord_ids
    );
    if stats.credentials > 0 {
        row!("  Creds:     {} password hashes", stats.credentials);
    }
    row!(
        "  Network:   {} IPs, {} domains, {} subdomains, {} URLs, {} admin paths",
        stats.ips,
        stats.domains,
        stats.subdomains,
        stats.urls,
        stats.admin_paths
    );
    row!(
        "  Geo:       {} coordinates, {} addresses",
        stats.coordinates,
        stats.addresses
    );
    row!(
        "  Device:    {} HWIDs, {} machine log IDs",
        stats.hwids,
        stats.machines
    );
    row!("  Keys:      {} API keys detected", stats.api_keys);
    row!("  Verified:  {} holehe platform checks", stats.holehe);
    row!(
        "  Source:    {} breach, {} stealer docs, {} victims",
        stats.breach_records,
        stats.stealer_docs,
        stats.victim_records
    );
    if !stats.date_range.is_empty() {
        row!("  Timeline:  {}", stats.date_range);
    }
    if stats.api_keys > 0 {
        row!(
            "  Pool:      {} API keys detected, {} validated active",
            stats.api_keys,
            stats.api_keys_valid
        );
    }
}
