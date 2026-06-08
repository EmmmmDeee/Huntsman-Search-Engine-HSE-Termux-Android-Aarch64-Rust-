use crate::core::error::{Error, Result};

pub(super) async fn cmd_import(path: &str, output: &str) -> Result<()> {
    let body = std::fs::read_to_string(path)
        .map_err(|e| Error::Other(format!("cannot read {path}: {e}")))?;

    let is_html = path.ends_with(".html")
        || body.trim_start().starts_with("<!")
        || body.trim_start().starts_with("<html");
    let is_txt = path.ends_with(".txt") && !is_html;

    if is_html {
        return cmd_import_html(&body, output);
    }
    if is_txt {
        // A breach/dossier compilation (`Entry #N:` blocks of `• key: value`
        // fields, plus `USERNAMES:`/`EMAILS:`/`PASSWORDS:` `-> value` lists) is a
        // different shape from the OathNet stealer-log TXT — route it to the
        // dossier parser, which correlates each entry's fields into individualised
        // entities carrying the full record (name, birthdate, country, hash, …).
        if looks_like_dossier(&body) {
            return cmd_import_dossier(&body, output);
        }
        return cmd_import_txt(&body, output);
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

    note(output, format!("Importing OathNet JSON export: query=\"{query}\", date={date}"));

    let sid = format!("import-{}", &crate::core::entity::unix_now().to_string());
    let (mut entities, stats) = parse_oathnet_json(&doc, &sid).await;
    deduplicate_by_uid(&mut entities);
    print_import_stats(&stats, entities.len(), output);
    import_json_output(&entities, &stats, query, date, path, output)
}

/// Parse an OathNet JSON API export (breach results, stealer victims, stealer
/// docs, holehe checks, geo) into entities + stats. `async` because it
/// opportunistically validates any API key found in stealer data. Reusable core
/// shared by the CLI (`cmd_import`) and the web upload dispatcher, so they never
/// drift.
async fn parse_oathnet_json(
    doc: &serde_json::Value,
    sid: &str,
) -> (Vec<crate::core::entity::Entity>, ImportStats) {
    use crate::core::entity::{Entity, EntityKind, Evidence};
    // Keep the (verbatim) parse body's `&sid` working — it expects an owned id.
    let sid = sid.to_string();
    let mut entities: Vec<Entity> = Vec::new();
    let mut stats = ImportStats::default();

    // ── Parse breach results ──
    if let Some(breach) = doc
        .pointer("/searchResults/MULTI_SERVICE_RESULTS/breach/data/results")
        .and_then(|v| v.as_array())
    {
        for item in breach {
            stats.breach_records += 1;
            if let Some(email) = item.get("email").and_then(|v| v.as_str())
                && email.contains('@')
                && !email.contains("UPGRADE")
            {
                let db = item
                    .get("dbname")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown");
                let mut e = Entity::new(EntityKind::Email, email, 0.75, &sid);
                e.tag("breach");
                e.tag("import");
                e.add_evidence(
                    Evidence::new("import:oathnet", format!("Breach on {db}"))
                        .with_attr("dbname", db),
                );
                entities.push(e);
                stats.emails += 1;
            }
            if let Some(ip) = item.get("ip").and_then(|v| v.as_str())
                && ip.contains('.')
                && !ip.contains("UPGRADE")
            {
                let mut e = Entity::new(EntityKind::IpAddress, ip, 0.65, &sid);
                e.tag("breach");
                e.tag("import");
                entities.push(e);
                stats.ips += 1;
            }
        }
    }

    // ── Parse stealer victims — IPs, emails, HWIDs, Discord IDs, severity ──
    if let Some(victims) = doc
        .pointer("/stealerData/victims")
        .and_then(|v| v.as_array())
    {
        let mut seen_hwids: std::collections::HashSet<String> = std::collections::HashSet::new();
        let mut seen_discord: std::collections::HashSet<String> = std::collections::HashSet::new();

        for victim in victims {
            stats.victim_records += 1;
            let total_docs = victim
                .get("total_docs")
                .and_then(|v| v.as_u64())
                .unwrap_or(0);
            let log_id = victim.get("log_id").and_then(|v| v.as_str()).unwrap_or("");

            if let Some(ips) = victim.get("device_ips").and_then(|v| v.as_array()) {
                for ip_val in ips.iter().take(10) {
                    if let Some(ip) = ip_val.as_str()
                        && ip.contains('.')
                        && !ip.contains("UPGRADE")
                    {
                        let mut e = Entity::new(EntityKind::IpAddress, ip, 0.60, &sid);
                        e.tag("stealer-victim");
                        e.tag("import");
                        if total_docs > 100 {
                            e.tag("high-exposure");
                        }
                        e.add_evidence(
                            Evidence::new(
                                "import:oathnet",
                                format!("Victim device IP ({total_docs} creds stolen)"),
                            )
                            .with_attr("log_id", log_id)
                            .with_attr("total_docs", total_docs.to_string()),
                        );
                        entities.push(e);
                        stats.ips += 1;
                    }
                }
            }
            if let Some(emails) = victim.get("device_emails").and_then(|v| v.as_array()) {
                for email_val in emails.iter().take(20) {
                    if let Some(email) = email_val.as_str()
                        && email.contains('@')
                        && !email.contains("UPGRADE")
                    {
                        let mut e = Entity::new(EntityKind::Email, email, 0.55, &sid);
                        e.tag("stealer-victim");
                        e.tag("import");
                        entities.push(e);
                        stats.emails += 1;
                    }
                }
            }
            // HWIDs — hardware identifiers for machine tracking
            if let Some(hwids) = victim.get("hwids").and_then(|v| v.as_array()) {
                for h in hwids.iter().take(5) {
                    if let Some(hwid) = h.as_str()
                        && !hwid.is_empty()
                        && seen_hwids.insert(hwid.to_string())
                    {
                        let mut e = Entity::new(EntityKind::DeviceId, hwid, 0.70, &sid);
                        e.tag("hwid");
                        e.tag("import");
                        e.add_evidence(
                            Evidence::new(
                                "import:oathnet",
                                format!("Hardware ID from infected machine ({total_docs} creds)"),
                            )
                            .with_attr("log_id", log_id),
                        );
                        entities.push(e);
                        stats.hwids += 1;
                    }
                }
            }
            // Discord IDs — identity pivots
            if let Some(dids) = victim.get("discord_ids").and_then(|v| v.as_array()) {
                for d in dids.iter().take(5) {
                    if let Some(did) = d.as_str()
                        && !did.is_empty()
                        && seen_discord.insert(did.to_string())
                    {
                        let mut e = Entity::new(EntityKind::Username, did, 0.60, &sid);
                        e.tag("discord-id");
                        e.tag("import");
                        entities.push(e);
                        stats.discord_ids += 1;
                    }
                }
            }
        }
    }

    // ── Parse stealer docs — domains, subdomains, URLs, usernames, timelines ──
    if let Some(docs) = doc.pointer("/stealerData/docs").and_then(|v| v.as_array()) {
        let mut seen_domains: std::collections::HashSet<String> = std::collections::HashSet::new();
        let mut seen_users: std::collections::HashSet<String> = std::collections::HashSet::new();
        let mut seen_urls: std::collections::HashSet<String> = std::collections::HashSet::new();
        let mut log_ids: std::collections::HashSet<String> = std::collections::HashSet::new();
        let mut earliest_date: Option<String> = None;
        let mut latest_date: Option<String> = None;

        for doc_item in docs {
            stats.stealer_docs += 1;

            // Domains
            if let Some(domains) = doc_item.get("domain").and_then(|v| v.as_array()) {
                for d in domains {
                    if let Some(domain) = d.as_str() {
                        let lower = domain.to_lowercase();
                        if seen_domains.insert(lower.clone()) && domain.contains('.') {
                            let mut e = Entity::new(EntityKind::Domain, &lower, 0.50, &sid);
                            e.tag("stealer-target");
                            e.tag("import");
                            entities.push(e);
                            stats.domains += 1;
                        }
                    }
                }
            }

            // Subdomains
            if let Some(subs) = doc_item.get("subdomain").and_then(|v| v.as_array()) {
                for s in subs {
                    if let Some(sub) = s.as_str() {
                        let lower = sub.to_lowercase();
                        if lower.contains('.') && seen_domains.insert(format!("sub:{lower}")) {
                            let mut e = Entity::new(EntityKind::Domain, &lower, 0.55, &sid);
                            e.tag("subdomain");
                            e.tag("stealer-target");
                            e.tag("import");
                            entities.push(e);
                            stats.subdomains += 1;
                        }
                    }
                }
            }

            // URLs (compromised login/register pages)
            if let Some(url) = doc_item.get("url").and_then(|v| v.as_str())
                && url.starts_with("http")
                && seen_urls.insert(url.to_string())
            {
                let mut e = Entity::new(EntityKind::Url, url, 0.45, &sid);
                e.tag("stealer-target");
                e.tag("import");
                entities.push(e);
                stats.urls += 1;
            }

            // Usernames (identity pivots)
            if let Some(username) = doc_item.get("username").and_then(|v| v.as_str())
                && !username.is_empty()
                && username.len() >= 3
                && seen_users.insert(username.to_lowercase())
            {
                let conf = if username.contains('@') { 0.55 } else { 0.40 };
                let kind = if username.contains('@') {
                    EntityKind::Email
                } else {
                    EntityKind::Username
                };
                let mut e = Entity::new(kind, username, conf, &sid);
                e.tag("stealer-username");
                e.tag("import");
                entities.push(e);
                stats.usernames += 1;
            }

            // Log IDs (unique infected machines) → DeviceId entities
            if let Some(lid) = doc_item.get("log_id").and_then(|v| v.as_str())
                && log_ids.insert(lid.to_string())
            {
                let mut e = Entity::new(EntityKind::DeviceId, lid, 0.50, &sid);
                e.tag("log-id");
                e.tag("import");
                entities.push(e);
            }

            // Paths (login/admin/API endpoints)
            if let Some(paths) = doc_item.get("path").and_then(|v| v.as_array()) {
                for p in paths {
                    if let Some(path) = p.as_str() {
                        let pl = path.to_lowercase();
                        if (pl.contains("admin")
                            || pl.contains("api")
                            || pl.contains("login")
                            || pl.contains("dashboard")
                            || pl.contains("panel"))
                            && seen_urls.insert(format!("path:{path}"))
                            && let Some(doms) = doc_item.get("domain").and_then(|v| v.as_array())
                            && let Some(dom) = doms.first().and_then(|d| d.as_str())
                        {
                            let full_url = format!("https://{dom}{path}");
                            let mut e = Entity::new(EntityKind::Url, &full_url, 0.50, &sid);
                            e.tag("admin-panel");
                            e.tag("import");
                            entities.push(e);
                            stats.admin_paths += 1;
                        }
                    }
                }
            }

            // API key pattern scanning on password field
            if let Some(pw) = doc_item.get("password").and_then(|v| v.as_str())
                && !pw.is_empty()
                && pw.len() >= 16
                && let Some((svc, e)) = detect_and_create_api_key_entity(pw, &sid, "import:oathnet")
            {
                entities.push(e);
                stats.api_keys += 1;

                let valid = crate::util::key_pool::add_and_validate(
                    svc,
                    pw,
                    Some(format!("Import: {svc} key from stealer data")),
                )
                .await;
                if valid {
                    stats.api_keys_valid += 1;
                }
            }

            // Infection timeline
            if let Some(dt) = doc_item.get("pwned_at").and_then(|v| v.as_str()) {
                let date = crate::util::str_util::truncate_safe(dt, 10);
                if earliest_date.as_deref().is_none_or(|e| date < e) {
                    earliest_date = Some(date.to_string());
                }
                if latest_date.as_deref().is_none_or(|l| date > l) {
                    latest_date = Some(date.to_string());
                }
            }
        }

        stats.machines = log_ids.len();
        stats.date_range = match (earliest_date, latest_date) {
            (Some(e), Some(l)) => format!("{e} to {l}"),
            _ => String::new(),
        };
    }

    // ── Parse victim device_users (OS account names) ──
    if let Some(victims) = doc
        .pointer("/stealerData/victims")
        .and_then(|v| v.as_array())
    {
        let mut seen_device_users: std::collections::HashSet<String> =
            std::collections::HashSet::new();
        for victim in victims {
            if let Some(users) = victim.get("device_users").and_then(|v| v.as_array()) {
                for u in users.iter().take(5) {
                    if let Some(name) = u.as_str()
                        && !name.is_empty()
                        && seen_device_users.insert(name.to_lowercase())
                    {
                        let mut e = Entity::new(EntityKind::Username, name, 0.35, &sid);
                        e.tag("device-user");
                        e.tag("import");
                        entities.push(e);
                        stats.device_users += 1;
                    }
                }
            }
        }
    }

    // ── Parse IP geolocation from osintData ──
    if let Some(ip_info) = doc.pointer("/osintData/ipInfo").and_then(|v| v.as_object()) {
        for (ip, info) in ip_info {
            let city = info.get("city").and_then(|v| v.as_str()).unwrap_or("");
            let region = info
                .get("regionName")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let country = info.get("country").and_then(|v| v.as_str()).unwrap_or("");
            let lat = info.get("lat").and_then(|v| v.as_f64());
            let lon = info.get("lon").and_then(|v| v.as_f64());
            let isp = info.get("isp").and_then(|v| v.as_str()).unwrap_or("");
            create_geolocation_entities(
                &GeoFields {
                    ip,
                    lat,
                    lon,
                    city,
                    region,
                    country,
                    isp,
                },
                &sid,
                &mut entities,
                &mut stats,
            );
        }
    }

    // ── Parse Holehe platform checks ──
    if let Some(holehe) = doc.pointer("/osintData/holehe").and_then(|v| v.as_object()) {
        for (email, data) in holehe {
            if let Some(domains) = data.pointer("/data/domains").and_then(|v| v.as_array()) {
                let platforms: Vec<&str> = domains.iter().filter_map(|d| d.as_str()).collect();
                if !platforms.is_empty() && !email.contains("UPGRADE") {
                    let mut e = Entity::new(EntityKind::Email, email, 0.85, &sid);
                    e.tag("holehe-verified");
                    e.tag("import");
                    e.add_evidence(
                        Evidence::new(
                            "import:oathnet",
                            format!(
                                "Holehe: registered on {} platform(s): {}",
                                platforms.len(),
                                platforms.join(", ")
                            ),
                        )
                        .with_attr("platforms", platforms.join(", "))
                        .with_attr("platform_count", platforms.len().to_string()),
                    );
                    entities.push(e);
                    stats.holehe += 1;
                }
            }
        }
    }

    (entities, stats)
}

/// Render the OathNet-JSON import result (CLI side only): a machine-readable
/// `--output json` envelope or the human entity list.
fn import_json_output(
    entities: &[crate::core::entity::Entity],
    stats: &ImportStats,
    query: &str,
    date: &str,
    path: &str,
    output: &str,
) -> Result<()> {
    match output {
        "json" => {
            let out = serde_json::json!({
                "import": { "query": query, "date": date, "file": path },
                "stats": {
                    "entities": entities.len(),
                    "emails": stats.emails,
                    "ips": stats.ips,
                    "domains": stats.domains,
                    "coordinates": stats.coordinates,
                },
                "entities": entities,
            });
            println!("{}", serde_json::to_string_pretty(&out).unwrap_or_default());
        }
        _ => {
            for e in entities {
                println!(
                    "  [{:.2}] {:15} {}",
                    e.confidence,
                    e.kind.to_string(),
                    // `truncate_safe`, not `&value[..len.min(70)]`: an entity
                    // value is arbitrary text (a non-ASCII name/address), so a
                    // raw byte slice at 70 panics when it lands mid-codepoint.
                    crate::util::str_util::truncate_safe(&e.value, 70)
                );
            }
        }
    }

    Ok(())
}

/// Parse an OathNet HTML export into entities (domains/subdomains, IPs, emails)
/// by regex over the page text. Pure — the reusable core shared by the CLI
/// (`cmd_import_html`) and the web upload dispatcher, so the two never drift.
fn parse_oathnet_html(body: &str, sid: &str) -> Vec<crate::core::entity::Entity> {
    use crate::core::entity::{Entity, EntityKind};
    use regex::Regex;
    use std::collections::HashSet;
    use std::sync::OnceLock;

    // Compile the three extraction patterns once (codebase convention — see
    // `util::html`, `address_au`, `employer_pivot`). Regex compilation is
    // non-trivial and these are otherwise rebuilt on every import call.
    static RES: OnceLock<(Regex, Regex, Regex)> = OnceLock::new();
    let (ip_re, email_re, domain_re) = RES.get_or_init(|| {
        (
            Regex::new(r"\b(?:\d{1,3}\.){3}\d{1,3}\b").unwrap(),
            Regex::new(r"[\w.+-]+@[\w.-]+\.\w{2,}").unwrap(),
            Regex::new(r"(?:https?://)?([a-z0-9][-a-z0-9]*(?:\.[a-z0-9][-a-z0-9]*)+)").unwrap(),
        )
    });

    let mut entities: Vec<Entity> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();

    let lower = body.to_lowercase();

    for cap in domain_re.captures_iter(&lower) {
        let dom = &cap[1];
        if dom.len() > 4 && seen.insert(format!("d:{dom}")) {
            let is_sub = dom.split('.').count() >= 3;
            let conf = if is_sub { 0.45 } else { 0.50 };
            let mut e = Entity::new(EntityKind::Domain, dom, conf, sid);
            e.tag("import");
            if is_sub {
                e.tag("subdomain");
            }
            entities.push(e);
        }
    }

    for cap in ip_re.captures_iter(body) {
        let ip = cap[0].to_string();
        if seen.insert(format!("ip:{ip}"))
            && !ip.starts_with("0.")
            && !ip.starts_with("127.")
            && !ip.starts_with("255.")
        {
            let mut e = Entity::new(EntityKind::IpAddress, &ip, 0.55, sid);
            e.tag("import");
            entities.push(e);
        }
    }

    for cap in email_re.captures_iter(body) {
        let em = cap[0].to_lowercase();
        if em.len() >= 5 && seen.insert(format!("em:{em}")) {
            let mut e = Entity::new(EntityKind::Email, &em, 0.50, sid);
            e.tag("import");
            entities.push(e);
        }
    }

    entities
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

fn cmd_import_html(body: &str, output: &str) -> Result<()> {
    use crate::core::entity::EntityKind;

    note(output, "Importing OathNet HTML export...");
    let sid = format!("import-html-{}", crate::core::entity::unix_now());
    let mut entities = parse_oathnet_html(body, &sid);

    deduplicate_by_uid(&mut entities);

    let domains = entities
        .iter()
        .filter(|e| e.kind == EntityKind::Domain)
        .count();
    let ips = entities
        .iter()
        .filter(|e| e.kind == EntityKind::IpAddress)
        .count();
    let emails = entities
        .iter()
        .filter(|e| e.kind == EntityKind::Email)
        .count();

    note(
        output,
        format!(
            "Imported {} entities: {} domains, {} IPs, {} emails",
            entities.len(),
            domains,
            ips,
            emails
        ),
    );

    render_import_entities(&entities, output);
    Ok(())
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

/// Which `-> value` list a run of lines belongs to.
#[derive(PartialEq, Clone, Copy)]
enum DossierSection {
    None,
    Usernames,
    Emails,
    Passwords,
}

/// Parse a breach/dossier compilation into individualised, correlated entities.
///
/// Two structures are recognised and both preserved in full:
///   * `Entry #N:` blocks of `• key: value` fields (username/email/name/_domain/
///     id/created/updated/language/hash/birthdate/country/gender). Every field
///     in an entry is attached as evidence to *each* entity the entry yields, so
///     the email, username and person stay correlated and carry the complete,
///     verifiable record (birthdate/country/gender included) — never a fragment.
///   * `USERNAMES:` / `EMAILS:` / `PASSWORDS:` sections of `-> value` lines, the
///     aggregate identifier lists. Dedup by UID folds these into the per-entry
///     entities where they overlap.
///
/// Pure (no I/O) so it is unit-testable; `cmd_import_dossier` does the output.
fn parse_dossier(body: &str, sid: &str) -> (Vec<crate::core::entity::Entity>, ImportStats) {
    use std::collections::HashSet;

    let mut entities = Vec::new();
    let mut stats = ImportStats::default();
    let mut seen: HashSet<String> = HashSet::new();
    let mut section = DossierSection::None;
    let mut entry: Vec<(String, String)> = Vec::new();

    for raw in body.lines() {
        let line = raw.trim();
        if line.is_empty() {
            continue;
        }

        // Section header — an all-caps label ending in ':' with no value.
        if let Some(label) = line.strip_suffix(':') {
            let sect = match label.trim() {
                "USERNAMES" => Some(DossierSection::Usernames),
                "EMAILS" => Some(DossierSection::Emails),
                "PASSWORDS" | "HASHES" => Some(DossierSection::Passwords),
                _ => None,
            };
            if let Some(s) = sect {
                emit_dossier_entry(&mut entry, sid, &mut entities, &mut stats, &mut seen);
                section = s;
                continue;
            }
        }

        // `Entry #N:` header begins a fresh record.
        if line.starts_with("Entry #") {
            emit_dossier_entry(&mut entry, sid, &mut entities, &mut stats, &mut seen);
            section = DossierSection::None;
            continue;
        }

        // `-> value` list item under the current section.
        if let Some(val) = line.strip_prefix("->").map(str::trim) {
            if !val.is_empty() {
                emit_dossier_list_item(section, val, sid, &mut entities, &mut stats, &mut seen);
            }
            continue;
        }

        // `• key: value` (or bare `key: value`) field — accumulate into the entry.
        let field = line.trim_start_matches('\u{2022}').trim();
        if let Some((k, v)) = field.split_once(':') {
            let key = k.trim().trim_start_matches('_').to_ascii_lowercase();
            let val = v.trim();
            // Only accept the known field keys so a stray "http://…: x" or prose
            // colon doesn't pollute the record.
            const FIELDS: &[&str] = &[
                "username",
                "email",
                "name",
                "domain",
                "ip",
                "id",
                "created",
                "updated",
                "language",
                "hash",
                "birthdate",
                "country",
                "gender",
                "phone",
            ];
            if !val.is_empty() && FIELDS.contains(&key.as_str()) {
                entry.push((key, val.to_string()));
                continue;
            }
        }

        // A bare top-level URL (e.g. the LinkedIn profile heading the file).
        if (line.starts_with("http://") || line.starts_with("https://"))
            && seen.insert(format!("u:{line}"))
        {
            let mut e = crate::core::entity::Entity::new(
                crate::core::entity::EntityKind::Url,
                line,
                0.55,
                sid,
            );
            e.tag("import");
            e.tag("dossier");
            entities.push(e);
            stats.urls += 1;
        }
    }
    // Flush the final entry.
    emit_dossier_entry(&mut entry, sid, &mut entities, &mut stats, &mut seen);

    (entities, stats)
}

/// Emit the entities for one accumulated `Entry #N` record, attaching the FULL
/// record as evidence to each so the data stays correlated and verifiable.
fn emit_dossier_entry(
    entry: &mut Vec<(String, String)>,
    sid: &str,
    entities: &mut Vec<crate::core::entity::Entity>,
    stats: &mut ImportStats,
    seen: &mut std::collections::HashSet<String>,
) {
    use crate::core::entity::{Entity, EntityKind, Evidence};
    use crate::core::validation::is_fragment_value;
    if entry.is_empty() {
        return;
    }
    let get = |k: &str| {
        entry
            .iter()
            .find(|(kk, _)| kk == k)
            .map(|(_, v)| v.as_str())
    };
    let email = get("email");
    let username = get("username");
    let name = get("name");
    let hash = get("hash");

    // One evidence record carrying every field of the entry — cloned onto each
    // entity so the complete record (birthdate/country/gender/created/id/hash/…)
    // travels with the email, the username and the person alike.
    let label = email.or(name).or(username).unwrap_or("breach entry");
    let mut ev = Evidence::new("import:dossier", format!("Breach dossier entry — {label}"));
    for (k, v) in entry.iter() {
        // Don't echo a raw password hash into a human-readable attribute under a
        // benign name; it's surfaced as its own Credential entity below.
        if k != "hash" {
            ev = ev.with_attr(k, v);
        }
    }

    let mut push = |mut e: Entity, tag: &str| {
        e.tag("import");
        e.tag("dossier");
        e.tag(tag);
        e.add_evidence(ev.clone());
        entities.push(e);
    };

    if let Some(em) = email {
        let em = em.to_ascii_lowercase();
        if em.contains('@')
            && !is_fragment_value(&EntityKind::Email, &em)
            && seen.insert(format!("em:{em}"))
        {
            push(Entity::new(EntityKind::Email, &em, 0.72, sid), "breach");
            stats.emails += 1;
        }
    }
    if let Some(un) = username
        && un.len() >= 2
        && !un.contains('@')
        && seen.insert(format!("un:{}", un.to_lowercase()))
    {
        push(Entity::new(EntityKind::Username, un, 0.60, sid), "breach");
        stats.usernames += 1;
    }
    if let Some(nm) = name {
        // A real person name: at least two words, not a placeholder.
        if nm.split_whitespace().count() >= 2
            && !crate::core::validation::is_placeholder_entity(&EntityKind::Person, nm)
            && seen.insert(format!("pn:{}", nm.to_lowercase()))
        {
            push(Entity::new(EntityKind::Person, nm, 0.62, sid), "breach");
            stats.persons += 1;
        }
    }
    if let Some(h) = hash {
        // A password hash is an inherently-unique credential artifact (bcrypt
        // `$2a$…`, hex digests). Keep it as a Credential, never a plaintext
        // Password, and tie it to the same record.
        if h.len() >= 8 && seen.insert(format!("cr:{h}")) {
            push(
                Entity::new(EntityKind::Credential, h, 0.60, sid),
                "password-hash",
            );
            stats.credentials += 1;
        }
    }
    // A dossier entry's `ip` / `phone` / `domain` are first-class pivotable seeds,
    // not just evidence attributes — the whole point of expansion is to re-scan
    // them. The JSON importer already emits IpAddress from `ip`; the text path
    // must match, or the same breach record yields fewer leads depending only on
    // its file format. Each is validated so malformed/placeholder values
    // ("256.256.256.256", "+0…") don't become high-confidence false seeds.
    if let Some(ip) = get("ip")
        && ip.parse::<std::net::IpAddr>().is_ok()
        && !crate::core::validation::is_bogus_ip(ip)
        && seen.insert(format!("ip:{ip}"))
    {
        push(Entity::new(EntityKind::IpAddress, ip, 0.65, sid), "breach");
        stats.ips += 1;
    }
    if let Some(ph) = get("phone")
        && crate::core::validation::validate_phone_e164(ph).valid
        && seen.insert(format!("ph:{ph}"))
    {
        push(Entity::new(EntityKind::Phone, ph, 0.62, sid), "breach");
        stats.phones += 1;
    }
    // A dossier's `_domain` is usually the email's OWN host (gmail.com) —
    // freemail/mega-domains are useless pivots (deep-expanding them maps a
    // platform, not the subject), so gate them out exactly as the engine's
    // expansion does. A genuine corporate domain still becomes a seed.
    if let Some(dom) = get("domain").map(str::to_ascii_lowercase)
        && dom.contains('.')
        && !crate::util::domains::is_freemail(&dom)
        && !crate::core::scan::is_mega_domain(&dom)
        && !crate::core::validation::is_placeholder_domain(&dom)
        && !is_fragment_value(&EntityKind::Domain, &dom)
        && seen.insert(format!("dom:{dom}"))
    {
        push(Entity::new(EntityKind::Domain, &dom, 0.60, sid), "breach");
        stats.domains += 1;
    }
    entry.clear();
}

/// Emit an entity for a single `-> value` line under a `USERNAMES:`/`EMAILS:`/
/// `PASSWORDS:` section.
fn emit_dossier_list_item(
    section: DossierSection,
    val: &str,
    sid: &str,
    entities: &mut Vec<crate::core::entity::Entity>,
    stats: &mut ImportStats,
    seen: &mut std::collections::HashSet<String>,
) {
    use crate::core::entity::{Entity, EntityKind};
    use crate::core::validation::is_fragment_value;
    let mut push = |e: Entity, key: String| {
        if seen.insert(key) {
            let mut e = e;
            e.tag("import");
            e.tag("dossier");
            e.tag("dossier-list");
            entities.push(e);
            return true;
        }
        false
    };
    match section {
        DossierSection::Emails => {
            let em = val.to_ascii_lowercase();
            if em.contains('@') && !is_fragment_value(&EntityKind::Email, &em) {
                let e = Entity::new(EntityKind::Email, &em, 0.55, sid);
                if push(e, format!("em:{em}")) {
                    stats.emails += 1;
                }
            }
        }
        DossierSection::Usernames => {
            // A username list can contain bare emails too — classify by shape.
            if val.contains('@') {
                let em = val.to_ascii_lowercase();
                if !is_fragment_value(&EntityKind::Email, &em) {
                    let e = Entity::new(EntityKind::Email, &em, 0.50, sid);
                    if push(e, format!("em:{em}")) {
                        stats.emails += 1;
                    }
                }
            } else if val.len() >= 2 {
                let e = Entity::new(EntityKind::Username, val, 0.50, sid);
                if push(e, format!("un:{}", val.to_lowercase())) {
                    stats.usernames += 1;
                }
            }
        }
        DossierSection::Passwords => {
            if val.len() >= 8 {
                let e = Entity::new(EntityKind::Credential, val, 0.50, sid);
                if push(e, format!("cr:{val}")) {
                    stats.credentials += 1;
                }
            }
        }
        DossierSection::None => {}
    }
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
    } else if looks_like_dossier(body) {
        (parse_dossier(body, sid).0, "dossier")
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

fn cmd_import_dossier(body: &str, output: &str) -> Result<()> {
    note(output, "Importing breach/dossier compilation...");
    let sid = format!("import-dossier-{}", crate::core::entity::unix_now());
    let (mut entities, stats) = parse_dossier(body, &sid);
    deduplicate_by_uid(&mut entities);
    print_import_stats(&stats, entities.len(), output);

    render_import_entities(&entities, output);
    Ok(())
}

/// Parse an OathNet stealer-log TXT export into entities + stats. Reusable core
/// shared by `cmd_import_txt` and the web upload dispatcher. Discovered API keys
/// are added to the in-memory key pool (as the CLI does); persisting the pool to
/// disk is left to the caller.
fn parse_oathnet_txt(body: &str, sid: &str) -> (Vec<crate::core::entity::Entity>, ImportStats) {
    use crate::core::entity::{Entity, EntityKind};
    use std::collections::HashSet;

    // Keep the (verbatim) parse body's `&sid` working — it expects an owned id.
    let sid = sid.to_string();
    let mut entities: Vec<Entity> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();
    let mut stats = ImportStats::default();

    // ── Credential section: URLs, domains, usernames, API key scanning ──
    for line in body.lines() {
        if let Some(rest) = line.strip_prefix("URL: ") {
            let url = rest.trim();
            if url.starts_with("http") && seen.insert(format!("u:{url}")) {
                let mut e = Entity::new(EntityKind::Url, url, 0.45, &sid);
                e.tag("import");
                let pl = url.to_lowercase();
                if pl.contains("admin")
                    || pl.contains("/api")
                    || pl.contains("login")
                    || pl.contains("dashboard")
                {
                    e.tag("admin-panel");
                    stats.admin_paths += 1;
                }
                entities.push(e);
                stats.urls += 1;
                if let Some(host) = url
                    .strip_prefix("https://")
                    .or_else(|| url.strip_prefix("http://"))
                {
                    let domain = host
                        .split('/')
                        .next()
                        .unwrap_or("")
                        .split(':')
                        .next()
                        .unwrap_or("");
                    if domain.contains('.') && seen.insert(format!("d:{domain}")) {
                        let is_sub = domain.split('.').count() >= 3;
                        let mut de = Entity::new(
                            EntityKind::Domain,
                            domain,
                            if is_sub { 0.45 } else { 0.50 },
                            &sid,
                        );
                        de.tag("import");
                        if is_sub {
                            de.tag("subdomain");
                            stats.subdomains += 1;
                        } else {
                            stats.domains += 1;
                        }
                        entities.push(de);
                    }
                }
            }
        } else if let Some(rest) = line.strip_prefix("Username: ") {
            let uname = rest.trim();
            if uname.len() >= 2 && seen.insert(format!("un:{uname}")) {
                let kind = if uname.contains('@') {
                    EntityKind::Email
                } else {
                    EntityKind::Username
                };
                let mut e = Entity::new(kind, uname, 0.40, &sid);
                e.tag("import");
                e.tag("stealer-username");
                entities.push(e);
                stats.usernames += 1;
            }
        } else if let Some(rest) = line.strip_prefix("Password: ")
            && rest.trim().len() >= 16
            && let Some((svc, e)) =
                detect_and_create_api_key_entity(rest.trim(), &sid, "import:txt")
        {
            entities.push(e);
            stats.api_keys += 1;
            store_key_in_pool(svc, rest.trim(), format!("TXT import: {svc} key"));
        }
    }

    // ── Victim section: IPs, emails, HWIDs, device users ──
    // The section runs from the INFECTED marker to the next OSINT ENRICHMENT
    // marker AFTER it (or end of file). Search for the end relative to `vs`: a
    // stray OSINT marker positioned *before* the INFECTED one would otherwise
    // make `victim_end < vs`, and `&body[vs..victim_end]` would panic
    // (start > end) on a crafted import file — the CLI path has no catch_unwind.
    if let Some(vs) = body.find("=== INFECTED MACHINES") {
        let victim_end = body[vs..]
            .find("=== OSINT ENRICHMENT")
            .map_or(body.len(), |rel| vs + rel);
        let victim_section = &body[vs..victim_end];
        for line in victim_section.lines() {
            if let Some(rest) = line.strip_prefix("IPs: ") {
                for ip in rest.split(", ") {
                    let ip = ip.trim();
                    if ip.contains('.') && !ip.starts_with("0.") && seen.insert(format!("ip:{ip}"))
                    {
                        let mut e = Entity::new(EntityKind::IpAddress, ip, 0.60, &sid);
                        e.tag("stealer-victim");
                        e.tag("import");
                        entities.push(e);
                        stats.ips += 1;
                    }
                }
            } else if let Some(rest) = line.strip_prefix("Device Emails: ") {
                for em in rest.split(", ") {
                    let em = em.trim().to_lowercase();
                    if em.contains('@') && em.len() >= 5 && seen.insert(format!("em:{em}")) {
                        let mut e = Entity::new(EntityKind::Email, &em, 0.55, &sid);
                        e.tag("stealer-victim");
                        e.tag("import");
                        entities.push(e);
                        stats.emails += 1;
                    }
                }
            } else if let Some(rest) = line.strip_prefix("HWIDs: ") {
                for hwid in rest.split(", ") {
                    let hwid = hwid.trim();
                    if !hwid.is_empty() && seen.insert(format!("hw:{hwid}")) {
                        let mut e = Entity::new(EntityKind::DeviceId, hwid, 0.70, &sid);
                        e.tag("hwid");
                        e.tag("import");
                        entities.push(e);
                        stats.hwids += 1;
                    }
                }
            } else if let Some(rest) = line.strip_prefix("Users: ") {
                for user in rest.split(", ") {
                    let user = user.trim();
                    if !user.is_empty() && seen.insert(format!("du:{user}")) {
                        let mut e = Entity::new(EntityKind::Username, user, 0.35, &sid);
                        e.tag("device-user");
                        e.tag("import");
                        entities.push(e);
                        stats.device_users += 1;
                    }
                }
            } else if let Some(rest) = line.strip_prefix("Log ID: ") {
                let lid = rest.trim();
                if !lid.is_empty() && seen.insert(format!("lid:{lid}")) {
                    let mut e = Entity::new(EntityKind::DeviceId, lid, 0.50, &sid);
                    e.tag("log-id");
                    e.tag("import");
                    entities.push(e);
                    stats.machines += 1;
                }
            } else if let Some(rest) = line.strip_prefix("Discord IDs: ") {
                for did in rest.split(", ") {
                    let did = did.trim();
                    if !did.is_empty() && seen.insert(format!("dc:{did}")) {
                        let mut e = Entity::new(EntityKind::Username, did, 0.60, &sid);
                        e.tag("discord-id");
                        e.tag("import");
                        entities.push(e);
                        stats.discord_ids += 1;
                    }
                }
            }
        }
    }

    // ── OSINT section: IP geolocation ──
    let osint_start = body.find("=== OSINT ENRICHMENT");
    if let Some(os) = osint_start {
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
                        &sid,
                        &mut entities,
                        &mut stats,
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
                &sid,
                &mut entities,
                &mut stats,
            );
        }
    }

    (entities, stats)
}

fn cmd_import_txt(body: &str, output: &str) -> Result<()> {
    note(output, "Importing OathNet TXT export...");
    let sid = format!("import-txt-{}", crate::core::entity::unix_now());
    let (mut entities, stats) = parse_oathnet_txt(body, &sid);

    deduplicate_by_uid(&mut entities);
    print_import_stats(&stats, entities.len(), output);
    if stats.api_keys > 0 {
        note(
            output,
            format!("  Pool:      {} keys stored for automatic use", stats.api_keys),
        );
        crate::util::key_pool::save_pool_best_effort(&crate::util::key_pool::global_pool());
    }

    render_import_entities(&entities, output);
    Ok(())
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
        if e.kind == crate::core::entity::EntityKind::IpAddress {
            !crate::core::validation::is_bogus_ip(&e.value)
        } else if e.kind == crate::core::entity::EntityKind::Domain {
            e.value.parse::<std::net::IpAddr>().is_err()
        } else {
            true
        }
    });
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    entities.retain(|e| seen.insert(e.uid.clone()));
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

fn store_key_in_pool(service: &str, key: &str, notes: String) {
    let pool = crate::util::key_pool::global_pool();
    let mut entry = crate::util::key_pool::KeyEntry::new(key);
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
        "  Identity:  {} emails, {} phones, {} usernames, {} persons, {} device users, {} Discord IDs",
        stats.emails, stats.phones, stats.usernames, stats.persons, stats.device_users, stats.discord_ids
    );
    if stats.credentials > 0 {
        row!("  Creds:     {} password hashes", stats.credentials);
    }
    row!(
        "  Network:   {} IPs, {} domains, {} subdomains, {} URLs, {} admin paths",
        stats.ips, stats.domains, stats.subdomains, stats.urls, stats.admin_paths
    );
    row!(
        "  Geo:       {} coordinates, {} addresses",
        stats.coordinates, stats.addresses
    );
    row!(
        "  Device:    {} HWIDs, {} machine log IDs",
        stats.hwids, stats.machines
    );
    row!("  Keys:      {} API keys detected", stats.api_keys);
    row!("  Verified:  {} holehe platform checks", stats.holehe);
    row!(
        "  Source:    {} breach, {} stealer docs, {} victims",
        stats.breach_records, stats.stealer_docs, stats.victim_records
    );
    if !stats.date_range.is_empty() {
        row!("  Timeline:  {}", stats.date_range);
    }
    if stats.api_keys > 0 {
        row!(
            "  Pool:      {} API keys detected, {} validated active",
            stats.api_keys, stats.api_keys_valid
        );
    }
}

#[cfg(test)]
mod tests {
    use super::{deduplicate_by_uid, entities_from_upload, looks_like_dossier, parse_dossier};

    /// The upload dispatcher parses UNTRUSTED text from the web endpoint, so it
    /// must never panic — not on truncation, not on a multibyte codepoint landing
    /// next to a structural marker (`@`, `->`, `•`, `:`, a section header), not on
    /// malformed JSON/HTML. This pins that contract: every hostile input returns
    /// Ok/Err, never unwinds. (Panic = abort is off, but a 500 from a paste is
    /// still a defect.)
    #[tokio::test]
    async fn upload_dispatcher_never_panics_on_adversarial_input() {
        let bomb = "é".repeat(4000); // multibyte filler
        let cases: Vec<String> = vec![
            String::new(),
            " \t\n ".into(),
            "@".into(),
            "->".into(),
            "\u{2022}".into(),                                   // lone bullet
            "Entry #".into(),                                    // truncated header
            "Entry #\u{2022}:é".into(),                          // bullet+multibyte at header
            format!("Entry #1:\n   \u{2022} email: {bomb}@"),    // dangling local@
            format!("EMAILS:\n  -> {bomb}@{bomb}"),              // huge no-TLD email
            "USERNAMES:\n->".into(),                             // empty list item
            "\u{2022} : value".into(),                           // empty key
            "URL: \nUsername: \nPassword: ".into(),              // empty TXT fields
            "=== INFECTED MACHINES".into(),                      // section marker, no body
            "=== OSINT ENRICHMENT\nIP: \nlat: zzz\nlon: ".into(),// bad geo numbers
            "{".into(),                                          // truncated JSON
            "{}".into(),
            r#"{"searchResults":{"MULTI_SERVICE_RESULTS":{"breach":{"data":{"results":[null,1,"x"]}}}}}"#.into(),
            r#"{"stealerData":{"victims":[{"device_ips":[1,null,"1.2.3.4"]}]}}"#.into(),
            "<html>".into(),
            format!("<html>{bomb}@{bomb}.com http://{bomb}</html>"),
            // Section markers butted against multibyte text.
            format!("PASSWORDS:é\n-> é{bomb}"),
            "Entry #1:\n   \u{2022} name: é\n   \u{2022} hash: $2a$".into(),
        ];
        for (i, input) in cases.iter().enumerate() {
            // The await completing at all is the assertion — a panic would unwind
            // through here and fail the test.
            let r = entities_from_upload(input, "fuzz").await;
            // Whatever the outcome, entities (if any) must be well-formed.
            if let Ok((ents, _)) = r {
                for e in &ents {
                    assert!(
                        !e.value.is_empty(),
                        "case {i}: produced an empty-value entity"
                    );
                }
            }
        }
    }

    #[tokio::test]
    async fn upload_dispatcher_routes_every_format_to_its_parser() {
        use crate::core::entity::EntityKind;
        let has = |ents: &[crate::core::entity::Entity], k: EntityKind, v: &str| {
            ents.iter().any(|e| e.kind == k && e.value == v)
        };

        // HTML export → regex extraction of domains/emails/IPs.
        let (html, label) = entities_from_upload(
            "<html><body>contact me at jo@acme-corp.com on acme-corp.com</body></html>",
            "s",
        )
        .await
        .unwrap();
        assert_eq!(label, "oathnet-html");
        assert!(has(&html, EntityKind::Email, "jo@acme-corp.com"));

        // Dossier compilation → per-entry correlation.
        let (dos, label) = entities_from_upload(
            "Entry #1:\n   \u{2022} email: isaacfrost@gmail.com\n   \u{2022} name: Isaac Frost\n",
            "s",
        )
        .await
        .unwrap();
        assert_eq!(label, "dossier");
        assert!(has(&dos, EntityKind::Email, "isaacfrost@gmail.com"));
        assert!(has(&dos, EntityKind::Person, "Isaac Frost"));

        // OathNet stealer-log TXT → the catch-all text branch.
        let (txt, label) = entities_from_upload(
            "URL: https://admin.target.io/login\nUsername: victim\n",
            "s",
        )
        .await
        .unwrap();
        assert_eq!(label, "oathnet-txt");
        assert!(txt.iter().any(|e| e.kind == EntityKind::Url));

        // JSON API export → parsed (and the label proves the branch).
        let (_json, label) =
            entities_from_upload(r#"{"exportInfo":{"query":"x"},"searchResults":{}}"#, "s")
                .await
                .unwrap();
        assert_eq!(label, "oathnet-json");

        // Malformed JSON is a clean error, not a panic.
        assert!(entities_from_upload("{ not valid json", "s").await.is_err());
    }
    use crate::core::entity::{Entity, EntityKind};

    // The exact shape of the user-provided "Isaac Frost.txt" dossier upload.
    const DOSSIER: &str = "http://www.linkedin.com/in/isaac-frost-42474a122
    Entry #82:
       \u{2022} username: zacfrost512
       \u{2022} email: zacfrost512@gmail.com
       \u{2022} name: Isaac Frost
       \u{2022} _domain: gmail.com
       \u{2022} ip: 8.8.8.8
       \u{2022} phone: +61412345678
       \u{2022} id: 9540629
       \u{2022} created: 2016-02-19 15:57:12
       \u{2022} language: en
    Entry #85:
       \u{2022} username: IsaacFrost6
       \u{2022} email: frostisms@gmail.com
       \u{2022} name: Isaac Frost
       \u{2022} domain: derbyrock.com
       \u{2022} ip: 203.0.113.45
       \u{2022} birthdate: 2002-11-17
       \u{2022} country: GB
       \u{2022} gender: M
       \u{2022} hash: $2a$10$id3HAw6TcOjKvPH/RK7MS.
USERNAMES:
  -> isaac frost
  -> a_frost_life
  -> isaac@derbyrock.com
EMAILS:
  -> betocastillo097@gmail.com
  -> @gmail
PASSWORDS:
  -> 00346D91DD87C74089F3BFA88E13DE8101000000DCB6
";

    #[test]
    fn dossier_is_detected_and_oathnet_txt_is_not() {
        assert!(looks_like_dossier(DOSSIER));
        assert!(!looks_like_dossier(
            "URL: https://x.com/login\nUsername: bob\nPassword: hunter2\n"
        ));
    }

    #[test]
    fn dossier_parse_yields_correlated_individualised_entities() {
        let (mut ents, stats) = parse_dossier(DOSSIER, "sid");
        deduplicate_by_uid(&mut ents);
        let has = |k: EntityKind, v: &str| ents.iter().any(|e| e.kind == k && e.value == v);

        // Entry-derived identity, fully parsed (not fragments).
        assert!(has(EntityKind::Email, "zacfrost512@gmail.com"));
        assert!(has(EntityKind::Username, "zacfrost512"));
        assert!(has(EntityKind::Person, "Isaac Frost"));
        assert!(has(
            EntityKind::Url,
            "http://www.linkedin.com/in/isaac-frost-42474a122"
        ));
        // Password hash is a Credential, never a Password.
        assert!(has(EntityKind::Credential, "$2a$10$id3HAw6TcOjKvPH/RK7MS."));
        assert!(!ents.iter().any(|e| e.kind == EntityKind::Password));

        // Section lists folded in; an email appears in the USERNAMES list too.
        assert!(has(EntityKind::Email, "betocastillo097@gmail.com"));
        assert!(has(EntityKind::Email, "isaac@derbyrock.com"));
        assert!(has(EntityKind::Username, "a_frost_life"));

        // The `@gmail` fragment is rejected, never surfaced.
        assert!(!ents.iter().any(|e| e.value == "@gmail"));
        // The freemail `_domain` is NOT emitted as a bare Domain entity.
        assert!(!has(EntityKind::Domain, "gmail.com"));

        // `ip`/`phone`/`domain` entry fields are first-class pivotable seeds — the
        // text path now matches the JSON importer's coverage. Each is validated:
        // a routable IP, a corporate domain and an E.164 phone are kept…
        assert!(has(EntityKind::IpAddress, "8.8.8.8"));
        assert!(has(EntityKind::Phone, "+61412345678"));
        assert!(has(EntityKind::Domain, "derbyrock.com"));
        // …while a documentation-range IP (RFC 5737) is rejected as bogus, never
        // becoming a high-confidence false seed.
        assert!(!has(EntityKind::IpAddress, "203.0.113.45"));

        // Individualised: the per-entry evidence carries the FULL record, so
        // birthdate/country/gender are verifiable on the finding, not lost.
        let frost = ents
            .iter()
            .find(|e| e.kind == EntityKind::Email && e.value == "frostisms@gmail.com")
            .expect("entry #85 email");
        let attrs = &frost.evidence[0].attributes;
        assert_eq!(
            attrs.get("birthdate").map(String::as_str),
            Some("2002-11-17")
        );
        assert_eq!(attrs.get("country").map(String::as_str), Some("GB"));
        assert_eq!(attrs.get("gender").map(String::as_str), Some("M"));
        assert_eq!(attrs.get("name").map(String::as_str), Some("Isaac Frost"));
        // The hash is NOT echoed into a benign attribute.
        assert!(!attrs.contains_key("hash"));

        // The PASSWORDS: section's `-> <hex hash>` becomes a Credential too — a
        // major part of the real file, distinct from the per-entry `hash:` field.
        assert!(
            has(
                EntityKind::Credential,
                "00346D91DD87C74089F3BFA88E13DE8101000000DCB6"
            ),
            "a PASSWORDS-section hex hash must be parsed as a Credential"
        );

        // Two distinct credentials: the entry's bcrypt hash + the PASSWORDS hex.
        assert!(stats.persons >= 1 && stats.credentials >= 2 && stats.emails >= 3);
    }

    #[test]
    fn finalize_drops_bogus_ips_keeps_real_and_private_and_dedups() {
        let sid = "import-test";
        let mut v = vec![
            Entity::new(EntityKind::IpAddress, "192.0.2.1", 0.6, sid), // doc -> drop
            Entity::new(EntityKind::IpAddress, "203.0.113.9", 0.6, sid), // doc -> drop
            Entity::new(EntityKind::IpAddress, "240.0.0.1", 0.6, sid), // reserved -> drop
            Entity::new(EntityKind::IpAddress, "8.8.8.8", 0.6, sid),   // real -> keep
            Entity::new(EntityKind::IpAddress, "192.168.1.5", 0.6, sid), // private -> keep
            Entity::new(EntityKind::IpAddress, "8.8.8.8", 0.6, sid),   // dup -> deduped
            Entity::new(EntityKind::Email, "x@b.com", 0.6, sid),       // non-IP untouched
        ];
        deduplicate_by_uid(&mut v);
        let vals: Vec<&str> = v.iter().map(|e| e.value.as_str()).collect();

        for bogus in ["192.0.2.1", "203.0.113.9", "240.0.0.1"] {
            assert!(
                !vals.contains(&bogus),
                "bogus {bogus} must be dropped: {vals:?}"
            );
        }
        assert_eq!(
            vals.iter().filter(|x| **x == "8.8.8.8").count(),
            1,
            "real IP kept exactly once (deduped)"
        );
        assert!(vals.contains(&"192.168.1.5"), "private IP kept");
        assert!(vals.contains(&"x@b.com"), "non-IP entity untouched");
    }

    #[test]
    fn finalize_drops_ip_literals_mis_classified_as_domains() {
        let sid = "import-test";
        let mut v = vec![
            Entity::new(EntityKind::Domain, "8.8.8.8", 0.45, sid), // IP-as-domain -> drop
            Entity::new(EntityKind::Domain, "192.0.2.1", 0.45, sid), // doc-IP-as-domain -> drop
            Entity::new(EntityKind::Domain, "evil.com", 0.50, sid), // real domain -> keep
            Entity::new(EntityKind::Domain, "sub.evil.com", 0.45, sid), // real subdomain -> keep
        ];
        deduplicate_by_uid(&mut v);
        let vals: Vec<&str> = v.iter().map(|e| e.value.as_str()).collect();
        assert!(
            !vals.contains(&"8.8.8.8"),
            "IP literal must not be a domain: {vals:?}"
        );
        assert!(
            !vals.contains(&"192.0.2.1"),
            "doc-IP literal must not be a domain"
        );
        assert!(vals.contains(&"evil.com"), "real domain kept");
        assert!(vals.contains(&"sub.evil.com"), "real subdomain kept");
    }

    #[test]
    fn import_txt_survives_misordered_section_markers() {
        // Regression: a crafted TXT export with the OSINT ENRICHMENT marker
        // BEFORE the INFECTED MACHINES marker used to panic
        // (`&body[vs..victim_end]` with start > end), aborting `hse import` —
        // the CLI path has no catch_unwind. The end marker is now sought after
        // the start, so the slice is always well-formed.
        let body = "=== OSINT ENRICHMENT ===\nstuff\n=== INFECTED MACHINES ===\nIPs: 8.8.8.8\n";
        assert!(
            super::cmd_import_txt(body, "table").is_ok(),
            "misordered section markers must not panic the importer"
        );
    }

    #[test]
    fn import_txt_parses_victim_section_in_normal_order() {
        // Happy path unaffected: INFECTED before OSINT still parses cleanly.
        let body = "=== INFECTED MACHINES ===\nIPs: 8.8.8.8\n=== OSINT ENRICHMENT ===\nMore: x\n";
        assert!(super::cmd_import_txt(body, "table").is_ok());
    }
}
