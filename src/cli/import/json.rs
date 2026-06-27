//! Parser for the OathNet JSON API export import format. Shared helpers (ImportStats,
//! persistence, geo/key construction) live in `super` and are reached via
//! `use super::*`.

use super::*;

/// Parse an OathNet JSON API export (breach results, stealer victims, stealer
/// docs, holehe checks, geo) into entities + stats. `async` because it
/// opportunistically validates any API key found in stealer data. Reusable core
/// shared by the CLI (`cmd_import`) and the web upload dispatcher, so they never
/// drift.
pub(super) async fn parse_oathnet_json(
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
                .and_then(serde_json::Value::as_u64)
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
                    Some("import:oathnet".to_string()),
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
            let lat = info.get("lat").and_then(serde_json::Value::as_f64);
            let lon = info.get("lon").and_then(serde_json::Value::as_f64);
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
pub(super) fn import_json_output(
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
