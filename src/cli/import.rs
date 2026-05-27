use crate::core::error::{Error, Result};

pub(super) async fn cmd_import(path: &str, output: &str) -> Result<()> {
    use crate::core::entity::{Entity, EntityKind, Evidence};

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

    println!("Importing OathNet JSON export: query=\"{query}\", date={date}");

    let sid = format!("import-{}", &crate::core::entity::unix_now().to_string());
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
                let date = &dt[..dt.len().min(10)];
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

    deduplicate_by_uid(&mut entities);
    print_import_stats(&stats, entities.len());

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
            for e in &entities {
                println!(
                    "  [{:.2}] {:15} {}",
                    e.confidence,
                    e.kind.to_string(),
                    &e.value[..e.value.len().min(70)]
                );
            }
        }
    }

    Ok(())
}

fn cmd_import_html(body: &str, output: &str) -> Result<()> {
    use crate::core::entity::{Entity, EntityKind};
    use std::collections::HashSet;

    println!("Importing OathNet HTML export...");
    let sid = format!("import-html-{}", crate::core::entity::unix_now());
    let mut entities: Vec<Entity> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();

    let ip_re = regex::Regex::new(r"\b(?:\d{1,3}\.){3}\d{1,3}\b").unwrap();
    let email_re = regex::Regex::new(r"[\w.+-]+@[\w.-]+\.\w{2,}").unwrap();
    let domain_re =
        regex::Regex::new(r"(?:https?://)?([a-z0-9][-a-z0-9]*(?:\.[a-z0-9][-a-z0-9]*)+)").unwrap();

    let lower = body.to_lowercase();

    for cap in domain_re.captures_iter(&lower) {
        let dom = &cap[1];
        if dom.len() > 4 && seen.insert(format!("d:{dom}")) {
            let parts: Vec<&str> = dom.split('.').collect();
            let is_sub = parts.len() >= 3;
            let conf = if is_sub { 0.45 } else { 0.50 };
            let mut e = Entity::new(EntityKind::Domain, dom, conf, &sid);
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
            let mut e = Entity::new(EntityKind::IpAddress, &ip, 0.55, &sid);
            e.tag("import");
            entities.push(e);
        }
    }

    for cap in email_re.captures_iter(body) {
        let em = cap[0].to_lowercase();
        if em.len() >= 5 && seen.insert(format!("em:{em}")) {
            let mut e = Entity::new(EntityKind::Email, &em, 0.50, &sid);
            e.tag("import");
            entities.push(e);
        }
    }

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

    println!(
        "Imported {} entities: {} domains, {} IPs, {} emails",
        entities.len(),
        domains,
        ips,
        emails
    );

    if output == "json" {
        let out = serde_json::json!({ "entities": entities });
        println!("{}", serde_json::to_string_pretty(&out).unwrap_or_default());
    } else {
        for e in &entities {
            println!(
                "  [{:.2}] {:15} {}",
                e.confidence,
                e.kind.to_string(),
                &e.value[..e.value.len().min(70)]
            );
        }
    }
    Ok(())
}

fn cmd_import_txt(body: &str, output: &str) -> Result<()> {
    use crate::core::entity::{Entity, EntityKind};
    use std::collections::HashSet;

    println!("Importing OathNet TXT export...");
    let sid = format!("import-txt-{}", crate::core::entity::unix_now());
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
                        let parts: Vec<&str> = domain.split('.').collect();
                        let is_sub = parts.len() >= 3;
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
    let victim_start = body.find("=== INFECTED MACHINES");
    let victim_end = body.find("=== OSINT ENRICHMENT").unwrap_or(body.len());
    if let Some(vs) = victim_start {
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

    deduplicate_by_uid(&mut entities);
    print_import_stats(&stats, entities.len());
    if stats.api_keys > 0 {
        println!(
            "  Pool:      {} keys stored for automatic use",
            stats.api_keys
        );
        let _ = crate::util::key_pool::save_pool(&crate::util::key_pool::global_pool());
    }

    if output == "json" {
        let out = serde_json::json!({ "entities": entities });
        println!("{}", serde_json::to_string_pretty(&out).unwrap_or_default());
    } else {
        for e in entities.iter().take(50) {
            println!(
                "  [{:.2}] {:15} {}",
                e.confidence,
                e.kind.to_string(),
                &e.value[..e.value.len().min(70)]
            );
        }
        if entities.len() > 50 {
            println!("  ... and {} more", entities.len() - 50);
        }
    }
    Ok(())
}

#[derive(Default)]
struct ImportStats {
    breach_records: usize,
    stealer_docs: usize,
    victim_records: usize,
    emails: usize,
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
    date_range: String,
}

fn deduplicate_by_uid(entities: &mut Vec<crate::core::entity::Entity>) {
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

fn print_import_stats(stats: &ImportStats, entity_count: usize) {
    println!("Imported {} entities:", entity_count);
    println!(
        "  Identity:  {} emails, {} usernames, {} device users, {} Discord IDs",
        stats.emails, stats.usernames, stats.device_users, stats.discord_ids
    );
    println!(
        "  Network:   {} IPs, {} domains, {} subdomains, {} URLs, {} admin paths",
        stats.ips, stats.domains, stats.subdomains, stats.urls, stats.admin_paths
    );
    println!(
        "  Geo:       {} coordinates, {} addresses",
        stats.coordinates, stats.addresses
    );
    println!(
        "  Device:    {} HWIDs, {} machine log IDs",
        stats.hwids, stats.machines
    );
    println!("  Keys:      {} API keys detected", stats.api_keys);
    println!("  Verified:  {} holehe platform checks", stats.holehe);
    println!(
        "  Source:    {} breach, {} stealer docs, {} victims",
        stats.breach_records, stats.stealer_docs, stats.victim_records
    );
    if !stats.date_range.is_empty() {
        println!("  Timeline:  {}", stats.date_range);
    }
    if stats.api_keys > 0 {
        println!(
            "  Pool:      {} API keys detected, {} validated active",
            stats.api_keys, stats.api_keys_valid
        );
    }
}
