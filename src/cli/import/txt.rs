//! Parser for the OathNet stealer-log TXT export import format. Shared helpers (ImportStats,
//! persistence, geo/key construction) live in `super` and are reached via
//! `use super::*`.

use super::*;

/// Parse an OathNet stealer-log TXT export into entities + stats. Reusable core
/// shared by `cmd_import_txt` and the web upload dispatcher. Discovered API keys
/// are added to the in-memory key pool (as the CLI does); persisting the pool to
/// disk is left to the caller.
pub(super) fn parse_oathnet_txt(
    body: &str,
    sid: &str,
) -> (Vec<crate::core::entity::Entity>, ImportStats) {
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
                    // Parse so an IPv6 victim address is kept too — the old
                    // `contains('.')` gate silently dropped EVERY IPv6 address. A
                    // victim's private LAN IP is legitimate stealer data, so this
                    // does NOT impose public-only; it only skips the "no address"
                    // junk the log emits (the `0.x` / `::` unspecified forms).
                    let keep = match ip.parse::<std::net::IpAddr>() {
                        Ok(std::net::IpAddr::V4(v4)) => v4.octets()[0] != 0,
                        Ok(std::net::IpAddr::V6(v6)) => !v6.is_unspecified(),
                        Err(_) => false,
                    };
                    if keep && seen.insert(format!("ip:{ip}")) {
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

    // A stealer log's network section often lists the victim's router BSSID —
    // pull every MAC out as a geolocation seed (mylnikov / wigle) — and any
    // crypto wallet the log captured as a chain-analysis seed.
    push_macs(body, &sid, "stealer", &mut entities);
    push_crypto(body, &sid, "stealer", &mut entities);
    // Leaked API keys/tokens anywhere in the log, not just `service: key` lines.
    push_api_keys(body, &sid, "stealer", &mut entities);
    push_ibans(body, &sid, "stealer", &mut entities);
    // A unique WiFi SSID from the log's network section → WiGLE geolocation.
    push_ssids(body, &sid, "stealer", &mut entities);
    (entities, stats)
}

pub(super) async fn cmd_import_txt(body: &str, output: &str) -> Result<()> {
    note(output, "Importing OathNet TXT export...");
    let sid = format!("import-txt-{}", crate::core::entity::unix_now());
    let (mut entities, stats) = parse_oathnet_txt(body, &sid);

    deduplicate_by_uid(&mut entities);
    print_import_stats(&stats, entities.len(), output);
    if stats.api_keys > 0 {
        note(
            output,
            format!(
                "  Pool:      {} keys stored for automatic use",
                stats.api_keys
            ),
        );
        crate::util::key_pool::save_pool_best_effort(&crate::util::key_pool::global_pool());
    }

    persist_and_report(&sid, &entities, output).await;
    render_import_entities(&entities, output);
    Ok(())
}
