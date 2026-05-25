//! OathNet Pro — full-spectrum breach, stealer, OSINT, and intelligence API.
//!
//! Uses the shared `util::oathnet` client for API calls. This module
//! orchestrates the search→extract→enrich pipeline and produces entities.

use std::collections::HashSet;

use async_trait::async_trait;
use serde_json::Value;

use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::{Module, ModuleContext, ModuleCost, ModuleResult},
    scan::{Target, TargetKind},
    tags,
};
use crate::util::oathnet::{self, paths, val_str, val_str_or};

pub struct OathnetPro;

#[async_trait]
impl Module for OathnetPro {
    fn name(&self) -> &'static str {
        "oathnet_pro"
    }

    fn description(&self) -> &'static str {
        "Full-spectrum breach, stealer & OSINT intelligence via OathNet API"
    }

    fn priority(&self) -> u8 {
        128
    }

    fn cost(&self) -> ModuleCost {
        ModuleCost::Paid
    }

    fn accepts(&self, t: &Target) -> bool {
        matches!(
            t.kind,
            TargetKind::Email
                | TargetKind::Username
                | TargetKind::Phone
                | TargetKind::IpAddress
                | TargetKind::Domain
        )
    }

    fn max_timeout_ms(&self) -> u64 {
        30_000
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let key = oathnet::resolve_key(ctx.key_opt(oathnet::KEY_ENV));

        let mut result = ModuleResult::new();
        let mut seen: HashSet<String> = HashSet::new();
        seen.insert(target.value.to_lowercase());

        let field = match target.kind {
            TargetKind::Email => "email",
            TargetKind::Username => "username",
            TargetKind::Phone => "phone",
            TargetKind::IpAddress => "ip",
            TargetKind::Domain => "domain",
            _ => return Ok(result),
        };

        // ── Breach search ───────────────────────────────────────────
        let items = oathnet::search(key, paths::BREACH, field, &target.value, 50).await?;
        if items.is_empty() {
            return Ok(result);
        }

        let total = items.len();
        let top_dbs = oathnet::top_dbnames(&items, 5);

        let mut parent = target.to_entity(0.85, &ctx.scan_id);
        parent.tag(tags::BREACH);
        parent.tag("oathnet-pro");
        let mut ev = Evidence::new(
            "oathnet_pro",
            format!("OathNet: {total} breach record(s) — {}", top_dbs.join(", ")),
        )
        .with_attr("hits", total.to_string())
        .with_attr("top_dbnames", top_dbs.join(", "));

        for item in &items {
            if let Some(c) = val_str(item, "country") {
                ev = ev.with_attr("country", &c);
            }
            if let Some(n) = val_str(item, "full_name") {
                ev = ev.with_attr("full_name", &n);
            }
            if let Some(g) = val_str(item, "gender") {
                ev = ev.with_attr("gender", &g);
            }
            if let Some(dob) = val_str(item, "date_birth") {
                ev = ev.with_attr("date_of_birth", &dob);
            }
            if item.get("country").is_some() || item.get("full_name").is_some() {
                break;
            }
        }
        parent.add_evidence(ev);
        result.push(parent);

        for item in &items {
            extract_breach_entities(item, &target.value, &ctx.scan_id, &mut seen, &mut result);
            store_api_credential(item);
        }

        // ── Stealer search ──────────────────────────────────────────
        if !ctx.cancel.is_cancelled()
            && let Ok(stealer_items) =
                oathnet::search(key, paths::STEALER, field, &target.value, 50).await
        {
            for item in &stealer_items {
                extract_stealer_entities(item, &ctx.scan_id, &mut seen, &mut result);
                store_api_credential(item);
            }
        }

        // ── Holehe (email targets) ──────────────────────────────────
        if target.kind == TargetKind::Email
            && !ctx.cancel.is_cancelled()
            && let Ok(holehe) = oathnet::osint(key, paths::HOLEHE, "email", &target.value).await
        {
            extract_holehe(holehe, &target.value, &ctx.scan_id, &mut result);
        }

        // ── Targeted API credential harvest ─────────────────────────
        // Query stealer endpoint for known API service domains to find
        // credentials that can be stored for future module use.
        if !ctx.cancel.is_cancelled() {
            harvest_api_credentials_from_stealer(key).await;
        }

        // ── IP info for discovered IPs ──────────────────────────────
        if !ctx.cancel.is_cancelled() {
            let ips: Vec<String> = result
                .entities
                .iter()
                .filter(|e| e.kind == EntityKind::IpAddress)
                .map(|e| e.value.clone())
                .collect();
            for ip in ips.iter().take(3) {
                if ctx.cancel.is_cancelled() {
                    break;
                }
                if let Ok(info) = oathnet::osint(key, paths::IP_INFO, "ip", ip).await {
                    extract_ip_info(info, ip, &ctx.scan_id, &mut result);
                }
            }
        }

        Ok(result)
    }
}

// ─── Entity extraction ─────────────────────────────────────────────────────

fn breach_evidence(item: &Value) -> Evidence {
    let db = val_str(item, "dbname").unwrap_or_else(|| "unknown".to_string());
    let mut ev = Evidence::new("oathnet_pro", format!("Breach on {db}")).with_attr("dbname", &db);
    for (field, attr) in [
        ("country", "country"),
        ("gender", "gender"),
        ("date_birth", "date_of_birth"),
        ("created_at", "account_created"),
        ("language", "language"),
        ("account_id", "account_id"),
        ("password", "password"),
        ("password_hash", "password_hash"),
        ("salt", "salt"),
        ("ip", "ip"),
        ("city", "city"),
        ("state", "state"),
        ("postal_code", "postal_code"),
        ("bio", "bio"),
        ("location", "location"),
        ("discordid", "discord_id"),
        ("instagram", "instagram"),
        ("linkedin", "linkedin"),
        ("iban", "iban"),
    ] {
        if let Some(v) = val_str(item, field) {
            ev = ev.with_attr(attr, &v);
        }
    }
    if let Some(age) = item.get("age") {
        let s = if age.is_number() {
            age.to_string()
        } else {
            age.as_str().unwrap_or("").to_string()
        };
        if !s.is_empty() {
            ev = ev.with_attr("age", &s);
        }
    }
    if let Some(f) = val_str(item, "followers") {
        ev = ev.with_attr("followers", &f);
    }
    ev
}

fn extract_breach_entities(
    item: &Value,
    target_value: &str,
    scan_id: &str,
    seen: &mut HashSet<String>,
    result: &mut ModuleResult,
) {
    let ev = breach_evidence(item);

    // Only emit entities from records that match the target lookup.
    // Breach databases contain millions of records — a phone/IP search
    // returns rows for many different people. We only want entities
    // from rows where the email/username/phone matches our target.
    let target_lower = target_value.to_lowercase();
    let target_terms: Vec<&str> = target_lower
        .split(|c: char| !c.is_alphanumeric())
        .filter(|w| w.len() >= 3)
        .collect();
    let row_matches_target = |item: &Value| -> bool {
        for field in ["email", "username", "phone_number", "full_name"] {
            if let Some(v) = val_str(item, field) {
                let vl = v.to_lowercase();
                if vl == target_lower || target_terms.iter().any(|t| vl.contains(t)) {
                    return true;
                }
            }
        }
        false
    };
    let is_target_row = row_matches_target(item);

    if let Some(email) = val_str(item, "email") {
        let lower = email.to_lowercase();
        if lower.contains('@') && seen.insert(lower) {
            let mut e = Entity::new(EntityKind::Email, &email, 0.70, scan_id);
            e.tag(tags::BREACH);
            e.tag("oathnet-pro");
            e.add_evidence(ev.clone());
            result.push(e);
        }
    }

    if let Some(uname) = val_str(item, "username") {
        let lower = uname.to_lowercase();
        if lower.len() >= 3 && seen.insert(lower) {
            let mut e = Entity::new(EntityKind::Username, &uname, 0.65, scan_id);
            e.tag(tags::BREACH);
            e.tag("oathnet-pro");
            e.add_evidence(ev.clone());
            result.push(e);
        }
    }

    // Phone/Person/IP: full confidence for target-matching rows,
    // CANDIDATE confidence for non-matching rows (preserved for
    // investigation — never silently discarded).
    let conf = |base: f64| -> f64 { if is_target_row { base } else { 0.25 } };

    if let Some(ph) = val_str_or(item, &["phone_number", "phone_national", "phone"])
        && ph.len() >= 7
        && seen.insert(ph.to_lowercase())
    {
        let mut e = Entity::new(EntityKind::Phone, &ph, conf(0.70), scan_id);
        e.tag(tags::BREACH);
        e.tag("oathnet-pro");
        if !is_target_row {
            e.tag("candidate");
        }
        e.add_evidence(ev.clone());
        result.push(e);
    }

    if let Some(n) = val_str_or(item, &["full_name", "display_name", "name"]) {
        let t = n.trim();
        if t.len() >= 4 && t.contains(' ') && seen.insert(t.to_lowercase()) {
            let mut e = Entity::new(EntityKind::Person, t, conf(0.70), scan_id);
            e.tag(tags::BREACH);
            e.tag("oathnet-pro");
            if !is_target_row {
                e.tag("candidate");
            }
            e.add_evidence(ev.clone());
            result.push(e);
        }
    }

    if let Some(ip) = val_str(item, "ip")
        && ip.len() >= 7
        && seen.insert(ip.clone())
    {
        let mut e = Entity::new(EntityKind::IpAddress, &ip, conf(0.60), scan_id);
        e.tag(tags::BREACH);
        e.tag("oathnet-pro");
        e.tag("geolocation-lead");
        e.add_evidence(ev.clone());
        result.push(e);
    }

    if let Some(country) = val_str(item, "country")
        && seen.insert(format!("@country:{country}"))
    {
        let mut e = Entity::new(EntityKind::Address, &country, conf(0.55), scan_id);
        e.tag(tags::BREACH);
        e.tag("oathnet-pro");
        if !is_target_row {
            e.tag("candidate");
        }
        e.add_evidence(ev.clone());
        result.push(e);
    }

    let street = val_str(item, "address_street");
    let city = val_str(item, "city");
    let state = val_str(item, "state");
    if city.is_some() || street.is_some() {
        let addr = [street.as_deref(), city.as_deref(), state.as_deref()]
            .iter()
            .flatten()
            .copied()
            .collect::<Vec<&str>>()
            .join(", ");
        if addr.len() >= 4 && seen.insert(format!("@addr:{}", addr.to_lowercase())) {
            let mut e = Entity::new(EntityKind::Address, &addr, 0.65, scan_id);
            e.tag(tags::BREACH);
            e.tag("oathnet-pro");
            e.add_evidence(ev.clone());
            result.push(e);
        }
    }

    if let Some(did) = val_str(item, "discordid")
        && seen.insert(format!("@discord:{did}"))
    {
        let mut e = Entity::new(
            EntityKind::Username,
            format!("discord:{did}"),
            0.55,
            scan_id,
        );
        e.tag(tags::BREACH);
        e.tag("oathnet-pro");
        e.tag("discord");
        e.add_evidence(ev.clone());
        result.push(e);
    }

    if let Some(ig) = val_str(item, "instagram")
        && seen.insert(format!("@ig:{}", ig.to_lowercase()))
    {
        let mut e = Entity::new(EntityKind::Username, &ig, 0.55, scan_id);
        e.tag(tags::BREACH);
        e.tag("oathnet-pro");
        e.tag("instagram");
        e.add_evidence(ev);
        result.push(e);
    }
}

fn extract_stealer_entities(
    item: &Value,
    scan_id: &str,
    seen: &mut HashSet<String>,
    result: &mut ModuleResult,
) {
    let mut ev = Evidence::new("oathnet_pro", "Stealer log entry".to_string())
        .with_attr("source", "stealer");
    if let Some(url) = val_str(item, "url_str") {
        ev = ev.with_attr("url", &url);
    }
    if let Some(lid) = val_str(item, "log_id") {
        ev = ev.with_attr("log_id", &lid);
    }
    if let Some(pw) = val_str(item, "password") {
        ev = ev.with_attr("password", &pw);
    }
    if let Some(uname) = val_str(item, "username") {
        ev = ev.with_attr("username", &uname);
    }

    if let Some(emails) = item.get("email").and_then(|v| v.as_array()) {
        for email_val in emails {
            if let Some(email) = email_val.as_str() {
                let lower = email.to_lowercase();
                if lower.contains('@') && seen.insert(lower) {
                    let mut e = Entity::new(EntityKind::Email, email, 0.65, scan_id);
                    e.tag(tags::BREACH);
                    e.tag("oathnet-pro");
                    e.tag("stealer");
                    e.add_evidence(ev.clone());
                    result.push(e);
                }
            }
        }
    }

    if let Some(domains) = item.get("domain").and_then(|v| v.as_array()) {
        for d in domains {
            if let Some(dom) = d.as_str()
                && dom.contains('.')
                && seen.insert(dom.to_lowercase())
            {
                let mut e = Entity::new(EntityKind::Domain, dom, 0.50, scan_id);
                e.tag("oathnet-pro");
                e.tag("stealer");
                e.add_evidence(
                    Evidence::new("oathnet_pro", format!("Stealer credential for {dom}"))
                        .with_attr("source", "stealer"),
                );
                result.push(e);
            }
        }
    }

    if let Some(uname) = val_str(item, "username")
        && let Some(url_str) = val_str(item, "url_str")
    {
        let cred_val = format!("{uname}@{url_str}");
        if seen.insert(format!("@cred:{}", cred_val.to_lowercase())) {
            let mut e = Entity::new(EntityKind::Credential, &cred_val, 0.60, scan_id);
            e.tag("oathnet-pro");
            e.tag("stealer");
            e.add_evidence(ev);
            result.push(e);
        }
    }
}

fn extract_holehe(data: Value, email: &str, scan_id: &str, result: &mut ModuleResult) {
    if let Some(domains) = data.get("domains").and_then(|v| v.as_array()) {
        if domains.is_empty() {
            return;
        }
        let domains_str: Vec<&str> = domains.iter().filter_map(|v| v.as_str()).collect();
        let mut parent = Entity::new(EntityKind::Email, email, 0.80, scan_id);
        parent.tag("oathnet-pro");
        parent.tag("holehe");
        parent.add_evidence(
            Evidence::new(
                "oathnet_pro",
                format!("Holehe: email on {} service(s)", domains_str.len()),
            )
            .with_attr("holehe_domains", domains_str.join(", ")),
        );
        result.push(parent);
    }
}

fn extract_ip_info(data: Value, ip: &str, scan_id: &str, result: &mut ModuleResult) {
    let mut ev =
        Evidence::new("oathnet_pro", format!("IP info for {ip}")).with_attr("source", "ip-info");
    for (field, attr) in [
        ("city", "city"),
        ("regionName", "region"),
        ("region", "region_code"),
        ("country", "country"),
        ("countryCode", "country_code"),
        ("zip", "postal_code"),
        ("isp", "isp"),
        ("org", "org"),
        ("as", "asn"),
        ("timezone", "timezone"),
        ("reverse", "reverse_dns"),
        ("district", "district"),
        ("continent", "continent"),
    ] {
        if let Some(v) = data.get(field).and_then(|v| v.as_str()) {
            ev = ev.with_attr(attr, v);
        }
    }

    let lat = data.get("lat").and_then(|v| v.as_f64());
    let lon = data.get("lon").and_then(|v| v.as_f64());
    if let (Some(lat), Some(lon)) = (lat, lon) {
        let coords = format!("{lat},{lon}");
        let mut e = Entity::new(EntityKind::Coordinates, &coords, 0.65, scan_id);
        e.tag("oathnet-pro");
        e.tag("geolocation");
        e.add_evidence(ev.clone());
        result.push(e);
    }

    let city = data.get("city").and_then(|v| v.as_str());
    let region = data
        .get("regionName")
        .or_else(|| data.get("region"))
        .and_then(|v| v.as_str());
    let country = data.get("country").and_then(|v| v.as_str());
    if city.is_some() {
        let addr = [city, region, country]
            .iter()
            .flatten()
            .copied()
            .collect::<Vec<&str>>()
            .join(", ");
        let mut e = Entity::new(EntityKind::Address, &addr, 0.60, scan_id);
        e.tag("oathnet-pro");
        e.tag("geolocation");
        e.add_evidence(ev);
        result.push(e);
    }
}

// ─── Automatic API credential storage ────────────────────────────────────────

const API_SERVICE_DOMAINS: &[(&str, &str)] = &[
    ("shodan.io", "shodan"),
    ("account.shodan.io", "shodan"),
    ("virustotal.com", "virustotal"),
    ("hunter.io", "hunter"),
    ("securitytrails.com", "securitytrails"),
    ("dehashed.com", "dehashed"),
    ("intelx.io", "intelx"),
    ("numverify.com", "numverify"),
    ("wigle.net", "wigle"),
    ("ipqualityscore.com", "ipqs"),
    ("leakix.net", "leakix"),
    ("haveibeenpwned.com", "hibp"),
    ("censys.io", "censys"),
    ("search.censys.io", "censys"),
    ("binaryedge.io", "binaryedge"),
    ("app.binaryedge.io", "binaryedge"),
    ("greynoise.io", "greynoise"),
    ("viz.greynoise.io", "greynoise"),
    ("fullhunt.io", "fullhunt"),
    ("urlscan.io", "urlscan"),
    ("abuseipdb.com", "abuseipdb"),
    ("serpapi.com", "serpapi"),
    ("criminalip.io", "criminal_ip"),
    ("api.criminalip.io", "criminal_ip"),
    ("abuse.ch", "threatfox"),
    ("openai.com", "openai"),
    ("api.openai.com", "openai"),
    ("anthropic.com", "anthropic"),
    ("api.anthropic.com", "anthropic"),
];

const HARVEST_TARGETS: &[(&str, &str)] = &[
    ("shodan.io", "shodan"),
    ("virustotal.com", "virustotal"),
    ("hunter.io", "hunter"),
    ("securitytrails.com", "securitytrails"),
    ("dehashed.com", "dehashed"),
    ("intelx.io", "intelx"),
    ("ipqualityscore.com", "ipqs"),
    ("leakix.net", "leakix"),
    ("haveibeenpwned.com", "hibp"),
    ("censys.io", "censys"),
    ("binaryedge.io", "binaryedge"),
    ("greynoise.io", "greynoise"),
    ("fullhunt.io", "fullhunt"),
    ("urlscan.io", "urlscan"),
    ("abuseipdb.com", "abuseipdb"),
    ("criminalip.io", "criminal_ip"),
    ("numverify.com", "numverify"),
    ("wigle.net", "wigle"),
    ("serpapi.com", "serpapi"),
    ("openai.com", "openai"),
    ("anthropic.com", "anthropic"),
];

async fn harvest_api_credentials_from_stealer(key: &str) {
    let pool = crate::util::key_pool::global_pool();
    let mut stored = 0u32;

    for (domain, service) in HARVEST_TARGETS {
        if pool.active_count(service) >= 3 {
            continue;
        }
        let items = match oathnet::search(key, paths::STEALER, "q", domain, 5).await {
            Ok(items) => items,
            Err(_) => continue,
        };
        for item in &items {
            let url = val_str(item, "url").unwrap_or_default();
            let user = val_str(item, "username").unwrap_or_default();
            let pw = val_str(item, "password").unwrap_or_default();
            if user.is_empty() || pw.is_empty() {
                continue;
            }

            let url_lower = url.to_lowercase();
            let domains_field: Vec<String> = item
                .get("domain")
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|v| v.as_str())
                        .map(|s| s.to_lowercase())
                        .collect()
                })
                .unwrap_or_default();

            let url_matches = url_lower.contains(domain)
                || domains_field.iter().any(|d| d.contains(domain));

            // Store credentials from URL-matching results with service tag
            if url_matches {
                let mut entry = crate::util::key_pool::KeyEntry::new(&pw);
                entry.notes = Some(format!(
                    "OathNet stealer [{}]: user={} url={}",
                    service,
                    &user[..user.len().min(30)],
                    &url[..url.len().min(60)]
                ));
                if pool.add(service, entry) {
                    stored += 1;
                }
            }

            // Always store the login pair for the queried service
            let mut login_entry = crate::util::key_pool::KeyEntry::new(
                format!("{user}:{pw}"),
            );
            login_entry.notes = Some(format!(
                "OathNet stealer login [{}]: url={}",
                service,
                &url[..url.len().min(60)]
            ));
            pool.add(&format!("{service}_login"), login_entry);
            stored += 1;
        }
    }

    if stored > 0 {
        let _ = crate::util::key_pool::save_pool(&pool);
    }
}

pub fn store_api_credential_from_item(item: &Value) {
    store_api_credential(item);
}

fn store_api_credential(item: &Value) {
    let url = val_str(item, "url")
        .or_else(|| val_str(item, "url_str"))
        .unwrap_or_default();
    let username = val_str(item, "username").unwrap_or_default();
    let password = val_str(item, "password").unwrap_or_default();

    if username.is_empty() || password.is_empty() || url.is_empty() {
        return;
    }

    let url_lower = url.to_lowercase();
    let matched_service = API_SERVICE_DOMAINS
        .iter()
        .find(|(domain, _)| url_lower.contains(domain));

    let Some((_, service)) = matched_service else {
        return;
    };

    let pool = crate::util::key_pool::global_pool();

    let mut entry = crate::util::key_pool::KeyEntry::new(&password);
    entry.notes = Some(format!(
        "OathNet stealer: user={} url={}",
        &username[..username.len().min(30)],
        &url[..url.len().min(60)]
    ));
    if pool.add(service, entry) {
        let _ = crate::util::key_pool::save_pool(&pool);
    }

    let user_entry = crate::util::key_pool::KeyEntry::new(
        format!("{}:{}", username, password),
    );
    pool.add(&format!("{service}_login"), user_entry);
    let _ = crate::util::key_pool::save_pool(&pool);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_identity_and_infra_kinds() {
        let m = OathnetPro;
        for k in [
            TargetKind::Email,
            TargetKind::Username,
            TargetKind::Phone,
            TargetKind::IpAddress,
            TargetKind::Domain,
        ] {
            assert!(m.accepts(&Target::new(k, "x")));
        }
        assert!(!m.accepts(&Target::new(TargetKind::FullName, "Jane Doe")));
    }

    #[test]
    fn cost_is_paid() {
        assert!(matches!(OathnetPro.cost(), ModuleCost::Paid));
    }

    #[test]
    fn timeout_exceeds_default() {
        assert!(OathnetPro.max_timeout_ms() > crate::MODULE_TIMEOUT_MS);
    }

    #[test]
    fn val_str_or_fallback() {
        let item = serde_json::json!({"full_name": "Jerome Despal"});
        assert_eq!(
            val_str_or(&item, &["display_name", "full_name"]).as_deref(),
            Some("Jerome Despal")
        );
    }
}
