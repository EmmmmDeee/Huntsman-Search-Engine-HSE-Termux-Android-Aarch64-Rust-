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

const SRC: &str = "oathnet_pro";

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
            extract_api_keys_from_item(item, &ctx.scan_id, &mut seen, &mut result);
        }

        // ── Stealer search ──────────────────────────────────────────
        if !ctx.cancel.is_cancelled()
            && let Ok(stealer_items) =
                oathnet::search(key, paths::STEALER, field, &target.value, 50).await
        {
            for item in &stealer_items {
                extract_stealer_entities(item, &ctx.scan_id, &mut seen, &mut result);
                store_api_credential(item);
                extract_api_keys_from_item(item, &ctx.scan_id, &mut seen, &mut result);
            }
        }

        // ── Victims search (compromised device intelligence) ────────
        if !ctx.cancel.is_cancelled()
            && let Ok(victim_items) =
                oathnet::search(key, paths::VICTIMS, field, &target.value, 20).await
        {
            for item in &victim_items {
                extract_victim_entities(item, &ctx.scan_id, &mut seen, &mut result);
            }
        }

        // ── Holehe (email targets) ──────────────────────────────────
        if target.kind == TargetKind::Email
            && !ctx.cancel.is_cancelled()
            && let Ok(holehe) = oathnet::osint(key, paths::HOLEHE, "email", &target.value).await
        {
            extract_holehe(holehe, &target.value, &ctx.scan_id, &mut result);
        }

        // ── Recursive credential discovery ─────────────────────────
        // Use discovered emails from breach data to search stealer
        // endpoint for additional credential exposure.
        if !ctx.cancel.is_cancelled() {
            let discovered_emails: Vec<String> = result
                .entities
                .iter()
                .filter(|e| e.kind == EntityKind::Email && e.value != target.value)
                .take(5)
                .map(|e| e.value.clone())
                .collect();
            for email in &discovered_emails {
                if ctx.cancel.is_cancelled() {
                    break;
                }
                if let Ok(items) = oathnet::search(key, paths::STEALER, "email", email, 10).await {
                    for item in &items {
                        store_api_credential(item);
                        extract_api_keys_from_item(item, &ctx.scan_id, &mut seen, &mut result);
                    }
                }
            }
        }

        // ── OSINT enrichment (Discord, Steam, GHunt) ──────────────
        if !ctx.cancel.is_cancelled() {
            let usernames: Vec<String> = result
                .entities
                .iter()
                .filter(|e| e.kind == EntityKind::Username && e.confidence >= 0.60)
                .take(3)
                .map(|e| e.value.clone())
                .collect();
            for uname in &usernames {
                if ctx.cancel.is_cancelled() {
                    break;
                }
                // Discord user info
                if let Ok(data) = oathnet::osint(key, paths::DISCORD_USER, "user", uname).await
                    && let Some(id) = data.get("id").and_then(|v| v.as_str())
                {
                    let mut e = Entity::new(
                        EntityKind::Username,
                        format!("discord:{id}"),
                        0.65,
                        &ctx.scan_id,
                    );
                    e.tag("oathnet-pro");
                    e.tag("discord");
                    let mut ev = Evidence::new(SRC, format!("Discord lookup for {uname}"));
                    if let Some(n) = data.get("username").and_then(|v| v.as_str()) {
                        ev = ev.with_attr("discord_username", n);
                    }
                    if let Some(a) = data.get("avatar").and_then(|v| v.as_str()) {
                        ev = ev.with_attr("avatar", a);
                    }
                    e.add_evidence(ev);
                    if seen.insert(format!("@discord:{id}")) {
                        result.push(e);
                    }
                }
            }

            // GHunt for email targets
            if target.kind == TargetKind::Email
                && let Ok(data) = oathnet::osint(key, paths::GHUNT, "email", &target.value).await
                && let Some(name) = data.get("name").and_then(|v| v.as_str())
                && name.len() >= 3
                && name.contains(' ')
                && seen.insert(format!("@ghunt:{}", name.to_lowercase()))
            {
                let mut e = Entity::new(EntityKind::Person, name, 0.70, &ctx.scan_id);
                e.tag("oathnet-pro");
                e.tag("google");
                e.add_evidence(Evidence::new(
                    "oathnet_pro",
                    format!("GHunt: Google account for {}", &target.value),
                ));
                result.push(e);
            }
        }

        // ── Targeted API credential harvest ─────────────────────────
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
    let mut ev = Evidence::new(SRC, format!("Breach on {db}")).with_attr("dbname", &db);
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
    let mut ev = Evidence::new(SRC, "Stealer log entry".to_string()).with_attr("source", "stealer");
    if let Some(url) = val_str(item, "url").or_else(|| val_str(item, "url_str")) {
        ev = ev.with_attr("url", &url);
    }
    if let Some(lid) = val_str(item, "log_id").or_else(|| val_str(item, "log")) {
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
                    Evidence::new(SRC, format!("Stealer credential for {dom}"))
                        .with_attr("source", "stealer"),
                );
                result.push(e);
            }
        }
    }

    if let Some(uname) = val_str(item, "username")
        && let Some(url_str) = val_str(item, "url").or_else(|| val_str(item, "url_str"))
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
    let mut ev = Evidence::new(SRC, format!("IP info for {ip}")).with_attr("source", "ip-info");
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

    let lat = data.get("lat").and_then(serde_json::Value::as_f64);
    let lon = data.get("lon").and_then(serde_json::Value::as_f64);
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

fn extract_victim_entities(
    item: &Value,
    scan_id: &str,
    seen: &mut HashSet<String>,
    result: &mut ModuleResult,
) {
    if let Some(emails) = item.get("device_emails").and_then(|v| v.as_array()) {
        for email_val in emails.iter().take(20) {
            if let Some(email) = email_val.as_str() {
                let lower = email.to_lowercase();
                if lower.contains('@') && lower.len() > 5 && seen.insert(lower) {
                    let mut e = Entity::new(EntityKind::Email, email, 0.50, scan_id);
                    e.tag("oathnet-pro");
                    e.tag("victim-device");
                    e.add_evidence(Evidence::new(
                        "oathnet_pro",
                        "Email found on compromised device",
                    ));
                    result.push(e);
                }
            }
        }
    }
    if let Some(ips) = item.get("device_ips").and_then(|v| v.as_array()) {
        for ip_val in ips.iter().take(5) {
            if let Some(ip) = ip_val.as_str()
                && ip.len() >= 7
                && seen.insert(ip.to_string())
            {
                let mut e = Entity::new(EntityKind::IpAddress, ip, 0.50, scan_id);
                e.tag("oathnet-pro");
                e.tag("victim-device");
                e.add_evidence(Evidence::new(SRC, "IP from compromised device"));
                result.push(e);
            }
        }
    }
}

// ─── API key pattern recognition ─────────────────────────────────────────────

struct KeyPattern {
    prefix: &'static str,
    service: &'static str,
    min_len: usize,
}

const KEY_PATTERNS: &[KeyPattern] = &[
    KeyPattern {
        prefix: "sk-ant-",
        service: "anthropic",
        min_len: 40,
    },
    KeyPattern {
        prefix: "sk-proj-",
        service: "openai",
        min_len: 40,
    },
    KeyPattern {
        prefix: "sk-",
        service: "openai_or_stripe",
        min_len: 20,
    },
    KeyPattern {
        prefix: "AIzaSy",
        service: "google",
        min_len: 30,
    },
    KeyPattern {
        prefix: "AKIA",
        service: "aws",
        min_len: 16,
    },
    KeyPattern {
        prefix: "ASIA",
        service: "aws_sts",
        min_len: 16,
    },
    KeyPattern {
        prefix: "ghp_",
        service: "github",
        min_len: 36,
    },
    KeyPattern {
        prefix: "gho_",
        service: "github_oauth",
        min_len: 36,
    },
    KeyPattern {
        prefix: "ghs_",
        service: "github_app",
        min_len: 36,
    },
    KeyPattern {
        prefix: "github_pat_",
        service: "github",
        min_len: 40,
    },
    KeyPattern {
        prefix: "SG.",
        service: "sendgrid",
        min_len: 20,
    },
    KeyPattern {
        prefix: "xkeysib-",
        service: "brevo",
        min_len: 40,
    },
    KeyPattern {
        prefix: "key-",
        service: "mailgun",
        min_len: 30,
    },
    KeyPattern {
        prefix: "sk_live_",
        service: "stripe",
        min_len: 24,
    },
    KeyPattern {
        prefix: "pk_live_",
        service: "stripe_pub",
        min_len: 24,
    },
    KeyPattern {
        prefix: "sk_test_",
        service: "stripe_test",
        min_len: 24,
    },
    KeyPattern {
        prefix: "hf_",
        service: "huggingface",
        min_len: 30,
    },
    KeyPattern {
        prefix: "r8_",
        service: "replicate",
        min_len: 30,
    },
    KeyPattern {
        prefix: "pplx-",
        service: "perplexity",
        min_len: 30,
    },
    KeyPattern {
        prefix: "sntrys_",
        service: "sentry",
        min_len: 20,
    },
    KeyPattern {
        prefix: "glc_",
        service: "grafana",
        min_len: 20,
    },
    KeyPattern {
        prefix: "NRAK-",
        service: "newrelic",
        min_len: 20,
    },
    KeyPattern {
        prefix: "dapi",
        service: "databricks",
        min_len: 30,
    },
    KeyPattern {
        prefix: "cfut_",
        service: "cloudflare",
        min_len: 40,
    },
    KeyPattern {
        prefix: "cfat_",
        service: "cloudflare_acct",
        min_len: 40,
    },
    KeyPattern {
        prefix: "shpat_",
        service: "shopify",
        min_len: 30,
    },
    KeyPattern {
        prefix: "ntn_",
        service: "notion",
        min_len: 40,
    },
    KeyPattern {
        prefix: "lin_api_",
        service: "linear",
        min_len: 30,
    },
    KeyPattern {
        prefix: "tfp_",
        service: "typeform",
        min_len: 30,
    },
    KeyPattern {
        prefix: "fo1_",
        service: "flyio",
        min_len: 30,
    },
    KeyPattern {
        prefix: "sbp_",
        service: "supabase",
        min_len: 30,
    },
    KeyPattern {
        prefix: "pul-",
        service: "pulumi",
        min_len: 30,
    },
    KeyPattern {
        prefix: "ATATT3",
        service: "atlassian",
        min_len: 40,
    },
    KeyPattern {
        prefix: "xoxb-",
        service: "slack_bot",
        min_len: 30,
    },
    KeyPattern {
        prefix: "xoxp-",
        service: "slack_user",
        min_len: 30,
    },
    KeyPattern {
        prefix: "xapp-",
        service: "slack_app",
        min_len: 30,
    },
    KeyPattern {
        prefix: "EAA",
        service: "facebook",
        min_len: 40,
    },
];

fn identify_api_key(value: &str) -> Option<(&'static str, &str)> {
    let trimmed = value.trim();
    if trimmed.len() < 16 {
        return None;
    }
    for pat in KEY_PATTERNS {
        if trimmed.starts_with(pat.prefix) && trimmed.len() >= pat.min_len {
            return Some((pat.service, trimmed));
        }
    }
    // Generic hex key detection (32 or 64 char hex = potential API key)
    if (trimmed.len() == 32 || trimmed.len() == 64)
        && trimmed.chars().all(|c| c.is_ascii_hexdigit())
    {
        return Some(("generic_hex", trimmed));
    }
    None
}

fn extract_api_keys_from_item(
    item: &Value,
    scan_id: &str,
    seen: &mut HashSet<String>,
    result: &mut ModuleResult,
) {
    let fields = [
        "password",
        "password_hash",
        "api_key",
        "token",
        "secret",
        "access_key",
        "auth_token",
        "api_token",
    ];

    for field in &fields {
        if let Some(val) = val_str(item, field)
            && let Some((service, key_val)) = identify_api_key(&val)
        {
            let dedup = format!(
                "@apikey:{service}:{}",
                crate::util::str_util::truncate_safe(key_val, 16)
            );
            if !seen.insert(dedup) {
                continue;
            }

            // Emit as Credential entity tagged for api_key_probe expansion
            let mut entity = Entity::new(EntityKind::ApiKey, key_val, 0.80, scan_id);
            entity.tag("api-key");
            entity.tag(format!("service:{service}"));
            entity.tag("oathnet-pro");
            entity.tag("auto-discovered");

            let db = val_str(item, "dbname").unwrap_or_default();
            entity.add_evidence(
                Evidence::new(
                    "oathnet_pro",
                    format!(
                        "API key discovered ({service}) in {}",
                        if db.is_empty() { "stealer log" } else { &db }
                    ),
                )
                .with_attr("service", service)
                .with_attr(
                    "key_prefix",
                    crate::util::str_util::truncate_safe(key_val, 8),
                )
                .with_attr("key_length", key_val.len().to_string()),
            );
            result.push(entity);

            // Auto-store in key pool
            let pool = crate::util::key_pool::global_pool();
            let mut entry = crate::util::key_pool::KeyEntry::new(key_val);
            entry.notes = Some(format!(
                "Auto-discovered {service} key from OathNet breach/stealer data"
            ));
            pool.add(service, entry);
            let _ = crate::util::key_pool::save_pool(&pool);
        }
    }

    // Also scan the username field — some stealer logs store API keys as usernames
    if let Some(user) = val_str(item, "username")
        && let Some((service, key_val)) = identify_api_key(&user)
    {
        let dedup = format!(
            "@apikey:{service}:{}",
            crate::util::str_util::truncate_safe(key_val, 16)
        );
        if seen.insert(dedup) {
            let mut entity = Entity::new(EntityKind::ApiKey, key_val, 0.75, scan_id);
            entity.tag("api-key");
            entity.tag(format!("service:{service}"));
            entity.tag("oathnet-pro");
            entity.add_evidence(
                Evidence::new(
                    "oathnet_pro",
                    format!("API key in username field ({service})"),
                )
                .with_attr("service", service),
            );
            result.push(entity);

            let pool = crate::util::key_pool::global_pool();
            let mut entry = crate::util::key_pool::KeyEntry::new(key_val);
            entry.notes = Some(format!("Auto-discovered {service} key (username field)"));
            pool.add(service, entry);
            let _ = crate::util::key_pool::save_pool(&pool);
        }
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
    ("passivetotal.org", "passivetotal"),
    ("riskiq.net", "passivetotal"),
    ("onyphe.io", "onyphe"),
    ("zoomeye.org", "zoomeye"),
    ("api.zoomeye.org", "zoomeye"),
    ("fofa.info", "fofa"),
    ("en.fofa.info", "fofa"),
    ("netlas.io", "netlas"),
    ("app.netlas.io", "netlas"),
    ("pulsedive.com", "pulsedive"),
    ("builtwith.com", "builtwith"),
    ("emailrep.io", "emailrep"),
    ("whoisxmlapi.com", "whoisxml"),
    ("breachdirectory.org", "breachdirectory"),
    ("c99.nl", "c99"),
    ("api.c99.nl", "c99"),
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
    ("passivetotal.org", "passivetotal"),
    ("riskiq.net", "passivetotal"),
    ("onyphe.io", "onyphe"),
    ("zoomeye.org", "zoomeye"),
    ("fofa.info", "fofa"),
    ("netlas.io", "netlas"),
    ("pulsedive.com", "pulsedive"),
    ("builtwith.com", "builtwith"),
    ("emailrep.io", "emailrep"),
    ("whoisxmlapi.com", "whoisxml"),
    ("breachdirectory.org", "breachdirectory"),
    ("c99.nl", "c99"),
];

async fn harvest_api_credentials_from_stealer(key: &str) {
    let pool = crate::util::key_pool::global_pool();
    let mut stored = 0u32;
    let mut seen: HashSet<String> = HashSet::new();

    // ── PRECISE QUERIES ONLY ──
    // Live-tested: only domain= and password= return domain-relevant results.
    // All other field params (q=, username=, email=) return generic data.

    // Phase 1: domain= queries — 100% precise (verified live).
    for (domain, service) in HARVEST_TARGETS {
        if pool.active_count(service) >= 5 {
            continue;
        }
        if let Ok(items) = oathnet::search(key, paths::STEALER, "domain", domain, 20).await {
            stored += store_unique_stealer_keys(&items, domain, service, &pool, &mut seen);
        }
    }

    // Phase 2: password= queries — 100% precise (verified live).
    for (domain, service) in HARVEST_TARGETS {
        if pool.active_count(service) >= 5 {
            continue;
        }
        if let Ok(items) = oathnet::search(key, paths::STEALER, "password", domain, 10).await {
            for item in &items {
                let pw = val_str(item, "password").unwrap_or_default();
                let user = val_str(item, "username").unwrap_or_default();
                let url = val_str(item, "url").unwrap_or_default();
                if user.is_empty() || pw.is_empty() || !seen.insert(format!("pw:{service}:{user}"))
                {
                    continue;
                }
                let mut entry = crate::util::key_pool::KeyEntry::new(&pw);
                entry.notes = Some(format!(
                    "OathNet password-match [{service}]: user={} url={}",
                    &crate::util::str_util::truncate_safe(&user, 25),
                    &crate::util::str_util::truncate_safe(&url, 50)
                ));
                pool.add(service, entry);
                pool.add(
                    &format!("{service}_login"),
                    crate::util::key_pool::KeyEntry::new(format!("{user}:{pw}")),
                );
                stored += 1;
            }
        }
    }

    // Phase 3: username= field-name capture — returns entries where form
    // field names like "api_key" were stored as the username. The password
    // field contains the actual key value. NOT domain-precise, but the
    // values are API-key-shaped (28+ chars, mixed alphanumeric).
    const KEY_FIELD_NAMES: &[&str] = &[
        "api_key",
        "apikey",
        "api-key",
        "apiKey",
        "access_key",
        "secret_key",
        "api_token",
        "auth_token",
        "token",
        "access_token",
        "x-api-key",
        "x-key",
        "SHODAN_API_KEY",
        "VT_API_KEY",
        "OPENAI_API_KEY",
        "ANTHROPIC_API_KEY",
        "GITHUB_TOKEN",
        "AWS_ACCESS_KEY_ID",
        "AWS_SECRET_ACCESS_KEY",
        "STRIPE_SECRET_KEY",
        "SENDGRID_API_KEY",
    ];
    for field_name in KEY_FIELD_NAMES {
        if pool.total_keys() > 500 {
            break;
        }
        if let Ok(items) = oathnet::search(key, paths::STEALER, "username", field_name, 10).await {
            for item in &items {
                let pw = val_str(item, "password").unwrap_or_default();
                let url = val_str(item, "url").unwrap_or_default();
                if pw.len() < 10 || !seen.insert(format!("fn:{field_name}:{pw}")) {
                    continue;
                }
                let service = identify_service_from_url(&url);
                let label = if service != "unknown" {
                    service
                } else {
                    "discovered_api_key"
                };
                let mut entry = crate::util::key_pool::KeyEntry::new(&pw);
                entry.notes = Some(format!(
                    "OathNet field-capture [{field_name}->{label}]: url={}",
                    &crate::util::str_util::truncate_safe(&url, 50)
                ));
                pool.add(label, entry);
                stored += 1;
            }
        }
    }

    // Phase 4: Breach domain= pattern scan with 37-prefix scanner.
    for (domain, service) in HARVEST_TARGETS.iter().take(15) {
        if pool.total_keys() > 500 {
            break;
        }
        if let Ok(items) = oathnet::search(key, paths::BREACH, "domain", domain, 20).await {
            for item in &items {
                for field in ["password", "password_hash", "username"] {
                    if let Some(val) = val_str(item, field)
                        && let Some((svc, key_val)) = identify_api_key(&val)
                        && seen.insert(format!(
                            "br:{svc}:{}",
                            crate::util::str_util::truncate_safe(key_val, 12)
                        ))
                    {
                        let mut entry = crate::util::key_pool::KeyEntry::new(key_val);
                        entry.notes = Some(format!(
                            "OathNet breach [{svc}]: field={field} via={service}"
                        ));
                        pool.add(svc, entry);
                        stored += 1;
                    }
                }
            }
        }
    }

    if stored > 0 {
        let _ = crate::util::key_pool::save_pool(&pool);
    }
}

fn store_unique_stealer_keys(
    items: &[Value],
    domain: &str,
    service: &str,
    pool: &crate::util::key_pool::KeyPool,
    seen: &mut HashSet<String>,
) -> u32 {
    let mut stored = 0u32;
    for item in items {
        let url = val_str(item, "url").unwrap_or_default();
        let user = val_str(item, "username").unwrap_or_default();
        let pw = val_str(item, "password").unwrap_or_default();
        if user.is_empty() || pw.is_empty() {
            continue;
        }
        if !seen.insert(format!("{service}:{pw}")) {
            continue;
        }

        let url_lower = url.to_lowercase();
        let domains_field: Vec<String> = item
            .get("domain")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str())
                    .map(str::to_lowercase)
                    .collect()
            })
            .unwrap_or_default();

        let url_matches =
            url_lower.contains(domain) || domains_field.iter().any(|d| d.contains(domain));

        if url_matches {
            let mut entry = crate::util::key_pool::KeyEntry::new(&pw);
            entry.notes = Some(format!(
                "OathNet stealer [{}]: user={} url={}",
                service,
                &crate::util::str_util::truncate_safe(&user, 30),
                &crate::util::str_util::truncate_safe(&url, 60)
            ));
            if pool.add(service, entry) {
                stored += 1;
            }
        }

        let login_entry = crate::util::key_pool::KeyEntry::new(format!("{user}:{pw}"));
        pool.add(&format!("{service}_login"), login_entry);
        stored += 1;
    }
    stored
}

fn identify_service_from_url(url: &str) -> &'static str {
    let lower = url.to_lowercase();
    for (domain, service) in API_SERVICE_DOMAINS {
        if lower.contains(domain) {
            return service;
        }
    }
    "unknown"
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

    let service = identify_service_from_url(&url);
    if service == "unknown" {
        return;
    }

    let pool = crate::util::key_pool::global_pool();

    let mut entry = crate::util::key_pool::KeyEntry::new(&password);
    entry.notes = Some(format!(
        "OathNet stealer: user={} url={}",
        &crate::util::str_util::truncate_safe(&username, 30),
        &crate::util::str_util::truncate_safe(&url, 60)
    ));
    if pool.add(service, entry) {
        let _ = crate::util::key_pool::save_pool(&pool);
    }

    let user_entry = crate::util::key_pool::KeyEntry::new(format!("{username}:{password}"));
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
