//! OathNet Pro — full-spectrum breach, stealer, OSINT, and intelligence API.
//!
//! Coverage: breach search, stealer logs, victim manifests, OSINT lookups
//! (holehe/ghunt/discord/steam/xbox/roblox/minecraft/ip-info/subdomain),
//! async jobs (bulk-search, exports, file-search), analytics, scanners.
//!
//! Wire contract (https://docs.oathnet.org):
//!   Base:  https://oathnet.org/api   (override: HUNTSMAN_OATHNET_BASE)
//!   Auth:  `x-api-key` header — NOT Authorization: Bearer
//!   Three response shapes:
//!     - Envelope JSON  { success, message, data, [errors] }
//!     - Raw JSON       (health, autocomplete, scanners)
//!     - File / stream  (victim files, archives, exports)
//!
//! INVARIANT: `success: true` with zero items is a legitimate empty result.
//! OSINT 404 ("user not found") is NotFound, not an error.
//! Only `success: false` (non-404) or transport failure is Err.

use std::collections::HashSet;
use std::time::Duration;

use async_trait::async_trait;
use serde::Deserialize;
use serde_json::Value;

use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    error::{Error, Result},
    module::{Module, ModuleContext, ModuleCost, ModuleResult},
    scan::{Target, TargetKind},
    tags,
};

const KEY_ENV: &str = "HUNTSMAN_OATHNET_KEY";
const HARDCODED_KEY: &str = "1f8097bdbf7dc68619857861adbc4343ddb490a1d72ae890551409e4b47116f2";

fn base_url() -> String {
    std::env::var("HUNTSMAN_OATHNET_BASE").unwrap_or_else(|_| "https://oathnet.org/api".to_string())
}

const P_BREACH: &str = "/service/v2/breach/search";
const P_STEALER: &str = "/service/v2/stealer/search";
const P_HOLEHE: &str = "/service/holehe";
const P_IP_INFO: &str = "/service/ip-info";

const PAGE_SIZE: &str = "50";

// ─── Envelope types ─────────────────────────────────────────────────────────

#[derive(Deserialize)]
struct Envelope {
    #[serde(default)]
    success: bool,
    #[serde(default)]
    data: Option<Value>,
    #[serde(default)]
    errors: Option<ErrorDetail>,
}

#[derive(Deserialize, Default)]
struct ErrorDetail {
    #[serde(default)]
    status_code: Option<u16>,
}

#[derive(Deserialize)]
struct SearchData {
    #[serde(default)]
    items: Vec<Value>,
}

// ─── Module ─────────────────────────────────────────────────────────────────

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
        15_000
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let key = ctx
            .key_opt(KEY_ENV)
            .filter(|k| !k.is_empty())
            .unwrap_or(HARDCODED_KEY);

        let mut result = ModuleResult::new();
        let mut seen: HashSet<String> = HashSet::new();
        seen.insert(target.value.to_lowercase());

        // ── Breach search ───────────────────────────────────────────
        let field = match target.kind {
            TargetKind::Email => "email",
            TargetKind::Username => "username",
            TargetKind::Phone => "phone",
            TargetKind::IpAddress => "ip",
            TargetKind::Domain => "domain",
            _ => return Ok(result),
        };

        let items = api_search(key, P_BREACH, field, &target.value).await?;
        if items.is_empty() {
            return Ok(result);
        }

        let total = items.len();
        let top_dbs = top_dbnames(&items, 5);

        let mut parent = target.to_entity(0.85, &ctx.scan_id);
        parent.tag(tags::BREACH);
        parent.tag("oathnet-pro");
        let mut ev = Evidence::new(
            "oathnet_pro",
            format!("OathNet: {total} breach record(s) — {}", top_dbs.join(", ")),
        )
        .with_attr("hits", total.to_string())
        .with_attr("top_dbnames", top_dbs.join(", "));

        // Attach the richest metadata from the first item with country/name
        for item in &items {
            if let Some(c) = item.get("country").and_then(|v| v.as_str()) {
                ev = ev.with_attr("country", c);
            }
            if let Some(n) = item.get("full_name").and_then(|v| v.as_str()) {
                ev = ev.with_attr("full_name", n);
            }
            if let Some(g) = item.get("gender").and_then(|v| v.as_str()) {
                ev = ev.with_attr("gender", g);
            }
            if let Some(dob) = item.get("date_birth").and_then(|v| v.as_str()) {
                ev = ev.with_attr("date_of_birth", dob);
            }
            if item.get("country").is_some() || item.get("full_name").is_some() {
                break;
            }
        }
        parent.add_evidence(ev);
        result.push(parent);

        // ── Extract every entity from every breach item ─────────────
        for item in &items {
            extract_breach_entities(item, &ctx.scan_id, &mut seen, &mut result);
        }

        // ── Stealer search (same target) ────────────────────────────
        if !ctx.cancel.is_cancelled()
            && let Ok(stealer_items) = api_search(key, P_STEALER, field, &target.value).await
        {
            for item in &stealer_items {
                extract_stealer_entities(item, &ctx.scan_id, &mut seen, &mut result);
            }
        }

        if target.kind == TargetKind::Email
            && !ctx.cancel.is_cancelled()
            && let Ok(holehe) = api_osint(key, P_HOLEHE, "email", &target.value).await
        {
            extract_holehe(holehe, &target.value, &ctx.scan_id, &mut result);
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
                if let Ok(info) = api_osint(key, P_IP_INFO, "ip_address", ip).await {
                    extract_ip_info(info, ip, &ctx.scan_id, &mut result);
                }
            }
        }

        Ok(result)
    }
}

// ─── API call helpers ───────────────────────────────────────────────────────

async fn api_search(key: &str, path: &str, field: &str, value: &str) -> Result<Vec<Value>> {
    let encoded = crate::util::http::urlencode(value);
    let url = format!(
        "{}{}?{}%5B%5D={}&page_size={}",
        base_url(),
        path,
        field,
        encoded,
        PAGE_SIZE
    );
    let body = curl_api(&url, key).await?;
    let env: Envelope =
        serde_json::from_str(&body).map_err(|e| Error::module("oathnet_pro", e.to_string()))?;
    if !env.success {
        if env.errors.as_ref().and_then(|e| e.status_code) == Some(404) {
            return Ok(Vec::new());
        }
        return Err(Error::module("oathnet_pro", "API returned success=false"));
    }
    let data = match env.data {
        Some(d) => d,
        None => return Ok(Vec::new()),
    };
    let sd: SearchData =
        serde_json::from_value(data).map_err(|e| Error::module("oathnet_pro", e.to_string()))?;
    Ok(sd.items)
}

async fn api_osint(key: &str, path: &str, param: &str, value: &str) -> Result<Value> {
    let encoded = crate::util::http::urlencode(value);
    let url = format!("{}{}?{}={}", base_url(), path, param, encoded);
    let body = curl_api(&url, key).await?;
    let env: Envelope =
        serde_json::from_str(&body).map_err(|e| Error::module("oathnet_pro", e.to_string()))?;
    if !env.success {
        return Err(Error::module("oathnet_pro", "OSINT lookup failed"));
    }
    Ok(env.data.unwrap_or(Value::Null))
}

async fn curl_api(url: &str, key: &str) -> Result<String> {
    let secs = 12u64.to_string();
    let header = format!("x-api-key: {key}");
    let mut cmd = tokio::process::Command::new("curl");
    cmd.args([
        "-s",
        "--max-time",
        &secs,
        "-H",
        &header,
        "-H",
        "Accept: application/json",
        "--",
        url,
    ]);
    cmd.kill_on_drop(true);

    let output = tokio::time::timeout(Duration::from_millis(15_000), cmd.output())
        .await
        .map_err(|_| Error::module("oathnet_pro", "timeout"))?
        .map_err(|e| Error::module("oathnet_pro", e.to_string()))?;

    if !output.status.success() {
        return Err(Error::module("oathnet_pro", "curl failed"));
    }
    String::from_utf8(output.stdout).map_err(|e| Error::module("oathnet_pro", e.to_string()))
}

// ─── Entity extraction ─────────────────────────────────────────────────────

fn val_str(item: &Value, key: &str) -> Option<String> {
    item.get(key)
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
}

fn val_str_or(item: &Value, keys: &[&str]) -> Option<String> {
    keys.iter().find_map(|k| val_str(item, k))
}

fn breach_evidence(item: &Value, source: &str) -> Evidence {
    let db = val_str(item, "dbname").unwrap_or_else(|| "unknown".to_string());
    let mut ev = Evidence::new("oathnet_pro", format!("Breach on {db}"))
        .with_attr("dbname", &db)
        .with_attr("source", source);
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
    scan_id: &str,
    seen: &mut HashSet<String>,
    result: &mut ModuleResult,
) {
    let ev = breach_evidence(item, "breach");

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

    if let Some(ph) = val_str_or(item, &["phone_number", "phone_national", "phone"])
        && ph.len() >= 7
        && seen.insert(ph.to_lowercase())
    {
        let mut e = Entity::new(EntityKind::Phone, &ph, 0.70, scan_id);
        e.tag(tags::BREACH);
        e.tag("oathnet-pro");
        e.add_evidence(ev.clone());
        result.push(e);
    }

    if let Some(n) = val_str_or(item, &["full_name", "display_name", "name"]) {
        let t = n.trim();
        if t.len() >= 4 && t.contains(' ') && seen.insert(t.to_lowercase()) {
            let mut e = Entity::new(EntityKind::Person, t, 0.70, scan_id);
            e.tag(tags::BREACH);
            e.tag("oathnet-pro");
            e.add_evidence(ev.clone());
            result.push(e);
        }
    }

    if let Some(ip) = val_str(item, "ip")
        && ip.len() >= 7
        && seen.insert(ip.clone())
    {
        let mut e = Entity::new(EntityKind::IpAddress, &ip, 0.60, scan_id);
        e.tag(tags::BREACH);
        e.tag("oathnet-pro");
        e.tag("geolocation-lead");
        e.add_evidence(ev.clone());
        result.push(e);
    }

    if let Some(country) = val_str(item, "country")
        && seen.insert(format!("@country:{country}"))
    {
        let mut e = Entity::new(EntityKind::Address, &country, 0.55, scan_id);
        e.tag(tags::BREACH);
        e.tag("oathnet-pro");
        e.add_evidence(ev.clone());
        result.push(e);
    }

    // Street address from breach data
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

    // Discord ID as username
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
    let db = "stealer-log";
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

    // Stealer emails are an array
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

    // Stealer domains are arrays
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
                        .with_attr("source", db),
                );
                result.push(e);
            }
        }
    }

    // Credential as entity
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
                format!(
                    "Holehe: email registered on {} service(s)",
                    domains_str.len()
                ),
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
        ("region", "region"),
        ("country", "country"),
        ("org", "org"),
        ("asn", "asn"),
        ("timezone", "timezone"),
        ("lat", "latitude"),
        ("lon", "longitude"),
    ] {
        if let Some(v) = data.get(field) {
            let s = if v.is_string() {
                v.as_str().unwrap_or("").to_string()
            } else {
                v.to_string()
            };
            if !s.is_empty() {
                ev = ev.with_attr(attr, &s);
            }
        }
    }

    // Coordinates for geolocation
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

    // City/region as address
    let city = data.get("city").and_then(|v| v.as_str());
    let region = data.get("region").and_then(|v| v.as_str());
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

fn top_dbnames(items: &[Value], n: usize) -> Vec<String> {
    let mut counts: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    for item in items {
        if let Some(db) = val_str(item, "dbname") {
            *counts.entry(db).or_default() += 1;
        }
    }
    let mut sorted: Vec<(String, usize)> = counts.into_iter().collect();
    sorted.sort_by(|a, b| b.1.cmp(&a.1));
    sorted.into_iter().take(n).map(|(k, _)| k).collect()
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
    fn entity_kind_mapping_is_total_for_accepted_targets() {
        for (tk, ek) in [
            (TargetKind::Email, EntityKind::Email),
            (TargetKind::Username, EntityKind::Username),
            (TargetKind::Phone, EntityKind::Phone),
            (TargetKind::IpAddress, EntityKind::IpAddress),
            (TargetKind::Domain, EntityKind::Domain),
        ] {
            assert_eq!(tk.to_entity_kind(), ek);
        }
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
