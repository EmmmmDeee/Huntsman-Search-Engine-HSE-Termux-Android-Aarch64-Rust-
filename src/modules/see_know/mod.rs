//! SeekNow (see-know.eu) — parallel breach + stealer + OSINT pool.
//!
//! Direct OathNet competitor with its own 5,000-lookup daily quota.
//! Runs alongside oathnet_pro so each scan effectively gets 2 parallel
//! Multiplier-tier pools (separate quotas, overlapping but distinct
//! data corpora — combining them maximises coverage).
//!
//! Per-target endpoint routing:
//!
//!   Email      → /search + /stealer + /network/email-check
//!   Username   → /search + /stealer
//!   Phone      → /network/phone
//!   Domain     → /domain/intel
//!   IpAddress  → /network/ip
//!   FullName   → /search (auto-detect)
//!
//! Each scan spends 1-3 SeekNow lookups (bounded by MAX_QUERIES_PER_SCAN).
//! Discovered credentials feed the same key-harvest pipeline as oathnet_pro
//! — extract_api_keys_from_item recognises the same 80+ prefix patterns.

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
use crate::modules::oathnet_pro::key_harvest::{extract_api_keys_from_item, store_api_credential};
use crate::util::see_know::{self, val_str};

const SRC: &str = "see_know";

/// Re-export budget reset for the engine.
pub fn reset_budget() {
    crate::util::see_know::reset_budget();
}

pub struct SeekNow;

#[async_trait]
impl Module for SeekNow {
    fn name(&self) -> &'static str {
        "see_know"
    }

    fn description(&self) -> &'static str {
        "SeekNow (see-know.eu) — parallel breach/stealer/OSINT quota pool"
    }

    fn priority(&self) -> u8 {
        // Runs right after oathnet_pro (127). Both are Multiplier-tier
        // Paid modules. Phase 1 in concurrent dispatch covers both.
        126
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
                | TargetKind::FullName
                | TargetKind::IpAddress
                | TargetKind::Domain
        )
    }

    fn max_timeout_ms(&self) -> u64 {
        30_000
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let key = see_know::resolve_key(ctx.key_opt(see_know::KEY_ENV));

        let mut result = ModuleResult::new();
        let mut seen: HashSet<String> = HashSet::new();
        seen.insert(target.value.to_lowercase());
        let v = target.value.trim();

        // Pre-flight skips — same pattern as oathnet_pro. Catching junk
        // before any HTTP call saves quota and pool noise.
        match target.kind {
            TargetKind::Email => {
                if let Some((_, host)) = v.split_once('@')
                    && is_local_domain(host)
                {
                    return Ok(result);
                }
            }
            TargetKind::Username => {
                if v.len() < 4
                    || v.chars().all(|c| c.is_ascii_digit())
                    || is_placeholder_username(v)
                {
                    return Ok(result);
                }
            }
            TargetKind::Phone => {
                let digits = v.chars().filter(|c| c.is_ascii_digit()).count();
                if digits < 6 {
                    return Ok(result);
                }
            }
            TargetKind::FullName => {
                if !v.contains(' ') || v.len() < 5 {
                    return Ok(result);
                }
            }
            TargetKind::IpAddress => {
                if is_private_ip(v) {
                    return Ok(result);
                }
            }
            TargetKind::Domain => {
                if is_local_domain(v) {
                    return Ok(result);
                }
            }
            _ => return Ok(result),
        }

        // ── Query 1: universal /search ─────────────────────────────────
        // Single endpoint that auto-routes to the highest-yield specialised
        // path internally. Most efficient first query for ALL target kinds.
        let qtype = match target.kind {
            TargetKind::Email => "email",
            TargetKind::Username => "username",
            TargetKind::Phone => "phone",
            TargetKind::Domain => "domain",
            TargetKind::IpAddress => "ip",
            TargetKind::FullName => "", // auto-detect
            _ => "",
        };
        let items = see_know::search(key, v, qtype).await?;
        let total = items.len();

        if total > 0 {
            let mut parent = target.to_entity(0.85, &ctx.scan_id);
            parent.tag(tags::BREACH);
            parent.tag("see-know");
            parent.add_evidence(
                Evidence::new(SRC, format!("SeekNow: {total} record(s) via /search"))
                    .with_attr("hits", total.to_string())
                    .with_attr("endpoint", "/api/v1/search"),
            );
            result.push(parent);

            for item in &items {
                extract_entities(item, v, &ctx.scan_id, &mut seen, &mut result);
                store_api_credential(item);
                extract_api_keys_from_item(item, &ctx.scan_id, &mut seen, &mut result);
            }
        }

        // ── Per-seed endpoint matrix: maximise OSINT→geolocation synergy ─
        //
        // Each target kind dispatches a tailored set of specialised
        // endpoints chosen for their geo-yielding potential:
        //
        //   Email     → stealer + email-check (device IPs, service map)
        //   Username  → social aggregate + github + twitter + history
        //               + tiktok + reddit (every profile carries possible
        //               location/timezone/bio data)
        //   Phone     → phone_info (carrier/region) + search
        //   Domain    → intel + whois (registrant address, name servers)
        //   IpAddress → ip_info (geo, ASN, ISP)
        //   FullName  → universal /search only (no specialised endpoint)
        //
        // Discord IDs surfaced as Username:"discord:<id>" are pivoted
        // through discord/user + discord/to-roblox so the gaming graph
        // joins the identity graph.
        if !ctx.cancel.is_cancelled() {
            let endpoint_calls: Vec<(&'static str, Vec<Value>)> = match target.kind {
                TargetKind::Email => {
                    let mut out = Vec::new();
                    if let Ok(items) = see_know::stealer(key, v).await {
                        out.push(("stealer", items));
                    }
                    if let Ok(items) = see_know::breachhub(key, v).await {
                        out.push(("breachhub", items));
                    }
                    if let Ok(items) = see_know::email_check(key, v).await {
                        out.push(("email_check", items));
                    }
                    out
                }
                TargetKind::Username => {
                    let mut out = Vec::new();
                    // Stealer first — highest credential yield
                    if let Ok(items) = see_know::stealer(key, v).await {
                        out.push(("stealer", items));
                    }
                    // social_aggregate is one call covering 20+ platforms
                    if let Ok(items) = see_know::social_aggregate(key, v).await {
                        out.push(("social", items));
                    }
                    // Per-platform deeper pulls for the highest-geo platforms
                    if let Ok(items) = see_know::github_profile(key, v).await {
                        out.push(("github", items));
                    }
                    if let Ok(items) = see_know::twitter_profile(key, v).await {
                        out.push(("twitter", items));
                    }
                    out
                }
                TargetKind::Phone => {
                    let mut out = Vec::new();
                    if let Ok(items) = see_know::phone_info(key, v).await {
                        out.push(("phone_info", items));
                    }
                    if let Ok(items) = see_know::breachhub(key, v).await {
                        out.push(("breachhub", items));
                    }
                    out
                }
                TargetKind::IpAddress => {
                    let mut out = Vec::new();
                    if let Ok(items) = see_know::ip_info(key, v).await {
                        out.push(("ip_info", items));
                    }
                    out
                }
                TargetKind::Domain => {
                    let mut out = Vec::new();
                    if let Ok(items) = see_know::domain_intel(key, v).await {
                        out.push(("domain_intel", items));
                    }
                    if let Ok(items) = see_know::whois(key, v).await {
                        out.push(("whois", items));
                    }
                    out
                }
                _ => Vec::new(),
            };

            for (endpoint, items) in &endpoint_calls {
                for item in items {
                    extract_entities(item, v, &ctx.scan_id, &mut seen, &mut result);
                    store_api_credential(item);
                    extract_api_keys_from_item(item, &ctx.scan_id, &mut seen, &mut result);
                    // Geo-specific extraction — pull coordinates/timezone/
                    // location directly when the endpoint returns them.
                    extract_geo_entities(item, endpoint, &ctx.scan_id, &mut seen, &mut result);
                }
            }
        }

        Ok(result)
    }
}

/// Geo-conscious extraction — surface coordinates, timezones, and
/// location-bearing fields from any SeekNow endpoint response so the
/// downstream geocode/overpass/wigle modules can converge.
fn extract_geo_entities(
    item: &Value,
    endpoint: &str,
    scan_id: &str,
    seen: &mut HashSet<String>,
    result: &mut ModuleResult,
) {
    // Direct coordinate fields — some endpoints (ip_info, phone_info)
    // return lat/lon pairs directly.
    let lat = item
        .get("latitude")
        .or_else(|| item.get("lat"))
        .and_then(|v| v.as_f64())
        .or_else(|| {
            item.get("latitude")
                .or_else(|| item.get("lat"))
                .and_then(|v| v.as_str()?.parse().ok())
        });
    let lon = item
        .get("longitude")
        .or_else(|| item.get("lon"))
        .or_else(|| item.get("lng"))
        .and_then(|v| v.as_f64())
        .or_else(|| {
            item.get("longitude")
                .or_else(|| item.get("lon"))
                .or_else(|| item.get("lng"))
                .and_then(|v| v.as_str()?.parse().ok())
        });
    if let (Some(la), Some(lo)) = (lat, lon)
        && (-90.0..=90.0).contains(&la)
        && (-180.0..=180.0).contains(&lo)
    {
        let coord_val = format!("{la:.5},{lo:.5}");
        if seen.insert(format!("@coord:{coord_val}")) {
            let mut e = Entity::new(EntityKind::Coordinates, &coord_val, 0.75, scan_id);
            e.tag("see-know");
            e.tag(format!("via:{endpoint}"));
            e.add_evidence(
                Evidence::new(SRC, format!("Coordinates from SeekNow /{endpoint}"))
                    .with_attr("lat", la.to_string())
                    .with_attr("lon", lo.to_string()),
            );
            result.push(e);
        }
    }

    // Location string fields — profile bios often contain "Sydney, NSW"-
    // style city/region strings that geocode can resolve.
    for field in ["location", "city_state", "region", "place", "hometown"] {
        if let Some(loc) = val_str(item, field)
            && loc.len() >= 3
            && seen.insert(format!("@loc:{}", loc.to_lowercase()))
        {
            let mut e = Entity::new(EntityKind::Address, &loc, 0.55, scan_id);
            e.tag("see-know");
            e.tag(format!("via:{endpoint}"));
            e.tag("geo-hint");
            e.add_evidence(
                Evidence::new(SRC, format!("Location hint from {endpoint}.{field}"))
                    .with_attr("raw_field", field),
            );
            result.push(e);
        }
    }

    // Timezone — feeds the breach_timezone correlator for chronolocation.
    if let Some(tz) = val_str(item, "timezone").or_else(|| val_str(item, "tz"))
        && tz.len() >= 3
        && seen.insert(format!("@tz:{}", tz.to_lowercase()))
    {
        // Timezones don't have their own EntityKind; surface as evidence
        // on a low-confidence Address so the correlator can join.
        let mut e = Entity::new(EntityKind::Address, format!("tz:{tz}"), 0.40, scan_id);
        e.tag("see-know");
        e.tag("timezone");
        e.tag(format!("via:{endpoint}"));
        e.add_evidence(
            Evidence::new(SRC, format!("Timezone from {endpoint}")).with_attr("timezone", &tz),
        );
        result.push(e);
    }

    // ASN / ISP / Organisation — only emit when endpoint is ip_info.
    if endpoint == "ip_info" {
        if let Some(asn) = val_str(item, "asn")
            && seen.insert(format!("@asn:{asn}"))
        {
            let mut e = Entity::new(EntityKind::Asn, &asn, 0.75, scan_id);
            e.tag("see-know");
            e.add_evidence(Evidence::new(SRC, "ASN from SeekNow /network/ip"));
            result.push(e);
        }
        if let Some(org) = val_str(item, "org")
            .or_else(|| val_str(item, "isp"))
            .or_else(|| val_str(item, "company"))
            && seen.insert(format!("@org:{}", org.to_lowercase()))
        {
            let mut e = Entity::new(EntityKind::Organisation, &org, 0.65, scan_id);
            e.tag("see-know");
            e.add_evidence(Evidence::new(SRC, "Organisation from SeekNow /network/ip"));
            result.push(e);
        }
    }

    // WHOIS registrant address (Domain target via /whois endpoint).
    if endpoint == "whois" {
        let parts: Vec<String> = [
            "registrant_street",
            "registrant_city",
            "registrant_state",
            "registrant_postal",
            "registrant_country",
        ]
        .iter()
        .filter_map(|f| val_str(item, f))
        .collect();
        if parts.len() >= 2 {
            let addr = parts.join(", ");
            if seen.insert(format!("@whois-addr:{}", addr.to_lowercase())) {
                let mut e = Entity::new(EntityKind::Address, &addr, 0.70, scan_id);
                e.tag("see-know");
                e.tag("whois-registrant");
                e.add_evidence(Evidence::new(SRC, "Domain WHOIS registrant address"));
                result.push(e);
            }
        }
    }
}

// ─── Entity extraction ─────────────────────────────────────────────────────
//
// SeekNow records share most field names with OathNet's V2 schema. We extract
// the same surface set: email, username, phone, full_name, ip, country,
// city, state, address, dbname, discord_id, plus URL+credential pairs from
// stealer items.

fn extract_entities(
    item: &Value,
    target_value: &str,
    scan_id: &str,
    seen: &mut HashSet<String>,
    result: &mut ModuleResult,
) {
    let dbname = val_str(item, "dbname")
        .or_else(|| val_str(item, "source"))
        .unwrap_or_else(|| "see-know".to_string());
    let ev =
        Evidence::new(SRC, format!("SeekNow record from {dbname}")).with_attr("source", &dbname);

    let target_lower = target_value.to_lowercase();

    if let Some(email) = val_str(item, "email") {
        let lower = email.to_lowercase();
        if lower.contains('@') && seen.insert(lower) {
            let mut e = Entity::new(EntityKind::Email, &email, 0.70, scan_id);
            e.tag(tags::BREACH);
            e.tag("see-know");
            e.add_evidence(ev.clone());
            result.push(e);
        }
    }
    if let Some(uname) = val_str(item, "username") {
        let lower = uname.to_lowercase();
        if lower.len() >= 3 && seen.insert(lower) {
            let mut e = Entity::new(EntityKind::Username, &uname, 0.65, scan_id);
            e.tag(tags::BREACH);
            e.tag("see-know");
            e.add_evidence(ev.clone());
            result.push(e);
        }
    }
    if let Some(phone) = val_str(item, "phone").or_else(|| val_str(item, "phone_number"))
        && phone.len() >= 7
        && seen.insert(phone.to_lowercase())
    {
        let conf = if phone.to_lowercase() == target_lower {
            0.70
        } else {
            0.55
        };
        let mut e = Entity::new(EntityKind::Phone, &phone, conf, scan_id);
        e.tag(tags::BREACH);
        e.tag("see-know");
        e.add_evidence(ev.clone());
        result.push(e);
    }
    if let Some(name) = val_str(item, "full_name").or_else(|| val_str(item, "name"))
        && name.trim().contains(' ')
        && seen.insert(name.to_lowercase())
    {
        let mut e = Entity::new(EntityKind::Person, name.trim(), 0.65, scan_id);
        e.tag(tags::BREACH);
        e.tag("see-know");
        e.add_evidence(ev.clone());
        result.push(e);
    }
    if let Some(ip) = val_str(item, "ip")
        && ip.len() >= 7
        && seen.insert(ip.clone())
    {
        let mut e = Entity::new(EntityKind::IpAddress, &ip, 0.60, scan_id);
        e.tag(tags::BREACH);
        e.tag("see-know");
        e.tag("geolocation-lead");
        e.add_evidence(ev.clone());
        result.push(e);
    }
    if let Some(country) = val_str(item, "country")
        && seen.insert(format!("@country:{country}"))
    {
        let mut e = Entity::new(EntityKind::Address, &country, 0.55, scan_id);
        e.tag(tags::BREACH);
        e.tag("see-know");
        e.add_evidence(ev.clone());
        result.push(e);
    }
    if let Some(did) = val_str(item, "discord_id").or_else(|| val_str(item, "discordid"))
        && seen.insert(format!("@discord:{did}"))
    {
        let mut e = Entity::new(
            EntityKind::Username,
            format!("discord:{did}"),
            0.60,
            scan_id,
        );
        e.tag(tags::BREACH);
        e.tag("see-know");
        e.tag("discord");
        e.add_evidence(ev.clone());
        result.push(e);
    }
    if let Some(domain) = val_str(item, "domain")
        && domain.contains('.')
        && seen.insert(domain.to_lowercase())
    {
        let mut e = Entity::new(EntityKind::Domain, &domain, 0.55, scan_id);
        e.tag("see-know");
        e.add_evidence(ev);
        result.push(e);
    }
}

// ─── Pre-flight helpers (mirrors oathnet_pro to keep behaviour symmetric) ──

fn is_private_ip(ip: &str) -> bool {
    if let Ok(addr) = ip.parse::<std::net::IpAddr>() {
        match addr {
            std::net::IpAddr::V4(v4) => {
                v4.is_loopback()
                    || v4.is_private()
                    || v4.is_link_local()
                    || v4.is_broadcast()
                    || v4.is_unspecified()
                    || v4.is_multicast()
                    || (v4.octets()[0] == 100 && (v4.octets()[1] & 0xC0) == 64)
            }
            std::net::IpAddr::V6(v6) => {
                v6.is_loopback()
                    || v6.is_unspecified()
                    || v6.is_multicast()
                    || (v6.octets()[0] == 0xfc || v6.octets()[0] == 0xfd)
                    || (v6.octets()[0] == 0xfe && (v6.octets()[1] & 0xC0) == 0x80)
            }
        }
    } else {
        false
    }
}

fn is_local_domain(domain: &str) -> bool {
    let d = domain.strip_suffix('.').unwrap_or(domain);
    d.eq_ignore_ascii_case("localhost")
        || d.ends_with(".local")
        || d.ends_with(".lan")
        || d.ends_with(".internal")
        || d.ends_with(".home")
        || d.ends_with(".arpa")
        || d.ends_with(".test")
        || d.ends_with(".invalid")
        || d.ends_with(".example")
        || d.ends_with(".localhost")
}

fn is_placeholder_username(u: &str) -> bool {
    let lower = u.to_lowercase();
    matches!(
        lower.as_str(),
        "anonymous"
            | "anon"
            | "user"
            | "admin"
            | "test"
            | "testing"
            | "demo"
            | "guest"
            | "root"
            | "username"
            | "default"
            | "example"
            | "null"
            | "undefined"
            | "none"
            | "n/a"
            | "na"
            | "unknown"
            | "tbd"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_six_target_kinds() {
        let m = SeekNow;
        for k in [
            TargetKind::Email,
            TargetKind::Username,
            TargetKind::Phone,
            TargetKind::IpAddress,
            TargetKind::Domain,
            TargetKind::FullName,
        ] {
            assert!(m.accepts(&Target::new(k, "x")));
        }
    }

    #[test]
    fn cost_is_paid() {
        assert!(matches!(SeekNow.cost(), ModuleCost::Paid));
    }

    #[test]
    fn priority_below_oathnet_pro() {
        assert!(SeekNow.priority() < 127);
        assert!(SeekNow.priority() >= 120);
    }
}
