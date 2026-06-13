//! Entity extraction from SeekNow API response items.
//!
//! `extract_entities` is the primary extractor — called for every item from
//! every endpoint. `extract_rich_detail` is the maximum-raw-data pass that
//! surfaces the long tail of typed and catch-all entities. `extract_geo_entities`
//! handles coordinates, timezones, and location strings.

use std::collections::HashSet;

use serde_json::Value;

use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    module::ModuleResult,
    tags,
};
use crate::util::geo::is_valid_coords;
use crate::util::see_know::val_str;
use crate::util::url_util::host_from_url;

use super::pivots::looks_like_steam_id;
use super::SRC;

pub(super) fn record_evidence(
    item: &Value,
    dbname: &str,
    endpoint: &str,
    key_fp: &str,
) -> Evidence {
    let mut ev = Evidence::new(SRC, format!("SeekNow record from {dbname}"))
        .with_attr("source", dbname)
        .with_attr("provider", "see-know.eu")
        .with_attr("api_key_origin", key_fp)
        .with_attr("via_endpoint", endpoint);
    if let Some(obj) = item.as_object() {
        for (k, v) in obj {
            let val = match v {
                Value::Null => continue,
                Value::String(s) => s.clone(),
                other => other.to_string(),
            };
            if val.is_empty() {
                continue;
            }
            let key = if k == "source" { "source_db" } else { k.as_str() };
            ev = ev.with_attr(key, val);
        }
    }
    ev
}

pub(super) fn extract_entities(
    item: &Value,
    target_value: &str,
    scan_id: &str,
    endpoint: &str,
    key_fp: &str,
    seen: &mut HashSet<String>,
    result: &mut ModuleResult,
) {
    let dbname = val_str(item, "dbname")
        .or_else(|| val_str(item, "source"))
        .unwrap_or_else(|| "see-know".to_string());
    let ev = record_evidence(item, &dbname, endpoint, key_fp);

    let target_lower = target_value.to_lowercase();

    if let Some(email) = val_str(item, "email") {
        let lower = email.to_lowercase();
        if lower.contains('@') && seen.insert(lower) {
            push_breach_entity(
                result,
                Entity::new(EntityKind::Email, &email, 0.70, scan_id),
                &ev,
                &[],
            );
        }
    }
    if let Some(uname) = val_str(item, "username") {
        let lower = uname.to_lowercase();
        if lower.len() >= 3 && seen.insert(lower) {
            push_breach_entity(
                result,
                Entity::new(EntityKind::Username, &uname, 0.65, scan_id),
                &ev,
                &[],
            );
        }
    }
    if let Some(phone) = val_str(item, "phone").or_else(|| val_str(item, "phone_number"))
        && phone.len() >= 7
        && seen.insert(phone.to_lowercase())
    {
        let conf = if phone.to_lowercase() == target_lower { 0.70 } else { 0.55 };
        push_breach_entity(
            result,
            Entity::new(EntityKind::Phone, &phone, conf, scan_id),
            &ev,
            &[],
        );
    }
    if let Some(name) = val_str(item, "full_name").or_else(|| val_str(item, "name"))
        && name.trim().contains(' ')
        && seen.insert(name.to_lowercase())
    {
        push_breach_entity(
            result,
            Entity::new(EntityKind::Person, name.trim(), 0.65, scan_id),
            &ev,
            &[],
        );
    }
    if let Some(ip) = val_str(item, "ip")
        && ip.len() >= 7
        && seen.insert(ip.clone())
    {
        push_breach_entity(
            result,
            Entity::new(EntityKind::IpAddress, &ip, 0.60, scan_id),
            &ev,
            &["geolocation-lead"],
        );
    }
    if let Some(country) = val_str(item, "country")
        && seen.insert(format!("@country:{country}"))
    {
        push_breach_entity(
            result,
            Entity::new(EntityKind::Address, &country, 0.55, scan_id),
            &ev,
            &[],
        );
    }
    if let Some(did) = val_str(item, "discord_id").or_else(|| val_str(item, "discordid"))
        && seen.insert(format!("@discord:{did}"))
    {
        push_breach_entity(
            result,
            Entity::new(EntityKind::Username, format!("discord:{did}"), 0.60, scan_id),
            &ev,
            &["discord"],
        );
    }
    if let Some(sid) = val_str(item, "steam_id")
        .or_else(|| val_str(item, "steamid"))
        .or_else(|| val_str(item, "steam_id64"))
        && looks_like_steam_id(&sid)
        && seen.insert(format!("@steam:{sid}"))
    {
        push_breach_entity(
            result,
            Entity::new(EntityKind::Username, format!("steam:{sid}"), 0.60, scan_id),
            &ev,
            &["steam"],
        );
    }
    for field in ["password", "passwordHash", "password_hash", "hashed_password", "hash"] {
        if let Some(pw) = val_str(item, field)
            && !pw.is_empty()
            && seen.insert(format!("@pw:{pw}"))
        {
            push_breach_entity(
                result,
                Entity::new(EntityKind::Password, &pw, 0.75, scan_id),
                &ev,
                &["credential"],
            );
            break;
        }
    }

    // ── Stealer-log saved-credential URL ──────────────────────────────────
    if let Some(url) = val_str(item, "url").or_else(|| val_str(item, "url_str")) {
        if url.len() >= 4 && seen.insert(format!("@url:{}", url.to_lowercase())) {
            let mut e = Entity::new(EntityKind::Url, &url, 0.60, scan_id);
            e.tag("see-know");
            e.tag("stealer");
            e.add_evidence(ev.clone());
            result.push(e);
        }
        if let Some(host) = host_from_url(&url)
            && seen.insert(format!("@stealer-dom:{host}"))
        {
            let mut e = Entity::new(EntityKind::Domain, &host, 0.55, scan_id);
            e.tag("see-know");
            e.tag("stealer");
            e.add_evidence(
                Evidence::new(SRC, format!("Stealer credential captured for {host}"))
                    .with_attr("url", &url),
            );
            result.push(e);
        }
        if let Some(uname) = val_str(item, "username") {
            let cred_val = format!("{uname}@{url}");
            if seen.insert(format!("@cred:{}", cred_val.to_lowercase())) {
                let mut e = Entity::new(EntityKind::Credential, &cred_val, 0.60, scan_id);
                e.tag("see-know");
                e.tag("stealer");
                e.add_evidence(ev.clone());
                result.push(e);
            }
        }
    }

    extract_rich_detail(item, scan_id, &ev, seen, result);

    // Domain is infrastructure, not a leaked credential — NOT tagged `breach`.
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

/// Field names already turned into typed entities by `extract_entities` (or
/// deliberately suppressed as structural/metadata noise). Lower-cased compare
/// so schema casing variants can't leak through.
const RICH_DETAIL_SKIP: &[&str] = &[
    "email", "username", "phone", "phone_number", "full_name", "name", "ip", "country",
    "discord_id", "discordid", "steam_id", "steamid", "steam_id64", "password", "passwordhash",
    "password_hash", "hashed_password", "hash", "url", "url_str", "domain",
    "first_name", "firstname", "last_name", "lastname", "company", "employer", "organization",
    "organisation", "org", "mac", "mac_address", "bssid", "hwid", "machine_id", "device_id",
    "uuid", "guid", "computer_name", "machine", "hostname", "telegram", "skype", "facebook",
    "instagram", "twitter", "linkedin", "vk", "snapchat", "city", "state", "region", "province",
    "zip", "zipcode", "postal", "postal_code", "postcode", "street", "address", "address_line",
    "source", "source_db", "dbname", "_origin", "id", "_id", "log_id", "log", "salt",
    "response_time_ms", "type", "success", "total", "breach_count", "stealer_count",
    "external_count", "index", "score", "_score",
    "registrar", "dns", "nameservers", "name_servers", "created", "created_date",
    "creation_date", "updated", "updated_date", "last_changed", "expires", "expiry",
    "expiration_date", "status", "whois",
];

/// Push a stealer/infrastructure-CONTEXT entity: tags `see-know` plus any
/// `extra_tags`, but deliberately NOT `breach`. Device fingerprints (MAC, HWID,
/// hostname, …) are infrastructure/context, not leaked PII.
pub(super) fn push_context_entity(
    result: &mut ModuleResult,
    mut e: Entity,
    ev: &Evidence,
    extra_tags: &[&str],
) {
    e.tag("see-know");
    for t in extra_tags {
        e.tag(*t);
    }
    e.add_evidence(ev.clone());
    result.push(e);
}

/// Maximum-raw-data extractor: turn the long tail of a breach/stealer record
/// into first-class, pivotable entities. Typed where a kind fits, and
/// `Other(field)` for everything else — so EVERY value-bearing field becomes
/// a node.
fn extract_rich_detail(
    item: &Value,
    scan_id: &str,
    ev: &Evidence,
    seen: &mut HashSet<String>,
    result: &mut ModuleResult,
) {
    let Some(obj) = item.as_object() else {
        return;
    };

    let first = val_str(item, "first_name").or_else(|| val_str(item, "firstname"));
    let last = val_str(item, "last_name").or_else(|| val_str(item, "lastname"));
    if let (Some(f), Some(l)) = (&first, &last) {
        let full = format!("{} {}", f.trim(), l.trim());
        if full.len() >= 3 && seen.insert(format!("@person:{}", full.to_lowercase())) {
            push_breach_entity(
                result,
                Entity::new(EntityKind::Person, &full, 0.60, scan_id),
                ev,
                &[],
            );
        }
    }

    for k in ["company", "employer", "organization", "organisation", "org"] {
        if let Some(o) = val_str(item, k)
            && o.len() >= 2
            && seen.insert(format!("@org:{}", o.to_lowercase()))
        {
            push_breach_entity(
                result,
                Entity::new(EntityKind::Organisation, &o, 0.50, scan_id),
                ev,
                &[],
            );
        }
    }

    for k in ["mac", "mac_address", "bssid"] {
        if let Some(m) = val_str(item, k)
            && m.len() >= 12
            && seen.insert(format!("@mac:{}", m.to_lowercase()))
        {
            push_context_entity(
                result,
                Entity::new(EntityKind::MacAddress, &m, 0.60, scan_id),
                ev,
                &["device"],
            );
        }
    }
    for k in ["hwid", "machine_id", "device_id", "uuid", "guid", "computer_name", "machine", "hostname"] {
        if let Some(d) = val_str(item, k)
            && d.len() >= 3
            && seen.insert(format!("@device:{k}:{}", d.to_lowercase()))
        {
            push_context_entity(
                result,
                Entity::new(EntityKind::DeviceId, &d, 0.55, scan_id),
                ev,
                &["device", "stealer"],
            );
        }
    }

    for (k, plat) in [
        ("telegram", "telegram"),
        ("skype", "skype"),
        ("facebook", "facebook"),
        ("instagram", "instagram"),
        ("twitter", "twitter"),
        ("linkedin", "linkedin"),
        ("vk", "vk"),
        ("snapchat", "snapchat"),
    ] {
        if let Some(h) = val_str(item, k)
            && h.len() >= 2
            && seen.insert(format!("@{plat}:{}", h.to_lowercase()))
        {
            push_breach_entity(
                result,
                Entity::new(EntityKind::Username, format!("{plat}:{h}"), 0.55, scan_id),
                ev,
                &[plat],
            );
        }
    }

    let mut addr_parts: Vec<String> = Vec::new();
    for k in [
        "street", "address", "address_line", "city", "state", "region", "province",
        "zip", "zipcode", "postal", "postal_code", "postcode",
    ] {
        if let Some(p) = val_str(item, k)
            && p.len() >= 2
        {
            if seen.insert(format!("@addr-part:{k}:{}", p.to_lowercase())) {
                push_breach_entity(
                    result,
                    Entity::new(EntityKind::Address, &p, 0.45, scan_id),
                    ev,
                    &["geo-hint"],
                );
            }
            addr_parts.push(p);
        }
    }
    if addr_parts.len() >= 2 {
        if let Some(c) = val_str(item, "country") {
            addr_parts.push(c);
        }
        let composed = addr_parts.join(", ");
        if seen.insert(format!("@addr:{}", composed.to_lowercase())) {
            push_breach_entity(
                result,
                Entity::new(EntityKind::Address, &composed, 0.55, scan_id),
                ev,
                &["geo-hint", "composed-address"],
            );
        }
    }

    // Catch-all: every remaining value-bearing scalar field → Other(field).
    for (k, v) in obj {
        if RICH_DETAIL_SKIP.contains(&k.to_lowercase().as_str()) {
            continue;
        }
        let val = match v {
            Value::Null | Value::Array(_) | Value::Object(_) => continue,
            Value::String(s) => s.clone(),
            Value::Bool(b) => b.to_string(),
            Value::Number(n) => n.to_string(),
        };
        if val.is_empty() || val.len() > 2000 {
            continue;
        }
        if seen.insert(format!("@other:{k}:{}", val.to_lowercase())) {
            push_breach_entity(
                result,
                Entity::new(EntityKind::Other(k.clone()), &val, 0.40, scan_id),
                ev,
                &["raw-field"],
            );
        }
    }
}

/// Apply see_know's standard breach tags (`breach`, `see-know`, plus any
/// endpoint-specific `extra_tags`) and a cloned evidence record to `e`, then
/// push it onto `result`.
pub(super) fn push_breach_entity(
    result: &mut ModuleResult,
    mut e: Entity,
    ev: &Evidence,
    extra_tags: &[&str],
) {
    e.tag(tags::BREACH);
    e.tag("see-know");
    for t in extra_tags {
        e.tag(*t);
    }
    e.add_evidence(ev.clone());
    result.push(e);
}

/// Geo-conscious extraction — surface coordinates, timezones, and
/// location-bearing fields from any SeekNow endpoint response.
pub(super) fn extract_geo_entities(
    item: &Value,
    endpoint: &str,
    scan_id: &str,
    seen: &mut HashSet<String>,
    result: &mut ModuleResult,
) {
    let lat = parse_coord(item, &["latitude", "lat"]);
    let lon = parse_coord(item, &["longitude", "lon", "lng"]);
    if let (Some(la), Some(lo)) = (lat, lon)
        && is_valid_coords(la, lo)
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

    if let Some(tz) = val_str(item, "timezone").or_else(|| val_str(item, "tz"))
        && tz.len() >= 3
        && seen.insert(format!("@tz:{}", tz.to_lowercase()))
    {
        let mut e = Entity::new(EntityKind::Address, format!("tz:{tz}"), 0.40, scan_id);
        e.tag("see-know");
        e.tag("timezone");
        e.tag(format!("via:{endpoint}"));
        e.add_evidence(
            Evidence::new(SRC, format!("Timezone from {endpoint}")).with_attr("timezone", &tz),
        );
        result.push(e);
    }

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
            && org.len() >= 2
            && seen.insert(format!("@org:{}", org.to_lowercase()))
        {
            let mut e = Entity::new(EntityKind::Organisation, &org, 0.55, scan_id);
            e.tag("see-know");
            e.add_evidence(Evidence::new(SRC, "ISP/Org from SeekNow /network/ip"));
            result.push(e);
        }
    }

    // WHOIS registrant address.
    if endpoint == "whois" {
        let parts: Vec<String> = ["registrant_city", "registrant_state", "registrant_country"]
            .iter()
            .filter_map(|k| val_str(item, k))
            .filter(|p| !p.is_empty())
            .collect();
        if parts.len() >= 2 {
            let composed = parts.join(", ");
            if seen.insert(format!("@whois-addr:{}", composed.to_lowercase())) {
                let mut e = Entity::new(EntityKind::Address, &composed, 0.60, scan_id);
                e.tag("see-know");
                e.tag("whois-registrant");
                e.add_evidence(
                    Evidence::new(SRC, "WHOIS registrant address from SeekNow /domain/whois"),
                );
                result.push(e);
            }
        }
    }
}

fn parse_coord(item: &Value, keys: &[&str]) -> Option<f64> {
    let v = keys.iter().find_map(|k| item.get(*k))?;
    v.as_f64().or_else(|| v.as_str()?.parse().ok())
}
