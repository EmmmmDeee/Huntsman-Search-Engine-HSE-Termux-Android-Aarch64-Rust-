//! SeekNow record → entity extraction.
//!
//! The pure(ish) extraction layer that turns SeekNow's breach/stealer/OSINT
//! JSON records into graph entities. Split out of `mod.rs` so the `Module`
//! trait impl and per-target dispatch orchestration stay readable, and so the
//! field-mapping / confidence / tagging logic can be unit-tested directly (the
//! `tests` module re-imports these via `super::*`).
//!
//! SeekNow records share most field names with OathNet's V2 schema. We extract
//! the same surface set: email, username, phone, full_name, ip, country,
//! city, state, address, dbname, discord_id, plus URL+credential pairs from
//! stealer items.

use std::collections::HashSet;

use serde_json::Value;

use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    module::ModuleResult,
    tags,
};
use crate::util::extract::EMAIL_RE;
use crate::util::geo::is_valid_coords;
use crate::util::see_know::val_str;
use crate::util::url_util::host_from_url;

use super::SRC;
use super::pivots::looks_like_steam_id;

/// Matches `<@id>` and `<@!id>` Discord user-mention shapes.
static MESSAGE_MENTION_RE: std::sync::LazyLock<regex::Regex> =
    std::sync::LazyLock::new(|| regex::Regex::new(r"<@!?(\d{17,20})>").unwrap());

/// Mine a `discord_messages` item's free-text `content` for embedded emails
/// and emit each as a low-confidence `Email` entity (0.30 — below pivot floor).
pub(super) fn extract_message_emails(
    item: &Value,
    scan_id: &str,
    seen: &mut HashSet<String>,
    result: &mut ModuleResult,
) {
    let Some(content) = val_str(item, "content") else {
        return;
    };
    let ev = Evidence::new(SRC, "SeekNow discord_messages content")
        .with_attr("source", "discord_messages");
    for m in EMAIL_RE.find_iter(&content) {
        let email = m.as_str().to_lowercase();
        if seen.insert(email.clone()) {
            let mut e = Entity::new(EntityKind::Email, &email, 0.30, scan_id);
            e.tag("see-know");
            e.tag("discord-message");
            e.tag("weak-lead");
            e.add_evidence(ev.clone());
            result.push(e);
        }
    }
}

/// Mine a `discord_messages` item's free-text `content` for `<@id>` / `<@!id>`
/// Discord user-mention snowflakes and emit each as a low-confidence `Username`
/// entity (`discord:<id>`, 0.30 — below pivot floor).
pub(super) fn extract_message_mentions(
    item: &Value,
    scan_id: &str,
    seen: &mut HashSet<String>,
    result: &mut ModuleResult,
) {
    let Some(content) = val_str(item, "content") else {
        return;
    };
    let ev = Evidence::new(SRC, "SeekNow discord_messages content")
        .with_attr("source", "discord_messages");
    for caps in MESSAGE_MENTION_RE.captures_iter(&content) {
        let id = &caps[1];
        if seen.insert(format!("@discord:{id}")) {
            let mut e = Entity::new(EntityKind::Username, format!("discord:{id}"), 0.30, scan_id);
            e.tag("see-know");
            e.tag("discord-message");
            e.tag("weak-lead");
            e.tag("mention");
            e.add_evidence(ev.clone());
            result.push(e);
        }
    }
}

/// Geo-conscious extraction — surface coordinates, timezones, and
/// location-bearing fields from any SeekNow endpoint response so the
/// downstream geocode/overpass/wigle modules can converge.
/// First-present-of-`keys` coordinate value, accepting either a JSON number or
/// a numeric string (some SeekNow endpoints serialise lat/lon as strings).
/// Preserves the original semantics: pick the first present key, then read it as
/// an f64 or, failing that, parse its string form.
fn parse_coord(item: &Value, keys: &[&str]) -> Option<f64> {
    let v = keys.iter().find_map(|k| item.get(*k))?;
    v.as_f64().or_else(|| v.as_str()?.parse().ok())
}

pub(super) fn extract_geo_entities(
    item: &Value,
    endpoint: &str,
    scan_id: &str,
    seen: &mut HashSet<String>,
    result: &mut ModuleResult,
) {
    // Direct coordinate fields — some endpoints (ip_info, phone_info)
    // return lat/lon pairs directly, as a JSON number or a numeric string.
    let lat = parse_coord(item, &["latitude", "lat"]);
    let lon = parse_coord(item, &["longitude", "lon", "lng"]);
    // Shared validator: finite + in-range + not-Null-Island. Breach/OSINT
    // aggregators commonly carry 0,0 as a null-location value in records,
    // which the prior range-only check admitted as a false Coordinates entity.
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

/// Build an [`Evidence`] record that preserves EVERY field of the raw source
/// record `item` as an attribute — full fidelity, nothing redacted or omitted
/// (operator data-fidelity policy). Scalars are stored as-is; nested
/// objects/arrays as compact JSON. This is what makes a result traceable to its
/// actual raw source record rather than just a module name + entity hash.
fn record_evidence(item: &Value, dbname: &str, endpoint: &str, key_fp: &str) -> Evidence {
    let ev = Evidence::new(SRC, format!("SeekNow record from {dbname}"))
        .with_attr("source", dbname)
        // Provenance: which provider, which exact API key, and which endpoint
        // returned this record. Stamped on EVERY record so a finding always
        // declares its origin (operator directive: specify the API key origin).
        .with_attr("provider", "see-know.eu")
        .with_attr("api_key_origin", key_fp)
        .with_attr("via_endpoint", endpoint);
    let Some(obj) = item.as_object() else {
        return ev;
    };
    obj.iter().fold(ev, |ev, (k, v)| {
        let val = match v {
            Value::Null => return ev,
            Value::String(s) => s.clone(),
            other => other.to_string(),
        };
        if val.is_empty() {
            return ev;
        }
        // Don't clobber the canonical "source" attribute set above.
        let key = if k == "source" {
            "source_db"
        } else {
            k.as_str()
        };
        ev.with_attr(key, val)
    })
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
    // Full raw record on the evidence chain — every entity derived from this
    // record carries the complete source data plus its provenance (provider,
    // API-key origin, endpoint) for traceability.
    let ev = record_evidence(item, &dbname, endpoint, key_fp);

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
    {
        // Lowercase `phone` once and reuse that single copy for both the dedup
        // key and the target comparison, instead of lowercasing it twice (and
        // the target unconditionally). Preserves the exact prior comparison.
        let phone_lower = phone.to_lowercase();
        if seen.insert(phone_lower.clone()) {
            let conf = if phone_lower == target_value.to_lowercase() {
                0.70
            } else {
                0.55
            };
            push_breach_entity(
                result,
                Entity::new(EntityKind::Phone, &phone, conf, scan_id),
                &ev,
                &[],
            );
        }
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
            Entity::new(
                EntityKind::Username,
                format!("discord:{did}"),
                0.60,
                scan_id,
            ),
            &ev,
            &["discord"],
        );
    }
    // Steam ID — 17-digit 64-bit SteamIDs (steamID64). Surface as a
    // Username with `steam:<id>` prefix so the gaming endpoint pivot
    // can find it without colliding with normal usernames. Matches
    // the discord-pivot pattern.
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
    // Leaked credentials were previously dropped entirely — capture them as
    // first-class Password entities (operator policy: never redacted). The full
    // record (including any hash) is already on `ev`, so nothing is lost even
    // when several credential fields coexist; one pivotable entity is enough.
    for field in [
        "password",
        "passwordHash",
        "password_hash",
        "hashed_password",
        "hash",
    ] {
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
    //
    // The single most OSINT-valuable artifact in a stealer record is the URL
    // the victim had a saved credential for. SeekNow's /stealer endpoint (and
    // the /search auto-route into it) carries it as `url`/`url_str`. Spider it
    // into three pivotable entities — exactly OathNet's proven stealer model —
    // so the rest of the graph (domain enumeration, credential correlation,
    // login-surface mapping) can converge on it:
    //
    //   • the Url itself (the captured login surface);
    //   • its registrable host as a Domain pivot (drives crt.sh, DNS, whois);
    //   • a `<username>@<url>` Credential when a login accompanies the URL.
    //
    // None are tagged `breach`: a saved-login URL is credential CONTEXT /
    // infrastructure, not leaked PII — the same policy `extract_stealer_entities`
    // applies in oathnet_pro, and the same policy the Domain block below uses.
    if let Some(url) = val_str(item, "url").or_else(|| val_str(item, "url_str")) {
        if url.len() >= 4 && seen.insert(format!("@url:{}", url.to_lowercase())) {
            let mut e = Entity::new(EntityKind::Url, &url, 0.60, scan_id);
            e.tag("see-know");
            e.tag("stealer");
            e.add_evidence(ev.clone());
            result.push(e);
        }
        // The URL's host → Domain pivot (eTLD-aware host extraction; dotless /
        // private / scheme-less junk is dropped by `host_from_url`).
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
        // `<username>@<url>` Credential — the login↔surface binding, surfaced as
        // a first-class pivotable entity (operator policy: never redacted).
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

    // Maximum-raw-data pass: surface the long tail of the record (names, full
    // address, organisation, device fingerprints, extra social handles, DOB,
    // and EVERY remaining scalar field) as first-class entities so nothing
    // valuable stays locked inside the evidence blob. Operator directive: "I
    // want everything. Maximum raw data."
    extract_rich_detail(item, scan_id, &ev, seen, result);

    // Domain is infrastructure, not a leaked credential, so it is the one kind
    // NOT tagged `breach` — keep its inline tail (and consume the last `ev`).
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
/// deliberately suppressed as structural/metadata noise). The catch-all pass
/// skips these so it only emits the *long tail* — every other value-bearing
/// field — without duplicating a node already created or surfacing envelope
/// bookkeeping. Lower-cased compare so schema casing variants can't leak through.
const RICH_DETAIL_SKIP: &[&str] = &[
    // Already typed above.
    "email",
    "username",
    "phone",
    "phone_number",
    "full_name",
    "name",
    "ip",
    "country",
    "discord_id",
    "discordid",
    "steam_id",
    "steamid",
    "steam_id64",
    "password",
    "passwordhash",
    "password_hash",
    "hashed_password",
    "hash",
    "url",
    "url_str",
    "domain",
    // Composed/typed in the rich pass itself.
    "first_name",
    "firstname",
    "last_name",
    "lastname",
    "company",
    "employer",
    "organization",
    "organisation",
    "org",
    "mac",
    "mac_address",
    "bssid",
    "hwid",
    "machine_id",
    "device_id",
    "uuid",
    "guid",
    "computer_name",
    "machine",
    "hostname",
    "telegram",
    "skype",
    "facebook",
    "instagram",
    "twitter",
    "linkedin",
    "vk",
    "snapchat",
    "city",
    "state",
    "region",
    "province",
    "zip",
    "zipcode",
    "postal",
    "postal_code",
    "postcode",
    "street",
    "address",
    "address_line",
    // Structural / metadata / provenance bookkeeping (kept verbatim on evidence,
    // but not worth a standalone graph node).
    "source",
    "source_db",
    "dbname",
    "_origin",
    "id",
    "_id",
    "log_id",
    "log",
    "salt",
    "response_time_ms",
    "type",
    "success",
    "total",
    "breach_count",
    "stealer_count",
    "external_count",
    "index",
    "score",
    "_score",
    // Domain WHOIS/RDAP metadata — surfaced as Domain *attributes* by
    // `rdap_domain` / `whoisxml`, not worth duplicating as standalone graph
    // nodes (and `dns` is a record map, never an entity value).
    "registrar",
    "dns",
    "nameservers",
    "name_servers",
    "created",
    "created_date",
    "creation_date",
    "updated",
    "updated_date",
    "last_changed",
    "expires",
    "expiry",
    "expiration_date",
    "status",
    "whois",
];

/// `O(1)` membership view over [`RICH_DETAIL_SKIP`], built once on first use.
/// The catch-all pass runs this lookup per field per record, so a `HashSet`
/// replaces the prior linear scan of ~90 `&str` entries without changing which
/// fields are skipped.
static RICH_DETAIL_SKIP_SET: std::sync::LazyLock<HashSet<&'static str>> =
    std::sync::LazyLock::new(|| RICH_DETAIL_SKIP.iter().copied().collect());

/// Push a stealer/infrastructure-CONTEXT entity: tags `see-know` plus any
/// `extra_tags`, but deliberately NOT `breach`. Device fingerprints (MAC, HWID,
/// hostname, …) are infrastructure/context, not leaked PII — the same policy the
/// URL/Domain/Credential spidering follows — so they must not carry the `breach`
/// tag that [`push_breach_entity`] forces.
fn push_context_entity(
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
/// into first-class, pivotable entities. Typed where a kind fits (Person,
/// Organisation, Address, MacAddress, DeviceId, platform Usernames), and
/// `Other(field)` for everything else — so EVERY value-bearing field of the raw
/// response becomes a node, not just an evidence attribute. Confidences are
/// modest (secondary, record-derived) so this breadth never outranks the
/// primary identity entities.
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

    // ── Names: first + last → a composed Person (the bare `name`/`full_name`
    // path above only fires when the value already contains a space). ──
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

    // ── Organisation / employer. ──
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

    // ── Device fingerprints — strong stealer-log pivots. ──
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
    for k in [
        "hwid",
        "machine_id",
        "device_id",
        "uuid",
        "guid",
        "computer_name",
        "machine",
        "hostname",
    ] {
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

    // ── Extra social handles → platform-prefixed Username pivots. ──
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

    // ── Physical location: each part as its own geo-hint Address, plus a
    // composed multi-part address (street/city/state/postal/country). ──
    let mut addr_parts: Vec<String> = Vec::new();
    for k in [
        "street",
        "address",
        "address_line",
        "city",
        "state",
        "region",
        "province",
        "zip",
        "zipcode",
        "postal",
        "postal_code",
        "postcode",
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

    // ── Catch-all: every remaining value-bearing SCALAR field becomes an
    // `Other(field)` node, so no atomic data point in the raw record is left
    // un-surfaced. Nested objects/arrays are NOT turned into entities — a
    // stringified JSON blob (e.g. a `dns` record map) is not a meaningful graph
    // node and only pollutes the entity set; its atomic contents are surfaced by
    // the typed paths above and by the dedicated DNS/RDAP modules. ──
    for (k, v) in obj {
        // O(1) set lookup instead of a linear scan of ~90 entries per field.
        // The skip list is all-lowercase; only pay for a lowercased copy when
        // `k` actually contains uppercase ASCII (the common case is already
        // lowercase, so no allocation), preserving the case-insensitive match.
        let skip = if k.bytes().any(|b| b.is_ascii_uppercase()) {
            RICH_DETAIL_SKIP_SET.contains(k.to_lowercase().as_str())
        } else {
            RICH_DETAIL_SKIP_SET.contains(k.as_str())
        };
        if skip {
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
/// push it onto `result`. Centralises the tag+evidence+push tail that every
/// breach-derived entity kind shares.
fn push_breach_entity(
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
