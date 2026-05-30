//! Merged IP registration + ASN module: RDAP (Registry Data Access
//! Protocol) allocation records **and** BGPView ASN / prefix lookups.
//!
//! For `IpAddress` targets both RDAP and BGPView are queried
//! concurrently. For `Asn` targets only BGPView is used.
//!
//! RDAP endpoint: `https://rdap.arin.net/registry/ip/{ip}` (ARIN
//! redirects to the matching RIR when necessary; `reqwest` follows
//! redirects transparently).
//!
//! BGPView endpoints:
//!   - `https://api.bgpview.io/asn/{asn}` (ASN registry record)
//!   - `https://api.bgpview.io/ip/{ip}`   (IP-to-ASN reverse mapping)
//!
//! Both APIs are free, keyless, and rate-limited to ~1 req/s.

use async_trait::async_trait;
use serde::Deserialize;

use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::{Module, ModuleCategory, ModuleContext, ModuleResult},
    scan::{Target, TargetKind},
};
use crate::util::http::fetch_json_or_404;

// ---------------------------------------------------------------------------
// Public module struct
// ---------------------------------------------------------------------------

pub struct IpRegistry;

// ---------------------------------------------------------------------------
// RDAP response types
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct RdapResp {
    #[serde(default)]
    handle: Option<String>,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    country: Option<String>,
    #[serde(default, rename = "startAddress")]
    start_address: Option<String>,
    #[serde(default, rename = "endAddress")]
    end_address: Option<String>,
    #[serde(default, rename = "ipVersion")]
    ip_version: Option<String>,
    #[serde(default, rename = "parentHandle")]
    parent_handle: Option<String>,
    #[serde(default, rename = "cidr0_cidrs")]
    cidr0_cidrs: Vec<CidrEntry>,
    #[serde(default)]
    events: Vec<RdapEvent>,
}

#[derive(Deserialize)]
struct CidrEntry {
    #[serde(default)]
    v4prefix: Option<String>,
    #[serde(default)]
    v6prefix: Option<String>,
    #[serde(default)]
    length: Option<u8>,
}

#[derive(Deserialize)]
struct RdapEvent {
    #[serde(rename = "eventAction")]
    action: String,
    #[serde(default, rename = "eventDate")]
    date: Option<String>,
}

// ---------------------------------------------------------------------------
// BGPView response types — ASN lookup
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct AsnResp {
    data: Option<AsnData>,
    status: String,
}

#[derive(Deserialize)]
struct AsnData {
    name: Option<String>,
    description_short: Option<String>,
    country_code: Option<String>,
    rir_allocation: Option<RirInfo>,
    email_contacts: Option<Vec<String>>,
    abuse_contacts: Option<Vec<String>>,
    website: Option<String>,
}

#[derive(Deserialize)]
struct RirInfo {
    rir_name: Option<String>,
    date_allocated: Option<String>,
}

// ---------------------------------------------------------------------------
// BGPView response types — IP lookup
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct IpResp {
    data: Option<IpData>,
    status: String,
}

#[derive(Deserialize)]
struct IpData {
    prefixes: Option<Vec<PrefixInfo>>,
}

#[derive(Deserialize)]
struct PrefixInfo {
    prefix: Option<String>,
    asn: Option<AsnRef>,
}

#[derive(Deserialize)]
struct AsnRef {
    asn: Option<u64>,
    name: Option<String>,
    description: Option<String>,
    country_code: Option<String>,
}

// ---------------------------------------------------------------------------
// Evidence source constant
// ---------------------------------------------------------------------------

const SRC: &str = "ip_registry";

// ---------------------------------------------------------------------------
// Module trait implementation
// ---------------------------------------------------------------------------

#[async_trait]
impl Module for IpRegistry {
    fn name(&self) -> &'static str {
        "ip_registry"
    }

    fn description(&self) -> &'static str {
        "IP registration and ASN data via RDAP and BGPView"
    }

    fn priority(&self) -> u8 {
        23
    }

    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::IpAddress | TargetKind::Asn)
    }

    fn max_timeout_ms(&self) -> u64 {
        8_000
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Infrastructure
    }

    fn produces(&self) -> &'static [EntityKind] {
        const KINDS: &[EntityKind] = &[
            EntityKind::Asn,
            EntityKind::Email,
            EntityKind::IpAddress,
            EntityKind::Url,
        ];
        KINDS
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        match target.kind {
            TargetKind::IpAddress => process_ip(target, ctx).await,
            TargetKind::Asn => bgp_lookup_asn(target, ctx).await,
            _ => Ok(ModuleResult::new()),
        }
    }
}

// ---------------------------------------------------------------------------
// IpAddress path: RDAP + BGPView (both)
// ---------------------------------------------------------------------------

async fn process_ip(target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
    let ip = target.value.trim();

    // Run both lookups concurrently.
    let (rdap_res, bgp_res) = tokio::join!(rdap_lookup_ip(ip, ctx), bgp_lookup_ip(ip, ctx),);

    let mut result = rdap_res?;
    let bgp = bgp_res?;

    for entity in bgp.entities {
        result.push(entity);
    }
    Ok(result)
}

// ---------------------------------------------------------------------------
// RDAP: IP allocation record
// ---------------------------------------------------------------------------

async fn rdap_lookup_ip(ip: &str, ctx: &ModuleContext) -> Result<ModuleResult> {
    let url = format!("https://rdap.arin.net/registry/ip/{ip}");
    let Some(body): Option<RdapResp> = fetch_json_or_404(&ctx.http, SRC, &url).await? else {
        return Ok(ModuleResult::new());
    };

    let cidr = body
        .cidr0_cidrs
        .iter()
        .find_map(|c| {
            let p = c.v4prefix.as_deref().or(c.v6prefix.as_deref())?;
            Some(match c.length {
                Some(l) => format!("{p}/{l}"),
                None => p.to_string(),
            })
        })
        .or_else(
            || match (body.start_address.as_deref(), body.end_address.as_deref()) {
                (Some(s), Some(e)) => Some(format!("{s} – {e}")),
                _ => None,
            },
        );

    let mut entity = Entity::new(EntityKind::IpAddress, ip, 0.90, &ctx.scan_id);
    entity.tag("rdap");
    if let Some(c) = body.country.as_deref() {
        entity.tag(format!("country:{}", c.to_uppercase()));
    }

    let mut ev = Evidence::new(SRC, format!("RDAP allocation record for {ip}"));
    if let Some(h) = body.handle.as_deref() {
        ev = ev.with_attr("handle", h);
    }
    if let Some(n) = body.name.as_deref() {
        ev = ev.with_attr("name", n);
    }
    if let Some(c) = body.country.as_deref() {
        ev = ev.with_attr("country", c);
    }
    if let Some(c) = cidr.as_deref() {
        ev = ev.with_attr("prefix", c);
    }
    if let Some(v) = body.ip_version.as_deref() {
        ev = ev.with_attr("ip_version", v);
    }
    if let Some(p) = body.parent_handle.as_deref() {
        ev = ev.with_attr("parent_handle", p);
    }
    for evt in &body.events {
        if let Some(d) = evt.date.as_deref() {
            let mut key = String::with_capacity(7 + evt.action.len());
            key.push_str("event:");
            for c in evt.action.chars() {
                key.push(if c == ' ' { '_' } else { c });
            }
            ev = ev.with_attr(key, d);
        }
    }
    entity.add_evidence(ev);

    let mut result = ModuleResult::new();
    result.push(entity);
    Ok(result)
}

// ---------------------------------------------------------------------------
// BGPView: IP-to-ASN reverse mapping
// ---------------------------------------------------------------------------

async fn bgp_lookup_ip(ip: &str, ctx: &ModuleContext) -> Result<ModuleResult> {
    let url = format!("https://api.bgpview.io/ip/{ip}");
    let Some(body): Option<IpResp> = fetch_json_or_404(&ctx.http, SRC, &url).await? else {
        return Ok(ModuleResult::new());
    };
    if body.status != "ok" {
        return Ok(ModuleResult::new());
    }
    let Some(data) = body.data else {
        return Ok(ModuleResult::new());
    };

    let mut result = ModuleResult::new();
    // Take only the most-specific (first) prefix announcement — bgpview
    // returns them ordered by length descending.
    if let Some(prefix) = data.prefixes.into_iter().flatten().next()
        && let Some(asn_ref) = prefix.asn
        && let Some(asn_num) = asn_ref.asn
    {
        let asn_num_str = asn_num.to_string();
        let mut e = Entity::new(EntityKind::Asn, format!("AS{asn_num}"), 0.88, &ctx.scan_id);
        e.tag("announcing");
        let mut ev = Evidence::new(SRC, format!("ASN announcing {ip}"))
            .with_attr("asn_number", &asn_num_str);
        if let Some(p) = prefix.prefix.as_deref() {
            ev = ev.with_attr("prefix", p);
        }
        if let Some(n) = asn_ref.name.as_deref() {
            ev = ev.with_attr("handle", n);
        }
        if let Some(d) = asn_ref.description.as_deref() {
            ev = ev.with_attr("name", d);
        }
        if let Some(c) = asn_ref.country_code.as_deref() {
            ev = ev.with_attr("country", c);
        }
        e.add_evidence(ev);
        result.push(e);
    }
    Ok(result)
}

// ---------------------------------------------------------------------------
// BGPView: ASN registry record
// ---------------------------------------------------------------------------

async fn bgp_lookup_asn(target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
    let raw = target.value.trim().to_uppercase();
    // Accept both "AS15169" and "15169".
    let digits = raw.trim_start_matches("AS").trim();
    let asn: u64 = match digits.parse() {
        Ok(n) => n,
        Err(_) => return Ok(ModuleResult::new()),
    };

    let url = format!("https://api.bgpview.io/asn/{asn}");
    let Some(body): Option<AsnResp> = fetch_json_or_404(&ctx.http, SRC, &url).await? else {
        return Ok(ModuleResult::new());
    };

    if body.status != "ok" {
        return Ok(ModuleResult::new());
    }
    let Some(data) = body.data else {
        return Ok(ModuleResult::new());
    };

    let mut result = ModuleResult::new();
    let asn_label = format!("AS{asn}");
    let asn_str = asn.to_string();
    let mut entity = Entity::new(EntityKind::Asn, &asn_label, 0.92, &ctx.scan_id);
    entity.tag("registered");

    let mut ev = Evidence::new(SRC, format!("ASN {asn_label} registry record"))
        .with_attr("asn_number", &asn_str);
    if let Some(n) = data.name.as_deref() {
        ev = ev.with_attr("handle", n);
    }
    if let Some(d) = data.description_short.as_deref() {
        ev = ev.with_attr("name", d);
    }
    if let Some(c) = data.country_code.as_deref() {
        ev = ev.with_attr("country", c);
    }
    if let Some(rir) = &data.rir_allocation {
        if let Some(n) = rir.rir_name.as_deref() {
            ev = ev.with_attr("rir", n);
        }
        if let Some(d) = rir.date_allocated.as_deref() {
            ev = ev.with_attr("allocated", d);
        }
    }
    if let Some(w) = data.website.as_deref()
        && !w.is_empty()
    {
        ev = ev.with_attr("website", w);
    }
    entity.add_evidence(ev);
    result.push(entity);

    // Surface contact emails as discrete Email entities.
    for email in data.email_contacts.into_iter().flatten() {
        if !email.contains('@') {
            continue;
        }
        let mut e = Entity::new(EntityKind::Email, &email, 0.78, &ctx.scan_id);
        e.tag("asn-contact");
        e.tag("role:admin");
        e.add_evidence(
            Evidence::new(SRC, format!("Contact for {asn_label}"))
                .with_attr("source", "bgpview")
                .with_attr("asn", &asn_str)
                .with_attr("contact_role", "admin"),
        );
        result.push(e);
    }
    for email in data.abuse_contacts.into_iter().flatten() {
        if !email.contains('@') {
            continue;
        }
        let mut e = Entity::new(EntityKind::Email, &email, 0.78, &ctx.scan_id);
        e.tag("asn-contact");
        e.tag("role:abuse");
        e.add_evidence(
            Evidence::new(SRC, format!("Contact for {asn_label}"))
                .with_attr("source", "bgpview")
                .with_attr("asn", &asn_str)
                .with_attr("contact_role", "abuse"),
        );
        result.push(e);
    }

    // If the AS has a website, emit it as a Url entity.
    if let Some(w) = data
        .website
        .as_deref()
        .filter(|w| w.starts_with("http://") || w.starts_with("https://"))
    {
        let mut u = Entity::new(EntityKind::Url, w, 0.75, &ctx.scan_id);
        u.tag("asn-website");
        u.add_evidence(
            Evidence::new(SRC, format!("Website of {asn_label}")).with_attr("asn", &asn_str),
        );
        result.push(u);
    }

    Ok(result)
}

// ---------------------------------------------------------------------------
// Tests (preserved from ip_rdap.rs + bgpview.rs)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_ip_and_asn() {
        let m = IpRegistry;
        assert!(m.accepts(&Target::new(TargetKind::IpAddress, "1.1.1.1")));
        assert!(m.accepts(&Target::new(TargetKind::Asn, "AS15169")));
        assert!(!m.accepts(&Target::new(TargetKind::Domain, "x")));
    }

    #[test]
    fn priority_and_timeout() {
        let m = IpRegistry;
        assert_eq!(m.priority(), 23);
        assert_eq!(m.max_timeout_ms(), 8_000);
    }

    #[test]
    fn parse_arin_rdap_response() {
        // Trimmed ARIN RDAP response for 8.8.8.8.
        let raw = r#"{
          "handle":"NET-8-8-8-0-1",
          "name":"LVLT-GOGL-8-8-8",
          "country":"US",
          "startAddress":"8.8.8.0",
          "endAddress":"8.8.8.255",
          "ipVersion":"v4",
          "parentHandle":"NET-8-0-0-0-0",
          "cidr0_cidrs":[{"v4prefix":"8.8.8.0","length":24}],
          "events":[
            {"eventAction":"last changed","eventDate":"2014-03-14T16:52:05-04:00"},
            {"eventAction":"registration","eventDate":"2014-03-14T16:52:05-04:00"}
          ]
        }"#;
        let r: RdapResp = serde_json::from_str(raw).unwrap();
        assert_eq!(r.handle.as_deref(), Some("NET-8-8-8-0-1"));
        assert_eq!(r.country.as_deref(), Some("US"));
        assert_eq!(r.cidr0_cidrs.len(), 1);
        assert_eq!(r.events.len(), 2);
    }

    #[test]
    fn parse_bgpview_asn_response() {
        let raw = r#"{
          "status": "ok",
          "data": {
            "name": "GOOGLE",
            "description_short": "Google LLC",
            "country_code": "US",
            "rir_allocation": {"rir_name": "ARIN", "date_allocated": "2000-03-30"},
            "email_contacts": ["noc@google.com"],
            "abuse_contacts": ["abuse@google.com"],
            "website": "https://about.google"
          }
        }"#;
        let r: AsnResp = serde_json::from_str(raw).unwrap();
        assert_eq!(r.status, "ok");
        let data = r.data.unwrap();
        assert_eq!(data.name.as_deref(), Some("GOOGLE"));
        assert_eq!(data.country_code.as_deref(), Some("US"));
    }
}
