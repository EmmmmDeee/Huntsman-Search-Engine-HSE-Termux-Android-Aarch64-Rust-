//! RDAP (Registry Data Access Protocol) lookup for an IP.
//!
//! Endpoint: `https://rdap.arin.net/registry/ip/{ip}`. ARIN handles the
//! 307-redirect to the matching RIR (RIPE / APNIC / LACNIC / AFRINIC)
//! when the IP isn't in ARIN's space. `reqwest` follows redirects by
//! default so the caller sees the final RIR response transparently.
//!
//! Surfaces the assignment record: handle, network name, country,
//! parent prefix, allocation/last-changed dates. Complements `whois`
//! and `bgpview` — those give holder + announcing-ASN respectively;
//! RDAP gives the *registry* view including normalised dates.

use async_trait::async_trait;
use serde::Deserialize;

use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::{Module, ModuleContext, ModuleResult},
    scan::{Target, TargetKind},
};
use crate::util::http::fetch_json_or_404;

pub struct IpRdap;

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

#[async_trait]
impl Module for IpRdap {
    fn name(&self) -> &'static str {
        "ip_rdap"
    }

    fn priority(&self) -> u8 {
        27
    }

    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::IpAddress)
    }

    fn max_timeout_ms(&self) -> u64 {
        // ARIN's redirect to a non-US RIR can add ~1 s to the round-trip.
        8_000
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let Some(ip) = target.trimmed() else {
            return Ok(ModuleResult::new());
        };

        let url = format!("https://rdap.arin.net/registry/ip/{ip}");
        let Some(body): Option<RdapResp> = fetch_json_or_404(&ctx.http, "ip_rdap", &url).await?
        else {
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
            entity.tag_country(c);
        }

        let mut ev = Evidence::new("ip_rdap", format!("RDAP allocation record for {ip}"));
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
            // Common eventAction values: "registration", "last changed",
            // "last reregistration", "expiration", "deletion".
            if let Some(d) = evt.date.as_deref() {
                let key = format!("event:{}", evt.action.replace(' ', "_"));
                ev = ev.with_attr(key, d);
            }
        }
        entity.add_evidence(ev);

        let mut result = ModuleResult::new();
        result.push(entity);
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_only_ip() {
        let m = IpRdap;
        assert!(m.accepts(&Target::new(TargetKind::IpAddress, "1.1.1.1")));
        assert!(!m.accepts(&Target::new(TargetKind::Domain, "x")));
    }

    #[test]
    fn parse_arin_response() {
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
}
