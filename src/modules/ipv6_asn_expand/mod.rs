//! IPv6 ASN expansion via BGPView — returns all IPv6 prefixes for an AS number.
//!
//! Complements the existing `bgpview` module (which handles IPv4 and general
//! ASN metadata) with a targeted IPv6-only expansion pass. IPv6 prefixes are
//! increasingly operationally significant as AU ISPs complete their dual-stack
//! deployments; this module makes them first-class `Netblock` entities.
//!
//! API: `GET https://api.bgpview.io/asn/{asn_number}/prefixes`
//!
//! MITRE ATT&CK:
//!   * T1590.001 — Gather Victim Network Information: IP Addresses

mod types;

#[cfg(test)]
mod tests;

use async_trait::async_trait;

use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    error::{Error, Result},
    module::{Module, ModuleCategory, ModuleContext, ModuleCost, ModuleResult},
    scan::{Target, TargetKind},
};
use crate::util::http::{RequestBuilderExt, json_decode};

const SRC: &str = "ipv6_asn_expand";

pub struct Ipv6AsnExpand;

#[async_trait]
impl Module for Ipv6AsnExpand {
    fn name(&self) -> &'static str {
        "ipv6_asn_expand"
    }

    fn description(&self) -> &'static str {
        "Expand an ASN to its announced IPv6 prefix space (BGPView)"
    }

    fn priority(&self) -> u8 {
        44
    }

    fn is_passive(&self) -> bool {
        true
    }

    fn cost(&self) -> ModuleCost {
        ModuleCost::Free
    }

    fn accepts(&self, t: &Target) -> bool {
        t.kind == TargetKind::Asn
    }

    fn max_timeout_ms(&self) -> u64 {
        10_000
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Infrastructure
    }

    fn attack_techniques(&self) -> &'static [&'static str] {
        &["T1590.001"]
    }

    fn produces(&self) -> &'static [EntityKind] {
        const KINDS: &[EntityKind] = &[EntityKind::Cidr];
        KINDS
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let asn_str = target.value.trim();
        let asn_num = asn_str
            .strip_prefix("AS")
            .or_else(|| asn_str.strip_prefix("as"))
            .unwrap_or(asn_str);
        if asn_num.is_empty() {
            return Ok(ModuleResult::new());
        }

        let url = format!("https://api.bgpview.io/asn/{asn_num}/prefixes");

        let resp = ctx
            .http
            .get(&url)
            .header("Accept", "application/json")
            .send_tagged(SRC)
            .await?;

        if resp.status().as_u16() == 404 {
            return Ok(ModuleResult::new());
        }
        if !resp.status().is_success() {
            return Err(Error::module(
                SRC,
                format!("BGPView HTTP {}", resp.status()),
            ));
        }

        let body: types::PrefixResp = json_decode(SRC, resp).await?;

        if body.status.as_deref() != Some("ok") {
            return Ok(ModuleResult::new());
        }

        let prefixes = match body.data {
            Some(d) => d.ipv6_prefixes,
            None => return Ok(ModuleResult::new()),
        };

        let mut result = ModuleResult::with_capacity(prefixes.len());
        for p in prefixes {
            let prefix = p.prefix.trim().to_string();
            if prefix.is_empty() {
                continue;
            }

            let mut e = Entity::new(EntityKind::Cidr, &prefix, 0.85, &ctx.scan_id);
            e.tag("ipv6");
            e.tag("bgpview");
            e.tag(format!("asn:{asn_num}"));
            if let Some(cc) = p.country_code.as_deref() {
                e.tag(format!("country:{cc}"));
            }

            let mut ev = Evidence::new(
                SRC,
                format!("IPv6 prefix {prefix} announced by AS{asn_num}"),
            )
            .with_attr("prefix", &prefix)
            .with_attr("asn", asn_num)
            .with_attr("source", "bgpview.io");
            if let Some(n) = p.name.as_deref() {
                ev = ev.with_attr("name", n);
            }
            if let Some(d) = p.description.as_deref() {
                ev = ev.with_attr("description", d);
            }
            if let Some(cc) = p.country_code.as_deref() {
                ev = ev.with_attr("country_code", cc);
            }

            e.add_evidence(ev);
            result.push(e);
        }

        Ok(result)
    }
}
