//! IPv6 ASN expansion via BGPView.
//!
//! Given an `Asn` target (e.g. `"AS1234"`), fetches all IPv6 prefixes
//! announced by that AS from the BGPView API and emits them as `Cidr`
//! entities.

use async_trait::async_trait;

use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::{Module, ModuleCategory, ModuleCost, ModuleContext, ModuleResult},
    scan::{Target, TargetKind},
};
use crate::util::http::fetch_json;
use crate::util::str_util::nonempty;

mod types;
use types::PrefixResponse;

const SRC: &str = "ipv6_asn_expand";

pub struct Ipv6AsnExpand;

#[async_trait]
impl Module for Ipv6AsnExpand {
    fn name(&self) -> &'static str {
        SRC
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
        matches!(t.kind, TargetKind::Asn)
    }

    fn max_timeout_ms(&self) -> u64 {
        10_000
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Infrastructure
    }

    fn attack_techniques(&self) -> &'static [&'static str] {
        &["T1590.004"]
    }

    fn produces(&self) -> &'static [EntityKind] {
        &[EntityKind::Cidr]
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let asn = target.value.trim().to_uppercase();
        let asn_num = asn.strip_prefix("AS").unwrap_or(&asn);

        let url = format!("https://api.bgpview.io/asn/{asn_num}/prefixes");
        let resp: PrefixResponse = fetch_json(&ctx.http, SRC, &url).await?;

        let mut result = ModuleResult::new();

        if let Some(data) = resp.data {
            for prefix_entry in data.ipv6_prefixes {
                let prefix = prefix_entry.prefix.trim();
                if prefix.is_empty() {
                    continue;
                }
                let mut e = Entity::new(EntityKind::Cidr, prefix, 0.85, &ctx.scan_id);
                e.tag("ipv6");
                e.tag("bgpview");
                e.tag(format!("asn:{asn_num}"));
                let mut ev = Evidence::new(
                    SRC,
                    format!("IPv6 prefix {prefix} announced by AS{asn_num}"),
                )
                .with_attr("prefix", prefix)
                .with_attr("asn", asn_num);
                if let Some(name) = nonempty(&prefix_entry.name) {
                    ev = ev.with_attr("name", name);
                }
                if let Some(cc) = nonempty(&prefix_entry.country_code) {
                    ev = ev.with_attr("country_code", cc);
                }
                if let Some(desc) = nonempty(&prefix_entry.description) {
                    ev = ev.with_attr("description", desc);
                }
                e.add_evidence(ev);
                result.push(e);
            }
        }

        Ok(result)
    }
}
