//! BGPView — ASN prefix enumeration and IP-to-ASN mapping.
//!
//! Queries the free `bgpview.io` API (no key) for two pivots:
//! - **ASN** → the prefixes it announces (`/asn/{n}/prefixes`) → `IpAddress`
//!   entities (the network blocks), each carrying the owning org name.
//! - **IP** → its PTR records and the prefix/ASN it sits in (`/ip/{ip}`) →
//!   `Domain` (reverse DNS) + `Asn` entities, the latter carrying the announced
//!   CIDR block as context.
//!
//! The response → entity mapping lives in the pure [`asn_prefix_entities`] /
//! [`ip_entities`] so it is unit-tested without a live API; `process` owns only
//! URL construction and transport.

use async_trait::async_trait;
use serde::Deserialize;

use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::{Module, ModuleCategory, ModuleContext, ModuleResult},
    scan::{Target, TargetKind},
};

const SRC: &str = "bgpview";

/// Output caps, keeping a single ASN/IP lookup bounded.
const MAX_ANNOUNCED_PREFIXES: usize = 20;
const MAX_PTR_RECORDS: usize = 3;
const MAX_IP_PREFIXES: usize = 3;

pub struct BgpView;

#[async_trait]
impl Module for BgpView {
    fn name(&self) -> &'static str {
        SRC
    }
    fn description(&self) -> &'static str {
        "BGPView ASN prefix enumeration and IP-to-ASN mapping"
    }
    fn priority(&self) -> u8 {
        35
    }
    fn max_timeout_ms(&self) -> u64 {
        8_000
    }
    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::Asn | TargetKind::IpAddress)
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Infrastructure
    }

    fn attack_techniques(&self) -> &'static [&'static str] {
        // ASN→prefix and IP→ASN mapping is IP-address recon (T1590.005, the
        // Infrastructure default) but it also surfaces the IP's PTR records as
        // DNS findings — add Gather Victim Network Information: DNS (T1590.002).
        // Superset of the category default, so coverage never regresses.
        &["T1590.005", "T1590.002", "T1596.005"]
    }

    fn produces(&self) -> &'static [EntityKind] {
        const KINDS: &[EntityKind] = &[EntityKind::IpAddress, EntityKind::Domain, EntityKind::Asn];
        KINDS
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let mut result = ModuleResult::new();

        match target.kind {
            TargetKind::Asn => {
                // Normalise `AS13335` / `as13335` / `13335` → `13335`.
                let asn = target.value.trim().to_uppercase();
                let asn_num = asn.strip_prefix("AS").unwrap_or(&asn);
                let url = format!("https://api.bgpview.io/asn/{asn_num}/prefixes");
                let resp: BgpPrefixResponse =
                    crate::util::http::fetch_json(&ctx.http, SRC, &url).await?;
                if let Some(data) = resp.data {
                    result.extend(asn_prefix_entities(&data, asn_num, &ctx.scan_id));
                }
            }
            TargetKind::IpAddress => {
                let ip = target.value.trim();
                let url = format!("https://api.bgpview.io/ip/{ip}");
                let resp: BgpIpResponse =
                    crate::util::http::fetch_json(&ctx.http, SRC, &url).await?;
                if let Some(data) = resp.data {
                    result.extend(ip_entities(&data, ip, &ctx.scan_id));
                }
            }
            _ => {}
        }

        Ok(result)
    }
}

use crate::util::str_util::nonempty;

/// `IpAddress` entities for the prefixes an ASN announces (the network blocks it
/// owns), each tagged `bgp-prefix` and carrying the owning org name when known.
fn asn_prefix_entities(data: &BgpPrefixData, asn_num: &str, scan_id: &str) -> Vec<Entity> {
    data.ipv4_prefixes
        .iter()
        .take(MAX_ANNOUNCED_PREFIXES)
        .filter_map(|prefix| {
            let cidr = prefix.prefix.trim();
            if cidr.is_empty() {
                return None;
            }
            let mut e = Entity::new(EntityKind::IpAddress, cidr, 0.70, scan_id);
            e.tag("bgp-prefix");
            let mut ev = Evidence::new(SRC, format!("AS{asn_num} announces {cidr}"))
                .with_attr("asn", asn_num)
                .with_attr("prefix", cidr);
            if let Some(name) = nonempty(&prefix.name) {
                ev = ev.with_attr("name", name);
            }
            e.add_evidence(ev);
            Some(e)
        })
        .collect()
}

/// `Domain` (reverse-DNS PTR) + `Asn` entities for an IP. The `Asn` entity now
/// carries the announced **CIDR block** the IP sits in (`prefix`) — previously
/// parsed and discarded — which is the actionable network-ownership datum.
fn ip_entities(data: &BgpIpData, ip: &str, scan_id: &str) -> Vec<Entity> {
    // PTRs are often trailing-dot FQDNs; normalise, require a real label, dedup.
    let mut seen_ptr = std::collections::HashSet::new();
    let ptr_entities = data
        .ptr_record
        .iter()
        .take(MAX_PTR_RECORDS)
        .filter_map(move |ptr| {
            let host = ptr.trim().trim_end_matches('.').to_lowercase();
            if !host.contains('.') || !seen_ptr.insert(host.clone()) {
                return None;
            }
            let mut e = Entity::new(EntityKind::Domain, &host, 0.65, scan_id);
            e.tag("ptr");
            e.add_evidence(Evidence::new(SRC, format!("PTR record for {ip}")));
            Some(e)
        });

    let asn_entities = data
        .prefixes
        .iter()
        .take(MAX_IP_PREFIXES)
        .filter_map(|prefix| {
            let asn = prefix.asn.as_ref()?;
            let asn_label = format!("AS{}", asn.asn);
            let mut e = Entity::new(EntityKind::Asn, &asn_label, 0.80, scan_id);
            let name = nonempty(&asn.name).unwrap_or("");
            let mut ev = Evidence::new(SRC, format!("{ip} in AS{} ({name})", asn.asn))
                .with_attr("asn", asn.asn.to_string());
            if let Some(name) = nonempty(&asn.name) {
                ev = ev.with_attr("name", name);
            }
            // The announced CIDR block the IP belongs to — the key network datum.
            if let Some(cidr) = nonempty(&prefix.prefix) {
                ev = ev.with_attr("prefix", cidr);
                e.tag(format!("prefix:{cidr}"));
            }
            e.add_evidence(ev);
            Some(e)
        });

    ptr_entities.chain(asn_entities).collect()
}

#[derive(Deserialize)]
struct BgpPrefixResponse {
    data: Option<BgpPrefixData>,
}

#[derive(Deserialize)]
struct BgpPrefixData {
    #[serde(default)]
    ipv4_prefixes: Vec<BgpPrefix>,
}

#[derive(Deserialize)]
struct BgpPrefix {
    prefix: String,
    name: Option<String>,
}

#[derive(Deserialize)]
struct BgpIpResponse {
    data: Option<BgpIpData>,
}

#[derive(Deserialize)]
struct BgpIpData {
    #[serde(default)]
    ptr_record: Vec<String>,
    #[serde(default)]
    prefixes: Vec<BgpIpPrefix>,
}

#[derive(Deserialize)]
struct BgpIpPrefix {
    #[serde(default)]
    prefix: Option<String>,
    asn: Option<BgpAsn>,
}

#[derive(Deserialize)]
struct BgpAsn {
    asn: u64,
    name: Option<String>,
}

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
