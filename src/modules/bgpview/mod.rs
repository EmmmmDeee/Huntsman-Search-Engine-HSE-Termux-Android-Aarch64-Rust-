//! BGPView — ASN prefix enumeration and IP-to-ASN mapping.
//!
//! Queries the free `bgpview.io` API (no key) for two pivots:
//! - **ASN** → every prefix it announces, both IPv4 and IPv6
//!   (`/asn/{n}/prefixes`) → `Cidr` entities (the network blocks), each
//!   carrying the owning org name.
//! - **IP** → its PTR records and the prefix/ASN it sits in (`/ip/{ip}`) →
//!   `Domain` (reverse DNS) + `Asn` + `Cidr` entities, the CIDR being the
//!   announced network block the IP belongs to.
//!
//! The response → entity mapping lives in the pure [`asn_prefix_entities`] /
//! [`ip_entities`] so it is unit-tested without a live API; `process` owns only
//! URL construction and transport.

use async_trait::async_trait;
use serde::Deserialize;

use crate::core::{confidence, 
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::{Module, ModuleCategory, ModuleContext, ModuleResult},
    scan::{Target, TargetKind},
};

const SRC: &str = "bgpview";

pub struct BgpView;

#[async_trait]
impl Module for BgpView {
    fn name(&self) -> &'static str {
        SRC
    }
    fn description(&self) -> &'static str {
        "BGPView recon — enumerates ASN prefixes and resolves IP-to-ASN mappings"
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
        const KINDS: &[EntityKind] = &[EntityKind::Cidr, EntityKind::Domain, EntityKind::Asn];
        KINDS
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let mut result = ModuleResult::new();

        match target.kind {
            TargetKind::Asn => {
                // Normalise `AS13335` / `as13335` / `13335` → `13335`; reject junk.
                let Some(asn_num) = crate::util::str_util::parse_asn(&target.value) else {
                    return Ok(result);
                };
                let url = format!("https://api.bgpview.io/asn/{asn_num}/prefixes");
                // BGPView returns 404 for an unknown ASN — a clean "not found", not a
                // module failure. fetch_json_or_404 maps that to Ok(None); fetch_json
                // would error on it and needlessly cool the provider off.
                let Some(resp): Option<BgpPrefixResponse> =
                    crate::util::http::fetch_json_or_404(&ctx.http, SRC, &url).await?
                else {
                    return Ok(result);
                };
                if let Some(data) = resp.data {
                    result.extend(asn_prefix_entities(
                        &data,
                        &asn_num.to_string(),
                        &ctx.scan_id,
                    ));
                }
            }
            TargetKind::IpAddress => {
                let ip = target.value.trim();
                let url = format!("https://api.bgpview.io/ip/{ip}");
                let Some(resp): Option<BgpIpResponse> =
                    crate::util::http::fetch_json_or_404(&ctx.http, SRC, &url).await?
                else {
                    return Ok(result);
                };
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

/// `Cidr` entities for the prefixes an ASN announces (the network blocks it
/// owns), each tagged `bgp-prefix` and carrying the owning org name when known.
///
/// Every announced prefix is emitted — both IPv4 AND IPv6 (the v6 set was
/// previously dropped entirely) — and no cap is applied: these are the seed
/// ASN's OWN routed blocks, the direct answer to an ASN lookup, not co-tenant
/// noise. Each `Cidr` is a re-dispatchable pivot whose expansion frontier is
/// owned by the engine's ROI gate, not this leaf — the same reasoning the
/// crtsh / netlas / onyphe resolution paths document.
fn asn_prefix_entities(data: &BgpPrefixData, asn_num: &str, scan_id: &str) -> Vec<Entity> {
    data.ipv4_prefixes
        .iter()
        .chain(data.ipv6_prefixes.iter())
        .filter_map(|prefix| {
            let cidr = prefix.prefix.trim();
            if cidr.is_empty() || !cidr.contains('/') {
                return None;
            }
            let mut e = Entity::new(EntityKind::Cidr, cidr, confidence::HIGH_PLUS, scan_id);
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
    // Every distinct PTR is emitted (deduped by `seen_ptr`): an IP's reverse-DNS
    // names are all genuine host attributions for that address.
    let mut seen_ptr = std::collections::HashSet::new();
    let ptr_entities = data.ptr_record.iter().filter_map(move |ptr| {
        let host = ptr.trim().trim_end_matches('.').to_lowercase();
        if !host.contains('.') || !seen_ptr.insert(host.clone()) {
            return None;
        }
        let mut e = Entity::new(EntityKind::Domain, &host, confidence::HIGH, scan_id);
        e.tag("ptr");
        e.add_evidence(Evidence::new(SRC, format!("PTR record for {ip}")));
        Some(e)
    });

    // Every covering prefix the IP sits in is emitted (BGPView returns the
    // nested more-/less-specific announcements) — each is a real network-block +
    // ASN mapping for the address, not a sample.
    let mut asn_and_cidr: Vec<Entity> = Vec::new();
    for prefix in &data.prefixes {
        let Some(asn) = prefix.asn.as_ref() else {
            continue;
        };
        let asn_label = format!("AS{}", asn.asn);
        let mut asn_e = Entity::new(EntityKind::Asn, &asn_label, confidence::HIGH_PLUSPLUS, scan_id);
        let name = nonempty(&asn.name).unwrap_or("");
        let mut ev = Evidence::new(SRC, format!("{ip} in AS{} ({name})", asn.asn))
            .with_attr("asn", asn.asn.to_string());
        if let Some(name) = nonempty(&asn.name) {
            ev = ev.with_attr("name", name);
        }
        if let Some(cidr) = nonempty(&prefix.prefix).filter(|c| c.contains('/')) {
            ev = ev.with_attr("prefix", cidr);
            // Emit the covering CIDR as a scannable entity, not just evidence.
            let mut ce = Entity::new(EntityKind::Cidr, cidr, confidence::VERY_HIGH, scan_id);
            ce.tag("bgp-prefix");
            ce.add_evidence(Evidence::new(SRC, format!("Covering prefix for {ip}")));
            asn_and_cidr.push(ce);
        }
        asn_e.add_evidence(ev);
        asn_and_cidr.push(asn_e);
    }

    ptr_entities.chain(asn_and_cidr).collect()
}

#[derive(Deserialize)]
struct BgpPrefixResponse {
    data: Option<BgpPrefixData>,
}

#[derive(Deserialize)]
struct BgpPrefixData {
    #[serde(default)]
    ipv4_prefixes: Vec<BgpPrefix>,
    /// IPv6 announcements — previously undeserialised, so every v6 block the AS
    /// owned was silently dropped. BGPView returns both families in one call.
    #[serde(default)]
    ipv6_prefixes: Vec<BgpPrefix>,
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
