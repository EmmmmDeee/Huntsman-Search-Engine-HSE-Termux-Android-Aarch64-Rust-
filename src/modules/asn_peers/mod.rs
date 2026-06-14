//! ASN peers — BGP neighbour discovery via RIPE NCC's free `asn-neighbours`
//! API (`stat.ripe.net/data/asn-neighbours/data.json`).
//!
//! Resolves an ASN's immediate BGP peers (left/right neighbours) and emits
//! each as an `Asn` entity. Keyless, passive, and Termux-friendly.
//!
//! MITRE ATT&CK TA0043: T1590.005 — Gather Victim Network Information: IP
//! Addresses (ASN peer enumeration maps the target's network topology, the
//! canonical infra-recon sub-technique for BGP-level discovery).

use async_trait::async_trait;
use serde::Deserialize;

use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::{Module, ModuleCategory, ModuleContext, ModuleCost, ModuleResult},
    scan::{Target, TargetKind},
};
use crate::util::http::fetch_json;

const SRC: &str = "asn_peers";

/// Maximum peer ASNs to emit — keeps a heavily-peered CDN ASN bounded.
const MAX_PEERS: usize = 50;

pub struct AsnPeers;

#[async_trait]
impl Module for AsnPeers {
    fn name(&self) -> &'static str {
        "asn_peers"
    }

    fn description(&self) -> &'static str {
        "BGP peer ASN discovery via RIPE NCC asn-neighbours API (free, no key)"
    }

    fn priority(&self) -> u8 {
        36
    }

    fn max_timeout_ms(&self) -> u64 {
        10_000
    }

    fn is_passive(&self) -> bool {
        true
    }

    fn cost(&self) -> ModuleCost {
        ModuleCost::Free
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Infrastructure
    }

    fn attack_techniques(&self) -> &'static [&'static str] {
        &["T1590.005"]
    }

    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::Asn)
    }

    fn produces(&self) -> &'static [EntityKind] {
        const KINDS: &[EntityKind] = &[EntityKind::Asn];
        KINDS
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let raw = target.value.trim().to_uppercase();
        let asn_num = raw.strip_prefix("AS").unwrap_or(&raw);
        if asn_num.is_empty() {
            return Ok(ModuleResult::new());
        }

        let url =
            format!("https://stat.ripe.net/data/asn-neighbours/data.json?resource=AS{asn_num}");
        let resp: NeighboursResp = fetch_json(&ctx.http, SRC, &url).await?;

        let mut result = ModuleResult::new();
        result.entities = peer_entities(&resp.data, asn_num, &ctx.scan_id);
        Ok(result)
    }
}

/// Emit one `Asn` entity per peer neighbour (capped at [`MAX_PEERS`]).
pub(super) fn peer_entities(data: &NeighboursData, asn_num: &str, scan_id: &str) -> Vec<Entity> {
    data.neighbours
        .iter()
        .take(MAX_PEERS)
        .map(|n| {
            let label = format!("AS{}", n.asn);
            let mut e = Entity::new(EntityKind::Asn, &label, 0.70, scan_id);
            e.tag(SRC);
            e.tag(format!("bgp-peer:{}", n.peer_type));
            let ev = Evidence::new(SRC, format!("BGP peer of AS{asn_num}"))
                .with_attr("origin_asn", asn_num)
                .with_attr("peer_type", &n.peer_type);
            e.add_evidence(ev);
            e
        })
        .collect()
}

// ── RIPE stat response types ─────────────────────────────────────────────────

/// Top-level RIPE stat envelope.
#[derive(Deserialize, Default)]
#[serde(default)]
pub(super) struct NeighboursResp {
    pub(super) data: NeighboursData,
}

#[derive(Deserialize, Default)]
#[serde(default)]
pub(super) struct NeighboursData {
    pub(super) neighbours: Vec<Neighbour>,
}

#[derive(Deserialize)]
pub(super) struct Neighbour {
    pub(super) asn: u64,
    #[serde(rename = "type")]
    pub(super) peer_type: String,
}

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
