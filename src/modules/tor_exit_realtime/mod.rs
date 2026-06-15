//! Real-time Tor exit node check via the Tor Project's bulk exit list.
//!
//! Fetches `https://check.torproject.org/torbulkexitlist` and checks whether
//! the target IP address appears in the current list. A confirmed Tor exit node
//! is tagged so downstream modules and correlators can treat anonymised traffic
//! differently from regular IP addresses.
//!
//! MITRE ATT&CK:
//!   * T1597.001 — Threat Intel Vendors (Tor exit list lookup)

#[cfg(test)]
mod tests;

use async_trait::async_trait;

use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    error::{Error, Result},
    module::{Module, ModuleCategory, ModuleContext, ModuleCost, ModuleResult},
    scan::{Target, TargetKind},
};
use crate::util::http::RequestBuilderExt;

const SRC: &str = "tor_exit_realtime";
const TOR_EXIT_LIST_URL: &str = "https://check.torproject.org/torbulkexitlist";

pub struct TorExitRealtime;

#[async_trait]
impl Module for TorExitRealtime {
    fn name(&self) -> &'static str {
        "tor_exit_realtime"
    }

    fn description(&self) -> &'static str {
        "Check whether an IP is a current Tor exit node (live consensus)"
    }

    fn priority(&self) -> u8 {
        48
    }

    fn is_passive(&self) -> bool {
        true
    }

    fn cost(&self) -> ModuleCost {
        ModuleCost::Free
    }

    fn accepts(&self, t: &Target) -> bool {
        t.kind == TargetKind::IpAddress
    }

    fn max_timeout_ms(&self) -> u64 {
        8_000
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Threat
    }

    fn attack_techniques(&self) -> &'static [&'static str] {
        &["T1597.001"]
    }

    fn produces(&self) -> &'static [EntityKind] {
        const KINDS: &[EntityKind] = &[EntityKind::IpAddress];
        KINDS
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let ip = target.value.trim();

        let resp = ctx
            .http
            .get(TOR_EXIT_LIST_URL)
            .header("Accept", "text/plain")
            .send_tagged(SRC)
            .await?;

        if !resp.status().is_success() {
            return Err(Error::module(
                SRC,
                format!("Tor exit list HTTP {}", resp.status()),
            ));
        }

        let body = resp
            .text()
            .await
            .map_err(|e| Error::module(SRC, format!("read body: {e}")))?;

        if !is_tor_exit(ip, &body) {
            return Ok(ModuleResult::new());
        }

        let mut e = Entity::new(EntityKind::IpAddress, ip, 0.95, &ctx.scan_id);
        e.tag("tor-exit");
        e.tag("anonymisation");
        e.tag("threat-intel");
        e.add_evidence(
            Evidence::new(SRC, "Confirmed Tor exit node (live consensus)")
                .with_attr("source", "torproject.org")
                .with_attr("list_url", TOR_EXIT_LIST_URL),
        );

        let mut result = ModuleResult::new();
        result.push(e);
        Ok(result)
    }
}

/// Check whether `ip` appears in the Tor bulk exit list text.
pub(crate) fn is_tor_exit(ip: &str, list: &str) -> bool {
    list.lines()
        .filter(|l| !l.starts_with('#') && !l.is_empty())
        .any(|l| l.trim() == ip)
}
