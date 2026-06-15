//! Tor exit node realtime check.
//!
//! Fetches the live Tor Project bulk exit list
//! (`https://check.torproject.org/torbulkexitlist`) and checks whether the
//! target IP is a current Tor exit node.

use async_trait::async_trait;

use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    error::{Error, Result},
    module::{Module, ModuleCategory, ModuleCost, ModuleContext, ModuleResult},
    scan::{Target, TargetKind},
};
use crate::util::http::{RequestBuilderExt, error_snippet};

const SRC: &str = "tor_exit_realtime";
const LIST_URL: &str = "https://check.torproject.org/torbulkexitlist";

pub struct TorExitRealtime;

#[async_trait]
impl Module for TorExitRealtime {
    fn name(&self) -> &'static str {
        SRC
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
        matches!(t.kind, TargetKind::IpAddress)
    }

    fn max_timeout_ms(&self) -> u64 {
        8_000
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Threat
    }

    fn attack_techniques(&self) -> &'static [&'static str] {
        &["T1090.003"]
    }

    fn produces(&self) -> &'static [EntityKind] {
        &[EntityKind::IpAddress]
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let ip = target.value.trim();

        let resp = ctx.http.get(LIST_URL).send_tagged(SRC).await?;

        if !resp.status().is_success() {
            let snippet = error_snippet(resp).await;
            return Err(Error::module(
                SRC,
                format!("HTTP error fetching Tor exit list: {snippet}"),
            ));
        }

        let body = resp.text().await.map_err(|e| {
            Error::module(SRC, format!("failed to read Tor exit list body: {e}"))
        })?;

        let found = parse_exit_list(&body).any(|line_ip| line_ip == ip);

        let mut result = ModuleResult::new();

        if found {
            let mut e = Entity::new(EntityKind::IpAddress, ip, 0.95, &ctx.scan_id);
            e.tag("tor-exit");
            e.tag("anonymisation");
            e.tag("threat-intel");
            let ev = Evidence::new(SRC, "Confirmed Tor exit node (live consensus)")
                .with_attr("source", "torproject.org")
                .with_attr("list_url", LIST_URL);
            e.add_evidence(ev);
            result.push(e);
        }

        Ok(result)
    }
}

/// Parse the Tor bulk exit list text, yielding one IP per line.
/// Blank lines and lines starting with `#` are skipped.
fn parse_exit_list(body: &str) -> impl Iterator<Item = &str> {
    body.lines()
        .filter(|line| {
            let trimmed = line.trim();
            !trimmed.is_empty() && !trimmed.starts_with('#')
        })
        .map(str::trim)
}

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
