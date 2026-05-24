//! Tor exit-relay check. Free, no key.
//!
//! Pulls `https://check.torproject.org/exit-addresses` (text format —
//! `ExitAddress <ip> <timestamp>` lines) once per process and caches
//! the resulting set. The list refreshes ~hourly upstream; we accept
//! process-lifetime staleness since most scans don't need second-level
//! freshness and the alternative (per-scan fetch) would be wasteful.
//!
//! A hit emits the input IP as a high-confidence entity tagged
//! `tor-exit` and `anonymous-network`. Useful for attribution analysis
//! when an IP looks suspicious — Tor-exit traffic should be reasoned
//! about differently than residential / hosting-provider traffic.

use std::collections::HashSet;
use std::time::Duration;

use async_trait::async_trait;
use tokio::sync::OnceCell;

use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::{Module, ModuleContext, ModuleResult},
    scan::{Target, TargetKind},
};

static EXIT_SET: OnceCell<HashSet<String>> = OnceCell::const_new();

async fn exit_set(http: &reqwest::Client) -> &'static HashSet<String> {
    EXIT_SET
        .get_or_init(|| async {
            let mut set = HashSet::new();
            let url = "https://check.torproject.org/exit-addresses";
            // Cap the fetch at 8 s — if torproject.org is slow we'd
            // rather skip the check than block the whole scan.
            let fut = http.get(url).send();
            if let Ok(Ok(resp)) = tokio::time::timeout(Duration::from_secs(8), fut).await
                && resp.status().is_success()
                && let Ok(text) = resp.text().await
            {
                for line in text.lines() {
                    if let Some(rest) = line.strip_prefix("ExitAddress ")
                        && let Some(ip) = rest.split_whitespace().next()
                    {
                        set.insert(ip.to_string());
                    }
                }
            }
            set
        })
        .await
}

pub struct TorExitCheck;

#[async_trait]
impl Module for TorExitCheck {
    fn name(&self) -> &'static str {
        "tor_exit_check"
    }

    fn priority(&self) -> u8 {
        32
    }

    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::IpAddress)
    }

    fn max_timeout_ms(&self) -> u64 {
        // Fast on cache-hit, can be ~8 s on first-cold-call.
        10_000
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let ip = target.value.trim();
        if ip.is_empty() {
            return Ok(ModuleResult::new());
        }
        let set = exit_set(&ctx.http).await;
        if set.is_empty() {
            // We couldn't fetch the list — quietly skip rather than
            // emit a noisy ModuleError; the rest of the scan still works.
            return Ok(ModuleResult::new());
        }
        if !set.contains(ip) {
            return Ok(ModuleResult::new());
        }

        let mut entity = Entity::new(EntityKind::IpAddress, ip, 0.95, &ctx.scan_id);
        entity.tag("tor-exit");
        entity.tag("anonymous-network");
        entity.add_evidence(
            Evidence::new(
                "tor_exit_check",
                format!("{ip} is on the public Tor exit-relay list"),
            )
            .with_attr("source", "check.torproject.org/exit-addresses")
            .with_attr("exit_list_size", set.len().to_string()),
        );

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
        let m = TorExitCheck;
        assert!(m.accepts(&Target::new(TargetKind::IpAddress, "1.1.1.1")));
        assert!(!m.accepts(&Target::new(TargetKind::Domain, "x")));
    }
}
