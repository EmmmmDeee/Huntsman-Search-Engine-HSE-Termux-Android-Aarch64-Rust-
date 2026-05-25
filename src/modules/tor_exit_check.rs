//! Tor exit-relay check. Free, no key.
//!
//! Pulls `https://check.torproject.org/exit-addresses` (text format —
//! `ExitAddress <ip> <timestamp>` lines) and caches the resulting set
//! **only on success**. A transient network failure on the first call
//! leaves the cache uninitialised so the next scan can retry — versus
//! the previous behaviour which permanently latched an empty set.
//!
//! A hit emits the input IP as a high-confidence entity tagged
//! `tor-exit` and `anonymous-network`. Useful for attribution analysis
//! when an IP looks suspicious — Tor-exit traffic should be reasoned
//! about differently than residential / hosting-provider traffic.

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use tokio::sync::OnceCell;

use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::{Module, ModuleContext, ModuleResult},
    scan::{Target, TargetKind},
};

/// Successful fetches are memoised here. Stored as `Arc<HashSet<…>>` so
/// readers get a cheap clone-of-pointer rather than the whole set.
static EXIT_SET: OnceCell<Arc<HashSet<String>>> = OnceCell::const_new();

/// Fetch + parse, with a single timeout covering BOTH the request and
/// body download — the previous shape only timed out `send()`, leaving
/// a stalled `text().await` to block until the engine's outer cap.
async fn fetch_exit_set(http: &reqwest::Client) -> Option<HashSet<String>> {
    let url = "https://check.torproject.org/exit-addresses";
    let body_res = tokio::time::timeout(Duration::from_secs(8), async {
        let resp = http.get(url).send().await.ok()?;
        if !resp.status().is_success() {
            return None;
        }
        resp.text().await.ok()
    })
    .await
    .ok()
    .flatten()?;

    // Typical exit list has ~1000-2000 entries; pre-count to avoid rehashing.
    let estimated = body_res
        .lines()
        .filter(|l| l.starts_with("ExitAddress "))
        .count();
    let mut set = HashSet::with_capacity(estimated);
    for line in body_res.lines() {
        if let Some(rest) = line.strip_prefix("ExitAddress ")
            && let Some(ip) = rest.split_whitespace().next()
        {
            set.insert(ip.to_string());
        }
    }
    if set.is_empty() { None } else { Some(set) }
}

/// Returns `Some` on cache hit or successful fresh fetch; `None` when
/// the upstream is unreachable AND we have no cached copy. Subsequent
/// calls will re-attempt the fetch.
async fn exit_set(http: &reqwest::Client) -> Option<Arc<HashSet<String>>> {
    if let Some(s) = EXIT_SET.get() {
        return Some(Arc::clone(s));
    }
    let fetched = fetch_exit_set(http).await?;
    let arc = Arc::new(fetched);
    // Race tolerant: if another task populated EXIT_SET while we were
    // fetching, `set()` fails silently and we return that value instead.
    let _ = EXIT_SET.set(Arc::clone(&arc));
    Some(EXIT_SET.get().map_or(arc, Arc::clone))
}

pub struct TorExitCheck;

#[async_trait]
impl Module for TorExitCheck {
    fn name(&self) -> &'static str {
        "tor_exit_check"
    }

    fn description(&self) -> &'static str {
        "Tor exit relay membership verification"
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
        let Some(set) = exit_set(&ctx.http).await else {
            // Couldn't fetch the list AND no prior success — quietly
            // skip; the rest of the scan continues unaffected, and the
            // next scan will retry the fetch.
            return Ok(ModuleResult::new());
        };
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
