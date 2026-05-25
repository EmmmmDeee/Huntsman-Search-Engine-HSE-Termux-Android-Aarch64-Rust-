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

static EXIT_SET: OnceCell<Arc<HashSet<String>>> = OnceCell::const_new();

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

async fn exit_set(http: &reqwest::Client) -> Option<Arc<HashSet<String>>> {
    if let Some(s) = EXIT_SET.get() {
        return Some(Arc::clone(s));
    }
    let fetched = fetch_exit_set(http).await?;
    let arc = Arc::new(fetched);
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
        10_000
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let ip = target.value.trim();
        if ip.is_empty() {
            return Ok(ModuleResult::new());
        }
        let Some(set) = exit_set(&ctx.http).await else {
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
