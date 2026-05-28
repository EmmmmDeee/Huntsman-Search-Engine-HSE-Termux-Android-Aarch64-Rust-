//! IP reputation — AlienVault OTX threat intel + Tor exit-relay check.
//!
//! Merges the former `alienvault_otx` and `tor_exit_check` modules.
//!
//! - **IpAddress** targets → OTX pulse lookup AND Tor exit-relay check.
//! - **Domain** targets   → OTX pulse lookup only (Tor list is IP-only).
//!
//! The Tor exit-relay list is fetched once and cached via `OnceCell` so
//! subsequent calls within the same process are free. A transient network
//! failure on the first fetch leaves the cache uninitialised, allowing
//! the next scan to retry.
//!
//! Free, no API key required.

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use serde::Deserialize;
use tokio::sync::OnceCell;

use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::{Module, ModuleContext, ModuleResult},
    scan::{Target, TargetKind},
};
use crate::util::http::{fetch_json_or_404, urlencode};

// ── OTX response types ─────────────────────────────────────────────

#[derive(Deserialize)]
struct OtxResp {
    pulse_info: Option<PulseInfo>,
}

#[derive(Deserialize)]
struct PulseInfo {
    count: Option<u64>,
    #[serde(default)]
    pulses: Vec<Pulse>,
}

#[derive(Deserialize)]
struct Pulse {
    name: Option<String>,
    #[serde(default)]
    tags: Vec<String>,
    adversary: Option<String>,
    tlp: Option<String>,
    created: Option<String>,
}

// ── Tor exit-relay cache ───────────────────────────────────────────

/// Successful fetches are memoised here. Stored as `Arc<HashSet<…>>` so
/// readers get a cheap clone-of-pointer rather than the whole set.
static EXIT_SET: OnceCell<Arc<HashSet<String>>> = OnceCell::const_new();

/// Fetch + parse, with a single timeout covering BOTH the request and
/// body download.
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

/// Returns `Some` on cache hit or successful fresh fetch; `None` when
/// the upstream is unreachable AND we have no cached copy.
async fn exit_set(http: &reqwest::Client) -> Option<Arc<HashSet<String>>> {
    if let Some(s) = EXIT_SET.get() {
        return Some(Arc::clone(s));
    }
    let fetched = fetch_exit_set(http).await?;
    let arc = Arc::new(fetched);
    let _ = EXIT_SET.set(Arc::clone(&arc));
    Some(EXIT_SET.get().map_or(arc, Arc::clone))
}

// ── Module ─────────────────────────────────────────────────────────

const SRC: &str = "ip_reputation";

pub struct IpReputation;

#[async_trait]
impl Module for IpReputation {
    fn name(&self) -> &'static str {
        "ip_reputation"
    }

    fn description(&self) -> &'static str {
        "IP reputation: AlienVault OTX threat intel and Tor exit relay check"
    }

    fn priority(&self) -> u8 {
        78
    }

    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::IpAddress | TargetKind::Domain)
    }

    fn max_timeout_ms(&self) -> u64 {
        10_000
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        // Skip private / v6 IPs without burning the OTX request.
        // Domain targets pass through (no domain-side equivalent
        // here yet; see batch 2).
        if target.kind == TargetKind::IpAddress
            && crate::util::preflight::should_skip_external_ipv4(&target.value)
        {
            return Ok(ModuleResult::new());
        }
        let mut result = ModuleResult::new();

        // ── 1. AlienVault OTX (IpAddress + Domain) ─────────────────
        run_otx(target, ctx, &mut result).await;

        // ── 2. Tor exit-relay check (IpAddress only) ───────────────
        if target.kind == TargetKind::IpAddress {
            run_tor_check(target, ctx, &mut result).await;
        }

        Ok(result)
    }
}

// ── OTX sub-routine ────────────────────────────────────────────────

async fn run_otx(target: &Target, ctx: &ModuleContext, result: &mut ModuleResult) {
    let itype = match target.kind {
        TargetKind::IpAddress => "IPv4",
        TargetKind::Domain => "domain",
        _ => return,
    };

    let url = format!(
        "https://otx.alienvault.com/api/v1/indicators/{}/{}/general",
        itype,
        urlencode(&target.value)
    );

    let data: Option<OtxResp> = match fetch_json_or_404(&ctx.http, SRC, &url).await {
        Ok(d) => d,
        Err(_) => return,
    };

    let Some(data) = data else { return };

    let pulse_info = match data.pulse_info {
        Some(p) => p,
        None => return,
    };
    let pulse_count = pulse_info.count.unwrap_or(0);
    if pulse_count == 0 {
        return;
    }

    let mut entity = target.to_entity(0.72, &ctx.scan_id);
    entity.tag("threat-intel");

    // Surface up to 5 pulse names + tag aggregate.
    let pulse_names: Vec<&str> = pulse_info
        .pulses
        .iter()
        .filter_map(|p| p.name.as_deref())
        .take(15)
        .collect();
    let tag_count_estimate: usize = pulse_info.pulses.iter().map(|p| p.tags.len()).sum();
    let mut all_tags: Vec<&str> = Vec::with_capacity(tag_count_estimate);
    all_tags.extend(
        pulse_info
            .pulses
            .iter()
            .flat_map(|p| p.tags.iter().map(String::as_str)),
    );
    all_tags.sort_unstable();
    all_tags.dedup();
    all_tags.truncate(50);
    let adversary = pulse_info
        .pulses
        .iter()
        .find_map(|p| p.adversary.as_deref().filter(|s| !s.is_empty()));

    let latest_tlp = pulse_info
        .pulses
        .iter()
        .find_map(|p| p.tlp.as_deref().filter(|s| !s.is_empty()));
    let earliest_created = pulse_info
        .pulses
        .iter()
        .filter_map(|p| p.created.as_deref())
        .min();

    // Tag high-level threat hints for SPA colour-coding.
    let combined_tags = all_tags.join(",").to_lowercase();
    for hint in ["malware", "ransomware", "apt", "phishing", "botnet", "c2"] {
        if combined_tags.contains(hint) {
            entity.tag(format!("ti:{hint}"));
        }
    }

    let mut ev = Evidence::new(SRC, format!("OTX: {pulse_count} threat pulse(s)"))
        .with_attr("pulse_count", pulse_count.to_string())
        .with_attr("indicator_type", itype);
    if !pulse_names.is_empty() {
        ev = ev.with_attr("recent_pulses", pulse_names.join(" | "));
    }
    if !all_tags.is_empty() {
        ev = ev.with_attr("pulse_tags", all_tags.join(", "));
    }
    if let Some(a) = adversary {
        ev = ev.with_attr("adversary", a);
    }
    if let Some(t) = latest_tlp {
        ev = ev.with_attr("tlp", t);
    }
    if let Some(c) = earliest_created {
        ev = ev.with_attr("first_pulse_created", c);
    }
    entity.add_evidence(ev);
    result.push(entity);
}

// ── Tor exit-relay sub-routine ─────────────────────────────────────

async fn run_tor_check(target: &Target, ctx: &ModuleContext, result: &mut ModuleResult) {
    let ip = target.value.trim();
    if ip.is_empty() {
        return;
    }
    let Some(set) = exit_set(&ctx.http).await else {
        return;
    };
    if !set.contains(ip) {
        return;
    }

    let mut entity = Entity::new(EntityKind::IpAddress, ip, 0.95, &ctx.scan_id);
    entity.tag("tor-exit");
    entity.tag("anonymous-network");
    entity.add_evidence(
        Evidence::new(
            "ip_reputation",
            format!("{ip} is on the public Tor exit-relay list"),
        )
        .with_attr("source", "check.torproject.org/exit-addresses")
        .with_attr("exit_list_size", set.len().to_string()),
    );
    result.push(entity);
}

// ── Tests (merged from alienvault_otx + tor_exit_check) ────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_ip_and_domain() {
        let m = IpReputation;
        assert!(m.accepts(&Target::new(TargetKind::IpAddress, "1.1.1.1")));
        assert!(m.accepts(&Target::new(TargetKind::Domain, "x.com")));
        assert!(!m.accepts(&Target::new(TargetKind::Email, "x@y.com")));
    }

    #[test]
    fn rejects_email() {
        let m = IpReputation;
        assert!(!m.accepts(&Target::new(TargetKind::Email, "a@b")));
    }

    #[test]
    fn module_metadata() {
        let m = IpReputation;
        assert_eq!(m.name(), "ip_reputation");
        assert_eq!(m.priority(), 78);
        assert_eq!(m.max_timeout_ms(), 10_000);
    }
}
