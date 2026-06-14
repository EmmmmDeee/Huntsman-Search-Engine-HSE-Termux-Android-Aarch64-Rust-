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
    module::{Module, ModuleCategory, ModuleContext, ModuleResult},
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
        // Cap the body so a hostile reputation endpoint can't OOM a phone.
        crate::util::http::read_body_capped(resp, 256 * 1024).await
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

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Infrastructure
    }

    fn attack_techniques(&self) -> &'static [&'static str] {
        // OTX pulse lookup → threat-intelligence vendor data (T1597.001);
        // surfaced organisation/ISP context (T1591.002); IP addresses confirmed
        // as Tor exits (T1590.005). Replaces the Infrastructure default T1596.005.
        &["T1590.005", "T1591.002", "T1597.001"]
    }

    fn produces(&self) -> &'static [EntityKind] {
        const KINDS: &[EntityKind] = &[EntityKind::IpAddress, EntityKind::Organisation];
        KINDS
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        if target.kind == TargetKind::IpAddress {
            // Both checks are independent — run them concurrently.
            let (mut otx, tor) = tokio::join!(collect_otx(target, ctx), collect_tor(target, ctx));
            otx.extend(tor.entities);
            Ok(otx)
        } else {
            Ok(collect_otx(target, ctx).await)
        }
    }
}

// ── OTX sub-routine ────────────────────────────────────────────────

/// True if an OTX pulse `tag` is a clean, human-meaningful threat category
/// (e.g. "malware", "Mirai", "NSO Group") rather than the hashes, filenames,
/// metadata lines, and single-character noise OTX also stuffs into `tags`.
///
/// Heuristic: 3–32 chars, starts with a letter, ≥50% alphabetic, at most four
/// words, and free of path/metadata punctuation or an explicit "hash" marker.
fn is_meaningful_tag(t: &str) -> bool {
    let len = t.len();
    (3..=32).contains(&len)
        && t.chars().next().is_some_and(|c| c.is_ascii_alphabetic())
        && t.chars().filter(|c| c.is_ascii_alphabetic()).count() * 2 >= len
        && !t.contains(['/', '\\', ':', '|', '=', '(', ')'])
        && !t.to_ascii_lowercase().contains("hash")
        && t.split_whitespace().count() <= 4
}

async fn collect_otx(target: &Target, ctx: &ModuleContext) -> ModuleResult {
    let mut result = ModuleResult::new();
    let itype = match target.kind {
        TargetKind::IpAddress => "IPv4",
        TargetKind::Domain => "domain",
        _ => return result,
    };

    let url = format!(
        "https://otx.alienvault.com/api/v1/indicators/{}/{}/general",
        itype,
        urlencode(&target.value)
    );

    let data: Option<OtxResp> = match fetch_json_or_404(&ctx.http, SRC, &url).await {
        Ok(d) => d,
        Err(_) => return result,
    };

    let Some(data) = data else { return result };

    let pulse_info = match data.pulse_info {
        Some(p) => p,
        None => return result,
    };
    let pulse_count = pulse_info.count.unwrap_or(0);
    if pulse_count == 0 {
        return result;
    }

    let mut entity = target.to_entity(0.72, &ctx.scan_id);
    entity.tag("threat-intel");

    // Surface a few pulse names + the most SIGNIFICANT tags. OTX pulses dump
    // hashes, filenames, single characters and freeform notes into `tags`; the
    // old code sorted them alphabetically and kept the first 50, which surfaced
    // a noise blob (".cc", "0007", "MD5 Hash: …", "NSO Group" all jumbled). We
    // now rank by frequency across pulses (the genuinely-recurring threat
    // categories) and keep only clean, meaningful tags — see `is_meaningful_tag`.
    let pulse_names: Vec<&str> = pulse_info
        .pulses
        .iter()
        .filter_map(|p| p.name.as_deref())
        .take(5)
        .collect();
    let mut tag_freq: std::collections::HashMap<&str, u32> = std::collections::HashMap::new();
    for p in &pulse_info.pulses {
        for t in &p.tags {
            let t = t.trim();
            if is_meaningful_tag(t) {
                *tag_freq.entry(t).or_default() += 1;
            }
        }
    }
    let mut ranked: Vec<(&str, u32)> = tag_freq.into_iter().collect();
    // Most frequent first; alphabetical tiebreak for determinism.
    ranked.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(b.0)));
    let all_tags: Vec<&str> = ranked.into_iter().take(12).map(|(t, _)| t).collect();
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
        // OTX `adversary` is sometimes a long freeform paragraph after the
        // group name — keep just the lead name, capped.
        let name = a.split('(').next().unwrap_or(a).trim();
        let capped: String = name.chars().take(64).collect();
        if !capped.is_empty() {
            ev = ev.with_attr("adversary", &capped);
        }
    }
    if let Some(t) = latest_tlp {
        ev = ev.with_attr("tlp", t);
    }
    if let Some(c) = earliest_created {
        ev = ev.with_attr("first_pulse_created", c);
    }
    entity.add_evidence(ev);
    result.push(entity);

    // The named adversary/threat-actor (e.g. "Mirai", "NSO Group") is a
    // correlatable Organisation pivot, not just an evidence string.
    if let Some(a) = adversary {
        let name = a.split('(').next().unwrap_or(a).trim();
        let capped: String = name.chars().take(64).collect();
        if capped.len() >= 2 {
            let mut o = Entity::new(EntityKind::Organisation, &capped, 0.58, &ctx.scan_id);
            o.tag("threat-intel");
            o.tag("adversary");
            o.add_evidence(
                Evidence::new(
                    SRC,
                    format!("Threat actor linked to {} per OTX", target.value),
                )
                .with_attr("indicator", target.value.as_str()),
            );
            result.push(o);
        }
    }
    result
}

// ── Tor exit-relay sub-routine ─────────────────────────────────────

async fn collect_tor(target: &Target, ctx: &ModuleContext) -> ModuleResult {
    let mut result = ModuleResult::new();
    let ip = target.value.trim();
    if ip.is_empty() {
        return result;
    }
    let Some(set) = exit_set(&ctx.http).await else {
        return result;
    };
    if !set.contains(ip) {
        return result;
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
    result
}

// ── Tests (merged from alienvault_otx + tor_exit_check) ────────────

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
