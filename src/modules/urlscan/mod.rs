//! URLScan.io domain intelligence — recent scans, resolved IPs, and verdicts.
//!
//! Endpoint: `GET https://urlscan.io/api/v1/search/?q=domain:{domain}&size=10`
//!           `GET https://urlscan.io/api/v1/search/?q=page.url:{url}&size=5`
//!
//! No API key required for the search endpoint. Anonymous queries are
//! rate-limited to ~100/min by URLScan.io. The response carries per-scan
//! metadata (page URL, domain, resolved IP, country, server header) and
//! community/engine verdicts. We surface aggregate intel (scan count,
//! unique IPs, countries, server types) and tag the target as
//! "urlscan-malicious" when any verdict flags it.

use std::collections::BTreeSet;

use async_trait::async_trait;
use serde::Deserialize;

use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::{Module, ModuleCategory, ModuleContext, ModuleResult},
    scan::{Target, TargetKind},
};
use crate::util::http::{fetch_json, urlencode};

const SRC: &str = "urlscan";

pub struct UrlScan;

// ─── Response types ─────────────────────────────────────────────────────────

#[derive(Deserialize)]
struct SearchResp {
    #[serde(default)]
    results: Vec<ScanResult>,
}

#[derive(Deserialize)]
struct ScanResult {
    #[serde(default)]
    page: Option<PageInfo>,
    #[serde(default)]
    verdicts: Option<Verdicts>,
}

#[derive(Deserialize)]
struct PageInfo {
    #[serde(default)]
    url: Option<String>,
    #[serde(default)]
    domain: Option<String>,
    #[serde(default)]
    ip: Option<String>,
    #[serde(default)]
    country: Option<String>,
    #[serde(default)]
    server: Option<String>,
}

#[derive(Deserialize)]
struct Verdicts {
    #[serde(default)]
    malicious: Option<bool>,
}

// ─── Module impl ────────────────────────────────────────────────────────────

#[async_trait]
impl Module for UrlScan {
    fn name(&self) -> &'static str {
        "urlscan"
    }

    fn description(&self) -> &'static str {
        "URLScan.io domain intelligence: recent scans, IPs, and verdicts"
    }

    fn priority(&self) -> u8 {
        15
    }

    fn accepts(&self, t: &Target) -> bool {
        matches!(
            t.kind,
            TargetKind::Domain | TargetKind::Url | TargetKind::IpAddress
        )
    }

    fn max_timeout_ms(&self) -> u64 {
        8_000
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Infrastructure
    }

    fn attack_techniques(&self) -> &'static [&'static str] {
        // URLScan.io is a genuine scan database (T1596.005) and surfaces IP
        // addresses (T1590.005). Scan results also carry the hosting country,
        // emitted as an Address entity → T1591.001 Physical Locations, which
        // the Infrastructure default omits.
        &["T1590.005", "T1591.001", "T1596.005"]
    }

    fn produces(&self) -> &'static [EntityKind] {
        const KINDS: &[EntityKind] = &[
            EntityKind::IpAddress,
            EntityKind::Address,
            // Domains/subdomains seen hosting the target + the scanned URLs —
            // attack-surface pivots the module used to discard.
            EntityKind::Domain,
            EntityKind::Url,
        ];
        KINDS
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let query = match target.kind {
            TargetKind::Domain => format!(
                "https://urlscan.io/api/v1/search/?q=domain:\"{}\"&size=10",
                urlencode(&target.value)
            ),
            TargetKind::Url => format!(
                "https://urlscan.io/api/v1/search/?q=page.url:\"{}\"&size=5",
                urlencode(&target.value)
            ),
            TargetKind::IpAddress => format!(
                "https://urlscan.io/api/v1/search/?q=page.ip:\"{}\"&size=10",
                urlencode(&target.value)
            ),
            _ => return Ok(ModuleResult::new()),
        };

        let data: SearchResp = fetch_json(&ctx.http, SRC, &query).await?;

        if data.results.is_empty() {
            return Ok(ModuleResult::new());
        }

        let intel = summarize(&data.results);

        // ── Build target entity + aggregate evidence ────────────────────────
        let confidence = if intel.any_malicious { 0.88 } else { 0.70 };
        let mut entity = target.to_entity(confidence, &ctx.scan_id);
        entity.tag("urlscan");
        if intel.any_malicious {
            entity.tag("urlscan-malicious");
        }

        let mut ev = Evidence::new(
            SRC,
            format!(
                "URLScan.io: {} recent scan(s), {} unique IP(s)",
                intel.scan_count,
                intel.unique_ips.len()
            ),
        )
        .with_attr("scan_count", intel.scan_count.to_string())
        .with_attr("unique_ips", intel.unique_ips.len().to_string());
        if !intel.countries.is_empty() {
            let list: Vec<&str> = intel.countries.iter().map(String::as_str).collect();
            ev = ev.with_attr("countries", list.join(", "));
        }
        if !intel.servers.is_empty() {
            // Cap at 8 distinct server strings to keep the row readable.
            let list: Vec<&str> = intel.servers.iter().take(8).map(String::as_str).collect();
            ev = ev.with_attr("servers", list.join(", "));
        }
        if intel.any_malicious {
            ev = ev.with_attr("malicious_verdict", "true");
        }
        entity.add_evidence(ev);

        let mut result = ModuleResult::new();
        result.push(entity);
        result.extend(child_entities(&intel, &target.value, &ctx.scan_id));
        Ok(result)
    }
}

/// Aggregated, deduplicated intel across a URLScan.io search response. **Pure.**
struct UrlScanIntel {
    unique_ips: BTreeSet<String>,
    countries: BTreeSet<String>,
    servers: BTreeSet<String>,
    /// Domains/subdomains the scans resolved for the target.
    domains: BTreeSet<String>,
    /// Distinct scanned page URLs.
    urls: BTreeSet<String>,
    scan_count: usize,
    any_malicious: bool,
}

/// Reduce a search response to its deduplicated fields. **Pure** (no IO).
fn summarize(results: &[ScanResult]) -> UrlScanIntel {
    let field = |f: fn(&PageInfo) -> Option<&str>| -> BTreeSet<String> {
        results
            .iter()
            .filter_map(|e| e.page.as_ref())
            .filter_map(f)
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(String::from)
            .collect()
    };
    UrlScanIntel {
        unique_ips: field(|p| p.ip.as_deref()),
        countries: field(|p| p.country.as_deref()),
        servers: field(|p| p.server.as_deref()),
        domains: field(|p| p.domain.as_deref()),
        urls: field(|p| p.url.as_deref()),
        scan_count: results.len(),
        any_malicious: results
            .iter()
            .filter_map(|e| e.verdicts.as_ref())
            .any(|v| v.malicious == Some(true)),
    }
}

/// Maximum scanned URLs surfaced as `Url` entities — a busy domain can have many
/// scans; a sample is plenty to characterise the attack surface.
const MAX_URLS: usize = 20;

/// Child entities for a URLScan.io result: the resolved IPs, hosting countries,
/// associated domains/subdomains, and scanned URLs. **Pure** (no IO) so the
/// dedup, validity gates and target-echo suppression are unit-tested directly.
fn child_entities(intel: &UrlScanIntel, target_value: &str, scan_id: &str) -> Vec<Entity> {
    let mut out: Vec<Entity> = Vec::new();
    let target_lc = target_value.trim().to_ascii_lowercase();

    // Resolved IPs (valid v4/v6 only).
    out.extend(
        intel
            .unique_ips
            .iter()
            .filter(|ip| ip.parse::<std::net::IpAddr>().is_ok())
            .map(|ip| {
                let mut e = Entity::new(EntityKind::IpAddress, ip, 0.65, scan_id);
                e.tag("urlscan");
                e.add_evidence(Evidence::new(
                    SRC,
                    format!("Resolved IP seen in URLScan.io scans of {target_value}"),
                ));
                e
            }),
    );

    // Hosting countries → geo-hint Address.
    out.extend(intel.countries.iter().map(|country| {
        let mut e = Entity::new(EntityKind::Address, country, 0.50, scan_id);
        e.tag("urlscan");
        e.tag("geoint");
        e.add_evidence(Evidence::new(
            SRC,
            format!("Hosting country from URLScan.io scans of {target_value}"),
        ));
        e
    }));

    // Associated domains/subdomains (drop the seed echo + dotless junk).
    out.extend(
        intel
            .domains
            .iter()
            .filter(|d| d.contains('.') && d.to_ascii_lowercase() != target_lc)
            .map(|d| {
                let mut e = Entity::new(EntityKind::Domain, d, 0.55, scan_id);
                e.tag("urlscan");
                e.tag("resolved-domain");
                e.add_evidence(Evidence::new(
                    SRC,
                    format!("Domain seen in URLScan.io scans of {target_value}"),
                ));
                e
            }),
    );

    // Scanned page URLs (capped) → attack-surface pivots.
    out.extend(
        intel
            .urls
            .iter()
            .filter(|u| u.len() >= 4)
            .take(MAX_URLS)
            .map(|u| {
                let mut e = Entity::new(EntityKind::Url, u, 0.50, scan_id);
                e.tag("urlscan");
                e.add_evidence(Evidence::new(
                    SRC,
                    format!("Page scanned by URLScan.io for {target_value}"),
                ));
                e
            }),
    );

    out
}

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
