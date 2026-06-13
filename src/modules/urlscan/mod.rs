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
#[allow(dead_code)] // url + domain are deserialised for test assertions
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
        const KINDS: &[EntityKind] = &[EntityKind::IpAddress, EntityKind::Address];
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

        // ── Aggregate intel from all scan results ───────────────────────────
        let trimmed_field = |field: fn(&PageInfo) -> Option<&str>| -> BTreeSet<String> {
            data.results
                .iter()
                .filter_map(|e| e.page.as_ref())
                .filter_map(field)
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(String::from)
                .collect()
        };
        let unique_ips = trimmed_field(|p| p.ip.as_deref());
        let countries = trimmed_field(|p| p.country.as_deref());
        let servers = trimmed_field(|p| p.server.as_deref());
        let any_malicious = data
            .results
            .iter()
            .filter_map(|e| e.verdicts.as_ref())
            .any(|v| v.malicious == Some(true));

        // ── Build target entity ─────────────────────────────────────────────
        let confidence = if any_malicious { 0.88 } else { 0.70 };
        let mut entity = target.to_entity(confidence, &ctx.scan_id);
        entity.tag("urlscan");

        if any_malicious {
            entity.tag("urlscan-malicious");
        }

        // ── Evidence ────────────────────────────────────────────────────────
        let scan_count = data.results.len();
        let mut ev = Evidence::new(
            SRC,
            format!(
                "URLScan.io: {scan_count} recent scan(s), {} unique IP(s)",
                unique_ips.len()
            ),
        )
        .with_attr("scan_count", scan_count.to_string())
        .with_attr("unique_ips", unique_ips.len().to_string());

        if !countries.is_empty() {
            let country_list: Vec<&str> = countries.iter().map(String::as_str).collect();
            ev = ev.with_attr("countries", country_list.join(", "));
        }
        if !servers.is_empty() {
            // Cap at 8 distinct server strings to keep the row readable.
            let server_list: Vec<&str> = servers.iter().take(8).map(String::as_str).collect();
            ev = ev.with_attr("servers", server_list.join(", "));
        }
        if any_malicious {
            ev = ev.with_attr("malicious_verdict", "true");
        }

        entity.add_evidence(ev);

        let mut result = ModuleResult::new();
        result.push(entity);

        // ── Extract unique IPs as child IpAddress entities ──────────────────
        result.extend(
            unique_ips
                .iter()
                // Only emit valid-looking IPs (v4 or v6).
                .filter(|ip| ip.parse::<std::net::IpAddr>().is_ok())
                .map(|ip| {
                    let mut ip_entity = Entity::new(EntityKind::IpAddress, ip, 0.65, &ctx.scan_id);
                    ip_entity.tag("urlscan");
                    ip_entity.add_evidence(Evidence::new(
                        SRC,
                        format!("Resolved IP seen in URLScan.io scans of {}", &target.value),
                    ));
                    ip_entity
                }),
        );

        result.extend(countries.iter().map(|country| {
            let mut ae = Entity::new(EntityKind::Address, country, 0.50, &ctx.scan_id);
            ae.tag("urlscan");
            ae.tag("geoint");
            ae.add_evidence(Evidence::new(
                SRC,
                format!("Hosting country from URLScan.io scans of {}", &target.value),
            ));
            ae
        }));

        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
