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

    fn produces(&self) -> &'static [EntityKind] {
        const KINDS: &[EntityKind] = &[EntityKind::IpAddress];
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
        let mut unique_ips: BTreeSet<String> = BTreeSet::new();
        let mut countries: BTreeSet<String> = BTreeSet::new();
        let mut servers: BTreeSet<String> = BTreeSet::new();
        let mut any_malicious = false;

        for entry in &data.results {
            if let Some(ref page) = entry.page {
                if let Some(ref ip) = page.ip {
                    let trimmed = ip.trim();
                    if !trimmed.is_empty() {
                        unique_ips.insert(trimmed.to_string());
                    }
                }
                if let Some(ref country) = page.country {
                    let trimmed = country.trim();
                    if !trimmed.is_empty() {
                        countries.insert(trimmed.to_string());
                    }
                }
                if let Some(ref server) = page.server {
                    let trimmed = server.trim();
                    if !trimmed.is_empty() {
                        servers.insert(trimmed.to_string());
                    }
                }
            }
            if let Some(ref verdicts) = entry.verdicts
                && verdicts.malicious == Some(true)
            {
                any_malicious = true;
            }
        }

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
        for ip in &unique_ips {
            // Only emit valid-looking IPs (v4 or v6).
            if ip.parse::<std::net::IpAddr>().is_ok() {
                let mut ip_entity = Entity::new(EntityKind::IpAddress, ip, 0.65, &ctx.scan_id);
                ip_entity.tag("urlscan");
                ip_entity.add_evidence(Evidence::new(
                    SRC,
                    format!("Resolved IP seen in URLScan.io scans of {}", &target.value),
                ));
                result.push(ip_entity);
            }
        }

        for country in &countries {
            let mut ae = Entity::new(
                crate::core::entity::EntityKind::Address,
                country,
                0.50,
                &ctx.scan_id,
            );
            ae.tag("urlscan");
            ae.tag("geoint");
            ae.add_evidence(Evidence::new(
                SRC,
                format!("Hosting country from URLScan.io scans of {}", &target.value),
            ));
            result.push(ae);
        }

        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_domain_url_and_ip() {
        let m = UrlScan;
        assert!(m.accepts(&Target::new(TargetKind::Domain, "example.com")));
        assert!(m.accepts(&Target::new(TargetKind::Url, "https://example.com/path")));
        assert!(m.accepts(&Target::new(TargetKind::IpAddress, "1.1.1.1")));
        assert!(!m.accepts(&Target::new(TargetKind::Email, "a@b.com")));
        assert!(!m.accepts(&Target::new(TargetKind::Username, "alice")));
    }

    #[test]
    fn module_metadata() {
        let m = UrlScan;
        assert_eq!(m.name(), "urlscan");
        assert_eq!(m.priority(), 15);
        assert_eq!(m.cost(), crate::core::module::ModuleCost::Free);
        assert_eq!(m.max_timeout_ms(), 8_000);
        assert!(!m.description().is_empty());
    }

    #[test]
    fn deserialize_empty_results() {
        let raw = r#"{"results":[]}"#;
        let resp: SearchResp = serde_json::from_str(raw).unwrap();
        assert!(resp.results.is_empty());
    }

    #[test]
    fn deserialize_results_with_page_and_verdicts() {
        let raw = r#"{
            "results": [
                {
                    "page": {
                        "url": "https://example.com/login",
                        "domain": "example.com",
                        "ip": "93.184.216.34",
                        "country": "US",
                        "server": "nginx"
                    },
                    "verdicts": {
                        "malicious": false
                    }
                },
                {
                    "page": {
                        "url": "https://example.com/phish",
                        "domain": "example.com",
                        "ip": "104.21.5.100",
                        "country": "DE",
                        "server": "cloudflare"
                    },
                    "verdicts": {
                        "malicious": true
                    }
                }
            ]
        }"#;
        let resp: SearchResp = serde_json::from_str(raw).unwrap();
        assert_eq!(resp.results.len(), 2);

        let first = &resp.results[0];
        let page = first.page.as_ref().unwrap();
        assert_eq!(page.domain.as_deref(), Some("example.com"));
        assert_eq!(page.ip.as_deref(), Some("93.184.216.34"));
        assert_eq!(page.country.as_deref(), Some("US"));
        assert_eq!(page.server.as_deref(), Some("nginx"));
        assert_eq!(first.verdicts.as_ref().unwrap().malicious, Some(false));

        let second = &resp.results[1];
        assert_eq!(second.verdicts.as_ref().unwrap().malicious, Some(true));
    }

    #[test]
    fn deserialize_sparse_response() {
        // URLScan.io can return results with missing optional fields.
        let raw = r#"{
            "results": [
                {
                    "page": {
                        "url": "https://example.com/"
                    }
                },
                {}
            ]
        }"#;
        let resp: SearchResp = serde_json::from_str(raw).unwrap();
        assert_eq!(resp.results.len(), 2);

        let first = &resp.results[0];
        let page = first.page.as_ref().unwrap();
        assert_eq!(page.url.as_deref(), Some("https://example.com/"));
        assert!(page.ip.is_none());
        assert!(page.country.is_none());
        assert!(first.verdicts.is_none());

        // Completely empty result object still deserialises.
        let second = &resp.results[1];
        assert!(second.page.is_none());
        assert!(second.verdicts.is_none());
    }
}
