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

    fn produces(&self) -> &'static [EntityKind] {
        const KINDS: &[EntityKind] = &[
            EntityKind::IpAddress,
            EntityKind::Url,
            EntityKind::Domain,
            EntityKind::Address,
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

        let mut result = ModuleResult::new();
        for e in build_entities(target, &data.results, &ctx.scan_id) {
            result.push(e);
        }
        Ok(result)
    }
}

/// Trimmed, non-empty view of an optional string field.
fn nonempty(o: &Option<String>) -> Option<&str> {
    o.as_deref().map(str::trim).filter(|s| !s.is_empty())
}

/// Aggregate a set of URLScan.io scan results into entities. **Pure** (no IO) so
/// the aggregation is unit-tested. Beyond the target entity (with the existing
/// IP/country/server aggregate) and the child IP/country entities, this now
/// recovers the previously-discarded `page.url` (the actual pages URLScan
/// captured — concrete page-level intel) as `Url` entities, and the distinct
/// `page.domain`s (reverse-IP / related hosts, valuable for an IP-target query)
/// as `Domain` entities.
fn build_entities(target: &Target, results: &[ScanResult], scan_id: &str) -> Vec<Entity> {
    let target_lc = target.value.trim().to_lowercase();

    let mut unique_ips: BTreeSet<String> = BTreeSet::new();
    let mut countries: BTreeSet<String> = BTreeSet::new();
    let mut servers: BTreeSet<String> = BTreeSet::new();
    let mut urls: BTreeSet<String> = BTreeSet::new();
    let mut domains: BTreeSet<String> = BTreeSet::new();
    let mut any_malicious = false;

    for entry in results {
        if let Some(ref page) = entry.page {
            if let Some(v) = nonempty(&page.ip) {
                unique_ips.insert(v.to_string());
            }
            if let Some(v) = nonempty(&page.country) {
                countries.insert(v.to_string());
            }
            if let Some(v) = nonempty(&page.server) {
                servers.insert(v.to_string());
            }
            if let Some(v) = nonempty(&page.url) {
                urls.insert(v.to_string());
            }
            if let Some(v) = nonempty(&page.domain) {
                let d = v.to_lowercase();
                // Skip the target itself; keep related/reverse-IP domains.
                if d != target_lc {
                    domains.insert(d);
                }
            }
        }
        if let Some(ref verdicts) = entry.verdicts
            && verdicts.malicious == Some(true)
        {
            any_malicious = true;
        }
    }

    let mut result: Vec<Entity> = Vec::new();

    // ── Target entity + aggregate evidence ──────────────────────────────────
    let confidence = if any_malicious { 0.88 } else { 0.70 };
    let mut entity = target.to_entity(confidence, scan_id);
    entity.tag("urlscan");
    if any_malicious {
        entity.tag("urlscan-malicious");
    }

    let scan_count = results.len();
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
    if !urls.is_empty() {
        ev = ev.with_attr("scanned_url_count", urls.len().to_string());
    }
    if any_malicious {
        ev = ev.with_attr("malicious_verdict", "true");
    }
    entity.add_evidence(ev);
    result.push(entity);

    // ── Child IP entities ───────────────────────────────────────────────────
    for ip in &unique_ips {
        // Only emit valid-looking IPs (v4 or v6).
        if ip.parse::<std::net::IpAddr>().is_ok() {
            let mut ip_entity = Entity::new(EntityKind::IpAddress, ip, 0.65, scan_id);
            ip_entity.tag("urlscan");
            ip_entity.add_evidence(Evidence::new(
                SRC,
                format!("Resolved IP seen in URLScan.io scans of {}", target.value),
            ));
            result.push(ip_entity);
        }
    }

    // ── Hosting countries → Address entities ────────────────────────────────
    for country in &countries {
        let mut ae = Entity::new(EntityKind::Address, country, 0.50, scan_id);
        ae.tag("urlscan");
        ae.tag("geoint");
        ae.add_evidence(Evidence::new(
            SRC,
            format!("Hosting country from URLScan.io scans of {}", target.value),
        ));
        result.push(ae);
    }

    // ── Recovered: scanned page URLs → Url entities ─────────────────────────
    for url in &urls {
        let mut ue = Entity::new(EntityKind::Url, url, 0.55, scan_id);
        ue.tag("urlscan");
        ue.tag("scanned-page");
        ue.add_evidence(Evidence::new(
            SRC,
            format!("Page captured by URLScan.io for {}", target.value),
        ));
        result.push(ue);
    }

    // ── Recovered: distinct page domains → Domain entities ──────────────────
    for domain in &domains {
        if domain.contains('.') {
            let mut de = Entity::new(EntityKind::Domain, domain, 0.55, scan_id);
            de.tag("urlscan");
            de.add_evidence(Evidence::new(
                SRC,
                format!(
                    "Domain seen in URLScan.io scans related to {}",
                    target.value
                ),
            ));
            result.push(de);
        }
    }

    result
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

    fn results(json: &str) -> Vec<ScanResult> {
        serde_json::from_str::<SearchResp>(json).unwrap().results
    }

    #[test]
    fn build_recovers_page_urls_and_related_domains() {
        // IP-target query: the page domains are reverse-IP hosts worth pivoting.
        let r = results(
            r#"{"results":[
                {"page":{"url":"https://evil.com/login","domain":"evil.com","ip":"9.9.9.9","country":"RU","server":"nginx"},
                 "verdicts":{"malicious":true}},
                {"page":{"url":"https://other.net/x","domain":"other.net","ip":"9.9.9.9","country":"RU"}}
            ]}"#,
        );
        let v = build_entities(&Target::new(TargetKind::IpAddress, "9.9.9.9"), &r, "s");
        // Recovered page URLs as Url entities (previously discarded).
        let urls: Vec<&str> = v
            .iter()
            .filter(|e| e.kind == EntityKind::Url)
            .map(|e| e.value.as_str())
            .collect();
        assert!(urls.contains(&"https://evil.com/login"));
        assert!(urls.contains(&"https://other.net/x"));
        // Recovered page domains as Domain entities.
        let doms: Vec<&str> = v
            .iter()
            .filter(|e| e.kind == EntityKind::Domain)
            .map(|e| e.value.as_str())
            .collect();
        assert!(doms.contains(&"evil.com") && doms.contains(&"other.net"));
        // Malicious verdict propagates to the target entity.
        let target_ent = v
            .iter()
            .find(|e| e.kind == EntityKind::IpAddress && e.value == "9.9.9.9");
        assert!(target_ent.unwrap().has_tag("urlscan-malicious"));
    }

    #[test]
    fn build_skips_self_domain_and_surfaces_url_count() {
        // Domain-target query: page.domain == target is not re-emitted.
        let r = results(
            r#"{"results":[
                {"page":{"url":"https://example.com/a","domain":"example.com","ip":"1.1.1.1"}},
                {"page":{"url":"https://example.com/b","domain":"EXAMPLE.COM","ip":"1.1.1.1"}}
            ]}"#,
        );
        let v = build_entities(&Target::new(TargetKind::Domain, "example.com"), &r, "s");
        // The only Domain entity is the target itself (kind echoed by to_entity);
        // the page domain "example.com" (and its uppercase dup) is not re-emitted.
        let extra_domains: Vec<&str> = v
            .iter()
            .filter(|e| e.kind == EntityKind::Domain && e.value != "example.com")
            .map(|e| e.value.as_str())
            .collect();
        assert!(
            extra_domains.is_empty(),
            "the target's own domain must not be re-emitted as a pivot: {extra_domains:?}"
        );
        // Two distinct page URLs recovered; one deduped IP child.
        assert_eq!(v.iter().filter(|e| e.kind == EntityKind::Url).count(), 2);
        let target_ent = v.iter().find(|e| e.value == "example.com").unwrap();
        assert_eq!(
            target_ent.evidence[0]
                .attributes
                .get("scanned_url_count")
                .map(String::as_str),
            Some("2")
        );
    }
}
