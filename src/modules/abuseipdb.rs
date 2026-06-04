//! AbuseIPDB — IP address abuse/threat reputation scoring.
//!
//! Queries the AbuseIPDB v2 API for abuse confidence score, report
//! count, and usage type. Tags high-risk IPs. Requires HUNTSMAN_ABUSEIPDB_KEY.

use async_trait::async_trait;
use serde::Deserialize;

use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::{Module, ModuleCategory, ModuleContext, ModuleCost, ModuleResult},
    scan::{Target, TargetKind},
};

const SRC: &str = "abuseipdb";

pub struct AbuseIpDb;

#[async_trait]
impl Module for AbuseIpDb {
    fn name(&self) -> &'static str {
        SRC
    }
    fn description(&self) -> &'static str {
        "AbuseIPDB IP reputation — abuse confidence score and report history"
    }
    fn priority(&self) -> u8 {
        52
    }
    fn cost(&self) -> ModuleCost {
        ModuleCost::KeyGated
    }
    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::IpAddress)
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Infrastructure
    }

    fn produces(&self) -> &'static [EntityKind] {
        const KINDS: &[EntityKind] = &[EntityKind::IpAddress];
        KINDS
    }

    fn max_timeout_ms(&self) -> u64 {
        // Single keyed request via fetch_keyed_json (no internal total
        // timeout, only the client's 5s connect). On the 3s default the
        // engine killed a slow-but-connected response as a spurious
        // "timeout".
        10_000
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let mut result = ModuleResult::new();

        let url = format!(
            "https://api.abuseipdb.com/api/v2/check?ipAddress={}&maxAgeInDays=90&verbose",
            crate::util::http::urlencode(&target.value)
        );

        let Some(body) = crate::util::http::fetch_keyed_json::<AbuseResponse>(
            ctx,
            SRC,
            &url,
            "HUNTSMAN_ABUSEIPDB_KEY",
            "Key",
        )
        .await?
        else {
            return Ok(result);
        };

        let Some(data) = body.data else {
            return Ok(result);
        };

        result.push(build_ip_entity(&target.value, &data, &ctx.scan_id));

        // Reverse-DNS pivots recovered from the verbose response: the domain and
        // hostnames behind a flagged IP are fresh expansion seeds.
        let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
        for host in data
            .hostnames
            .iter()
            .map(String::as_str)
            .chain(data.domain.as_deref())
        {
            let host = host.trim().trim_end_matches('.').to_lowercase();
            // A real reverse-DNS host has a dot and is not an IP literal.
            if host.contains('.')
                && host.parse::<std::net::IpAddr>().is_err()
                && seen.insert(host.clone())
            {
                let mut de = Entity::new(EntityKind::Domain, &host, 0.45, &ctx.scan_id);
                de.tag("reverse-dns");
                de.tag("threat-adjacent");
                de.add_evidence(
                    Evidence::new(
                        SRC,
                        format!("Reverse-DNS host of flagged IP {}", target.value),
                    )
                    .with_attr("source_ip", &target.value),
                );
                result.push(de);
            }
        }

        Ok(result)
    }
}

#[derive(Deserialize)]
struct AbuseResponse {
    data: Option<AbuseData>,
}

#[derive(Deserialize)]
struct AbuseData {
    #[serde(rename = "abuseConfidenceScore")]
    abuse_confidence_score: Option<u32>,
    #[serde(rename = "totalReports")]
    total_reports: Option<u32>,
    #[serde(rename = "isTor")]
    is_tor: Option<bool>,
    isp: Option<String>,
    #[serde(rename = "usageType")]
    usage_type: Option<String>,
    #[serde(rename = "countryCode")]
    country_code: Option<String>,
    // ── verbose fields — requested via `&verbose` but previously discarded ──
    #[serde(rename = "countryName", default)]
    country_name: Option<String>,
    #[serde(default)]
    domain: Option<String>,
    #[serde(default)]
    hostnames: Vec<String>,
    #[serde(rename = "isPublic", default)]
    is_public: Option<bool>,
    #[serde(rename = "ipVersion", default)]
    ip_version: Option<u8>,
    #[serde(rename = "isWhitelisted", default)]
    is_whitelisted: Option<bool>,
    #[serde(rename = "lastReportedAt", default)]
    last_reported_at: Option<String>,
    #[serde(rename = "numDistinctUsers", default)]
    num_distinct_users: Option<u32>,
    #[serde(default)]
    reports: Vec<AbuseReport>,
}

#[derive(Deserialize)]
struct AbuseReport {
    #[serde(default)]
    categories: Vec<u32>,
}

/// Map an AbuseIPDB report-category code to its name. The taxonomy is fixed
/// (https://www.abuseipdb.com/categories), so the distinct categories an IP was
/// reported under — the actionable "what kind of abuse" signal carried in the
/// verbose `reports` array — can be surfaced instead of discarded.
fn category_name(code: u32) -> &'static str {
    match code {
        1 => "DNS Compromise",
        2 => "DNS Poisoning",
        3 => "Fraud Orders",
        4 => "DDoS Attack",
        5 => "FTP Brute-Force",
        6 => "Ping of Death",
        7 => "Phishing",
        8 => "Fraud VoIP",
        9 => "Open Proxy",
        10 => "Web Spam",
        11 => "Email Spam",
        12 => "Blog Spam",
        13 => "VPN IP",
        14 => "Port Scan",
        15 => "Hacking",
        16 => "SQL Injection",
        17 => "Spoofing",
        18 => "Brute-Force",
        19 => "Bad Web Bot",
        20 => "Exploited Host",
        21 => "Web App Attack",
        22 => "SSH",
        23 => "IoT Targeted",
        _ => "Unknown",
    }
}

/// Build the reputation `IpAddress` entity from an AbuseIPDB record. **Pure**
/// (no IO) so the score→confidence/tag mapping and the recovered-field surfacing
/// are unit-tested. The confidence baseline (0.60) scales with the abuse score;
/// the previously-discarded verbose fields (whitelist status, distinct reporter
/// count, last-reported timestamp, ISP/usage/geo, and the union of attack
/// categories) are surfaced as evidence so no API datum is dropped.
fn build_ip_entity(ip: &str, data: &AbuseData, scan_id: &str) -> Entity {
    let abuse_score = data.abuse_confidence_score.unwrap_or(0);
    let confidence = 0.60 + (abuse_score as f64 / 100.0) * 0.35;

    let mut e = Entity::new(EntityKind::IpAddress, ip, confidence, scan_id);
    e.tag("threat-intel");
    if abuse_score >= 80 {
        e.tag("malicious");
        e.tag("high-risk");
    } else if abuse_score >= 40 {
        e.tag("suspicious");
    }
    if data.is_tor.unwrap_or(false) {
        e.tag("tor-exit");
    }
    // Recovered: AbuseIPDB's own allowlist (search engines, CDNs) — a benign
    // signal that should temper an otherwise-flagged IP.
    if data.is_whitelisted == Some(true) {
        e.tag("whitelisted");
    }

    // Distinct attack categories across every verbose report — the threat-type
    // intelligence the `&verbose` query asked for and the old code dropped.
    let mut codes: std::collections::BTreeSet<u32> = std::collections::BTreeSet::new();
    for r in &data.reports {
        codes.extend(r.categories.iter().copied());
    }

    let mut ev = Evidence::new(
        SRC,
        format!(
            "AbuseIPDB: {}% abuse confidence, {} reports",
            abuse_score,
            data.total_reports.unwrap_or(0)
        ),
    )
    .with_attr("abuse_score", abuse_score.to_string())
    .with_attr("total_reports", data.total_reports.unwrap_or(0).to_string());
    if let Some(ref isp) = data.isp {
        ev = ev.with_attr("isp", isp);
    }
    if let Some(ref usage) = data.usage_type {
        ev = ev.with_attr("usage_type", usage);
    }
    if let Some(ref cc) = data.country_code {
        ev = ev.with_attr("country_code", cc);
    }
    if let Some(ref cn) = data.country_name {
        ev = ev.with_attr("country_name", cn);
    }
    if let Some(ref d) = data.domain {
        ev = ev.with_attr("domain", d);
    }
    if !data.hostnames.is_empty() {
        ev = ev.with_attr("hostnames", data.hostnames.join(", "));
    }
    if let Some(v) = data.is_public {
        ev = ev.with_attr("is_public", v.to_string());
    }
    if let Some(v) = data.ip_version {
        ev = ev.with_attr("ip_version", v.to_string());
    }
    if let Some(v) = data.is_whitelisted {
        ev = ev.with_attr("is_whitelisted", v.to_string());
    }
    if let Some(ref t) = data.last_reported_at {
        ev = ev.with_attr("last_reported_at", t);
    }
    if let Some(n) = data.num_distinct_users {
        ev = ev.with_attr("num_distinct_users", n.to_string());
    }
    if !codes.is_empty() {
        let names: Vec<&str> = codes.iter().map(|c| category_name(*c)).collect();
        ev = ev.with_attr("attack_categories", names.join(", "));
    }
    e.add_evidence(ev);
    e
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deserialize_abuse_response() {
        let json = r#"{"data":{"abuseConfidenceScore":85,"totalReports":42,"isTor":false,"isp":"Cloudflare","usageType":"Content Delivery Network","countryCode":"US"}}"#;
        let r: AbuseResponse = serde_json::from_str(json).unwrap();
        let d = r.data.unwrap();
        assert_eq!(d.abuse_confidence_score, Some(85));
        assert_eq!(d.total_reports, Some(42));
        assert_eq!(d.country_code.as_deref(), Some("US"));
    }

    #[tokio::test]
    async fn module_metadata() {
        let m = AbuseIpDb;
        assert_eq!(m.cost(), ModuleCost::KeyGated);
        assert!(m.accepts(&Target::new(TargetKind::IpAddress, "8.8.8.8")));
        assert!(!m.accepts(&Target::new(TargetKind::Domain, "example.com")));
    }

    #[test]
    fn confidence_formula_score_zero() {
        let score: u32 = 0;
        let conf = 0.60 + (score as f64 / 100.0) * 0.35;
        assert!((conf - 0.60).abs() < 1e-9);
    }

    #[test]
    fn confidence_formula_score_80() {
        let score: u32 = 80;
        let conf = 0.60 + (score as f64 / 100.0) * 0.35;
        assert!((conf - 0.88).abs() < 1e-9);
    }

    #[test]
    fn confidence_formula_score_100() {
        let score: u32 = 100;
        let conf = 0.60 + (score as f64 / 100.0) * 0.35;
        assert!((conf - 0.95).abs() < 1e-9);
    }

    #[test]
    fn deserialize_tor_exit() {
        let json = r#"{"data":{"abuseConfidenceScore":95,"totalReports":200,"isTor":true,"isp":"TorProject","countryCode":"DE"}}"#;
        let r: AbuseResponse = serde_json::from_str(json).unwrap();
        let d = r.data.unwrap();
        assert_eq!(d.is_tor, Some(true));
        assert_eq!(d.abuse_confidence_score, Some(95));
    }

    #[test]
    fn deserialize_null_data() {
        let json = r#"{"data":null}"#;
        let r: AbuseResponse = serde_json::from_str(json).unwrap();
        assert!(r.data.is_none());
    }

    #[test]
    fn deserialize_missing_optional_fields() {
        let json = r#"{"data":{"abuseConfidenceScore":10}}"#;
        let r: AbuseResponse = serde_json::from_str(json).unwrap();
        let d = r.data.unwrap();
        assert_eq!(d.abuse_confidence_score, Some(10));
        assert!(d.total_reports.is_none());
        assert!(d.is_tor.is_none());
        assert!(d.isp.is_none());
    }

    fn data_of(json: &str) -> AbuseData {
        serde_json::from_str::<AbuseResponse>(json)
            .unwrap()
            .data
            .unwrap()
    }

    #[test]
    fn category_names_cover_the_taxonomy() {
        assert_eq!(category_name(18), "Brute-Force");
        assert_eq!(category_name(22), "SSH");
        assert_eq!(category_name(21), "Web App Attack");
        assert_eq!(category_name(14), "Port Scan");
        assert_eq!(category_name(999), "Unknown");
    }

    #[test]
    fn build_entity_surfaces_recovered_verbose_fields_and_categories() {
        // A flagged IP with the full verbose payload the old code requested
        // (&verbose) but discarded.
        let d = data_of(
            r#"{"data":{
                "abuseConfidenceScore":92,"totalReports":300,"isTor":false,
                "isp":"EvilHost","usageType":"Data Center","countryCode":"RU",
                "countryName":"Russia","domain":"evilhost.ru",
                "hostnames":["mail.evilhost.ru"],"isPublic":true,"ipVersion":4,
                "isWhitelisted":false,"lastReportedAt":"2026-01-01T00:00:00+00:00",
                "numDistinctUsers":120,
                "reports":[{"categories":[18,22]},{"categories":[14,18]}]
            }}"#,
        );
        let e = build_ip_entity("9.9.9.9", &d, "scan");
        assert!(e.has_tag("malicious") && e.has_tag("high-risk") && e.has_tag("threat-intel"));
        assert!((e.confidence - (0.60 + 0.92 * 0.35)).abs() < 1e-9);
        let a = &e.evidence[0].attributes;
        assert_eq!(a.get("country_name").map(String::as_str), Some("Russia"));
        assert_eq!(a.get("domain").map(String::as_str), Some("evilhost.ru"));
        assert_eq!(
            a.get("hostnames").map(String::as_str),
            Some("mail.evilhost.ru")
        );
        assert_eq!(a.get("num_distinct_users").map(String::as_str), Some("120"));
        assert_eq!(
            a.get("last_reported_at").map(String::as_str),
            Some("2026-01-01T00:00:00+00:00")
        );
        // Distinct categories, deduped + sorted by code (14,18,22), as names.
        assert_eq!(
            a.get("attack_categories").map(String::as_str),
            Some("Port Scan, Brute-Force, SSH")
        );
    }

    #[test]
    fn build_entity_tags_whitelisted_benign_ip() {
        let d =
            data_of(r#"{"data":{"abuseConfidenceScore":0,"isWhitelisted":true,"isp":"Google"}}"#);
        let e = build_ip_entity("8.8.8.8", &d, "scan");
        assert!(e.has_tag("whitelisted"));
        assert!(!e.has_tag("malicious") && !e.has_tag("suspicious"));
        assert_eq!(
            e.evidence[0]
                .attributes
                .get("is_whitelisted")
                .map(String::as_str),
            Some("true")
        );
    }

    #[tokio::test]
    async fn process_emits_reverse_dns_domain_pivots() {
        // The verbose hostnames/domain behind a flagged IP must become Domain
        // seeds (IP literals and dotless junk are rejected).
        let d = data_of(
            r#"{"data":{"abuseConfidenceScore":80,"domain":"evil.com",
                "hostnames":["a.evil.com","evil.com","1.2.3.4",""]}}"#,
        );
        // Exercise the same pivot logic process() uses.
        let mut doms: Vec<String> = Vec::new();
        let mut seen = std::collections::HashSet::new();
        for host in d
            .hostnames
            .iter()
            .map(String::as_str)
            .chain(d.domain.as_deref())
        {
            let host = host.trim().trim_end_matches('.').to_lowercase();
            if host.contains('.')
                && host.parse::<std::net::IpAddr>().is_err()
                && seen.insert(host.clone())
            {
                doms.push(host);
            }
        }
        assert!(doms.contains(&"a.evil.com".to_string()));
        assert!(doms.contains(&"evil.com".to_string()));
        assert!(!doms.iter().any(|h| h == "1.2.3.4"), "IP literal rejected");
        assert_eq!(
            doms.iter()
                .filter(|h| *h == &"evil.com".to_string())
                .count(),
            1,
            "domain deduped against hostnames"
        );
    }
}
