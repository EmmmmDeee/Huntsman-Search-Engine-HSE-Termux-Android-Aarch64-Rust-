//! AbuseIPDB — IP abuse/threat reputation + resolved-domain / ISP discovery.
//!
//! Queries the AbuseIPDB v2 `/check` API for abuse confidence score, report
//! count, usage type, Tor flag, ISP, and the IP's resolved `domain` and
//! reverse-DNS `hostnames`. Emits the abuse-scored IP, each associated Domain
//! (a first-class DNS / cert / WHOIS pivot the module previously discarded),
//! and the ISP as an Organisation. Key-gated (`HUNTSMAN_ABUSEIPDB_KEY`).

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

    fn attack_techniques(&self) -> &'static [&'static str] {
        // AbuseIPDB is an open reputation/scan database (T1596.005) and gathers
        // IP address info (T1590.005). It also identifies the ISP/network operator
        // as an Organisation entity (T1591.002 Business Relationships) — absent
        // from the Infrastructure default.
        &["T1590.005", "T1591.002", "T1596.005"]
    }

    fn produces(&self) -> &'static [EntityKind] {
        const KINDS: &[EntityKind] = &[
            EntityKind::IpAddress,
            EntityKind::Domain,
            EntityKind::Organisation,
        ];
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

        result.entities = build_entities(&data, &target.value, &ctx.scan_id);
        Ok(result)
    }
}

/// Map an AbuseIPDB `/check` record to entities. **Pure** (no network/IO):
/// always yields the abuse-scored `IpAddress`, plus a `Domain` for the IP's
/// `domain` and each reverse-DNS `hostname` (deduped; IP-shaped and dotless
/// hosts dropped) and an `Organisation` for the ISP. The resolved domains are
/// first-class DNS/cert/WHOIS pivots the module used to discard.
fn build_entities(data: &AbuseData, ip: &str, scan_id: &str) -> Vec<Entity> {
    let abuse_score = data.abuse_confidence_score.unwrap_or(0);
    let confidence = 0.60 + (abuse_score as f64 / 100.0) * 0.35;

    let mut ip_entity = Entity::new(EntityKind::IpAddress, ip, confidence, scan_id);
    ip_entity.tag("threat-intel");
    if abuse_score >= 80 {
        ip_entity.tag("malicious");
        ip_entity.tag("high-risk");
    } else if abuse_score >= 40 {
        ip_entity.tag("suspicious");
    }
    if data.is_tor.unwrap_or(false) {
        ip_entity.tag("tor-exit");
    }

    let ev = [
        ("isp", data.isp.as_deref()),
        ("usage_type", data.usage_type.as_deref()),
        ("country_code", data.country_code.as_deref()),
        ("domain", data.domain.as_deref()),
    ]
    .into_iter()
    .filter_map(|(key, value)| value.map(|v| (key, v)))
    .fold(
        Evidence::new(
            SRC,
            format!(
                "AbuseIPDB: {abuse_score}% abuse confidence, {} reports",
                data.total_reports.unwrap_or(0)
            ),
        )
        .with_attr("abuse_score", abuse_score.to_string())
        .with_attr("total_reports", data.total_reports.unwrap_or(0).to_string()),
        |ev, (key, v)| ev.with_attr(key, v),
    );
    ip_entity.add_evidence(ev);

    let mut out = vec![ip_entity];

    // Resolved domains (`domain` + reverse-DNS `hostnames`) → first-class pivots.
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    out.extend(
        std::iter::once(data.domain.as_deref())
            .chain(data.hostnames.iter().map(|h| Some(h.as_str())))
            .flatten()
            .map(str::trim)
            .map(str::to_ascii_lowercase)
            .filter(|h| {
                !h.is_empty()
                    && h.contains('.')
                    && h.parse::<std::net::IpAddr>().is_err()
                    && seen.insert(h.clone())
            })
            .map(|host| {
                let mut d = Entity::new(EntityKind::Domain, &host, 0.72, scan_id);
                d.tag("abuseipdb");
                d.tag("resolved-domain");
                d.add_evidence(
                    Evidence::new(SRC, format!("Domain associated with {ip} per AbuseIPDB"))
                        .with_attr("ip", ip),
                );
                d
            }),
    );

    // ISP / operator → Organisation pivot.
    if let Some(isp) = data.isp.as_deref().map(str::trim).filter(|s| s.len() >= 2) {
        let mut o = Entity::new(EntityKind::Organisation, isp, 0.60, scan_id);
        o.tag("abuseipdb");
        o.tag("isp");
        o.add_evidence(
            Evidence::new(SRC, format!("ISP/operator of {ip} per AbuseIPDB")).with_attr("ip", ip),
        );
        out.push(o);
    }

    out
}

#[derive(Deserialize)]
struct AbuseResponse {
    data: Option<AbuseData>,
}

#[allow(dead_code)]
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
    /// The IP's primary resolved domain (AbuseIPDB `domain` field).
    #[serde(default)]
    domain: Option<String>,
    /// Reverse-DNS hostnames the IP resolves to (`hostnames` field).
    #[serde(default)]
    hostnames: Vec<String>,
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
        assert!(d.domain.is_none());
        assert!(d.hostnames.is_empty());
    }

    #[test]
    fn build_entities_surfaces_resolved_domains_and_isp() {
        // The verbose /check response carries `domain` + `hostnames` + `isp` —
        // real pivots the module used to discard, leaving only the seed IP.
        let data: AbuseData = serde_json::from_str(
            r#"{"abuseConfidenceScore":90,"totalReports":12,"isTor":false,
                "isp":"DigitalOcean, LLC","usageType":"Data Center/Web Hosting/Transit",
                "countryCode":"US","domain":"digitalocean.com",
                "hostnames":["mail.example.com","example.com","1.2.3.4","digitalocean.com"]}"#,
        )
        .unwrap();
        let ents = build_entities(&data, "1.2.3.4", "s");
        let has = |k: EntityKind, v: &str| ents.iter().any(|e| e.kind == k && e.value == v);

        // The abuse-scored IP is still emitted (with the domain in its evidence).
        assert!(has(EntityKind::IpAddress, "1.2.3.4"));
        let ip = ents
            .iter()
            .find(|e| e.kind == EntityKind::IpAddress)
            .unwrap();
        assert!(ip.has_tag("malicious") && ip.has_tag("high-risk"));
        assert_eq!(
            ip.evidence[0].attributes.get("domain").map(String::as_str),
            Some("digitalocean.com")
        );

        // domain + hostnames → Domain pivots; IP-shaped host dropped.
        assert!(has(EntityKind::Domain, "digitalocean.com"));
        assert!(has(EntityKind::Domain, "mail.example.com"));
        assert!(has(EntityKind::Domain, "example.com"));
        assert!(
            !ents
                .iter()
                .any(|e| e.kind == EntityKind::Domain && e.value == "1.2.3.4"),
            "IP-shaped hostname must not become a Domain"
        );
        // `digitalocean.com` is in both `domain` and `hostnames` → deduped to one.
        assert_eq!(
            ents.iter()
                .filter(|e| e.kind == EntityKind::Domain && e.value == "digitalocean.com")
                .count(),
            1
        );
        // ISP → Organisation pivot (value case-normalised by Entity::new).
        assert!(ents.iter().any(|e| e.kind == EntityKind::Organisation
            && e.value.to_lowercase().contains("digitalocean")));
    }
}
