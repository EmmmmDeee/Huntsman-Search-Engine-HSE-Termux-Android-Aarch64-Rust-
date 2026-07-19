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
        "AbuseIPDB reputation recon — pivots an IP to its abuse-confidence score and community report history"
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
    ip_entity.tag(crate::core::tags::THREAT_INTEL);
    if abuse_score >= 80 {
        ip_entity.tag(crate::core::tags::MALICIOUS);
        ip_entity.tag("high-risk");
    } else if abuse_score >= 40 {
        ip_entity.tag("suspicious");
    }
    if data.is_tor.unwrap_or(false) {
        ip_entity.tag("tor-exit");
    }
    // Usage type → a first-class infrastructure tag (consistent with the
    // ipquery/ip2location "hosting" signal), so a datacenter/hosting IP — whose
    // geolocation is the facility, not a subject — is filterable, not just an
    // evidence string.
    if data.usage_type.as_deref().is_some_and(|u| {
        let u = u.to_ascii_lowercase();
        u.contains("data center") || u.contains("datacenter") || u.contains("hosting")
    }) {
        ip_entity.tag("hosting");
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
    include!("tests.rs");
}
