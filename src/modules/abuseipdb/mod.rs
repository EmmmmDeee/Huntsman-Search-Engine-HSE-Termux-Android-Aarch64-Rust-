//! AbuseIPDB — IP abuse/threat reputation + resolved-domain / ISP discovery.
//!
//! Queries the AbuseIPDB v2 `/check` API (with `&verbose`) for abuse confidence
//! score, report count, usage type, Tor flag, ISP, the IP's resolved `domain`
//! and reverse-DNS `hostnames`, plus the verbose payload: the most-recent report
//! timestamp, the whitelist flag, and the per-report category array. Emits the
//! abuse-scored IP (with a deterministic top-category summary + recency in
//! evidence, and a `whitelisted` tag when flagged), each associated Domain (a
//! first-class DNS / cert / WHOIS pivot the module previously discarded), and
//! the ISP as an Organisation. The raw free-text report comment is never
//! surfaced. Key-gated (`HUNTSMAN_ABUSEIPDB_KEY`).

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
    // AbuseIPDB's own false-positive flag: a whitelisted IP with a residual
    // score is very likely benign infrastructure, not a real threat.
    if data.is_whitelisted == Some(true) {
        ip_entity.tag("whitelisted");
    }

    let mut ev = [
        ("isp", data.isp.as_deref()),
        ("usage_type", data.usage_type.as_deref()),
        ("country_code", data.country_code.as_deref()),
        ("domain", data.domain.as_deref()),
        ("last_reported_at", data.last_reported_at.as_deref()),
    ]
    .into_iter()
    .filter_map(|(key, value)| value.filter(|v| !v.is_empty()).map(|v| (key, v)))
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
    // Per-report category breakdown (SSH, Port Scan, Web App Attack, …) — the
    // paid-for `&verbose` payload that materially sharpens triage over a bare
    // score. The raw free-text report comment is never surfaced.
    let category_summary = summarize_categories(&data.reports);
    if !category_summary.is_empty() {
        ev = ev.with_attr("report_categories", category_summary);
    }
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
    /// Timestamp of the most recent abuse report — recency of abuse, a far
    /// sharper triage signal than a bare confidence score. `&verbose` field.
    #[serde(rename = "lastReportedAt", default)]
    last_reported_at: Option<String>,
    /// AbuseIPDB's false-positive suppression flag — a whitelisted IP (major
    /// CDN/DNS resolver) with a residual score is very likely a false positive.
    #[serde(rename = "isWhitelisted", default)]
    is_whitelisted: Option<bool>,
    /// The per-report array `&verbose` returns and the module was paying for,
    /// then discarding. Only the numeric `categories` are modelled — the
    /// free-text `comment` is deliberately never read, let alone emitted.
    #[serde(default)]
    reports: Vec<Report>,
}

#[derive(Deserialize)]
struct Report {
    #[serde(default)]
    categories: Vec<u16>,
}

/// Map an AbuseIPDB numeric report-category id to its label. `None` for an
/// unknown id (taxonomy drift) so it is summarised as `other` rather than a bare
/// number. Source: AbuseIPDB's published category taxonomy.
fn abuse_category_label(id: u16) -> Option<&'static str> {
    Some(match id {
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
        _ => return None,
    })
}

/// Deterministic top-5 category summary across all reports, e.g.
/// `"SSH:42, Brute-Force:30, Port Scan:12"`. Counts each category occurrence,
/// then sorts by count desc with an ascending-id tie-break so the output is
/// stable across runs regardless of report order. **Pure.** Empty when no
/// report carries a category.
fn summarize_categories(reports: &[Report]) -> String {
    let mut counts: std::collections::BTreeMap<u16, usize> = std::collections::BTreeMap::new();
    for r in reports {
        for &c in &r.categories {
            *counts.entry(c).or_default() += 1;
        }
    }
    if counts.is_empty() {
        return String::new();
    }
    let mut ranked: Vec<(u16, usize)> = counts.into_iter().collect();
    ranked.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
    ranked
        .into_iter()
        .take(5)
        .map(|(id, n)| format!("{}:{n}", abuse_category_label(id).unwrap_or("other")))
        .collect::<Vec<_>>()
        .join(", ")
}

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
