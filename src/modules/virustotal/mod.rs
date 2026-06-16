//! VirusTotal — URL and domain reputation scanning via the VT v3 API.
//!
//! Queries the VirusTotal API for domain/IP analysis results and tags the
//! scanned entity with the full detection breakdown (malicious / suspicious /
//! undetected / harmless), a detection-ratio-scaled confidence, and the
//! community reputation score. A *suspicious* detection with zero malicious is
//! still flagged — the old code only tagged on `malicious > 0`, silently
//! dropping that signal. Requires `HUNTSMAN_VIRUSTOTAL_KEY`.
//!
//! Beyond reputation, the VT v3 record is a passive-DNS / network-ownership
//! goldmine that the module previously discarded: the network operator
//! (`as_owner` → Organisation), `asn` (→ Asn), the announcing `network` CIDR,
//! the registration `country` (→ Address), site `categories`, crowd `tags`,
//! and crucially `last_dns_records` — A/AAAA records (→ IpAddress) and
//! MX/NS/CNAME hosts (→ Domain). Every one is now surfaced as a pivot.
//!
//! The response → entity mapping lives in the pure [`build_entities`] so the
//! detection ratio, confidence, tags and every pivot are unit-tested without a
//! live API; `process` owns only URL/auth/transport.

use async_trait::async_trait;
use serde::Deserialize;

use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::{Module, ModuleCategory, ModuleContext, ModuleCost, ModuleResult},
    scan::{Target, TargetKind},
    tags,
};

const SRC: &str = "virustotal";
/// VT's community reputation is a signed vote score; at/below this it is a
/// negative-reputation signal worth a tag in its own right.
const LOW_REPUTATION_THRESHOLD: i64 = -10;
/// Cap on passive-DNS records expanded into pivot entities from one record — a
/// busy domain can list dozens of historical A/MX entries; this keeps graph
/// expansion bounded while still surfacing the salient pivots.
const MAX_DNS_RECORDS: usize = 30;

pub struct VirusTotal;

#[derive(Deserialize)]
struct VtResponse {
    data: Option<VtData>,
}

#[derive(Deserialize)]
struct VtData {
    attributes: Option<VtAttributes>,
}

#[derive(Deserialize)]
struct VtAttributes {
    last_analysis_stats: Option<VtStats>,
    reputation: Option<i64>,
    /// Network operator name (e.g. "CLOUDFLARENET") — IP records carry this.
    #[serde(default)]
    as_owner: Option<String>,
    /// Autonomous System Number announcing the address.
    #[serde(default)]
    asn: Option<u64>,
    /// Announced CIDR the address falls in (e.g. "1.1.1.0/24").
    #[serde(default)]
    network: Option<String>,
    /// Two-letter registration country of the address/domain.
    #[serde(default)]
    country: Option<String>,
    /// Crowd-sourced threat/behaviour tags (e.g. "phishing", "malware").
    #[serde(default)]
    tags: Vec<String>,
    /// Vendor → category map (e.g. `{"BitDefender":"malware"}`); the distinct
    /// category values are surfaced as evidence.
    #[serde(default)]
    categories: std::collections::BTreeMap<String, String>,
    /// Passive-DNS records — A/AAAA (IP pivots) and MX/NS/CNAME (domain pivots).
    #[serde(default)]
    last_dns_records: Vec<VtDnsRecord>,
}

#[derive(Deserialize)]
struct VtDnsRecord {
    #[serde(default, rename = "type")]
    record_type: Option<String>,
    #[serde(default)]
    value: Option<String>,
}

#[derive(Deserialize)]
struct VtStats {
    #[serde(default)]
    malicious: u32,
    #[serde(default)]
    suspicious: u32,
    #[serde(default)]
    undetected: u32,
    #[serde(default)]
    harmless: u32,
}

/// Trim an optional string, returning `None` if it is absent or blank.
fn nonblank(s: Option<&str>) -> Option<&str> {
    s.map(str::trim).filter(|v| !v.is_empty())
}

/// Map a VT analysis record onto the scanned entity plus every network /
/// passive-DNS pivot it carries. **Pure** (no network/IO) so the detection
/// ratio, confidence, tags and pivots are all unit-tested directly. The
/// scanned entity is always element 0; pivots (Organisation / Asn / Address /
/// IpAddress / Domain) follow.
///
/// Confidence scales with the malicious detection ratio (0.50 baseline → 0.95
/// at 100% malicious); a thin/empty stats block stays at the 0.50 baseline.
fn build_entities(target: &Target, attrs: &VtAttributes, scan_id: &str) -> Vec<Entity> {
    let stats = attrs.last_analysis_stats.as_ref();
    let malicious = stats.map_or(0, |s| s.malicious);
    let suspicious = stats.map_or(0, |s| s.suspicious);
    let total = stats.map_or(0, |s| {
        s.malicious + s.suspicious + s.undetected + s.harmless
    });

    let confidence = if total > 0 {
        0.50 + (malicious as f64 / total as f64) * 0.45
    } else {
        0.50
    };

    let mut e = Entity::new(
        target.kind.to_entity_kind(),
        &target.value,
        confidence,
        scan_id,
    );
    e.tag(SRC);
    if malicious > 0 {
        e.tag(tags::MALICIOUS);
        e.tag(tags::THREAT_INTEL);
    }
    // A suspicious-but-not-malicious verdict is a real signal the old code lost.
    if suspicious > 0 {
        e.tag("suspicious");
    }
    if attrs
        .reputation
        .is_some_and(|r| r <= LOW_REPUTATION_THRESHOLD)
    {
        e.tag("low-reputation");
    }
    // Crowd tags double as entity tags so correlators can match on them.
    for t in &attrs.tags {
        let t = t.trim();
        if !t.is_empty() {
            e.tag(format!("vt:{t}"));
        }
    }

    let mut ev = Evidence::new(
        SRC,
        format!(
            "{}/{} engines flagged {} as malicious",
            malicious, total, target.value
        ),
    )
    .with_attr("malicious", malicious.to_string())
    .with_attr("total_engines", total.to_string());
    if let Some(s) = stats {
        // The full breakdown — previously summed into `total` and discarded.
        ev = ev
            .with_attr("suspicious", s.suspicious.to_string())
            .with_attr("undetected", s.undetected.to_string())
            .with_attr("harmless", s.harmless.to_string());
    }
    if let Some(rep) = attrs.reputation {
        ev = ev.with_attr("reputation", rep.to_string());
    }
    if let Some(owner) = nonblank(attrs.as_owner.as_deref()) {
        ev = ev.with_attr("as_owner", owner);
    }
    if let Some(asn) = attrs.asn {
        ev = ev.with_attr("asn", asn.to_string());
    }
    if let Some(net) = nonblank(attrs.network.as_deref()) {
        ev = ev.with_attr("network", net);
    }
    if let Some(cc) = nonblank(attrs.country.as_deref()) {
        ev = ev.with_attr("country", cc);
        e.tag(format!("country:{}", cc.to_uppercase()));
    }
    if !attrs.categories.is_empty() {
        let mut cats: Vec<&str> = attrs
            .categories
            .values()
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .collect();
        cats.sort_unstable();
        cats.dedup();
        if !cats.is_empty() {
            ev = ev.with_attr("categories", cats.join(","));
        }
    }
    if !attrs.tags.is_empty() {
        ev = ev.with_attr("tags", attrs.tags.join(","));
    }
    e.add_evidence(ev);

    let mut out = vec![e];
    let label = target.value.as_str();

    // ── Network ownership pivots (mostly IP records) ─────────────────────
    if let Some(owner) = nonblank(attrs.as_owner.as_deref()) {
        let mut o = Entity::new(EntityKind::Organisation, owner, 0.65, scan_id);
        o.tag(SRC);
        o.tag(tags::HOSTING);
        o.add_evidence(
            Evidence::new(
                SRC,
                format!("Network operator (AS owner) of {label} per VirusTotal"),
            )
            .with_attr("subject", label),
        );
        out.push(o);
    }
    if let Some(asn) = attrs.asn {
        let asn_label = format!("AS{asn}");
        let mut a = Entity::new(EntityKind::Asn, &asn_label, 0.78, scan_id);
        a.tag(SRC);
        let mut aev = Evidence::new(SRC, format!("ASN announcing {label} per VirusTotal"))
            .with_attr("subject", label);
        if let Some(net) = nonblank(attrs.network.as_deref()) {
            aev = aev.with_attr("network", net);
        }
        a.add_evidence(aev);
        out.push(a);
    }
    if let Some(cc) = nonblank(attrs.country.as_deref()) {
        let mut addr = Entity::new(EntityKind::Address, cc.to_uppercase(), 0.55, scan_id);
        addr.tag(SRC);
        addr.tag(tags::GEOINT);
        addr.tag(tags::COARSE);
        addr.add_evidence(
            Evidence::new(
                SRC,
                format!("Registration country for {label} per VirusTotal"),
            )
            .with_attr("subject", label),
        );
        out.push(addr);
    }

    // ── Passive-DNS pivots ───────────────────────────────────────────────
    for rec in attrs.last_dns_records.iter().take(MAX_DNS_RECORDS) {
        let Some(rtype) = rec.record_type.as_deref().map(str::trim) else {
            continue;
        };
        let Some(value) = rec
            .value
            .as_deref()
            .map(|v| v.trim().trim_end_matches('.'))
            .filter(|v| !v.is_empty())
        else {
            continue;
        };
        match rtype.to_ascii_uppercase().as_str() {
            "A" | "AAAA" => {
                if value.parse::<std::net::IpAddr>().is_ok() {
                    let mut ip = Entity::new(EntityKind::IpAddress, value, 0.82, scan_id);
                    ip.tag(SRC);
                    ip.tag("resolved");
                    ip.add_evidence(
                        Evidence::new(SRC, format!("{rtype} record for {label} per VirusTotal"))
                            .with_attr("domain", label)
                            .with_attr("record_type", rtype),
                    );
                    out.push(ip);
                }
            }
            "MX" | "NS" | "CNAME" => {
                // MX values may be "10 mail.host" — keep only the hostname.
                let host = value.split_whitespace().last().unwrap_or(value);
                let host = host.trim_end_matches('.');
                if host.contains('.')
                    && host.parse::<std::net::IpAddr>().is_err()
                    && !host.contains(char::is_whitespace)
                {
                    let mut d = Entity::new(EntityKind::Domain, host, 0.78, scan_id);
                    d.tag(SRC);
                    d.tag("passive-dns");
                    d.add_evidence(
                        Evidence::new(SRC, format!("{rtype} record for {label} per VirusTotal"))
                            .with_attr("domain", label)
                            .with_attr("record_type", rtype),
                    );
                    out.push(d);
                }
            }
            _ => {}
        }
    }

    out
}

#[async_trait]
impl Module for VirusTotal {
    fn name(&self) -> &'static str {
        SRC
    }
    fn description(&self) -> &'static str {
        "VirusTotal domain/IP/URL reputation and detection ratios"
    }
    fn priority(&self) -> u8 {
        55
    }
    fn cost(&self) -> ModuleCost {
        ModuleCost::KeyGated
    }
    fn max_timeout_ms(&self) -> u64 {
        10_000
    }
    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::Domain | TargetKind::IpAddress)
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Threat
    }

    fn attack_techniques(&self) -> &'static [&'static str] {
        // VT is a passive scan/reputation database (T1596.005) gathering IP
        // address info (T1590.005). The amplified module also resolves the
        // operator as an Organisation (T1591.002 Business Relationships) and
        // the registration country as an Address (T1591.001 Physical
        // Locations) — neither covered by the Threat default.
        &["T1590.005", "T1591.001", "T1591.002", "T1596.005"]
    }

    fn produces(&self) -> &'static [EntityKind] {
        // Scanned entity (Domain or IpAddress) plus passive-DNS / ownership
        // pivots: A/AAAA → IpAddress, MX/NS/CNAME → Domain, as_owner →
        // Organisation, asn → Asn, country → Address.
        const KINDS: &[EntityKind] = &[
            EntityKind::Domain,
            EntityKind::IpAddress,
            EntityKind::Asn,
            EntityKind::Organisation,
            EntityKind::Address,
        ];
        KINDS
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let mut result = ModuleResult::new();

        let url = match target.kind {
            TargetKind::Domain => format!(
                "https://www.virustotal.com/api/v3/domains/{}",
                crate::util::http::urlencode(&target.value)
            ),
            TargetKind::IpAddress => format!(
                "https://www.virustotal.com/api/v3/ip_addresses/{}",
                crate::util::http::urlencode(&target.value)
            ),
            _ => return Ok(result),
        };

        let Some(body) = crate::util::http::fetch_keyed_json::<VtResponse>(
            ctx,
            SRC,
            &url,
            "HUNTSMAN_VIRUSTOTAL_KEY",
            "x-apikey",
        )
        .await?
        else {
            return Ok(result);
        };

        let Some(attrs) = body.data.and_then(|d| d.attributes) else {
            return Ok(result);
        };

        for entity in build_entities(target, &attrs, &ctx.scan_id) {
            result.push(entity);
        }
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
