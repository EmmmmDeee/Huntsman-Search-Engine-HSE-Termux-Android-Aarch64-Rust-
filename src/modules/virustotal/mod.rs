//! VirusTotal — URL and domain reputation scanning via the VT v3 API.
//!
//! Queries the VirusTotal API for domain/IP analysis results and tags the entity
//! with the full detection breakdown (malicious / suspicious / undetected /
//! harmless), a detection-ratio-scaled confidence, and the community reputation
//! score. A *suspicious* detection with zero malicious is still flagged — the
//! old code only tagged on `malicious > 0`, silently dropping that signal.
//! Requires `HUNTSMAN_VIRUSTOTAL_KEY`.
//!
//! The same VT v3 record also carries `last_dns_records` — a lightweight
//! passive-DNS snapshot (A/AAAA/MX/NS/CNAME) VT already returns on this
//! already-called endpoint but the module previously deserialized straight
//! into a narrow struct that silently dropped it. Historical A/AAAA values
//! become `IpAddress` pivots; MX/NS/CNAME hostnames become `Domain` pivots.
//!
//! The response → entity mapping lives in the pure [`build_entities`] so it is
//! unit-tested without a live API; `process` owns only URL/auth/transport.

use async_trait::async_trait;
use serde::Deserialize;

use crate::core::{
    confidence,
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::{Module, ModuleCategory, ModuleContext, ModuleCost, ModuleResult},
    scan::{Target, TargetKind},
};

const SRC: &str = "virustotal";

/// VirusTotal's deterministic URL identifier: the unpadded base64url encoding
/// of the exact URL string (VT's documented `/urls/{id}` scheme). **Pure**, so
/// the id derivation is unit-tested without a live API.
fn vt_url_id(url: &str) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(url.as_bytes())
}

/// VT's community reputation is a signed vote score; at/below this it is a
/// negative-reputation signal worth a tag in its own right.
const LOW_REPUTATION_THRESHOLD: i64 = -10;
/// Cap on passive-DNS records expanded into pivot entities — a long-lived
/// domain can list dozens of historical records; this keeps graph expansion
/// bounded while still surfacing the salient pivots.
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
    /// Passive-DNS snapshot — A/AAAA (IP pivots) and MX/NS/CNAME (domain
    /// pivots). Absent unless VT has resolution history for the target.
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

/// Map VT analysis attributes onto the scanned entity plus every passive-DNS
/// pivot it carries. **Pure** (no network/IO) so the detection ratio,
/// confidence, tags, and pivots are all unit-tested directly. The scanned
/// entity is always element 0; passive-DNS pivots (`IpAddress`/`Domain`)
/// follow.
///
/// Confidence scales with the malicious detection ratio (confidence::MEDIUM baseline → confidence::VERY_HIGH_PLUSPLUS at
/// 100% malicious); a thin/empty stats block stays at the confidence::MEDIUM baseline.
fn build_entities(target: &Target, attrs: &VtAttributes, scan_id: &str) -> Vec<Entity> {
    let stats = attrs.last_analysis_stats.as_ref();
    let malicious = stats.map_or(0, |s| s.malicious);
    let suspicious = stats.map_or(0, |s| s.suspicious);
    let total = stats.map_or(0, |s| {
        s.malicious + s.suspicious + s.undetected + s.harmless
    });

    let confidence = if total > 0 {
        confidence::MEDIUM + (malicious as f64 / total as f64) * confidence::LOW_MEDIUM
    } else {
        confidence::MEDIUM
    };

    let mut e = Entity::new(
        target.kind.to_entity_kind(),
        &target.value,
        confidence,
        scan_id,
    );
    e.tag("virustotal");
    if malicious > 0 {
        e.tag(crate::core::tags::MALICIOUS);
        e.tag(crate::core::tags::THREAT_INTEL);
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
    e.add_evidence(ev);

    let mut out = vec![e];
    let label = target.value.as_str();

    // Never drop silently. Unlike `overpass`, whose per-node cap is backed by a
    // summary entity carrying the true total, nothing here records the records
    // beyond the cap — so a domain with 200 historical entries would present 30
    // as though that were all of them. An operator reading a passive-DNS pivot
    // list must be able to tell "this domain has 30 records" from "30 of 200 are
    // shown", exactly as `sanctions_ofac` does for its own bounded emission.
    let dns_total = attrs.last_dns_records.len();
    if dns_total > MAX_DNS_RECORDS {
        tracing::warn!(
            module = SRC,
            domain = label,
            total = dns_total,
            emitted = MAX_DNS_RECORDS,
            "VirusTotal passive DNS truncated — the remaining records are NOT in this \
             scan's results"
        );
    }

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
                    let mut d = Entity::new(EntityKind::Domain, host, confidence::STRONG, scan_id);
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
        "VirusTotal recon — correlates domain/IP/URL reputation and engine detection ratios"
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
        matches!(
            t.kind,
            TargetKind::Domain | TargetKind::IpAddress | TargetKind::Url
        )
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Threat
    }

    fn produces(&self) -> &'static [EntityKind] {
        // The scanned entity (Domain, IpAddress, or Url), enriched in-place,
        // plus passive-DNS pivots from last_dns_records: A/AAAA -> IpAddress,
        // MX/NS/CNAME -> Domain (the URL object carries no passive DNS).
        const KINDS: &[EntityKind] = &[EntityKind::Domain, EntityKind::IpAddress, EntityKind::Url];
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
            // VT's URL object is addressed by the unpadded base64url of the URL;
            // its last_analysis_stats/reputation are identical to the domain/IP
            // objects, so build_entities decodes it unchanged (last_dns_records
            // is simply absent for this object type).
            TargetKind::Url => format!(
                "https://www.virustotal.com/api/v3/urls/{}",
                vt_url_id(target.value.trim())
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
