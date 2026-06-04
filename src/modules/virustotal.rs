//! VirusTotal — URL and domain reputation scanning via the VT v3 API.
//!
//! Queries the VirusTotal API for domain/IP analysis results and tags the entity
//! with the full detection breakdown (malicious / suspicious / undetected /
//! harmless), a detection-ratio-scaled confidence, and the community reputation
//! score. A *suspicious* detection with zero malicious is still flagged — the
//! old code only tagged on `malicious > 0`, silently dropping that signal.
//! Requires `HUNTSMAN_VIRUSTOTAL_KEY`.
//!
//! The response → entity mapping lives in the pure [`build_entity`] so it is
//! unit-tested without a live API; `process` owns only URL/auth/transport.

use async_trait::async_trait;
use serde::Deserialize;

use crate::core::{
    entity::{Entity, Evidence},
    error::Result,
    module::{Module, ModuleCategory, ModuleContext, ModuleCost, ModuleResult},
    scan::{Target, TargetKind},
};

const SRC: &str = "virustotal";
/// VT's community reputation is a signed vote score; at/below this it is a
/// negative-reputation signal worth a tag in its own right.
const LOW_REPUTATION_THRESHOLD: i64 = -10;

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

/// Map VT analysis attributes onto the scanned entity. **Pure** (no network/IO)
/// so the detection ratio, confidence, and every tag is unit-tested directly.
///
/// Confidence scales with the malicious detection ratio (0.50 baseline → 0.95 at
/// 100% malicious); a thin/empty stats block stays at the 0.50 baseline.
fn build_entity(target: &Target, attrs: &VtAttributes, scan_id: &str) -> Entity {
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
    e.tag("virustotal");
    if malicious > 0 {
        e.tag("malicious");
        e.tag("threat-intel");
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
    e
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

        result.push(build_entity(target, &attrs, &ctx.scan_id));
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::entity::EntityKind;

    fn build(json: &str) -> Entity {
        let r: VtResponse = serde_json::from_str(json).unwrap();
        let attrs = r.data.unwrap().attributes.unwrap();
        build_entity(
            &Target::new(TargetKind::Domain, "evil.example"),
            &attrs,
            "s",
        )
    }

    #[test]
    fn module_metadata() {
        let m = VirusTotal;
        assert_eq!(m.name(), "virustotal");
        assert!(m.accepts(&Target::new(TargetKind::Domain, "x.com")));
        assert!(m.accepts(&Target::new(TargetKind::IpAddress, "8.8.8.8")));
        assert!(!m.accepts(&Target::new(TargetKind::Email, "x@y.com")));
        assert!(matches!(m.cost(), ModuleCost::KeyGated));
    }

    #[test]
    fn malicious_detections_tag_and_scale_confidence() {
        let e = build(
            r#"{"data":{"attributes":{"last_analysis_stats":
                {"malicious":9,"suspicious":1,"undetected":80,"harmless":10},"reputation":5}}}"#,
        );
        assert_eq!(e.kind, EntityKind::Domain);
        assert!(e.has_tag("malicious") && e.has_tag("threat-intel") && e.has_tag("virustotal"));
        assert!(e.has_tag("suspicious")); // surfaced even alongside malicious
        // confidence = 0.50 + (9/100)*0.45 = 0.5405
        assert!((e.confidence - 0.5405).abs() < 1e-6);
        let ev = &e.evidence[0];
        assert_eq!(
            ev.attributes.get("malicious").map(String::as_str),
            Some("9")
        );
        assert_eq!(
            ev.attributes.get("total_engines").map(String::as_str),
            Some("100")
        );
        // The full breakdown the old code discarded:
        assert_eq!(
            ev.attributes.get("suspicious").map(String::as_str),
            Some("1")
        );
        assert_eq!(
            ev.attributes.get("undetected").map(String::as_str),
            Some("80")
        );
        assert_eq!(
            ev.attributes.get("harmless").map(String::as_str),
            Some("10")
        );
        assert_eq!(
            ev.attributes.get("reputation").map(String::as_str),
            Some("5")
        );
    }

    #[test]
    fn suspicious_only_is_flagged_without_malicious() {
        // The exact case the old `if malicious > 0` gate silently dropped.
        let e = build(
            r#"{"data":{"attributes":{"last_analysis_stats":
                {"malicious":0,"suspicious":4,"undetected":90,"harmless":6}}}}"#,
        );
        assert!(e.has_tag("suspicious"));
        assert!(!e.has_tag("malicious") && !e.has_tag("threat-intel"));
        assert!((e.confidence - 0.50).abs() < 1e-6); // no malicious → baseline
    }

    #[test]
    fn strongly_negative_reputation_is_tagged() {
        let bad = build(r#"{"data":{"attributes":{"reputation":-42}}}"#);
        assert!(bad.has_tag("low-reputation"));
        let ok = build(r#"{"data":{"attributes":{"reputation":-3}}}"#);
        assert!(!ok.has_tag("low-reputation"));
    }

    #[test]
    fn clean_entity_carries_only_the_source_tag() {
        let e = build(
            r#"{"data":{"attributes":{"last_analysis_stats":
                {"malicious":0,"suspicious":0,"undetected":95,"harmless":5},"reputation":10}}}"#,
        );
        assert!(e.has_tag("virustotal"));
        for t in ["malicious", "threat-intel", "suspicious", "low-reputation"] {
            assert!(!e.has_tag(t), "clean entity must not be tagged {t}");
        }
    }

    #[test]
    fn empty_attributes_stay_at_baseline_without_phantom_reputation() {
        let e = build(r#"{"data":{"attributes":{}}}"#);
        assert!((e.confidence - 0.50).abs() < 1e-6);
        let ev = &e.evidence[0];
        assert_eq!(
            ev.attributes.get("total_engines").map(String::as_str),
            Some("0")
        );
        // No stats → no breakdown attrs; absent reputation → no phantom "0".
        assert!(!ev.attributes.contains_key("undetected"));
        assert!(!ev.attributes.contains_key("reputation"));
    }
}
