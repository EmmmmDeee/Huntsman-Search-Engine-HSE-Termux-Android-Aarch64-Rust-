//! GreyNoise Community API — free IP reputation: internet noise and RIOT
//! classification.
//!
//! Endpoint: `GET https://api.greynoise.io/v3/community/{ip}`
//! Auth:     None (community tier is key-free).
//!
//! Returns whether an IP is observed scanning the internet ("noise"), is
//! part of a known-benign service ("RIOT"), and a classification label
//! (benign / malicious / unknown).
//!
//! Free, no API key required.

use async_trait::async_trait;
use serde::Deserialize;

use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::{Module, ModuleCategory, ModuleContext, ModuleResult},
    scan::{Target, TargetKind},
};
use crate::util::http::{fetch_json_or_404, urlencode};

// ── Response types ────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub(crate) struct CommunityResp {
    /// IP address queried.
    #[serde(default)]
    pub ip: Option<String>,
    /// `true` if the IP has been observed scanning the internet.
    #[serde(default)]
    pub noise: bool,
    /// `true` if the IP belongs to a known-benign service (RIOT dataset).
    #[serde(default)]
    pub riot: bool,
    /// `"benign"`, `"malicious"`, or `"unknown"`.
    #[serde(default)]
    pub classification: Option<String>,
    /// Human-readable name (e.g. "Cloudflare", "Shodan.io").
    #[serde(default)]
    pub name: Option<String>,
    /// Link to the GreyNoise visualiser page for this IP.
    #[serde(default)]
    pub link: Option<String>,
    /// Human-readable status message (e.g. "IP not observed scanning the internet").
    #[serde(default)]
    pub message: Option<String>,
}

// ── Module ────────────────────────────────────────────────────────

const SRC: &str = "greynoise";

/// Trimmed, non-empty view of an optional string field.
fn nonempty(o: &Option<String>) -> Option<&str> {
    o.as_deref().map(str::trim).filter(|s| !s.is_empty())
}

/// Build the reputation `IpAddress` entity from a GreyNoise community record.
/// **Pure** (no IO) so the classification→confidence/tag mapping — which the
/// correlator's `is_benign_infra` veto keys off via the `greynoise-riot` /
/// `greynoise-benign` tags — is unit-tested directly. Returns `None` for the
/// "IP not in dataset" reply (no noise, no RIOT, no classification), the
/// no-findings case `process` previously inlined.
///
/// Surfaces the previously-discarded `message` status text, and — when GreyNoise
/// echoes a different IP than queried (`queried_ip`) — flags `ip-mismatch`, so a
/// verdict that is actually about another host can't masquerade as this one's.
fn build_entity(ip: &str, data: &CommunityResp, scan_id: &str) -> Option<Entity> {
    if !data.noise && !data.riot && data.classification.is_none() {
        return None;
    }

    let confidence = match data.classification.as_deref() {
        Some("malicious") => 0.80,
        Some("benign") => 0.70,
        _ => 0.55,
    };

    let mut entity = Entity::new(EntityKind::IpAddress, ip, confidence, scan_id);
    if data.noise {
        entity.tag("greynoise-noise");
    }
    if data.riot {
        entity.tag("greynoise-riot");
    }
    match data.classification.as_deref() {
        Some("malicious") => {
            entity.tag("malicious");
            entity.tag("greynoise-malicious");
        }
        Some("benign") => entity.tag("greynoise-benign"),
        _ => entity.tag("greynoise-unknown"),
    }

    let echoed = nonempty(&data.ip);
    let mismatch = echoed.is_some_and(|e| e != ip);
    if mismatch {
        entity.tag("ip-mismatch");
    }

    let classification = data.classification.as_deref().unwrap_or("unknown");
    let mut ev = Evidence::new(
        SRC,
        format!(
            "GreyNoise: classification={classification}, noise={}, riot={}",
            data.noise, data.riot
        ),
    )
    .with_attr("classification", classification)
    .with_attr("noise", data.noise.to_string())
    .with_attr("riot", data.riot.to_string());
    if let Some(name) = nonempty(&data.name) {
        ev = ev.with_attr("name", name);
    }
    if let Some(link) = nonempty(&data.link) {
        ev = ev.with_attr("link", link);
    }
    if let Some(message) = nonempty(&data.message) {
        ev = ev.with_attr("message", message);
    }
    if mismatch && let Some(e) = echoed {
        ev = ev.with_attr("queried_ip", e);
    }
    entity.add_evidence(ev);
    Some(entity)
}

pub struct GreyNoise;

#[async_trait]
impl Module for GreyNoise {
    fn name(&self) -> &'static str {
        "greynoise"
    }

    fn description(&self) -> &'static str {
        "GreyNoise IP reputation: internet noise and RIOT classification"
    }

    fn priority(&self) -> u8 {
        30
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
        // Single network request with no per-request timeout (governed only
        // by the client's 5s connect timeout). On the 3s default the engine
        // killed a slow-but-connected response as a spurious "timeout".
        10_000
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let ip = target.value.trim();
        if ip.is_empty() {
            return Ok(ModuleResult::new());
        }

        let url = format!("https://api.greynoise.io/v3/community/{}", urlencode(ip));

        let Some(data): Option<CommunityResp> = fetch_json_or_404(&ctx.http, SRC, &url).await?
        else {
            return Ok(ModuleResult::new());
        };

        // GreyNoise returns 200 with `message: "IP not observed ..."` for IPs
        // not in its dataset; `build_entity` maps those to `None` (no findings).
        let Some(entity) = build_entity(ip, &data, &ctx.scan_id) else {
            return Ok(ModuleResult::new());
        };

        let mut result = ModuleResult::new();
        result.push(entity);
        Ok(result)
    }
}

// ── Tests ─────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_ip_only() {
        let m = GreyNoise;
        assert!(m.accepts(&Target::new(TargetKind::IpAddress, "1.2.3.4")));
        assert!(!m.accepts(&Target::new(TargetKind::Domain, "example.com")));
        assert!(!m.accepts(&Target::new(TargetKind::Email, "a@b.com")));
        assert!(!m.accepts(&Target::new(TargetKind::Username, "user")));
    }

    #[test]
    fn module_metadata() {
        let m = GreyNoise;
        assert_eq!(m.name(), "greynoise");
        assert_eq!(m.priority(), 30);
        assert_eq!(
            m.description(),
            "GreyNoise IP reputation: internet noise and RIOT classification"
        );
        // Free, community tier — no API key required.
        assert!(matches!(m.cost(), crate::core::module::ModuleCost::Free));
    }

    #[test]
    fn response_deserialization_full() {
        let json = r#"{
            "ip": "8.8.8.8",
            "noise": true,
            "riot": true,
            "classification": "benign",
            "name": "Google Public DNS",
            "link": "https://viz.greynoise.io/ip/8.8.8.8",
            "message": "Success"
        }"#;
        let resp: CommunityResp = serde_json::from_str(json).unwrap();
        assert_eq!(resp.ip.as_deref(), Some("8.8.8.8"));
        assert!(resp.noise);
        assert!(resp.riot);
        assert_eq!(resp.classification.as_deref(), Some("benign"));
        assert_eq!(resp.name.as_deref(), Some("Google Public DNS"));
        assert_eq!(
            resp.link.as_deref(),
            Some("https://viz.greynoise.io/ip/8.8.8.8")
        );
    }

    #[test]
    fn response_deserialization_minimal() {
        // GreyNoise returns a minimal body for IPs not in its dataset.
        let json = r#"{
            "ip": "192.168.1.1",
            "noise": false,
            "riot": false,
            "message": "IP not observed scanning the internet or contained in RIOT data set."
        }"#;
        let resp: CommunityResp = serde_json::from_str(json).unwrap();
        assert!(!resp.noise);
        assert!(!resp.riot);
        assert!(resp.classification.is_none());
        assert!(resp.name.is_none());
        assert!(resp.link.is_none());
    }

    #[test]
    fn response_deserialization_malicious() {
        let json = r#"{
            "ip": "71.6.135.131",
            "noise": true,
            "riot": false,
            "classification": "malicious",
            "name": "unknown",
            "link": "https://viz.greynoise.io/ip/71.6.135.131"
        }"#;
        let resp: CommunityResp = serde_json::from_str(json).unwrap();
        assert!(resp.noise);
        assert!(!resp.riot);
        assert_eq!(resp.classification.as_deref(), Some("malicious"));
    }

    fn resp(json: &str) -> CommunityResp {
        serde_json::from_str(json).unwrap()
    }

    #[test]
    fn build_entity_malicious_tags_and_scores() {
        let d = resp(r#"{"ip":"71.6.135.131","noise":true,"classification":"malicious"}"#);
        let e = build_entity("71.6.135.131", &d, "s").unwrap();
        assert!((e.confidence - 0.80).abs() < 1e-9);
        assert!(
            e.has_tag("malicious")
                && e.has_tag("greynoise-malicious")
                && e.has_tag("greynoise-noise")
        );
    }

    #[test]
    fn build_entity_benign_riot_feeds_is_benign_infra_tags() {
        // The greynoise-riot + greynoise-benign tags the correlator vetoes on.
        let d = resp(
            r#"{"ip":"8.8.8.8","noise":true,"riot":true,"classification":"benign","name":"Google Public DNS","message":"Success"}"#,
        );
        let e = build_entity("8.8.8.8", &d, "s").unwrap();
        assert!((e.confidence - 0.70).abs() < 1e-9);
        assert!(e.has_tag("greynoise-benign") && e.has_tag("greynoise-riot"));
        let a = &e.evidence[0].attributes;
        assert_eq!(a.get("name").map(String::as_str), Some("Google Public DNS"));
        // Recovered status text.
        assert_eq!(a.get("message").map(String::as_str), Some("Success"));
    }

    #[test]
    fn build_entity_none_for_ip_not_in_dataset() {
        let d = resp(
            r#"{"ip":"192.168.1.1","noise":false,"riot":false,
            "message":"IP not observed scanning the internet or contained in RIOT data set."}"#,
        );
        assert!(build_entity("192.168.1.1", &d, "s").is_none());
    }

    #[test]
    fn build_entity_flags_echoed_ip_mismatch() {
        // GreyNoise echoed a different IP than queried → verdict is for another host.
        let d = resp(r#"{"ip":"9.9.9.9","noise":true,"classification":"malicious"}"#);
        let e = build_entity("1.1.1.1", &d, "s").unwrap();
        assert!(e.has_tag("ip-mismatch"));
        assert_eq!(
            e.evidence[0]
                .attributes
                .get("queried_ip")
                .map(String::as_str),
            Some("9.9.9.9")
        );
        // No mismatch when the echo matches.
        let ok = resp(r#"{"ip":"1.1.1.1","noise":true,"classification":"malicious"}"#);
        let e2 = build_entity("1.1.1.1", &ok, "s").unwrap();
        assert!(!e2.has_tag("ip-mismatch"));
    }
}
