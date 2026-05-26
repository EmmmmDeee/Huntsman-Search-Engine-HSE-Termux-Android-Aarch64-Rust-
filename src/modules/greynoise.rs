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
    module::{Module, ModuleContext, ModuleResult},
    scan::{Target, TargetKind},
};
use crate::util::http::{fetch_json_or_404, urlencode};

// ── Response types ────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
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

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let ip = target.value.trim();
        if ip.is_empty() {
            return Ok(ModuleResult::new());
        }

        let url = format!("https://api.greynoise.io/v3/community/{}", urlencode(ip));

        let Some(data): Option<CommunityResp> =
            fetch_json_or_404(&ctx.http, "greynoise", &url).await?
        else {
            return Ok(ModuleResult::new());
        };

        // GreyNoise returns 200 with `message: "IP not observed ..."` for
        // IPs not in its dataset. Treat those as no-findings.
        if !data.noise && !data.riot && data.classification.is_none() {
            return Ok(ModuleResult::new());
        }

        let confidence = match data.classification.as_deref() {
            Some("malicious") => 0.80,
            Some("benign") => 0.70,
            _ => 0.55,
        };

        let mut entity = Entity::new(EntityKind::IpAddress, ip, confidence, &ctx.scan_id);

        // ── Tags ──────────────────────────────────────────────────
        if data.noise {
            entity.tag("greynoise-noise");
        }
        if data.riot {
            entity.tag("greynoise-riot");
        }
        match data.classification.as_deref() {
            Some("malicious") => entity.tag("greynoise-malicious"),
            Some("benign") => entity.tag("greynoise-benign"),
            _ => entity.tag("greynoise-unknown"),
        }

        // ── Evidence ──────────────────────────────────────────────
        let classification = data.classification.as_deref().unwrap_or("unknown");
        let summary = format!(
            "GreyNoise: classification={classification}, noise={}, riot={}",
            data.noise, data.riot
        );

        let mut ev = Evidence::new("greynoise", summary)
            .with_attr("classification", classification)
            .with_attr("noise", data.noise.to_string())
            .with_attr("riot", data.riot.to_string());
        if let Some(name) = data.name.as_deref().filter(|s| !s.is_empty()) {
            ev = ev.with_attr("name", name);
        }
        if let Some(link) = data.link.as_deref().filter(|s| !s.is_empty()) {
            ev = ev.with_attr("link", link);
        }
        entity.add_evidence(ev);

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
}
