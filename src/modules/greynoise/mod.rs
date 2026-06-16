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

    fn attack_techniques(&self) -> &'static [&'static str] {
        // GreyNoise is an internet-noise classification / scan database (T1596.005)
        // and gathers IP address info (T1590.005). It also identifies the
        // ISP/network operator as an Organisation (T1591.002 Business Relationships)
        // — absent from the Infrastructure default.
        &["T1590.005", "T1591.002", "T1596.005"]
    }

    fn produces(&self) -> &'static [EntityKind] {
        const KINDS: &[EntityKind] = &[EntityKind::IpAddress, EntityKind::Organisation];
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
            Some("malicious") => {
                entity.tag("malicious");
                entity.tag("greynoise-malicious");
            }
            Some("benign") => entity.tag("greynoise-benign"),
            _ => entity.tag("greynoise-unknown"),
        }

        // ── Evidence ──────────────────────────────────────────────
        let classification = data.classification.as_deref().unwrap_or("unknown");
        let summary = format!(
            "GreyNoise: classification={classification}, noise={}, riot={}",
            data.noise, data.riot
        );

        let base = Evidence::new(SRC, summary)
            .with_attr("classification", classification)
            .with_attr("noise", data.noise.to_string())
            .with_attr("riot", data.riot.to_string());
        let ev = [
            ("name", data.name.as_deref()),
            ("link", data.link.as_deref()),
            // GreyNoise's own status text (e.g. the RIOT service description) —
            // surfaced as the API's words, not synthesised from the booleans.
            ("message", data.message.as_deref()),
        ]
        .into_iter()
        .filter_map(|(key, value)| value.filter(|s| !s.is_empty()).map(|v| (key, v)))
        .fold(base, |ev, (key, v)| ev.with_attr(key, v));
        entity.add_evidence(ev);

        let mut result = ModuleResult::new();
        result.push(entity);

        // The operator/actor name (e.g. "Cloudflare", "Shodan.io") is a real
        // Organisation pivot — surface it, don't leave it in evidence only.
        if let Some(name) = data
            .name
            .as_deref()
            .map(str::trim)
            .filter(|n| n.len() >= 2 && !n.eq_ignore_ascii_case("unknown"))
        {
            let mut o = Entity::new(EntityKind::Organisation, name, 0.62, &ctx.scan_id);
            o.tag("greynoise");
            o.tag("ip-operator");
            o.add_evidence(
                Evidence::new(SRC, format!("Operator/actor of {ip} per GreyNoise"))
                    .with_attr("ip", ip),
            );
            result.push(o);
        }
        Ok(result)
    }
}

// ── Tests ─────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
