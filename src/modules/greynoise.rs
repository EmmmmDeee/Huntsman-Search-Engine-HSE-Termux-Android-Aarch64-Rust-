//! GreyNoise Community API — mass-scanner / benign-service classification.
//! Free community tier (no key needed for basic; keyed for richer data).
//!
//! Endpoint: `GET https://api.greynoise.io/v3/community/{ip}`
//! Auth:     optional `key: {HUNTSMAN_GREYNOISE_KEY}` header.
//!
//! Classifies an IP as benign (known scanner like Shodan/Censys),
//! malicious (attack infrastructure), or unknown. Emits tags the
//! correlator can consume (e.g., `scanner`, `malicious`, `benign`).

use async_trait::async_trait;
use serde::Deserialize;

use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    error::{Error, Result},
    module::{Module, ModuleContext, ModuleResult},
    scan::{Target, TargetKind},
};
use crate::util::http::error_snippet;

#[derive(Deserialize)]
#[allow(dead_code)]
struct Resp {
    #[serde(default)]
    ip: Option<String>,
    #[serde(default)]
    noise: Option<bool>,
    #[serde(default)]
    riot: Option<bool>,
    #[serde(default)]
    classification: Option<String>,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    link: Option<String>,
    #[serde(default)]
    last_seen: Option<String>,
    #[serde(default)]
    message: Option<String>,
}

pub struct GreyNoise;

#[async_trait]
impl Module for GreyNoise {
    fn name(&self) -> &'static str {
        "greynoise"
    }
    fn priority(&self) -> u8 {
        92
    }
    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::IpAddress)
    }
    fn max_timeout_ms(&self) -> u64 {
        8_000
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let Some(ip) = target.trimmed() else {
            return Ok(ModuleResult::new());
        };

        let url = format!("https://api.greynoise.io/v3/community/{ip}");
        let mut req = ctx.http.get(&url).header("Accept", "application/json");
        if let Some(key) = ctx.key_opt("HUNTSMAN_GREYNOISE_KEY") {
            req = req.header("key", key);
        }
        let resp = req
            .send()
            .await
            .map_err(|e| Error::module("greynoise", e.to_string()))?;

        let status = resp.status().as_u16();
        if status == 404 {
            return Ok(ModuleResult::new());
        }
        if status == 429 {
            return Err(Error::module("greynoise", "rate limited"));
        }
        if !(200..=299).contains(&status) {
            return Err(Error::module(
                "greynoise",
                format!("HTTP {status}: {}", error_snippet(resp).await),
            ));
        }

        let body: Resp = resp
            .json()
            .await
            .map_err(|e| Error::module("greynoise", e.to_string()))?;

        let classification = body.classification.as_deref().unwrap_or("unknown");
        if classification == "unknown" && body.noise != Some(true) {
            return Ok(ModuleResult::new());
        }

        let mut entity = Entity::new(EntityKind::IpAddress, ip, 0.82, &ctx.scan_id);
        entity.tag("greynoise");

        match classification {
            "malicious" => {
                entity.tag("malicious");
                entity.tag("scanner");
            }
            "benign" => {
                entity.tag("benign-scanner");
            }
            _ => {}
        }
        if body.noise == Some(true) {
            entity.tag("internet-noise");
        }
        if body.riot == Some(true) {
            entity.tag("common-business-service");
        }

        let mut ev = Evidence::new(
            "greynoise",
            format!("GreyNoise: {ip} classified as {classification}"),
        )
        .with_attr("classification", classification);

        if let Some(n) = body.name.as_deref() {
            ev = ev.with_attr("name", n);
        }
        if let Some(ls) = body.last_seen.as_deref() {
            ev = ev.with_attr("last_seen", ls);
        }
        if let Some(noise) = body.noise {
            ev = ev.with_attr("noise", noise.to_string());
        }
        if let Some(riot) = body.riot {
            ev = ev.with_attr("riot", riot.to_string());
        }

        entity.add_evidence(ev);
        let mut result = ModuleResult::new();
        result.push(entity);
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn accepts_ip() {
        assert!(GreyNoise.accepts(&Target::new(TargetKind::IpAddress, "1.1.1.1")));
        assert!(!GreyNoise.accepts(&Target::new(TargetKind::Domain, "x")));
    }
}
