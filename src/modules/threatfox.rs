use async_trait::async_trait;
use serde::Deserialize;
use serde_json::json;

use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    error::{Error, Result},
    module::{Module, ModuleContext, ModuleCost, ModuleResult},
    scan::{Target, TargetKind},
};
use crate::util::http::error_snippet;

const KEY_ENV: &str = "HUNTSMAN_THREATFOX_KEY";

#[derive(Deserialize)]
struct Resp {
    query_status: String,
    #[serde(default)]
    data: Vec<Ioc>,
}

#[derive(Deserialize)]
struct Ioc {
    #[serde(default)]
    ioc_type: Option<String>,
    #[serde(default)]
    threat_type: Option<String>,
    #[serde(default)]
    malware: Option<String>,
    #[serde(default)]
    confidence_level: Option<u32>,
    #[serde(default)]
    first_seen: Option<String>,
    #[serde(default)]
    last_seen: Option<String>,
    #[serde(default)]
    tags: Option<Vec<String>>,
}

pub struct ThreatFox;

#[async_trait]
impl Module for ThreatFox {
    fn name(&self) -> &'static str {
        "threatfox"
    }

    fn description(&self) -> &'static str {
        "abuse.ch ThreatFox IOC reputation check for domains and IPs"
    }

    fn priority(&self) -> u8 {
        109
    }

    fn cost(&self) -> ModuleCost {
        ModuleCost::KeyGated
    }

    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::Domain | TargetKind::IpAddress)
    }

    fn max_timeout_ms(&self) -> u64 {
        12_000
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let key = ctx.key(KEY_ENV)?;
        let term = target.value.trim();
        if term.is_empty() {
            return Ok(ModuleResult::new());
        }

        let body = json!({
            "query": "search_ioc",
            "search_term": term,
            "exact_match": true,
        });

        let resp = ctx
            .http
            .post("https://threatfox-api.abuse.ch/api/v1/")
            .header("Auth-Key", key)
            .timeout(std::time::Duration::from_millis(self.max_timeout_ms()))
            .json(&body)
            .send()
            .await
            .map_err(|e| Error::module("threatfox", e.to_string()))?;
        let status = resp.status();
        if !status.is_success() {
            return Err(Error::module(
                "threatfox",
                format!("HTTP {status}: {}", error_snippet(resp).await),
            ));
        }
        let parsed: Resp = resp
            .json()
            .await
            .map_err(|e| Error::module("threatfox", e.to_string()))?;

        match parsed.query_status.as_str() {
            "ok" => {}
            "no_result" => return Ok(ModuleResult::new()),
            other => {
                return Err(Error::module("threatfox", format!("query_status={other}")));
            }
        }
        if parsed.data.is_empty() {
            return Ok(ModuleResult::new());
        }

        let kind = if matches!(target.kind, TargetKind::IpAddress) {
            EntityKind::IpAddress
        } else {
            EntityKind::Domain
        };

        let mut entity = Entity::new(kind, term, 0.92, &ctx.scan_id);
        entity.tag("threatfox");
        entity.tag("threat-intel");
        entity.tag("malicious");

        // Aggregate threat families + ioc types + per-IOC context tags.
        let mut families: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
        let mut types: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
        let mut threat_types: std::collections::BTreeSet<String> =
            std::collections::BTreeSet::new();
        let mut ioc_tags: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
        let mut max_confidence: u32 = 0;
        let mut first_seen: Option<String> = None;
        let mut last_seen: Option<String> = None;
        for ioc in &parsed.data {
            if let Some(m) = ioc.malware.as_deref() {
                families.insert(m.to_string());
            }
            if let Some(t) = ioc.ioc_type.as_deref() {
                types.insert(t.to_string());
            }
            if let Some(t) = ioc.threat_type.as_deref() {
                threat_types.insert(t.to_string());
            }
            if let Some(tags) = ioc.tags.as_deref() {
                for t in tags {
                    if !t.trim().is_empty() {
                        ioc_tags.insert(t.to_string());
                    }
                }
            }
            if let Some(c) = ioc.confidence_level {
                max_confidence = max_confidence.max(c);
            }
            if let Some(f) = ioc.first_seen.as_deref()
                && first_seen.as_deref().is_none_or(|e| f < e)
            {
                first_seen = Some(f.to_string());
            }
            if let Some(l) = ioc.last_seen.as_deref()
                && last_seen.as_deref().is_none_or(|e| l > e)
            {
                last_seen = Some(l.to_string());
            }
        }

        let mut ev = Evidence::new(
            "threatfox",
            format!(
                "ThreatFox: {} IOC record(s) match {term}",
                parsed.data.len()
            ),
        )
        .with_attr("hits", parsed.data.len().to_string());
        if !families.is_empty() {
            let families_vec: Vec<String> = families.into_iter().take(8).collect();
            ev = ev.with_attr("malware_families", families_vec.join(","));
        }
        if !types.is_empty() {
            ev = ev.with_attr("ioc_types", types.into_iter().collect::<Vec<_>>().join(","));
        }
        if !threat_types.is_empty() {
            ev = ev.with_attr(
                "threat_types",
                threat_types.into_iter().collect::<Vec<_>>().join(","),
            );
        }
        if !ioc_tags.is_empty() {
            let tags_vec: Vec<String> = ioc_tags.into_iter().take(16).collect();
            ev = ev.with_attr("ioc_tags", tags_vec.join(","));
        }
        if max_confidence > 0 {
            ev = ev.with_attr("max_confidence", max_confidence.to_string());
        }
        ev = ev
            .with_opt_attr("first_seen", first_seen)
            .with_opt_attr("last_seen", last_seen);
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
    fn accepts_domain_and_ip() {
        let m = ThreatFox;
        assert!(m.accepts(&Target::new(TargetKind::Domain, "x.com")));
        assert!(m.accepts(&Target::new(TargetKind::IpAddress, "1.1.1.1")));
        assert!(!m.accepts(&Target::new(TargetKind::Email, "a@b.com")));
    }

    #[test]
    fn cost_is_key_gated() {
        // ThreatFox requires an Auth-Key header on every request
        // (https://threatfox.abuse.ch/api).
        assert!(matches!(ThreatFox.cost(), ModuleCost::KeyGated));
    }
}
