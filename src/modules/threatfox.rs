//! abuse.ch ThreatFox — IOC reputation. Free, no key.
//!
//! Endpoint: `POST https://threatfox-api.abuse.ch/api/v1/`
//! Body:     `{"query":"search_ioc","search_term":"<value>"}`
//!
//! ThreatFox is abuse.ch's IOC sharing platform — every result here is
//! a hand-curated indicator submitted by malware analysts. The "free,
//! anonymous" path is rate-limited; we surface aggregate counts and
//! threat family names but never ingest the underlying sample hashes
//! or C2 URLs (which can still be live).

use async_trait::async_trait;
use serde::Deserialize;
use serde_json::json;

use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    error::{Error, Result},
    module::{Module, ModuleContext, ModuleResult},
    scan::{Target, TargetKind},
};
use crate::util::http::error_snippet;

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
}

pub struct ThreatFox;

#[async_trait]
impl Module for ThreatFox {
    fn name(&self) -> &'static str {
        "threatfox"
    }

    fn priority(&self) -> u8 {
        // Same band as urlhaus — high-signal threat intel.
        109
    }

    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::Domain | TargetKind::IpAddress)
    }

    fn max_timeout_ms(&self) -> u64 {
        12_000
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let term = target.value.trim();
        if term.is_empty() {
            return Ok(ModuleResult::new());
        }

        let body = json!({
            "query": "search_ioc",
            "search_term": term,
        });

        let resp = ctx
            .http
            .post("https://threatfox-api.abuse.ch/api/v1/")
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

        // "no_result" is the common case for clean indicators.
        if parsed.query_status != "ok" || parsed.data.is_empty() {
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

        // Aggregate threat families + ioc types.
        let mut families: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
        let mut types: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
        let mut threat_types: std::collections::BTreeSet<String> =
            std::collections::BTreeSet::new();
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
            if let Some(c) = ioc.confidence_level {
                max_confidence = max_confidence.max(c);
            }
            if let Some(f) = ioc.first_seen.as_deref() {
                first_seen = match &first_seen {
                    Some(existing) if existing.as_str() <= f => Some(existing.clone()),
                    _ => Some(f.to_string()),
                };
            }
            if let Some(l) = ioc.last_seen.as_deref() {
                last_seen = match &last_seen {
                    Some(existing) if existing.as_str() >= l => Some(existing.clone()),
                    _ => Some(l.to_string()),
                };
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
        if max_confidence > 0 {
            ev = ev.with_attr("max_confidence", max_confidence.to_string());
        }
        if let Some(f) = first_seen {
            ev = ev.with_attr("first_seen", f);
        }
        if let Some(l) = last_seen {
            ev = ev.with_attr("last_seen", l);
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
    fn accepts_domain_and_ip() {
        let m = ThreatFox;
        assert!(m.accepts(&Target::new(TargetKind::Domain, "x.com")));
        assert!(m.accepts(&Target::new(TargetKind::IpAddress, "1.1.1.1")));
        assert!(!m.accepts(&Target::new(TargetKind::Email, "a@b.com")));
    }
}
