//! abuse.ch ThreatFox — IOC reputation. Key-gated.
//!
//! Endpoint: `POST https://threatfox-api.abuse.ch/api/v1/`
//! Auth:     HTTP header `Auth-Key: <HUNTSMAN_THREATFOX_KEY>`.
//! Body:     `{"query":"search_ioc","search_term":"<value>","exact_match":true}`
//!
//! ThreatFox is abuse.ch's IOC sharing platform — every result here is
//! hand-curated by malware analysts. As of 2024 abuse.ch requires a
//! free Auth-Key on every request (see https://threatfox.abuse.ch/api).
//! Without the key every request would 4xx; we treat the module as
//! KeyGated and silently no-op when the env var is absent, matching
//! the project's other key-gated modules.
//!
//! Per project invariants we surface aggregate counts, threat families
//! and IOC types but never ingest the underlying malware sample hashes,
//! credentials, or live C2 URLs.

use async_trait::async_trait;
use serde::Deserialize;
use serde_json::json;

use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    error::{Error, Result},
    module::{Module, ModuleContext, ModuleCost, ModuleResult},
    scan::{Target, TargetKind},
};
use crate::util::http::{error_snippet, handle_keyed_error};

const KEY_ENV: &str = "HUNTSMAN_THREATFOX_KEY";
const SRC: &str = "threatfox";

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
    // ThreatFox attaches high-value contextual labels here
    // (e.g. `Magecart`, `CobaltStrike`, `WSHRAT`). The field can
    // be either a JSON array or `null` per the documented samples.
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
        // Same band as urlhaus — high-signal threat intel.
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
        let key = match ctx.key_opt(KEY_ENV) {
            Some(k) => k,
            None => return Ok(ModuleResult::new()),
        };
        let term = target.value.trim();
        if term.is_empty() {
            return Ok(ModuleResult::new());
        }

        // `exact_match: true` — without it the API does a wildcard
        // match that returns IOCs containing the search_term as a
        // substring (e.g. searching for `1.2.3.4` would also return
        // `1.2.3.40` records).
        let body = json!({
            "query": "search_ioc",
            "search_term": term,
            "exact_match": true,
        });

        // ctx.http carries a 3 s default timeout (MODULE_TIMEOUT_MS);
        // override per-request to match this module's declared 12 s.
        let mut retries = 2u8;
        let parsed: Resp = loop {
            let resp = ctx
                .http
                .post("https://threatfox-api.abuse.ch/api/v1/")
                .header("Auth-Key", key)
                .timeout(std::time::Duration::from_millis(self.max_timeout_ms()))
                .json(&body)
                .send()
                .await
                .map_err(|e| Error::module(SRC, e.to_string()))?;
            let status = resp.status();
            if !status.is_success() {
                let code = status.as_u16();
                if handle_keyed_error(code, resp.headers(), &mut retries, SRC, key, ctx)
                    .await
                {
                    continue;
                }
                return Err(Error::module(
                    SRC,
                    format!("HTTP {status}: {}", error_snippet(resp).await),
                ));
            }
            break resp
                .json()
                .await
                .map_err(|e| Error::module(SRC, e.to_string()))?;
        };

        // abuse.ch's anonymous tier returns HTTP 200 + `query_status:
        // "rate_limited"` (or `illegal_search_term` etc.) instead of a
        // non-success HTTP code. Surface these as module errors so the
        // operator can distinguish them from genuine clean indicators
        // (which return `query_status: "no_result"`).
        match parsed.query_status.as_str() {
            "ok" => {}
            "no_result" => return Ok(ModuleResult::new()),
            "rate_limited" => {
                ctx.report_key_exhausted(SRC, key, 429);
                return Err(Error::module(
                    SRC,
                    "query_status=rate_limited".to_string(),
                ));
            }
            other => {
                return Err(Error::module(SRC, format!("query_status={other}")));
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
            // Only allocate when we actually replace the running min/max.
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
            SRC,
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
            // Cap at 16 so a noisy IOC doesn't blow up the evidence row.
            let tags_vec: Vec<String> = ioc_tags.into_iter().take(16).collect();
            ev = ev.with_attr("ioc_tags", tags_vec.join(","));
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

    #[test]
    fn cost_is_key_gated() {
        // ThreatFox requires an Auth-Key header on every request
        // (https://threatfox.abuse.ch/api).
        assert!(matches!(ThreatFox.cost(), ModuleCost::KeyGated));
    }
}
