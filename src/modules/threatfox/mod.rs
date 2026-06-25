//! abuse.ch ThreatFox — IOC reputation. Key-gated.
//!
//! Endpoint: `POST https://threatfox-api.abuse.ch/api/v1/`
//! Auth:     HTTP header `Auth-Key: <HUNTSMAN_THREATFOX_KEY>`.
//! Body:     `{"query":"search_ioc","search_term":"<value>","exact_match":true}`
//!
//! ThreatFox is abuse.ch's IOC sharing platform — every result here is
//! hand-curated by malware analysts. As of 2024 abuse.ch requires a
//! free Auth-Key on every request (see <https://threatfox.abuse.ch/api>).
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
    module::{Module, ModuleCategory, ModuleContext, ModuleCost, ModuleResult},
    scan::{Target, TargetKind},
};
use crate::util::http::RequestBuilderExt;
use crate::util::http::handle_keyed_error;
use crate::util::str_util::nonempty;

const KEY_ENV: &str = "HUNTSMAN_THREATFOX_KEY";
const SRC: &str = "threatfox";

#[derive(Deserialize)]
struct Resp {
    query_status: String,
    #[serde(default)]
    data: Vec<Ioc>,
}

#[derive(Deserialize)]
pub(super) struct Ioc {
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

/// A malware family / IOC-tag list this long is plenty for an operator; cap so a
/// pathological IOC record can't blow up a single evidence row.
pub(super) const MAX_FAMILIES: usize = 8;
pub(super) const MAX_IOC_TAGS: usize = 16;

/// Aggregate a non-empty batch of ThreatFox IOC records into the single
/// `malicious` entity for `term`. **Pure** (no network/IO): folds the per-IOC
/// malware families, IOC/threat types and context tags into deduplicated,
/// capped, deterministically-ordered (`BTreeSet`) attribute lists, takes the
/// **max** analyst confidence and the **outer** first/last-seen window across
/// the batch, and records the hit count. Caller guarantees `iocs` is non-empty.
pub(super) fn build_ioc_entity(
    kind: EntityKind,
    term: &str,
    iocs: &[Ioc],
    scan_id: &str,
) -> Entity {
    use std::collections::BTreeSet;

    let mut entity = Entity::new(kind, term, 0.92, scan_id);
    entity.tag("threatfox");
    entity.tag("threat-intel");
    entity.tag("malicious");

    let mut families: BTreeSet<String> = BTreeSet::new();
    let mut types: BTreeSet<String> = BTreeSet::new();
    let mut threat_types: BTreeSet<String> = BTreeSet::new();
    let mut ioc_tags: BTreeSet<String> = BTreeSet::new();
    let mut max_confidence: u32 = 0;
    let mut first_seen: Option<&str> = None;
    let mut last_seen: Option<&str> = None;
    for ioc in iocs {
        if let Some(m) = nonempty(&ioc.malware) {
            families.insert(m.to_string());
        }
        if let Some(t) = nonempty(&ioc.ioc_type) {
            types.insert(t.to_string());
        }
        if let Some(t) = nonempty(&ioc.threat_type) {
            threat_types.insert(t.to_string());
        }
        if let Some(tags) = ioc.tags.as_deref() {
            for t in tags {
                let t = t.trim();
                if !t.is_empty() {
                    ioc_tags.insert(t.to_string());
                }
            }
        }
        if let Some(c) = ioc.confidence_level {
            max_confidence = max_confidence.max(c);
        }
        // Widest observed window: earliest first_seen, latest last_seen.
        if let Some(f) = nonempty(&ioc.first_seen)
            && first_seen.is_none_or(|e| f < e)
        {
            first_seen = Some(f);
        }
        if let Some(l) = nonempty(&ioc.last_seen)
            && last_seen.is_none_or(|e| l > e)
        {
            last_seen = Some(l);
        }
    }

    let mut ev = Evidence::new(
        SRC,
        format!("ThreatFox: {} IOC record(s) match {term}", iocs.len()),
    )
    .with_attr("hits", iocs.len().to_string());
    if !families.is_empty() {
        ev = ev.with_attr(
            "malware_families",
            families.into_iter().take(MAX_FAMILIES).enumerate().fold(
                String::new(),
                |mut acc, (i, s)| {
                    if i > 0 {
                        acc.push(',');
                    }
                    acc.push_str(&s);
                    acc
                },
            ),
        );
    }
    if !types.is_empty() {
        ev = ev.with_attr(
            "ioc_types",
            types
                .into_iter()
                .enumerate()
                .fold(String::new(), |mut acc, (i, s)| {
                    if i > 0 {
                        acc.push(',');
                    }
                    acc.push_str(&s);
                    acc
                }),
        );
    }
    if !threat_types.is_empty() {
        ev = ev.with_attr(
            "threat_types",
            threat_types
                .into_iter()
                .enumerate()
                .fold(String::new(), |mut acc, (i, s)| {
                    if i > 0 {
                        acc.push(',');
                    }
                    acc.push_str(&s);
                    acc
                }),
        );
    }
    if !ioc_tags.is_empty() {
        ev = ev.with_attr(
            "ioc_tags",
            ioc_tags.into_iter().take(MAX_IOC_TAGS).enumerate().fold(
                String::new(),
                |mut acc, (i, s)| {
                    if i > 0 {
                        acc.push(',');
                    }
                    acc.push_str(&s);
                    acc
                },
            ),
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
    entity
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

    fn cache_ttl_secs(&self) -> u64 {
        21_600
    }

    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::Domain | TargetKind::IpAddress)
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Threat
    }

    fn produces(&self) -> &'static [EntityKind] {
        const KINDS: &[EntityKind] = &[EntityKind::Domain, EntityKind::IpAddress, EntityKind::Url];
        KINDS
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
                .send_tagged(SRC)
                .await?;
            let status = resp.status();
            if !status.is_success() {
                let code = status.as_u16();
                if handle_keyed_error(code, resp.headers(), &mut retries, SRC, key, ctx).await {
                    continue;
                }
                return Err(crate::util::http::http_status_error(SRC, resp).await);
            }
            break crate::util::http::json_decode(SRC, resp).await?;
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
                return Err(Error::module(SRC, "query_status=rate_limited".to_string()));
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

        let mut result = ModuleResult::new();
        result.push(build_ioc_entity(kind, term, &parsed.data, &ctx.scan_id));
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
