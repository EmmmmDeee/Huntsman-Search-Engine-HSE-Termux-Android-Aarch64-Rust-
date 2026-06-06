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

/// A malware family / IOC-tag list this long is plenty for an operator; cap so a
/// pathological IOC record can't blow up a single evidence row.
const MAX_FAMILIES: usize = 8;
const MAX_IOC_TAGS: usize = 16;

/// Aggregate a non-empty batch of ThreatFox IOC records into the single
/// `malicious` entity for `term`. **Pure** (no network/IO): folds the per-IOC
/// malware families, IOC/threat types and context tags into deduplicated,
/// capped, deterministically-ordered (`BTreeSet`) attribute lists, takes the
/// **max** analyst confidence and the **outer** first/last-seen window across
/// the batch, and records the hit count. Caller guarantees `iocs` is non-empty.
fn build_ioc_entity(kind: EntityKind, term: &str, iocs: &[Ioc], scan_id: &str) -> Entity {
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
            families
                .into_iter()
                .take(MAX_FAMILIES)
                .collect::<Vec<_>>()
                .join(","),
        );
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
        ev = ev.with_attr(
            "ioc_tags",
            ioc_tags
                .into_iter()
                .take(MAX_IOC_TAGS)
                .collect::<Vec<_>>()
                .join(","),
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

use crate::util::str_util::nonempty;

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
                .send()
                .await
                .map_err(|e| Error::module(SRC, e.to_string()))?;
            let status = resp.status();
            if !status.is_success() {
                let code = status.as_u16();
                if handle_keyed_error(code, resp.headers(), &mut retries, SRC, key, ctx).await {
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

    fn ioc(json: &str) -> Ioc {
        serde_json::from_str(json).unwrap()
    }

    fn attr<'a>(e: &'a Entity, k: &str) -> Option<&'a str> {
        e.evidence[0].attributes.get(k).map(String::as_str)
    }

    #[test]
    fn single_ioc_marks_malicious_with_threat_band_confidence() {
        let e = build_ioc_entity(
            EntityKind::Domain,
            "evil.test",
            &[ioc(
                r#"{"ioc_type":"domain","threat_type":"botnet_cc","malware":"CobaltStrike",
                    "confidence_level":75}"#,
            )],
            "s",
        );
        assert_eq!(e.kind, EntityKind::Domain);
        assert!(e.has_tag("threatfox") && e.has_tag("threat-intel") && e.has_tag("malicious"));
        assert!((e.confidence - 0.92).abs() < 1e-9);
        assert_eq!(attr(&e, "hits"), Some("1"));
        assert_eq!(attr(&e, "malware_families"), Some("CobaltStrike"));
        assert_eq!(attr(&e, "ioc_types"), Some("domain"));
        assert_eq!(attr(&e, "threat_types"), Some("botnet_cc"));
        assert_eq!(attr(&e, "max_confidence"), Some("75"));
    }

    #[test]
    fn aggregates_dedup_sorted_and_takes_max_confidence_and_outer_window() {
        let e = build_ioc_entity(
            EntityKind::IpAddress,
            "1.2.3.4",
            &[
                ioc(
                    r#"{"malware":"WSHRAT","ioc_type":"ip:port","confidence_level":40,
                        "first_seen":"2024-03-01","last_seen":"2024-03-10",
                        "tags":["RAT","keylogger"]}"#,
                ),
                ioc(
                    r#"{"malware":"Magecart","ioc_type":"ip:port","confidence_level":90,
                        "first_seen":"2024-01-15","last_seen":"2024-06-20",
                        "tags":["skimmer","RAT"]}"#,
                ),
            ],
            "s",
        );
        assert_eq!(e.kind, EntityKind::IpAddress);
        assert_eq!(attr(&e, "hits"), Some("2"));
        // BTreeSet → deduplicated + lexicographically sorted.
        assert_eq!(attr(&e, "malware_families"), Some("Magecart,WSHRAT"));
        assert_eq!(attr(&e, "ioc_types"), Some("ip:port")); // deduped to one
        assert_eq!(attr(&e, "ioc_tags"), Some("RAT,keylogger,skimmer"));
        // max confidence, not last-wins.
        assert_eq!(attr(&e, "max_confidence"), Some("90"));
        // Outer window: earliest first_seen, latest last_seen across the batch.
        assert_eq!(attr(&e, "first_seen"), Some("2024-01-15"));
        assert_eq!(attr(&e, "last_seen"), Some("2024-06-20"));
    }

    #[test]
    fn sparse_ioc_omits_absent_attributes() {
        // Only ioc_type present; everything else null/empty must be omitted,
        // not emitted blank.
        let e = build_ioc_entity(
            EntityKind::Domain,
            "x.test",
            &[ioc(
                r#"{"ioc_type":"domain","malware":"  ","confidence_level":0}"#,
            )],
            "s",
        );
        assert_eq!(attr(&e, "ioc_types"), Some("domain"));
        assert_eq!(attr(&e, "malware_families"), None); // whitespace-only dropped
        assert_eq!(attr(&e, "max_confidence"), None); // 0 is not surfaced
        assert_eq!(attr(&e, "first_seen"), None);
        assert_eq!(attr(&e, "threat_types"), None);
    }

    #[test]
    fn family_and_tag_lists_are_capped() {
        let many_families: Vec<Ioc> = (0..20)
            .map(|i| ioc(&format!(r#"{{"malware":"fam{i:02}"}}"#)))
            .collect();
        let e = build_ioc_entity(EntityKind::Domain, "x.test", &many_families, "s");
        let fams = attr(&e, "malware_families").unwrap();
        assert_eq!(fams.split(',').count(), MAX_FAMILIES);

        let big_tags = ioc(&format!(
            r#"{{"tags":[{}]}}"#,
            (0..30)
                .map(|i| format!(r#""t{i:02}""#))
                .collect::<Vec<_>>()
                .join(",")
        ));
        let e = build_ioc_entity(EntityKind::Domain, "x.test", &[big_tags], "s");
        assert_eq!(
            attr(&e, "ioc_tags").unwrap().split(',').count(),
            MAX_IOC_TAGS
        );
    }
}
