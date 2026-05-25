//! Intelligence X selector search. Paid; async two-phase API.
//!
//! Phase 1: `POST https://2.intelx.io/intelligent/search` (header `x-key`)
//!          with a JSON body specifying the search term.
//! Phase 2: `GET  https://2.intelx.io/intelligent/search/result?id=<id>&limit=10&statistics=0`
//!          polled until status==0 (complete) or our internal timeout.
//!
//! IntelX returns "selectors" (matched indicators) and references to
//! the source materials. We surface the selector count + per-bucket
//! breakdown; per project invariant we do NOT pull the raw document
//! bodies (those frequently contain credentials).

use std::time::Duration;

use async_trait::async_trait;
use serde::Deserialize;
use serde_json::json;

use crate::core::{
    entity::Evidence,
    error::{Error, Result},
    module::{Module, ModuleContext, ModuleCost, ModuleResult},
    scan::{Target, TargetKind},
};
use crate::util::http::error_snippet;

const KEY_ENV: &str = "HUNTSMAN_INTELX_KEY";

#[derive(Deserialize)]
struct StartResp {
    #[serde(default)]
    id: Option<String>,
    /// 0 = success, 1 = invalid term, 2 = max concurrent searches reached.
    #[serde(default)]
    status: Option<i32>,
}

#[derive(Deserialize)]
struct ResultResp {
    /// 0 = complete, 1 = no results, 2 = partial, 3 = error.
    #[serde(default)]
    status: Option<i32>,
    #[serde(default)]
    records: Vec<Record>,
}

#[derive(Deserialize)]
struct Record {
    #[serde(default)]
    bucket: Option<String>,
    #[serde(default)]
    media: Option<i32>,
    #[serde(default)]
    date: Option<String>,
}

pub struct IntelX;

/// Map IntelX media type codes to human-readable labels.
fn media_label(code: i32) -> Option<&'static str> {
    match code {
        0 => Some("pastes"),
        1 => Some("darknet"),
        2 => Some("breach"),
        3 => Some("general"),
        5 => Some("leaks"),
        _ => None,
    }
}

#[async_trait]
impl Module for IntelX {
    fn name(&self) -> &'static str {
        "intelx"
    }
    fn description(&self) -> &'static str {
        "Intelligence X selector search across breach data"
    }
    fn priority(&self) -> u8 {
        116
    }

    fn cost(&self) -> ModuleCost {
        ModuleCost::Paid
    }
    fn accepts(&self, t: &Target) -> bool {
        matches!(
            t.kind,
            TargetKind::Email
                | TargetKind::Username
                | TargetKind::Phone
                | TargetKind::Domain
                | TargetKind::IpAddress
        )
    }
    fn max_timeout_ms(&self) -> u64 {
        // Up to one start + a few poll iterations.
        25_000
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let key = ctx.key(KEY_ENV)?;
        let value = target.value.trim();
        if value.is_empty() {
            return Ok(ModuleResult::new());
        }

        // Phase 1 — start the search.
        let body = json!({
            "term": value,
            "buckets": [],
            "lookuplevel": 0,
            "maxresults": 50,
            "timeout": 0,
            "datefrom": "",
            "dateto": "",
            "sort": 4,
            "media": 0,
            "terminate": []
        });
        let resp = ctx
            .http
            .post("https://2.intelx.io/intelligent/search")
            .header("x-key", key)
            .header("Accept", "application/json")
            .json(&body)
            .send()
            .await
            .map_err(|e| Error::module("intelx", e.to_string()))?;
        let status = resp.status();
        if !status.is_success() {
            let code = status.as_u16();
            if code == 429 || code == 401 || code == 403 {
                ctx.report_key_exhausted("intelx", key, code);
            }
            return Err(Error::module(
                "intelx",
                format!("HTTP {status} on start: {}", error_snippet(resp).await),
            ));
        }
        let start: StartResp = resp
            .json()
            .await
            .map_err(|e| Error::module("intelx", e.to_string()))?;
        let search_id = match (start.id, start.status) {
            (Some(id), Some(0)) | (Some(id), None) if !id.is_empty() => id,
            (_, Some(1)) => return Ok(ModuleResult::new()), // invalid term
            (_, Some(2)) => {
                return Err(Error::module("intelx", "max concurrent searches reached"));
            }
            _ => return Ok(ModuleResult::new()),
        };

        // Phase 2 — poll for completion. Up to 5 attempts, 1.5 s apart.
        let result_url = format!(
            "https://2.intelx.io/intelligent/search/result?id={search_id}&limit=50&statistics=0"
        );
        let mut last_records: Vec<Record> = Vec::with_capacity(50);
        for _ in 0..5 {
            tokio::time::sleep(Duration::from_millis(1_500)).await;
            let resp = ctx
                .http
                .get(&result_url)
                .header("x-key", key)
                .header("Accept", "application/json")
                .send()
                .await
                .map_err(|e| Error::module("intelx", e.to_string()))?;
            let poll_status = resp.status();
            if !poll_status.is_success() {
                let code = poll_status.as_u16();
                if code == 429 || code == 401 || code == 403 {
                    ctx.report_key_exhausted("intelx", key, code);
                }
                continue;
            }
            let r: ResultResp = match resp.json().await {
                Ok(x) => x,
                Err(_) => continue,
            };
            last_records = r.records;
            // status 0 = complete, 1 = no results.
            if matches!(r.status, Some(0) | Some(1)) {
                break;
            }
        }

        if last_records.is_empty() {
            return Ok(ModuleResult::new());
        }

        let mut entity = target.to_entity(0.86, &ctx.scan_id);
        entity.tag("intelx");
        entity.tag("indicator");

        let mut bucket_counts: std::collections::BTreeMap<&str, u32> =
            std::collections::BTreeMap::new();
        let mut media_counts: std::collections::BTreeMap<i32, u32> =
            std::collections::BTreeMap::new();
        for r in &last_records {
            if let Some(b) = r.bucket.as_deref() {
                *bucket_counts.entry(b).or_insert(0) += 1;
            }
            if let Some(m) = r.media {
                *media_counts.entry(m).or_insert(0) += 1;
            }
        }
        let mut top_buckets: Vec<(&str, u32)> = bucket_counts.into_iter().collect();
        top_buckets.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(b.0)));
        let top = top_buckets
            .iter()
            .take(5)
            .map(|(b, n)| format!("{b}×{n}"))
            .collect::<Vec<_>>()
            .join(", ");

        let latest = last_records.iter().filter_map(|r| r.date.as_deref()).max();

        let mut ev = Evidence::new(
            "intelx",
            format!(
                "IntelX: {} selector record(s) for {value}",
                last_records.len()
            ),
        )
        .with_attr("records", last_records.len().to_string())
        .with_attr("search_id", search_id);
        if !top.is_empty() {
            ev = ev.with_attr("top_buckets", top);
        }
        // Map media type codes to human-readable labels.
        let media_labels: std::collections::BTreeSet<&str> = media_counts
            .keys()
            .filter_map(|code| media_label(*code))
            .collect();
        if !media_labels.is_empty() {
            let types_joined: Vec<&str> = media_labels.into_iter().collect();
            ev = ev.with_attr("media_types", types_joined.join(", "));
        }
        if let Some(d) = latest {
            ev = ev.with_attr("latest_record", d);
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
    fn accepts_five_kinds() {
        let m = IntelX;
        for k in [
            TargetKind::Email,
            TargetKind::Username,
            TargetKind::Phone,
            TargetKind::Domain,
            TargetKind::IpAddress,
        ] {
            assert!(m.accepts(&Target::new(k, "x")));
        }
        assert!(!m.accepts(&Target::new(TargetKind::FullName, "Jane Doe")));
    }
    #[test]
    fn cost_is_paid() {
        assert!(matches!(IntelX.cost(), ModuleCost::Paid));
    }
}
