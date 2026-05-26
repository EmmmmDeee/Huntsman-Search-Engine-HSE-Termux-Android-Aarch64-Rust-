//! Intelligence X selector search. Paid; async two-phase API.
//!
//! Phase 1: `POST https://2.intelx.io/intelligent/search` (header `x-key`)
//!          with a JSON body specifying the search term. The response carries
//!          a search `id` and a start `status` (0 ok, 1 invalid term,
//!          2 max-concurrent-searches reached).
//! Phase 2: `GET  https://2.intelx.io/intelligent/search/result?id=<id>&limit=<n>&statistics=0`
//!          polled until the search FINISHES, then we read the collected
//!          records.
//!
//! Result polling status semantics (per the official Search API docs):
//!   0 = results in this batch (more may follow — keep polling)
//!   1 = no results yet, search still running (keep polling)
//!   2 = search finished (terminal — stop)
//!   3 = no results available (terminal — stop, clean empty)
//!   Earlier revisions of this module treated `1` as a terminal "no results"
//!   state and broke out of the poll loop on it. That was wrong: a slow search
//!   that has not yet returned its first batch reports `1`, so breaking on `1`
//!   made slow-but-non-empty searches look empty. We now only stop on the
//!   terminal states 2/3 (or the attempt ceiling), accumulating records across
//!   batches, and treat an empty record set at the end as the clean no-hit case.
//!
//! Data model note (corrected): IntelX distinguishes `media` (the item's data
//! TYPE — paste document, forum post, URL, PDF, etc.) from `bucket` (the data
//! SOURCE — `darknet.tor`, `leaks.public.general`, `leaks.logs`, `pastes`, …).
//! The previous media-code table conflated the two (mapping media codes to
//! source-like words such as "breach"/"leaks"). We now (a) map media codes
//! against the real documented table, and (b) derive the source breakdown from
//! the `bucket`/`bucketh` fields, which is what actually conveys "where".
//!
//! IntelX returns matched items and references to source materials. We surface
//! the record count + per-bucket breakdown + media-type breakdown; per project
//! invariant we do NOT pull the raw document bodies (those frequently contain
//! credentials).

use std::time::Duration;

use async_trait::async_trait;
use serde::Deserialize;
use serde_json::json;

use crate::core::{
    entity::Evidence,
    error::{Error, Result},
    module::{Module, ModuleContext, ModuleCost, ModuleResult},
    scan::{Target, TargetKind},
    tags,
};
use crate::util::http::error_snippet;

const KEY_ENV: &str = "HUNTSMAN_INTELX_KEY";
const BASE: &str = "https://2.intelx.io";
const MAX_RESULTS: u32 = 50;
const POLL_ATTEMPTS: u32 = 6;
const POLL_INTERVAL_MS: u64 = 1_500;

// --- Phase 1: search-start response ----------------------------------------

#[derive(Deserialize)]
struct StartResp {
    #[serde(default)]
    id: Option<String>,
    /// 0 = success, 1 = invalid term, 2 = max concurrent searches reached.
    #[serde(default)]
    status: Option<i32>,
}

// --- Phase 2: result-page response ------------------------------------------

#[derive(Deserialize)]
struct ResultResp {
    /// 0 = results-this-batch, 1 = none-yet (running), 2 = finished,
    /// 3 = none-available. 2 and 3 are terminal.
    #[serde(default)]
    status: Option<i32>,
    #[serde(default)]
    records: Vec<Record>,
}

#[derive(Deserialize)]
struct Record {
    #[serde(default)]
    bucket: Option<String>,
    /// Human-readable bucket name where the API provides it.
    #[serde(default)]
    bucketh: Option<String>,
    #[serde(default)]
    media: Option<i32>,
    #[serde(default)]
    date: Option<String>,
}

pub struct IntelX;

/// Map IntelX `media` type codes to human-readable labels, per the official
/// SDK media-type table. This is the item DATA TYPE, not the data source.
/// Unrecognised/new codes return `None` and are reported numerically.
fn media_label(code: i32) -> Option<&'static str> {
    Some(match code {
        0 => "all",
        1 => "paste document",
        2 => "paste user",
        3 => "forum",
        4 => "forum board",
        5 => "forum thread",
        6 => "forum post",
        7 => "forum user",
        8 => "website screenshot",
        9 => "website HTML copy",
        13 => "tweet",
        14 => "URL",
        15 => "PDF document",
        16 => "Word document",
        17 => "Excel document",
        18 => "PowerPoint document",
        19 => "picture",
        20 => "audio file",
        21 => "video file",
        22 => "container file",
        23 => "HTML file",
        24 => "text file",
        _ => return None,
    })
}

/// Collapse a machine bucket name to a coarse source family for tagging.
/// e.g. `leaks.public.general` -> "leaks", `darknet.tor` -> "darknet".
fn bucket_family(bucket: &str) -> &str {
    bucket.split('.').next().unwrap_or(bucket)
}

#[async_trait]
impl Module for IntelX {
    fn name(&self) -> &'static str {
        "intelx"
    }
    fn description(&self) -> &'static str {
        "Intelligence X selector search across breach, paste, and darknet data"
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
        // One start + up to POLL_ATTEMPTS poll iterations at POLL_INTERVAL_MS.
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
            "maxresults": MAX_RESULTS,
            "timeout": 0,
            "datefrom": "",
            "dateto": "",
            "sort": 4,
            "media": 0,
            "terminate": []
        });
        let resp = ctx
            .http
            .post(format!("{BASE}/intelligent/search"))
            .header("x-key", key)
            .header("Accept", "application/json")
            .json(&body)
            .send()
            .await
            .map_err(|e| Error::module("intelx", e.to_string()))?;
        let status = resp.status();
        if !status.is_success() {
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
            (Some(id), Some(0) | None) if !id.is_empty() => id,
            (_, Some(1)) => return Ok(ModuleResult::new()), // invalid term
            (_, Some(2)) => {
                return Err(Error::module("intelx", "max concurrent searches reached"));
            }
            _ => return Ok(ModuleResult::new()),
        };

        // Phase 2 — poll until the search reaches a TERMINAL state (2 finished
        // or 3 none-available), accumulating records across batches. Status 0
        // and 1 both mean "keep polling". We never break early on 1.
        let result_url = format!(
            "{BASE}/intelligent/search/result?id={search_id}&limit={MAX_RESULTS}&statistics=0"
        );
        let mut all_records: Vec<Record> = Vec::with_capacity(MAX_RESULTS as usize);
        let mut finished = false;
        for _ in 0..POLL_ATTEMPTS {
            // Honor scan cancellation for faster abort latency (issue #23).
            if ctx.cancel.is_cancelled() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(POLL_INTERVAL_MS)).await;
            let resp = match ctx
                .http
                .get(&result_url)
                .header("x-key", key)
                .header("Accept", "application/json")
                .send()
                .await
            {
                Ok(r) => r,
                Err(_) => continue,
            };
            if !resp.status().is_success() {
                continue;
            }
            let r: ResultResp = match resp.json().await {
                Ok(x) => x,
                Err(_) => continue,
            };
            all_records.extend(r.records);
            // Terminal states only: 2 = finished, 3 = none available.
            if matches!(r.status, Some(2 | 3)) {
                finished = true;
                break;
            }
        }

        // If we stopped before the search reported finished (attempt ceiling or
        // cancellation), terminate it server-side so we don't leak a slot toward
        // the max-concurrent-searches limit.
        if !finished {
            let _ = ctx
                .http
                .get(format!(
                    "{BASE}/intelligent/search/terminate?id={search_id}"
                ))
                .header("x-key", key)
                .send()
                .await;
        }

        if all_records.is_empty() {
            return Ok(ModuleResult::new());
        }

        let mut entity = target.to_entity(0.86, &ctx.scan_id);
        entity.tag("intelx");
        entity.tag(tags::EXTERNAL);

        // Source breakdown comes from BUCKETS (the "where"), preferring the
        // human-readable bucket name when present.
        let mut bucket_counts: std::collections::BTreeMap<String, u32> =
            std::collections::BTreeMap::new();
        // Data-type breakdown comes from MEDIA codes (the "what").
        let mut media_counts: std::collections::BTreeMap<i32, u32> =
            std::collections::BTreeMap::new();
        let mut family_tags: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();

        for r in &all_records {
            if let Some(b) = r.bucket.as_deref().filter(|s| !s.is_empty()) {
                let display = r.bucketh.as_deref().filter(|s| !s.is_empty()).unwrap_or(b);
                *bucket_counts.entry(display.to_string()).or_insert(0) += 1;
                family_tags.insert(bucket_family(b).to_string());
            }
            if let Some(m) = r.media {
                *media_counts.entry(m).or_insert(0) += 1;
            }
        }

        // Tag by coarse source family so downstream correlation can group on
        // breach/leak/darknet/paste exposure.
        for fam in &family_tags {
            match fam.as_str() {
                "leaks" => {
                    entity.tag(tags::BREACH);
                    entity.tag(tags::PASSWORD_AT_RISK);
                }
                "pastes" => entity.tag(tags::PASTE_EXPOSED),
                other => entity.tag(format!("intelx-source:{other}")),
            }
        }

        // Top buckets by frequency (source breakdown), deterministic ordering.
        let mut top_buckets: Vec<(String, u32)> = bucket_counts.into_iter().collect();
        top_buckets.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        let top = top_buckets
            .iter()
            .take(5)
            .map(|(b, n)| format!("{b}×{n}"))
            .collect::<Vec<_>>()
            .join(", ");

        // Media-type breakdown (data types), labeled where known, numeric else.
        let mut media_pairs: Vec<(i32, u32)> = media_counts.into_iter().collect();
        media_pairs.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        let media_summary = media_pairs
            .iter()
            .take(5)
            .map(|(code, n)| match media_label(*code) {
                Some(l) => format!("{l}×{n}"),
                None => format!("media{code}×{n}"),
            })
            .collect::<Vec<_>>()
            .join(", ");

        let latest = all_records.iter().filter_map(|r| r.date.as_deref()).max();

        let mut ev = Evidence::new(
            "intelx",
            format!("IntelX: {} record(s) for {value}", all_records.len()),
        )
        .with_attr("records", all_records.len().to_string())
        .with_attr("search_id", search_id);
        if !top.is_empty() {
            ev = ev.with_attr("top_buckets", top);
        }
        if !media_summary.is_empty() {
            ev = ev.with_attr("media_types", media_summary);
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

    #[test]
    fn media_labels_match_official_table() {
        // Spot-check the corrected media-code table against the SDK docs.
        assert_eq!(media_label(1), Some("paste document"));
        assert_eq!(media_label(14), Some("URL"));
        assert_eq!(media_label(15), Some("PDF document"));
        assert_eq!(media_label(24), Some("text file"));
        // Codes not in the table are reported numerically, not mislabeled.
        assert_eq!(media_label(999), None);
        // The OLD table's wrong mappings must not reappear: code 2 is
        // "paste user", never "breach".
        assert_eq!(media_label(2), Some("paste user"));
    }

    #[test]
    fn bucket_family_collapses_dotted_names() {
        assert_eq!(bucket_family("leaks.public.general"), "leaks");
        assert_eq!(bucket_family("darknet.tor"), "darknet");
        assert_eq!(bucket_family("pastes"), "pastes");
        assert_eq!(bucket_family(""), "");
    }

    #[test]
    fn result_resp_terminal_status_parsing() {
        let running: ResultResp = serde_json::from_str(r#"{"status":1,"records":[]}"#).unwrap();
        assert_eq!(running.status, Some(1)); // must NOT be treated as terminal
        let finished: ResultResp = serde_json::from_str(
            r#"{"status":2,"records":[{"bucket":"leaks.public.general","media":24,"date":"2024-01-01"}]}"#,
        )
        .unwrap();
        assert_eq!(finished.status, Some(2));
        assert_eq!(finished.records[0].media, Some(24));
        assert_eq!(
            finished.records[0].bucket.as_deref(),
            Some("leaks.public.general")
        );
    }

    #[test]
    fn record_tolerates_missing_and_human_bucket() {
        let r: ResultResp = serde_json::from_str(
            r#"{"status":2,"records":[{"bucketh":"Public Leaks","media":1}]}"#,
        )
        .unwrap();
        assert_eq!(r.records[0].bucketh.as_deref(), Some("Public Leaks"));
        assert!(r.records[0].bucket.is_none());
        assert!(r.records[0].date.is_none());
    }
}
