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
//! credentials). We never fetch or render the underlying `.onion` pages IntelX's
//! own crawler indexed — only the metadata (bucket/media/date) its API returns
//! for a matched record. A hit in the `darknet.tor` bucket specifically is
//! tagged [`crate::core::tags::DARKNET_EXPOSED`] (`tag_by_source_family`), so a
//! correlator rule can distinguish "circulating on an active Tor
//! forum/market" from a generic public leak.
//!
//! Selector coverage: IntelX auto-classifies the search term against its
//! `SelectorType` table, so this module forwards every target kind IntelX has a
//! selector for — email, domain, URL, IPv4/IPv6, CIDR, phone, crypto (Bitcoin)
//! address, and MAC — plus username and full-name as general text searches.
//! Kinds IntelX cannot resolve (ASN, coordinates, ABN/ACN, organisation,
//! address, API key) are declined so a paid query is never spent on a term
//! IntelX would reject. The single-sourced [`intelx_selector`] map is the one
//! place this coverage is defined; [`IntelX::accepts`] is derived from it.

#[cfg(test)]
mod tests;

use std::time::Duration;

use async_trait::async_trait;
use serde::Deserialize;
use serde_json::json;

use crate::core::{
    entity::{Entity, Evidence},
    error::{Error, Result},
    module::{Module, ModuleCategory, ModuleContext, ModuleCost, ModuleResult},
    scan::{Target, TargetKind},
    tags,
};
use crate::util::http::RequestBuilderExt;
use crate::util::http::error_snippet;

pub(crate) const KEY_ENV: &str = "HUNTSMAN_INTELX_KEY";
pub(crate) const BASE: &str = "https://2.intelx.io";
pub(crate) const MAX_RESULTS: u32 = 50;
pub(crate) const POLL_ATTEMPTS: u32 = 3;
pub(crate) const POLL_INTERVAL_MS: u64 = 1_500;

// --- Phase 1: search-start response ----------------------------------------

#[derive(Deserialize)]
pub(crate) struct StartResp {
    #[serde(default)]
    pub(crate) id: Option<String>,
    /// 0 = success, 1 = invalid term, 2 = max concurrent searches reached.
    #[serde(default)]
    pub(crate) status: Option<i32>,
}

// --- Phase 2: result-page response ------------------------------------------

#[derive(Deserialize)]
pub(crate) struct ResultResp {
    /// 0 = results-this-batch, 1 = none-yet (running), 2 = finished,
    /// 3 = none-available. 2 and 3 are terminal.
    #[serde(default)]
    pub(crate) status: Option<i32>,
    #[serde(default)]
    pub(crate) records: Vec<Record>,
}

#[derive(Deserialize)]
pub(crate) struct Record {
    #[serde(default)]
    pub(crate) bucket: Option<String>,
    /// Human-readable bucket name where the API provides it.
    #[serde(default)]
    pub(crate) bucketh: Option<String>,
    #[serde(default)]
    pub(crate) media: Option<i32>,
    #[serde(default)]
    pub(crate) date: Option<String>,
}

pub(crate) const SRC: &str = "intelx";

pub struct IntelX;

/// Map IntelX `media` type codes to human-readable labels, per the official
/// SDK media-type table. This is the item DATA TYPE, not the data source.
/// Unrecognised/new codes return `None` and are reported numerically.
pub(crate) fn media_label(code: i32) -> Option<&'static str> {
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
pub(crate) fn bucket_family(bucket: &str) -> &str {
    bucket.split('.').next().unwrap_or(bucket)
}

/// Tag `entity` by its coarse source families so downstream correlation can
/// group on breach/leak/darknet/paste exposure. **Pure** (no I/O) — separated
/// from [`IntelX::process`] so the mapping is unit-testable without a live key.
///
/// `darknet` (IntelX's `darknet.tor` bucket — active Tor-hidden-service
/// forum/market data, confirmed via the bucket-family doc note above) gets
/// its own [`tags::DARKNET_EXPOSED`] in addition to the generic
/// `intelx-source:darknet` marker, mirroring how `leaks`/`pastes` already get
/// dedicated `tags::` constants a correlator rule can match on precisely,
/// rather than only the generic per-family marker no rule reads.
pub(crate) fn tag_by_source_family(
    entity: &mut Entity,
    family_tags: &std::collections::BTreeSet<String>,
) {
    family_tags.iter().for_each(|fam| match fam.as_str() {
        "leaks" => {
            entity.tag(tags::BREACH);
            entity.tag(tags::PASSWORD_AT_RISK);
        }
        "pastes" => entity.tag(tags::PASTE_EXPOSED),
        "darknet" => {
            entity.tag(tags::DARKNET_EXPOSED);
            entity.tag(format!("intelx-source:{fam}"));
        }
        other => entity.tag(format!("intelx-source:{other}")),
    });
}

/// The Intelligence X selector a target kind maps to, or `None` for a kind
/// IntelX has no selector for. **Single source of truth** for this module's
/// coverage: [`IntelX::accepts`] is `intelx_selector(kind).is_some()`, so the
/// accept gate and the documented selector list can never drift.
///
/// IntelX auto-classifies the search term, so the returned label is descriptive
/// (it isn't sent to the API): the structured selectors carry their own name,
/// while `username` / `full_name` resolve as general `text` searches. Kinds with
/// no IntelX selector (`asn`, `coordinates`, `abn_acn`, `organisation`,
/// `address`, `api_key`) return `None` so a paid query is never spent on a term
/// IntelX would reject.
pub(crate) fn intelx_selector(kind: TargetKind) -> Option<&'static str> {
    Some(match kind {
        TargetKind::Email => "email",
        TargetKind::Domain => "domain",
        TargetKind::Url => "url",
        TargetKind::IpAddress => "ip",
        TargetKind::Cidr => "cidr",
        TargetKind::Phone => "phone",
        TargetKind::CryptoAddress => "crypto-address",
        TargetKind::MacAddress => "mac",
        // No structured selector — IntelX runs these as a general text search.
        TargetKind::Username | TargetKind::FullName => "text",
        _ => return None,
    })
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
        // Derived from the single-sourced selector map so coverage stays in one
        // place. IntelX has dedicated selectors for URL / CIDR / MAC / crypto
        // address in addition to the email/domain/IP/phone set, and resolves
        // username/full-name as general text searches.
        intelx_selector(t.kind).is_some()
    }
    fn max_timeout_ms(&self) -> u64 {
        15_000
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Breach
    }

    fn attack_techniques(&self) -> &'static [&'static str] {
        // Breach default covers Credentials (T1589.001) + Email Addresses
        // (T1589.002). IntelX also surfaces real-name Person entities →
        // T1589.003 Employee Names, which the Breach default omits.
        &["T1589.001", "T1589.002", "T1589.003"]
    }

    fn produces(&self) -> &'static [crate::core::entity::EntityKind] {
        use crate::core::entity::EntityKind;
        // The module re-emits the scanned target as its own entity (it does not
        // extract child entities — see the no-document-bodies invariant), so it
        // produces exactly the entity kinds for the target kinds it accepts.
        const KINDS: &[EntityKind] = &[
            EntityKind::Email,
            EntityKind::Username,
            EntityKind::Phone,
            EntityKind::Person,
            EntityKind::Domain,
            EntityKind::IpAddress,
            EntityKind::Url,
            EntityKind::Cidr,
            EntityKind::MacAddress,
            EntityKind::CryptoAddress,
        ];
        KINDS
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let key = match ctx.key_opt(KEY_ENV) {
            Some(k) => k,
            None => return Ok(ModuleResult::new()),
        };
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
        let mut retries = 0u32;
        let start: StartResp = loop {
            let resp = ctx
                .http
                .post(format!("{BASE}/intelligent/search"))
                .header("x-key", key)
                .header("Accept", "application/json")
                .json(&body)
                .send_tagged(SRC)
                .await?;
            let status = resp.status();
            if status.is_success() {
                break crate::util::http::json_decode(SRC, resp).await?;
            }
            let code = status.as_u16();
            if code == 429 && retries < 2 {
                // 15s module budget across search + poll phases: cap each
                // backoff at 4s so two retries can't exhaust process()'s timeout.
                let retry_secs = crate::util::http::retry_after_secs(resp.headers(), 4, 4);
                retries += 1;
                tokio::time::sleep(Duration::from_secs(retry_secs)).await;
                continue;
            }
            crate::util::http::note_keyed_error(code, SRC, key, ctx);
            return Err(Error::module(
                "intelx",
                format!("HTTP {status} on start: {}", error_snippet(resp).await),
            ));
        };
        let search_id = match (start.id, start.status) {
            (Some(id), Some(0) | None) if !id.is_empty() => id,
            (_, Some(1)) => return Ok(ModuleResult::new()), // invalid term
            (_, Some(2)) => {
                return Err(Error::module(SRC, "max concurrent searches reached"));
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
        let mut poll_retries = 0u32;
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
                let code = resp.status().as_u16();
                if code == 429 && poll_retries < 2 {
                    let retry_secs = crate::util::http::retry_after_secs(resp.headers(), 4, 4);
                    poll_retries += 1;
                    tokio::time::sleep(Duration::from_secs(retry_secs)).await;
                }
                if code != 429 || poll_retries >= 2 {
                    crate::util::http::note_keyed_error(code, SRC, key, ctx);
                }
                continue;
            }
            let r: ResultResp = match crate::util::http::json_scanned(resp, SRC).await {
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

        tag_by_source_family(&mut entity, &family_tags);

        // Top buckets by frequency (source breakdown), deterministic ordering.
        let mut top_buckets: Vec<(String, u32)> = bucket_counts.into_iter().collect();
        top_buckets.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        let top = top_buckets
            .iter()
            .take(15)
            .map(|(b, n)| format!("{b}×{n}"))
            .collect::<Vec<_>>()
            .join(", ");

        // Media-type breakdown (data types), labeled where known, numeric else.
        let mut media_pairs: Vec<(i32, u32)> = media_counts.into_iter().collect();
        media_pairs.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        let media_summary = media_pairs
            .iter()
            .take(15)
            .map(|(code, n)| match media_label(*code) {
                Some(l) => format!("{l}×{n}"),
                None => format!("media{code}×{n}"),
            })
            .collect::<Vec<_>>()
            .join(", ");

        let latest = all_records.iter().filter_map(|r| r.date.as_deref()).max();

        let mut ev = Evidence::new(
            SRC,
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
