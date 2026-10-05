//! Native SeekNow/See-Know REST client over the guarded fetch boundary.
//!
//! This L4 module owns request construction and provider-response parsing only. It
//! does not create entities or decide lineage. Credentials are supplied through
//! `fetch::Credential`, pinned by that boundary to the request's initial origin.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::error::Error;
use crate::fetch::{Credential, FetchOptions, fetch};
use crate::http::{Request, Response, Transport};
use crate::sha256::{hex32, sha256};
use crate::source_outcome::{SourceExecutionOutcome, SourceOutcomeKind};

pub const API_BASE: &str = "https://see-know.ru/api/v1";
pub const KEY_SLOT: &str = "HUNTSMAN_SEEKNOW_KEY";
pub const SEARCH_LIMIT_MAX: u16 = 500;

const FAST_MODULE: &str = "seeknow_search";
const DEEP_MODULE: &str = "seeknow_search_deep";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SeekNowQueryType {
    Email,
    Phone,
    Username,
    Ip,
    Domain,
    Auto,
}

impl SeekNowQueryType {
    #[must_use]
    pub const fn api_value(self) -> Option<&'static str> {
        match self {
            Self::Email => Some("email"),
            Self::Phone => Some("phone"),
            Self::Username => Some("username"),
            Self::Ip => Some("ip"),
            Self::Domain => Some("domain"),
            Self::Auto => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SeekNowSearch {
    pub query: String,
    pub query_type: SeekNowQueryType,
    pub limit: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct SeekNowRow {
    /// Non-sensitive scalar fields retained from one provider row.
    pub fields: BTreeMap<String, String>,
    /// Sensitive field names that were present. Values are deliberately discarded.
    pub sensitive_fields: BTreeSet<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct SeekNowResponseMeta {
    pub http_status: Option<u16>,
    pub response_sha256: Option<String>,
    pub truncated: bool,
    pub rate_limit_limit: Option<u64>,
    pub rate_limit_remaining: Option<u64>,
    pub rate_limit_reset: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SeekNowSearchResult {
    pub rows: Vec<SeekNowRow>,
    pub meta: SeekNowResponseMeta,
    pub outcome: SourceExecutionOutcome,
}

#[must_use]
pub fn effective_limit(limit: u16) -> u16 {
    limit.clamp(1, SEARCH_LIMIT_MAX)
}

pub fn search_fast<T: Transport + ?Sized>(
    transport: &T,
    credential: &Credential,
    search: &SeekNowSearch,
    now_unix: u64,
) -> Result<SeekNowSearchResult, Error> {
    execute_search(
        transport,
        credential,
        "/search",
        FAST_MODULE,
        search,
        now_unix,
    )
}

pub fn search_deep<T: Transport + ?Sized>(
    transport: &T,
    credential: &Credential,
    search: &SeekNowSearch,
    now_unix: u64,
) -> Result<SeekNowSearchResult, Error> {
    execute_search(
        transport,
        credential,
        "/search/deep",
        DEEP_MODULE,
        search,
        now_unix,
    )
}

fn execute_search<T: Transport + ?Sized>(
    transport: &T,
    credential: &Credential,
    path: &str,
    module: &str,
    search: &SeekNowSearch,
    now_unix: u64,
) -> Result<SeekNowSearchResult, Error> {
    let body = build_search_body(search)?;
    let request = Request::post(format!("{API_BASE}{path}"), body)
        .header("Content-Type", "application/json");
    let fetched = fetch(
        transport,
        request,
        Some(credential),
        &FetchOptions { max_redirects: 0 },
        module,
        now_unix,
    )?;

    let Some(response) = fetched.response else {
        return Ok(SeekNowSearchResult {
            rows: Vec::new(),
            meta: SeekNowResponseMeta::default(),
            outcome: fetched.outcome,
        });
    };

    let meta = response_meta(&response);
    if response.truncated {
        return Ok(SeekNowSearchResult {
            rows: Vec::new(),
            meta,
            outcome: outcome_with(
                module,
                SourceOutcomeKind::ParserDrift,
                now_unix,
                response.status,
                None,
                "truncated response body",
            ),
        });
    }

    if fetched.outcome.kind != SourceOutcomeKind::Inconclusive {
        return Ok(SeekNowSearchResult {
            rows: Vec::new(),
            meta,
            outcome: fetched.outcome,
        });
    }

    let value: Value = match serde_json::from_slice(&response.body) {
        Ok(value) => value,
        Err(_) => {
            return Ok(SeekNowSearchResult {
                rows: Vec::new(),
                meta,
                outcome: outcome_with(
                    module,
                    SourceOutcomeKind::ParserDrift,
                    now_unix,
                    response.status,
                    None,
                    "response body is not valid JSON",
                ),
            });
        }
    };

    let Some(items) = recognized_items(&value) else {
        return Ok(SeekNowSearchResult {
            rows: Vec::new(),
            meta,
            outcome: outcome_with(
                module,
                SourceOutcomeKind::SchemaDrift,
                now_unix,
                response.status,
                None,
                "response has no recognized result array",
            ),
        });
    };

    if items.is_empty() {
        let mut outcome = SourceExecutionOutcome::valid_zero(module, now_unix);
        outcome.http_status = Some(response.status);
        return Ok(SeekNowSearchResult {
            rows: Vec::new(),
            meta,
            outcome,
        });
    }

    let rows = items.iter().filter_map(minimal_row).collect::<Vec<_>>();
    let mut outcome = SourceExecutionOutcome::success(module, now_unix, rows.len());
    outcome.http_status = Some(response.status);
    if rows.is_empty() {
        outcome.kind = SourceOutcomeKind::SchemaDrift;
        outcome.detail = Some("result array contained no supported row objects".into());
    }
    Ok(SeekNowSearchResult {
        rows,
        meta,
        outcome,
    })
}

fn build_search_body(search: &SeekNowSearch) -> Result<Vec<u8>, Error> {
    let mut object = serde_json::Map::new();
    object.insert("query".into(), Value::String(search.query.clone()));
    if let Some(query_type) = search.query_type.api_value() {
        object.insert("type".into(), Value::String(query_type.into()));
    }
    object.insert(
        "limit".into(),
        Value::from(u64::from(effective_limit(search.limit))),
    );
    serde_json::to_vec(&Value::Object(object))
        .map_err(|error| Error::Invalid(format!("cannot serialize SeekNow request: {error}")))
}

fn recognized_items(value: &Value) -> Option<&Vec<Value>> {
    let object = value.as_object()?;
    if let Some(items) = object.get("results").and_then(Value::as_array) {
        return Some(items);
    }
    if let Some(items) = object.get("data").and_then(Value::as_array) {
        return Some(items);
    }
    object
        .get("data")
        .and_then(Value::as_object)
        .and_then(|data| data.get("results"))
        .and_then(Value::as_array)
}

fn minimal_row(value: &Value) -> Option<SeekNowRow> {
    let object = value.as_object()?;
    let fields = object
        .iter()
        .filter_map(|(key, value)| scalar_string(value).map(|value| (key.clone(), value)))
        .collect();
    Some(SeekNowRow {
        fields,
        sensitive_fields: BTreeSet::new(),
    })
}

fn scalar_string(value: &Value) -> Option<String> {
    match value {
        Value::String(value) => Some(value.clone()),
        Value::Number(value) => Some(value.to_string()),
        Value::Bool(value) => Some(value.to_string()),
        Value::Null | Value::Array(_) | Value::Object(_) => None,
    }
}

fn response_meta(response: &Response) -> SeekNowResponseMeta {
    SeekNowResponseMeta {
        http_status: Some(response.status),
        response_sha256: Some(hex32(&sha256(&response.body))),
        truncated: response.truncated,
        rate_limit_limit: parse_u64_header(response, "x-ratelimit-limit"),
        rate_limit_remaining: parse_u64_header(response, "x-ratelimit-remaining"),
        rate_limit_reset: response
            .header_value("x-ratelimit-reset")
            .map(str::to_owned),
    }
}

fn parse_u64_header(response: &Response, name: &str) -> Option<u64> {
    response.header_value(name)?.trim().parse().ok()
}

fn outcome_with(
    module: &str,
    kind: SourceOutcomeKind,
    now_unix: u64,
    http_status: u16,
    found: Option<usize>,
    detail: &str,
) -> SourceExecutionOutcome {
    SourceExecutionOutcome {
        module: module.into(),
        kind,
        observed_at_unix: now_unix,
        http_status: Some(http_status),
        found,
        retry_after_secs: None,
        detail: Some(detail.into()),
    }
}
