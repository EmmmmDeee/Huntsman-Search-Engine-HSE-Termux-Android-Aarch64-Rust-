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
    let request =
        Request::post(format!("{API_BASE}{path}"), body).header("Content-Type", "application/json");
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

    // Body-independent causal states remain authoritative. Auth/plan and rate/quota
    // states are the exception: SeekNow's top-level JSON envelope refines those.
    if !matches!(
        fetched.outcome.kind,
        SourceOutcomeKind::Inconclusive
            | SourceOutcomeKind::AuthRejected
            | SourceOutcomeKind::AuthRequired
            | SourceOutcomeKind::RateLimited
            | SourceOutcomeKind::Upstream4xx
    ) {
        return Ok(SeekNowSearchResult {
            rows: Vec::new(),
            meta,
            outcome: fetched.outcome,
        });
    }

    let value: Value = match serde_json::from_slice(&response.body) {
        Ok(value) => value,
        Err(_) if fetched.outcome.kind != SourceOutcomeKind::Inconclusive => {
            return Ok(SeekNowSearchResult {
                rows: Vec::new(),
                meta,
                outcome: fetched.outcome,
            });
        }
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

    if let Some(kind) = provider_failure_kind(&value, response.status) {
        return Ok(SeekNowSearchResult {
            rows: Vec::new(),
            meta,
            outcome: outcome_with(
                module,
                kind,
                now_unix,
                response.status,
                Some(0),
                "provider reported request failure",
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

/// Refine only from provider-level envelope fields. Values inside result rows are
/// deliberately unreachable from this function, so breach payload text such as
/// `invalid_api_key` can never disable authentication for the provider.
fn provider_failure_kind(value: &Value, http_status: u16) -> Option<SourceOutcomeKind> {
    let object = value.as_object()?;
    let failed = object.get("success").and_then(Value::as_bool) == Some(false);
    let error = top_level_text(object, "error");
    let code = top_level_text(object, "code");
    let status = top_level_text(object, "status");
    let message = top_level_text(object, "message");
    let signal = [error, code, status, message]
        .into_iter()
        .flatten()
        .collect::<Vec<_>>()
        .join(" ")
        .to_ascii_lowercase();

    let has_failure_signal = failed || object.contains_key("error");
    if !has_failure_signal && !matches!(http_status, 401 | 403 | 429) {
        return None;
    }

    if contains_any(
        &signal,
        &[
            "invalid_api_key",
            "invalid api key",
            "unauthorized",
            "bad api key",
        ],
    ) {
        return Some(SourceOutcomeKind::AuthRejected);
    }

    if contains_any(
        &signal,
        &[
            "plan_required",
            "plan required",
            "upgrade plan",
            "entitlement",
            "not entitled",
            "subscription required",
        ],
    ) {
        return Some(SourceOutcomeKind::EntitlementDenied);
    }

    if http_status == 429 {
        let credits_zero = object
            .get("credits_remaining")
            .and_then(Value::as_u64)
            .is_some_and(|remaining| remaining == 0);
        if contains_any(
            &signal,
            &[
                "quota_exhausted",
                "quota exhausted",
                "credits exhausted",
                "daily limit",
                "no credits",
            ],
        ) || (failed && credits_zero)
        {
            return Some(SourceOutcomeKind::QuotaExhausted);
        }
        return Some(SourceOutcomeKind::RateLimited);
    }

    if http_status == 401 {
        return Some(SourceOutcomeKind::AuthRejected);
    }
    if http_status == 403 && failed {
        return Some(SourceOutcomeKind::AuthRejected);
    }
    None
}

fn top_level_text<'a>(object: &'a serde_json::Map<String, Value>, key: &str) -> Option<&'a str> {
    object.get(key)?.as_str()
}

fn contains_any(haystack: &str, needles: &[&str]) -> bool {
    needles.iter().any(|needle| haystack.contains(needle))
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
    let mut fields = BTreeMap::new();
    let mut sensitive_fields = BTreeSet::new();
    for (key, value) in object {
        if is_sensitive_result_field(key) {
            sensitive_fields.insert(key.clone());
            continue;
        }
        if let Some(value) = scalar_string(value) {
            fields.insert(key.clone(), value);
        }
    }
    Some(SeekNowRow {
        fields,
        sensitive_fields,
    })
}

fn is_sensitive_result_field(key: &str) -> bool {
    let normalized = key.trim().to_ascii_lowercase().replace(['-', ' '], "_");
    matches!(
        normalized.as_str(),
        "password"
            | "passwd"
            | "pwd"
            | "pass"
            | "secret"
            | "token"
            | "access_token"
            | "refresh_token"
            | "auth_token"
            | "api_key"
            | "apikey"
            | "cookie"
            | "cookies"
            | "session"
            | "session_id"
            | "session_token"
            | "authorization"
    ) || normalized.ends_with("_password")
        || normalized.ends_with("_passwd")
        || normalized.ends_with("_token")
        || normalized.ends_with("_secret")
        || normalized.ends_with("_cookie")
        || normalized.ends_with("_api_key")
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
