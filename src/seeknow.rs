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
pub const SEARCH_LIMIT_MAX: u16 = 1000;
pub const SEARCH_PATH: &str = "/search";
pub const STEALER_PATH: &str = "/stealer";
pub const MAX_FIELDS_PER_ROW: usize = 64;
pub const MAX_FIELD_CHARS: usize = 4096;

const FAST_MODULE: &str = "seeknow_search";
const STEALER_MODULE: &str = "seeknow_stealer";
const CREDITS_MODULE: &str = "seeknow_credits";
const STATUS_MODULE: &str = "seeknow_status";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SeekNowQueryType {
    Auto,
    Email,
    Username,
    Phone,
    Ip,
    Domain,
    Name,
    Hash,
    Url,
    MachineId,
}

impl SeekNowQueryType {
    #[must_use]
    pub const fn api_value(self) -> Option<&'static str> {
        match self {
            Self::Auto => None,
            Self::Email => Some("email"),
            Self::Username => Some("username"),
            Self::Phone => Some("phone"),
            Self::Ip => Some("ip"),
            Self::Domain => Some("domain"),
            Self::Name => Some("name"),
            Self::Hash => Some("hash"),
            Self::Url => Some("url"),
            Self::MachineId => Some("machine_id"),
        }
    }

    #[must_use]
    pub const fn supports_search(self) -> bool {
        matches!(
            self,
            Self::Auto
                | Self::Email
                | Self::Username
                | Self::Phone
                | Self::Ip
                | Self::Domain
                | Self::Name
                | Self::Hash
        )
    }

    #[must_use]
    pub const fn supports_stealer(self) -> bool {
        matches!(
            self,
            Self::Auto
                | Self::Email
                | Self::Username
                | Self::Ip
                | Self::Domain
                | Self::Url
                | Self::MachineId
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SeekNowSearch {
    pub query: String,
    pub query_type: SeekNowQueryType,
    pub limit: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct SeekNowUpstream {
    #[serde(default)]
    pub dbname: Vec<String>,
    #[serde(default)]
    pub breach: Vec<String>,
    #[serde(default)]
    pub source_db: Vec<String>,
    #[serde(default)]
    pub database_name: Vec<String>,
    #[serde(default)]
    pub dataset: Vec<String>,
    #[serde(default)]
    pub source: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub record_id: Option<String>,
}

impl SeekNowUpstream {
    #[must_use]
    pub fn values(&self, field: &str) -> &[String] {
        match field {
            "dbname" => &self.dbname,
            "breach" => &self.breach,
            "source_db" => &self.source_db,
            "database_name" => &self.database_name,
            "dataset" => &self.dataset,
            "source" => &self.source,
            _ => &[],
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct SeekNowRow {
    /// Non-sensitive bounded scalar fields retained from one provider row.
    pub fields: BTreeMap<String, String>,
    /// Structured upstream aliases retained separately so array-valued lineage survives.
    pub upstream: SeekNowUpstream,
    /// Sensitive field names that were present. Values are deliberately discarded.
    pub sensitive_fields: BTreeSet<String>,
    /// Oversized scalar fields discarded rather than shortened ambiguously.
    pub truncated_fields: BTreeSet<String>,
    /// True when field-count or field-length bounds removed data from this normalized row.
    pub fields_truncated: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct SeekNowResponseMeta {
    pub http_status: Option<u16>,
    pub response_sha256: Option<String>,
    pub truncated: bool,
    pub normalized_rows_truncated: bool,
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SeekNowCredits {
    pub remaining: Option<u64>,
    pub limit: Option<u64>,
    pub meta: SeekNowResponseMeta,
    pub outcome: SourceExecutionOutcome,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SeekNowStatus {
    pub fields: BTreeMap<String, String>,
    pub meta: SeekNowResponseMeta,
    pub outcome: SourceExecutionOutcome,
}

#[derive(Debug)]
struct JsonEndpointResult {
    value: Option<Value>,
    meta: SeekNowResponseMeta,
    outcome: SourceExecutionOutcome,
}

#[must_use]
pub fn effective_limit(limit: u16) -> u16 {
    limit.clamp(1, SEARCH_LIMIT_MAX)
}

pub fn credits<T: Transport + ?Sized>(
    transport: &T,
    credential: &Credential,
    now_unix: u64,
) -> Result<SeekNowCredits, Error> {
    let result = execute_json_get(transport, credential, "/credits", CREDITS_MODULE, now_unix)?;
    let remaining = result
        .value
        .as_ref()
        .and_then(|value| first_u64(value, &["credits_remaining", "remaining", "credits"]));
    let limit = result
        .value
        .as_ref()
        .and_then(|value| first_u64(value, &["daily_limit", "limit", "credits_limit"]));
    Ok(SeekNowCredits {
        remaining,
        limit,
        meta: result.meta,
        outcome: result.outcome,
    })
}

pub fn status<T: Transport + ?Sized>(
    transport: &T,
    credential: &Credential,
    now_unix: u64,
) -> Result<SeekNowStatus, Error> {
    let result = execute_json_get(transport, credential, "/status", STATUS_MODULE, now_unix)?;
    let fields = result
        .value
        .as_ref()
        .and_then(Value::as_object)
        .map(bounded_top_level_fields)
        .unwrap_or_default();
    Ok(SeekNowStatus {
        fields,
        meta: result.meta,
        outcome: result.outcome,
    })
}

pub fn search_fast<T: Transport + ?Sized>(
    transport: &T,
    credential: &Credential,
    search: &SeekNowSearch,
    now_unix: u64,
) -> Result<SeekNowSearchResult, Error> {
    if !search.query_type.supports_search() {
        return Err(Error::Invalid(format!(
            "SeekNow search endpoint does not support query type {}",
            search.query_type.api_value().unwrap_or("auto")
        )));
    }
    execute_search(
        transport,
        credential,
        SEARCH_PATH,
        FAST_MODULE,
        search,
        now_unix,
    )
}

/// Execute SeekNow's current stealer/deep endpoint.
pub fn search_deep<T: Transport + ?Sized>(
    transport: &T,
    credential: &Credential,
    search: &SeekNowSearch,
    now_unix: u64,
) -> Result<SeekNowSearchResult, Error> {
    if !search.query_type.supports_stealer() {
        return Err(Error::Invalid(format!(
            "SeekNow stealer endpoint does not support query type {}",
            search.query_type.api_value().unwrap_or("auto")
        )));
    }
    execute_search(
        transport,
        credential,
        STEALER_PATH,
        STEALER_MODULE,
        search,
        now_unix,
    )
}

fn execute_json_get<T: Transport + ?Sized>(
    transport: &T,
    credential: &Credential,
    path: &str,
    module: &str,
    now_unix: u64,
) -> Result<JsonEndpointResult, Error> {
    let fetched = fetch(
        transport,
        Request::get(format!("{API_BASE}{path}")),
        Some(credential),
        &FetchOptions::no_redirects(),
        module,
        now_unix,
    )?;
    let Some(response) = fetched.response else {
        return Ok(JsonEndpointResult {
            value: None,
            meta: SeekNowResponseMeta::default(),
            outcome: fetched.outcome,
        });
    };
    Ok(parse_json_endpoint(
        &response,
        fetched.outcome,
        module,
        now_unix,
    ))
}

fn parse_json_endpoint(
    response: &Response,
    fetched_outcome: SourceExecutionOutcome,
    module: &str,
    now_unix: u64,
) -> JsonEndpointResult {
    let meta = response_meta(response);
    if response.truncated {
        return JsonEndpointResult {
            value: None,
            meta,
            outcome: outcome_with(
                module,
                SourceOutcomeKind::ParserDrift,
                now_unix,
                response.status,
                None,
                "truncated response body",
            ),
        };
    }
    if !response_body_may_refine(fetched_outcome.kind) {
        return JsonEndpointResult {
            value: None,
            meta,
            outcome: fetched_outcome,
        };
    }
    let Ok(value) = serde_json::from_slice::<Value>(&response.body) else {
        let outcome = if fetched_outcome.kind == SourceOutcomeKind::Inconclusive {
            outcome_with(
                module,
                SourceOutcomeKind::ParserDrift,
                now_unix,
                response.status,
                None,
                "response body is not valid JSON",
            )
        } else {
            fetched_outcome
        };
        return JsonEndpointResult {
            value: None,
            meta,
            outcome,
        };
    };
    if let Some(kind) = provider_failure_kind(&value, response.status) {
        return JsonEndpointResult {
            value: None,
            meta,
            outcome: outcome_with(
                module,
                kind,
                now_unix,
                response.status,
                Some(0),
                "provider reported request failure",
            ),
        };
    }
    if fetched_outcome.kind != SourceOutcomeKind::Inconclusive {
        return JsonEndpointResult {
            value: None,
            meta,
            outcome: fetched_outcome,
        };
    }
    let mut outcome = SourceExecutionOutcome::success(module, now_unix, 1);
    outcome.http_status = Some(response.status);
    JsonEndpointResult {
        value: Some(value),
        meta,
        outcome,
    }
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
        &FetchOptions::no_redirects(),
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
    Ok(parse_search_response(
        &response,
        fetched.outcome,
        module,
        now_unix,
        usize::from(effective_limit(search.limit)),
    ))
}

fn parse_search_response(
    response: &Response,
    fetched_outcome: SourceExecutionOutcome,
    module: &str,
    now_unix: u64,
    row_limit: usize,
) -> SeekNowSearchResult {
    let mut meta = response_meta(response);
    if response.truncated {
        return result_with_outcome(
            meta,
            outcome_with(
                module,
                SourceOutcomeKind::ParserDrift,
                now_unix,
                response.status,
                None,
                "truncated response body",
            ),
        );
    }

    if !response_body_may_refine(fetched_outcome.kind) {
        return result_with_outcome(meta, fetched_outcome);
    }

    let value: Value = match serde_json::from_slice(&response.body) {
        Ok(value) => value,
        Err(_) if fetched_outcome.kind != SourceOutcomeKind::Inconclusive => {
            return result_with_outcome(meta, fetched_outcome);
        }
        Err(_) => {
            return result_with_outcome(
                meta,
                outcome_with(
                    module,
                    SourceOutcomeKind::ParserDrift,
                    now_unix,
                    response.status,
                    None,
                    "response body is not valid JSON",
                ),
            );
        }
    };

    if let Some(kind) = provider_failure_kind(&value, response.status) {
        return result_with_outcome(
            meta,
            outcome_with(
                module,
                kind,
                now_unix,
                response.status,
                Some(0),
                "provider reported request failure",
            ),
        );
    }

    if fetched_outcome.kind != SourceOutcomeKind::Inconclusive {
        return result_with_outcome(meta, fetched_outcome);
    }

    let Some(items) = recognized_items(&value) else {
        return result_with_outcome(
            meta,
            outcome_with(
                module,
                SourceOutcomeKind::SchemaDrift,
                now_unix,
                response.status,
                None,
                "response has no recognized result array",
            ),
        );
    };

    if items.is_empty() {
        let mut outcome = SourceExecutionOutcome::valid_zero(module, now_unix);
        outcome.http_status = Some(response.status);
        return result_with_outcome(meta, outcome);
    }

    meta.normalized_rows_truncated = items.len() > row_limit;
    let rows = items
        .iter()
        .take(row_limit)
        .filter_map(normalize_row)
        .collect::<Vec<_>>();
    let mut outcome = SourceExecutionOutcome::success(module, now_unix, rows.len());
    outcome.http_status = Some(response.status);
    if rows.is_empty() {
        outcome.kind = SourceOutcomeKind::SchemaDrift;
        outcome.detail = Some("result array contained no supported row objects".into());
    }
    SeekNowSearchResult {
        rows,
        meta,
        outcome,
    }
}

fn response_body_may_refine(kind: SourceOutcomeKind) -> bool {
    matches!(
        kind,
        SourceOutcomeKind::Inconclusive
            | SourceOutcomeKind::AuthRejected
            | SourceOutcomeKind::AuthRequired
            | SourceOutcomeKind::RateLimited
            | SourceOutcomeKind::Upstream4xx
    )
}

fn result_with_outcome(
    meta: SeekNowResponseMeta,
    outcome: SourceExecutionOutcome,
) -> SeekNowSearchResult {
    SeekNowSearchResult {
        rows: Vec::new(),
        meta,
        outcome,
    }
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

fn normalize_row(value: &Value) -> Option<SeekNowRow> {
    let object = value.as_object()?;
    let upstream = extract_upstream(object);
    let mut fields = BTreeMap::new();
    let mut sensitive_fields = BTreeSet::new();
    let mut truncated_fields = BTreeSet::new();
    let mut fields_truncated = false;

    for (key, value) in object {
        if is_sensitive_result_field(key) {
            sensitive_fields.insert(key.clone());
            continue;
        }
        let Some(value) = scalar_string(value) else {
            continue;
        };
        if value.chars().count() > MAX_FIELD_CHARS {
            truncated_fields.insert(key.clone());
            fields_truncated = true;
            continue;
        }
        if fields.len() >= MAX_FIELDS_PER_ROW {
            fields_truncated = true;
            continue;
        }
        fields.insert(key.clone(), value);
    }

    Some(SeekNowRow {
        fields,
        upstream,
        sensitive_fields,
        truncated_fields,
        fields_truncated,
    })
}

fn extract_upstream(object: &serde_json::Map<String, Value>) -> SeekNowUpstream {
    SeekNowUpstream {
        dbname: upstream_values(object.get("dbname")),
        breach: upstream_values(object.get("breach")),
        source_db: upstream_values(object.get("source_db")),
        database_name: upstream_values(object.get("database_name")),
        dataset: upstream_values(object.get("dataset")),
        source: upstream_values(object.get("source")),
        record_id: ["record_id", "id", "_id"]
            .iter()
            .find_map(|key| object.get(*key).and_then(bounded_scalar_string)),
    }
}

fn upstream_values(value: Option<&Value>) -> Vec<String> {
    match value {
        Some(Value::Array(values)) => values
            .iter()
            .filter_map(bounded_scalar_string)
            .take(MAX_FIELDS_PER_ROW)
            .collect(),
        Some(value) => bounded_scalar_string(value).into_iter().collect(),
        None => Vec::new(),
    }
}

fn bounded_top_level_fields(object: &serde_json::Map<String, Value>) -> BTreeMap<String, String> {
    object
        .iter()
        .filter(|(key, _)| key.as_str() != "success" && !is_sensitive_result_field(key))
        .filter_map(|(key, value)| bounded_scalar_string(value).map(|value| (key.clone(), value)))
        .take(MAX_FIELDS_PER_ROW)
        .collect()
}

fn first_u64(value: &Value, keys: &[&str]) -> Option<u64> {
    let object = value.as_object()?;
    for key in keys {
        if let Some(number) = object.get(*key).and_then(value_as_u64) {
            return Some(number);
        }
    }
    let data = object.get("data")?.as_object()?;
    keys.iter()
        .find_map(|key| data.get(*key).and_then(value_as_u64))
}

fn value_as_u64(value: &Value) -> Option<u64> {
    value
        .as_u64()
        .or_else(|| value.as_str()?.trim().parse::<u64>().ok())
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

fn bounded_scalar_string(value: &Value) -> Option<String> {
    let value = scalar_string(value)?;
    (value.chars().count() <= MAX_FIELD_CHARS).then_some(value)
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
        normalized_rows_truncated: false,
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
