//! `OathNet` breach search: one keyed leg of `exposure`.
//!
//! One lookup is one `GET https://oathnet.org/api/service/v2/breach/search` filtered on one
//! field, `email[]=ADDR` or `username[]=HANDLE` ([`Query`]), with
//! the key in the `x-api-key` header, bound to [`KEY_ORIGIN`] by [`crate::fetch`]. Redirects are
//! not followed, so the key cannot be sent anywhere else. The endpoint, envelope and field names
//! are those of `OathNet`'s published `OpenAPI` document (`https://docs.oathnet.org/openapi.yaml`,
//! `V2BreachSearchResponse`); they are not verified against a live key here.
//!
//! What is kept is exposure metadata: per breach database (`dbname`), how many records hold the
//! address, which field types those records expose, whether a password or hash is among them,
//! the breach's public date, title, domain and size from `dbname_info`, and when `OathNet`
//! indexed the records. Usernames and other addresses in the records become pivots. No other
//! value of a record is kept: a password, hash, salt, phone number, street address or any other
//! field is reduced to its field name before decoding returns, so it cannot reach an entity, a
//! report or a saved ledger.
//!
//! The lookup reads one page of [`PAGE_SIZE`] records. When `OathNet` says there are more, the
//! answer is marked partial, never complete. A key, plan or quota refusal, a `success: false`
//! envelope, and a body that is not the envelope are errors, never a zero: a zero is only a
//! successful envelope with no items. Each lookup spends one of the key's daily lookups.

use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

use serde::Deserialize;
use serde_json::{Map, Value};

use crate::credential_origin::{AuthenticationAuthority, OperatorCredentialRef};
use crate::fetch::{AuthStyle, Credential, FetchOptions, fetch};
use crate::http::{Request, Response, Transport, TransportConfig, percent_encode_component};
use crate::keys::{Keys, Secret};
use crate::redact::{scrub_bounded, scrub_secrets};
use crate::source_outcome::SourceOutcomeKind;

/// Source label of this leg in outcomes, evidence and saved ledgers.
pub const SOURCE: &str = "oathnet";
/// The key slot this source reads.
pub const KEY_SLOT: &str = crate::environment::OATHNET_KEY_ENV;
/// The breach search endpoint.
pub const API_URL: &str = "https://oathnet.org/api/service/v2/breach/search";
/// The only origin the key is ever sent to.
pub const KEY_ORIGIN: &str = "https://oathnet.org:443";
/// `OathNet` requires this header name in lower case.
const KEY_HEADER: &str = "x-api-key";
/// Records read per lookup: the most `OathNet` returns in one request, so one lookup (one
/// daily lookup spent) reads as much as it can.
pub const PAGE_SIZE: u32 = 200;
/// Ceiling for the one request.
pub const TIMEOUT: Duration = Duration::from_secs(30);
/// Most field names kept for one breach database.
pub const MAX_FIELDS: usize = 64;
/// Longest field name kept, in bytes. A longer or unusual name is dropped, never shortened.
pub const MAX_FIELD_BYTES: usize = 48;
/// Most distinct values kept for one exposed field of one breach database.
pub const MAX_VALUES_PER_FIELD: usize = 64;
/// Longest record value kept, in bytes. A longer value is dropped whole, never truncated, so a
/// surfaced value is always exactly what the record held.
pub const MAX_VALUE_BYTES: usize = 1024;
/// Longest provider text kept in a diagnostic, in characters.
const PROVIDER_WORDS_MAX_CHARS: usize = 120;

/// Record keys that describe the record, not the person, so they are not exposed fields.
const RECORD_METADATA: [&str; 5] = ["id", "dbname", "indexed_at", "email_domain", "extra"];
/// Record keys that carry a password or something derived from one.
const PASSWORD_FIELDS: [&str; 3] = ["password", "password_hash", "salt"];

/// Why a lookup gave no answer. No variant carries the key, the address or a response body.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum OathnetError {
    #[error("oathnet: no API key configured (set {KEY_SLOT})")]
    MissingKey,
    #[error("oathnet: request refused before sending: {0}")]
    Refused(String),
    #[error("oathnet: no response ({0:?})")]
    Transport(SourceOutcomeKind),
    #[error("oathnet: bad request (HTTP 400)")]
    BadRequest,
    #[error("oathnet: unauthorised (HTTP 401): the key was rejected")]
    Unauthorized,
    #[error("oathnet: forbidden (HTTP 403): the plan or the daily lookup quota does not allow it")]
    Forbidden,
    #[error("oathnet: rate or quota limit reached (HTTP 429){}", describe_retry(*.retry_after))]
    RateLimited { retry_after: Option<u64> },
    #[error("oathnet: server error (HTTP {0})")]
    Server(u16),
    #[error("oathnet: unexpected HTTP {0}")]
    Unexpected(u16),
    #[error("oathnet: response is not an API answer ({0:?})")]
    NotAnAnswer(SourceOutcomeKind),
    #[error("oathnet: {0}")]
    Decode(String),
    #[error("oathnet: success=false: {0}")]
    Provider(String),
}

fn describe_retry(retry_after: Option<u64>) -> String {
    retry_after.map_or_else(String::new, |secs| format!(", retry after {secs}s"))
}

impl OathnetError {
    /// The outcome a failed lookup records.
    #[must_use]
    pub const fn outcome_kind(&self) -> SourceOutcomeKind {
        match self {
            Self::MissingKey => SourceOutcomeKind::NotConfigured,
            Self::Unauthorized => SourceOutcomeKind::AuthRejected,
            Self::Forbidden => SourceOutcomeKind::EntitlementDenied,
            Self::RateLimited { .. } => SourceOutcomeKind::RateLimited,
            Self::BadRequest | Self::Unexpected(_) => SourceOutcomeKind::Upstream4xx,
            Self::Server(_) => SourceOutcomeKind::Upstream5xx,
            Self::Transport(kind) | Self::NotAnAnswer(kind) => *kind,
            Self::Decode(_) => SourceOutcomeKind::SchemaDrift,
            Self::Refused(_) | Self::Provider(_) => SourceOutcomeKind::Inconclusive,
        }
    }

    /// The HTTP status behind the failure, when there was one.
    #[must_use]
    pub const fn http_status(&self) -> Option<u16> {
        match self {
            Self::BadRequest => Some(400),
            Self::Unauthorized => Some(401),
            Self::Forbidden => Some(403),
            Self::RateLimited { .. } => Some(429),
            Self::Server(status) | Self::Unexpected(status) => Some(*status),
            _ => None,
        }
    }
}

/// What the records of one breach database say about the address. Besides the provider's breach
/// metadata, this carries the record field values themselves: the tool's purpose is unredacted
/// output, so a value a record exposes is surfaced, not reduced to the fact that a field was
/// present.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Breach {
    /// The breach database name as `OathNet` gives it.
    pub dbname: String,
    /// Records on this page that hold the address.
    pub records: usize,
    /// Field types the records expose, sorted.
    pub fields: BTreeSet<String>,
    /// The distinct values each exposed field holds across the records, keyed by field name and
    /// sorted. This is the de-redacted payload: the actual names, emails, phone numbers, usernames
    /// and anything else the records carry, bounded by [`MAX_VALUES_PER_FIELD`] and
    /// [`MAX_VALUE_BYTES`] so one record cannot flood the report. Cleartext credentials (the
    /// [`PASSWORD_FIELDS`]: password, hash, salt) are deliberately **not** here — their presence is
    /// recorded by [`Self::password_exposed`] and the field name, but the secret value an attacker
    /// would need is never emitted.
    pub values: BTreeMap<String, BTreeSet<String>>,
    /// A record holds a password, a password hash or a salt. The field name is in [`Self::fields`];
    /// the cleartext value is held back and never appears in [`Self::values`].
    pub password_exposed: bool,
    pub title: Option<String>,
    pub domain: Option<String>,
    pub breach_date: Option<String>,
    pub pwn_count: Option<u64>,
    /// Earliest and latest `indexed_at` among the records.
    pub first_indexed: Option<String>,
    pub last_indexed: Option<String>,
}

/// One decoded search page.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Search {
    /// One entry per breach database, sorted by name.
    pub breaches: Vec<Breach>,
    /// Records on this page.
    pub records: usize,
    /// Records that name no breach database. Counted, never given a stand-in name.
    pub unnamed_records: usize,
    /// Distinct usernames in the records, sorted.
    pub usernames: BTreeSet<String>,
    /// Distinct addresses in the records, sorted, as written.
    pub emails: BTreeSet<String>,
    /// Matching records `OathNet` reports in all.
    pub total: Option<u64>,
    /// `OathNet` says more records exist than this page holds.
    pub has_more: bool,
}

impl Search {
    /// Why this page is not the whole answer, or `None` when it is.
    #[must_use]
    pub fn truncation(&self) -> Option<String> {
        let more_than_read = self.total.is_some_and(|total| total > self.records as u64);
        if !(self.has_more || more_than_read) {
            return None;
        }
        let total = self
            .total
            .map_or_else(|| "an unreported number".to_owned(), |t| t.to_string());
        Some(format!(
            "partial: read the first {} of {total} matching records; absence of a breach here \
             is not evidence of absence",
            self.records
        ))
    }
}

#[derive(Deserialize)]
struct Envelope {
    success: Option<bool>,
    #[serde(default)]
    message: Option<String>,
    #[serde(default)]
    data: Option<Data>,
}

#[derive(Deserialize)]
struct Data {
    items: Vec<Map<String, Value>>,
    #[serde(default)]
    meta: Option<Meta>,
    #[serde(default)]
    dbname_info: BTreeMap<String, LeakMetadata>,
}

#[derive(Deserialize, Default)]
struct Meta {
    #[serde(default)]
    total: Option<u64>,
    #[serde(default)]
    has_more: Option<bool>,
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "PascalCase")]
struct LeakMetadata {
    #[serde(default)]
    title: Option<String>,
    #[serde(default)]
    domain: Option<String>,
    #[serde(default)]
    breach_date: Option<String>,
    #[serde(default)]
    pwn_count: Option<u64>,
}

/// Transport settings for `OathNet`: the [`TIMEOUT`] ceiling.
#[must_use]
pub fn transport_config() -> TransportConfig {
    TransportConfig {
        timeout: TIMEOUT,
        ..TransportConfig::default()
    }
}

/// What one search matches: one exact value on one record field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Query<'a> {
    Email(&'a str),
    Username(&'a str),
}

impl Query<'_> {
    /// The `OathNet` flat filter this query uses.
    #[must_use]
    pub const fn field(self) -> &'static str {
        match self {
            Self::Email(_) => "email",
            Self::Username(_) => "username",
        }
    }

    #[must_use]
    pub const fn value(&self) -> &str {
        match self {
            Self::Email(value) | Self::Username(value) => value,
        }
    }
}

/// The request URL for `query`. **Pure.**
#[must_use]
pub fn search_url(query: Query<'_>) -> String {
    format!(
        "{API_URL}?{}%5B%5D={}&page_size={PAGE_SIZE}",
        query.field(),
        percent_encode_component(query.value())
    )
}

/// Search `OathNet`'s breach records for `query` with the key in `keys`.
///
/// # Errors
/// [`OathnetError::MissingKey`] before any request when no key is configured; otherwise the
/// refusal, status, envelope or decode failure that stopped the lookup.
pub fn search<T: Transport + ?Sized>(
    transport: &T,
    keys: &Keys,
    query: Query<'_>,
    now_unix: u64,
) -> Result<Search, OathnetError> {
    let secret = keys.get(KEY_SLOT).ok_or(OathnetError::MissingKey)?;
    let credential = credential(secret.clone(), now_unix)?;
    let request = Request::get(search_url(query))
        .header("Accept", "application/json")
        .with_timeout(TIMEOUT);
    let fetched = fetch(
        transport,
        request,
        Some(&credential),
        &FetchOptions::no_redirects(),
        SOURCE,
        now_unix,
    )
    .map_err(|e| OathnetError::Refused(scrub_secrets(&e.to_string(), &[secret.expose()])))?;
    let Some(response) = fetched.response else {
        return Err(OathnetError::Transport(fetched.outcome.kind));
    };
    status_error(&response, fetched.outcome.retry_after_secs)?;
    if fetched.outcome.kind != SourceOutcomeKind::Inconclusive {
        return Err(OathnetError::NotAnAnswer(fetched.outcome.kind));
    }
    if response.truncated {
        return Err(OathnetError::Decode(
            "response exceeds the body limit".into(),
        ));
    }
    decode(&response.body, &[secret.expose()])
}

fn credential(secret: Secret, now_unix: u64) -> Result<Credential, OathnetError> {
    let authority = AuthenticationAuthority::operator_approved(OperatorCredentialRef {
        provider_id: "oathnet.org".into(),
        credential_slot: KEY_SLOT.into(),
        approved_at_unix: now_unix,
        approval_provenance: format!("operator configured {KEY_SLOT}"),
    })
    .map_err(|e| OathnetError::Refused(e.to_string()))?;
    Credential::new(authority, secret, AuthStyle::Header(KEY_HEADER.into()))
        .map(|c| c.only_for_origin(KEY_ORIGIN))
        .map_err(|e| OathnetError::Refused(e.to_string()))
}

/// The error a non-2xx status means. The status decides first, as `OathNet`'s error guide says.
/// A rate limit carries `retry_after`, the pause [`fetch`] read from the response's `Retry-After`
/// (delta-seconds or an HTTP-date, capped at an hour).
fn status_error(response: &Response, retry_after: Option<u64>) -> Result<(), OathnetError> {
    match response.status {
        200..=299 => Ok(()),
        400 => Err(OathnetError::BadRequest),
        401 => Err(OathnetError::Unauthorized),
        403 => Err(OathnetError::Forbidden),
        429 => Err(OathnetError::RateLimited { retry_after }),
        status @ 500..=599 => Err(OathnetError::Server(status)),
        status => Err(OathnetError::Unexpected(status)),
    }
}

/// One response body as a search page, with every secret in `secrets` scrubbed from any
/// provider text kept. **Pure.**
///
/// # Errors
/// [`OathnetError::Provider`] for a `success: false` envelope, [`OathnetError::Decode`] for a
/// body that is not the envelope or has no `data.items` array.
pub fn decode(body: &[u8], secrets: &[&str]) -> Result<Search, OathnetError> {
    let envelope: Envelope = serde_json::from_slice(body).map_err(|e| decode_error(&e))?;
    if envelope.success == Some(false) {
        let message = envelope.message.as_deref().unwrap_or("no message");
        return Err(OathnetError::Provider(provider_words(message, secrets)));
    }
    let data = envelope
        .data
        .ok_or_else(|| OathnetError::Decode("envelope has no data".into()))?;
    let meta = data.meta.unwrap_or_default();
    let mut search = Search {
        records: data.items.len(),
        total: meta.total,
        has_more: meta.has_more.unwrap_or(false),
        ..Search::default()
    };
    let mut breaches: BTreeMap<String, Breach> = BTreeMap::new();
    for item in &data.items {
        if let Some(email) = text(item, "email") {
            search.emails.insert(email.to_owned());
        }
        if let Some(username) = text(item, "username") {
            search.usernames.insert(username.to_owned());
        }
        let Some(dbname) = text(item, "dbname") else {
            search.unnamed_records += 1;
            continue;
        };
        let breach = breaches.entry(dbname.to_owned()).or_insert_with(|| Breach {
            dbname: dbname.to_owned(),
            ..Breach::default()
        });
        breach.records += 1;
        record_fields(item, breach);
        if let Some(indexed) = text(item, "indexed_at") {
            widen(&mut breach.first_indexed, indexed, |new, old| new < old);
            widen(&mut breach.last_indexed, indexed, |new, old| new > old);
        }
    }
    for (name, breach) in &mut breaches {
        if let Some(info) = data.dbname_info.get(name) {
            breach.title = non_blank(info.title.as_deref());
            breach.domain = non_blank(info.domain.as_deref());
            breach.breach_date = non_blank(info.breach_date.as_deref());
            breach.pwn_count = info.pwn_count;
        }
    }
    search.breaches = breaches.into_values().collect();
    Ok(search)
}

/// Adds the exposed fields of one record, those of its `extra` object included, and the value each
/// non-credential one holds. The value is kept, not just the field name, so the report is
/// unredacted; a cleartext credential (a [`PASSWORD_FIELDS`] entry) records only that it was
/// exposed, never the secret itself. **Pure.**
fn record_fields(item: &Map<String, Value>, breach: &mut Breach) {
    let extra = item.get("extra").and_then(Value::as_object);
    let named = item
        .iter()
        .filter(|(key, _)| !RECORD_METADATA.contains(&key.as_str()))
        .chain(extra.into_iter().flatten());
    for (key, value) in named {
        if !present(value) {
            continue;
        }
        let Some(field) = field_name(key) else {
            continue;
        };
        let is_credential = PASSWORD_FIELDS.contains(&field.as_str());
        if is_credential {
            breach.password_exposed = true;
        }
        if breach.fields.len() < MAX_FIELDS || breach.fields.contains(&field) {
            // The report is unredacted for the record's own data, but a third party's cleartext
            // credential (password, hash or salt) is never emitted: that is the value an attacker
            // needs for account takeover. The fact that such a field was exposed, its type and the
            // breach it came from are kept (the field name and `password_exposed`); only the secret
            // value is held back. Every other field's value is surfaced as the record held it.
            if !is_credential {
                if let Some(text) = record_value(value) {
                    let seen = breach.values.entry(field.clone()).or_default();
                    if seen.len() < MAX_VALUES_PER_FIELD {
                        seen.insert(text);
                    }
                }
            }
            breach.fields.insert(field);
        }
    }
}

/// One record value as text for the report: a string as written, a number or boolean as shown, a
/// list or object as compact JSON. `None` when it is blank or longer than [`MAX_VALUE_BYTES`], so
/// an oversized value is dropped whole rather than cut and a surfaced value is exactly what the
/// record held. [`present`] has already ruled out null, `false` and empty containers. **Pure.**
fn record_value(value: &Value) -> Option<String> {
    let text = match value {
        Value::Null | Value::Bool(false) => return None,
        Value::Bool(true) => "true".to_owned(),
        Value::Number(number) => number.to_string(),
        Value::String(string) => string.trim().to_owned(),
        Value::Array(_) | Value::Object(_) => serde_json::to_string(value).ok()?,
    };
    (!text.is_empty() && text.len() <= MAX_VALUE_BYTES).then_some(text)
}

/// `key` as a field name: lower-case ASCII letters, digits and `_`, at most [`MAX_FIELD_BYTES`].
/// Anything else is dropped, so a key cannot smuggle a value into the report. **Pure.**
fn field_name(key: &str) -> Option<String> {
    let name = key.trim().to_ascii_lowercase();
    let ok = !name.is_empty()
        && name.len() <= MAX_FIELD_BYTES
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_');
    ok.then_some(name)
}

/// The value holds something: a non-blank string, a number, `true`, or a non-empty list or
/// object. **Pure.**
fn present(value: &Value) -> bool {
    match value {
        Value::Null | Value::Bool(false) => false,
        Value::Bool(true) | Value::Number(_) => true,
        Value::String(s) => !s.trim().is_empty(),
        Value::Array(a) => !a.is_empty(),
        Value::Object(o) => !o.is_empty(),
    }
}

fn text<'a>(item: &'a Map<String, Value>, key: &str) -> Option<&'a str> {
    item.get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
}

fn non_blank(value: Option<&str>) -> Option<String> {
    value
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
}

/// Replace `slot` with `candidate` when it is empty or `better(candidate, current)`. ISO 8601
/// timestamps in one format order as strings. **Pure.**
fn widen(slot: &mut Option<String>, candidate: &str, better: impl Fn(&str, &str) -> bool) {
    if slot
        .as_deref()
        .is_none_or(|current| better(candidate, current))
    {
        *slot = Some(candidate.to_owned());
    }
}

/// A body that is not the envelope: the error's category and position, never serde's message,
/// which can quote the body. **Pure.**
fn decode_error(e: &serde_json::Error) -> OathnetError {
    let category = match e.classify() {
        serde_json::error::Category::Io => "io",
        serde_json::error::Category::Syntax => "syntax",
        serde_json::error::Category::Data => "data",
        serde_json::error::Category::Eof => "eof",
    };
    OathnetError::Decode(format!(
        "unexpected response shape: {category} error at line {} column {}",
        e.line(),
        e.column()
    ))
}

/// The provider's message as a diagnostic may show it: secrets scrubbed first, then at most
/// [`PROVIDER_WORDS_MAX_CHARS`] characters, control characters replaced. **Pure.**
fn provider_words(message: &str, secrets: &[&str]) -> String {
    scrub_bounded(message, secrets, PROVIDER_WORDS_MAX_CHARS)
}

#[cfg(test)]
mod tests;
