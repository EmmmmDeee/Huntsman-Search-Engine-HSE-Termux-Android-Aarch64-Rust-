//! stolen.tax v2: credential-breach and stealer-log exposure, key-gated.
//!
//! Ported from M D's `src/modules/stolen_tax` (lost local commit 764ce8e, restored on
//! the old tree as `1dfb5c9d`, plus M D's uncommitted blank-name/host guard). The
//! stale v1 copy under `legacy/` (`GET api.stolen.tax`, `Api-Key` header) is not the
//! source.
//!
//! One query string is sent as a `POST` body `{"query": …}` to each v2 path in
//! cascade order, `https://stolen.tax/api/v2/index.php?path=snusbase|osintcat|hudsonrock`,
//! with
//! `Authorization: Bearer <key>` bound to the `https://stolen.tax` origin by
//! [`crate::fetch`]. Results are merged and deduplicated into Email / Username pivots
//! and `Credential` markers (`breach:{corpus}`, `stealer:{host}`).
//!
//! Never emitted: cleartext passwords, hashes, `top_passwords`. The wire types do not
//! declare those fields, so they cannot become entity values.
//!
//! Budget: the whole lookup (all three paths) shares one [`LOOKUP_BUDGET`] of 120 s,
//! the monolith's `max_timeout_ms() = 120_000` for the cascade. Each request is sent
//! with what is left of it (never more than [`TIMEOUT`]); a path that would start
//! after the budget is spent is not sent and is listed in
//! [`StolenTaxReport::skipped_paths`]. Worst case: 120 s, not 3 x 120 s.
//!
//! Honest failure: a path that fails or is skipped while another produced evidence
//! is reported in [`StolenTaxReport::failed_paths`] / [`StolenTaxReport::skipped_paths`]
//! and [`StolenTaxReport::truncation`]; when nothing was collected and any path
//! failed or was skipped, the lookup is an error, never a clean negative. A paid
//! source: nothing in this crate calls it automatically.

use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

use serde::Deserialize;
use serde_json::Value;

use crate::credential_origin::{AuthenticationAuthority, OperatorCredentialRef};
use crate::deadline::{Clock, Deadline, SystemClock};
use crate::entity::{Entity, EntityKind, Evidence, EvidenceProvenance, normalise};
use crate::fetch::{AuthStyle, Credential, FetchOptions, fetch};
use crate::http::{Request, Transport, TransportConfig};
use crate::keys::{Keys, Secret};
use crate::redact::scrub_secrets;
use crate::source_outcome::SourceOutcomeKind;

const SRC: &str = "stolen_tax";
/// The key slot this source reads (keys file or environment).
pub const KEY_SLOT: &str = "HUNTSMAN_STOLEN_TAX_KEY";
/// v2 gateway; the path is appended per cascade step.
const API_BASE: &str = "https://stolen.tax/api/v2/index.php?path=";
/// Cascade order: snusbase primary, then the secondary corpora, always all three.
const PATHS: [&str; 3] = ["snusbase", "osintcat", "hudsonrock"];
/// Budget for the whole lookup, every path included. The monolith's engine stopped
/// the three-path cascade at `max_timeout_ms() = 120_000` (snusbase alone takes
/// ~30–50 s).
pub const LOOKUP_BUDGET: Duration = Duration::from_secs(120);
/// Per-request ceiling (the transport timeout). A request is sent with
/// `min(TIMEOUT, what is left of LOOKUP_BUDGET)`.
pub const TIMEOUT: Duration = Duration::from_secs(120);

// Confidence tiers carried over from the monolith's `core::confidence`.
const MEDIUM: f64 = 0.50;
const HIGH: f64 = 0.65;

/// Why a lookup produced no answer. Never carries the key.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum StolenTaxError {
    /// No key in the keys file or environment.
    #[error("stolen_tax: no API key configured (set {KEY_SLOT})")]
    MissingKey,
    /// Refused before sending: the egress policy or a malformed request.
    #[error("stolen_tax: request refused: {0}")]
    Refused(String),
    /// Every path failed or none produced evidence while one failed: the first
    /// failure, in cascade order.
    #[error("stolen_tax: `{}` path failed: {}", .0.path, .0.reason)]
    Failed(PathFailure),
    /// Nothing was collected and the lookup budget ran out before every path was
    /// sent. Not a clean negative: `skipped` were never asked.
    #[error(
        "stolen_tax: {}s lookup budget exhausted; `{}` path(s) not sent{}",
        LOOKUP_BUDGET.as_secs(),
        .skipped.join("`, `"),
        .failed.first().map_or_else(String::new, |f| format!("; `{}` path failed: {}", f.path, f.reason))
    )]
    BudgetExhausted {
        /// Paths not sent, in cascade order.
        skipped: Vec<&'static str>,
        /// Paths that were sent and failed, in cascade order.
        failed: Vec<PathFailure>,
    },
}

/// One cascade path that gave no usable answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathFailure {
    pub path: &'static str,
    /// Diagnostic text with the key scrubbed. Never a response body.
    pub reason: String,
}

/// What one lookup returned.
#[derive(Debug, Clone, PartialEq)]
pub struct StolenTaxReport {
    /// Distinct entities: emails, then usernames, then credential markers.
    pub entities: Vec<Entity>,
    /// Paths that failed while another still produced evidence.
    pub failed_paths: Vec<PathFailure>,
    /// Paths never sent because [`LOOKUP_BUDGET`] was spent first, in cascade order.
    pub skipped_paths: Vec<&'static str>,
    /// Set when `failed_paths` or `skipped_paths` is non-empty: this answer is
    /// incomplete.
    pub truncation: Option<String>,
}

/// Transport settings for stolen.tax: the 120 s per-request ceiling. The lookup
/// lowers it per request to what is left of [`LOOKUP_BUDGET`].
#[must_use]
pub fn transport_config() -> TransportConfig {
    TransportConfig {
        timeout: TIMEOUT,
        ..TransportConfig::default()
    }
}

/// Query every stolen.tax v2 path for `query` with the key in `keys`, all of it
/// within [`LOOKUP_BUDGET`].
///
/// # Errors
/// [`StolenTaxError::MissingKey`] before any request when no key is configured;
/// [`StolenTaxError::Refused`] when the egress policy refused the destination;
/// [`StolenTaxError::Failed`] when no evidence was collected and a path failed;
/// [`StolenTaxError::BudgetExhausted`] when no evidence was collected and a path
/// was not sent because the budget ran out.
pub fn lookup<T: Transport + ?Sized>(
    transport: &T,
    keys: &Keys,
    query: &str,
    scan_id: &str,
    now_unix: u64,
) -> Result<StolenTaxReport, StolenTaxError> {
    lookup_with_clock(transport, &SystemClock, keys, query, scan_id, now_unix)
}

fn lookup_with_clock<T: Transport + ?Sized>(
    transport: &T,
    clock: &dyn Clock,
    keys: &Keys,
    query: &str,
    scan_id: &str,
    now_unix: u64,
) -> Result<StolenTaxReport, StolenTaxError> {
    let secret = keys.get(KEY_SLOT).ok_or(StolenTaxError::MissingKey)?;
    let credential = credential(secret.clone(), now_unix)?;
    let body = serde_json::to_vec(&serde_json::json!({ "query": query }))
        .map_err(|e| StolenTaxError::Refused(e.to_string()))?;

    let deadline = Deadline::start(clock, LOOKUP_BUDGET);
    let mut merged = StolenTaxData::default();
    let mut failures = Vec::new();
    let mut skipped = Vec::new();
    for path in PATHS {
        let remaining = deadline.remaining();
        if remaining.is_zero() {
            skipped.push(path);
            continue;
        }
        let cap = remaining.min(TIMEOUT);
        match query_path(transport, &credential, &secret, path, &body, now_unix, cap)? {
            Ok(chunk) => merge_data(&mut merged, chunk),
            Err(reason) => failures.push(PathFailure { path, reason }),
        }
    }
    assemble(&merged, failures, skipped, query, scan_id)
}

fn credential(secret: Secret, now_unix: u64) -> Result<Credential, StolenTaxError> {
    let authority = AuthenticationAuthority::operator_approved(OperatorCredentialRef {
        provider_id: "stolen.tax".into(),
        credential_slot: KEY_SLOT.into(),
        approved_at_unix: now_unix,
        approval_provenance: format!("operator configured {KEY_SLOT}"),
    })
    .map_err(|e| StolenTaxError::Refused(e.to_string()))?;
    Credential::new(authority, secret, AuthStyle::Bearer)
        .map_err(|e| StolenTaxError::Refused(e.to_string()))
}

/// One POST, capped at `cap`. Outer `Err` aborts the cascade (refused before
/// sending); inner `Err` is this path's failure, and the cascade continues.
fn query_path<T: Transport + ?Sized>(
    transport: &T,
    credential: &Credential,
    secret: &Secret,
    path: &'static str,
    body: &[u8],
    now_unix: u64,
    cap: Duration,
) -> Result<Result<StolenTaxData, String>, StolenTaxError> {
    let request = Request::post(format!("{API_BASE}{path}"), body.to_vec())
        .header("Content-Type", "application/json")
        .header("Accept", "application/json")
        .with_timeout(cap);
    let fetched = fetch(
        transport,
        request,
        Some(credential),
        &FetchOptions { max_redirects: 0 },
        SRC,
        now_unix,
    )
    .map_err(|e| StolenTaxError::Refused(e.to_string()))?;
    let scrub = |text: &str| scrub_secrets(text, &[secret.expose()]);
    let Some(response) = fetched.response else {
        let kind = fetched.outcome.kind;
        return Ok(Err(if cap < TIMEOUT {
            format!(
                "no response ({kind:?}); request capped at {:.1}s, the rest of the {}s lookup budget",
                cap.as_secs_f64(),
                LOOKUP_BUDGET.as_secs()
            )
        } else {
            format!("no response ({kind:?})")
        }));
    };
    if !(200..300).contains(&response.status) {
        return Ok(Err(format!(
            "HTTP {} ({:?})",
            response.status, fetched.outcome.kind
        )));
    }
    if fetched.outcome.kind != SourceOutcomeKind::Inconclusive {
        return Ok(Err(format!(
            "response is not an API answer ({:?})",
            fetched.outcome.kind
        )));
    }
    if response.truncated {
        return Ok(Err("response exceeds the body limit".into()));
    }
    Ok(decode_path(path, &response.body).map_err(|reason| scrub(&reason)))
}

/// Envelope → normalised rows for one path. A `success: false` envelope is a
/// failure in the provider's own words: a zero-hit search answers `success: true`
/// with empty data, so `false` is never "no results". **Pure.**
fn decode_path(path: &str, body: &[u8]) -> Result<StolenTaxData, String> {
    let envelope: StolenTaxResponse =
        serde_json::from_slice(body).map_err(|e| format!("could not decode response: {e}"))?;
    if !envelope.success {
        let message = envelope.error.as_deref().unwrap_or("no error text");
        let class = if crate::service_defs::looks_like_auth_failure_text(message) {
            "key or quota rejected"
        } else {
            "provider reported failure"
        };
        return Err(format!("success=false, {class}: {message}"));
    }
    match envelope.data {
        Some(data) => normalize_path(path, data),
        None => Ok(StolenTaxData::default()),
    }
}

/// Merge the cascade into the report, or fail when there is nothing to report and a
/// path failed or was skipped. **Pure.**
fn assemble(
    merged: &StolenTaxData,
    failures: Vec<PathFailure>,
    skipped: Vec<&'static str>,
    query: &str,
    scan_id: &str,
) -> Result<StolenTaxReport, StolenTaxError> {
    let entities = dedup(build_entities(merged, query, scan_id));
    if entities.is_empty() {
        if !skipped.is_empty() {
            return Err(StolenTaxError::BudgetExhausted {
                skipped,
                failed: failures,
            });
        }
        if let Some(first) = failures.into_iter().next() {
            return Err(StolenTaxError::Failed(first));
        }
        return Ok(StolenTaxReport {
            entities,
            failed_paths: Vec::new(),
            skipped_paths: Vec::new(),
            truncation: None,
        });
    }
    let truncation = partial_note(entities.len(), &failures, &skipped);
    Ok(StolenTaxReport {
        entities,
        failed_paths: failures,
        skipped_paths: skipped,
        truncation,
    })
}

/// The partial-answer note, or `None` for a complete cascade. Failures alone keep
/// the monolith's wording. **Pure.**
fn partial_note(retrieved: usize, failures: &[PathFailure], skipped: &[&str]) -> Option<String> {
    let mut causes = Vec::new();
    if !failures.is_empty() {
        let names: Vec<&str> = failures.iter().map(|f| f.path).collect();
        causes.push(format!(
            "the stolen.tax `{}` path(s) failing",
            names.join("`, `")
        ));
    }
    if !skipped.is_empty() {
        causes.push(format!(
            "{} `{}` path(s) not sent ({}s lookup budget exhausted)",
            if failures.is_empty() {
                "the stolen.tax"
            } else {
                "the"
            },
            skipped.join("`, `"),
            LOOKUP_BUDGET.as_secs()
        ));
    }
    (!causes.is_empty()).then(|| {
        format!(
            "{retrieved} retrieved — stopped by {}, and the provider did not report how many exist. Absence of a finding here is not evidence of absence.",
            causes.join(" and ")
        )
    })
}

/// Fold same-uid entities into the first occurrence. **Pure.**
fn dedup(entities: Vec<Entity>) -> Vec<Entity> {
    let mut index: BTreeMap<String, usize> = BTreeMap::new();
    let mut out: Vec<Entity> = Vec::with_capacity(entities.len());
    for entity in entities {
        if let Some(&i) = index.get(&entity.uid) {
            out[i].absorb(entity);
        } else {
            index.insert(entity.uid.clone(), out.len());
            out.push(entity);
        }
    }
    out
}

/// Wire envelope (`success` / `data` / `error`). `data` is path-shaped and stays
/// a raw value until the path normaliser runs.
#[derive(Debug, Deserialize)]
struct StolenTaxResponse {
    success: bool,
    #[serde(default)]
    data: Option<Value>,
    #[serde(default)]
    error: Option<String>,
}

/// snusbase `data`: `results` maps breach-db name → rows. An empty hit is wired
/// as `results: []`, not `{}`; both (and `null`) are accepted.
#[derive(Debug, Deserialize, Default)]
struct SnusbaseApiData {
    #[serde(default, deserialize_with = "deserialize_snusbase_results")]
    results: BTreeMap<String, Vec<SnusbaseRow>>,
}

fn deserialize_snusbase_results<'de, D>(
    deserializer: D,
) -> Result<BTreeMap<String, Vec<SnusbaseRow>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    match Value::deserialize(deserializer)? {
        Value::Null => Ok(BTreeMap::new()),
        Value::Object(map) => {
            serde_json::from_value(Value::Object(map)).map_err(serde::de::Error::custom)
        }
        Value::Array(arr) if arr.is_empty() => Ok(BTreeMap::new()),
        Value::Array(_) => Err(serde::de::Error::custom(
            "snusbase results: expected object map or empty array, got non-empty array",
        )),
        other => Err(serde::de::Error::custom(format!(
            "snusbase results: expected object map or empty array, got {other}"
        ))),
    }
}

/// One snusbase row. Only identity fields are declared; `hash` / `password` are not.
#[derive(Debug, Deserialize, Default)]
struct SnusbaseRow {
    #[serde(default)]
    email: Option<String>,
    #[serde(default)]
    username: Option<String>,
}

/// osintcat `data`: identity rows in `breach_data`; meta keys are ignored.
#[derive(Debug, Deserialize, Default)]
struct OsintcatApiData {
    #[serde(default)]
    breach_data: Vec<Value>,
}

/// One osintcat row; field names vary. Password / hash keys are not declared.
#[derive(Debug, Deserialize, Default)]
struct OsintcatRow {
    #[serde(default)]
    email: Option<String>,
    #[serde(default)]
    username: Option<String>,
    #[serde(default)]
    source: Option<String>,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    database: Option<String>,
    #[serde(default, alias = "db_name", alias = "breach_name")]
    breach: Option<String>,
    #[serde(default, alias = "breach_date")]
    date: Option<String>,
}

/// hudsonrock `data`: stealer-log hits. `top_passwords` is not declared.
#[derive(Debug, Deserialize, Default)]
struct HudsonrockApiData {
    #[serde(default)]
    stealers: Vec<HudsonrockStealer>,
}

#[derive(Debug, Deserialize, Default)]
struct HudsonrockStealer {
    #[serde(default)]
    computer_name: Option<String>,
    #[serde(default)]
    operating_system: Option<String>,
    #[serde(default)]
    date_compromised: Option<String>,
    #[serde(default)]
    ip: Option<String>,
    #[serde(default)]
    top_logins: Vec<String>,
}

/// The merged, path-independent view the entity builder reads.
#[derive(Debug, Default)]
struct StolenTaxData {
    breaches: Vec<BreachRecord>,
    emails: Vec<String>,
    usernames: Vec<String>,
}

#[derive(Debug)]
struct BreachRecord {
    /// A corpus name (→ `breach:{name}`) or a full `stealer:{host}` marker.
    name: String,
    date: Option<String>,
    record_count: Option<usize>,
    /// Extra text-only facts (`path=…; os=…; ip=…`).
    detail: Option<String>,
}

/// Append `from` onto `into`. **Pure.**
fn merge_data(into: &mut StolenTaxData, from: StolenTaxData) {
    into.emails.extend(from.emails);
    into.usernames.extend(from.usernames);
    into.breaches.extend(from.breaches);
}

/// `Some(trimmed)` for a present, non-blank provider field. **Pure.**
fn non_blank(v: Option<&str>) -> Option<&str> {
    v.map(str::trim).filter(|s| !s.is_empty())
}

fn normalize_path(path: &str, data: Value) -> Result<StolenTaxData, String> {
    match path {
        "snusbase" => serde_json::from_value::<SnusbaseApiData>(data)
            .map(|api| normalize_snusbase(&api.results))
            .map_err(|e| format!("snusbase data decode failed: {e}")),
        "osintcat" => serde_json::from_value::<OsintcatApiData>(data)
            .map(|api| normalize_osintcat(&api.breach_data))
            .map_err(|e| format!("osintcat data decode failed: {e}")),
        "hudsonrock" => serde_json::from_value::<HudsonrockApiData>(data)
            .map(|api| normalize_hudsonrock(&api.stealers))
            .map_err(|e| format!("hudsonrock data decode failed: {e}")),
        other => Err(format!("unknown stolen.tax path: {other}")),
    }
}

/// Emails, usernames, and one breach record per db name with its row count. **Pure.**
fn normalize_snusbase(results: &BTreeMap<String, Vec<SnusbaseRow>>) -> StolenTaxData {
    let mut data = StolenTaxData::default();
    for (db_name, rows) in results {
        data.breaches.push(BreachRecord {
            name: db_name.clone(),
            date: None,
            record_count: Some(rows.len()),
            detail: None,
        });
        for row in rows {
            if let Some(email) = non_blank(row.email.as_deref()) {
                data.emails.push(email.to_owned());
            }
            if let Some(user) = non_blank(row.username.as_deref()) {
                data.usernames.push(user.to_owned());
            }
        }
    }
    data
}

/// osintcat rows. A row whose corpus is unnamed still contributes its identity
/// pivots but mints no `breach:` marker: a stand-in name would be a placeholder
/// posing as a breach the provider never named. A row that is not an object is
/// skipped. **Pure.**
fn normalize_osintcat(breach_data: &[Value]) -> StolenTaxData {
    let mut data = StolenTaxData::default();
    for raw in breach_data {
        let Ok(row) = serde_json::from_value::<OsintcatRow>(raw.clone()) else {
            continue;
        };
        let corpus = non_blank(row.source.as_deref())
            .or_else(|| non_blank(row.name.as_deref()))
            .or_else(|| non_blank(row.database.as_deref()))
            .or_else(|| non_blank(row.breach.as_deref()));
        if let Some(corpus) = corpus {
            data.breaches.push(BreachRecord {
                name: corpus.to_owned(),
                date: row.date.clone(),
                record_count: Some(1),
                detail: Some("path=osintcat".into()),
            });
        }
        if let Some(email) = non_blank(row.email.as_deref()) {
            data.emails.push(email.to_owned());
        }
        if let Some(user) = non_blank(row.username.as_deref()) {
            data.usernames.push(user.to_owned());
        }
    }
    data
}

/// A clear (unmasked) email from hudsonrock `top_logins`. **Pure.**
fn clear_email_login(login: &str) -> Option<&str> {
    let t = login.trim();
    if t.is_empty() || t.contains('*') {
        return None;
    }
    crate::canonical::canonical_email(t).map(|_| t)
}

/// Stealer hits → clear-login emails plus a `stealer:{host}` marker per named
/// host. No host name → no marker (`stealer:unknown` would be a placeholder that
/// also merged every host-less hit into one entity); the clear logins are still
/// emitted. Absent OS / IP are omitted, never written as stand-ins. **Pure.**
fn normalize_hudsonrock(stealers: &[HudsonrockStealer]) -> StolenTaxData {
    let mut data = StolenTaxData::default();
    for stealer in stealers {
        for login in &stealer.top_logins {
            if let Some(email) = clear_email_login(login) {
                data.emails.push(email.to_owned());
            }
        }
        let Some(host) = non_blank(stealer.computer_name.as_deref()) else {
            continue;
        };
        let mut detail = String::from("path=hudsonrock");
        if let Some(os) = non_blank(stealer.operating_system.as_deref()) {
            detail.push_str("; os=");
            detail.push_str(os);
        }
        if let Some(ip) = non_blank(stealer.ip.as_deref()) {
            detail.push_str("; ip=");
            detail.push_str(ip);
        }
        data.breaches.push(BreachRecord {
            name: format!("stealer:{host}"),
            date: stealer.date_compromised.clone(),
            record_count: Some(1),
            detail: Some(detail),
        });
    }
    data
}

fn credential_marker_value(name: &str) -> String {
    if name.starts_with("stealer:") || name.starts_with("breach:") {
        name.to_owned()
    } else {
        format!("breach:{name}")
    }
}

/// Evidence sentence for one marker from only the facts the provider supplied:
/// an absent record count or date is omitted, never rendered as `0` or
/// `unknown`. A fully populated record reads as before. **Pure.**
fn breach_evidence_text(name: &str, marker: &str, breach: &BreachRecord) -> String {
    let stealer = marker.starts_with("stealer:");
    let mut core: Vec<String> = Vec::new();
    if !stealer {
        if let Some(n) = breach.record_count {
            core.push(format!("records: {n}"));
        }
    }
    if let Some(date) = non_blank(breach.date.as_deref()) {
        core.push(format!("date: {date}"));
    }
    let mut parts: Vec<String> = Vec::new();
    if !core.is_empty() {
        parts.push(core.join(", "));
    }
    if let Some(detail) = non_blank(breach.detail.as_deref()) {
        parts.push(detail.to_owned());
    }
    let head = if stealer {
        format!("Stealer hit: {marker}")
    } else {
        format!("Breach: {name}")
    };
    if parts.is_empty() {
        head
    } else {
        format!("{head} ({})", parts.join("; "))
    }
}

/// Merged rows → entities. The queried identity is never re-emitted as its own
/// pivot (case-insensitive), and a restated spelling of one value mints once.
/// **Pure.**
fn build_entities(data: &StolenTaxData, query: &str, scan_id: &str) -> Vec<Entity> {
    let mut entities = Vec::new();
    let mut seen: BTreeSet<(EntityKind, String)> = BTreeSet::new();
    let query_lower = query.to_lowercase();
    let correlated = format!("Exposed in breach: correlated with {query}");

    for (kind, values) in [
        (EntityKind::Email, &data.emails),
        (EntityKind::Username, &data.usernames),
    ] {
        for value in values {
            if value.to_lowercase() == query_lower
                || !seen.insert((kind.clone(), normalise(&kind, value)))
            {
                continue;
            }
            let mut entity = Entity::new(kind.clone(), value, MEDIUM, scan_id);
            entity.add_evidence(Evidence::new(
                EvidenceProvenance::for_scan(SRC, scan_id),
                correlated.clone(),
            ));
            entities.push(entity);
        }
    }

    for breach in &data.breaches {
        let marker = credential_marker_value(&breach.name);
        let text = breach_evidence_text(&breach.name, &marker, breach);
        let mut entity = Entity::new(EntityKind::Credential, marker, HIGH, scan_id);
        entity.add_evidence(Evidence::new(
            EvidenceProvenance::for_scan(SRC, scan_id),
            text,
        ));
        entities.push(entity);
    }
    entities
}

#[cfg(test)]
mod differential;
#[cfg(test)]
mod tests;
