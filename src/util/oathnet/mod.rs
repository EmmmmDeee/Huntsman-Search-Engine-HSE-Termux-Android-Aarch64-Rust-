//! Shared OathNet API client — used by both oathnet_pro module and
//! search_engines enrichment pass. Lives in util/ so any module can
//! call it without violating the "no inter-module imports" invariant.

use std::collections::HashMap;

use serde::Deserialize;
use serde_json::Value;

use crate::core::error::{Error, Result};
use crate::util::budget::QuotaBudget;
use crate::util::curl_client::{AuthScheme, CurlClient};
use crate::util::response_cache::ResponseCache;

// Embedded fallback: single source of truth lives in `util::keys`.
const HARDCODED_KEY: &str = crate::util::keys::OATHNET_DEFAULT_KEY;

pub const KEY_ENV: &str = "HUNTSMAN_OATHNET_KEY";

/// Per-process response cache: deduplicates identical (path, field, value)
/// queries across modules. When oathnet_pro, geo_intel, and search_engines
/// all query `search(BREACH, "email", "x@y.com")` for the same entity,
/// only the first makes the HTTP call; subsequent modules get the cached
/// response. Empirically saves ~60% of OathNet API calls on expansion scans.
///
/// Backed by the shared [`ResponseCache`] primitive (cap 1024).
static RESPONSE_CACHE: ResponseCache<Vec<Value>> = ResponseCache::new(1024);

/// Shared curl-subprocess client. `x-api-key` auth, 12s curl timeout,
/// 15s outer tokio timeout — same calibration as the SeekNow client
/// since both providers' rate-limit responses arrive within this
/// window.
static CLIENT: CurlClient = CurlClient::new("oathnet", AuthScheme::XApiKey, 12, 15_000);

/// Per-scan + per-session quota budget for OathNet API calls.
///
/// Default 4 queries per scan (the OathNet quota is tighter than
/// SeekNow's) with a 30-query session ceiling that prevents
/// radar/live sessions from burning the daily allowance. Both caps
/// are env-tunable via `HUNTSMAN_OATHNET_SCAN_CAP` and
/// `HUNTSMAN_OATHNET_SESSION_CAP`.
static BUDGET: QuotaBudget = QuotaBudget::new(
    "oathnet",
    4,
    30,
    "HUNTSMAN_OATHNET_SCAN_CAP",
    "HUNTSMAN_OATHNET_SESSION_CAP",
);

fn cache_key(path: &str, field: &str, value: &str) -> String {
    format!("{path}:{field}:{}", value.to_lowercase())
}

fn cache_get(key: &str) -> Option<Vec<Value>> {
    RESPONSE_CACHE.get(key)
}

fn cache_put(key: String, items: &[Value]) {
    RESPONSE_CACHE.put(key, items.to_vec());
}

/// Atomically reserve one query against the OathNet budget (see
/// [`crate::util::budget::QuotaBudget::try_increment`]). Replaces the racy
/// `remaining()`-then-`increment()` gate: under `hse serve`'s concurrent scans
/// (up to `MAX_CONCURRENT_SCANS`) two scans could both pass a plain
/// `remaining()` check and then both charge, overspending the operator's *paid*
/// daily OathNet cap. The CAS in `try_increment` makes the reserve atomic, so the
/// cap holds regardless of interleaving (mirrors the `see_know` fix).
fn budget_try_increment() -> bool {
    BUDGET.try_increment()
}

/// True once the OathNet daily quota has been tripped — a quota/`402` response
/// latched it via `mark_quota_exhausted`. Callers gate on this to skip remaining
/// billable queries cleanly rather than fire them into a cap that will only reject
/// (and still bill) them.
#[must_use]
pub fn is_quota_exhausted() -> bool {
    BUDGET.is_exhausted()
}

/// Snapshot of current per-scan + per-session OathNet budget consumption.
/// Surfaced for diagnostics and `/api/v1/stats` so operators can see
/// how much of the daily allowance has been spent.
pub fn budget_snapshot() -> crate::util::budget::BudgetSnapshot {
    BUDGET.snapshot()
}

/// Reset the per-scan budget counters. Must be called at the start of every
/// scan so that `hse serve` / `hse live` (long-lived processes) get a fresh
/// budget for each scan rather than accumulating across scans.
pub fn reset_budget() {
    BUDGET.reset_scan();
}

/// True while the shared OathNet budget can absorb at least one more billable
/// query (per-scan + per-session room, quota not tripped). Public so the
/// deliberate `hse oathnet-batch --execute` runner can stop cleanly at the
/// session ceiling instead of firing calls the budget would silently drop.
pub fn has_budget() -> bool {
    BUDGET.remaining()
}

/// Lift the per-scan OathNet cap for a deliberate batch run, so the batch is
/// bounded by the per-session ceiling (the operator's daily-quota contract)
/// rather than the tight per-scan default sized for automated scans. Cleared
/// by [`reset_budget`].
pub fn set_scan_cap_override(cap: u32) {
    BUDGET.set_scan_cap_override(cap);
}

fn mark_quota_exhausted() {
    BUDGET.mark_exhausted();
    tracing::warn!("OathNet daily quota exhausted — skipping remaining queries");
}

fn base_url() -> String {
    std::env::var("HUNTSMAN_OATHNET_BASE").unwrap_or_else(|_| "https://oathnet.org/api".to_string())
}

/// The OathNet API key to use for a request: the per-scan context key `ctx_key`
/// when the operator supplied one, otherwise the built-in default
/// ([`crate::util::keys::resolve_or_default`]). Mirrors `see_know::resolve_key`.
#[must_use]
pub fn resolve_key(ctx_key: Option<&str>) -> &str {
    crate::util::keys::resolve_or_default(ctx_key, HARDCODED_KEY)
}

/// Provider-prefixed, identifiable fingerprint of the OathNet API key used for a
/// request, so every derived entity declares which key/origin returned it —
/// without persisting the full secret across the entity store. Mirrors
/// `see_know::key_fingerprint`. Pure, so it is unit-testable.
#[must_use]
pub fn key_fingerprint(key: &str) -> String {
    let k = key.trim();
    if k.is_empty() {
        return "oathnet.org:(no key)".to_string();
    }
    if k.len() <= 12 {
        return format!("oathnet.org:{k}");
    }
    let head: String = k.chars().take(8).collect();
    let tail: String = {
        let mut t: Vec<char> = k.chars().rev().take(4).collect();
        t.reverse();
        t.into_iter().collect()
    };
    format!("oathnet.org:{head}\u{2026}{tail}")
}

#[derive(Deserialize)]
struct Envelope {
    #[serde(default)]
    success: bool,
    #[serde(default)]
    data: Option<Value>,
    #[serde(default)]
    errors: Option<ErrorDetail>,
}

#[derive(Deserialize, Default)]
struct ErrorDetail {
    #[serde(default)]
    status_code: Option<u16>,
}

#[derive(Deserialize)]
struct SearchData {
    #[serde(default)]
    items: Vec<Value>,
    // A breach-search response's `data` object carries this sibling of `items`:
    // per-`dbname` metadata (HIBP-style — `BreachDate`/`Description`/`PwnCount`/
    // `Title`) for every distinct breach database the hits belong to. Previously
    // entirely unparsed (not a field on this struct, so serde silently dropped
    // it), so every oathnet-sourced breach hit's actual breach date was
    // discarded even though the response carried it. Only `BreachDate` is
    // captured for now — see the enrichment note in `search()`; `Description`/
    // `PwnCount`/`Title` are left for a future cycle to avoid scope creep.
    #[serde(default)]
    dbname_info: HashMap<String, DbMeta>,
}

#[derive(Deserialize, Default)]
struct DbMeta {
    #[serde(rename = "BreachDate", default)]
    breach_date: Option<String>,
}

/// Search a specific OathNet surface (breach, stealer, etc.) by field.
/// Returns the raw item array on success, empty vec on 404/clean miss.
/// Returns empty vec immediately if daily quota is exhausted.
/// Build the OathNet search URL. Pure (no I/O, no shared state) so the
/// session-id threading — the id is appended as `&search_id=` iff the caller
/// supplies one — is unit-testable without a live endpoint. Extracted from
/// [`search`] when the per-value session lookup moved off a process-global slot
/// (which a concurrently-running scan under `hse serve` could clobber) to an
/// explicit parameter.
fn build_search_url(
    base: &str,
    path: &str,
    field: &str,
    value: &str,
    page_size: u32,
    session_id: Option<&str>,
) -> String {
    let encoded = crate::util::http::urlencode(value);
    // sort=indexed_at:desc gives the freshest records first within
    // the page_size cap, maximising data freshness per query.
    let mut url =
        format!("{base}{path}?{field}%5B%5D={encoded}&page_size={page_size}&sort=indexed_at:desc");
    if let Some(sid) = session_id {
        url.push_str("&search_id=");
        url.push_str(&crate::util::http::urlencode(sid));
    }
    url
}

pub async fn search(
    key: &str,
    path: &str,
    field: &str,
    value: &str,
    page_size: u32,
    session_id: Option<&str>,
) -> Result<Vec<Value>> {
    let ck = cache_key(path, field, value);
    if let Some(cached) = cache_get(&ck) {
        return Ok(cached);
    }
    if is_quota_exhausted() || !budget_try_increment() {
        return Ok(Vec::new());
    }
    // A search session (when the caller initialised one for this value) lets the
    // breach + stealer queries share ONE lookup. The id is threaded in
    // explicitly — never read from shared process state — so a concurrent scan
    // under `hse serve` can't clobber which session THIS query uses.
    let url = build_search_url(&base_url(), path, field, value, page_size, session_id);
    let body = CLIENT.get(&url, key).await?;
    // Retain the paid response verbatim BEFORE parsing/extraction — operator
    // policy: purchased data is kept in absolute completeness until manually
    // deleted (see `util::raw_archive`). The endpoint label is the last two
    // path segments (e.g. `/service/v2/breach/search` → `breach-search`) and the
    // query is the looked-up value, so the saved filename names exactly what was
    // queried. The archive skips empty bodies on its own.
    let trimmed = path.trim_matches('/');
    let mut segs = trimmed.rsplit('/').take(2);
    let endpoint_label = match (segs.next(), segs.next()) {
        (Some(b), Some(a)) => format!("{a}-{b}"),
        (Some(b), None) => b.to_owned(),
        _ => trimmed.to_owned(),
    };
    crate::util::raw_archive::record("oathnet", &endpoint_label, value, &body);
    // Detect actual quota exhaustion. Earlier check used `body.contains("quota")`
    // which false-positives on legitimate metadata fields like `session_quota`
    // and `recommended_quota`. Match only true exhaustion signals.
    if body.contains("\"left_today\":0")
        || body.contains("limit exceeded")
        || body.contains("Daily quota exceeded")
        || body.contains("quota exceeded")
        || body.contains("\"is_unlimited\":false,\"left_today\":0")
    {
        mark_quota_exhausted();
        return Ok(Vec::new());
    }
    let env: Envelope =
        serde_json::from_str(&body).map_err(|e| Error::module("oathnet", e.to_string()))?;
    if !env.success {
        if env.errors.as_ref().and_then(|e| e.status_code) == Some(404) {
            // Negative-cache the clean miss so subsequent scans of the same
            // dead target don't re-spend an OathNet lookup confirming it's
            // still empty. The cache is per-process so this only affects
            // within-session re-queries.
            cache_put(ck, &[]);
            return Ok(Vec::new());
        }
        if env.errors.as_ref().and_then(|e| e.status_code) == Some(429) {
            mark_quota_exhausted();
            return Ok(Vec::new());
        }
        return Err(Error::module("oathnet", "API returned success=false"));
    }
    let data = match env.data {
        Some(d) => d,
        // Negative-cache empty data envelopes too.
        None => {
            cache_put(ck, &[]);
            return Ok(Vec::new());
        }
    };
    let sd: SearchData =
        serde_json::from_value(data).map_err(|e| Error::module("oathnet", e.to_string()))?;
    let items = enrich_with_breach_dates(sd.items, &sd.dbname_info);
    cache_put(ck, &items);
    Ok(items)
}

/// Additively stamp each row with the canonical `breach_date` its OWN `dbname`
/// entry in `dbname_info` carries, never overriding a `breach_date` a row
/// already has. Pure (no I/O), so the enrichment is unit-testable without a
/// live endpoint — extracted from [`search`].
///
/// This is the ONLY thing that lets AU-019's temporal breach-cluster rule
/// (which reads `breach_date` off breach-tagged entity evidence) see
/// oathnet-sourced hits at all: `oathnet_pro::breach::breach_evidence` forwards
/// this key straight through to the entity's evidence once present, exactly
/// like every other mapped field.
fn enrich_with_breach_dates(
    mut items: Vec<Value>,
    dbname_info: &HashMap<String, DbMeta>,
) -> Vec<Value> {
    if dbname_info.is_empty() {
        return items;
    }
    for item in &mut items {
        let Some(obj) = item.as_object() else {
            continue;
        };
        if obj.contains_key("breach_date") {
            continue;
        }
        let Some(date) = obj
            .get("dbname")
            .and_then(Value::as_str)
            .and_then(|dbname| dbname_info.get(dbname))
            .and_then(|m| m.breach_date.clone())
        else {
            continue;
        };
        // Re-borrow mutably: the lookup above held `obj` (and, via `dbname`,
        // `dbname_info`) immutably, so the owned `date` above must be resolved
        // first — an object mutation can't overlap that borrow.
        item.as_object_mut()
            .expect("already confirmed to be an object above")
            .insert("breach_date".to_string(), Value::String(date));
    }
    items
}

/// Extract a string field from a JSON Value.
// Shared JSON helpers — single definition in `util::json`, re-exported here so
// existing `crate::util::oathnet::val_str{,_or}` call sites are unchanged.
pub use crate::util::json::{val_str, val_str_coerce, val_str_or, val_str_or_coerce};

/// Count top N database names by frequency.
pub fn top_dbnames(items: &[Value], n: usize) -> Vec<String> {
    let mut counts: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    for item in items {
        if let Some(db) = val_str(item, "dbname") {
            *counts.entry(db).or_default() += 1;
        }
    }
    let mut sorted: Vec<(String, usize)> = counts.into_iter().collect();
    sorted.sort_by_key(|b| std::cmp::Reverse(b.1));
    sorted.into_iter().take(n).map(|(k, _)| k).collect()
}

/// Distinct, order-preserving non-empty values of `field` across every item in
/// `items` (empties skipped via [`val_str`]). The additive companion to
/// [`top_dbnames`]: identity attributes (country, full_name, gender, …) are
/// aggregated across ALL records so multiple hits and aliases are retained,
/// never collapsed to a single record's value by a last-write-wins overwrite.
pub fn distinct_field(items: &[Value], field: &str) -> Vec<String> {
    let mut seen = std::collections::HashSet::new();
    items
        .iter()
        .filter_map(|item| val_str(item, field))
        .filter(|v| seen.insert(v.clone()))
        .collect()
}

pub mod paths;

// ─── Query vocabulary — single source of truth ──────────────────────────────
//
// The mapping of "which corpus" (surface) and "which selector field a target
// kind searches on" is shared by the `oathnet_pro` scan module and the
// `oathnet_batch` query generator. Defining it once here keeps the two in
// lockstep — a kind added or a field renamed updates both consumers at once.

/// An OathNet search surface — the typed companion to the [`paths`] constants.
///
/// ```
/// use huntsman_search_engine::util::oathnet::{Surface, paths};
///
/// assert_eq!(Surface::Breach.label(), "breach");
/// assert_eq!(Surface::Breach.path(), paths::BREACH);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Surface {
    /// Breach corpus ([`paths::BREACH`]).
    Breach,
    /// Stealer-log corpus ([`paths::STEALER`]).
    Stealer,
}

impl Surface {
    /// The [`paths`] constant this surface dispatches against.
    #[must_use]
    pub fn path(self) -> &'static str {
        match self {
            Self::Breach => paths::BREACH,
            Self::Stealer => paths::STEALER,
        }
    }

    /// Short human/JSON label.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::Breach => "breach",
            Self::Stealer => "stealer",
        }
    }
}

/// OathNet selector field names — the single source for the wire field strings,
/// referenced by both [`selector_field`] and the batch generator's derived-query
/// logic so a selector rename can't let the seed and derived queries drift apart.
pub const FIELD_EMAIL: &str = "email";
/// OathNet `username` selector. See [`FIELD_EMAIL`].
pub const FIELD_USERNAME: &str = "username";
/// OathNet `phone` selector. See [`FIELD_EMAIL`].
pub const FIELD_PHONE: &str = "phone";
/// OathNet free-text `q` selector (used by `FullName` seeds). See [`FIELD_EMAIL`].
pub const FIELD_QUERY: &str = "q";
/// OathNet `ip` selector. See [`FIELD_EMAIL`].
pub const FIELD_IP: &str = "ip";
/// OathNet `domain` selector. See [`FIELD_EMAIL`].
pub const FIELD_DOMAIN: &str = "domain";

/// The OathNet selector field a target kind searches on, or `None` for a kind
/// OathNet does not index. The breach corpus indexes all of these; the stealer
/// corpus only those for which [`stealer_indexable`] is true.
///
/// ```
/// use huntsman_search_engine::util::oathnet::selector_field;
/// use huntsman_search_engine::core::scan::TargetKind;
///
/// assert_eq!(selector_field(TargetKind::Email), Some("email"));
/// assert_eq!(selector_field(TargetKind::FullName), Some("q"));
/// assert_eq!(selector_field(TargetKind::Url), None); // OathNet doesn't index URLs
/// ```
#[must_use]
pub fn selector_field(kind: crate::core::scan::TargetKind) -> Option<&'static str> {
    use crate::core::scan::TargetKind;
    Some(match kind {
        TargetKind::Email => FIELD_EMAIL,
        TargetKind::Username => FIELD_USERNAME,
        TargetKind::Phone => FIELD_PHONE,
        TargetKind::FullName => FIELD_QUERY,
        TargetKind::IpAddress => FIELD_IP,
        TargetKind::Domain => FIELD_DOMAIN,
        _ => return None,
    })
}

/// True for selector fields the stealer corpus indexes — it is keyed on login
/// credentials, so only `email` / `username` resolve there. Phone / name /
/// domain / IP are breach-only.
///
/// ```
/// use huntsman_search_engine::util::oathnet::stealer_indexable;
///
/// assert!(stealer_indexable("email"));
/// assert!(stealer_indexable("username"));
/// assert!(!stealer_indexable("phone")); // breach-only
/// ```
#[must_use]
pub fn stealer_indexable(field: &str) -> bool {
    matches!(field, "email" | "username")
}

/// Initialise a search session for `value`. Returns the session ID on
/// success, or None if the init call fails (non-fatal — queries still
/// work without a session, they just cost more quota).
///
/// The caller owns the returned id and threads it into [`search`] explicitly.
/// It is deliberately NOT stashed in shared process state: a single-slot global
/// (keyed only by value) was clobbered by any concurrently-running scan under
/// `hse serve`, so a scan's own query silently lost its session — costing double
/// quota — whenever another scan initialised a session in between.
pub async fn init_session(key: &str, value: &str) -> Option<String> {
    if is_quota_exhausted() {
        return None;
    }
    let url = format!("{}{}", base_url(), paths::SESSION_INIT);
    let body = format!(r#"{{"query":"{}"}}"#, value.replace('"', "\\\""));
    // Routed through the shared CurlClient — same UA / Accept /
    // auth-header layout as the GET path, just with a JSON body.
    let text = CLIENT.post_json(&url, key, &body).await.ok()?;
    let parsed: Value = serde_json::from_str(&text).ok()?;
    let sid = parsed
        .pointer("/session/id")
        .or_else(|| parsed.pointer("/data/session/id"))
        .and_then(|v| v.as_str())
        .map(str::to_string)?;
    tracing::info!(session_id = %sid, query = %value, "OathNet search session initialised");
    Some(sid)
}

// The curl-subprocess transport now lives in `util::curl_client` —
// shared with util::see_know via the per-provider `CLIENT` static
// declared at the top of this file. The `Duration` re-export below
// is no longer needed locally now that the timeout lives inside
// CurlClient.

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
