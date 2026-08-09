//! Shared OathNet API client — used by the `oathnet_pro` scan module and
//! the `oathnet-batch` CLI tool. Lives in util/ so any module can call it
//! without violating the "no inter-module imports" invariant.

use std::collections::HashMap;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};

use serde::Deserialize;
use serde_json::Value;

use crate::core::error::{Error, Result};
use crate::util::backoff::BackoffPolicy;
use crate::util::budget::QuotaBudget;
use crate::util::curl_client::{AuthScheme, CurlClient};
use crate::util::response_cache::ResponseCache;

// Embedded fallback: single source of truth lives in `util::keys`.
const HARDCODED_KEY: &str = crate::util::keys::OATHNET_DEFAULT_KEY;

/// Retry pacing for a transient OathNet HTTP 429 (distinct from true daily
/// quota exhaustion — see the inline notes in [`search`]). Mirrors
/// `see_know`'s `RATE_LIMIT_BACKOFF`: 3 attempts (initial call + 2 retries),
/// doubling 2s → 4s, capped at 8s, jittered so concurrently-dispatched
/// requests that all get rate-limited at once don't retry in lockstep.
const RATE_LIMIT_BACKOFF: BackoffPolicy = BackoffPolicy::new(3, 2_000, 8_000, true);

pub const KEY_ENV: &str = "HUNTSMAN_OATHNET_KEY";

/// Per-process response cache: deduplicates identical (path, field, value)
/// queries across modules. When oathnet_pro, geo_intel, and search_engines
/// all query `search(BREACH, "email", "x@y.com")` for the same entity,
/// only the first makes the HTTP call; subsequent modules get the cached
/// response. Empirically saves ~60% of OathNet API calls on expansion scans.
///
/// Backed by the shared [`ResponseCache`] primitive (cap 1024).
static RESPONSE_CACHE: ResponseCache<SearchResult> = ResponseCache::new(1024);

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

/// Whether an enumeration returned the whole answer — and if not, what stopped
/// it.
///
/// Pagination has six exits and five of them can leave the item set short, and
/// two further exits refuse the query at the door before a single request is
/// made. Every one used to return a bare `Vec<Value>` indistinguishable from a
/// complete result, so a dossier built on a truncated sweep reported N findings
/// with nothing saying more existed. Only the budget exit said anything at all,
/// and only to the log.
///
/// The causes are kept apart rather than collapsed into one `truncated: bool`
/// because an operator acts on them differently: raise the scan cap (which
/// spends money), wait for the daily quota to reset, retry after a rate limit,
/// or report a provider that advertises more pages without a cursor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Completeness {
    /// The provider reported no further pages. This is the whole answer.
    Complete,
    /// The operator's own scan/session budget stopped the query — either
    /// mid-pagination with more pages available, or at the door before a single
    /// request was made. The cap is a paid-quota spending guard and is working
    /// as intended — the defect was never disclosing that it bit.
    BudgetExhausted,
    /// The provider's daily paid quota is spent: either it ran out
    /// mid-enumeration (`left_today: 0`), or it was already latched before this
    /// query was attempted.
    QuotaExhausted,
    /// Rate-limited with no retries left, mid-enumeration.
    RateLimited,
    /// The provider reported `has_more` but supplied no cursor to continue.
    CursorMissing,
    /// A page *after* the first returned 404. Earlier pages are real; the rest
    /// is unknown. A first-page 404 is a genuine empty result, not this.
    PageVanished,
}

impl Completeness {
    /// True when the item set is real but short of the full answer.
    #[must_use]
    pub fn is_partial(self) -> bool {
        !matches!(self, Self::Complete)
    }

    /// Stable tag for evidence attributes and logs; `None` when complete.
    #[must_use]
    pub fn reason(self) -> Option<&'static str> {
        match self {
            Self::Complete => None,
            Self::BudgetExhausted => Some("scan/session budget exhausted"),
            Self::QuotaExhausted => Some("provider daily quota exhausted"),
            Self::RateLimited => Some("rate-limited, retries exhausted"),
            Self::CursorMissing => Some("provider reported more pages but gave no cursor"),
            Self::PageVanished => Some("a page after the first returned 404"),
        }
    }
}

/// A page-set plus whether it is the whole answer.
///
/// Cached as a unit, deliberately: the truncation has to survive a cache hit or
/// the second caller for the same `(path, field, value)` is told a partial set
/// is complete — which is what happened before, since `cache_put` ran on every
/// exit including the truncating ones.
#[derive(Debug, Clone)]
pub struct SearchResult {
    pub items: Vec<Value>,
    pub completeness: Completeness,
}

impl SearchResult {
    fn new(items: Vec<Value>, completeness: Completeness) -> Self {
        Self {
            items,
            completeness,
        }
    }
}

fn cache_key(path: &str, field: &str, value: &str) -> String {
    format!("{path}:{field}:{}", value.to_lowercase())
}

fn cache_get(key: &str) -> Option<SearchResult> {
    RESPONSE_CACHE.get(key)
}

/// Cache the page-set WITH its completeness, so a hit reports the same truth the
/// original call did.
fn cache_put(key: String, items: Vec<Value>, completeness: Completeness) -> SearchResult {
    // Takes the vec by value so callers move `all_items` in: the cache needs one
    // copy and the caller needs one, and the previous `&[Value]` signature forced
    // `to_vec()` on top of that clone — two deep copies of a page set that can
    // run to thousands of breach rows, on every cache write.
    let res = SearchResult::new(items, completeness);
    RESPONSE_CACHE.put(key, res.clone());
    res
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

/// The account's real, provider-reported daily quota state — distinct from
/// [`budget_snapshot`], which is HSE's own self-imposed per-scan/per-session
/// spending cap. Every OathNet search response carries this for free (a
/// top-level `_meta.lookups` block, live-confirmed 2026-07-15 — see
/// [`Envelope`]'s doc comment), so capturing it costs nothing beyond a
/// search HSE was already making. Before this existed, the only quota
/// signal anywhere was a binary "hit exactly 0" latch
/// ([`is_quota_exhausted`]) — the documented best practice ("Monitor
/// `left_today` after every response. Stop gracefully when quota is low",
/// `docs/OATHNET_API_GUIDE.txt` §14.1.4) had no code path to follow at
/// all: there was nothing tracking the actual remaining count, only
/// whether it had already hit zero.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RealQuota {
    pub used_today: u32,
    pub left_today: u32,
    pub daily_limit: Option<u32>,
    pub is_unlimited: bool,
}

/// Last real quota snapshot observed from a live response this process.
/// `None` until the first successful search response carries a `_meta`
/// block — no dedicated probe call is ever made purely to populate this
/// (that would spend a lookup on a meta-query for a provider whose docs
/// don't even list a free account-status endpoint), matching the same
/// "monitor passively, never spend quota just to check quota" discipline
/// `see_know::query_credits` uses its own dedicated free endpoint for.
static LAST_REAL_QUOTA: Mutex<Option<RealQuota>> = Mutex::new(None);

/// Extract [`RealQuota`] from a parsed envelope's top-level `_meta` block,
/// if present. Pure — no global state touched — so the extraction logic is
/// unit-testable directly against a captured response shape.
fn real_quota_from_envelope(env: &Envelope) -> Option<RealQuota> {
    let lookups = env.top_meta.as_ref()?.lookups.as_ref()?;
    Some(RealQuota {
        used_today: lookups.used_today.unwrap_or_default(),
        left_today: lookups.left_today?,
        daily_limit: lookups.daily_limit,
        is_unlimited: lookups.is_unlimited.unwrap_or_default(),
    })
}

/// True when a parsed envelope's real quota meter shows a spent daily
/// allowance — a metered (non-unlimited) account whose `left_today` has
/// reached zero.
///
/// Read from the TYPED `_meta.lookups` block ([`real_quota_from_envelope`]),
/// never a raw-body substring. The former `body.contains("\"left_today\":0")`
/// guard ran BEFORE the body was parsed and the page accumulated, so the day's
/// final SUCCESSFUL page — which carries its data AND `left_today:0` in the
/// same body, because `used_today` counts the current call
/// (`docs/OATHNET_API_GUIDE.txt`: `used_today:13 + left_today:487 =
/// daily_limit:500`) — had its paid records silently dropped. It also
/// false-latched on an unlimited account that happened to report
/// `left_today:0`. Driving the latch off the typed meter fixes both: the
/// `is_unlimited` guard excludes unlimited accounts, and the caller acts on
/// this only AFTER accumulating a successful page — mirroring the sibling
/// [`crate::util::see_know`] `credits_exhausted` discipline (exhaustion latches
/// to stop LATER queries, but the data of the call that spent the last credit
/// is still returned).
fn envelope_quota_exhausted(env: &Envelope) -> bool {
    real_quota_from_envelope(env).is_some_and(|q| !q.is_unlimited && q.left_today == 0)
}

/// Record a freshly-observed [`RealQuota`], overwriting whatever was
/// captured before — the newest response is always the most accurate.
fn record_real_quota(q: RealQuota) {
    if let Ok(mut guard) = LAST_REAL_QUOTA.lock() {
        *guard = Some(q);
    }
}

/// The most recent real quota state observed from a live OathNet response
/// this process, if any search has succeeded yet. Surfaced to `hse doctor`
/// and the web UI's Key Harvest account-health card so an operator can see
/// the ACTUAL remaining daily balance, not just HSE's own self-imposed
/// scan/session spending cap.
#[must_use]
pub fn real_quota() -> Option<RealQuota> {
    LAST_REAL_QUOTA.lock().ok().and_then(|g| *g)
}

/// Reset the per-scan budget counters. Must be called at the start of every
/// scan so that `hse serve` / `hse live` (long-lived processes) get a fresh
/// budget for each scan rather than accumulating across scans.
///
/// Also clears [`RESPONSE_CACHE`]: it exists to dedup identical
/// `(path, field, value)` queries *within one scan* across oathnet_pro,
/// geo_intel, and search_engines (see its own doc comment) — but with no
/// scan-boundary reset, a long-lived `hse serve`/`hse live` process would
/// silently keep returning the first scan's cached breach/stealer records
/// for every later re-scan of the same email/username/phone, indefinitely,
/// with no live re-check and no way for the operator to force a refresh.
pub fn reset_budget() {
    BUDGET.reset_scan();
    RESPONSE_CACHE.clear();
    // Per-scan, exactly like the quota latch `reset_scan` clears: a rate limit
    // one scan hit must not bench the provider for every later scan in a
    // long-lived `hse serve`/`hse live` process.
    RATE_LIMITED.store(false, Ordering::Release);
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

/// Set when a 429 outlived its retry budget, so the *reason* the module stopped
/// survives alongside the stop itself.
///
/// The 429 path latches `mark_quota_exhausted()` deliberately — a persistent
/// rate limit must stop the scan firing at OathNet rather than retry forever —
/// but that latch is the *daily quota* signal, and reusing it made a burst rate
/// limit indistinguishable from a spent daily allowance everywhere the latch is
/// read: the door guard in [`search`], and `"quota_exhausted"` in
/// `api::key_harvest_handlers`. The two need opposite operator responses —
/// retry shortly vs. wait for the daily reset, possibly hours — so reporting
/// the wrong one is exactly the misdirection [`Completeness`] exists to remove.
///
/// This records the cause without touching the stop: the quota latch is still
/// set, so every existing gate behaves precisely as before. Cleared by
/// [`reset_budget`] at the scan boundary, like the rest of the per-scan state.
static RATE_LIMITED: AtomicBool = AtomicBool::new(false);

fn mark_quota_exhausted() {
    BUDGET.mark_exhausted();
    tracing::warn!("OathNet daily quota exhausted — skipping remaining queries");
}

/// Latch that the stop came from a rate limit, not a spent daily quota.
fn mark_rate_limited() {
    RATE_LIMITED.store(true, Ordering::Release);
    tracing::warn!("OathNet rate-limited with retries exhausted — skipping remaining queries");
}

/// True when this scan stopped querying OathNet because of a persistent 429.
fn is_rate_limited() -> bool {
    RATE_LIMITED.load(Ordering::Acquire)
}

fn base_url() -> String {
    // Vet the operator's override: refuse non-https / private-host redirects and
    // WARN on a divergent host, so a key-bearing request can't be silently
    // redirected to a look-alike or internal address. See
    // [`crate::util::endpoint_override`].
    crate::util::endpoint_override::resolve("HUNTSMAN_OATHNET_BASE", "https://oathnet.org/api")
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
    // Shared implementation in `util::key_fingerprint`; this fixes OathNet's
    // label and truncation widths (show ≤12-byte keys whole, else 8…4).
    crate::util::key_fingerprint::fingerprint("oathnet.org", key, 12, 8, 4)
}

#[derive(Deserialize)]
struct Envelope {
    #[serde(default)]
    success: bool,
    #[serde(default)]
    data: Option<Value>,
    #[serde(default)]
    errors: Option<ErrorDetail>,
    /// Live-confirmed (2026-07-15): a TOP-LEVEL sibling of `data`, not
    /// nested inside it — see [`SearchData`]'s own doc comment for the
    /// same "the doc's illustrative example nests things differently to
    /// reality" story on the pagination fields. Carries the account's
    /// real quota state on every successful response, at zero extra
    /// query cost — see [`RealQuota`].
    #[serde(default, rename = "_meta")]
    top_meta: Option<TopMeta>,
}

#[derive(Deserialize, Default)]
struct TopMeta {
    #[serde(default)]
    lookups: Option<Lookups>,
}

#[derive(Deserialize, Default)]
struct Lookups {
    #[serde(default)]
    used_today: Option<u32>,
    #[serde(default)]
    left_today: Option<u32>,
    #[serde(default)]
    daily_limit: Option<u32>,
    #[serde(default)]
    is_unlimited: Option<bool>,
}

#[derive(Deserialize, Default)]
struct ErrorDetail {
    #[serde(default)]
    status_code: Option<u16>,
}

/// Resolve the effective HTTP status for classifying an unsuccessful
/// `search()` response: prefer the API's own `errors.status_code` (when
/// present and nonzero — a `0` there is not a real status) over the
/// transport-layer status, since the body's code may be more specific; but
/// FALL BACK to the real HTTP status curl observed when the body doesn't
/// provide one at all.
///
/// Previously `env.errors.status_code` was the ONLY signal available, via
/// the status-discarding `CurlClient::get`. A genuine 404/429/5xx response
/// whose body didn't happen to carry a matching `errors.status_code` field
/// (a differently-shaped error body, a gateway/proxy response ahead of the
/// real API) had no way to be classified at all and fell straight through
/// to the generic `Err("API returned success=false")` at the end of the
/// branch — discarding any results already accumulated from earlier,
/// successful pages of the SAME paginated query. `get_with_status` gives an
/// independent, always-available signal that can't be silently absent the
/// way the body's own field can.
fn effective_error_status(body_status: Option<u16>, http_status: u16) -> u16 {
    body_status.filter(|&c| c != 0).unwrap_or(http_status)
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
    /// Live-confirmed (2026-07-15) against the real
    /// `GET /service/v2/breach/search`: this block is keyed `"meta"`, NOT
    /// `"_meta"` as `docs/OATHNET_API_GUIDE.txt` §3.1's illustrative example
    /// shows — the real quota block (`user`/`lookups`/`service`/
    /// `performance`) is what actually lives at a TOP-LEVEL `_meta`, a
    /// sibling of `data` itself, not nested inside it. `alias = "_meta"` is
    /// kept as a defensive fallback in case some other surface (stealer,
    /// victims) or a future response variant genuinely does nest it there —
    /// this was only directly observed for breach search. Before this fix,
    /// `#[serde(rename = "_meta")]` meant this field NEVER matched the real
    /// key, so `meta` silently deserialized to `None` on every real
    /// response and pagination past page 1 could never fire — the actual
    /// cause of a real GitHub-observed-class bug: T2.151's "implemented
    /// real cursor-based pagination" compiled clean and passed its own unit
    /// tests (which used the same wrong `_meta`-shaped fixture the doc
    /// implies), but was structurally inert against the live API the whole
    /// time.
    #[serde(default, alias = "_meta")]
    meta: Option<PageMeta>,
    /// Live-confirmed (2026-07-15): the continuation cursor is a SIBLING of
    /// `meta`, directly under `data` — not nested inside the meta/`_meta`
    /// block as the doc's §3.1 example implies. Checked first;
    /// `PageMeta::next_cursor` is kept as a defensive fallback for a
    /// response shape that nests it there instead (see [`PageMeta`]).
    #[serde(default)]
    next_cursor: Option<String>,
}

#[derive(Deserialize, Default)]
struct DbMeta {
    #[serde(rename = "BreachDate", default)]
    breach_date: Option<String>,
}

/// Pagination signal from the response envelope's `data` block
/// (`docs/OATHNET_API_GUIDE.txt` §3.1/§11 — see [`SearchData`]'s doc
/// comment for the live-confirmed real key names, which differ from this
/// doc's own illustrative example). OathNet uses cursor-based pagination —
/// no offset/page-number support — so `next_cursor` is the only way to
/// fetch the rest of a result set once `has_more` is true.
#[derive(Deserialize, Default)]
struct PageMeta {
    #[serde(default)]
    has_more: bool,
    /// Defensive fallback location only — the real, live-confirmed location
    /// is [`SearchData::next_cursor`], a sibling of this block, not nested
    /// inside it.
    #[serde(default)]
    next_cursor: Option<String>,
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
) -> Result<SearchResult> {
    let ck = cache_key(path, field, value);
    if let Some(cached) = cache_get(&ck) {
        return Ok(cached);
    }
    // Split deliberately. Both arms return zero rows, but neither is a
    // finding: no query was made, so nothing was established about this target.
    // Reporting `Complete` here would have made "we were not allowed to ask"
    // indistinguishable from "we asked and there is nothing" — the exact
    // conflation this type exists to remove, one guard earlier than the
    // pagination exits it was written for.
    // Checked BEFORE the quota latch, because the 429 path sets both: the quota
    // latch to stop, this one to say why. Reading the quota latch first would
    // report every post-rate-limit refusal as a spent daily allowance.
    if is_rate_limited() {
        return Ok(SearchResult::new(Vec::new(), Completeness::RateLimited));
    }
    if is_quota_exhausted() {
        return Ok(SearchResult::new(Vec::new(), Completeness::QuotaExhausted));
    }
    if !budget_try_increment() {
        return Ok(SearchResult::new(Vec::new(), Completeness::BudgetExhausted));
    }
    // A search session (when the caller initialised one for this value) lets the
    // breach + stealer queries share ONE lookup. The id is threaded in
    // explicitly — never read from shared process state — so a concurrent scan
    // under `hse serve` can't clobber which session THIS query uses.
    //
    // OathNet uses cursor-based pagination (`docs/OATHNET_API_GUIDE.txt` §11:
    // "No offset/page-number support... Read next_cursor... Repeat until
    // cursor is null"), not offset/page-number — the operator directive is to
    // always fetch the entire content of a batch query's results, so a
    // `has_more:true` response now keeps paging rather than silently
    // returning only the first page. The docs also state each page is billed
    // as its own lookup ("Each API call deducts one lookup"), so every
    // subsequent page is gated behind the same [`budget_try_increment`] check
    // as the first — pagination stops (not errors) the moment the operator's
    // own scan/session budget is exhausted, exactly like a single-page query
    // already would, rather than a separately invented page-count cap.
    let mut all_items: Vec<Value> = Vec::new();
    // Set by whichever exit stops pagination short; the loop's normal end
    // leaves it `Complete`.
    let mut completeness = Completeness::Complete;
    let mut cursor: Option<String> = None;
    loop {
        // Do NOT change filters between pages (the cursor is bound to the
        // original query per the API's own rules) — field/value/page_size/
        // sort/search_id stay identical across every page; only `cursor`
        // (absent on the first request) changes.
        let mut url = build_search_url(&base_url(), path, field, value, page_size, session_id);
        if let Some(c) = &cursor {
            url.push_str("&cursor=");
            url.push_str(&crate::util::http::urlencode(c));
        }

        // A genuine 429 is a transient burst rate-limit — the key still has
        // credits, the request was simply too fast — DISTINCT from true
        // exhaustion (`"left_today":0`). Diagnosed as a real bug: a 429 used to
        // be classified identically to true exhaustion, immediately latching
        // `mark_quota_exhausted()` and abandoning OathNet for the rest of the
        // scan with zero backoff. Retry with exponential backoff instead; only
        // latch exhaustion if backoff attempts run out, so a persistent 429
        // still degrades exactly as before rather than retrying forever.
        let mut attempt = 0u32;
        let (sd, quota_exhausted): (SearchData, bool) = loop {
            let (body, http_status) = CLIENT.get_with_status(&url, key).await?;
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
            let env: Envelope =
                serde_json::from_str(&body).map_err(|e| Error::module("oathnet", e.to_string()))?;
            // Record real quota state regardless of success/failure — a
            // quota-exhausted 403 carries this block too, and that's
            // exactly the moment an operator most wants to see the real
            // left_today rather than just "something failed".
            if let Some(q) = real_quota_from_envelope(&env) {
                record_real_quota(q);
            }
            // Detect true daily-quota exhaustion from the TYPED `_meta.lookups`
            // meter — NOT a raw-body substring. The former
            // `body.contains("\"left_today\":0")` check ran BEFORE the page was
            // parsed and accumulated, silently discarding the day's final
            // SUCCESSFUL page (which carries its data AND `left_today:0` in the
            // same body). Compute the latch here but ACT on it only after the
            // page is accumulated (the success path, below the retry loop) or
            // when the body is a genuine non-success exhaustion (403, below).
            // See [`envelope_quota_exhausted`].
            let quota_exhausted = envelope_quota_exhausted(&env);
            if !env.success {
                let code = effective_error_status(
                    env.errors.as_ref().and_then(|e| e.status_code),
                    http_status,
                );
                if code == 404 {
                    // Negative-cache the clean miss so subsequent scans of the same
                    // dead target don't re-spend an OathNet lookup confirming it's
                    // still empty. The cache is per-process so this only affects
                    // within-session re-queries. Only a true first-page 404 negative-
                    // caches an empty result; a 404 on a later page still returns
                    // whatever earlier pages already accumulated.
                    // A FIRST-page 404 is a genuine empty result and is
                    // negative-cached as complete. A 404 on a later page means
                    // earlier pages are real and the remainder is unknown.
                    let completeness = if all_items.is_empty() {
                        Completeness::Complete
                    } else {
                        Completeness::PageVanished
                    };
                    return Ok(cache_put(ck, all_items, completeness));
                }
                if code == 429 {
                    if !RATE_LIMIT_BACKOFF.should_retry(attempt) {
                        // Both latches: `mark_quota_exhausted` is what actually
                        // stops the scan re-firing at OathNet (every existing
                        // gate reads it, unchanged), while `mark_rate_limited`
                        // records that a 429 — not a spent daily allowance —
                        // is why. Without the second, this call correctly
                        // reports `RateLimited` and then every LATER query in
                        // the scan is refused at the door as `QuotaExhausted`,
                        // telling the operator to wait hours for a reset that
                        // was never the problem.
                        mark_quota_exhausted();
                        mark_rate_limited();
                        return Ok(cache_put(ck, all_items, Completeness::RateLimited));
                    }
                    let delay = RATE_LIMIT_BACKOFF.delay(attempt);
                    tracing::debug!(
                        path,
                        attempt = attempt + 1,
                        delay_ms = delay.as_millis() as u64,
                        "oathnet 429 rate-limited — backing off"
                    );
                    tokio::time::sleep(delay).await;
                    attempt += 1;
                    continue;
                }
                // `docs/OATHNET_API_GUIDE.txt` §13: "5xx: retry up to 3
                // times with exponential backoff (2s, 4s, 8s)" — identical
                // numbers to `RATE_LIMIT_BACKOFF`, reused rather than
                // duplicated. Previously ANY status other than 404/429
                // (including every 5xx) fell straight to the generic,
                // unretried `Err` below — a transient server error got no
                // retry at all despite the documented policy, and the
                // module `Err`'d out of pagination on what might have been
                // a one-off blip. After retries are exhausted, still
                // return `Err` (not `Ok(all_items)`) — a persistent 5xx is
                // a real failure signal, not a clean "no more pages" or a
                // quota condition, and must not be silently absorbed as
                // either.
                // Status 0 means curl reported no HTTP response at all (a
                // connection reset after connect) — transient in the same
                // way a 5xx is, per `CurlClient::get_with_status`'s doc, so
                // it shares the same retry-then-fail treatment.
                if code == 0 || (500..600).contains(&code) {
                    if RATE_LIMIT_BACKOFF.should_retry(attempt) {
                        let delay = RATE_LIMIT_BACKOFF.delay(attempt);
                        tracing::debug!(
                            path,
                            attempt = attempt + 1,
                            delay_ms = delay.as_millis() as u64,
                            status = code,
                            "oathnet server error — retrying with backoff"
                        );
                        tokio::time::sleep(delay).await;
                        attempt += 1;
                        continue;
                    }
                    return Err(Error::module(
                        "oathnet",
                        format!("HTTP {code} after {attempt} retries"),
                    ));
                }
                // A genuine non-success exhaustion body (HTTP 403 "You have
                // reached your daily lookup limit") that carries the real
                // `left_today:0` meter: latch and return whatever earlier pages
                // accumulated — exactly what the old raw-body check did for this
                // case, now driven off the typed meter so it cannot fire on a
                // successful page's payload text.
                if quota_exhausted {
                    mark_quota_exhausted();
                    return Ok(cache_put(ck, all_items, Completeness::QuotaExhausted));
                }
                return Err(Error::module("oathnet", "API returned success=false"));
            }
            let data = match env.data {
                Some(d) => d,
                // Negative-cache empty data envelopes too (first page only).
                None => {
                    // The provider returned an envelope with no data block: it
                    // has nothing further, so this IS the whole answer.
                    return Ok(cache_put(ck, all_items, Completeness::Complete));
                }
            };
            break (
                serde_json::from_value(data)
                    .map_err(|e| Error::module("oathnet", e.to_string()))?,
                quota_exhausted,
            );
        };

        // Enrich each page against its OWN `dbname_info` block before
        // accumulating — different pages of the same paginated query can
        // legitimately carry different sets of breach databases.
        all_items.extend(enrich_with_breach_dates(sd.items, &sd.dbname_info));

        // This page SUCCEEDED and spent the account's last daily credit
        // (`left_today:0` on a metered account). KEEP the page — it is paid data
        // the old raw-body pre-parse check discarded — but latch exhaustion so
        // LATER queries in this scan are refused at the door, and stop paging.
        if quota_exhausted {
            mark_quota_exhausted();
            completeness = Completeness::QuotaExhausted;
            break;
        }

        let has_more = sd.meta.as_ref().is_some_and(|m| m.has_more);
        // Prefer the live-confirmed real location (`data.next_cursor`,
        // sibling of `meta`); fall back to the nested `meta.next_cursor`
        // location for a response shape that puts it there instead.
        let next_cursor = sd
            .next_cursor
            .or_else(|| sd.meta.and_then(|m| m.next_cursor));
        let Some(next) = continuation_cursor(has_more, next_cursor) else {
            if has_more {
                // Server says more exist but gave no cursor to continue —
                // nothing more this call can do. The item set is short and the
                // caller has to be told, not just the log.
                completeness = Completeness::CursorMissing;
                tracing::debug!(
                    path,
                    fetched = all_items.len(),
                    "oathnet reported has_more with no next_cursor — stopping"
                );
            }
            break;
        };
        // Only reserve budget for a page that will actually be fetched —
        // checked here, not earlier, so a `has_more`-but-no-cursor stop
        // above never wastes a reservation on a page that wasn't going to
        // happen anyway.
        if !budget_try_increment() {
            // Budget exhausted mid-pagination: return what was genuinely
            // fetched rather than erroring, but say so — this is real,
            // honest partial data, not a silent truncation dressed up as
            // complete.
            completeness = Completeness::BudgetExhausted;
            tracing::debug!(
                path,
                fetched = all_items.len(),
                "oathnet pagination stopped: scan/session budget exhausted with more pages available"
            );
            break;
        }
        cursor = Some(next);
    }

    Ok(cache_put(ck, all_items, completeness))
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

/// Whether OathNet's cursor-based pagination should continue, and with
/// which cursor: only when the page's own `_meta` says more results exist
/// AND it actually supplied a cursor to fetch them with. Pure — extracted
/// from [`search`]'s I/O loop so this two-part requirement is unit-testable
/// without a live HTTP round-trip.
fn continuation_cursor(has_more: bool, next_cursor: Option<String>) -> Option<String> {
    if has_more { next_cursor } else { None }
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
    // Count descending, then dbname ascending as a deterministic tie-break.
    // `counts` came from a `HashMap`, so its pre-sort order (and therefore
    // which of several equal-count names lands inside the top-`n` cutoff) is
    // process-random without the second key — the same reproducibility class
    // already closed elsewhere in this codebase (`recall_prior_entities`,
    // `wigle::mode`). This feeds both the operator-facing "OathNet: N
    // matching breach record(s) … — {top_dbs}" headline and the AU-047
    // reused-secret correlator's `distinct_sources` reader, so a tied 5th/6th
    // dbname flipping in or out of the result between identical re-runs of
    // the identical scan is a real, not cosmetic, non-determinism.
    sorted.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
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

    /// The documented per-request page-size ceiling for this surface
    /// (`docs/OATHNET_API_GUIDE.txt` §11: Breach Search max 1000, V2
    /// Stealer max 100 — they differ). A caller-supplied page_size should
    /// be clamped to this, not passed through uncapped: a batch plan that
    /// spans both surfaces with one shared page_size value would otherwise
    /// risk sending an over-limit request to whichever surface has the
    /// smaller ceiling.
    #[must_use]
    pub fn max_page_size(self) -> u32 {
        match self {
            Self::Breach => 1000,
            Self::Stealer => 100,
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

/// Build the JSON body for the session-init POST. Serialised via `serde_json`
/// so `value` is escaped correctly — a hand-rolled `replace('"', ...)` escaped
/// only double-quotes, so a value containing a backslash produced invalid JSON
/// (silent session-init failure) and a literal `\n`/`\t` decoded to a real
/// control char rather than being escaped. Pure, so the escaping is unit-tested
/// without a live POST.
fn session_init_body(value: &str) -> String {
    serde_json::json!({ "query": value }).to_string()
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
    let body = session_init_body(value);
    // Routed through the shared CurlClient — same UA / Accept /
    // auth-header layout as the GET path, just with a JSON body.
    let text = CLIENT.post_json(&url, key, &body).await.ok()?;
    let parsed: Value = serde_json::from_str(&text).ok()?;
    let sid = parsed
        .pointer("/session/id")
        .or_else(|| parsed.pointer("/data/session/id"))
        .and_then(|v| v.as_str())
        .map(str::to_string)?;
    // `debug!`, not `info!`: `value` is the raw scan target (email / username /
    // phone = PII). Every other target-bearing detail in the system lives at the
    // debug/trace "raw logs" tier so `RUST_LOG=info` never surfaces the subject's
    // identifier; this line must not be the one exception that leaks it at info.
    tracing::debug!(session_id = %sid, query = %value, "OathNet search session initialised");
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
