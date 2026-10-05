//! Acquisition and caching of OFAC's two published CSV lists.
//!
//! The only part of this module that touches the network. Everything the
//! screening logic needs is a `&[SdnRecord]`, so isolating the fetch here keeps
//! [`super::crypto`], [`super::parse`], and [`super::entity`] pure and testable
//! without a HTTP fixture.

use std::sync::{LazyLock, RwLock};
use std::time::{Duration, Instant};

use crate::core::error::{Error, Result};
use crate::core::module::ModuleContext;
use crate::util::http::{RequestBuilderExt, UA_BROWSER, read_text};

use super::SRC;
use super::parse::{OfacList, SdnRecord, parse_sdn_csv};

/// OFAC's PRIMARY list — the Specially Designated Nationals (full blocking) list.
const SDN_URL: &str = "https://sanctionslistservice.ofac.treas.gov/api/download/SDN.CSV";

/// OFAC's SECOND list — the Consolidated (non-SDN) sanctions list (sectoral
/// sanctions, FSE, NS-ISA, PLC, … designations that are NOT full SDN blocking
/// but ARE sanctions). Same CSV schema as SDN.CSV (verified live), so the same
/// parser handles it. Screening against SDN alone silently missed every
/// consolidated-list designation.
pub(super) const CONS_URL: &str =
    "https://sanctionslistservice.ofac.treas.gov/api/download/CONS_PRIM.CSV";

/// The host suffix of the pre-signed S3 URL both download endpoints redirect to.
///
/// Observed live (2026-09-23): a plain `GET` of [`SDN_URL`] or [`CONS_URL`]
/// answers `302 Found` with an absolute `Location` of the shape
///
/// ```text
/// https://wc2h-sls-prod-public-published.s3.us-gov-west-1.amazonaws.com/Published/…/SDN.CSV?X-Amz-Expires=3600&…&X-Amz-Signature=…
/// ```
///
/// and that URL answers `200` `text/csv` (SDN ≈ 5.7 MB, CONS_PRIM ≈ 263 KB).
/// The signature lives in the query and is valid for an hour, so the hop has to
/// be taken fresh each time — it cannot be pinned as a constant URL.
///
/// Deliberately the AWS suffix rather than the exact bucket host: the bucket
/// and region are OFAC's operational detail and can move without notice, while
/// `amazonaws.com` is a registrable domain only AWS can issue names under. See
/// [`presigned_hop`] for why accepting any bucket there is safe.
const PRESIGNED_HOST_SUFFIX: &str = ".amazonaws.com";

/// How long the in-process parsed-list cache is trusted before a re-download.
/// OFAC updates the SDN list irregularly (typically at most a few times a
/// week), so a half-day TTL is generous headroom against staleness while
/// avoiding a multi-thousand-row re-fetch on every query. This is the
/// module's OWN raw-list cache — distinct from the engine's persisted
/// per-(module, target) entity cache (`ModuleContext`/`cache_ttl_secs`),
/// which caches the mapped *entities* for one exact target, not the shared
/// underlying list every target query filters.
pub(super) const LIST_CACHE_TTL_SECS: u64 = 12 * 60 * 60;

/// How long a failed refresh is remembered before another download is tried.
///
/// Without it every dispatch retried the whole download: a failure was never
/// recorded anywhere (only a success wrote the cache), so one scan that screened
/// six names made six multi-megabyte attempts against the same broken path and
/// logged the same error six times. Five minutes is long enough that one scan's
/// burst of dispatches shares a single attempt, and short enough that a
/// transient outage costs the operator minutes of screening, not the list TTL.
///
/// A dispatch inside the cool-down answers exactly as the failure it follows
/// did — the stale list when there is one, the honest cold-cache error when
/// there is not ([`degrade_on_fetch_failure`]) — so memoising the failure never
/// changes WHAT the operator is told, only how often OFAC is asked.
pub(super) const FAILURE_COOLDOWN_SECS: u64 = 5 * 60;

/// Timestamp + the parsed list it was fetched with.
type SdnCache = Option<(Instant, Vec<SdnRecord>)>;

/// The parsed-list cache together with the gate every refresh passes through.
///
/// A value rather than two bare statics so the refresh discipline — one
/// download at a time, failures remembered — is testable on a private instance
/// with a scripted fetch, without touching the process-global [`STORE`] or the
/// network.
#[derive(Default)]
pub(super) struct ListStore {
    /// The last list that downloaded successfully, refreshed at most once per
    /// [`LIST_CACHE_TTL_SECS`]. `Instant`-keyed (monotonic, no wall-clock skew
    /// concerns). Written only while `refresh` is held, so a holder of
    /// that lock sees a cache no other dispatch can change under it.
    cache: RwLock<SdnCache>,
    /// Single-flight gate AND failure memo: when the last refresh attempt failed
    /// (or, for one still in flight or cut off mid-download, when it began).
    /// `None` once an attempt succeeds.
    ///
    /// The one lock serialises every refresh, so a burst of concurrent
    /// dispatches on a cold cache downloads the 5.7 MB list once and the rest
    /// queue behind it (tokio's mutex is FIFO) rather than each fetching its own
    /// copy. Keeping the memo inside that lock means only the dispatch currently
    /// entitled to refresh can read or write it.
    ///
    /// An async mutex because the guard is held across the download's `.await`s.
    refresh: tokio::sync::Mutex<Option<Instant>>,
}

/// The process-global store every dispatch screens against — same
/// lazily-initialised process-global shape as `search_engines::health`'s
/// liveness-sweep cache.
static STORE: LazyLock<ListStore> = LazyLock::new(ListStore::default);

/// Whether a cached list of this age can be served without a refresh.
fn is_fresh(age: Duration) -> bool {
    age.as_secs() < LIST_CACHE_TTL_SECS
}

/// Whether a dispatch that holds the refresh gate should download the lists.
///
/// `cache_age` is the age of the cached list, `None` when there is no
/// *screenable* one ([`is_screenable`]); `since_failure` is how long ago the
/// last refresh attempt failed, `None` when the last attempt succeeded or none
/// has been made (see [`ListStore`]). Both are durations the caller measured, so
/// the decision itself reads no clock and every row of its truth table is a
/// plain unit test.
///
/// Download only when the cache cannot answer (absent, unscreenable or past the
/// TTL) AND no attempt has failed within [`FAILURE_COOLDOWN_SECS`]. A fresh
/// cache wins regardless of the memo; a cool-down suppresses the download even
/// when there is no list at all, because a retry seconds after the same failure
/// would almost certainly fail the same way and would re-download megabytes to
/// find that out.
pub(super) fn should_refetch(cache_age: Option<Duration>, since_failure: Option<Duration>) -> bool {
    let cache_answers = cache_age.is_some_and(is_fresh);
    let cooling_down = since_failure.is_some_and(|d| d.as_secs() < FAILURE_COOLDOWN_SECS);
    !cache_answers && !cooling_down
}

/// Whether a record set can actually be screened against.
///
/// The single definition of "usable screening data", consulted by every route
/// that could otherwise hand callers an empty set: the cache fast path, the
/// post-fetch parse result, and [`degrade_on_fetch_failure`]. An empty set is
/// never usable — callers find zero designations in it, which is the same answer
/// they get for a subject who is genuinely clean, so serving one turns any
/// upstream problem into a false clearance.
///
/// It exists as one predicate rather than three inline `is_empty()` checks
/// precisely so those routes cannot drift apart: the first version of this fix
/// guarded only the transport-failure route and left the other two returning
/// `Ok(vec![])`.
pub(super) fn is_screenable(records: &[SdnRecord]) -> bool {
    !records.is_empty()
}

/// Decide what a failed list download MEANS, given whatever was cached before.
///
/// A stale-but-real list is a sound degradation: OFAC publishes irregularly, so
/// screening against last night's set still answers the operator's question.
/// **No list at all is not a degradation — it is the inability to screen.**
///
/// Returning an empty record set there would make the caller emit zero hits,
/// which is byte-identical to the answer for a subject who is genuinely not
/// designated. That turns an outage into an affirmative sanctions clearance:
/// the module reports "clean" for a name it never actually checked. For a tool
/// whose output is used in engagement reporting, a false negative here is the
/// worst failure the module can produce, so it must surface as a `ModuleError`
/// and reach the operator instead.
///
/// An empty cached list is treated as no list for the same reason — a parse that
/// yielded zero rows screens exactly as blindly as no download at all.
///
/// Pure (no I/O, no cache access) so the cold-cache case is unit-testable
/// without a live OFAC endpoint — mirroring `cert_intel`'s
/// `never_answered` predicate, which encodes the same distinction.
pub(super) fn degrade_on_fetch_failure(cached: Option<Vec<SdnRecord>>) -> Result<Vec<SdnRecord>> {
    match cached {
        Some(stale) if is_screenable(&stale) => Ok(stale),
        _ => Err(Error::module(
            SRC,
            "OFAC list download failed and no list has ever been cached — cannot \
             screen. Reporting this as an error rather than an empty result, because \
             zero hits from an unloaded list is indistinguishable from a subject who \
             is genuinely not designated.",
        )),
    }
}

impl ListStore {
    /// The previous cached list (even if stale) — the degradation target when a
    /// re-download fails, so a transient outage doesn't blind screening for the
    /// TTL. `None` when nothing has ever loaded successfully.
    fn cached_list(&self) -> Option<Vec<SdnRecord>> {
        self.cache
            .read()
            .ok()
            .and_then(|g| g.as_ref().map(|(_, r)| r.clone()))
    }

    /// Age of the cached list, `None` unless there is a screenable one — the
    /// `cache_age` input of [`should_refetch`].
    fn screenable_age(&self) -> Option<Duration> {
        let guard = self.cache.read().ok()?;
        let (fetched_at, records) = guard.as_ref()?;
        is_screenable(records).then(|| fetched_at.elapsed())
    }

    /// The cached list when it can be served as-is: screenable and within TTL.
    ///
    /// The screenable check is load-bearing, not defensive noise: an empty
    /// cached set would be served straight back as a successful screen, which is
    /// the very false-clean-screen this module exists to prevent. Treating it as
    /// a miss falls through to a re-fetch, and to the error path when that also
    /// fails.
    fn fresh_list(&self) -> Option<Vec<SdnRecord>> {
        let guard = self.cache.read().ok()?;
        let (fetched_at, records) = guard.as_ref()?;
        (is_screenable(records) && is_fresh(fetched_at.elapsed())).then(|| records.clone())
    }

    /// Serve the cached list, refreshing it through `download` when
    /// [`should_refetch`] says so — at most one `download` in flight, and none
    /// within the cool-down of a failed one.
    pub(super) async fn get_or_refresh<F, Fut>(&self, download: F) -> Result<Vec<SdnRecord>>
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = Option<Vec<SdnRecord>>>,
    {
        // Lock-free fast path: a fresh cache never waits behind a refresh.
        if let Some(fresh) = self.fresh_list() {
            return Ok(fresh);
        }

        let mut last_attempt = self.refresh.lock().await;
        let since_failure = last_attempt.as_ref().map(Instant::elapsed);
        // The cache is only written under this lock, so these reads and the
        // `cached_list()` below agree with each other.
        if !should_refetch(self.screenable_age(), since_failure) {
            // Two ways here, one answer. Either the refresh this dispatch queued
            // behind has just succeeded — the cache is fresh and screenable,
            // which `degrade_on_fetch_failure` serves as-is — or a refresh
            // failed inside the cool-down, and this dispatch must answer exactly
            // as that failure did without downloading again.
            return degrade_on_fetch_failure(self.cached_list());
        }

        // Presumed failed until it succeeds. The engine enforces the module
        // timeout by DROPPING this future, so an attempt cut off mid-download
        // never reaches either arm below; stamping first means that attempt is
        // still remembered, and a list too slow to fetch inside one dispatch's
        // budget is not re-downloaded by every dispatch that follows.
        *last_attempt = Some(Instant::now());

        // An empty set is treated exactly like a failed download: caching it
        // would serve that blindness for the whole TTL.
        let Some(records) = download().await.filter(|r| is_screenable(r)) else {
            // Restart the cool-down from when the failure was observed, not from
            // when a slow attempt began.
            *last_attempt = Some(Instant::now());
            return degrade_on_fetch_failure(self.cached_list());
        };
        *last_attempt = None;
        if let Ok(mut w) = self.cache.write() {
            *w = Some((Instant::now(), records.clone()));
        }
        Ok(records)
    }
}

/// Validate a download endpoint's redirect target as OFAC's pre-signed S3 hop.
///
/// Why this module follows the hop itself: the shared client stops every
/// redirect that leaves the original request's registrable domain
/// (`util::http::ssrf::redirect_verdict`), because reqwest would replay a
/// provider's custom API-key header onto the new host. `ofac.treas.gov` →
/// `amazonaws.com` is exactly such a hop, so the client hands back the `302`
/// itself — and treating that as a failure is what left sanctions screening
/// with no list at all in production. That rule is right for the tree and is
/// not loosened here; this one module takes this one hop deliberately.
///
/// Taking it is safe because the request carries nothing to leak — the download
/// is keyless and the only header set is a browser User-Agent — and it is
/// narrowed to the one shape OFAC is observed to issue (see
/// [`PRESIGNED_HOST_SUFFIX`]). The suffix does not authenticate the list (any
/// AWS customer can own a bucket under it) and is not asked to: the hop is only
/// ever taken from a `Location` OFAC's own endpoint served over TLS, so the
/// list is exactly as trustworthy as that first response. What the checks bound
/// is where a redirect can send this request:
///
/// * **`https` only** — no downgrade of a list whose integrity the screen rests on.
/// * **A DNS name ending in `.amazonaws.com`, with a label in front of it** —
///   never an IP literal, which is where a hostile redirect would aim at
///   internal addresses; a name is resolved through the shared client's SSRF
///   resolver, which drops private answers. `amazonaws.com.evil.example`,
///   `evilamazonaws.com` and the bare apex are all refused.
/// * **No userinfo, no explicit non-default port** — neither appears in OFAC's
///   URL, and both are ways to make a URL read as one host while meaning another.
///
/// Any other `Location` — relative, another host, another scheme — is refused,
/// and the download counts as failed. `url` lowercases hosts when it parses, so
/// the suffix match is case-insensitive.
pub(super) fn presigned_hop(location: &str) -> Option<url::Url> {
    let hop = url::Url::parse(location).ok()?;
    let host_ok = match hop.host() {
        Some(url::Host::Domain(host)) => host
            .strip_suffix(PRESIGNED_HOST_SUFFIX)
            .is_some_and(|label| !label.is_empty() && !label.ends_with('.')),
        _ => false,
    };
    (hop.scheme() == "https"
        && host_ok
        && hop.username().is_empty()
        && hop.password().is_none()
        && hop.port().is_none())
    .then_some(hop)
}

/// One keyless `GET` through the shared client. `None` on a transport failure.
async fn get(ctx: &ModuleContext, url: &str) -> Option<reqwest::Response> {
    ctx.http
        .get(url)
        .header("User-Agent", UA_BROWSER)
        .send_tagged(SRC)
        .await
        .ok()
}

/// Fetch + parse ONE OFAC CSV list, taking OFAC's pre-signed S3 redirect when
/// the endpoint issues one. Returns `None` on any transport / non-2xx /
/// refused-redirect / body-read failure so the caller can decide how to degrade.
///
/// Exactly one hop, and only to a target [`presigned_hop`] accepts. The hop's
/// response goes through the same 2xx check and the same [`read_text`] body cap
/// and challenge-page check as a direct answer would, under the same shared
/// client's connect/read timeouts.
pub(super) async fn fetch_one_list(
    ctx: &ModuleContext,
    url: &str,
    list: OfacList,
) -> Option<Vec<SdnRecord>> {
    let mut resp = get(ctx, url).await?;
    if resp.status().is_redirection() {
        let hop = resp
            .headers()
            .get(reqwest::header::LOCATION)
            .and_then(|v| v.to_str().ok())
            .and_then(presigned_hop);
        let Some(hop) = hop else {
            // The Location itself is not logged: OFAC's carries a live
            // (hour-long) S3 signature and session token in its query.
            tracing::warn!(
                "{SRC}: {url} answered {} with a redirect that is not OFAC's pre-signed \
                 S3 download — not following it; this list is unavailable",
                resp.status()
            );
            return None;
        };
        resp = get(ctx, hop.as_str()).await?;
    }
    if !resp.status().is_success() {
        return None;
    }
    let body = read_text(SRC, resp).await.ok()?;
    Some(parse_sdn_csv(&body, list))
}

/// Download both lists. `None` when the primary SDN list is unavailable or
/// parses to nothing; the Consolidated list is supplementary.
async fn download_lists(ctx: &ModuleContext) -> Option<Vec<SdnRecord>> {
    // An empty SDN parse is a failure even if the Consolidated list would add
    // rows: a 2xx whose body yields zero rows — an empty response, a garbled
    // body, or OFAC changing the CSV shape under us — must not be papered over
    // by the secondary list and cached as a full screen.
    let mut records = fetch_one_list(ctx, SDN_URL, OfacList::Sdn)
        .await
        .filter(|r| is_screenable(r))?;
    // Consolidated (non-SDN / sectoral) list — same schema, supplementary. A
    // failure here is non-fatal: keep the SDN-only set rather than blocking the
    // whole screen on the secondary list.
    // Each row keeps the list it came from (`SdnRecord::list`), so a
    // consolidated-list designation is never reported as an SDN match.
    if let Some(cons) = fetch_one_list(ctx, CONS_URL, OfacList::Consolidated).await {
        records.extend(cons);
    }
    Some(records)
}

/// The combined SDN + Consolidated screening set, from cache when fresh.
///
/// `Err` means the list could not be obtained at all, so screening did not
/// happen — see [`degrade_on_fetch_failure`]. It is never used to signal "no
/// designations matched"; that is an `Ok` with a populated list the caller finds
/// no hits in.
pub(super) async fn fetch_sdn_list(ctx: &ModuleContext) -> Result<Vec<SdnRecord>> {
    STORE.get_or_refresh(|| download_lists(ctx)).await
}
