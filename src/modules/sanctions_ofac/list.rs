//! Acquisition and caching of OFAC's two published CSV lists.
//!
//! The only part of this module that touches the network. Everything the
//! screening logic needs is a `&[SdnRecord]`, so isolating the fetch here keeps
//! [`super::crypto`], [`super::parse`], and [`super::entity`] pure and testable
//! without a HTTP fixture.

use std::sync::{LazyLock, RwLock};
use std::time::Instant;

use crate::core::module::ModuleContext;
use crate::util::http::{RequestBuilderExt, UA_BROWSER, read_text};

use super::SRC;
use super::parse::{SdnRecord, parse_sdn_csv};

/// OFAC's PRIMARY list — the Specially Designated Nationals (full blocking) list.
const SDN_URL: &str = "https://sanctionslistservice.ofac.treas.gov/api/download/SDN.CSV";

/// OFAC's SECOND list — the Consolidated (non-SDN) sanctions list (sectoral
/// sanctions, FSE, NS-ISA, PLC, … designations that are NOT full SDN blocking
/// but ARE sanctions). Same CSV schema as SDN.CSV (verified live), so the same
/// parser handles it. Screening against SDN alone silently missed every
/// consolidated-list designation.
const CONS_URL: &str = "https://sanctionslistservice.ofac.treas.gov/api/download/CONS_PRIM.CSV";

/// How long the in-process parsed-list cache is trusted before a re-download.
/// OFAC updates the SDN list irregularly (typically at most a few times a
/// week), so a half-day TTL is generous headroom against staleness while
/// avoiding a multi-thousand-row re-fetch on every query. This is the
/// module's OWN raw-list cache — distinct from the engine's persisted
/// per-(module, target) entity cache (`ModuleContext`/`cache_ttl_secs`),
/// which caches the mapped *entities* for one exact target, not the shared
/// underlying list every target query filters.
const LIST_CACHE_TTL_SECS: u64 = 12 * 60 * 60;

/// Timestamp + the parsed list it was fetched with.
type SdnCache = Option<(Instant, Vec<SdnRecord>)>;

/// Process-global cache of the parsed SDN list, refreshed at most once per
/// [`LIST_CACHE_TTL_SECS`]. `Instant`-keyed (monotonic, no wall-clock skew
/// concerns) — same `LazyLock<RwLock<Option<T>>>` shape as
/// `search_engines::health`'s liveness-sweep cache.
static CACHE: LazyLock<RwLock<SdnCache>> = LazyLock::new(|| RwLock::new(None));

/// The previous cached list (even if stale) — the degradation target when a
/// re-download fails, so a transient outage doesn't blind screening for the TTL.
fn cached_or_default() -> Vec<SdnRecord> {
    CACHE
        .read()
        .ok()
        .and_then(|g| g.as_ref().map(|(_, r)| r.clone()))
        .unwrap_or_default()
}

/// Fetch + parse ONE OFAC CSV list. Returns `None` on any transport / non-2xx /
/// body-read failure so the caller can decide how to degrade.
async fn fetch_one_list(ctx: &ModuleContext, url: &str) -> Option<Vec<SdnRecord>> {
    let resp = ctx
        .http
        .get(url)
        .header("User-Agent", UA_BROWSER)
        .send_tagged(SRC)
        .await
        .ok()?;
    if !resp.status().is_success() {
        return None;
    }
    let body = read_text(SRC, resp).await.ok()?;
    Some(parse_sdn_csv(&body))
}

/// The combined SDN + Consolidated screening set, from cache when fresh.
pub(super) async fn fetch_sdn_list(ctx: &ModuleContext) -> Vec<SdnRecord> {
    if let Ok(guard) = CACHE.read()
        && let Some((fetched_at, records)) = guard.as_ref()
        && fetched_at.elapsed().as_secs() < LIST_CACHE_TTL_SECS
    {
        return records.clone();
    }

    // Primary SDN (full-blocking) list. A failure degrades to the previous
    // cached set rather than blinding screening.
    let Some(mut records) = fetch_one_list(ctx, SDN_URL).await else {
        return cached_or_default();
    };
    // Consolidated (non-SDN / sectoral) list — same schema, supplementary. A
    // failure here is non-fatal: keep the SDN-only set rather than blocking the
    // whole screen on the secondary list.
    if let Some(cons) = fetch_one_list(ctx, CONS_URL).await {
        records.extend(cons);
    }

    if let Ok(mut w) = CACHE.write() {
        *w = Some((Instant::now(), records.clone()));
    }
    records
}
