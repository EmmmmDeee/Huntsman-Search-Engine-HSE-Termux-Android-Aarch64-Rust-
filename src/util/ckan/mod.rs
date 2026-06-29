//! CKAN `datastore_search` response envelope + field helpers.
//!
//! Several Australian open-data registers expose their datasets through CKAN's
//! `action/datastore_search` API — `data.gov.au` (the ACNC charities register),
//! `data.qld.gov.au` (the Public Trustee unclaimed-monies register), and others
//! the charter targets. The JSON envelope and the defensive field
//! stringification are identical across every one of them (it's a fixed CKAN API
//! contract, not per-portal), so they live here once rather than being
//! re-implemented — and re-tested — in each module.

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

use serde::Deserialize;
use serde_json::{Map, Value};

/// The CKAN `action/datastore_search` response envelope.
///
/// CKAN action endpoints return HTTP 200 even on application errors (bad
/// resource id, datastore offline, rate-limit), signalling failure via
/// `success: false`. Both fields are captured (rather than only `result`) so a
/// caller can surface an application error instead of silently treating a
/// missing `result` as "no findings".
#[derive(Debug, Deserialize)]
pub struct Response {
    #[serde(default)]
    pub success: Option<bool>,
    #[serde(default)]
    pub result: Option<ResultSet>,
}

/// The `result` object of a [`Response`]: the matched record set plus the total
/// match count.
///
/// Records are returned with CKAN-inferred field types (text vs numeric), so
/// they are kept as raw JSON objects and read defensively via [`field_str`]
/// rather than risking a deserialize failure on a numerically-typed column
/// (an `ABN`/`Amount`/`PCode` that the datastore happens to type as a number).
#[derive(Debug, Deserialize)]
pub struct ResultSet {
    #[serde(default)]
    pub total: Option<u64>,
    #[serde(default)]
    pub records: Vec<Map<String, Value>>,
}

/// Stringify a CKAN field value (text stays as-is, numbers/bools are rendered,
/// null/missing → `None`) and trim it; empty becomes `None`.
#[must_use]
pub fn field_str(rec: &Map<String, Value>, key: &str) -> Option<String> {
    let s = match rec.get(key)? {
        Value::String(s) => s.trim().to_string(),
        Value::Null => return None,
        other => other.to_string(),
    };
    if s.is_empty() { None } else { Some(s) }
}

/// Build a CKAN `datastore_search` URL: a full-text query `q` against
/// `resource_id` on a portal's `action_base` (e.g.
/// `https://data.gov.au/data/api/3/action`), capped at `limit` rows.
///
/// `q` is url-encoded, so a query containing `&`, `=`, spaces or other
/// reserved characters can't break out of the value and inject extra query
/// parameters — the one correctness property every CKAN caller needs, kept in
/// one place.
#[must_use]
pub fn datastore_search_url(action_base: &str, resource_id: &str, q: &str, limit: usize) -> String {
    format!(
        "{action_base}/datastore_search?resource_id={resource_id}&q={}&limit={limit}",
        crate::util::http::urlencode(q)
    )
}

/// The CKAN `action/package_show` response envelope.
///
/// Used to resolve a dataset's *current* datastore-active resource id at runtime
/// rather than pinning a single id that goes stale when the publisher rotates the
/// resource each quarter (e.g. the AGOR register on `data.gov.au`).
#[derive(Debug, Deserialize)]
pub struct PackageResponse {
    #[serde(default)]
    pub success: Option<bool>,
    #[serde(default)]
    pub result: Option<Package>,
}

/// The `result` object of a [`PackageResponse`]: a dataset and its resources.
#[derive(Debug, Deserialize)]
pub struct Package {
    #[serde(default)]
    pub resources: Vec<Resource>,
}

/// One resource (file/datastore) attached to a [`Package`].
#[derive(Debug, Deserialize)]
pub struct Resource {
    #[serde(default)]
    pub id: Option<String>,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub datastore_active: Option<bool>,
}

/// Build a CKAN `package_show` URL for `dataset_id` on a portal's `action_base`.
///
/// `dataset_id` is url-encoded so a slug containing reserved characters can't
/// break out of the value.
#[must_use]
pub fn package_show_url(action_base: &str, dataset_id: &str) -> String {
    format!(
        "{action_base}/package_show?id={}",
        crate::util::http::urlencode(dataset_id)
    )
}

/// Default time-to-live (seconds) for a cached datastore-resource resolution.
///
/// `package_show` maps a stable dataset slug to the id of its *current*
/// datastore-active resource. Publishers rotate that resource on a slow cadence
/// (the AGOR / ASIC registers refresh roughly quarterly), so re-running
/// `package_show` on every scan is a wasted round-trip — and on a metered /
/// battery-bound Termux link every CKAN module otherwise spends TWO requests per
/// scan (resolve + search). Six hours is far shorter than any real rotation
/// window, so a cached id is never meaningfully stale, while a long-lived
/// `serve` / `live` process collapses the resolve step to one request per slug
/// per window.
pub const RESOURCE_TTL_SECS: u64 = 6 * 3600;

/// Process-global resolved-resource cache: dataset slug -> (resource_id, expiry).
/// `std::sync::Mutex` (matching `util::response_cache`); the critical section is
/// a single map probe/insert, never held across an `.await`, so it cannot stall
/// the reactor.
fn resource_cache() -> &'static Mutex<HashMap<String, (String, u64)>> {
    static CACHE: OnceLock<Mutex<HashMap<String, (String, u64)>>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

/// The cached current resource id for `slug`, if present and not yet expired at
/// `now` (unix seconds). A miss — absent or expired — returns `None`, so the
/// caller falls back to a live `package_show` resolve and records the result via
/// [`cache_resource`]. `now` is passed in (not read here) so this layer stays
/// free of any `core` time dependency. Lock poisoning degrades to a miss: the
/// cache is a best-effort optimisation, never a correctness dependency.
#[must_use]
pub fn cached_resource(slug: &str, now: u64) -> Option<String> {
    let guard = resource_cache().lock().ok()?;
    let (id, expiry) = guard.get(slug)?;
    (now < *expiry).then(|| id.clone())
}

/// Record `resource_id` as the current resolution for `slug`, valid for `ttl`
/// seconds from `now`. Best-effort: a poisoned lock is silently ignored (the next
/// resolve simply re-fetches). Pass [`RESOURCE_TTL_SECS`] for the default window.
pub fn cache_resource(slug: &str, resource_id: &str, now: u64, ttl: u64) {
    if let Ok(mut guard) = resource_cache().lock() {
        guard.insert(
            slug.to_string(),
            (resource_id.to_string(), now.saturating_add(ttl)),
        );
    }
}

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
