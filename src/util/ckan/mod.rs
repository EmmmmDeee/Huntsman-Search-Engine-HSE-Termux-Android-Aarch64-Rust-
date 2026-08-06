//! CKAN `datastore_search` response envelope + field helpers.
//!
//! Several Australian open-data registers expose their datasets through CKAN's
//! `action/datastore_search` API — `data.gov.au` (the ACNC charities register),
//! `data.qld.gov.au` (the Public Trustee unclaimed-monies register), and others
//! the charter targets. The JSON envelope and the defensive field
//! stringification are identical across every one of them (it's a fixed CKAN API
//! contract, not per-portal), so they live here once rather than being
//! re-implemented — and re-tested — in each module.

use crate::core::error::{Error, Result};
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

/// Enforce the CKAN application-error invariant on a parsed [`Response`],
/// returning the `result` set (or `None` for a genuine empty answer).
///
/// CKAN `action` endpoints return **HTTP 200 even on application errors** — a
/// bad resource id, an offline datastore, a rate-limit — signalling the failure
/// only via `success: false` in the body. `fetch_json` cannot see that (it sees
/// a 2xx with a parseable body), so without this check every one of those
/// failures collapses into an empty record set indistinguishable from a genuine
/// "no match", and a portal outage reads to the operator as a confirmed
/// negative. This is the one correctness property every CKAN caller needs, so it
/// lives here once — pure and unit-testable — rather than being re-implemented,
/// with an identical error string, in each register module (the ASIC banned /
/// business-names / persons modules, ACNC charities, and the QLD unclaimed-money
/// module all shared a verbatim copy before this was hoisted).
///
/// A `success: false` envelope becomes an [`Error::module`] tagged with the
/// caller's `module` name. `success: true` or an absent flag passes through,
/// yielding `resp.result` — `None` when the portal returned no `result` object
/// at all, which callers treat as the honest empty answer.
pub fn check_envelope(resp: Response, module: &'static str) -> Result<Option<ResultSet>> {
    if resp.success == Some(false) {
        return Err(Error::module(
            module,
            "CKAN datastore_search returned success=false (bad resource id or portal error)",
        ));
    }
    Ok(resp.result)
}

/// Fetch a CKAN `datastore_search` `url` and validate its envelope in one step:
/// [`crate::util::http::fetch_json`] (which surfaces transport / non-2xx / parse
/// failures via `?`) composed with [`check_envelope`] (which surfaces the
/// HTTP-200 `success:false` application error). Returns the matched
/// [`ResultSet`], or `None` for a genuine empty answer.
///
/// The single entry point every register module uses for its primary query, so
/// the "a CKAN failure must not masquerade as no-findings" guarantee cannot be
/// forgotten by a new caller — build the URL with [`datastore_search_url`], pass
/// it here, and the envelope is checked for you.
pub async fn validated_result(
    client: &reqwest::Client,
    module: &'static str,
    url: &str,
) -> Result<Option<ResultSet>> {
    let resp: Response = crate::util::http::fetch_json(client, module, url).await?;
    check_envelope(resp, module)
}

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
