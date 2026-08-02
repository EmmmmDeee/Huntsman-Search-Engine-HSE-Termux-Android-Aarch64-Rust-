//! CKAN `datastore_search` response envelope + field helpers.
//!
//! Several Australian open-data registers expose their datasets through CKAN's
//! `action/datastore_search` API — `data.gov.au` (the ACNC charities register),
//! `data.qld.gov.au` (the Public Trustee unclaimed-monies register), and others
//! the charter targets. The JSON envelope and the defensive field
//! stringification are identical across every one of them (it's a fixed CKAN API
//! contract, not per-portal), so they live here once rather than being
//! re-implemented — and re-tested — in each module.

use serde::Deserialize;
use serde_json::{Map, Value};

use crate::core::error::{Error, Result};

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
#[derive(Debug, Default, Deserialize)]
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

/// Lower-cased alphanumeric name tokens (≥2 chars) of a free-text name — the
/// tokenization [`asic_banned_orgs`](crate::modules::asic_banned_orgs) and
/// [`asic_business_names`](crate::modules::asic_business_names) both split a
/// CKAN record's org/business name field into for order-independent
/// substring matching (`tokens.iter().all(|t| lower.contains(t))`). Digits
/// are kept (unlike a person-name tokenizer) since an organisation/business
/// name routinely carries one (`7-Eleven`, `ABC123 Pty Ltd`).
#[must_use]
pub fn name_tokens(name: &str) -> Vec<String> {
    name.split(|c: char| !c.is_alphanumeric())
        .filter(|t| t.len() >= 2)
        .map(str::to_ascii_lowercase)
        .collect()
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

/// Fetch and validate one CKAN `datastore_search` query: builds the URL via
/// [`datastore_search_url`], performs the request, and surfaces an
/// application-level `success: false` envelope (CKAN's own "bad resource id
/// / datastore offline / rate-limit" signal, returned with HTTP 200) as an
/// [`Error::module`] — every real failure now surfaces instead of collapsing
/// into an empty result indistinguishable from a genuine "no findings".
/// A response that carries no `result` field at all is the honest empty
/// case and resolves to a default (empty) [`ResultSet`], not an error.
///
/// Shared by every CKAN-backed module (`acnc_charities`, `asic_persons`,
/// `asic_banned_orgs`, `asic_business_names`, `au_unclaimed`'s QLD path) —
/// each previously re-implemented this identical fetch-validate-unwrap
/// sequence, only the portal/resource/query differing.
pub async fn datastore_search(
    client: &reqwest::Client,
    action_base: &str,
    resource_id: &str,
    q: &str,
    limit: usize,
    src: &'static str,
) -> Result<ResultSet> {
    let url = datastore_search_url(action_base, resource_id, q, limit);
    let resp: Response = crate::util::http::fetch_json(client, src, &url).await?;
    if resp.success == Some(false) {
        return Err(Error::module(
            src,
            "CKAN datastore_search returned success=false (bad resource id or portal error)",
        ));
    }
    Ok(resp.result.unwrap_or_default())
}

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
