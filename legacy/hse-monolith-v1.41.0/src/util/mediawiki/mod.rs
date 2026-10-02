//! MediaWiki Action API shared helpers.
//!
//! Under the legacy (bc) `format=json` errorformat that HSE's MediaWiki Action
//! API callers use (`wiki_geosearch` against Wikipedia, `wikidata` against
//! wikidata.org), the API returns errors as **HTTP 200** with a top-level
//! `{"error":{"code":…,"info":…}}` object
//! (docs: <https://www.mediawiki.org/wiki/API:Errors_and_warnings>), NOT a
//! non-2xx status. [`crate::util::http::fetch_json`] therefore decodes that
//! envelope as a *successful* response whose data arrays are simply empty —
//! which each caller read as a clean negative ("no nearby places", "no matching
//! item"). That is the RULE 1 false-negative class: an API failure reported as a
//! confident absence.
//!
//! This module is the single authority that models that envelope and turns it
//! into a hard error, so callers cannot drift in how they detect it or word it.
//! A caller adds `#[serde(default)] error: Option<MwError>` to the response
//! struct it decodes and gates on [`MwError::check`] before reading the payload.
//! (`wikitree` is NOT a caller here — it queries WikiTree's own `api.wikitree.com`,
//! whose distinct `status` field it already checks.)

#[cfg(test)]
mod tests;

use serde::Deserialize;

use crate::core::error::{Error, Result};

/// The MediaWiki Action API's HTTP-200 error envelope
/// (`{"error":{"code":"…","info":"…"}}`). `#[serde(default)]` on both fields so
/// a partial or future-extended envelope still deserialises rather than turning
/// a real API error back into a decode failure.
#[derive(Deserialize, Debug, Clone, Default)]
pub struct MwError {
    #[serde(default)]
    pub code: String,
    #[serde(default)]
    pub info: String,
}

impl MwError {
    /// `Err` (naming `module`) when a MediaWiki error envelope is present, so a
    /// failure returned inside an HTTP 200 is surfaced instead of read as an
    /// empty, clean-negative result; `Ok(())` when `error` is absent (the normal
    /// success path).
    ///
    /// `module` is the caller's `SRC` tag, so the surfaced error is attributable
    /// exactly like every other module error.
    pub fn check(error: &Option<Self>, module: &'static str) -> Result<()> {
        match error {
            Some(e) => Err(Error::module(
                module,
                format!("MediaWiki API error [{}]: {}", e.code.trim(), e.info.trim()),
            )),
            None => Ok(()),
        }
    }
}
