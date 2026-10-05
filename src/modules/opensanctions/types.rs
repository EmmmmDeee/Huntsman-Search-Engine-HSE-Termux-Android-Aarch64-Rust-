//! Deserialisation types for the OpenSanctions `/match` API response.
//!
//! Matches the response shape documented in OpenSanctions' own matching-API
//! quickstart tutorial (verified against their live OpenAPI spec, 2026-07).
//! Properties are always multi-valued (aggregated from every source dataset
//! an entity appears in — the FollowTheMoney data model's own convention),
//! hence `Vec<String>` rather than `Option<String>` throughout.

use serde::Deserialize;

#[derive(Deserialize, Default)]
pub(super) struct MatchResp {
    #[serde(default)]
    pub(super) responses: Responses,
}

/// We always submit exactly one query keyed `"q"`, so the response is read
/// directly rather than through a dynamic `HashMap<String, _>`.
#[derive(Deserialize, Default)]
pub(super) struct Responses {
    #[serde(default)]
    pub(super) q: QueryResponse,
}

#[derive(Deserialize, Default)]
pub(super) struct QueryResponse {
    #[serde(default)]
    pub(super) results: Vec<MatchResult>,
}

#[derive(Deserialize)]
pub(super) struct MatchResult {
    pub(super) id: String,
    #[serde(default)]
    pub(super) caption: Option<String>,
    #[serde(default)]
    pub(super) properties: MatchProperties,
    #[serde(default)]
    pub(super) datasets: Vec<String>,
    #[serde(default)]
    pub(super) score: Option<f64>,
    /// The API's own scoring verdict: this candidate cleared the match
    /// threshold, not merely a fuzzy near-miss. `match` is a Rust keyword,
    /// hence the rename.
    #[serde(default, rename = "match")]
    pub(super) is_match: Option<bool>,
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub(super) struct MatchProperties {
    /// Risk-category tags — `sanction`, `role.pep`, `debarment`, `poi`, …
    #[serde(default)]
    pub(super) topics: Vec<String>,
    /// A PEP's official political/administrative role — genuinely present
    /// (unlike a category-default over-claim), since OpenSanctions' PEP
    /// datasets carry it directly.
    #[serde(default)]
    pub(super) position: Vec<String>,
    #[serde(default)]
    pub(super) birth_date: Vec<String>,
    #[serde(default)]
    pub(super) country: Vec<String>,
    #[serde(default)]
    pub(super) nationality: Vec<String>,
    /// The specific sanctions programme code(s) (e.g. `EU-UKR`, `US-RUSHAR`).
    #[serde(default)]
    pub(super) program_id: Vec<String>,
}
