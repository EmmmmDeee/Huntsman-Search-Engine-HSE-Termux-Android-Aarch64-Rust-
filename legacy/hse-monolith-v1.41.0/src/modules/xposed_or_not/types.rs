//! Serde types for the XposedOrNot API responses.

use serde::Deserialize;

/// XposedOrNot's response shape. Successful lookups return one of:
///   { "breaches": [["MyFitnessPal", "Quizlet", ...]] }  — exposed
///   { "Error": "Not found" }                            — clean
#[derive(Deserialize, Default)]
#[serde(default)]
pub(super) struct XonResp {
    pub(super) breaches: Option<Vec<Vec<String>>>,
}

/// Breach analytics response (`/v1/breach-analytics?email=`).
#[derive(Deserialize, Default)]
#[serde(default)]
pub(super) struct AnalyticsResp {
    #[serde(alias = "ExposedBreaches")]
    pub(super) exposed_breaches: Option<AnalyticsBreaches>,
    #[serde(alias = "PastesSummary")]
    pub(super) pastes_summary: Option<PastesSummary>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
pub(super) struct AnalyticsBreaches {
    #[serde(alias = "breaches_details")]
    pub(super) breaches_details: Option<Vec<BreachDetail>>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
pub(super) struct BreachDetail {
    pub(super) breach: Option<String>,
    #[serde(alias = "xposed_data")]
    pub(super) xposed_data: Option<String>,
    #[serde(alias = "xposed_records")]
    pub(super) xposed_records: Option<u64>,
    #[serde(alias = "xposure_desc")]
    pub(super) xposure_desc: Option<String>,
    #[serde(alias = "xposed_date")]
    pub(super) xposed_date: Option<String>,
    #[serde(alias = "password_risk")]
    pub(super) password_risk: Option<String>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
pub(super) struct PastesSummary {
    pub(super) cnt: Option<u64>,
}
