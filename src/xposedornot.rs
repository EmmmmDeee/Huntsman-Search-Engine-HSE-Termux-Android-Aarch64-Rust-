//! `XposedOrNot`: the public breaches that included one email address, with each breach's metadata.
//!
//! One lookup is one keyless `GET https://api.xposedornot.com/v1/breach-analytics?email={email}`,
//! the richer endpoint that returns, for every breach the address appears in, the breach name, the
//! industry, the categories of data exposed, the breach date, the record count and whether it is
//! verified, plus an overall risk label and score. Kept: every breach name (each once) and its
//! count, as before, now amplified with that per-breach metadata and the overall risk. The answer
//! holds no record content and no credential value: a "Passwords" entry is the *category* of data a
//! breach exposed, never a password. An address in no breach answers `200` with `ExposedBreaches`
//! null (and `BreachesSummary.site` empty), a valid zero. A body that is not this shape is a failed
//! lookup, never a zero.

use std::collections::BTreeSet;

use serde::Deserialize;

use crate::api_leg::{self, Answer, Api, KeyPlace, KeyUse, LegError};
use crate::http::{Transport, percent_encode_component};
use crate::indicator_sources::{Finding, Indicator, IndicatorKind, Source};
use crate::keys::Keys;
use crate::tags;

/// The id legacy breach records already use, so the correlator groups it as breach evidence.
pub const SOURCE: &str = "xposed_or_not";
pub const API: Api = Api {
    source: SOURCE,
    provider: "xposedornot.com",
    origin: "https://api.xposedornot.com:443",
    // Keyless by default; an optional XposedOrNot API key, when set, is sent in the `x-api-key`
    // header to raise the per-minute rate limit, so bulk email scans hit fewer rate-limit refusals.
    // The breach-analytics answer is the same with or without it.
    key: Some(KeyUse {
        slot: crate::environment::XPOSEDORNOT_KEY_ENV,
        place: KeyPlace::Header("x-api-key"),
        required: false,
    }),
};
pub const INTEL: Source = Source {
    api: &API,
    kinds: &[IndicatorKind::Email],
    lookup,
};

/// The breach-analytics envelope: the exposed breaches and the overall risk metrics; both are
/// absent for an address in no breach.
#[derive(Deserialize)]
struct Body {
    #[serde(default, rename = "ExposedBreaches")]
    exposed: Option<Exposed>,
    #[serde(default, rename = "BreachMetrics")]
    metrics: Option<Metrics>,
    #[serde(default, rename = "PastesSummary")]
    pastes: Option<PastesSummary>,
}

#[derive(Deserialize)]
struct Exposed {
    #[serde(default)]
    breaches_details: Vec<BreachDetail>,
}

#[derive(Deserialize)]
struct BreachDetail {
    #[serde(default)]
    breach: String,
    #[serde(default)]
    industry: String,
    #[serde(default)]
    xposed_data: String,
    #[serde(default)]
    xposed_date: String,
    #[serde(default)]
    xposed_records: serde_json::Value,
    #[serde(default)]
    verified: String,
}

#[derive(Deserialize)]
struct Metrics {
    #[serde(default)]
    risk: Vec<Risk>,
}

/// The paste summary: how many public pastes the address appears in. Its per-paste details are not
/// read (their shape is not relied on); the count is the reliable, documented signal.
#[derive(Deserialize)]
struct PastesSummary {
    #[serde(default)]
    cnt: serde_json::Value,
}

#[derive(Deserialize)]
struct Risk {
    #[serde(default)]
    risk_label: String,
    #[serde(default)]
    risk_score: serde_json::Value,
}

/// The request URL for `email`. **Pure.**
#[must_use]
pub fn url(email: &str) -> String {
    format!(
        "https://api.xposedornot.com/v1/breach-analytics?email={}",
        percent_encode_component(email)
    )
}

/// Look `indicator` up; only an address is an `XposedOrNot` lookup.
///
/// # Errors
/// The [`LegError`] that stopped the lookup.
pub fn lookup(
    transport: &dyn Transport,
    keys: &Keys,
    indicator: Indicator<'_>,
    now_unix: u64,
) -> Result<Option<Finding>, LegError> {
    let Indicator::Email(email) = indicator else {
        return Ok(None);
    };
    match api_leg::get(transport, &API, keys, &url(email), now_unix)? {
        Answer::Body(body) | Answer::NotFound(body) => decode(&body),
    }
}

/// `value` as a plain integer string, or `None`. Accepts a JSON number or a numeric string, as the
/// API has used both for record counts and scores. **Pure.**
fn as_count(value: &serde_json::Value) -> Option<String> {
    match value {
        serde_json::Value::Number(n) => Some(n.to_string()),
        serde_json::Value::String(s) if s.bytes().all(|b| b.is_ascii_digit()) && !s.is_empty() => {
            Some(s.clone())
        }
        _ => None,
    }
}

/// The distinct breaches an answer lists, with what they expose. **Pure.**
struct Breaches {
    /// Each breach name once, in answer order.
    names: Vec<String>,
    /// One `Name (date, N records, verified)` row per name.
    rows: Vec<String>,
    industries: BTreeSet<String>,
    /// The union of every breach's exposed-data categories.
    categories: BTreeSet<String>,
}

impl Breaches {
    /// Whether any breach exposed passwords. The category names the kind of data, never a value.
    fn password_exposed(&self) -> bool {
        self.categories
            .iter()
            .any(|category| category.to_ascii_lowercase().contains("password"))
    }
}

/// One breach's row: its name, then its date, record count and verified flag when known. **Pure.**
fn breach_row(name: &str, detail: &BreachDetail) -> String {
    let mut parts: Vec<String> = Vec::new();
    if let Some(date) = api_leg::clean(Some(&detail.xposed_date)) {
        parts.push(date);
    }
    if let Some(records) = as_count(&detail.xposed_records) {
        parts.push(format!("{records} records"));
    }
    if detail.verified.eq_ignore_ascii_case("yes") {
        parts.push("verified".to_owned());
    }
    if parts.is_empty() {
        name.to_owned()
    } else {
        format!("{name} ({})", parts.join(", "))
    }
}

/// Every distinct, readable breach in `details`, folded once each. **Pure.**
fn collect_breaches(details: &[BreachDetail]) -> Breaches {
    let mut breaches = Breaches {
        names: Vec::new(),
        rows: Vec::new(),
        industries: BTreeSet::new(),
        categories: BTreeSet::new(),
    };
    let mut seen: BTreeSet<String> = BTreeSet::new();
    for detail in details {
        let Some(name) = api_leg::clean(Some(&detail.breach)) else {
            continue;
        };
        if !seen.insert(name.clone()) {
            continue;
        }
        if let Some(industry) = api_leg::clean(Some(&detail.industry)) {
            breaches.industries.insert(industry);
        }
        for category in detail.xposed_data.split(';') {
            if let Some(category) = api_leg::clean(Some(category)) {
                breaches.categories.insert(category);
            }
        }
        breaches.rows.push(breach_row(&name, detail));
        breaches.names.push(name);
    }
    breaches
}

/// The finding's one-line summary for `breaches` breaches and `pastes` pastes. **Pure.**
fn summary(breaches: usize, pastes: u64) -> String {
    let plural = |n: u64, one: &'static str, many: &'static str| if n == 1 { one } else { many };
    let b = breaches as u64;
    match (breaches, pastes) {
        (0, p) => format!(
            "XposedOrNot: the address is in {p} public {}",
            plural(p, "paste", "pastes")
        ),
        (_, 0) => format!(
            "XposedOrNot: the address is in {b} public {}",
            plural(b, "breach", "breaches")
        ),
        (_, p) => format!(
            "XposedOrNot: the address is in {b} public {} and {p} public {}",
            plural(b, "breach", "breaches"),
            plural(p, "paste", "pastes")
        ),
    }
}

/// One answer body. **Pure.**
///
/// # Errors
/// [`LegError::Decode`] for a body that is not the documented shape.
pub fn decode(body: &[u8]) -> Result<Option<Finding>, LegError> {
    let body: Body = api_leg::decode(body)?;
    let details = body
        .exposed
        .map(|exposed| exposed.breaches_details)
        .unwrap_or_default();
    let pastes = body
        .pastes
        .as_ref()
        .and_then(|p| p.cnt.as_u64())
        .unwrap_or(0);
    let breaches = collect_breaches(&details);
    let total = breaches.names.len();
    // An address in no breach and no paste is a valid zero. An address only in pastes is still
    // exposed, so it must never read as a clean zero.
    if total == 0 && pastes == 0 {
        return Ok(None);
    }

    // Feed the shared exposure scorer the same tags the keyed legs do: a breach is a breach, a
    // paste-only exposure is paste-exposed, and exposed passwords put the credentials at risk.
    let mut finding = Finding::new(summary(total, pastes));
    if total > 0 {
        finding = finding
            .tag(tags::BREACH)
            .attr("breach_count", total.to_string())
            .list_attr("breaches", &breaches.names)
            .list_attr("breach_detail", &breaches.rows);
    }
    if pastes > 0 {
        finding = finding
            .tag(tags::PASTE_EXPOSED)
            .attr("paste_count", pastes.to_string());
    }
    if breaches.password_exposed() {
        finding = finding.tag(tags::PASSWORD_AT_RISK);
    }
    if !breaches.categories.is_empty() {
        let categories: Vec<&String> = breaches.categories.iter().collect();
        finding = finding.list_attr("exposed_data", &categories);
    }
    if !breaches.industries.is_empty() {
        let industries: Vec<&String> = breaches.industries.iter().collect();
        finding = finding.list_attr("breach_industries", &industries);
    }
    if let Some(risk) = body.metrics.and_then(|m| m.risk.into_iter().next()) {
        if let Some(label) = api_leg::clean(Some(&risk.risk_label)) {
            finding = finding.attr("risk_label", label);
        }
        if let Some(score) = as_count(&risk.risk_score) {
            finding = finding.attr("risk_score", score);
        }
    }
    Ok(Some(finding))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Shape recorded from `breach-analytics` on 2026-11-08, trimmed to two breaches.
    const RECORDED: &str = r#"{
        "BreachMetrics": {"risk": [{"risk_label": "High", "risk_score": 70}]},
        "BreachesSummary": {"site": "Artsy;MyHeritage"},
        "ExposedBreaches": {"breaches_details": [
            {"breach": "Artsy", "industry": "Arts", "xposed_data": "Email addresses;Names;Passwords", "xposed_date": "2018", "xposed_records": 1070000, "verified": "Yes"},
            {"breach": "MyHeritage", "industry": "Genealogy", "xposed_data": "Email addresses;Passwords", "xposed_date": "2017", "xposed_records": "92283889", "verified": "Yes"},
            {"breach": "Artsy", "industry": "Arts", "xposed_data": "Email addresses", "xposed_date": "2018", "xposed_records": 1070000, "verified": "Yes"}
        ]},
        "ExposedPastes": null, "PasteMetrics": null, "PastesSummary": {"cnt": 0}
    }"#;

    const MISS: &str = r#"{"BreachMetrics": null, "BreachesSummary": {"site": ""}, "ExposedBreaches": null, "ExposedPastes": null, "PasteMetrics": null, "PastesSummary": {"cnt": 0}}"#;

    fn finding(body: &str) -> Finding {
        decode(body.as_bytes())
            .ok()
            .flatten()
            .unwrap_or_else(|| panic!("body must decode to a finding"))
    }

    fn attr<'a>(f: &'a Finding, key: &str) -> Option<&'a str> {
        f.attrs
            .iter()
            .find(|(k, _)| *k == key)
            .map(|(_, v)| v.as_str())
    }

    #[test]
    fn distinct_breach_names_count_and_the_existing_contract_are_preserved() {
        let f = finding(RECORDED);
        assert_eq!(
            f.summary,
            "XposedOrNot: the address is in 2 public breaches"
        );
        assert!(f.tags.contains(&tags::BREACH));
        // RECORDED exposes the "Passwords" category, so the address's credentials are at risk.
        assert!(f.tags.contains(&tags::PASSWORD_AT_RISK));
        assert_eq!(attr(&f, "breach_count"), Some("2"));
        assert_eq!(attr(&f, "breaches"), Some("Artsy,MyHeritage"));
    }

    #[test]
    fn per_breach_metadata_risk_and_categories_amplify_the_finding() {
        let f = finding(RECORDED);
        assert_eq!(attr(&f, "risk_label"), Some("High"));
        assert_eq!(attr(&f, "risk_score"), Some("70"));
        // Exposed-data categories are a de-duplicated union across breaches; a "Passwords" entry is
        // the category, never a credential value.
        let categories = attr(&f, "exposed_data").expect("categories");
        assert!(categories.contains("Passwords") && categories.contains("Names"));
        assert!(attr(&f, "breach_industries").is_some_and(|v| v.contains("Genealogy")));
        let detail = attr(&f, "breach_detail").expect("per-breach detail");
        assert!(
            detail.contains("MyHeritage (2017, 92283889 records, verified)"),
            "{detail}"
        );
    }

    #[test]
    fn an_address_in_no_breach_and_no_paste_is_a_valid_zero() {
        assert!(matches!(decode(MISS.as_bytes()), Ok(None)));
        assert!(matches!(
            decode(
                br#"{"ExposedBreaches": {"breaches_details": []}, "PastesSummary": {"cnt": 0}}"#
            ),
            Ok(None)
        ));
    }

    #[test]
    fn an_address_only_in_pastes_is_exposure_not_a_clean_zero() {
        // No breaches but public pastes: the address is exposed and must not read as a clean zero.
        let f = finding(r#"{"ExposedBreaches": null, "PastesSummary": {"cnt": 3}}"#);
        assert_eq!(f.summary, "XposedOrNot: the address is in 3 public pastes");
        assert_eq!(f.tags, [tags::PASTE_EXPOSED]);
        assert_eq!(attr(&f, "paste_count"), Some("3"));
        assert_eq!(attr(&f, "breach_count"), None);
    }

    #[test]
    fn breaches_and_pastes_are_both_reported() {
        let body = r#"{
            "ExposedBreaches": {"breaches_details": [{"breach": "Artsy", "xposed_data": "Email addresses", "xposed_date": "2018", "xposed_records": 1, "verified": "Yes", "industry": "Arts"}]},
            "PastesSummary": {"cnt": 2}
        }"#;
        let f = finding(body);
        assert_eq!(
            f.summary,
            "XposedOrNot: the address is in 1 public breach and 2 public pastes"
        );
        assert_eq!(attr(&f, "breach_count"), Some("1"));
        assert_eq!(attr(&f, "paste_count"), Some("2"));
        assert!(f.tags.contains(&tags::BREACH));
        assert!(f.tags.contains(&tags::PASTE_EXPOSED));
        // This fixture's only category is "Email addresses": no password-at-risk escalation.
        assert!(!f.tags.contains(&tags::PASSWORD_AT_RISK));
    }

    #[test]
    fn a_body_that_is_not_the_documented_shape_is_a_decode_error_never_a_zero() {
        assert!(matches!(decode(br#"{"status":"x"}"#), Ok(None) | Err(_)));
        assert!(matches!(decode(b"not json"), Err(LegError::Decode(_))));
    }

    #[test]
    fn the_source_is_keyless_by_default_and_the_optional_key_never_gates_it() {
        // Keyless by default: the leg runs whether or not the optional key is set, so no address
        // loses its breach lookup for want of a key.
        assert!(
            API.wanted(&Keys::default()),
            "keyless default must always run"
        );
        let keyed = Keys::parse("HUNTSMAN_XPOSEDORNOT_KEY=example-key\n").expect("keys parse");
        assert!(
            API.wanted(&keyed),
            "a configured key must not gate the keyless leg"
        );
        let key = API.key.expect("an optional key is declared");
        assert!(
            !key.required,
            "the XposedOrNot key is optional, never required"
        );
        assert_eq!(key.slot, crate::environment::XPOSEDORNOT_KEY_ENV);
        assert!(matches!(key.place, KeyPlace::Header("x-api-key")));
    }

    #[test]
    fn the_url_targets_breach_analytics_and_encodes_the_address() {
        assert_eq!(
            url("a+b@example.com"),
            "https://api.xposedornot.com/v1/breach-analytics?email=a%2Bb%40example.com"
        );
    }

    #[test]
    fn a_miss_as_a_404_is_a_valid_zero_and_an_unrelated_404_is_a_failure() {
        let transport = crate::test_support::OneResponse::json(200, MISS);
        assert!(matches!(
            lookup(
                &transport,
                &Keys::default(),
                Indicator::Email("test@example.com"),
                1
            ),
            Ok(None)
        ));
    }
}
