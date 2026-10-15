//! `XposedOrNot`: the names of public breaches that included one email address.
//!
//! One lookup is one keyless `GET https://api.xposedornot.com/v1/check-email/{email}`. Kept: the
//! breach names (at most [`MAX_NAMES`]) and how many there are. No record content is returned or
//! kept. An address in no breach answers `{"Error":"Not found"}` (or 404), a valid zero.

use serde::Deserialize;

use crate::api_leg::{self, Answer, Api, LegError};
use crate::http::{Transport, percent_encode_component};
use crate::indicator_sources::{Finding, Indicator, IndicatorKind, Source};
use crate::keys::Keys;

/// The id legacy breach records already use, so the correlator groups it as breach evidence.
pub const SOURCE: &str = "xposed_or_not";
pub const API: Api = Api {
    source: SOURCE,
    provider: "xposedornot.com",
    origin: "https://api.xposedornot.com:443",
    key: None,
};
pub const INTEL: Source = Source {
    api: &API,
    kinds: &[IndicatorKind::Email],
    lookup,
};

/// Breach names kept in the finding; the count covers all of them.
const MAX_NAMES: usize = 25;

/// `breaches` is a list holding one list of names; a miss carries `Error` instead.
#[derive(Deserialize)]
struct Body {
    #[serde(default)]
    breaches: Option<Vec<Vec<String>>>,
    #[serde(default, rename = "Error")]
    error: Option<String>,
}

/// The request URL for `email`. **Pure.**
#[must_use]
pub fn url(email: &str) -> String {
    format!(
        "https://api.xposedornot.com/v1/check-email/{}",
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
        Answer::Body(body) => decode(&body),
        Answer::NotFound(_) => Ok(None),
    }
}

/// One answer body. **Pure.**
///
/// # Errors
/// [`LegError::Decode`] for a body that is not the documented shape.
pub fn decode(body: &[u8]) -> Result<Option<Finding>, LegError> {
    let body: Body = api_leg::decode(body)?;
    let Some(breaches) = body.breaches else {
        return match body.error.as_deref() {
            Some(e) if e.eq_ignore_ascii_case("not found") => Ok(None),
            _ => Err(LegError::Decode(
                "answer has neither breaches nor a miss".into(),
            )),
        };
    };
    let mut names: Vec<String> = Vec::new();
    let mut total = 0usize;
    for name in breaches.iter().flatten() {
        let Some(name) = api_leg::clean(Some(name)) else {
            continue;
        };
        if names.contains(&name) {
            continue;
        }
        total += 1;
        if names.len() < MAX_NAMES {
            names.push(name);
        }
    }
    if total == 0 {
        return Ok(None);
    }
    Ok(Some(
        Finding::new(format!(
            "XposedOrNot: the address is in {total} public breach{}",
            if total == 1 { "" } else { "es" }
        ))
        .attr("breach_count", total.to_string())
        .list_attr("breaches", &names)
        .tag("breached")
        .tag_if(total > names.len(), "truncated"),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Shape recorded for a test address on 2026-10-14, shortened.
    const RECORDED: &str = r#"{"breaches":[["Artsy","MalindoAir","MyHeritage","Artsy"]]}"#;

    #[test]
    fn a_recorded_answer_keeps_distinct_breach_names_and_their_count() {
        let f = decode(RECORDED.as_bytes())
            .ok()
            .flatten()
            .unwrap_or_else(|| panic!("recorded body must decode"));
        assert_eq!(
            f.summary,
            "XposedOrNot: the address is in 3 public breaches"
        );
        assert_eq!(f.tags, ["breached"]);
        assert!(
            f.attrs
                .iter()
                .any(|(k, v)| *k == "breaches" && v == "Artsy,MalindoAir,MyHeritage")
        );
    }

    #[test]
    fn more_names_than_kept_are_counted_and_tagged_truncated() {
        let names: Vec<String> = (0..30).map(|i| format!("\"B{i}\"")).collect();
        let body = format!(r#"{{"breaches":[[{}]]}}"#, names.join(","));
        let f = decode(body.as_bytes())
            .ok()
            .flatten()
            .unwrap_or_else(|| panic!("body must decode"));
        assert!(f.summary.contains("30 public breaches"));
        assert_eq!(f.tags, ["breached", "truncated"]);
    }

    #[test]
    fn a_miss_or_an_empty_list_is_a_valid_zero_and_the_address_is_encoded() {
        assert!(matches!(decode(br#"{"breaches":[[]]}"#), Ok(None)));
        assert!(matches!(
            decode(br#"{"Error":"Not found","email":null}"#),
            Ok(None)
        ));
        assert!(matches!(
            decode(br#"{"status":"x"}"#),
            Err(LegError::Decode(_))
        ));
        assert_eq!(
            url("a+b@example.com"),
            "https://api.xposedornot.com/v1/check-email/a%2Bb%40example.com"
        );
    }
}
