//! `XposedOrNot`: the names of public breaches that included one email address.
//!
//! One lookup is one keyless `GET https://api.xposedornot.com/v1/check-email/{email}`. Kept: every
//! breach name, each once, and how many there are. The answer holds no record content. An address in no breach answers `200` `{"Error":"Not found","email":null}`, a valid zero;
//! a `404` carrying that body is read the same way. Any other `404`, such as
//! `{"detail":"Not Found"}` for a path the API does not have, is a failed lookup, never a zero
//! (both checked 2026-10-15).

use std::collections::HashSet;

use serde::Deserialize;

use crate::api_leg::{self, Answer, Api, LegError};
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
    key: None,
};
pub const INTEL: Source = Source {
    api: &API,
    kinds: &[IndicatorKind::Email],
    lookup,
};

/// `breaches` is a list holding one list of names; a miss carries `Error` instead.
#[derive(Deserialize)]
struct Body {
    #[serde(default)]
    breaches: Option<Vec<Vec<String>>>,
    #[serde(default, rename = "Error")]
    error: Option<String>,
}

impl Body {
    /// The miss: no breaches and `Error` "not found", whatever its case.
    fn is_miss(&self) -> bool {
        self.breaches.is_none()
            && self
                .error
                .as_deref()
                .is_some_and(|e| e.eq_ignore_ascii_case("not found"))
    }
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
        Answer::NotFound(body) => decode_not_found(&body),
    }
}

/// One `404` body: the miss is a valid zero, anything else is [`LegError::Unexpected`]. **Pure.**
///
/// # Errors
/// [`LegError::Unexpected`] for a `404` that is not the miss.
fn decode_not_found(body: &[u8]) -> Result<Option<Finding>, LegError> {
    match api_leg::decode::<Body>(body) {
        Ok(body) if body.is_miss() => Ok(None),
        _ => Err(LegError::Unexpected(404)),
    }
}

/// One answer body. **Pure.**
///
/// # Errors
/// [`LegError::Decode`] for a body that is not the documented shape.
pub fn decode(body: &[u8]) -> Result<Option<Finding>, LegError> {
    let body: Body = api_leg::decode(body)?;
    if body.is_miss() {
        return Ok(None);
    }
    let Some(breaches) = body.breaches else {
        return Err(LegError::Decode(
            "answer has neither breaches nor a miss".into(),
        ));
    };
    let mut names: Vec<String> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();
    for name in breaches.iter().flatten() {
        if let Some(name) = api_leg::clean(Some(name)) {
            if seen.insert(name.clone()) {
                names.push(name);
            }
        }
    }
    let total = names.len();
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
        .tag(tags::BREACH),
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
        assert_eq!(f.tags, [tags::BREACH]);
        assert!(
            f.attrs
                .iter()
                .any(|(k, v)| *k == "breaches" && v == "Artsy,MalindoAir,MyHeritage")
        );
    }

    #[test]
    fn every_breach_name_is_kept_and_counted_once() {
        let names: Vec<String> = (0..300).map(|i| format!("\"Breach{}\"", i % 120)).collect();
        let body = format!(r#"{{"breaches":[[{}]]}}"#, names.join(","));
        let f = decode(body.as_bytes())
            .ok()
            .flatten()
            .unwrap_or_else(|| panic!("body must decode"));
        assert!(f.summary.contains("120 public breaches"), "{}", f.summary);
        assert_eq!(f.tags, [tags::BREACH]);
        let kept = f
            .attrs
            .iter()
            .find(|(k, _)| *k == "breaches")
            .map_or(0, |(_, v)| v.split(',').count());
        assert_eq!(kept, 120);
    }

    #[test]
    fn a_miss_or_an_empty_list_is_a_valid_zero_and_the_address_is_encoded() {
        assert!(matches!(decode(br#"{"breaches":[[]]}"#), Ok(None)));
        assert!(matches!(
            decode(br#"{"Error":"Not found","email":null}"#),
            Ok(None)
        ));
        // Breaches beside a miss's `Error` are still breaches, never hidden as a miss.
        assert!(matches!(
            decode(br#"{"breaches":[["A"]],"Error":"Not found"}"#),
            Ok(Some(f)) if f.tags == [tags::BREACH]
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

    #[test]
    fn a_404_for_a_path_the_api_lacks_is_a_failure_not_a_valid_zero() {
        // Recorded for `https://api.xposedornot.com/v1/check-emailx/test%40example.com` on 2026-10-15.
        let unknown = r#"{"detail":"Not Found"}"#;
        let transport = crate::test_support::OneResponse::json(404, unknown);
        let looked_up = lookup(
            &transport,
            &Keys::default(),
            Indicator::Email("test@example.com"),
            1,
        );
        assert!(
            matches!(looked_up, Err(LegError::Unexpected(404))),
            "{looked_up:?}"
        );
        // The miss, as a 404, is still a valid zero.
        let miss = r#"{"Error":"Not found","email":null}"#;
        let transport = crate::test_support::OneResponse::json(404, miss);
        let looked_up = lookup(
            &transport,
            &Keys::default(),
            Indicator::Email("test@example.com"),
            1,
        );
        assert!(matches!(looked_up, Ok(None)), "{looked_up:?}");
    }
}
