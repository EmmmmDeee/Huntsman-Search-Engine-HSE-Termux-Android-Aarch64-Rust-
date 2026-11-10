//! BreachDirectory's RapidAPI breach-source lookup for one email or username.
//!
//! Uses only `func=sources`. It does not request the provider's `auto`, `domain`,
//! `dehash`, or password modes, or retain credentials from an unexpected body.
//! A missing key, malformed response, quota error, or HTTP failure is never a
//! negative breach result. All requests use the existing origin-pinned fetch path.
//!
//! API availability, exact response shapes and account quotas require a live,
//! operator-authorised credential. The two accepted source shapes below are
//! deliberately tested as synthetic fixtures, not claimed live observations.

use std::collections::HashSet;

use serde_json::Value;

use crate::api_leg::{self, Api, KeyPlace, KeyUse, LegError};
use crate::http::{Transport, percent_encode_component};
use crate::indicator_sources::{Finding, Indicator, IndicatorKind, Source};
use crate::keys::Keys;
use crate::tags;

/// Stable source label for scan evidence and source outcomes.
pub const SOURCE: &str = "breachdirectory";
/// The only gateway hostname and the required RapidAPI Host header value.
pub const RAPIDAPI_HOST: &str = "breachdirectory.p.rapidapi.com";
/// The one allowed credential-bearing HTTPS origin.
pub const API: Api = Api {
    source: SOURCE,
    provider: "breachdirectory.p.rapidapi.com",
    origin: "https://breachdirectory.p.rapidapi.com:443",
    key: Some(KeyUse {
        slot: crate::environment::BREACHDIRECTORY_KEY_ENV,
        place: KeyPlace::Header("X-RapidAPI-Key"),
        required: true,
    }),
};

/// Email lookups run through HUNTSMAN's common indicator pipeline.
pub const INTEL: Source = Source {
    api: &API,
    kinds: &[IndicatorKind::Email],
    lookup,
};

/// Build the documented `sources` query. The operator-supplied selector is
/// percent-encoded as one parameter, never concatenated as a URL fragment.
#[must_use]
pub fn url(selector: &str) -> String {
    format!(
        "https://{RAPIDAPI_HOST}/?func=sources&term={}",
        percent_encode_component(selector)
    )
}

/// One email lookup from the common indicator pipeline.
///
/// # Errors
/// Only an HTTP, credential, or decoding failure; a documented empty source
/// result is `Ok(None)`.
pub fn lookup(
    transport: &dyn Transport,
    keys: &Keys,
    indicator: Indicator<'_>,
    now_unix: u64,
) -> Result<Option<Finding>, LegError> {
    let Indicator::Email(email) = indicator else {
        return Ok(None);
    };
    lookup_selector(transport, keys, email, now_unix)
}

/// The identical one-selector contract for the username front-end.
///
/// # Errors
/// The same errors as `lookup`.
pub fn lookup_username<T: Transport + ?Sized>(
    transport: &T,
    keys: &Keys,
    username: &str,
    now_unix: u64,
) -> Result<Option<Finding>, LegError> {
    lookup_selector(transport, keys, username, now_unix)
}

fn lookup_selector<T: Transport + ?Sized>(
    transport: &T,
    keys: &Keys,
    selector: &str,
    now_unix: u64,
) -> Result<Option<Finding>, LegError> {
    let reply = api_leg::get_with_headers(
        transport,
        &API,
        keys,
        &url(selector),
        &[("X-RapidAPI-Host", RAPIDAPI_HOST)],
        now_unix,
    )?
    .body_or_unexpected()?;
    decode(&reply)
}

fn add_sources(value: &Value, sources: &mut Vec<String>) -> Result<(), LegError> {
    match value {
        Value::String(name) => {
            sources.push(name.clone());
            Ok(())
        }
        Value::Array(items) => {
            for item in items {
                let Some(name) = item.as_str() else {
                    return Err(LegError::Decode("invalid BreachDirectory source entry".into()));
                };
                sources.push(name.to_owned());
            }
            Ok(())
        }
        _ => Err(LegError::Decode("invalid BreachDirectory sources field".into())),
    }
}

/// Decode only breach-source names and counts. Unexpected `password`, `sha1`,
/// `hash` and all other credential fields are never read into a Finding.
///
/// # Errors
/// An unknown, ambiguous, or provider-failed body is not treated as an
/// authoritative clean result.
pub fn decode(bytes: &[u8]) -> Result<Option<Finding>, LegError> {
    let value: Value = api_leg::decode(bytes)?;
    let object = value
        .as_object()
        .ok_or_else(|| LegError::Decode("BreachDirectory response is not an object".into()))?;

    if object.get("success") == Some(&Value::Bool(false))
        || object.contains_key("error")
        || object.contains_key("message")
    {
        return Err(LegError::Decode("BreachDirectory reported a failure".into()));
    }
    if object.get("success").is_some_and(|v| !v.is_boolean()) {
        return Err(LegError::Decode("invalid BreachDirectory success field".into()));
    }

    let reported_found = match object.get("found") {
        Some(value) => Some(
            value
                .as_u64()
                .ok_or_else(|| LegError::Decode("invalid BreachDirectory found count".into()))?,
        ),
        None => None,
    };
    let mut names = Vec::new();
    let mut explicit_sources = false;
    if let Some(source_field) = object.get("sources") {
        explicit_sources = true;
        add_sources(source_field, &mut names)?;
    }
    if let Some(result) = object.get("result") {
        explicit_sources = true;
        let records = result
            .as_array()
            .ok_or_else(|| LegError::Decode("invalid BreachDirectory result list".into()))?;
        for record in records {
            let fields = record
                .as_object()
                .ok_or_else(|| LegError::Decode("invalid BreachDirectory result entry".into()))?;
            if let Some(source_field) = fields.get("sources") {
                add_sources(source_field, &mut names)?;
            }
        }
    }
    if !explicit_sources && reported_found.is_none() {
        return Err(LegError::Decode(
            "BreachDirectory response has no source list or result count".into(),
        ));
    }

    let mut seen = HashSet::new();
    let mut distinct = Vec::new();
    for name in names {
        if let Some(clean) = api_leg::clean(Some(&name)) {
            if seen.insert(clean.to_ascii_lowercase()) {
                distinct.push(clean);
            }
        }
    }
    if distinct.is_empty() && reported_found.unwrap_or(0) == 0 {
        return Ok(None);
    }
    let count = distinct.len();
    let mut finding = Finding::new(format!(
        "BreachDirectory: {} reported breach source{}",
        count,
        if count == 1 { "" } else { "s" }
    ))
    .attr("source_count", count.to_string())
    .list_attr("breach_sources", &distinct)
    .tag(tags::BREACH);
    if let Some(found) = reported_found {
        finding = finding.attr("reported_found", found.to_string());
    }
    Ok(Some(finding))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::Response;
    use crate::test_support::ScriptedTransport;

    #[test]
    fn percent_encodes_one_exact_selector() {
        assert_eq!(
            url("a+b@example.com"),
            "https://breachdirectory.p.rapidapi.com/?func=sources&term=a%2Bb%40example.com"
        );
    }

    #[test]
    fn sources_are_deduplicated_and_credentials_never_become_evidence() {
        let fixture = br#"{"success":true,"found":3,"sources":["Breach A","breach a","Breach B"],"password":"test-secret","sha1":"test-hash","hash":"test-hash"}"#;
        let finding = decode(fixture).expect("fixture decodes").expect("breaches");
        assert_eq!(finding.tags, [tags::BREACH]);
        assert!(finding.attrs.iter().any(|(key, val)| *key == "breach_sources" && val == "Breach A,Breach B"));
        let rendered = format!("{finding:?}");
        assert!(!rendered.contains("test-secret"));
        assert!(!rendered.contains("test-hash"));
    }

    #[test]
    fn nested_source_names_and_explicit_zeros() {
        let fixture = br#"{"success":true,"found":2,"result":[{"sources":"A","password":"not-used"},{"sources":["B","A"]}]}"#;
        let finding = decode(fixture).expect("fixture decodes").expect("breaches");
        assert!(finding.attrs.iter().any(|(key, val)| *key == "breach_sources" && val == "A,B"));
        assert!(matches!(decode(br#"{"success":true,"sources":[]}"#), Ok(None)));
        assert!(matches!(decode(br#"{"success":true,"found":0}"#), Ok(None)));
    }

    #[test]
    fn unknown_and_failed_shapes_cannot_be_mistaken_for_a_negative() {
        for fixture in [
            br#"{}"#.as_slice(),
            br#"{"success":false,"found":0}"#,
            br#"{"message":"quota exceeded"}"#,
            br#"{"sources":null}"#,
            br#"{"sources":[{"password":"secret"}]}"#,
        ] {
            assert!(decode(fixture).is_err(), "{fixture:?}");
        }
    }

    #[test]
    fn missing_key_never_sends_and_valid_key_uses_correct_host_headers() {
        let missing = ScriptedTransport::new(vec![]);
        let error = lookup_username(&missing, &Keys::default(), "testuser", 1);
        assert!(matches!(error, Err(LegError::MissingKey(_))));
        assert!(missing.seen.borrow().is_empty());

        let keys = Keys::parse(
            "HUNTSMAN_BREACHDIRECTORY_KEY=integration-test-key-0123456789\n",
        )
        .expect("test key");
        let transport = ScriptedTransport::new(vec![Ok(Response {
            status: 200,
            headers: vec![],
            body: br#"{"success":true,"sources":["A"]}"#.to_vec(),
            truncated: false,
        })]);
        let result = lookup_username(&transport, &keys, "testuser", 1);
        assert!(matches!(result, Ok(Some(_))), "{result:?}");
        let sent = transport.seen.borrow();
        assert_eq!(sent.len(), 1);
        assert!(sent[0].url.contains("func=sources&term=testuser"));
        assert!(sent[0].headers.iter().any(|(name, val)| name.eq_ignore_ascii_case("X-RapidAPI-Host") && val == RAPIDAPI_HOST));
        assert!(sent[0].headers.iter().any(|(name, val)| name.eq_ignore_ascii_case("X-RapidAPI-Key") && val == "integration-test-key-0123456789"));
    }
}
