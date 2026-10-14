//! Numverify (`APILayer` Number Verification): carrier, line type and location for one number
//! (free key, 100 lookups a month).
//!
//! One lookup is one `GET https://api.apilayer.com/number_verification/validate?number={digits}`
//! with the key in the `apikey` header, the same origin and header `credential-status --probe`
//! checks. It runs only when `HUNTSMAN_NUMVERIFY_KEY` is set. The number is sent as E.164 digits
//! without the `+`. An answer for another number is refused.

use serde::Deserialize;

use crate::api_leg::{self, Answer, Api, KeyPlace, KeyUse, LegError};
use crate::http::Transport;
use crate::keys::Keys;

pub const SOURCE: &str = "numverify";
pub const KEY_SLOT: &str = crate::environment::NUMVERIFY_KEY_ENV;
pub const API: Api = Api {
    source: SOURCE,
    provider: "apilayer.com",
    origin: "https://api.apilayer.com:443",
    key: Some(KeyUse {
        slot: KEY_SLOT,
        place: KeyPlace::Header("apikey"),
        required: true,
    }),
};

/// What Numverify says about one number.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Verification {
    pub valid: bool,
    pub country_code: Option<String>,
    pub location: Option<String>,
    pub carrier: Option<String>,
    /// `mobile`, `landline`, `special_services`, `toll_free`, `premium_rate`, ...
    pub line_type: Option<String>,
}

#[derive(Deserialize)]
struct Body {
    valid: bool,
    #[serde(default)]
    number: Option<String>,
    #[serde(default)]
    country_code: Option<String>,
    #[serde(default)]
    location: Option<String>,
    #[serde(default)]
    carrier: Option<String>,
    #[serde(default)]
    line_type: Option<String>,
}

/// `e164` (`+` and digits) as the digits Numverify takes. **Pure.**
#[must_use]
pub fn digits(e164: &str) -> Option<&str> {
    let digits = e164.strip_prefix('+')?;
    (!digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit())).then_some(digits)
}

/// The request URL for an E.164 number. **Pure.**
#[must_use]
pub fn url(e164: &str) -> Option<String> {
    digits(e164)
        .map(|d| format!("https://api.apilayer.com/number_verification/validate?number={d}"))
}

/// Verify the E.164 number `e164` with the key in `keys`.
///
/// # Errors
/// [`LegError::MissingKey`] before any request when no key is configured; otherwise the
/// [`LegError`] that stopped the lookup.
pub fn verify<T: Transport + ?Sized>(
    transport: &T,
    keys: &Keys,
    e164: &str,
    now_unix: u64,
) -> Result<Verification, LegError> {
    let url = url(e164).ok_or_else(|| LegError::Refused("not an E.164 number".into()))?;
    match api_leg::get(transport, &API, keys, &url, now_unix)? {
        Answer::Body(body) => decode(&body, e164),
        Answer::NotFound(_) => Err(LegError::Unexpected(404)),
    }
}

/// One answer body for `e164`. **Pure.**
///
/// # Errors
/// [`LegError::Decode`] for a body that is not the documented shape or is about another number.
pub fn decode(body: &[u8], e164: &str) -> Result<Verification, LegError> {
    let body: Body = api_leg::decode(body)?;
    if let Some(number) = body.number.as_deref().map(str::trim) {
        if !number.is_empty() && Some(number) != digits(e164) {
            return Err(LegError::Decode("answer is about another number".into()));
        }
    }
    Ok(Verification {
        valid: body.valid,
        country_code: api_leg::clean(body.country_code.as_deref()),
        location: api_leg::clean(body.location.as_deref()),
        carrier: api_leg::clean(body.carrier.as_deref()),
        line_type: api_leg::clean(body.line_type.as_deref()).map(|t| t.to_ascii_lowercase()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The `validate` example of the Number Verification API documentation.
    const DOCUMENTED: &str = r#"{"valid":true,"number":"14158586273","local_format":"4158586273","international_format":"+14158586273","country_prefix":"+1","country_code":"US","country_name":"United States of America","location":"Novato","carrier":"AT&T Mobility LLC","line_type":"mobile"}"#;

    #[test]
    fn the_documented_answer_names_carrier_and_line_type() {
        let v = decode(DOCUMENTED.as_bytes(), "+14158586273").unwrap_or_else(|e| panic!("{e}"));
        assert!(v.valid);
        assert_eq!(v.carrier.as_deref(), Some("AT&T Mobility LLC"));
        assert_eq!(v.line_type.as_deref(), Some("mobile"));
        assert_eq!(v.location.as_deref(), Some("Novato"));
        assert_eq!(v.country_code.as_deref(), Some("US"));
    }

    #[test]
    fn an_answer_about_another_number_is_refused() {
        assert!(decode(DOCUMENTED.as_bytes(), "+61412345678").is_err());
    }

    #[test]
    fn a_message_body_is_not_a_verification() {
        assert!(decode(br#"{"message":"Invalid authentication credentials"}"#, "+1").is_err());
    }

    #[test]
    fn only_e164_is_sent() {
        assert_eq!(
            url("+61412345678").as_deref(),
            Some("https://api.apilayer.com/number_verification/validate?number=61412345678")
        );
        assert_eq!(url("0412345678"), None);
        assert_eq!(url("+61 412"), None);
    }
}
