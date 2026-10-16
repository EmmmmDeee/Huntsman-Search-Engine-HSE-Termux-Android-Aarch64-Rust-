//! USACallerLookup: keyless US phone number lookup.
//!
//! One lookup is one `GET https://www.usacallerlookup.com/wp-json/ucl/v1/number/{digits}`.
//! No key. Accepts a 10-digit NANP number. Returns the NANPA carrier and rate-centre location,
//! plus the FTC Do-Not-Call complaint profile. A number with no complaint history still returns
//! carrier and location with complaint counts at zero. Toll-free numbers return `toll_free: true`
//! and no location. HTTP 400 is an invalid number; 429 is the 60 req/min per-IP rate limit.
//!
//! Runs alongside Numverify for US numbers. Everything the answer holds is kept as `raw_answer`.

use serde::Deserialize;

use crate::api_leg::{self, Answer, Api, LegError};
use crate::http::Transport;
use crate::keys::Keys;

pub const SOURCE: &str = "usacallerlookup";
pub const API: Api = Api {
    source: SOURCE,
    provider: "usacallerlookup.com",
    origin: "https://www.usacallerlookup.com:443",
    key: None,
};

/// What USACallerLookup says about one US number.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Profile {
    pub phone: String,
    pub toll_free: bool,
    pub city: Option<String>,
    pub state: Option<String>,
    pub carrier: Option<String>,
    pub complaint_total: u64,
    pub robocall_total: u64,
    pub first_seen: Option<String>,
    pub last_seen: Option<String>,
    pub states_reporting: u64,
    pub raw_answer: String,
}

#[derive(Deserialize)]
struct Body {
    #[serde(default)]
    phone: Option<String>,
    #[serde(default)]
    toll_free: Option<bool>,
    #[serde(default)]
    location: Option<Location>,
    #[serde(default)]
    complaints: Option<Complaints>,
}

#[derive(Deserialize)]
struct Location {
    #[serde(default)]
    city: Option<String>,
    #[serde(default)]
    state: Option<String>,
    #[serde(default)]
    carrier: Option<String>,
}

#[derive(Deserialize)]
struct Complaints {
    #[serde(default)]
    total: Option<u64>,
    #[serde(default)]
    robocalls: Option<u64>,
    #[serde(default)]
    first_seen: Option<String>,
    #[serde(default)]
    last_seen: Option<String>,
    #[serde(default)]
    states_reporting: Option<u64>,
}

/// `e164` as the 10-digit NANP number the API takes, or `None` when it is not a US number.
/// **Pure.**
#[must_use]
pub fn nanp_digits(e164: &str) -> Option<String> {
    let digits = e164.strip_prefix('+')?.strip_prefix('1')?;
    (digits.len() == 10 && digits.bytes().all(|b| b.is_ascii_digit())).then(|| digits.to_owned())
}

/// The request URL for a US E.164 number. **Pure.**
#[must_use]
pub fn url(e164: &str) -> Option<String> {
    nanp_digits(e164)
        .map(|d| format!("https://www.usacallerlookup.com/wp-json/ucl/v1/number/{d}"))
}

/// Look the US E.164 number up.
///
/// # Errors
/// The [`LegError`] that stopped the lookup. A non-US number is refused before any request.
pub fn lookup<T: Transport + ?Sized>(
    transport: &T,
    e164: &str,
    now_unix: u64,
) -> Result<Option<Profile>, LegError> {
    let Some(url) = url(e164) else {
        return Ok(None);
    };
    match api_leg::get(transport, &API, &Keys::default(), &url, now_unix)? {
        Answer::Body(body) => Ok(Some(decode(&body)?)),
        Answer::NotFound(_) => Ok(None),
    }
}

/// One answer body. **Pure.**
///
/// # Errors
/// [`LegError::Decode`] for a body that is not the documented shape.
pub fn decode(body: &[u8]) -> Result<Profile, LegError> {
    let whole: serde_json::Value = api_leg::decode(body)?;
    let body: Body = api_leg::decode(body)?;
    let loc = body.location.unwrap_or(Location {
        city: None,
        state: None,
        carrier: None,
    });
    let comp = body.complaints.unwrap_or(Complaints {
        total: None,
        robocalls: None,
        first_seen: None,
        last_seen: None,
        states_reporting: None,
    });
    Ok(Profile {
        phone: api_leg::clean(body.phone.as_deref()).unwrap_or_default(),
        toll_free: body.toll_free.unwrap_or(false),
        city: api_leg::clean(loc.city.as_deref()),
        state: api_leg::clean(loc.state.as_deref()),
        carrier: api_leg::clean(loc.carrier.as_deref()),
        complaint_total: comp.total.unwrap_or(0),
        robocall_total: comp.robocalls.unwrap_or(0),
        first_seen: api_leg::clean(comp.first_seen.as_deref()),
        last_seen: api_leg::clean(comp.last_seen.as_deref()),
        states_reporting: comp.states_reporting.unwrap_or(0),
        raw_answer: whole.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Recorded from `https://www.usacallerlookup.com/wp-json/ucl/v1/number/6282017751` on 2026-10-16.
    const RECORDED: &str = r#"{
        "phone":"628-201-7751",
        "digits":"6282017751",
        "toll_free":false,
        "location":{"city":"San Francisco","state":"CA","carrier":"ONVOY, LLC - CA"},
        "complaints":{"total":9,"robocalls":4,"first_seen":"2026-07-14","last_seen":"2026-08-19","states_reporting":4}
    }"#;

    #[test]
    fn a_recorded_answer_keeps_carrier_location_and_complaints() {
        let p = decode(RECORDED.as_bytes()).unwrap();
        assert_eq!(p.carrier.as_deref(), Some("ONVOY, LLC - CA"));
        assert_eq!(p.city.as_deref(), Some("San Francisco"));
        assert_eq!(p.state.as_deref(), Some("CA"));
        assert_eq!(p.complaint_total, 9);
        assert_eq!(p.robocall_total, 4);
        assert_eq!(p.first_seen.as_deref(), Some("2026-07-14"));
        assert_eq!(p.last_seen.as_deref(), Some("2026-08-19"));
        assert_eq!(p.states_reporting, 4);
        assert!(p.raw_answer.contains("ONVOY"));
    }

    #[test]
    fn only_us_nanp_builds_a_url() {
        assert!(url("+14155552671").is_some());
        assert!(url("+61412345678").is_none());
        assert!(url("+442071838750").is_none());
    }
}
