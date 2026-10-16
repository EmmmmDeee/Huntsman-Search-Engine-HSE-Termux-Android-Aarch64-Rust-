//! Tellows: keyless phone reputation score.
//!
//! One lookup is one `GET https://www.tellows.de/basic/num/{e164}?json=1`.
//! No key. Returns the community score (1 trustworthy to 9 dubious), search and comment counts,
//! location, and caller type when reported. A number with no reports still returns a score.
//!
//! Runs alongside Numverify and USACallerLookup. Everything the answer holds is kept as `raw_answer`.

use serde::Deserialize;

use crate::api_leg::{self, Answer, Api, LegError};
use crate::http::Transport;
use crate::keys::Keys;

pub const SOURCE: &str = "tellows";
pub const API: Api = Api {
    source: SOURCE,
    provider: "tellows.de",
    origin: "https://www.tellows.de:443",
    key: None,
};

/// What Tellows says about one number.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Score {
    pub number: String,
    pub score: u8,
    pub searches: u64,
    pub comments: u64,
    pub location: Option<String>,
    pub country: Option<String>,
    pub caller_type: Option<String>,
    pub raw_answer: String,
}

#[derive(Deserialize)]
struct Body {
    #[serde(default)]
    tellows: Option<Tellows>,
}

#[derive(Deserialize)]
struct Tellows {
    #[serde(default)]
    number: Option<String>,
    #[serde(default)]
    score: Option<String>,
    #[serde(default)]
    searches: Option<String>,
    #[serde(default)]
    comments: Option<String>,
    #[serde(default)]
    location: Option<String>,
    #[serde(default)]
    country: Option<String>,
    #[serde(default)]
    callerTypes: Option<CallerTypes>,
}

#[derive(Deserialize)]
struct CallerTypes {
    #[serde(default)]
    caller: Option<Vec<Caller>>,
}

#[derive(Deserialize)]
struct Caller {
    #[serde(default)]
    name: Option<String>,
}

/// The request URL for an E.164 number. **Pure.**
#[must_use]
pub fn url(e164: &str) -> Option<String> {
    (e164.starts_with('+') && e164.len() > 1)
        .then(|| format!("https://www.tellows.de/basic/num/{e164}?json=1"))
}

/// Look the E.164 number up.
///
/// # Errors
/// The [`LegError`] that stopped the lookup.
pub fn lookup<T: Transport + ?Sized>(
    transport: &T,
    e164: &str,
    now_unix: u64,
) -> Result<Option<Score>, LegError> {
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
pub fn decode(body: &[u8]) -> Result<Score, LegError> {
    let whole: serde_json::Value = api_leg::decode(body)?;
    let body: Body = api_leg::decode(body)?;
    let t = body.tellows.ok_or_else(|| LegError::Decode("no tellows object".into()))?;
    let caller_type = t
        .callerTypes
        .as_ref()
        .and_then(|ct| ct.caller.as_ref())
        .and_then(|c| c.first())
        .and_then(|c| api_leg::clean(c.name.as_deref()));
    Ok(Score {
        number: api_leg::clean(t.number.as_deref()).unwrap_or_default(),
        score: t.score.as_deref().and_then(|s| s.parse().ok()).unwrap_or(0),
        searches: t.searches.as_deref().and_then(|s| s.parse().ok()).unwrap_or(0),
        comments: t.comments.as_deref().and_then(|s| s.parse().ok()).unwrap_or(0),
        location: api_leg::clean(t.location.as_deref()),
        country: api_leg::clean(t.country.as_deref()),
        caller_type,
        raw_answer: whole.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Recorded from `https://www.tellows.de/basic/num/+14155552671?json=1` on 2026-10-16.
    const RECORDED: &str = r#"{
        "tellows":{
            "number":"+14155552671",
            "score":"6",
            "searches":"413",
            "comments":"1",
            "location":"San Francisco, CA",
            "country":"USA, Kanada",
            "callerTypes":{"caller":[{"name":"Inkassounternehmen","count":"1"}]}
        }
    }"#;

    #[test]
    fn a_recorded_answer_keeps_score_location_and_caller_type() {
        let s = decode(RECORDED.as_bytes()).unwrap();
        assert_eq!(s.score, 6);
        assert_eq!(s.searches, 413);
        assert_eq!(s.comments, 1);
        assert_eq!(s.location.as_deref(), Some("San Francisco, CA"));
        assert_eq!(s.caller_type.as_deref(), Some("Inkassounternehmen"));
        assert!(s.raw_answer.contains("Inkassounternehmen"));
    }
}
