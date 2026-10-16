//! Hudson Rock Cavalier: keyless infostealer intelligence.
//!
//! One lookup is one `GET https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-domain?domain={domain}`.
//! No key. Returns infected employee counts and stolen login URLs.
//! Separates infostealer leaks from database breaches.

use crate::api_leg::{self, Answer, Api, LegError};
use crate::http::{Transport, percent_encode_component};
use crate::indicator_sources::{Finding, Indicator, IndicatorKind, Source};
use crate::keys::Keys;

pub const SOURCE: &str = "hudsonrock";
pub const API: Api = Api {
    source: SOURCE,
    provider: "cavalier.hudsonrock.com",
    origin: "https://cavalier.hudsonrock.com:443",
    key: None,
};
pub const INTEL: Source = Source {
    api: &API,
    kinds: &[IndicatorKind::Domain, IndicatorKind::Email],
    lookup,
};

/// The request URL for a domain. **Pure.**
#[must_use]
pub fn url(domain: &str) -> String {
    format!(
        "https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-domain?domain={}",
        percent_encode_component(domain)
    )
}

/// Look the domain up.
///
/// # Errors
/// The [`LegError`] that stopped the lookup.
pub fn lookup(
    transport: &dyn Transport,
    keys: &Keys,
    indicator: Indicator<'_>,
    now_unix: u64,
) -> Result<Option<Finding>, LegError> {
    let domain = match indicator {
        Indicator::Domain(d) => d,
        Indicator::Email(e) => e.split('@').nth(1).unwrap_or(e),
        _ => return Ok(None),
    };
    let url = url(domain);
    match api_leg::get(transport, &API, keys, &url, now_unix)? {
        Answer::Body(body) => decode(&body),
        Answer::NotFound(_) => Ok(None),
    }
}

/// One answer body. **Pure.**
///
/// # Errors
/// [`LegError::Decode`] for a body that is not UTF-8 or not the expected shape.
pub fn decode(body: &[u8]) -> Result<Option<Finding>, LegError> {
    let text =
        std::str::from_utf8(body).map_err(|_| LegError::Decode("answer is not UTF-8".into()))?;
    let value: serde_json::Value =
        serde_json::from_str(text).map_err(|_| LegError::Decode("answer is not JSON".into()))?;
    let employees = value
        .get("total_employees")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(0);
    let users = value
        .get("total_users")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(0);
    if employees == 0 && users == 0 {
        return Ok(None);
    }
    let mut finding = Finding::new(format!("Hudson Rock: {employees} employees, {users} users"))
        .attr("employees", employees.to_string())
        .attr("users", users.to_string())
        .attr("raw_answer", text);
    if let Some(stealers) = value.get("stealers").and_then(|v| v.as_array()) {
        finding = finding.attr("stealers", stealers.len().to_string());
    }
    Ok(Some(finding))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_count_is_kept() {
        let body = br#"{"total_employees":5,"total_users":10,"stealers":[]}"#;
        let f = decode(body).unwrap().unwrap();
        assert!(f.summary.contains('5'));
    }

    #[test]
    fn a_zero_is_none() {
        assert!(
            decode(br#"{"total_employees":0,"total_users":0}"#)
                .unwrap()
                .is_none()
        );
    }
}
