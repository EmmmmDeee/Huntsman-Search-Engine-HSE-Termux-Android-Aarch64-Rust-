//! Pulsedive: community threat-intelligence risk for one IP or domain.
//!
//! One lookup is one `GET https://pulsedive.com/api/info.php?indicator={value}`. Pulsedive
//! answers without a key at a low limit; with `HUNTSMAN_PULSEDIVE_KEY` set the key goes in the
//! `key` query parameter (added as the request is sent) and the limit is the account's. The
//! answer is Pulsedive's overall risk, the risk factors behind it, linked threats and feeds, and
//! the ports, protocols and technologies it has seen. A `404` `Indicator not found.` is a valid
//! zero.

use serde::Deserialize;

use crate::api_leg::{self, Answer, Api, KeyPlace, KeyUse, LegError};
use crate::http::{Transport, percent_encode_component};
use crate::indicator_sources::{Finding, Indicator, PivotKind, Source};
use crate::keys::Keys;
use crate::tags;

pub const SOURCE: &str = "pulsedive";
pub const KEY_SLOT: &str = crate::environment::PULSEDIVE_KEY_ENV;
pub const API: Api = Api {
    source: SOURCE,
    provider: "pulsedive.com",
    origin: "https://pulsedive.com:443",
    key: Some(KeyUse {
        slot: KEY_SLOT,
        place: KeyPlace::Query("key"),
        required: false,
    }),
};
pub const INTEL: Source = Source {
    api: &API,
    ip: true,
    domain: true,
    lookup,
};
/// Most threat, feed and risk-factor names kept in one attribute.
const MAX_NAMES: usize = 10;

#[derive(Deserialize)]
struct Body {
    indicator: String,
    risk: String,
    #[serde(default)]
    risk_recommended: Option<String>,
    #[serde(default)]
    retired: Option<String>,
    #[serde(default)]
    stamp_seen: Option<String>,
    #[serde(default)]
    umbrella_rank: Option<u64>,
    #[serde(default)]
    umbrella_domain: Option<String>,
    #[serde(default)]
    riskfactors: Vec<Named>,
    #[serde(default)]
    threats: Vec<Named>,
    #[serde(default)]
    feeds: Vec<Named>,
    #[serde(default)]
    attributes: Option<Attributes>,
}

#[derive(Deserialize)]
struct Named {
    #[serde(default, alias = "description")]
    name: Option<String>,
}

#[derive(Deserialize, Default)]
struct Attributes {
    #[serde(default)]
    port: Vec<String>,
    #[serde(default)]
    protocol: Vec<String>,
    #[serde(default)]
    technology: Vec<String>,
}

/// The request URL for `indicator`. **Pure.**
#[must_use]
pub fn url(indicator: Indicator<'_>) -> String {
    format!(
        "https://pulsedive.com/api/info.php?indicator={}",
        percent_encode_component(indicator.value())
    )
}

/// Look `indicator` up.
///
/// # Errors
/// The [`LegError`] that stopped the lookup.
pub fn lookup(
    transport: &dyn Transport,
    keys: &Keys,
    indicator: Indicator<'_>,
    now_unix: u64,
) -> Result<Option<Finding>, LegError> {
    decode(
        api_leg::get(transport, &API, keys, &url(indicator), now_unix)?,
        indicator,
    )
}

fn names(items: &[Named]) -> Vec<String> {
    items
        .iter()
        .filter_map(|n| api_leg::clean(n.name.as_deref()))
        .take(MAX_NAMES)
        .collect()
}

/// One answer for `indicator`. **Pure.**
///
/// # Errors
/// [`LegError::Decode`] for a body that is not the documented shape or is about something else.
pub fn decode(answer: Answer, indicator: Indicator<'_>) -> Result<Option<Finding>, LegError> {
    let body = match answer {
        Answer::NotFound(_) => return Ok(None),
        Answer::Body(body) => body,
    };
    let body: Body = api_leg::decode(&body)?;
    if !body.indicator.eq_ignore_ascii_case(indicator.value()) {
        return Err(LegError::Decode("answer names another indicator".into()));
    }
    let risk = api_leg::clean(Some(&body.risk)).unwrap_or_else(|| "unknown".into());
    let attributes = body.attributes.unwrap_or_default();
    let mut finding = Finding::new(format!(
        "Pulsedive: risk {risk}, {} linked threat(s), {} feed(s)",
        body.threats.len(),
        body.feeds.len()
    ))
    .attr("risk", &risk)
    .opt_attr("risk_recommended", body.risk_recommended.as_deref())
    .list_attr("threats", &names(&body.threats))
    .list_attr("feeds", &names(&body.feeds))
    .list_attr("risk_factors", &names(&body.riskfactors))
    .list_attr("ports", &attributes.port)
    .list_attr("protocols", &attributes.protocol)
    .list_attr("technologies", &attributes.technology)
    .opt_attr("last_seen", body.stamp_seen.as_deref())
    .opt_attr("retired", body.retired.as_deref())
    .opt_attr("umbrella_rank", body.umbrella_rank.map(|r| r.to_string()))
    .tag_if(
        matches!(risk.as_str(), "high" | "critical"),
        tags::MALICIOUS,
    )
    .tag_if(risk == "medium", "suspicious");
    if let Some(domain) = body.umbrella_domain.as_deref() {
        if !domain.eq_ignore_ascii_case(indicator.value()) {
            finding = finding.pivot(
                PivotKind::Domain,
                domain,
                "Domain Pulsedive ranks for the indicator",
            );
        }
    }
    Ok(Some(finding))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Recorded without a key for `1.1.1.1` on 2026-10-14 (lists trimmed).
    const IP: &str = r#"{"iid":100939,"indicator":"1.1.1.1","type":"ip","risk":"none","risk_recommended":"none","manualrisk":0,"retired":null,"stamp_seen":"2026-10-14 08:09:58","umbrella_rank":2810,"umbrella_domain":"one.one.one.one","riskfactors":[{"rfid":60,"description":"found in threat feeds","risk":"medium"},{"rfid":50,"description":"hosted on common ISP","risk":"none"}],"threats":[{"tid":90,"name":"Adware","category":"pup","risk":"low","stamp_linked":"2020-04-05 19:32:53"},{"tid":305,"name":"LDAP DDoS","category":"attack","risk":"unknown","stamp_linked":"2018-12-11 19:24:14"}],"feeds":[{"fid":11,"name":"Bad IPs","category":"attack","organization":"badIPs","pricing":"free","stamp_linked":"2018-07-15 22:11:56"}],"attributes":{"hosttype":["Name Server"],"port":["443","53"],"protocol":["DNS","HTTPS"],"technology":["CloudFlare"]}}"#;
    /// Recorded without a key for an unknown domain on 2026-10-14 (HTTP 404).
    const NOT_FOUND: &str = r#"{"error":"Indicator not found."}"#;

    #[test]
    fn a_recorded_answer_keeps_risk_threats_and_the_ranked_domain() {
        let finding = decode(Answer::Body(IP.into()), Indicator::Ip("1.1.1.1"))
            .ok()
            .flatten()
            .unwrap_or_else(|| panic!("recorded body must decode"));
        assert!(
            finding
                .summary
                .contains("risk none, 2 linked threat(s), 1 feed(s)")
        );
        assert!(
            finding
                .attrs
                .contains(&("threats", "Adware,LDAP DDoS".into()))
        );
        assert!(finding.attrs.contains(&(
            "risk_factors",
            "found in threat feeds,hosted on common ISP".into()
        )));
        assert!(finding.attrs.contains(&("ports", "443,53".into())));
        assert!(finding.tags.is_empty(), "risk none is not malicious");
        assert_eq!(finding.pivots.len(), 1);
        assert_eq!(finding.pivots[0].value, "one.one.one.one");
    }

    #[test]
    fn high_risk_is_malicious() {
        let body = IP.replace(
            r#""risk":"none","risk_recommended""#,
            r#""risk":"high","risk_recommended""#,
        );
        let finding = decode(Answer::Body(body.into()), Indicator::Ip("1.1.1.1"))
            .ok()
            .flatten()
            .unwrap_or_else(|| panic!("must decode"));
        assert_eq!(finding.tags, [tags::MALICIOUS]);
    }

    #[test]
    fn not_found_is_a_valid_zero_and_another_indicator_is_refused() {
        assert_eq!(
            decode(
                Answer::NotFound(NOT_FOUND.into()),
                Indicator::Domain("zz.example")
            ),
            Ok(None)
        );
        assert!(decode(Answer::Body(IP.into()), Indicator::Ip("8.8.8.8")).is_err());
    }
}
