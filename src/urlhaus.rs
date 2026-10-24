//! abuse.ch `URLhaus`: malware-distribution URLs hosted on one IPv4 address or domain.
//!
//! One lookup is one form `POST https://urlhaus-api.abuse.ch/v1/host/` with `host={indicator}` and
//! the abuse.ch key in the `Auth-Key` header, run whenever `HUNTSMAN_ABUSECH_KEY` is set (the same
//! free abuse.ch Auth-Key `ThreatFox` uses). The API reference defines `host` as an IPv4 address,
//! host name or domain name, so the source answers for IPv4 addresses and domains only.
//! `no_results` is a valid zero; any other status than `ok` is an error, never a zero. An `ok`
//! answer must name the host it is about and list its URLs; one that does not is drift, never a
//! finding. Everything an answer lists is kept: every hosted URL with its id, `URLhaus` page,
//! status, threat, tags, reporter and dates, the host's page and every blocklist verdict, and the
//! whole answer as `raw_answer`.

use serde::Deserialize;

use crate::api_leg::{self, Answer, Api, KeyPlace, KeyUse, LegError};
use crate::http::Transport;
use crate::indicator_sources::{Finding, Indicator, IndicatorKind, Source};
use crate::keys::Keys;
use crate::tags;

pub const SOURCE: &str = "urlhaus";
pub const KEY_SLOT: &str = crate::environment::ABUSECH_KEY_ENV;
pub const URL: &str = "https://urlhaus-api.abuse.ch/v1/host/";
pub const API: Api = Api {
    source: SOURCE,
    provider: "abuse.ch",
    origin: "https://urlhaus-api.abuse.ch:443",
    key: Some(KeyUse {
        slot: KEY_SLOT,
        place: KeyPlace::Header("Auth-Key"),
        required: true,
    }),
};
pub const INTEL: Source = Source {
    api: &API,
    kinds: &[IndicatorKind::Ipv4, IndicatorKind::Domain],
    lookup,
};
#[derive(Deserialize)]
struct Body {
    query_status: String,
    #[serde(default)]
    host: Option<String>,
    #[serde(default)]
    urlhaus_reference: Option<String>,
    #[serde(default)]
    firstseen: Option<String>,
    #[serde(default)]
    url_count: Option<serde_json::Value>,
    #[serde(default)]
    blacklists: Option<serde_json::Map<String, serde_json::Value>>,
    #[serde(default)]
    urls: Option<Vec<Hosted>>,
}

#[derive(Deserialize)]
struct Hosted {
    #[serde(default)]
    id: Option<serde_json::Value>,
    #[serde(default)]
    url: Option<String>,
    #[serde(default)]
    urlhaus_reference: Option<String>,
    #[serde(default)]
    reporter: Option<String>,
    #[serde(default)]
    url_status: Option<String>,
    #[serde(default)]
    threat: Option<String>,
    #[serde(default)]
    tags: Option<Vec<String>>,
    #[serde(default)]
    date_added: Option<String>,
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
    match api_leg::post_form(
        transport,
        &API,
        keys,
        URL,
        &[("host", indicator.value())],
        now_unix,
    )? {
        Answer::Body(body) => decode(&body, indicator),
        Answer::NotFound(_) => Err(LegError::Unexpected(404)),
    }
}

fn distinct<'a>(values: impl Iterator<Item = &'a str>) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for value in values.filter_map(|v| api_leg::clean(Some(v))) {
        if !out.contains(&value) {
            out.push(value);
        }
    }
    out
}

/// One answer body for `indicator`. **Pure.**
///
/// # Errors
/// [`LegError::Decode`] for another shape, another or no host, no URL list, or a status other
/// than `ok` or `no_results`.
pub fn decode(body: &[u8], indicator: Indicator<'_>) -> Result<Option<Finding>, LegError> {
    let whole: serde_json::Value = api_leg::decode(body)?;
    let body: Body = api_leg::decode(body)?;
    match body.query_status.as_str() {
        "ok" => {}
        "no_results" => return Ok(None),
        other => {
            return Err(LegError::Decode(format!(
                "query_status {}",
                api_leg::clean(Some(other)).unwrap_or_default()
            )));
        }
    }
    match body.host.as_deref() {
        Some(host) if host.eq_ignore_ascii_case(indicator.value()) => {}
        Some(_) => return Err(LegError::Decode("answer names another host".into())),
        None => return Err(LegError::Decode("an ok answer names no host".into())),
    }
    let Some(urls) = body.urls else {
        return Err(LegError::Decode("an ok answer lists no urls".into()));
    };
    let count = body
        .url_count
        .as_ref()
        .and_then(api_leg::scalar)
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(urls.len() as u64);
    let online = urls
        .iter()
        .filter(|u| u.url_status.as_deref() == Some("online"))
        .count();
    let threats = distinct(urls.iter().filter_map(|u| u.threat.as_deref()));
    let malware = distinct(
        urls.iter()
            .flat_map(|u| u.tags.iter().flatten())
            .map(String::as_str),
    );
    let last = urls.iter().filter_map(|u| u.date_added.as_deref()).max();
    let listed: Vec<String> = body
        .blacklists
        .iter()
        .flatten()
        .filter(|(_, v)| v.as_str().is_some_and(|s| s != "not listed"))
        .map(|(k, _)| k.clone())
        .collect();
    let verdicts: Vec<String> = body
        .blacklists
        .iter()
        .flatten()
        .filter_map(|(list, verdict)| Some(format!("{list}: {}", verdict.as_str()?)))
        .collect();
    let id_text: Vec<String> = urls
        .iter()
        .filter_map(|u| u.id.as_ref().and_then(api_leg::scalar))
        .collect();
    let ids = distinct(id_text.iter().map(String::as_str));
    let first_added = urls.iter().filter_map(|u| u.date_added.as_deref()).min();
    let mut finding = Finding::new(format!("URLhaus: {count} malware URL(s), {online} online"))
        .attr("url_count", count.to_string())
        .attr("online_urls", online.to_string())
        .list_attr("threats", &threats)
        .list_attr("malware_tags", &malware)
        .list_attr("blocklists", &listed)
        .list_attr("url_ids", &ids)
        .list_attr(
            "reporters",
            &distinct(urls.iter().filter_map(|u| u.reporter.as_deref())),
        )
        .opt_attr("first_seen", body.firstseen.as_deref())
        .opt_attr("first_added", first_added)
        .opt_attr("last_added", last)
        .opt_attr("reference", body.urlhaus_reference.as_deref())
        .tag(tags::MALICIOUS);
    for verdict in &verdicts {
        finding = finding.attr("blocklist_verdicts", verdict);
    }
    // A URL can hold a comma, so each is its own value rather than a joined list.
    for url in distinct(urls.iter().filter_map(|u| u.url.as_deref())) {
        finding = finding.attr("urls", url);
    }
    for page in distinct(urls.iter().filter_map(|u| u.urlhaus_reference.as_deref())) {
        finding = finding.attr("url_references", page);
    }
    Ok(Some(finding.attr("raw_answer", whole.to_string())))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The documented `host` answer shape (`URLhaus` API reference), two URLs.
    const DOCUMENTED: &str = r#"{"query_status":"ok","urlhaus_reference":"https://urlhaus.abuse.ch/host/vektorex.com/","host":"vektorex.com","firstseen":"2019-01-15 07:09:01 UTC","url_count":"2","blacklists":{"spamhaus_dbl":"abused_legit_malware","surbl":"not listed"},"urls":[{"id":"121319","urlhaus_reference":"https://urlhaus.abuse.ch/url/121319/","url":"http://vektorex.com/source/Z/Order%20specification.doc","url_status":"offline","date_added":"2019-01-22 03:29:03 UTC","threat":"malware_download","reporter":"abuse_ch","larted":"true","takedown_time_seconds":null,"tags":["doc","emotet"]},{"id":"121320","url":"http://vektorex.com/x.exe","url_status":"online","date_added":"2019-01-23 01:00:00 UTC","threat":"malware_download","tags":null}]}"#;

    #[test]
    fn the_documented_answer_counts_urls_and_listings() {
        let f = decode(DOCUMENTED.as_bytes(), Indicator::Domain("vektorex.com"))
            .ok()
            .flatten()
            .unwrap_or_else(|| panic!("documented body must decode"));
        assert_eq!(f.summary, "URLhaus: 2 malware URL(s), 1 online");
        assert!(f.attrs.contains(&("malware_tags", "doc,emotet".into())));
        assert!(f.attrs.contains(&("blocklists", "spamhaus_dbl".into())));
        assert_eq!(f.tags, [tags::MALICIOUS]);
    }

    #[test]
    fn padded_and_blank_ids_and_a_padded_count_read_as_their_values() {
        let body = r#"{"query_status":"ok","host":"vektorex.com","url_count":" 120 ","urls":[{"id":""},{"id":" 121320 "},{"id":121320}]}"#;
        let f = decode(body.as_bytes(), Indicator::Domain("vektorex.com"))
            .ok()
            .flatten()
            .unwrap_or_else(|| panic!("body must decode"));
        assert!(
            f.attrs.contains(&("url_ids", "121320".into())),
            "{:?}",
            f.attrs
        );
        assert!(
            f.attrs.contains(&("url_count", "120".into())),
            "{:?}",
            f.attrs
        );
    }

    #[test]
    fn no_results_is_a_zero_and_other_statuses_are_errors() {
        let none = br#"{"query_status":"no_results"}"#;
        assert_eq!(decode(none, Indicator::Ip("1.1.1.1")), Ok(None));
        assert!(
            decode(
                br#"{"query_status":"invalid_host"}"#,
                Indicator::Ip("1.1.1.1")
            )
            .is_err()
        );
        assert!(decode(DOCUMENTED.as_bytes(), Indicator::Domain("example.com")).is_err());
    }

    #[test]
    fn an_ok_answer_without_its_host_or_urls_is_drift_not_a_malicious_finding() {
        for body in [
            r#"{"query_status":"ok"}"#,
            r#"{"query_status":"ok","urls":[]}"#,
            r#"{"query_status":"ok","host":"vektorex.com"}"#,
            r#"{"query_status":"ok","host":"vektorex.com","urls":null}"#,
        ] {
            let got = decode(body.as_bytes(), Indicator::Domain("vektorex.com"));
            assert!(matches!(got, Err(LegError::Decode(_))), "{body}: {got:?}");
        }
    }
}
