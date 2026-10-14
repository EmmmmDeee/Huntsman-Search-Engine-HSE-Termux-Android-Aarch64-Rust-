//! `LeakIX`: exposed services and data leaks found on one IP or domain.
//!
//! One lookup is one `GET https://leakix.net/host/{ip}` or `GET https://leakix.net/domain/{domain}`
//! with the key in the `api-key` header, run whenever `HUNTSMAN_LEAKIX_KEY` is set. The answer is
//! two lists of `l9format` events, `Services` and `Leaks`. Only the event plugin, host, address,
//! port, protocol, software and leak severity, type and row count leave the module: an event's
//! `service.credentials` (which can hold a found username or password) is never decoded. A `404`
//! is "nothing indexed", a valid zero.

use serde::Deserialize;

use crate::api_leg::{self, Answer, Api, KeyPlace, KeyUse, LegError};
use crate::http::Transport;
use crate::indicator_sources::{Finding, Indicator, IndicatorKind, PivotKind, Source};
use crate::keys::Keys;
use crate::tags;

pub const SOURCE: &str = "leakix";
pub const KEY_SLOT: &str = crate::environment::LEAKIX_KEY_ENV;
pub const API: Api = Api {
    source: SOURCE,
    provider: "leakix.net",
    origin: "https://leakix.net:443",
    key: Some(KeyUse {
        slot: KEY_SLOT,
        place: KeyPlace::Header("api-key"),
        required: true,
    }),
};
pub const INTEL: Source = Source {
    api: &API,
    kinds: &[IndicatorKind::Ip, IndicatorKind::Domain],
    lookup,
};
/// Most distinct names kept in one attribute.
const MAX_NAMES: usize = 15;

#[derive(Deserialize)]
struct Body {
    #[serde(rename = "Services", default)]
    services: Option<Vec<Event>>,
    #[serde(rename = "Leaks", default)]
    leaks: Option<Vec<Event>>,
}

#[derive(Deserialize)]
struct Event {
    #[serde(rename = "event_source", default)]
    plugin: Option<String>,
    #[serde(default)]
    ip: Option<String>,
    #[serde(default)]
    host: Option<String>,
    #[serde(default)]
    port: Option<String>,
    #[serde(default)]
    protocol: Option<String>,
    #[serde(default)]
    service: Option<Service>,
    #[serde(default)]
    leak: Option<Leak>,
}

/// `service.software` only: `service.credentials` is deliberately not a field here.
#[derive(Deserialize)]
struct Service {
    #[serde(default)]
    software: Option<Software>,
}

#[derive(Deserialize)]
struct Software {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    version: Option<String>,
}

#[derive(Deserialize)]
struct Leak {
    #[serde(default)]
    severity: Option<String>,
    #[serde(rename = "type", default)]
    kind: Option<String>,
    #[serde(default)]
    dataset: Option<Dataset>,
}

#[derive(Deserialize)]
struct Dataset {
    #[serde(default)]
    rows: i64,
    #[serde(default)]
    infected: bool,
}

/// The request URL for `indicator`, `None` for a kind this source does not answer. **Pure.**
#[must_use]
pub fn url(indicator: Indicator<'_>) -> Option<String> {
    match indicator {
        Indicator::Ip(ip) => Some(format!("https://leakix.net/host/{ip}")),
        Indicator::Domain(domain) => Some(format!("https://leakix.net/domain/{domain}")),
        Indicator::Email(_) | Indicator::Phone(_) => None,
    }
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
    let Some(url) = url(indicator) else {
        return Ok(None);
    };
    decode(
        api_leg::get(transport, &API, keys, &url, now_unix)?,
        indicator,
    )
}

fn distinct(values: impl Iterator<Item = String>) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for value in values {
        if !out.contains(&value) && out.len() < MAX_NAMES {
            out.push(value);
        }
    }
    out
}

/// One answer for `indicator`. **Pure.**
///
/// # Errors
/// [`LegError::Decode`] for a body that is not the documented shape.
pub fn decode(answer: Answer, indicator: Indicator<'_>) -> Result<Option<Finding>, LegError> {
    let body = match answer {
        Answer::NotFound(_) => return Ok(None),
        Answer::Body(body) => body,
    };
    let body: Body = api_leg::decode(&body)?;
    let services = body.services.unwrap_or_default();
    let leaks = body.leaks.unwrap_or_default();
    if services.is_empty() && leaks.is_empty() {
        return Ok(None);
    }
    let all = || services.iter().chain(&leaks);
    let ports = distinct(all().filter_map(|e| api_leg::clean(e.port.as_deref())));
    let plugins = distinct(all().filter_map(|e| api_leg::clean(e.plugin.as_deref())));
    let software = distinct(services.iter().filter_map(|e| {
        let software = e.service.as_ref()?.software.as_ref()?;
        let name = api_leg::clean(software.name.as_deref())?;
        Some(match api_leg::clean(software.version.as_deref()) {
            Some(version) => format!("{name} {version}"),
            None => name,
        })
    }));
    let protocols = distinct(all().filter_map(|e| api_leg::clean(e.protocol.as_deref())));
    let leak_info = || leaks.iter().filter_map(|e| e.leak.as_ref());
    let severities = distinct(leak_info().filter_map(|l| api_leg::clean(l.severity.as_deref())));
    let leak_types = distinct(leak_info().filter_map(|l| api_leg::clean(l.kind.as_deref())));
    let rows: i64 = leak_info()
        .filter_map(|l| l.dataset.as_ref())
        .map(|d| d.rows.max(0))
        .sum();
    let infected = leak_info().any(|l| l.dataset.as_ref().is_some_and(|d| d.infected));
    let serious = severities.iter().any(|s| s == "critical" || s == "high");

    let mut finding = Finding::new(format!(
        "LeakIX: {} exposed service(s), {} leak(s)",
        services.len(),
        leaks.len()
    ))
    .attr("services", services.len().to_string())
    .attr("leaks", leaks.len().to_string())
    .list_attr("ports", &ports)
    .list_attr("protocols", &protocols)
    .list_attr("plugins", &plugins)
    .list_attr("software", &software)
    .list_attr("leak_severities", &severities)
    .list_attr("leak_types", &leak_types)
    .tag_if(!leaks.is_empty(), tags::HIGH_EXPOSURE)
    .tag_if(serious || infected, tags::VULNERABLE);
    if rows > 0 {
        finding = finding.attr("leaked_rows", rows.to_string());
    }
    if infected {
        finding = finding.attr("ransomed", "true");
    }
    for event in all() {
        if let Some(host) = event.host.as_deref() {
            if !host.eq_ignore_ascii_case(indicator.value()) {
                finding = finding.pivot(
                    PivotKind::Domain,
                    host,
                    "Host LeakIX indexed with the indicator",
                );
            }
        }
        if let (Indicator::Domain(_), Some(ip)) = (indicator, event.ip.as_deref()) {
            finding = finding.pivot(PivotKind::Ip, ip, "Address LeakIX indexed for the domain");
        }
    }
    Ok(Some(finding))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An `l9format` host answer built from the published `L9Event` schema: one service and one
    /// leak whose service carries credentials, which must never be decoded or kept.
    const HOST: &str = r#"{"Services":[{"event_type":"service","event_source":"HttpPlugin","ip":"198.51.100.7","host":"files.example.com","port":"443","protocol":"https","service":{"credentials":{"noauth":false,"username":"admin","password":"hunter2-leaked"},"software":{"name":"nginx","version":"1.18.0"}},"leak":{"severity":"","type":"","dataset":{"rows":0}},"time":"2026-10-01T00:00:00Z"}],"Leaks":[{"event_type":"leak","event_source":"ElasticSearchOpenPlugin","ip":"198.51.100.7","host":"","port":"9200","protocol":"http","leak":{"stage":"open","type":"open_database","severity":"high","dataset":{"rows":120000,"infected":true,"ransom_notes":["read_me"]}},"time":"2026-10-02T00:00:00Z"}]}"#;

    fn finding(body: &str, indicator: Indicator<'_>) -> Finding {
        decode(Answer::Body(body.into()), indicator)
            .ok()
            .flatten()
            .unwrap_or_else(|| panic!("fixture must decode"))
    }

    #[test]
    fn services_and_leaks_are_summarised_without_credentials() {
        let f = finding(HOST, Indicator::Ip("198.51.100.7"));
        assert!(f.summary.contains("1 exposed service(s), 1 leak(s)"));
        assert!(f.attrs.contains(&("ports", "443,9200".into())));
        assert!(f.attrs.contains(&("software", "nginx 1.18.0".into())));
        assert!(f.attrs.contains(&("leak_severities", "high".into())));
        assert!(f.attrs.contains(&("leaked_rows", "120000".into())));
        assert_eq!(f.tags, [tags::HIGH_EXPOSURE, tags::VULNERABLE]);
        let text = format!("{f:?}");
        assert!(
            !text.contains("hunter2") && !text.contains("admin"),
            "{text}"
        );
        assert_eq!(f.pivots.len(), 1);
        assert_eq!(f.pivots[0].value, "files.example.com");
    }

    #[test]
    fn a_domain_lookup_pivots_to_addresses() {
        let f = finding(HOST, Indicator::Domain("example.com"));
        assert!(
            f.pivots
                .iter()
                .any(|p| p.kind == PivotKind::Ip && p.value == "198.51.100.7")
        );
    }

    #[test]
    fn empty_lists_and_404_are_valid_zeros() {
        for body in [
            r#"{"Services":null,"Leaks":null}"#,
            r#"{"Services":[],"Leaks":[]}"#,
        ] {
            assert_eq!(
                decode(Answer::Body(body.into()), Indicator::Ip("1.1.1.1")),
                Ok(None)
            );
        }
        assert_eq!(
            decode(Answer::NotFound(Vec::new()), Indicator::Ip("1.1.1.1")),
            Ok(None)
        );
        assert!(
            decode(
                Answer::Body(br#""Invalid API key""#.to_vec()),
                Indicator::Ip("1.1.1.1")
            )
            .is_err()
        );
    }
}
