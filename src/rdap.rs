//! Domain registration data over RDAP (RFC 9082/9083), the registries' JSON successor to WHOIS.
//!
//! Keyless and authoritative: the IANA bootstrap registry (`data.iana.org/rdap/dns.json`,
//! RFC 9224) names the RDAP service for the domain's TLD, then `GET {service}domain/{name}`.
//! Both requests go through the guarded fetch layer with redirects off, so nothing is followed to
//! an origin the bootstrap did not name. The registrar becomes an `Organisation` tagged
//! `registrar`, each nameserver a `Domain`; registration, expiration and status ride on the
//! evidence. RDAP 404 means the name is not registered: a definitive zero, not a failure.

use std::time::Duration;

use serde::Deserialize;

use crate::entity::{Entity, EntityKind, Evidence, EvidenceProvenance};
use crate::fetch::{FetchOptions, fetch};
use crate::http::{Request, Response, Transport};
use crate::source_outcome::SourceOutcomeKind;

pub const SOURCE: &str = "rdap";
const BOOTSTRAP: &str = "https://data.iana.org/rdap/dns.json";
const TIMEOUT: Duration = Duration::from_secs(20);
/// Tag on the registrar organisation, so `sf` can report it as `DOMAIN_REGISTRAR`.
pub const REGISTRAR_TAG: &str = "registrar";

/// A failure in the shared outcome taxonomy, with the HTTP status when one came.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Failure {
    pub kind: SourceOutcomeKind,
    pub http_status: Option<u16>,
    pub detail: String,
}

/// One RDAP domain record.
#[derive(Debug, Clone, PartialEq)]
pub struct Report {
    /// False when the registry answered 404: the name is not registered.
    pub registered: bool,
    pub entities: Vec<Entity>,
}

#[derive(Debug, Deserialize)]
struct Bootstrap {
    services: Vec<(Vec<String>, Vec<String>)>,
}

#[derive(Debug, Default, Deserialize)]
struct DomainObject {
    #[serde(rename = "ldhName", default)]
    ldh_name: Option<String>,
    #[serde(default)]
    events: Vec<RdapEvent>,
    #[serde(default)]
    entities: Vec<RdapEntity>,
    #[serde(default)]
    nameservers: Vec<Nameserver>,
    #[serde(default)]
    status: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct RdapEvent {
    #[serde(rename = "eventAction")]
    action: String,
    #[serde(rename = "eventDate", default)]
    date: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RdapEntity {
    #[serde(default)]
    roles: Vec<String>,
    #[serde(rename = "vcardArray", default)]
    vcard: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
struct Nameserver {
    #[serde(rename = "ldhName", default)]
    ldh_name: Option<String>,
}

/// The RDAP service base URL for `domain` from a bootstrap document: the entry whose TLD is the
/// longest dot-aligned suffix of the name. **Pure.**
fn service_for(bootstrap: &Bootstrap, domain: &str) -> Option<String> {
    let mut best: Option<(&str, &str)> = None;
    for (tlds, urls) in &bootstrap.services {
        let Some(url) = urls
            .iter()
            .find(|url| url.starts_with("https://"))
            .or_else(|| urls.first())
        else {
            continue;
        };
        for tld in tlds {
            let tld = tld.trim_matches('.');
            let matches = domain == tld || domain.ends_with(&format!(".{tld}"));
            if matches && best.is_none_or(|(current, _)| tld.len() > current.len()) {
                best = Some((tld, url));
            }
        }
    }
    best.map(|(_, url)| {
        if url.ends_with('/') {
            url.to_owned()
        } else {
            format!("{url}/")
        }
    })
}

/// The `fn` (formatted name) of a jCard, the RFC 7095 shape RDAP uses. **Pure.**
fn vcard_name(vcard: &serde_json::Value) -> Option<String> {
    vcard
        .get(1)?
        .as_array()?
        .iter()
        .find(|property| property.get(0).and_then(serde_json::Value::as_str) == Some("fn"))?
        .get(3)?
        .as_str()
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .map(str::to_owned)
}

fn get<T: Transport + ?Sized>(transport: &T, url: &str, accept: &str) -> Result<Response, Failure> {
    let fetched = fetch(
        transport,
        Request::get(url)
            .header("Accept", accept)
            .with_timeout(TIMEOUT),
        None,
        &FetchOptions::no_redirects(),
        SOURCE,
        0,
    )
    .map_err(|e| Failure {
        kind: SourceOutcomeKind::Inconclusive,
        http_status: None,
        detail: e.to_string(),
    })?;
    let Some(response) = fetched.response else {
        return Err(Failure {
            kind: fetched.outcome.kind,
            http_status: None,
            detail: fetched
                .outcome
                .detail
                .unwrap_or_else(|| "no response".into()),
        });
    };
    if crate::classify::is_challenge(&response.text()) {
        return Err(Failure {
            kind: SourceOutcomeKind::BotWaf,
            http_status: Some(response.status),
            detail: "challenge page".into(),
        });
    }
    if response.truncated {
        return Err(Failure {
            kind: SourceOutcomeKind::Inconclusive,
            http_status: Some(response.status),
            detail: "truncated body".into(),
        });
    }
    Ok(response)
}

fn status_failure(response: &Response) -> Failure {
    let kind = match response.status {
        429 => SourceOutcomeKind::RateLimited,
        300..=399 => SourceOutcomeKind::RedirectChanged,
        500.. => SourceOutcomeKind::Upstream5xx,
        _ => SourceOutcomeKind::Upstream4xx,
    };
    Failure {
        kind,
        http_status: Some(response.status),
        detail: format!("HTTP {}", response.status),
    }
}

fn decode<D: serde::de::DeserializeOwned>(response: &Response, what: &str) -> Result<D, Failure> {
    crate::http::parse_json_body(response).map_err(|e| Failure {
        kind: SourceOutcomeKind::SchemaDrift,
        http_status: Some(response.status),
        detail: format!("not an RDAP {what}: {e}"),
    })
}

/// Look up `domain`'s registration through its TLD's RDAP service.
///
/// # Errors
/// [`Failure`] when the bootstrap or the registry gave no usable answer, or the TLD has no RDAP
/// service in the bootstrap (`EntitlementDenied`: there is nothing to query, not an outage).
pub fn lookup<T: Transport + ?Sized>(
    transport: &T,
    domain: &str,
    scan_id: &str,
) -> Result<Report, Failure> {
    let domain = domain.trim().trim_end_matches('.').to_ascii_lowercase();
    let bootstrap = get(transport, BOOTSTRAP, "application/json")?;
    if !(200..300).contains(&bootstrap.status) {
        return Err(status_failure(&bootstrap));
    }
    let bootstrap: Bootstrap = decode(&bootstrap, "bootstrap registry")?;
    let Some(service) = service_for(&bootstrap, &domain) else {
        return Err(Failure {
            kind: SourceOutcomeKind::EntitlementDenied,
            http_status: None,
            detail: format!("no RDAP service for {domain} in the IANA bootstrap"),
        });
    };
    let url = format!("{service}domain/{domain}");
    let response = get(transport, &url, "application/rdap+json, application/json")?;
    if response.status == 404 {
        return Ok(Report {
            registered: false,
            entities: Vec::new(),
        });
    }
    if !(200..300).contains(&response.status) {
        return Err(status_failure(&response));
    }
    let record: DomainObject = decode(&response, "domain object")?;
    Ok(Report {
        registered: true,
        entities: build_entities(&record, &domain, &url, scan_id),
    })
}

/// Registrar and nameserver entities from one domain object. **Pure.**
fn build_entities(record: &DomainObject, domain: &str, url: &str, scan_id: &str) -> Vec<Entity> {
    let date = |action: &str| {
        record
            .events
            .iter()
            .find(|event| event.action.eq_ignore_ascii_case(action))
            .and_then(|event| event.date.clone())
            .unwrap_or_default()
    };
    let (registered, expires, changed) = (
        date("registration"),
        date("expiration"),
        date("last changed"),
    );
    let status = record.status.join(", ");
    let name = record
        .ldh_name
        .as_deref()
        .map_or_else(|| domain.to_owned(), str::to_ascii_lowercase);
    let evidence = |summary: String| {
        Evidence::new(EvidenceProvenance::for_scan(SOURCE, scan_id), summary)
            .with_attr("domain", &name)
            .with_attr("registered", &registered)
            .with_attr("expires", &expires)
            .with_attr("last_changed", &changed)
            .with_attr("status", &status)
            .with_attr("rdap_url", url)
    };

    let mut out = Vec::new();
    for entity in &record.entities {
        if !entity
            .roles
            .iter()
            .any(|role| role.eq_ignore_ascii_case("registrar"))
        {
            continue;
        }
        let Some(registrar) = entity.vcard.as_ref().and_then(vcard_name) else {
            continue;
        };
        let mut org = Entity::new(EntityKind::Organisation, &registrar, 0.9, scan_id);
        org.tag(REGISTRAR_TAG);
        org.add_evidence(evidence(format!(
            "{name} registrar {registrar} (registered {registered}, expires {expires})"
        )));
        out.push(org);
    }
    for server in &record.nameservers {
        let Some(host) = server
            .ldh_name
            .as_deref()
            .and_then(|host| crate::canonical::canonical_domain(host.trim_end_matches('.')))
        else {
            continue;
        };
        let mut ns = Entity::new(EntityKind::Domain, &host, 0.9, scan_id);
        ns.add_evidence(evidence(format!("{name} delegated to nameserver {host}")));
        out.push(ns);
    }
    crate::entity::merge_by_uid(&mut out);
    out
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::collections::VecDeque;

    use super::*;
    use crate::http::TransportFailure;

    struct Fake {
        responses: RefCell<VecDeque<(u16, &'static str)>>,
        urls: RefCell<Vec<String>>,
    }

    impl Fake {
        fn new(responses: &[(u16, &'static str)]) -> Self {
            Self {
                responses: RefCell::new(responses.iter().copied().collect()),
                urls: RefCell::new(Vec::new()),
            }
        }
    }

    impl Transport for Fake {
        fn send(&self, request: &Request) -> Result<Response, TransportFailure> {
            self.urls.borrow_mut().push(request.url.clone());
            self.responses
                .borrow_mut()
                .pop_front()
                .map(|(status, body)| Response {
                    status,
                    headers: Vec::new(),
                    body: body.as_bytes().to_vec(),
                    truncated: false,
                })
                .ok_or_else(|| TransportFailure {
                    kind: SourceOutcomeKind::ConnectFailure,
                    detail: "down".into(),
                    blocked: false,
                })
        }
    }

    const BOOT: &str = r#"{"services":[[["com","net"],["https://rdap.verisign.com/com/v1/"]],[["uk"],["https://rdap.nominet.uk/uk/"]],[["co.uk"],["https://example.test/couk"]]]}"#;

    /// Trimmed from Verisign's live `github.com` answer, 2026-10-13.
    const GITHUB: &str = r#"{"objectClassName":"domain","ldhName":"GITHUB.COM",
        "events":[{"eventAction":"registration","eventDate":"2007-10-09T18:20:50Z"},
                  {"eventAction":"expiration","eventDate":"2026-10-09T18:20:50Z"},
                  {"eventAction":"last changed","eventDate":"2024-09-07T09:16:32Z"}],
        "entities":[{"roles":["registrar"],"vcardArray":["vcard",[["version",{},"text","4.0"],["fn",{},"text","MarkMonitor Inc."]]]}],
        "nameservers":[{"ldhName":"DNS1.P08.NSONE.NET"},{"ldhName":"NS-421.AWSDNS-52.COM"}],
        "status":["client delete prohibited","client transfer prohibited"]}"#;

    #[test]
    fn bootstrap_picks_the_longest_dot_aligned_tld() {
        let boot: Bootstrap = serde_json::from_str(BOOT).unwrap_or(Bootstrap {
            services: Vec::new(),
        });
        assert_eq!(
            service_for(&boot, "github.com").as_deref(),
            Some("https://rdap.verisign.com/com/v1/")
        );
        assert_eq!(
            service_for(&boot, "bbc.co.uk").as_deref(),
            Some("https://example.test/couk/")
        );
        assert_eq!(service_for(&boot, "notcom"), None);
        assert_eq!(service_for(&boot, "example.org"), None);
    }

    #[test]
    fn a_registered_domain_yields_registrar_and_nameservers() {
        let fake = Fake::new(&[(200, BOOT), (200, GITHUB)]);
        let report = lookup(&fake, "GitHub.com.", "s").unwrap_or_else(|f| panic!("{f:?}"));
        assert!(report.registered);
        let urls = fake.urls.borrow();
        assert_eq!(urls[0], BOOTSTRAP);
        assert_eq!(
            urls[1],
            "https://rdap.verisign.com/com/v1/domain/github.com"
        );
        let registrar = report
            .entities
            .iter()
            .find(|e| e.has_tag(REGISTRAR_TAG))
            .unwrap_or_else(|| panic!("{:?}", report.entities));
        assert_eq!(registrar.raw_value, "MarkMonitor Inc.");
        assert!(
            registrar.evidence[0]
                .summary
                .contains("registered 2007-10-09T18:20:50Z")
        );
        let hosts: Vec<&str> = report
            .entities
            .iter()
            .filter(|e| e.kind == EntityKind::Domain)
            .map(|e| e.value.as_str())
            .collect();
        assert_eq!(hosts, vec!["dns1.p08.nsone.net", "ns-421.awsdns-52.com"]);
    }

    #[test]
    fn not_found_is_unregistered_and_failures_are_typed() {
        let fake = Fake::new(&[(200, BOOT), (404, "{}")]);
        let report = lookup(&fake, "no-such-name-zz.com", "s").unwrap_or_else(|f| panic!("{f:?}"));
        assert!(!report.registered && report.entities.is_empty());

        let cases = [
            (
                vec![(200, BOOT), (503, "busy")],
                SourceOutcomeKind::Upstream5xx,
            ),
            (
                vec![(200, BOOT), (429, "{}")],
                SourceOutcomeKind::RateLimited,
            ),
            (
                vec![(200, BOOT), (302, "")],
                SourceOutcomeKind::RedirectChanged,
            ),
            (vec![(200, "not json")], SourceOutcomeKind::SchemaDrift),
            (vec![(200, BOOT)], SourceOutcomeKind::ConnectFailure),
        ];
        for (replies, want) in cases {
            match lookup(&Fake::new(&replies), "github.com", "s") {
                Err(failure) => assert_eq!(failure.kind, want, "{failure:?}"),
                Ok(report) => panic!("{want:?} accepted: {report:?}"),
            }
        }
        match lookup(&Fake::new(&[(200, BOOT)]), "example.org", "s") {
            Err(failure) => assert_eq!(failure.kind, SourceOutcomeKind::EntitlementDenied),
            Ok(report) => panic!("{report:?}"),
        }
    }
}
