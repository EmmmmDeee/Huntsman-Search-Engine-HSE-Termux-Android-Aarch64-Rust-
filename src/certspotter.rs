//! `SSLMate` Cert Spotter certificate-transparency search on the guarded fetch layer.
//!
//! Keyless: `GET https://api.certspotter.com/v1/issuances?domain=…&include_subdomains=true
//! &expand=dns_names`. An independent CT index beside [`crate::crtsh`], so subdomain discovery
//! survives a crt.sh outage. Results are paginated by the last issuance id (`after=`); pages are
//! followed up to [`MAX_PAGES`], and a run that stops at the cap says so (`complete == false`)
//! rather than presenting a partial list as the whole. DNS names are classified against the
//! seed apex by the same [`crate::domains::classify_domain_candidate`] crt.sh uses; wildcard
//! names are skipped. HTTP 429 is a typed rate-limit outcome and is not retried.

use std::collections::BTreeSet;
use std::time::Duration;

use serde::Deserialize;

use crate::entity::{Entity, EntityKind, Evidence, EvidenceProvenance};
use crate::fetch::{FetchOptions, fetch};
use crate::http::{Request, Transport, append_query_param};
use crate::source_outcome::SourceOutcomeKind;
use crate::tags;

pub const SOURCE: &str = "certspotter";
const ENDPOINT: &str = "https://api.certspotter.com/v1/issuances";
const TIMEOUT: Duration = Duration::from_secs(20);
/// Pages followed for one domain; each page holds up to ~100 issuances.
pub const MAX_PAGES: usize = 10;

const SUBDOMAIN_CONFIDENCE: f64 = 0.75;
const EXTERNAL_CONFIDENCE: f64 = 0.45;

#[derive(Debug, Deserialize)]
struct Issuance {
    id: String,
    #[serde(default)]
    dns_names: Vec<String>,
    #[serde(default)]
    not_before: Option<String>,
    #[serde(default)]
    not_after: Option<String>,
    #[serde(default)]
    cert_sha256: Option<String>,
}

/// One Cert Spotter lookup.
#[derive(Debug, Clone, PartialEq)]
pub struct Report {
    pub entities: Vec<Entity>,
    pub pages: usize,
    /// False when [`MAX_PAGES`] stopped pagination before the index ran out.
    pub complete: bool,
}

/// A Cert Spotter failure in the shared outcome taxonomy, with the HTTP status when one came.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Failure {
    pub kind: SourceOutcomeKind,
    pub http_status: Option<u16>,
    pub detail: String,
}

/// Every DNS name certificates for `domain` (and its subdomains) carry.
///
/// # Errors
/// [`Failure`] when no page could be read: refused by egress policy, no response, a challenge
/// page, a non-2xx status (429 is `RateLimited`), a truncated body, or JSON that is not an
/// issuance list. A failure after the first page is also returned, never a silent partial.
pub fn lookup<T: Transport + ?Sized>(
    transport: &T,
    domain: &str,
    scan_id: &str,
) -> Result<Report, Failure> {
    let base = crate::domains::canonical_domain_host(domain)
        .unwrap_or_else(|| domain.trim().trim_end_matches('.').to_ascii_lowercase());
    let mut after: Option<String> = None;
    let mut issuances = Vec::new();
    let mut pages = 0;
    let complete = loop {
        if pages == MAX_PAGES {
            break false;
        }
        let page = fetch_page(transport, &base, after.as_deref())?;
        pages += 1;
        let Some(last) = page.last() else {
            break true;
        };
        after = Some(last.id.clone());
        issuances.extend(page);
    };
    Ok(Report {
        entities: build_entities(&issuances, &base, scan_id),
        pages,
        complete,
    })
}

fn fetch_page<T: Transport + ?Sized>(
    transport: &T,
    domain: &str,
    after: Option<&str>,
) -> Result<Vec<Issuance>, Failure> {
    let mut url = append_query_param(ENDPOINT, "domain", domain);
    url = append_query_param(&url, "include_subdomains", "true");
    url = append_query_param(&url, "expand", "dns_names");
    if let Some(after) = after {
        url = append_query_param(&url, "after", after);
    }
    let failure = |kind, http_status, detail: String| Failure {
        kind,
        http_status,
        detail,
    };
    let fetched = fetch(
        transport,
        Request::get(url)
            .header("Accept", "application/json")
            .with_timeout(TIMEOUT),
        None,
        &FetchOptions::no_redirects(),
        SOURCE,
        0,
    )
    .map_err(|e| failure(SourceOutcomeKind::Inconclusive, None, e.to_string()))?;
    let Some(response) = fetched.response else {
        return Err(failure(
            fetched.outcome.kind,
            None,
            fetched
                .outcome
                .detail
                .unwrap_or_else(|| "no response".into()),
        ));
    };
    if crate::classify::is_challenge(&response.text()) {
        return Err(failure(
            SourceOutcomeKind::BotWaf,
            Some(response.status),
            "challenge page".into(),
        ));
    }
    if response.status == 429 {
        let retry = response
            .header_value("retry-after")
            .map_or_else(String::new, |secs| format!("; retry after {secs}s"));
        return Err(failure(
            SourceOutcomeKind::RateLimited,
            Some(429),
            format!("rate limited{retry}"),
        ));
    }
    if !(200..300).contains(&response.status) {
        let kind = if response.status >= 500 {
            SourceOutcomeKind::Upstream5xx
        } else {
            SourceOutcomeKind::Upstream4xx
        };
        return Err(failure(
            kind,
            Some(response.status),
            format!("HTTP {}", response.status),
        ));
    }
    if response.truncated {
        return Err(failure(
            SourceOutcomeKind::Inconclusive,
            Some(response.status),
            "truncated body".into(),
        ));
    }
    crate::http::parse_json_body(&response).map_err(|e| {
        failure(
            SourceOutcomeKind::SchemaDrift,
            Some(response.status),
            format!("not an issuance list: {e}"),
        )
    })
}

/// Issuances → one `Domain` entity per distinct canonical name, subdomains of `base` tagged and
/// boosted. **Pure.**
fn build_entities(issuances: &[Issuance], base: &str, scan_id: &str) -> Vec<Entity> {
    let mut seen = BTreeSet::new();
    let mut out = Vec::new();
    for issuance in issuances {
        for raw in &issuance.dns_names {
            let name = raw.trim().to_ascii_lowercase();
            if name.is_empty() || name.starts_with('*') || !name.contains('.') {
                continue;
            }
            let (canonical, is_sub) = crate::domains::classify_domain_candidate(&name, base);
            if !seen.insert(canonical.clone()) {
                continue;
            }
            let confidence = if is_sub {
                SUBDOMAIN_CONFIDENCE
            } else {
                EXTERNAL_CONFIDENCE
            };
            let mut entity = Entity::new(EntityKind::Domain, &canonical, confidence, scan_id);
            entity.raw_value = name;
            entity.tag(tags::CT_LOG);
            if is_sub {
                entity.tag(tags::SUBDOMAIN);
            }
            entity.add_evidence(
                Evidence::new(
                    EvidenceProvenance::for_scan(SOURCE, scan_id),
                    "Certificate Transparency (Cert Spotter)",
                )
                .with_attr("issuance_id", &issuance.id)
                .with_attr("cert_sha256", issuance.cert_sha256.as_deref().unwrap_or(""))
                .with_attr("not_before", issuance.not_before.as_deref().unwrap_or(""))
                .with_attr("not_after", issuance.not_after.as_deref().unwrap_or("")),
            );
            out.push(entity);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::collections::VecDeque;

    use super::*;
    use crate::http::{Response, TransportFailure};

    struct Fake {
        responses: RefCell<VecDeque<Response>>,
        urls: RefCell<Vec<String>>,
    }

    fn response(status: u16, body: &str) -> Response {
        Response {
            status,
            headers: vec![("retry-after".into(), "60".into())],
            body: body.as_bytes().to_vec(),
            truncated: false,
        }
    }

    impl Fake {
        fn new(responses: Vec<Response>) -> Self {
            Self {
                responses: RefCell::new(responses.into()),
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
                .ok_or_else(|| TransportFailure {
                    kind: SourceOutcomeKind::ConnectFailure,
                    detail: "down".into(),
                    blocked: false,
                })
        }
    }

    const PAGE_ONE: &str = r#"[
        {"id":"10","dns_names":["*.example.com","example.com","www.example.com"],"cert_sha256":"aa"},
        {"id":"11","dns_names":["API.example.com","example.net"]}
    ]"#;

    #[test]
    fn pages_until_empty_and_classifies_names() {
        let fake = Fake::new(vec![response(200, PAGE_ONE), response(200, "[]")]);
        let report = lookup(&fake, "Example.COM", "s").unwrap_or_else(|f| panic!("{f:?}"));
        assert!(report.complete);
        assert_eq!(report.pages, 2);
        let names: Vec<(&str, bool)> = report
            .entities
            .iter()
            .map(|e| (e.value.as_str(), e.has_tag(tags::SUBDOMAIN)))
            .collect();
        // Wildcard skipped; `www.` folds into the apex; the apex is not its own subdomain.
        assert_eq!(
            names,
            vec![
                ("example.com", false),
                ("api.example.com", true),
                ("example.net", false)
            ]
        );
        let urls = fake.urls.borrow();
        assert!(urls[0].contains("domain=example.com"), "{}", urls[0]);
        assert!(urls[0].contains("include_subdomains=true"), "{}", urls[0]);
        assert!(!urls[0].contains("after="), "{}", urls[0]);
        assert!(urls[1].contains("after=11"), "{}", urls[1]);
    }

    #[test]
    fn the_page_cap_is_reported_not_hidden() {
        let pages: Vec<Response> = (0..=MAX_PAGES).map(|_| response(200, PAGE_ONE)).collect();
        let report =
            lookup(&Fake::new(pages), "example.com", "s").unwrap_or_else(|f| panic!("{f:?}"));
        assert_eq!(report.pages, MAX_PAGES);
        assert!(!report.complete);
    }

    #[test]
    fn failures_are_typed() {
        let cases = [
            (response(429, "{}"), SourceOutcomeKind::RateLimited),
            (response(503, "busy"), SourceOutcomeKind::Upstream5xx),
            (
                response(200, r#"{"not":"a list"}"#),
                SourceOutcomeKind::SchemaDrift,
            ),
        ];
        for (reply, want) in cases {
            match lookup(&Fake::new(vec![reply]), "example.com", "s") {
                Err(failure) => assert_eq!(failure.kind, want, "{failure:?}"),
                Ok(report) => panic!("{want:?} accepted: {report:?}"),
            }
        }
        // A failure on a later page is not a silent partial result.
        let later = Fake::new(vec![response(200, PAGE_ONE), response(503, "busy")]);
        assert!(lookup(&later, "example.com", "s").is_err());
        // 429 is not retried and keeps the server's hint.
        let limited = Fake::new(vec![response(429, "{}")]);
        match lookup(&limited, "example.com", "s") {
            Err(failure) => assert!(failure.detail.contains("retry after 60s"), "{failure:?}"),
            Ok(report) => panic!("{report:?}"),
        }
        assert_eq!(limited.urls.borrow().len(), 1);
    }
}
