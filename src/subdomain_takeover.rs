//! Subdomain takeover detection: identify subdomains pointing to unclaimed service endpoints.
//!
//! When a subdomain's CNAME or A record points to a service (GitHub Pages, AWS S3, Heroku, etc.)
//! that is no longer claimed or provisioned, an attacker can claim the service and assume control
//! of that subdomain. This detector probes each subdomain over HTTP and matches the provider's
//! own "unclaimed" signature. A status code alone is never a signature: a plain 404 is what most
//! of the web answers for an unknown name.
//!
//! The pass over a subdomain list runs under one [`Deadline`]: every probe is capped at what is
//! left of the budget (never more than [`PROBE_TIMEOUT`]), and a probe that would start after the
//! budget is spent is not sent and is counted as skipped. Worst case: [`BUDGET`], not
//! `MAX_PROBES x PROBE_TIMEOUT`.

use std::time::Duration;

use crate::deadline::{Clock, Deadline};
use crate::entity::{Evidence, EvidenceProvenance};
use crate::http::{Request, Response, Transport};

/// Cap on one probe, recomputed against the budget before every send.
pub const PROBE_TIMEOUT: Duration = Duration::from_secs(3);
/// Wall-clock budget for the whole pass over a subdomain list.
pub const BUDGET: Duration = Duration::from_secs(20);
/// Subdomains probed per pass; the rest are reported as skipped.
pub const MAX_PROBES: usize = 50;

/// A provider's "unclaimed" signature: the status it answers with, body substrings it alone
/// uses on that page, and response headers that identify the provider's edge.
#[derive(Debug, Clone, Eq, PartialEq)]
struct TakeoverPattern {
    service: &'static str,
    status: u16,
    body_indicators: &'static [&'static str],
    /// `(header name, lower-cased value substring)`.
    header_indicators: &'static [(&'static str, &'static str)],
}

const TAKEOVER_PATTERNS: &[TakeoverPattern] = &[
    TakeoverPattern {
        service: "github_pages",
        status: 404,
        body_indicators: &["There isn't a GitHub Pages site here"],
        header_indicators: &[("server", "github.com")],
    },
    TakeoverPattern {
        service: "heroku",
        status: 404,
        body_indicators: &["no-such-app", "No such app"],
        header_indicators: &[("via", "vegur")],
    },
    TakeoverPattern {
        service: "aws_s3",
        status: 404,
        body_indicators: &["NoSuchBucket", "The specified bucket does not exist"],
        header_indicators: &[("server", "amazons3")],
    },
    TakeoverPattern {
        service: "vercel",
        status: 404,
        body_indicators: &["DEPLOYMENT_NOT_FOUND", "The deployment could not be found"],
        header_indicators: &[("server", "vercel")],
    },
    TakeoverPattern {
        service: "netlify",
        status: 404,
        body_indicators: &["Not Found - Request ID"],
        header_indicators: &[("server", "netlify")],
    },
    TakeoverPattern {
        service: "fastly",
        status: 404,
        body_indicators: &["Fastly error: unknown domain"],
        header_indicators: &[],
    },
    TakeoverPattern {
        service: "azure",
        status: 404,
        body_indicators: &["Error 404 - Web app not found", "404 Web Site not found"],
        header_indicators: &[],
    },
    TakeoverPattern {
        service: "shopify",
        status: 404,
        body_indicators: &["Sorry, this shop is currently unavailable"],
        header_indicators: &[],
    },
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TakeoverFinding {
    pub subdomain: String,
    pub service: String,
    pub risk_level: RiskLevel,
    pub evidence_summary: String,
    pub http_status: u16,
    pub response_sample: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum RiskLevel {
    /// The provider's edge answered the status, but without its unclaimed-page body.
    Medium,
    /// The provider's own unclaimed-page body: the name can be claimed.
    High,
}

impl RiskLevel {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::High => "high",
            Self::Medium => "medium",
        }
    }
}

/// What one pass over a subdomain list did.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct TakeoverReport {
    pub findings: Vec<TakeoverFinding>,
    /// Probes sent (answered or not).
    pub probed: usize,
    /// Subdomains not probed: past [`MAX_PROBES`], or the budget was spent.
    pub skipped: usize,
}

fn sample(body: &str) -> String {
    body.chars().take(200).collect()
}

/// Match a response against the provider signatures.
fn classify(subdomain: &str, response: &Response) -> Option<TakeoverFinding> {
    let body = response.text();
    for pattern in TAKEOVER_PATTERNS {
        if response.status != pattern.status {
            continue;
        }
        if let Some(indicator) = pattern
            .body_indicators
            .iter()
            .find(|indicator| body.contains(*indicator))
        {
            return Some(TakeoverFinding {
                subdomain: subdomain.to_owned(),
                service: pattern.service.to_owned(),
                risk_level: RiskLevel::High,
                evidence_summary: format!(
                    "Subdomain points to unclaimed {} service: {indicator}",
                    pattern.service
                ),
                http_status: response.status,
                response_sample: sample(&body),
            });
        }
        let edge = pattern.header_indicators.iter().find(|(name, needle)| {
            response
                .header_value(name)
                .is_some_and(|value| value.to_ascii_lowercase().contains(needle))
        });
        if let Some((name, _)) = edge {
            return Some(TakeoverFinding {
                subdomain: subdomain.to_owned(),
                service: pattern.service.to_owned(),
                risk_level: RiskLevel::Medium,
                evidence_summary: format!(
                    "{} edge ({name} header) answers {} for the subdomain without a site",
                    pattern.service, response.status
                ),
                http_status: response.status,
                response_sample: sample(&body),
            });
        }
    }
    None
}

/// Probe one subdomain with `cap` as the request timeout.
///
/// `Some(Some(finding))` when a provider signature matched, `Some(None)` when the subdomain
/// answered without one, `None` when no response was obtained.
#[must_use]
pub fn probe<T: Transport + ?Sized>(
    transport: &T,
    subdomain: &str,
    cap: Duration,
) -> Option<Option<TakeoverFinding>> {
    let request = Request::get(format!("http://{subdomain}")).with_timeout(cap);
    let response = transport.send(&request).ok()?;
    Some(classify(subdomain, &response))
}

/// Convert a takeover finding into evidence for inclusion in an entity.
#[must_use]
pub fn finding_to_evidence(finding: &TakeoverFinding, scan_id: &str) -> Evidence {
    let mut provenance = EvidenceProvenance::new("subdomain_takeover_detector");
    provenance.scan_id = Some(scan_id.to_owned());

    let mut attributes = std::collections::BTreeMap::new();
    attributes.insert("service".to_owned(), finding.service.clone());
    attributes.insert(
        "risk_level".to_owned(),
        finding.risk_level.as_str().to_owned(),
    );
    attributes.insert("http_status".to_owned(), finding.http_status.to_string());
    attributes.insert("sample".to_owned(), finding.response_sample.clone());

    let summary = format!(
        "Subdomain {} vulnerable to takeover via {}",
        finding.subdomain, finding.service
    );

    let mut evidence = Evidence::new(provenance, summary);
    evidence.attributes = attributes;
    evidence
}

/// Probe up to [`MAX_PROBES`] subdomains within one [`BUDGET`].
pub fn detect_in_subdomains<T: Transport + ?Sized>(
    transport: &T,
    clock: &dyn Clock,
    subdomains: &[String],
) -> TakeoverReport {
    let deadline = Deadline::start(clock, BUDGET);
    let mut report = TakeoverReport::default();
    for subdomain in subdomains {
        if report.probed >= MAX_PROBES || deadline.expired() {
            report.skipped += 1;
            continue;
        }
        report.probed += 1;
        let cap = deadline.remaining().min(PROBE_TIMEOUT);
        if let Some(Some(finding)) = probe(transport, subdomain, cap) {
            report.findings.push(finding);
        }
    }
    report
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;

    use super::*;
    use crate::deadline::{FakeClock, SystemClock};
    use crate::http::TransportFailure;
    use crate::source_outcome::SourceOutcomeKind;

    /// Answers every host with the same response and records each request's timeout.
    /// With a clock, every request "hangs" for its whole cap before answering.
    struct Edge<'c> {
        status: u16,
        headers: Vec<(String, String)>,
        body: &'static str,
        fail: bool,
        caps: RefCell<Vec<Duration>>,
        clock: Option<&'c FakeClock>,
    }

    impl<'c> Edge<'c> {
        fn answering(status: u16, headers: &[(&str, &str)], body: &'static str) -> Self {
            Self {
                status,
                headers: headers
                    .iter()
                    .map(|(n, v)| ((*n).to_owned(), (*v).to_owned()))
                    .collect(),
                body,
                fail: false,
                caps: RefCell::new(Vec::new()),
                clock: None,
            }
        }

        fn hanging(clock: &'c FakeClock) -> Self {
            let mut edge = Self::answering(200, &[], "");
            edge.clock = Some(clock);
            edge
        }
    }

    impl Transport for Edge<'_> {
        fn send(&self, request: &Request) -> Result<Response, TransportFailure> {
            let cap = request.timeout.expect("every probe carries its cap");
            self.caps.borrow_mut().push(cap);
            if let Some(clock) = self.clock {
                clock.advance(cap);
            }
            if self.fail {
                return Err(TransportFailure {
                    kind: SourceOutcomeKind::ConnectFailure,
                    detail: "down".into(),
                    blocked: false,
                });
            }
            Ok(Response {
                status: self.status,
                headers: self.headers.clone(),
                body: self.body.as_bytes().to_vec(),
                truncated: false,
            })
        }
    }

    fn names(n: usize) -> Vec<String> {
        (0..n).map(|i| format!("h{i}.example.com")).collect()
    }

    #[test]
    fn a_plain_404_is_not_a_takeover() {
        let edge = Edge::answering(404, &[("server", "nginx")], "<h1>Not Found</h1>");
        assert_eq!(probe(&edge, "a.example.com", PROBE_TIMEOUT), Some(None));
    }

    #[test]
    fn a_provider_unclaimed_page_is_high_risk() {
        let edge = Edge::answering(
            404,
            &[("Server", "GitHub.com")],
            "<p>There isn't a GitHub Pages site here.</p>",
        );
        let finding = probe(&edge, "a.example.com", PROBE_TIMEOUT)
            .flatten()
            .expect("signature matched");
        assert_eq!(finding.service, "github_pages");
        assert_eq!(finding.risk_level, RiskLevel::High);
        assert_eq!(finding.http_status, 404);
        assert!(finding.response_sample.contains("GitHub Pages"));
    }

    #[test]
    fn a_provider_edge_without_its_page_is_medium_risk() {
        let edge = Edge::answering(404, &[("Via", "1.1 vegur")], "<h1>Not Found</h1>");
        let finding = probe(&edge, "a.example.com", PROBE_TIMEOUT)
            .flatten()
            .expect("edge header matched");
        assert_eq!(finding.service, "heroku");
        assert_eq!(finding.risk_level, RiskLevel::Medium);
        assert!(finding.evidence_summary.contains("via header"));
    }

    #[test]
    fn a_provider_body_on_the_wrong_status_is_not_matched() {
        let edge = Edge::answering(200, &[], "There isn't a GitHub Pages site here");
        assert_eq!(probe(&edge, "a.example.com", PROBE_TIMEOUT), Some(None));
    }

    #[test]
    fn no_response_is_none_not_safe() {
        let mut edge = Edge::answering(404, &[], "");
        edge.fail = true;
        assert_eq!(probe(&edge, "a.example.com", PROBE_TIMEOUT), None);
    }

    #[test]
    fn the_pass_probes_at_most_max_probes_and_reports_the_rest_skipped() {
        let edge = Edge::answering(200, &[], "");
        let report = detect_in_subdomains(&edge, &SystemClock, &names(MAX_PROBES + 10));
        assert_eq!(report.probed, MAX_PROBES);
        assert_eq!(report.skipped, 10);
        assert!(report.findings.is_empty());
        assert!(edge.caps.borrow().iter().all(|c| *c == PROBE_TIMEOUT));
    }

    #[test]
    fn hanging_hosts_spend_one_budget_not_one_timeout_each() {
        let clock = FakeClock::new();
        let edge = Edge::hanging(&clock);
        let report = detect_in_subdomains(&edge, &clock, &names(MAX_PROBES));
        // 20 s / 3 s: six full probes, a seventh capped at the 2 s left, then nothing.
        let caps = edge.caps.borrow();
        assert_eq!(caps.len(), 7, "{caps:?}");
        assert!(caps[..6].iter().all(|c| *c == PROBE_TIMEOUT));
        assert_eq!(caps[6], Duration::from_secs(2));
        assert_eq!(report.probed, 7);
        assert_eq!(report.skipped, MAX_PROBES - 7);
        assert_eq!(clock.elapsed(), BUDGET);
    }

    #[test]
    fn risk_level_strings() {
        assert!(RiskLevel::Medium < RiskLevel::High);
        assert_eq!(RiskLevel::High.as_str(), "high");
        assert_eq!(RiskLevel::Medium.as_str(), "medium");
    }

    #[test]
    fn finding_to_evidence_creates_attributes() {
        let finding = TakeoverFinding {
            subdomain: "test.example.com".to_owned(),
            service: "github_pages".to_owned(),
            risk_level: RiskLevel::High,
            evidence_summary: "Test".to_owned(),
            http_status: 404,
            response_sample: "sample".to_owned(),
        };

        let evidence = finding_to_evidence(&finding, "scan123");
        assert_eq!(evidence.provenance.scan_id.as_deref(), Some("scan123"));
        assert_eq!(
            evidence.attributes.get("service").map(String::as_str),
            Some("github_pages")
        );
        assert_eq!(
            evidence.attributes.get("risk_level").map(String::as_str),
            Some("high")
        );
        assert_eq!(
            evidence.attributes.get("http_status").map(String::as_str),
            Some("404")
        );
    }
}
