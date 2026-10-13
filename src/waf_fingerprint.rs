//! WAF/CDN fingerprinting: identify content delivery networks and web application firewalls.
//!
//! Analyzes HTTP response headers and status codes to detect commonly deployed WAF and CDN
//! solutions. Useful for understanding infrastructure and potential bypass vectors during
//! legitimate security assessments.
//!
//! Two kinds of header evidence: a header only the vendor sets (`cf-ray`, `x-amz-cf-id`,
//! `x-iinfo`), whose presence is the signal and whose value is an opaque id; and a generic
//! header (`server`, `via`, `x-cdn`) whose value names the vendor. A status code alone is never
//! a fingerprint; it only strengthens a header match.
//!
//! A pass over a domain's web roots runs under the caller's [`Deadline`]: every probe is capped
//! at what is left of it (never more than [`PROBE_TIMEOUT`]), and a probe that would start after
//! the budget is spent is not sent.

use std::time::Duration;

use crate::deadline::Deadline;
use crate::http::{Request, Response, Transport};

/// Cap on one probe, recomputed against the budget before every send.
pub const PROBE_TIMEOUT: Duration = Duration::from_secs(5);

/// A header match: the vendor identified itself.
const FIRST_HEADER: f64 = 0.75;
/// Each further header match corroborates the first.
const MORE_HEADER: f64 = 0.15;
/// A status the vendor's edge answers with, only beside a header match.
const STATUS: f64 = 0.1;

/// Known WAF/CDN patterns detected by analyzing response headers and behavior.
#[derive(Debug, Clone, Eq, PartialEq)]
struct FingerprintPattern {
    name: &'static str,
    category: &'static str,
    /// Headers only this vendor sets: presence is the signal.
    vendor_headers: &'static [&'static str],
    /// `(generic header, lower-cased vendor substring)`: the value names the vendor.
    value_headers: &'static [(&'static str, &'static str)],
    status_indicators: &'static [u16],
}

const FINGERPRINT_PATTERNS: &[FingerprintPattern] = &[
    FingerprintPattern {
        name: "Cloudflare",
        category: "cdn",
        vendor_headers: &["cf-ray", "cf-cache-status"],
        value_headers: &[("server", "cloudflare")],
        status_indicators: &[403, 503],
    },
    FingerprintPattern {
        name: "AWS CloudFront",
        category: "cdn",
        vendor_headers: &["x-amz-cf-id", "x-amz-cf-pop"],
        value_headers: &[("via", "cloudfront"), ("server", "cloudfront")],
        status_indicators: &[403],
    },
    FingerprintPattern {
        name: "Akamai",
        category: "cdn",
        vendor_headers: &["x-akamai-transformed", "x-akamai-request-id"],
        value_headers: &[("server", "akamaighost")],
        status_indicators: &[403],
    },
    FingerprintPattern {
        name: "Sucuri",
        category: "waf",
        vendor_headers: &["x-sucuri-id", "x-sucuri-cache"],
        value_headers: &[("server", "sucuri")],
        status_indicators: &[403],
    },
    FingerprintPattern {
        name: "ModSecurity",
        category: "waf",
        vendor_headers: &[],
        value_headers: &[("server", "mod_security"), ("server", "modsecurity")],
        status_indicators: &[403, 406],
    },
    FingerprintPattern {
        name: "Imperva/Incapsula",
        category: "waf",
        vendor_headers: &["x-iinfo"],
        value_headers: &[("x-cdn", "incapsula"), ("x-cdn", "imperva")],
        status_indicators: &[403],
    },
    FingerprintPattern {
        name: "F5 BIG-IP",
        category: "waf",
        vendor_headers: &[],
        value_headers: &[("server", "big-ip"), ("server", "bigip")],
        status_indicators: &[403],
    },
    FingerprintPattern {
        name: "Nginx",
        category: "webserver",
        vendor_headers: &[],
        value_headers: &[("server", "nginx")],
        status_indicators: &[],
    },
    FingerprintPattern {
        name: "Apache",
        category: "webserver",
        vendor_headers: &[],
        value_headers: &[("server", "apache")],
        status_indicators: &[],
    },
    FingerprintPattern {
        name: "Microsoft IIS",
        category: "webserver",
        vendor_headers: &[],
        value_headers: &[("server", "microsoft-iis"), ("x-powered-by", "asp.net")],
        status_indicators: &[],
    },
];

#[derive(Debug, Clone, PartialEq)]
pub struct FingerprintFinding {
    pub url: String,
    pub detected_service: String,
    pub category: String,
    pub headers_matched: Vec<String>,
    pub confidence: f64,
}

impl FingerprintFinding {
    #[must_use]
    pub const fn confidence_level(&self) -> &'static str {
        match self.confidence {
            x if x >= 0.9 => "high",
            x if x >= 0.7 => "medium",
            _ => "low",
        }
    }
}

/// Every pattern a response matches, in catalogue order.
fn classify(url: &str, response: &Response) -> Vec<FingerprintFinding> {
    let mut findings = Vec::new();
    for pattern in FINGERPRINT_PATTERNS {
        let mut matched = Vec::new();
        for name in pattern.vendor_headers {
            if let Some(value) = response.header_value(name) {
                matched.push(format!("{name}: {value}"));
            }
        }
        for (name, needle) in pattern.value_headers {
            if let Some(value) = response.header_value(name) {
                if value.to_ascii_lowercase().contains(needle) {
                    matched.push(format!("{name}: {value}"));
                }
            }
        }
        if matched.is_empty() {
            continue;
        }

        let mut confidence = matched
            .iter()
            .skip(1)
            .fold(FIRST_HEADER, |sum, _| sum + MORE_HEADER);
        if pattern.status_indicators.contains(&response.status) {
            confidence += STATUS;
        }
        findings.push(FingerprintFinding {
            url: url.to_owned(),
            detected_service: pattern.name.to_owned(),
            category: pattern.category.to_owned(),
            headers_matched: matched,
            confidence: confidence.min(1.0),
        });
    }
    findings
}

/// Probe one URL for WAF/CDN fingerprints via HTTP headers, with `cap` as the request timeout.
///
/// `Some(findings)` when the URL answered (empty when nothing matched), `None` when no
/// response was obtained.
#[must_use]
pub fn fingerprint<T: Transport + ?Sized>(
    transport: &T,
    url: &str,
    cap: Duration,
) -> Option<Vec<FingerprintFinding>> {
    let request = Request::get(url).with_timeout(cap);
    let response = transport.send(&request).ok()?;
    Some(classify(url, &response))
}

/// Fingerprint a domain's web roots and `robots.txt` over both schemes, within `deadline`.
///
/// One finding per technology: the same edge seen on every root is reported once, at the
/// highest confidence it reached, with the URL that reached it.
pub fn fingerprint_domain<T: Transport + ?Sized>(
    transport: &T,
    deadline: &Deadline<'_>,
    domain: &str,
) -> Vec<FingerprintFinding> {
    let urls = [
        format!("http://{domain}"),
        format!("https://{domain}"),
        format!("http://{domain}/robots.txt"),
        format!("https://{domain}/robots.txt"),
    ];

    let mut findings: Vec<FingerprintFinding> = Vec::new();
    for url in urls {
        if deadline.expired() {
            break;
        }
        let cap = deadline.remaining().min(PROBE_TIMEOUT);
        for finding in fingerprint(transport, &url, cap).unwrap_or_default() {
            match findings
                .iter_mut()
                .find(|known| known.detected_service == finding.detected_service)
            {
                Some(known) if known.confidence < finding.confidence => *known = finding,
                Some(_) => {}
                None => findings.push(finding),
            }
        }
    }
    findings
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;

    use super::*;
    use crate::deadline::{FakeClock, SystemClock};
    use crate::http::TransportFailure;

    /// Answers every URL with the same headers and status; records each request's timeout and,
    /// with a clock, "hangs" for its whole cap before answering.
    struct Edge<'c> {
        status: u16,
        headers: Vec<(String, String)>,
        caps: RefCell<Vec<Duration>>,
        clock: Option<&'c FakeClock>,
    }

    impl Edge<'_> {
        fn answering(status: u16, headers: &[(&str, &str)]) -> Self {
            Self {
                status,
                headers: headers
                    .iter()
                    .map(|(n, v)| ((*n).to_owned(), (*v).to_owned()))
                    .collect(),
                caps: RefCell::new(Vec::new()),
                clock: None,
            }
        }
    }

    impl Transport for Edge<'_> {
        fn send(&self, request: &Request) -> Result<Response, TransportFailure> {
            let cap = request.timeout.expect("every probe carries its cap");
            self.caps.borrow_mut().push(cap);
            if let Some(clock) = self.clock {
                clock.advance(cap);
            }
            Ok(Response {
                status: self.status,
                headers: self.headers.clone(),
                body: Vec::new(),
                truncated: false,
            })
        }
    }

    fn services(findings: &[FingerprintFinding]) -> Vec<&str> {
        findings
            .iter()
            .map(|f| f.detected_service.as_str())
            .collect()
    }

    #[test]
    fn a_server_header_names_the_edge() {
        let edge = Edge::answering(200, &[("Server", "cloudflare")]);
        let findings = fingerprint(&edge, "https://example.com", PROBE_TIMEOUT).expect("answered");
        assert_eq!(findings.len(), 1, "{findings:?}");
        assert_eq!(findings[0].detected_service, "Cloudflare");
        assert_eq!(findings[0].category, "cdn");
        assert_eq!(
            findings[0].headers_matched,
            vec!["server: cloudflare".to_owned()]
        );
        assert_eq!(findings[0].confidence_level(), "medium");
    }

    #[test]
    fn an_opaque_vendor_header_is_the_signal() {
        let edge = Edge::answering(200, &[("X-Amz-Cf-Id", "AbC123xyz==")]);
        let findings = fingerprint(&edge, "https://example.com", PROBE_TIMEOUT).expect("answered");
        assert_eq!(services(&findings), vec!["AWS CloudFront"]);
        assert_eq!(findings[0].confidence_level(), "medium");
    }

    #[test]
    fn corroborating_headers_and_the_edge_status_raise_confidence() {
        let edge = Edge::answering(
            403,
            &[("cf-ray", "8a1b2c3d4e5f-SYD"), ("Server", "cloudflare")],
        );
        let findings = fingerprint(&edge, "https://example.com", PROBE_TIMEOUT).expect("answered");
        assert_eq!(services(&findings), vec!["Cloudflare"]);
        assert_eq!(findings[0].headers_matched.len(), 2);
        assert_eq!(findings[0].confidence_level(), "high");
        assert!(findings[0].confidence <= 1.0);
    }

    #[test]
    fn every_edge_on_one_response_is_reported() {
        let edge = Edge::answering(
            200,
            &[("X-Amz-Cf-Id", "AbC123=="), ("Server", "nginx/1.24.0")],
        );
        let findings = fingerprint(&edge, "https://example.com", PROBE_TIMEOUT).expect("answered");
        assert_eq!(services(&findings), vec!["AWS CloudFront", "Nginx"]);
    }

    #[test]
    fn a_status_alone_is_not_a_fingerprint() {
        let edge = Edge::answering(403, &[("Server", "something-else")]);
        assert_eq!(
            fingerprint(&edge, "https://example.com", PROBE_TIMEOUT),
            Some(Vec::new())
        );
    }

    #[test]
    fn the_same_edge_on_every_root_is_one_finding() {
        let edge = Edge::answering(200, &[("Server", "cloudflare")]);
        let deadline = Deadline::start(&SystemClock, Duration::from_secs(30));
        let findings = fingerprint_domain(&edge, &deadline, "example.com");
        assert_eq!(services(&findings), vec!["Cloudflare"]);
        assert_eq!(findings[0].url, "http://example.com");
        let caps = edge.caps.borrow();
        assert_eq!(caps.len(), 4);
        assert!(caps.iter().all(|c| *c == PROBE_TIMEOUT));
    }

    #[test]
    fn hanging_roots_spend_the_budget_not_four_timeouts() {
        let clock = FakeClock::new();
        let mut edge = Edge::answering(200, &[]);
        edge.clock = Some(&clock);
        let deadline = Deadline::start(&clock, Duration::from_secs(7));
        fingerprint_domain(&edge, &deadline, "example.com");
        // 7 s / 5 s: one full probe, a second capped at the 2 s left, then nothing.
        let caps = edge.caps.borrow();
        assert_eq!(*caps, vec![PROBE_TIMEOUT, Duration::from_secs(2)]);
        assert_eq!(clock.elapsed(), Duration::from_secs(7));
    }

    #[test]
    fn confidence_levels_map_correctly() {
        let at = |confidence: f64| FingerprintFinding {
            url: "test".to_owned(),
            detected_service: "x".to_owned(),
            category: "cdn".to_owned(),
            headers_matched: vec![],
            confidence,
        };
        assert_eq!(at(0.95).confidence_level(), "high");
        assert_eq!(at(0.75).confidence_level(), "medium");
        assert_eq!(at(0.5).confidence_level(), "low");
    }

    #[test]
    fn every_pattern_has_header_evidence_and_real_statuses() {
        for pattern in FINGERPRINT_PATTERNS {
            assert!(
                !pattern.vendor_headers.is_empty() || !pattern.value_headers.is_empty(),
                "pattern {} has no header evidence",
                pattern.name
            );
            for (_, needle) in pattern.value_headers {
                assert_eq!(needle.to_ascii_lowercase(), *needle, "{}", pattern.name);
            }
            for status in pattern.status_indicators {
                assert!((100..600).contains(status), "{}: {status}", pattern.name);
            }
        }
    }
}
