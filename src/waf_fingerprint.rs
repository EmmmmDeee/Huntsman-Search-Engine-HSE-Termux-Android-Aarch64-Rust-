//! WAF/CDN fingerprinting: identify content delivery networks and web application firewalls.
//!
//! Analyzes HTTP response headers and status codes to detect commonly deployed WAF and CDN
//! solutions. Useful for understanding infrastructure and potential bypass vectors during
//! legitimate security assessments.
//!
//! A pass over a domain's web roots runs under the caller's [`Deadline`]: every probe is capped
//! at what is left of it (never more than [`PROBE_TIMEOUT`]), and a probe that would start after
//! the budget is spent is not sent.

use std::time::Duration;

use crate::deadline::Deadline;
use crate::http::{Request, Transport};

/// Cap on one probe, recomputed against the budget before every send.
pub const PROBE_TIMEOUT: Duration = Duration::from_secs(5);

/// Known WAF/CDN patterns detected by analyzing response headers and behavior.
#[derive(Debug, Clone, Eq, PartialEq)]
struct FingerprintPattern {
    name: &'static str,
    category: &'static str,
    headers: &'static [&'static str],
    header_values: &'static [&'static str],
    status_indicators: &'static [u16],
}

const FINGERPRINT_PATTERNS: &[FingerprintPattern] = &[
    // Cloudflare: Server header, cf-ray header, 1020 error pages
    FingerprintPattern {
        name: "Cloudflare",
        category: "cdn",
        headers: &["cf-ray", "cf-cache-status", "server"],
        header_values: &["cloudflare", "cf_"],
        status_indicators: &[1020, 1010],
    },
    // AWS CloudFront: Server header, X-Amz-Cf-Id header
    FingerprintPattern {
        name: "AWS CloudFront",
        category: "cdn",
        headers: &["x-amz-cf-id", "x-amz-cf-pop"],
        header_values: &["cloudfront"],
        status_indicators: &[403, 404],
    },
    // Akamai: AkamaiGHost, X-Akamai headers
    FingerprintPattern {
        name: "Akamai",
        category: "cdn",
        headers: &["x-akamai-transformed", "server"],
        header_values: &["akamaighost", "akamai"],
        status_indicators: &[403],
    },
    // Sucuri: Sucuri/CloudProxy WAF
    FingerprintPattern {
        name: "Sucuri",
        category: "waf",
        headers: &["server", "x-sucuri-id"],
        header_values: &["sucuri", "cloudproxy"],
        status_indicators: &[403],
    },
    // ModSecurity: X-ModSecurity headers
    FingerprintPattern {
        name: "ModSecurity",
        category: "waf",
        headers: &["x-modsecurity", "server"],
        header_values: &["modsecurity"],
        status_indicators: &[403, 406],
    },
    // Imperva/Incapsula: X-Iinfo, X-CDN headers
    FingerprintPattern {
        name: "Imperva/Incapsula",
        category: "waf",
        headers: &["x-iinfo", "x-cdn"],
        header_values: &["incapsula", "imperva"],
        status_indicators: &[403],
    },
    // F5 BIG-IP: Server headers, specific error pages
    FingerprintPattern {
        name: "F5 BIG-IP",
        category: "waf",
        headers: &["server"],
        header_values: &["big-ip"],
        status_indicators: &[403],
    },
    // Nginx: Server header
    FingerprintPattern {
        name: "Nginx",
        category: "webserver",
        headers: &["server"],
        header_values: &["nginx"],
        status_indicators: &[404],
    },
    // Apache: Server header
    FingerprintPattern {
        name: "Apache",
        category: "webserver",
        headers: &["server"],
        header_values: &["apache"],
        status_indicators: &[404],
    },
    // IIS: Server header, X-Powered-By
    FingerprintPattern {
        name: "Microsoft IIS",
        category: "webserver",
        headers: &["server", "x-powered-by"],
        header_values: &["iis", "microsoft-iis"],
        status_indicators: &[404],
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

/// Probe one URL for WAF/CDN fingerprints via HTTP headers, with `cap` as the request timeout.
///
/// `Some(Some(finding))` when a pattern matched, `Some(None)` when the URL answered without
/// one, `None` when no response was obtained.
#[must_use]
pub fn fingerprint<T: Transport + ?Sized>(
    transport: &T,
    url: &str,
    cap: Duration,
) -> Option<Option<FingerprintFinding>> {
    let request = Request::get(url).with_timeout(cap);
    let response = transport.send(&request).ok()?;

    for pattern in FINGERPRINT_PATTERNS {
        let mut matched_headers = Vec::new();
        let mut match_score: f64 = 0.0;

        for header_name in pattern.headers {
            if let Some(value) = response.header_value(header_name) {
                let lowered = value.to_lowercase();
                if pattern
                    .header_values
                    .iter()
                    .any(|needle| lowered.contains(&needle.to_lowercase()))
                {
                    matched_headers.push(format!("{header_name}: {value}"));
                    match_score += 0.4;
                }
            }
        }

        if pattern.status_indicators.contains(&response.status) {
            match_score += 0.3;
        }

        if match_score > 0.3 && !matched_headers.is_empty() {
            let confidence = (match_score / 0.7).min(1.0_f64);
            return Some(Some(FingerprintFinding {
                url: url.to_owned(),
                detected_service: pattern.name.to_owned(),
                category: pattern.category.to_owned(),
                headers_matched: matched_headers,
                confidence,
            }));
        }
    }

    Some(None)
}

/// Fingerprint a domain's web roots and `robots.txt` over both schemes, within `deadline`.
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

    let mut findings = Vec::new();
    for url in urls {
        if deadline.expired() {
            break;
        }
        let cap = deadline.remaining().min(PROBE_TIMEOUT);
        if let Some(Some(finding)) = fingerprint(transport, &url, cap) {
            findings.push(finding);
        }
    }
    findings
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;

    use super::*;
    use crate::deadline::{FakeClock, SystemClock};
    use crate::http::{Response, TransportFailure};

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

    #[test]
    fn a_server_header_names_the_edge() {
        let edge = Edge::answering(200, &[("Server", "cloudflare")]);
        let finding = fingerprint(&edge, "https://example.com", PROBE_TIMEOUT)
            .flatten()
            .expect("cloudflare matched");
        assert_eq!(finding.detected_service, "Cloudflare");
        assert_eq!(finding.category, "cdn");
        assert_eq!(
            finding.headers_matched,
            vec!["server: cloudflare".to_owned()]
        );
        assert_eq!(finding.confidence_level(), "low");
    }

    #[test]
    fn a_status_alone_is_not_a_fingerprint() {
        let edge = Edge::answering(403, &[("Server", "something-else")]);
        assert_eq!(
            fingerprint(&edge, "https://example.com", PROBE_TIMEOUT),
            Some(None)
        );
    }

    #[test]
    fn the_pass_probes_four_urls_within_the_budget() {
        let edge = Edge::answering(200, &[]);
        let deadline = Deadline::start(&SystemClock, Duration::from_secs(30));
        assert!(fingerprint_domain(&edge, &deadline, "example.com").is_empty());
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
    fn patterns_are_well_formed() {
        for pattern in FINGERPRINT_PATTERNS {
            assert!(
                !pattern.headers.is_empty(),
                "Pattern {} has no headers",
                pattern.name
            );
            assert!(
                !pattern.header_values.is_empty(),
                "Pattern {} has no header values",
                pattern.name
            );
        }
    }
}
