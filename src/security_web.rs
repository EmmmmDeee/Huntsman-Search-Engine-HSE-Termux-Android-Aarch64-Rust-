//! Bounded, operator-initiated HTTP assessment reusing HUNTSMAN's guarded transport.
//!
//! There is no proxy, credential use, SQL injection or inferred exploitation.
//! The production CLI always supplies a public-only transport; this library
//! accepts a trait to permit deterministic offline tests without network access.

use std::collections::BTreeSet;
use std::thread;
use std::time::Duration;

use serde::Serialize;

use crate::http::{Request, Response, Transport, parse_http_uri};
use crate::sha256::{hex32, sha256};

pub const MAX_PATHLIST_BYTES: u64 = 8192;
pub const MAX_PATHS: usize = 16;

#[derive(Debug, Serialize)]
pub struct HeaderCheck {
    pub name: &'static str,
    pub present: bool,
    pub note: &'static str,
}

#[derive(Debug, Serialize)]
pub struct HeaderReport {
    pub url: String,
    pub status: u16,
    pub checks: Vec<HeaderCheck>,
    pub secure_cookies: usize,
    pub cookies_without_secure: usize,
    pub body_truncated: bool,
    pub caveat: &'static str,
}

/// This is a hygiene assessment, not a vulnerability proof. No values of
/// Set-Cookie, Authorization or other headers enter the output.
#[must_use]
pub fn assess_headers(url: &str, response: &Response) -> HeaderReport {
    let checks = [
        ("strict-transport-security", "HSTS is a HTTPS-only browser policy"),
        ("content-security-policy", "CSP mitigates some script-injection impact"),
        ("x-content-type-options", "nosniff helps resist MIME confusion"),
        ("referrer-policy", "Referrer-Policy controls referrer disclosure"),
        ("x-frame-options", "CSP frame-ancestors can replace this legacy header"),
        ("permissions-policy", "Permissions-Policy restricts some browser features"),
    ]
    .into_iter()
    .map(|(name, note)| HeaderCheck {
        name,
        present: response.header_value(name).is_some(),
        note,
    })
    .collect();

    let mut secure_cookies = 0;
    let mut cookies_without_secure = 0;
    for (_, value) in response
        .headers
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case("set-cookie"))
    {
        let secure = value
            .split(';')
            .skip(1)
            .any(|attribute| attribute.trim().eq_ignore_ascii_case("secure"));
        if secure {
            secure_cookies += 1;
        } else {
            cookies_without_secure += 1;
        }
    }

    HeaderReport {
        url: url.to_owned(),
        status: response.status,
        checks,
        secure_cookies,
        cookies_without_secure,
        body_truncated: response.truncated,
        caveat: "Header presence does not establish application security or vulnerability.",
    }
}

#[derive(Debug, Serialize)]
pub struct PathHit {
    pub path: String,
    pub status: u16,
    pub classification: &'static str,
}

#[derive(Debug, Serialize)]
pub struct PathReport {
    pub origin: String,
    pub candidate_paths: usize,
    pub request_attempts: usize,
    pub probes_failed: usize,
    pub baseline_status: Option<u16>,
    pub hits: Vec<PathHit>,
    pub caveat: &'static str,
}

/// Only origin-form HTTPS URLs are accepted; path/query/userinfo/fragment
/// could unexpectedly change probe scope. The egress transport must still
/// enforce its independent IP policy against rebinding and private addresses.
pub fn checked_origin(raw: &str) -> Result<String, String> {
    if raw.len() > 240
        || !raw.starts_with("https://")
        || raw.contains('?')
        || raw.contains('#')
        || raw.contains('@')
        || raw.bytes().any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
    {
        return Err("expected an HTTPS origin without userinfo, query or fragment".into());
    }
    let uri = parse_http_uri(raw).map_err(|_| "invalid HTTPS origin".to_owned())?;
    if uri.scheme_str() != Some("https") {
        return Err("HTTPS is required".into());
    }
    let host = uri.host().ok_or("HTTPS origin has no hostname")?;
    if host.is_empty()
        || !host.contains('.')
        || host.starts_with('-')
        || host.ends_with('-')
        || !host
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'.' || byte == b'-')
    {
        return Err("HTTPS origin must use a simple DNS hostname or IPv4 address".into());
    }
    if uri.path_and_query().is_some_and(|item| item.as_str() != "/") {
        return Err("origin must not contain a non-root path".into());
    }
    Ok(raw.trim_end_matches('/').to_ascii_lowercase())
}

/// Strict, bounded wordlist ingestion. No URL schemes, traversal, query
/// strings, encoded path delimiters or untrusted redirection targets.
pub fn parse_paths(input: &[u8]) -> Result<Vec<String>, String> {
    if input.is_empty() || input.len() as u64 > MAX_PATHLIST_BYTES {
        return Err("path wordlist must be 1-8192 bytes".into());
    }
    let text = std::str::from_utf8(input).map_err(|_| "path wordlist is not UTF-8")?;
    let mut paths = Vec::new();
    let mut seen = BTreeSet::new();
    for line in text.lines() {
        let path = line.trim();
        if path.is_empty() || path.starts_with('#') {
            continue;
        }
        if path.starts_with("//") {
            return Err("absolute network paths are not allowed".into());
        }
        let path = path.strip_prefix('/').unwrap_or(path);
        if path.is_empty()
            || path.len() > 128
            || path.contains("..")
            || path.contains("//")
            || !path
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_' | b'/'))
        {
            return Err("unsafe path in wordlist; use relative ASCII path segments".into());
        }
        if seen.insert(path.to_owned()) {
            paths.push(path.to_owned());
        }
        if paths.len() > MAX_PATHS {
            return Err("path wordlist exceeds 16 unique paths".into());
        }
    }
    if paths.is_empty() {
        return Err("wordlist contains no valid candidate paths".into());
    }
    Ok(paths)
}

fn fetch_once(transport: &dyn Transport, url: &str) -> Result<Response, String> {
    transport
        .send(&Request::get(url).with_timeout(Duration::from_secs(7)))
        .map_err(|failure| format!("HTTP transport outcome: {:?}", failure.kind))
}

/// Read-only, anonymous HTTP header assessment. The CLI uses a public-only
/// transport; this function doesn't follow redirects or submit a form.
pub fn inspect_headers(transport: &dyn Transport, raw: &str) -> Result<HeaderReport, String> {
    let origin = checked_origin(raw)?;
    let response = fetch_once(transport, &origin)?;
    Ok(assess_headers(&origin, &response))
}

/// Explicitly authorised, sequential, read-only path checks with a missing
/// path baseline. A matching status+body to a baseline is marked ambiguous.
/// A 2xx/3xx hit is a *candidate*, never confirmed access or vulnerability.
///
/// Production CLI uses 150ms pacing and never sends credentials, request
/// bodies or cookies. This function refuses to send without user consent.
pub fn discover_paths(
    transport: &dyn Transport,
    raw_origin: &str,
    input: &[u8],
    authorised: bool,
    pause: Duration,
) -> Result<PathReport, String> {
    if !authorised {
        return Err("explicit --authorized flag required before any network probes".into());
    }
    let origin = checked_origin(raw_origin)?;
    let paths = parse_paths(input)?;
    let suffix = &hex32(&sha256(origin.as_bytes()))[..16];
    let baseline_url = format!("{origin}/__huntsman_absent_{suffix}");
    let baseline = fetch_once(transport, &baseline_url).ok();
    let mut report = PathReport {
        origin: origin.clone(),
        candidate_paths: paths.len(),
        request_attempts: 1,
        probes_failed: usize::from(baseline.is_none()),
        baseline_status: baseline.as_ref().map(|item| item.status),
        hits: Vec::new(),
        caveat: "A path response is only a lead; wildcard, authentication and CDN behavior can mislead.",
    };
    for path in paths {
        if !pause.is_zero() {
            thread::sleep(pause);
        }
        report.request_attempts += 1;
        let response = match fetch_once(transport, &format!("{origin}/{path}")) {
            Ok(response) => response,
            Err(_) => {
                report.probes_failed += 1;
                continue;
            }
        };
        if !(200..400).contains(&response.status) {
            continue;
        }
        let same_as_baseline = baseline.as_ref().is_some_and(|missing| {
            missing.status == response.status
                && missing.body == response.body
                && !missing.truncated
                && !response.truncated
        });
        report.hits.push(PathHit {
            path,
            status: response.status,
            classification: if same_as_baseline {
                "wildcard_or_soft404_candidate"
            } else {
                "unverified_resource_candidate"
            },
        });
    }
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::{Transport, TransportFailure};
    use std::cell::RefCell;

    struct Fake {
        requests: RefCell<Vec<String>>,
        response: Response,
    }

    impl Transport for Fake {
        fn send(&self, request: &Request) -> Result<Response, TransportFailure> {
            self.requests.borrow_mut().push(request.url.clone());
            Ok(self.response.clone())
        }
    }

    fn fake(status: u16) -> Fake {
        Fake {
            requests: RefCell::new(Vec::new()),
            response: Response {
                status,
                headers: vec![
                    (
                        "content-security-policy".into(),
                        "default-src 'self'".into(),
                    ),
                    ("set-cookie".into(), "session=test; HttpOnly; Secure".into()),
                    ("set-cookie".into(), "legacy=test; HttpOnly".into()),
                ],
                body: b"fixture".to_vec(),
                truncated: false,
            },
        }
    }

    #[test]
    fn no_authority_means_zero_http_requests() {
        let transport = fake(200);
        let result = discover_paths(
            &transport,
            "https://example.com",
            b"admin\n",
            false,
            Duration::ZERO,
        );
        assert!(result.is_err());
        assert!(transport.requests.borrow().is_empty());
    }

    #[test]
    fn path_discovery_is_bounded_and_wildcards_are_not_confirmed() {
        let transport = fake(200);
        let result = discover_paths(
            &transport,
            "https://example.com",
            b"login\n/login\nimages\n",
            true,
            Duration::ZERO,
        )
        .unwrap();
        assert_eq!(result.candidate_paths, 2);
        assert_eq!(result.request_attempts, 3);
        assert_eq!(transport.requests.borrow().len(), 3);
        assert!(
            result
                .hits
                .iter()
                .all(|hit| hit.classification == "wildcard_or_soft404_candidate")
        );
    }

    #[test]
    fn unsafe_targets_and_paths_are_rejected_before_network() {
        let transport = fake(200);
        for target in [
            "http://example.com",
            "https://user@example.com",
            "https://example.com/private",
            "https://example.com?q=1",
        ] {
            assert!(inspect_headers(&transport, target).is_err());
        }
        for bad in [b"../etc".as_slice(), b"safe?no", b"//host/path", b"%2e%2e"] {
            assert!(parse_paths(bad).is_err(), "{bad:?}");
        }
        assert!(transport.requests.borrow().is_empty());
    }

    #[test]
    fn header_audit_never_leaks_cookie_contents() {
        let transport = fake(200);
        let report = inspect_headers(&transport, "https://example.com").unwrap();
        assert_eq!(report.secure_cookies, 1);
        assert_eq!(report.cookies_without_secure, 1);
        let json = serde_json::to_string(&report).unwrap();
        assert!(!json.contains("session=test"));
        assert!(!json.contains("legacy=test"));
    }
}
