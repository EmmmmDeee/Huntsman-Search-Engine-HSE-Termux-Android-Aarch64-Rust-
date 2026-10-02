use std::cell::RefCell;
use std::collections::VecDeque;

use huntsman_recon::active_probe::{ProbeOptions, probe};
use huntsman_recon::http::{Request, Response, Transport, TransportFailure};
use huntsman_recon::source_outcome::SourceOutcomeKind;

struct Fake {
    script: RefCell<VecDeque<Result<Response, TransportFailure>>>,
    seen: RefCell<Vec<Request>>,
}

impl Fake {
    fn new(script: Vec<Result<Response, TransportFailure>>) -> Self {
        Self {
            script: RefCell::new(script.into()),
            seen: RefCell::default(),
        }
    }
}

impl Transport for Fake {
    fn send(&self, request: &Request) -> Result<Response, TransportFailure> {
        self.seen.borrow_mut().push(request.clone());
        self.script
            .borrow_mut()
            .pop_front()
            .expect("active probe exceeded scripted request budget")
    }
}

fn resp(status: u16, headers: &[(&str, &str)], body: &str) -> Response {
    Response {
        status,
        headers: headers
            .iter()
            .map(|(k, v)| ((*k).into(), (*v).into()))
            .collect(),
        body: body.as_bytes().to_vec(),
        truncated: false,
    }
}

#[test]
fn probes_a_deterministic_bounded_surface_and_extracts_pivots() {
    let f = Fake::new(vec![
        Ok(resp(
            200,
            &[
                ("server", "nginx"),
                ("content-type", "text/html"),
                ("strict-transport-security", "max-age=31536000"),
                (
                    "content-security-policy",
                    "default-src 'self' https://cdn.example.net",
                ),
            ],
            r#"<html><head><title>Example Portal</title></head><body>
<a href="/login">Login</a><script src="https://cdn.example.net/app.js"></script>
</body></html>"#,
        )),
        Ok(resp(
            200,
            &[("content-type", "text/plain")],
            "User-agent: *\nDisallow: /private\nSitemap: https://example.com/sitemap.xml\n",
        )),
        Ok(resp(
            200,
            &[("content-type", "application/xml")],
            "<urlset><url><loc>https://example.com/public</loc></url></urlset>",
        )),
        Ok(resp(
            200,
            &[("content-type", "text/plain")],
            "Contact: mailto:security@example.com\nCanonical: https://example.com/.well-known/security.txt\n",
        )),
    ]);

    let report = probe(&f, "https://example.com", &ProbeOptions::default(), 100)
        .expect("bounded probe succeeds");

    assert_eq!(report.requests_made, 4);
    assert_eq!(report.observations.len(), 4);
    assert_eq!(
        report.observations[0].outcome,
        SourceOutcomeKind::Inconclusive
    );
    assert_eq!(report.fingerprint.title.as_deref(), Some("Example Portal"));
    assert_eq!(report.fingerprint.server.as_deref(), Some("nginx"));
    assert!(report.fingerprint.hsts);
    assert!(report.fingerprint.csp);

    let pivot_urls: Vec<_> = report.pivots.iter().map(|p| p.url.as_str()).collect();
    assert!(pivot_urls.contains(&"https://example.com/login"));
    assert!(pivot_urls.contains(&"https://cdn.example.net/app.js"));
    assert!(pivot_urls.contains(&"https://example.com/public"));
    assert!(pivot_urls.contains(&"https://example.com/sitemap.xml"));

    let recorded = f.seen.borrow();
    let seen: Vec<_> = recorded.iter().map(|r| r.url.as_str()).collect();
    assert_eq!(
        seen,
        vec![
            "https://example.com/",
            "https://example.com/robots.txt",
            "https://example.com/sitemap.xml",
            "https://example.com/.well-known/security.txt",
        ]
    );
    assert!(!seen.iter().any(|u| u.contains("cdn.example.net")));
}

#[test]
fn cross_origin_redirect_is_reported_but_never_followed() {
    let f = Fake::new(vec![Ok(resp(
        302,
        &[("location", "https://outside.example/path")],
        "",
    ))]);

    let report = probe(
        &f,
        "https://example.com",
        &ProbeOptions { max_requests: 1 },
        100,
    )
    .expect("redirect is observed without leaving authorization scope");

    assert_eq!(f.seen.borrow().len(), 1);
    assert_eq!(f.seen.borrow()[0].url, "https://example.com/");
    let pivot = report
        .pivots
        .iter()
        .find(|pivot| pivot.url == "https://outside.example/path")
        .expect("redirect target is retained as a pivot");
    assert!(!pivot.same_origin);
    assert_eq!(pivot.source, "redirect_location");
}

#[test]
fn utf8_lines_cannot_panic_prefix_parsing() {
    let f = Fake::new(vec![
        Ok(resp(200, &[("content-type", "text/html")], "root")),
        Ok(resp(
            200,
            &[("content-type", "text/plain")],
            "aéééé\nSitemap: https://example.com/a\n",
        )),
    ]);

    let report = probe(
        &f,
        "https://example.com",
        &ProbeOptions { max_requests: 2 },
        100,
    )
    .expect("non-ASCII robots lines must not panic");

    assert!(
        report
            .pivots
            .iter()
            .any(|pivot| pivot.url == "https://example.com/a")
    );
}

#[test]
fn request_budget_is_a_hard_stop() {
    let f = Fake::new(vec![
        Ok(resp(200, &[], "root")),
        Ok(resp(200, &[], "robots")),
    ]);
    let report = probe(
        &f,
        "https://example.com/path?q=secret",
        &ProbeOptions { max_requests: 2 },
        100,
    )
    .expect("probe stays within budget");

    assert_eq!(report.requests_made, 2);
    assert_eq!(f.seen.borrow().len(), 2);
    assert_eq!(report.base_url, "https://example.com");
}

#[test]
fn challenge_pages_are_fingerprinted_as_waf_not_success_evidence() {
    let f = Fake::new(vec![Ok(resp(
        200,
        &[("server", "cloudflare")],
        "<html><title>Just a moment...</title>Cloudflare</html>",
    ))]);
    let report = probe(
        &f,
        "https://example.com",
        &ProbeOptions { max_requests: 1 },
        100,
    )
    .expect("challenge is an observation");

    assert_eq!(report.observations[0].outcome, SourceOutcomeKind::BotWaf);
    assert_eq!(report.observations[0].found, None);
}
