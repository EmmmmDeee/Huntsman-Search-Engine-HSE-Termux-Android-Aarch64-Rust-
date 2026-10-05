//! One causal fetch: request, manual redirects, optional credential, outcome.
//!
//! This is where transport meets the typed outcomes. The result says what happened
//! (`SourceOutcomeKind`), never "found". A 200 is `Inconclusive` until a parser
//! turns rows into evidence; a challenge page is a WAF at any status.
//!
//! Credential rules enforced here, independent of the transport:
//! - a credential is only sent to the origin it was approved for (scheme, host and
//!   port of the first URL); a redirect to anywhere else is followed without it;
//! - a credential is only built from an `AuthenticationAuthority`, so a secret found
//!   in breach data cannot authenticate a request;
//! - a 401 after a credential was sent is `AuthRejected`, not `AuthRequired`;
//! - diagnostic text has the credential scrubbed before it is stored.

use std::fmt::Write as _;

use crate::credential_origin::{AuthenticationAuthority, CredentialFingerprint};
use crate::deadline::{Deadline, SystemClock};
use crate::error::Error;
use crate::http::{
    Method, Request, Response, Transport, origin_of, parse_http_uri, redact_url, resolve_location,
};
use crate::keys::Secret;
use crate::redact::scrub_secrets;
use crate::source_outcome::{SourceExecutionOutcome, SourceOutcomeKind, classify_fetch};

pub const DEFAULT_MAX_REDIRECTS: u32 = 5;
/// A provider asking for a longer pause than this is reported as one hour.
const MAX_RETRY_AFTER_SECS: u64 = 3600;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthStyle {
    /// `Authorization: Bearer <secret>`.
    Bearer,
    /// `<name>: <secret>`, e.g. `X-Api-Key`.
    Header(String),
}

/// An operator-approved secret bound to the origin it may be sent to.
pub struct Credential {
    authority: AuthenticationAuthority,
    secret: Secret,
    style: AuthStyle,
    /// The one origin (`scheme://host:port`) the secret may go to. `None` binds it to
    /// the origin of the fetch's first URL.
    origin: Option<&'static str>,
}

impl Credential {
    /// # Errors
    /// `Error::Invalid` when a custom header name is not a plain token.
    pub fn new(
        authority: AuthenticationAuthority,
        secret: Secret,
        style: AuthStyle,
    ) -> Result<Self, Error> {
        if let AuthStyle::Header(name) = &style {
            let ok = !name.is_empty()
                && name
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_');
            if !ok {
                return Err(Error::Invalid(
                    "credential header name must be a token".into(),
                ));
            }
        }
        Ok(Self {
            authority,
            secret,
            style,
            origin: None,
        })
    }

    /// Pin the secret to exactly `origin`, written as [`crate::http::origin_of`]
    /// writes it (`https://host:443`). A hop is sent with the secret only while every
    /// hop so far, that one included, is exactly this origin; the pin is a
    /// compile-time constant, so nothing at runtime can widen it.
    #[must_use]
    pub const fn only_for_origin(mut self, origin: &'static str) -> Self {
        self.origin = Some(origin);
        self
    }

    #[must_use]
    pub fn fingerprint(&self) -> CredentialFingerprint {
        self.secret.fingerprint()
    }

    #[must_use]
    pub fn provider_id(&self) -> &str {
        self.authority.provider_id()
    }

    /// `request` without this credential's header (and without any other header
    /// marked sensitive): stripped, not merely not added.
    fn strip(&self, request: &Request) -> Request {
        let mut r = without_credentials(request);
        if let AuthStyle::Header(name) = &self.style {
            r.headers.retain(|(k, _)| !k.eq_ignore_ascii_case(name));
        }
        r
    }

    fn apply(&self, request: Request) -> Request {
        match &self.style {
            AuthStyle::Bearer => {
                request.header("Authorization", format!("Bearer {}", self.secret.expose()))
            }
            AuthStyle::Header(name) => request.header(name.clone(), self.secret.expose()),
        }
    }
}

#[derive(Debug, Clone)]
pub struct FetchOptions {
    pub max_redirects: u32,
    pub redirect_policy: RedirectPolicy,
}

impl Default for FetchOptions {
    fn default() -> Self {
        Self {
            max_redirects: DEFAULT_MAX_REDIRECTS,
            redirect_policy: RedirectPolicy::Any,
        }
    }
}

impl FetchOptions {
    /// Redirects not followed: a 3xx is the answer.
    #[must_use]
    pub const fn no_redirects() -> Self {
        Self {
            max_redirects: 0,
            redirect_policy: RedirectPolicy::Any,
        }
    }
}

/// Which redirect hops [`fetch`] follows. Every followed hop is still sent through
/// the caller's transport (egress-guarded resolver) and the caller's deadline.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RedirectPolicy {
    /// Any http(s) hop, up to `max_redirects`.
    Any,
    /// The monolith's `redirect_verdict` (`src/util/http/ssrf.rs`) for a first URL
    /// inside `site`: a hop is followed only when its host equals the first URL's
    /// host (ASCII case-insensitive) or both lie in `site` (the registrable domain:
    /// `site` itself or a subdomain of it, any port), and an `https` first URL is
    /// never followed to a non-`https` hop. Anything else is refused before it is
    /// requested; the 3xx is the answer.
    ///
    /// `site` must be a registrable domain with no Public Suffix List rule at or
    /// below it, so "ends with `.site`" is exactly "same eTLD+1"; that is checked for
    /// each constant passed here (`stolen.tax`: the list has `tax` and nothing under
    /// it).
    SameSite { site: &'static str },
}

#[derive(Debug)]
pub struct Fetched {
    pub outcome: SourceExecutionOutcome,
    /// `None` when no HTTP response was obtained (DNS, connect, TLS, timeout).
    pub response: Option<Response>,
    /// Redacted URL of the last request made.
    pub final_url: String,
    pub redirects: u32,
    /// Fingerprint of the credential if one was sent on the last request.
    pub credential_sent: Option<CredentialFingerprint>,
    /// Why a redirect was not followed under [`RedirectPolicy::SameSite`]; the 3xx
    /// is then the response.
    pub redirect_refused: Option<&'static str>,
    /// Set when hop N (1-based: the first request is hop 1) was not sent because
    /// the deadline was already spent. There is then no response.
    pub not_sent_hop: Option<u32>,
}

/// Fetch `request` through `transport`.
///
/// A request cap ([`Request::with_timeout`]) bounds the whole fetch, every redirect
/// hop included: each hop is sent with what is left of the cap, not the cap again.
///
/// # Errors
/// `Error::Network` when the URL is not http(s), the egress policy refused the
/// destination, or a redirect target is malformed. Causal transport results
/// (timeout, TLS, DNS, ...) are *not* errors; they come back as `outcome.kind`.
pub fn fetch<T: Transport + ?Sized>(
    transport: &T,
    request: Request,
    credential: Option<&Credential>,
    options: &FetchOptions,
    module: &str,
    now_unix: u64,
) -> Result<Fetched, Error> {
    match request.timeout {
        Some(cap) => {
            let deadline = Deadline::start(&SystemClock, cap);
            fetch_within(
                transport, request, credential, options, &deadline, module, now_unix,
            )
        }
        None => fetch_hops(
            transport, request, credential, options, None, module, now_unix,
        ),
    }
}

/// [`fetch`] inside a caller's [`Deadline`]. Before every hop (the first request and
/// each redirect) the hop's cap is recomputed as the smaller of what is left of
/// `deadline` and the request's own cap, so a timeout is only ever lowered and a
/// redirect chain cannot outlive the deadline. A hop that would start with nothing
/// left is not sent: the result is `TtfbTimeout` with no response.
///
/// # Errors
/// As [`fetch`].
pub fn fetch_within<T: Transport + ?Sized>(
    transport: &T,
    request: Request,
    credential: Option<&Credential>,
    options: &FetchOptions,
    deadline: &Deadline<'_>,
    module: &str,
    now_unix: u64,
) -> Result<Fetched, Error> {
    fetch_hops(
        transport,
        request,
        credential,
        options,
        Some(deadline),
        module,
        now_unix,
    )
}

fn fetch_hops<T: Transport + ?Sized>(
    transport: &T,
    request: Request,
    credential: Option<&Credential>,
    options: &FetchOptions,
    deadline: Option<&Deadline<'_>>,
    module: &str,
    now_unix: u64,
) -> Result<Fetched, Error> {
    parse_http_uri(&request.url)?;
    let first_url = request.url.clone();
    let key_origin = credential
        .and_then(|c| c.origin.map(str::to_owned))
        .or_else(|| origin_of(&request.url));
    // Once a hop leaves the credential's origin the credential is never re-attached,
    // even if a later hop comes back.
    let mut left_origin = false;
    let secret_text = credential.map(|c| c.secret.expose());
    let scrub = |text: &str| match secret_text {
        Some(s) => scrub_secrets(text, &[s]),
        None => text.to_owned(),
    };

    let mut current = request;
    let mut redirects = 0u32;
    loop {
        if let Some(deadline) = deadline {
            let remaining = deadline.remaining();
            if remaining.is_zero() {
                return Ok(not_sent(module, now_unix, deadline, &current, redirects));
            }
            // Only ever lower: the request's own cap still applies when it is smaller.
            current.timeout = Some(current.timeout.map_or(remaining, |cap| cap.min(remaining)));
        }
        let hop_origin = origin_of(&current.url);
        left_origin |= hop_origin.is_none() || hop_origin != key_origin;
        let (to_send, sent) = match credential {
            Some(c) if !left_origin => (c.apply(c.strip(&current)), Some(c.fingerprint())),
            Some(c) => (c.strip(&current), None),
            None if left_origin => (without_credentials(&current), None),
            None => (current.clone(), None),
        };

        let response = match transport.send(&to_send) {
            Ok(r) => r,
            Err(failure) if failure.blocked => {
                return Err(Error::Network(scrub(&failure.detail)));
            }
            Err(failure) => {
                let outcome = SourceExecutionOutcome::success(module, now_unix, 0);
                let outcome = SourceExecutionOutcome {
                    kind: failure.kind,
                    found: None,
                    detail: Some(scrub(&failure.detail)),
                    ..outcome
                };
                return Ok(Fetched {
                    outcome,
                    response: None,
                    final_url: redact_url(&current.url),
                    redirects,
                    credential_sent: sent,
                    redirect_refused: None,
                    not_sent_hop: None,
                });
            }
        };

        let next = match redirect_target(&current, &response) {
            Ok(next) => next,
            // The monolith's client did not follow a Location it could not parse
            // into an http(s) URL with a host; the 3xx was the answer.
            Err(_) if matches!(options.redirect_policy, RedirectPolicy::SameSite { .. }) => {
                let refusal = Refusal {
                    why: "redirect refused: unusable Location",
                    redirects,
                    sent,
                };
                return Ok(refusal.finish(module, now_unix, &current, response, &scrub));
            }
            Err(e) => return Err(e),
        };
        if let Some(next) = next {
            if redirects >= options.max_redirects {
                return Ok(finish(
                    module,
                    now_unix,
                    &current,
                    response,
                    redirects,
                    sent,
                    Some("redirect limit reached"),
                    &scrub,
                ));
            }
            if let Some(why) = refused_hop(options.redirect_policy, &first_url, &next.url) {
                let refusal = Refusal {
                    why,
                    redirects,
                    sent,
                };
                return Ok(refusal.finish(module, now_unix, &current, response, &scrub));
            }
            redirects += 1;
            current = next;
            continue;
        }
        return Ok(finish(
            module, now_unix, &current, response, redirects, sent, None, &scrub,
        ));
    }
}

#[allow(clippy::too_many_arguments)] // one call site shape; a struct would only rename the arguments
fn finish(
    module: &str,
    now_unix: u64,
    request: &Request,
    response: Response,
    redirects: u32,
    sent: Option<CredentialFingerprint>,
    note: Option<&str>,
    scrub: &dyn Fn(&str) -> String,
) -> Fetched {
    let text = response.text();
    let mut kind = classify_fetch(response.status, &text);
    if kind == SourceOutcomeKind::AuthRequired && sent.is_some() {
        kind = SourceOutcomeKind::AuthRejected;
    }
    let mut detail = format!("bytes={}", response.body.len());
    if response.truncated {
        detail.push_str(" truncated");
    }
    if redirects > 0 {
        let _ = write!(detail, " redirects={redirects}");
    }
    if let Some(n) = note {
        detail.push(' ');
        detail.push_str(n);
    }
    let mut outcome = SourceExecutionOutcome::success(module, now_unix, 0)
        .with_http_status(response.status)
        .with_detail(scrub(&detail));
    outcome.kind = kind;
    outcome.found = None;
    if matches!(response.status, 429 | 503) {
        if let Some(secs) = response
            .header_value("retry-after")
            .and_then(parse_retry_after)
        {
            outcome = outcome.with_retry_after(secs.min(MAX_RETRY_AFTER_SECS));
        }
    }
    Fetched {
        outcome,
        final_url: redact_url(&request.url),
        response: Some(response),
        redirects,
        credential_sent: sent,
        redirect_refused: None,
        not_sent_hop: None,
    }
}

/// The result for hop `redirects + 1` when `deadline` was spent before it was sent.
fn not_sent(
    module: &str,
    now_unix: u64,
    deadline: &Deadline<'_>,
    current: &Request,
    redirects: u32,
) -> Fetched {
    let outcome = SourceExecutionOutcome::success(module, now_unix, 0);
    let outcome = SourceExecutionOutcome {
        kind: SourceOutcomeKind::TtfbTimeout,
        found: None,
        detail: Some(format!(
            "{:.1}s budget spent before hop {}; not sent",
            deadline.budget().as_secs_f64(),
            redirects + 1
        )),
        ..outcome
    };
    Fetched {
        outcome,
        response: None,
        final_url: redact_url(&current.url),
        redirects,
        credential_sent: None,
        redirect_refused: None,
        not_sent_hop: Some(redirects + 1),
    }
}

/// A redirect the policy would not follow: the 3xx is the answer.
struct Refusal {
    why: &'static str,
    redirects: u32,
    sent: Option<CredentialFingerprint>,
}

impl Refusal {
    fn finish(
        self,
        module: &str,
        now_unix: u64,
        current: &Request,
        response: Response,
        scrub: &dyn Fn(&str) -> String,
    ) -> Fetched {
        let mut fetched = finish(
            module,
            now_unix,
            current,
            response,
            self.redirects,
            self.sent,
            Some(self.why),
            scrub,
        );
        fetched.redirect_refused = Some(self.why);
        fetched
    }
}

/// Why `policy` refuses the hop from the chain that began at `first` to `next`, or
/// `None` to follow it. **Pure.**
fn refused_hop(policy: RedirectPolicy, first: &str, next: &str) -> Option<&'static str> {
    let RedirectPolicy::SameSite { site } = policy else {
        return None;
    };
    let (Ok(first), Ok(next)) = (parse_http_uri(first), parse_http_uri(next)) else {
        return Some("redirect refused: unparseable hop");
    };
    let (Some(a), Some(b)) = (first.host(), next.host()) else {
        return Some("redirect refused: no host");
    };
    let same_site = a.eq_ignore_ascii_case(b) || (in_site(a, site) && in_site(b, site));
    if !same_site {
        return Some("redirect refused: off-site hop");
    }
    if first.scheme_str() == Some("https") && next.scheme_str() != Some("https") {
        return Some("redirect refused: https to http downgrade");
    }
    None
}

/// `host` is `site` or a subdomain of it: the monolith's
/// `registrable_domain(host) == registrable_domain(site)` for a `site` with no
/// Public Suffix List rule at or below it. Trims, lowercases and drops trailing dots
/// as the monolith did; an IP literal or an empty label is never in a site. **Pure.**
fn in_site(host: &str, site: &str) -> bool {
    let host = host.trim().trim_end_matches('.').to_ascii_lowercase();
    if host.is_empty() || host.split('.').any(str::is_empty) || host.starts_with('[') {
        return false;
    }
    host == site
        || host
            .strip_suffix(site)
            .is_some_and(|rest| rest.ends_with('.'))
}

/// Delta-seconds only; HTTP-date values are ignored rather than guessed at.
fn parse_retry_after(v: &str) -> Option<u64> {
    v.trim().parse().ok()
}

/// `url` with any `user:pass@` removed from its authority. **Pure.**
fn without_userinfo(url: &str) -> String {
    let Some((scheme, rest)) = url.split_once("://") else {
        return url.to_owned();
    };
    let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let (authority, tail) = rest.split_at(end);
    match authority.rsplit_once('@') {
        Some((_, host)) => format!("{scheme}://{host}{tail}"),
        None => url.to_owned(),
    }
}

fn without_credentials(request: &Request) -> Request {
    let mut r = request.clone();
    r.headers
        .retain(|(k, _)| !crate::http::is_sensitive_header(k));
    r
}

fn redirect_target(current: &Request, response: &Response) -> Result<Option<Request>, Error> {
    if !matches!(response.status, 301 | 302 | 303 | 307 | 308) {
        return Ok(None);
    }
    let Some(location) = response.header_value("location") else {
        return Ok(None);
    };
    let url = resolve_location(&current.url, location)?;
    let mut next = current.clone();
    // A redirect target's userinfo is never sent: the transport would turn it into
    // an `Authorization: Basic` header.
    next.url = without_userinfo(&url);
    let to_get = response.status == 303
        || (matches!(response.status, 301 | 302) && current.method == Method::Post);
    if to_get {
        next.method = Method::Get;
        next.body.clear();
        next.headers
            .retain(|(k, _)| !k.to_ascii_lowercase().starts_with("content-"));
    }
    if origin_of(&next.url) != origin_of(&current.url) {
        // Anything the caller marked sensitive stays on the origin it was meant for.
        next = without_credentials(&next);
    }
    Ok(Some(next))
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::collections::VecDeque;

    use super::*;
    use crate::credential_origin::OperatorCredentialRef;
    use crate::http::TransportFailure;

    /// Scripted transport that records what it was asked to send.
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
                .expect("script exhausted")
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

    fn cred(secret: &str, style: AuthStyle) -> Credential {
        let authority = AuthenticationAuthority::operator_approved(OperatorCredentialRef {
            provider_id: "example".into(),
            credential_slot: "EXAMPLE_KEY".into(),
            approved_at_unix: 1,
            approval_provenance: "test".into(),
        })
        .expect("authority");
        Credential::new(authority, Secret::new(secret).expect("secret"), style).expect("cred")
    }

    fn run(f: &Fake, url: &str, c: Option<&Credential>, max: u32) -> Result<Fetched, Error> {
        fetch(
            f,
            Request::get(url),
            c,
            &FetchOptions {
                max_redirects: max,
                ..FetchOptions::default()
            },
            "t",
            100,
        )
    }

    #[test]
    fn ok_page_is_inconclusive_not_found() {
        let f = Fake::new(vec![Ok(resp(200, &[], "hello"))]);
        let r = run(&f, "https://a.example/x", None, 5).expect("fetch");
        assert_eq!(r.outcome.kind, SourceOutcomeKind::Inconclusive);
        assert_eq!(r.outcome.found, None);
        assert_eq!(r.outcome.http_status, Some(200));
        assert!(r.credential_sent.is_none());
    }

    #[test]
    fn challenge_page_is_a_waf_even_at_200() {
        let f = Fake::new(vec![Ok(resp(
            200,
            &[],
            "<html><title>Just a moment...</title>Cloudflare</html>",
        ))]);
        let r = run(&f, "https://a.example/", None, 0).expect("fetch");
        assert_eq!(r.outcome.kind, SourceOutcomeKind::BotWaf);
    }

    #[test]
    fn rate_limit_carries_a_bounded_retry_after() {
        let f = Fake::new(vec![Ok(resp(429, &[("retry-after", "120")], ""))]);
        assert_eq!(
            run(&f, "https://a.example/", None, 0)
                .expect("f")
                .outcome
                .retry_after_secs,
            Some(120)
        );
        let f = Fake::new(vec![Ok(resp(429, &[("retry-after", "999999")], ""))]);
        assert_eq!(
            run(&f, "https://a.example/", None, 0)
                .expect("f")
                .outcome
                .retry_after_secs,
            Some(3600)
        );
        let f = Fake::new(vec![Ok(resp(
            429,
            &[("retry-after", "Wed, 21 Oct 2026 07:28:00 GMT")],
            "",
        ))]);
        assert_eq!(
            run(&f, "https://a.example/", None, 0)
                .expect("f")
                .outcome
                .retry_after_secs,
            None
        );
    }

    #[test]
    fn transport_failures_keep_their_cause() {
        for kind in [
            SourceOutcomeKind::DnsFailure,
            SourceOutcomeKind::TlsFailure,
            SourceOutcomeKind::TtfbTimeout,
        ] {
            let f = Fake::new(vec![Err(TransportFailure {
                kind,
                detail: "x".into(),
                blocked: false,
            })]);
            let r = run(&f, "https://a.example/", None, 0).expect("fetch");
            assert_eq!(r.outcome.kind, kind);
            assert!(r.response.is_none());
            assert!(r.outcome.kind.is_transport_failure());
        }
    }

    #[test]
    fn blocked_egress_is_an_error_not_an_outcome() {
        let f = Fake::new(vec![Err(TransportFailure {
            kind: SourceOutcomeKind::ConnectFailure,
            detail: "egress-policy: destination (10.0.0.1) is not publicly routable".into(),
            blocked: true,
        })]);
        let err = run(&f, "https://a.example/", None, 0).expect_err("blocked");
        assert!(matches!(err, Error::Network(m) if m.contains("egress-policy")));
    }

    #[test]
    fn non_http_urls_never_reach_the_transport() {
        let f = Fake::new(vec![]);
        for u in ["file:///etc/passwd", "ftp://a/", "/relative", ""] {
            assert!(run(&f, u, None, 0).is_err(), "{u}");
        }
        assert!(f.seen.borrow().is_empty());
    }

    #[test]
    fn bearer_is_sent_to_its_origin_and_recorded_by_fingerprint() {
        let c = cred("tok-abcdef-123456", AuthStyle::Bearer);
        let f = Fake::new(vec![Ok(resp(200, &[], "{}"))]);
        let r = run(&f, "https://a.example/api", Some(&c), 5).expect("fetch");
        assert_eq!(
            f.seen.borrow()[0].header_value("authorization"),
            Some("Bearer tok-abcdef-123456")
        );
        assert_eq!(r.credential_sent, Some(c.fingerprint()));
        assert!(!format!("{r:?}").contains("tok-abcdef"));
    }

    #[test]
    fn custom_header_style_and_validation() {
        let c = cred("tok-abcdef-123456", AuthStyle::Header("X-Api-Key".into()));
        let f = Fake::new(vec![Ok(resp(200, &[], ""))]);
        run(&f, "https://a.example/", Some(&c), 0).expect("fetch");
        assert_eq!(
            f.seen.borrow()[0].header_value("x-api-key"),
            Some("tok-abcdef-123456")
        );
        let authority = AuthenticationAuthority::operator_approved(OperatorCredentialRef {
            provider_id: "p".into(),
            credential_slot: "P_KEY".into(),
            approved_at_unix: 1,
            approval_provenance: "t".into(),
        })
        .expect("authority");
        let bad = Credential::new(
            authority,
            Secret::new("tok-abcdef-123456").expect("s"),
            AuthStyle::Header("X: y\r\nZ".into()),
        );
        assert!(bad.is_err());
    }

    #[test]
    fn credential_is_stripped_when_a_redirect_leaves_the_origin() {
        let c = cred("tok-abcdef-123456", AuthStyle::Bearer);
        let f = Fake::new(vec![
            Ok(resp(302, &[("location", "https://evil.example/steal")], "")),
            Ok(resp(200, &[], "")),
        ]);
        let r = run(&f, "https://a.example/api", Some(&c), 5).expect("fetch");
        let seen = f.seen.borrow();
        assert!(seen[0].header_value("authorization").is_some());
        assert!(
            seen[1].header_value("authorization").is_none(),
            "leaked across origins"
        );
        assert_eq!(seen[1].url, "https://evil.example/steal");
        assert!(r.credential_sent.is_none());
        assert_eq!(r.redirects, 1);
    }

    #[test]
    fn https_to_http_downgrade_on_the_same_host_loses_the_credential() {
        let c = cred("tok-abcdef-123456", AuthStyle::Bearer);
        let f = Fake::new(vec![
            Ok(resp(301, &[("location", "http://a.example/api")], "")),
            Ok(resp(200, &[], "")),
        ]);
        run(&f, "https://a.example/api", Some(&c), 5).expect("fetch");
        assert!(f.seen.borrow()[1].header_value("authorization").is_none());
    }

    #[test]
    fn same_origin_redirect_keeps_the_credential() {
        let c = cred("tok-abcdef-123456", AuthStyle::Bearer);
        let f = Fake::new(vec![
            Ok(resp(307, &[("location", "/v2/api")], "")),
            Ok(resp(200, &[], "")),
        ]);
        let r = run(&f, "https://a.example/v1/api", Some(&c), 5).expect("fetch");
        assert!(f.seen.borrow()[1].header_value("authorization").is_some());
        assert_eq!(r.final_url, "https://a.example/v2/api");
    }

    #[test]
    fn caller_supplied_sensitive_headers_also_do_not_cross_origins() {
        let f = Fake::new(vec![
            Ok(resp(302, &[("location", "https://b.example/")], "")),
            Ok(resp(200, &[], "")),
        ]);
        let req = Request::get("https://a.example/")
            .header("Cookie", "sid=1")
            .header("Accept", "*/*");
        fetch(&f, req, None, &FetchOptions::default(), "t", 1).expect("fetch");
        let seen = f.seen.borrow();
        assert!(seen[0].header_value("cookie").is_some());
        assert!(seen[1].header_value("cookie").is_none());
        assert_eq!(seen[1].header_value("accept"), Some("*/*"));
    }

    #[test]
    fn redirect_loops_stop_at_the_limit_and_say_so() {
        let hop = || Ok(resp(302, &[("location", "/again")], ""));
        let f = Fake::new((0..10).map(|_| hop()).collect());
        let r = run(&f, "https://a.example/", None, 3).expect("fetch");
        assert_eq!(r.redirects, 3);
        assert_eq!(f.seen.borrow().len(), 4);
        assert_eq!(r.outcome.kind, SourceOutcomeKind::RedirectChanged);
        assert!(
            r.outcome
                .detail
                .as_deref()
                .is_some_and(|d| d.contains("redirect limit"))
        );
    }

    #[test]
    fn redirects_disabled_report_a_changed_contract() {
        let f = Fake::new(vec![Ok(resp(
            301,
            &[("location", "https://b.example/")],
            "",
        ))]);
        let r = run(&f, "https://a.example/", None, 0).expect("fetch");
        assert_eq!(r.outcome.kind, SourceOutcomeKind::RedirectChanged);
        assert_eq!(f.seen.borrow().len(), 1);
    }

    #[test]
    fn redirect_to_a_non_http_scheme_is_refused() {
        let f = Fake::new(vec![Ok(resp(
            302,
            &[("location", "file:///etc/passwd")],
            "",
        ))]);
        assert!(run(&f, "https://a.example/", None, 5).is_err());
        assert_eq!(f.seen.borrow().len(), 1);
    }

    #[test]
    fn a_post_becomes_a_bodyless_get_on_303() {
        let f = Fake::new(vec![
            Ok(resp(303, &[("location", "/done")], "")),
            Ok(resp(200, &[], "")),
        ]);
        let req = Request::post("https://a.example/submit", b"data".to_vec())
            .header("Content-Type", "text/plain");
        fetch(&f, req, None, &FetchOptions::default(), "t", 1).expect("fetch");
        let seen = f.seen.borrow();
        assert_eq!(seen[1].method, Method::Get);
        assert!(seen[1].body.is_empty() && seen[1].header_value("content-type").is_none());
    }

    #[test]
    fn a_307_keeps_method_and_body() {
        let f = Fake::new(vec![
            Ok(resp(307, &[("location", "/again")], "")),
            Ok(resp(200, &[], "")),
        ]);
        fetch(
            &f,
            Request::post("https://a.example/s", b"data".to_vec()),
            None,
            &FetchOptions::default(),
            "t",
            1,
        )
        .expect("fetch");
        let seen = f.seen.borrow();
        assert_eq!(
            (seen[1].method, seen[1].body.as_slice()),
            (Method::Post, &b"data"[..])
        );
    }

    #[test]
    fn rejected_credential_is_distinguished_from_a_missing_one() {
        let f = Fake::new(vec![Ok(resp(401, &[], "no"))]);
        let anon = run(&f, "https://a.example/", None, 0).expect("fetch");
        assert_eq!(anon.outcome.kind, SourceOutcomeKind::AuthRequired);
        let c = cred("tok-abcdef-123456", AuthStyle::Bearer);
        let f = Fake::new(vec![Ok(resp(401, &[], "no"))]);
        let sent = run(&f, "https://a.example/", Some(&c), 0).expect("fetch");
        assert_eq!(sent.outcome.kind, SourceOutcomeKind::AuthRejected);
    }

    #[test]
    fn echoed_credentials_do_not_survive_into_diagnostics() {
        let c = cred("tok-abcdef-123456", AuthStyle::Bearer);
        let f = Fake::new(vec![Err(TransportFailure {
            kind: SourceOutcomeKind::ConnectFailure,
            detail: "proxy said: bad Bearer tok-abcdef-123456".into(),
            blocked: false,
        })]);
        let r = run(&f, "https://a.example/", Some(&c), 0).expect("fetch");
        let detail = r.outcome.detail.expect("detail");
        assert!(!detail.contains("tok-abcdef"));
    }

    #[test]
    fn truncation_is_visible_in_the_outcome() {
        let mut big = resp(200, &[], "xxxx");
        big.truncated = true;
        let f = Fake::new(vec![Ok(big)]);
        let r = run(&f, "https://a.example/", None, 0).expect("fetch");
        assert!(r.outcome.detail.expect("detail").contains("truncated"));
    }

    /// Every hop answers `302` to the next one after `delay` on a fake clock; a
    /// delay longer than the hop's cap times out after the cap, like the transport.
    struct SlowChain<'c> {
        clock: &'c crate::deadline::FakeClock,
        delay: std::time::Duration,
        caps: RefCell<Vec<Option<std::time::Duration>>>,
    }

    impl Transport for SlowChain<'_> {
        fn send(&self, request: &Request) -> Result<Response, TransportFailure> {
            let n = self.caps.borrow().len();
            self.caps.borrow_mut().push(request.timeout);
            if let Some(cap) = request.timeout.filter(|cap| self.delay > *cap) {
                self.clock.advance(cap);
                return Err(TransportFailure {
                    kind: SourceOutcomeKind::TtfbTimeout,
                    detail: "timed out".into(),
                    blocked: false,
                });
            }
            self.clock.advance(self.delay);
            Ok(resp(302, &[("location", &format!("/hop{}", n + 1))], ""))
        }
    }

    fn ms(n: u64) -> std::time::Duration {
        std::time::Duration::from_millis(n)
    }

    fn chain_within(
        delay: u64,
        request: Request,
    ) -> (
        Fetched,
        Vec<Option<std::time::Duration>>,
        std::time::Duration,
    ) {
        let clock = crate::deadline::FakeClock::new();
        let chain = SlowChain {
            clock: &clock,
            delay: ms(delay),
            caps: RefCell::default(),
        };
        let deadline = Deadline::start(&clock, ms(1000));
        let fetched = fetch_within(
            &chain,
            request,
            None,
            &FetchOptions::default(),
            &deadline,
            "t",
            100,
        )
        .expect("fetch");
        let caps = chain.caps.into_inner();
        (fetched, caps, clock.elapsed())
    }

    #[test]
    fn each_redirect_hop_gets_only_what_is_left_of_the_deadline() {
        let (fetched, caps, elapsed) = chain_within(400, Request::get("https://a.example/"));
        assert_eq!(caps, [Some(ms(1000)), Some(ms(600)), Some(ms(200))]);
        assert_eq!(elapsed, ms(1000));
        assert_eq!(fetched.outcome.kind, SourceOutcomeKind::TtfbTimeout);
        assert!(fetched.response.is_none());
        assert_eq!(fetched.redirects, 2);
    }

    #[test]
    fn a_hop_with_nothing_left_is_not_sent() {
        let (fetched, caps, elapsed) = chain_within(500, Request::get("https://a.example/"));
        assert_eq!(caps, [Some(ms(1000)), Some(ms(500))]);
        assert_eq!(elapsed, ms(1000));
        assert_eq!(fetched.outcome.kind, SourceOutcomeKind::TtfbTimeout);
        assert!(fetched.response.is_none());
        assert_eq!(fetched.redirects, 2);
        assert_eq!(
            fetched.outcome.detail.as_deref(),
            Some("1.0s budget spent before hop 3; not sent")
        );
        assert!(fetched.final_url.ends_with("/hop2"));
        assert!(fetched.credential_sent.is_none());
    }

    #[test]
    fn a_smaller_request_cap_is_kept_on_every_hop() {
        let (fetched, caps, _) = chain_within(
            100,
            Request::get("https://a.example/").with_timeout(ms(300)),
        );
        // Six requests (the first plus five redirects), never raised above 300 ms.
        assert_eq!(caps, vec![Some(ms(300)); 6]);
        assert_eq!(fetched.redirects, 5);
        assert!(
            fetched
                .outcome
                .detail
                .expect("detail")
                .contains("redirect limit reached")
        );
    }

    #[test]
    fn an_uncapped_fetch_leaves_every_hop_to_the_transport_timeout() {
        let f = Fake::new(vec![
            Ok(resp(302, &[("location", "/b")], "")),
            Ok(resp(200, &[], "ok")),
        ]);
        let r = run(&f, "https://a.example/", None, 5).expect("fetch");
        assert_eq!(r.redirects, 1);
        assert!(f.seen.borrow().iter().all(|req| req.timeout.is_none()));
    }

    #[test]
    fn same_site_follows_the_monolith_s_redirect_verdict() {
        let site = RedirectPolicy::SameSite { site: "stolen.tax" };
        let first = "https://stolen.tax/api/v2/index.php?path=snusbase";
        for next in [
            "https://stolen.tax/other",
            "https://STOLEN.TAX/other",
            "https://api.stolen.tax/v2",
            "https://a.b.stolen.tax/v2",
            "https://stolen.tax:8443/v2",
            "https://stolen.tax./v2",
        ] {
            assert_eq!(refused_hop(site, first, next), None, "{next}");
        }
        for (next, why) in [
            ("https://evil.example/", "redirect refused: off-site hop"),
            (
                "https://stolen.tax@evil.example/",
                "redirect refused: off-site hop",
            ),
            (
                "https://stolen.tax:443@evil.example/",
                "redirect refused: off-site hop",
            ),
            ("https://xstolen.tax/", "redirect refused: off-site hop"),
            (
                "https://stolen.tax.evil.example/",
                "redirect refused: off-site hop",
            ),
            ("https://a..stolen.tax/", "redirect refused: off-site hop"),
            ("https://127.0.0.1/", "redirect refused: off-site hop"),
            ("https://[::1]/", "redirect refused: off-site hop"),
            (
                "http://stolen.tax/",
                "redirect refused: https to http downgrade",
            ),
            (
                "http://api.stolen.tax/",
                "redirect refused: https to http downgrade",
            ),
        ] {
            assert_eq!(refused_hop(site, first, next), Some(why), "{next}");
        }
        assert_eq!(
            refused_hop(RedirectPolicy::Any, first, "http://evil.example/"),
            None
        );
    }

    #[test]
    fn userinfo_is_dropped_from_a_redirect_target() {
        assert_eq!(
            without_userinfo("https://u:p@www.stolen.tax/x?a=b@c"),
            "https://www.stolen.tax/x?a=b@c"
        );
        assert_eq!(
            without_userinfo("https://stolen.tax:443@evil.example/"),
            "https://evil.example/"
        );
        assert_eq!(
            without_userinfo("https://a.example/p"),
            "https://a.example/p"
        );
    }

    #[test]
    fn a_pinned_credential_goes_only_to_its_origin_and_never_back_after_leaving() {
        let c =
            cred("tok-abcdef-123456", AuthStyle::Bearer).only_for_origin("https://a.example:443");
        let f = Fake::new(vec![
            Ok(resp(302, &[("location", "https://b.a.example/")], "")),
            Ok(resp(302, &[("location", "https://a.example/back")], "")),
            Ok(resp(200, &[], "")),
        ]);
        let r = run(&f, "https://a.example/start", Some(&c), 5).expect("fetch");
        let seen = f.seen.borrow();
        assert!(seen[0].header_value("authorization").is_some());
        assert!(seen[1].header_value("authorization").is_none());
        assert!(
            seen[2].header_value("authorization").is_none(),
            "re-attached on return"
        );
        assert!(r.credential_sent.is_none());

        let elsewhere = Fake::new(vec![Ok(resp(200, &[], ""))]);
        run(&elsewhere, "https://a.example:8443/", Some(&c), 0).expect("fetch");
        assert!(
            elsewhere.seen.borrow()[0]
                .header_value("authorization")
                .is_none()
        );
    }

    #[test]
    fn a_custom_key_header_is_stripped_off_origin_even_if_the_caller_set_it() {
        let c = cred("tok-abcdef-123456", AuthStyle::Header("X-Feed".into()));
        let f = Fake::new(vec![
            Ok(resp(307, &[("location", "https://b.example/")], "")),
            Ok(resp(200, &[], "")),
        ]);
        fetch(
            &f,
            Request::get("https://a.example/").header("X-Feed", "caller-copy"),
            Some(&c),
            &FetchOptions::default(),
            "t",
            100,
        )
        .expect("fetch");
        let seen = f.seen.borrow();
        assert_eq!(
            seen[0]
                .headers
                .iter()
                .filter(|(k, _)| k == "X-Feed")
                .count(),
            1
        );
        assert!(seen[1].header_value("x-feed").is_none());
    }

    #[test]
    fn an_unusable_location_is_a_refused_hop_under_same_site() {
        let f = Fake::new(vec![Ok(resp(
            302,
            &[("location", "javascript:alert(1)")],
            "",
        ))]);
        let r = fetch(
            &f,
            Request::get("https://stolen.tax/"),
            None,
            &FetchOptions {
                max_redirects: 9,
                redirect_policy: RedirectPolicy::SameSite { site: "stolen.tax" },
            },
            "t",
            100,
        )
        .expect("a refused hop, not an error");
        assert_eq!(
            r.redirect_refused,
            Some("redirect refused: unusable Location")
        );
        assert_eq!(f.seen.borrow().len(), 1);
    }
}
