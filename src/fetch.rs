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
//! - a 403 to a request that carried no credential is `Upstream4xx`, never `AuthRejected`:
//!   only a sent credential can be rejected;
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
pub(crate) const MAX_RETRY_AFTER_SECS: u64 = 3600;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthStyle {
    /// `Authorization: Bearer <secret>`.
    Bearer,
    /// `<name>: <secret>`, e.g. `X-Api-Key`.
    Header(String),
    /// `?<name>=<secret>` appended to the URL, for providers that take the key only as a query
    /// parameter (Shodan, Whoxy). The URL the caller passes never holds the key: it is added to
    /// the request as it is sent, removed from anything the caller set under that name, and every
    /// recorded URL is [`redact_url`]ed.
    Query(String),
    /// `Authorization: Basic <base64(secret)>` (RFC 7617). The secret is the joined
    /// `user:password` pair, so the pair is one value that is fingerprinted, pinned and
    /// scrubbed like any other credential.
    Basic,
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

/// Whether `name` may name a credential's header or query parameter: a non-empty token of ASCII
/// letters, digits, `-` and `_`, so it can carry no separator, space or line break.
#[must_use]
pub fn valid_param_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

impl Credential {
    /// # Errors
    /// `Error::Invalid` when a custom header name is not a plain token.
    pub fn new(
        authority: AuthenticationAuthority,
        secret: Secret,
        style: AuthStyle,
    ) -> Result<Self, Error> {
        if let AuthStyle::Header(name) | AuthStyle::Query(name) = &style {
            if !valid_param_name(name) {
                return Err(Error::Invalid(
                    "credential header or parameter name must be a token".into(),
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
        match &self.style {
            AuthStyle::Header(name) => r.headers.retain(|(k, _)| !k.eq_ignore_ascii_case(name)),
            AuthStyle::Query(name) => r.url = without_query_param(&r.url, name),
            AuthStyle::Bearer | AuthStyle::Basic => {}
        }
        r
    }

    fn apply(&self, request: Request) -> Request {
        match &self.style {
            AuthStyle::Bearer => {
                request.header("Authorization", format!("Bearer {}", self.secret.expose()))
            }
            AuthStyle::Header(name) => request.header(name.clone(), self.secret.expose()),
            AuthStyle::Query(name) => {
                let mut request = request;
                request.url =
                    crate::http::append_query_param(&request.url, name, self.secret.expose());
                request
            }
            AuthStyle::Basic => request.header("Authorization", format!("Basic {}", self.basic())),
        }
    }

    /// The base64 form a [`AuthStyle::Basic`] credential travels in.
    fn basic(&self) -> String {
        crate::base64::standard(self.secret.expose().as_bytes())
    }

    /// Every form of the secret that can appear on the wire, for scrubbing diagnostics.
    /// A query-placed key travels percent-encoded, so that form is scrubbed too.
    fn wire_forms(&self) -> Vec<String> {
        let raw = self.secret.expose();
        let mut forms = vec![raw.to_owned()];
        let encoded = crate::http::percent_encode_component(raw);
        if encoded != raw {
            forms.push(encoded);
        }
        if self.style == AuthStyle::Basic {
            forms.push(self.basic());
        }
        forms
    }
}

#[derive(Debug, Clone)]
pub struct FetchOptions {
    pub max_redirects: u32,
    pub redirect_policy: RedirectPolicy,
    /// When set, the fetch is gated by the shared per-host circuit breaker
    /// ([`crate::circuit`]): the first request is not sent while the host's circuit
    /// is open (the result is a no-response `Inconclusive` outcome saying so), and
    /// the final outcome feeds the breaker's health so a failing host is paced
    /// down for every caller. Off by default; callers opt in with [`Self::paced`].
    pub circuit_breaker: bool,
}

impl Default for FetchOptions {
    fn default() -> Self {
        Self {
            max_redirects: DEFAULT_MAX_REDIRECTS,
            redirect_policy: RedirectPolicy::Any,
            circuit_breaker: false,
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
            circuit_breaker: false,
        }
    }

    /// Gate this fetch by the shared per-host circuit breaker. See
    /// [`FetchOptions::circuit_breaker`].
    #[must_use]
    pub const fn paced(mut self) -> Self {
        self.circuit_breaker = true;
        self
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

/// The response of `fetched`, when it was read whole. With no response the outcome is
/// `fetched`'s own (the transport failure, the spent deadline, the open circuit); a body cut at
/// the transport's limit is `ParserDrift`, never a document to read. `what` names the provider in
/// the diagnostic. **Pure.**
///
/// A source reads one answer through this, [`answer`] and [`decode_json`], in that order. A
/// provider rule on the status (a documented "not found", which only a plain 4xx in `fetch`'s kind
/// is) goes before this one, and a rule that reads the body (an explicit "no such profile"
/// document) between this and [`answer`].
///
/// # Errors
/// The outcome to record when there is no whole response.
pub fn whole_response<'a>(
    fetched: &'a Fetched,
    what: &str,
) -> Result<&'a Response, SourceExecutionOutcome> {
    let Some(response) = &fetched.response else {
        return Err(fetched.outcome.clone());
    };
    if response.truncated {
        return Err(SourceExecutionOutcome::failed(
            &fetched.outcome.module,
            fetched.outcome.observed_at_unix,
            SourceOutcomeKind::ParserDrift,
            Some(response.status),
            format!("truncated {what} response"),
        ));
    }
    Ok(response)
}

/// `Ok` when `fetched` is an answer to read: its outcome is still `Inconclusive`, so the status is
/// a 2xx and the body no challenge page. Otherwise the failed outcome of the kind the fetch gave
/// it, with its status and the pause the provider asked for; after a sent credential a `401` is
/// therefore `AuthRejected`, not `AuthRequired`. **Pure.**
///
/// # Errors
/// The outcome to record when the response is a refusal, a wall or an error.
pub fn answer(fetched: &Fetched, what: &str) -> Result<(), SourceExecutionOutcome> {
    let outcome = &fetched.outcome;
    if fetched.response.is_none() {
        return Err(outcome.clone());
    }
    if outcome.kind == SourceOutcomeKind::Inconclusive {
        return Ok(());
    }
    let failed = SourceExecutionOutcome::failed(
        &outcome.module,
        outcome.observed_at_unix,
        outcome.kind,
        outcome.http_status,
        format!("{what} answered with a refusal, a wall or an error, not a document"),
    );
    Err(match outcome.retry_after_secs {
        Some(secs) => failed.with_retry_after(secs),
        None => failed,
    })
}

/// `response`'s body as `D`, or `ParserDrift` naming only the error's category and position (see
/// [`json_error_detail`]). **Pure.**
///
/// # Errors
/// The outcome to record when the body is not `D`.
pub fn decode_json<D: serde::de::DeserializeOwned>(
    response: &Response,
    module: &str,
    now_unix: u64,
    what: &str,
) -> Result<D, SourceExecutionOutcome> {
    serde_json::from_slice(&response.body).map_err(|error| {
        SourceExecutionOutcome::failed(
            module,
            now_unix,
            SourceOutcomeKind::ParserDrift,
            Some(response.status),
            format!("{what} JSON: {}", json_error_detail(&error)),
        )
    })
}

/// A JSON decode error as a diagnostic may give it: its category and position, never serde's
/// message, which can quote the body. Diagnostics are saved in ledgers. **Pure.**
#[must_use]
pub fn json_error_detail(error: &serde_json::Error) -> String {
    let category = match error.classify() {
        serde_json::error::Category::Io => "io",
        serde_json::error::Category::Syntax => "syntax",
        serde_json::error::Category::Data => "data",
        serde_json::error::Category::Eof => "eof",
    };
    format!(
        "{category} error at line {} column {}",
        error.line(),
        error.column()
    )
}

/// The outcome of a `MediaWiki` Action API answer that carries an `error` envelope
/// (`{"error":{"code":…,"info":…}}`) instead of its result. The Action API sends an error with
/// HTTP 200, so [`answer`] passes it: the envelope says only that the API did not run the query,
/// never that the query found nothing. A search backend too busy to run it
/// (`cirrussearch-too-busy-error`) and a throttle or lag refusal (`ratelimited`, `maxlag`) ask the
/// client to come back later; any other code (`cirrussearch-backend-error`, an
/// `internal_api_error_…`) is inconclusive. A source whose query one code does answer (Wikipedia's
/// `baduser`: the name can be no account) checks for that code first, with
/// [`mediawiki_error_code`]. `what` names the provider in the diagnostic. **Pure.**
#[must_use]
pub fn mediawiki_api_error(
    error: &serde_json::Value,
    module: &str,
    status: u16,
    now_unix: u64,
    what: &str,
) -> SourceExecutionOutcome {
    let code = mediawiki_error_code(error);
    let kind = if matches!(
        code,
        "cirrussearch-too-busy-error" | "ratelimited" | "maxlag"
    ) {
        SourceOutcomeKind::RateLimited
    } else {
        SourceOutcomeKind::Inconclusive
    };
    SourceExecutionOutcome::failed(
        module,
        now_unix,
        kind,
        Some(status),
        format!("{what} API error: {code}"),
    )
}

/// The code of a `MediaWiki` Action API error envelope, or `unknown` when it has none or it is not
/// shaped like one (ASCII letters, digits, `_`, `-` and the `\` of a namespaced exception's
/// `internal_api_error_…`, at most [`MEDIAWIKI_CODE_MAX`] of them), so a diagnostic never carries
/// arbitrary upstream text. **Pure.**
#[must_use]
pub fn mediawiki_error_code(error: &serde_json::Value) -> &str {
    error
        .get("code")
        .and_then(serde_json::Value::as_str)
        .filter(|code| {
            (1..=MEDIAWIKI_CODE_MAX).contains(&code.len())
                && code
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'\\'))
        })
        .unwrap_or("unknown")
}

/// The longest `MediaWiki` error code a diagnostic carries.
pub const MEDIAWIKI_CODE_MAX: usize = 128;

fn fetch_hops<T: Transport + ?Sized>(
    transport: &T,
    request: Request,
    credential: Option<&Credential>,
    options: &FetchOptions,
    deadline: Option<&Deadline<'_>>,
    module: &str,
    now_unix: u64,
) -> Result<Fetched, Error> {
    if !options.circuit_breaker {
        return fetch_hops_inner(
            transport, request, credential, options, deadline, module, now_unix,
        );
    }
    // One causal fetch, paced by the shared per-host breaker: suppress while the
    // host's circuit is open, otherwise feed the final outcome back to the breaker.
    let host = crate::circuit::host_of(&request.url);
    if let Some(host) = &host {
        if !crate::circuit::allow_host(host, now_unix) {
            return Ok(suppressed(module, now_unix, &request.url));
        }
    }
    let result = fetch_hops_inner(
        transport, request, credential, options, deadline, module, now_unix,
    );
    if let (Some(host), Ok(fetched)) = (&host, &result) {
        record_breaker_health(
            host,
            fetched.outcome.kind,
            fetched.outcome.retry_after_secs,
            now_unix,
        );
    }
    result
}

/// The result when the host's breaker is open and the first request was not sent.
fn suppressed(module: &str, now_unix: u64, url: &str) -> Fetched {
    let outcome = SourceExecutionOutcome::observed(
        module,
        now_unix,
        SourceOutcomeKind::Inconclusive,
        None,
        None,
        "source pacing circuit is open; request not sent",
    );
    Fetched {
        outcome,
        response: None,
        final_url: redact_url(url),
        redirects: 0,
        credential_sent: None,
        redirect_refused: None,
        not_sent_hop: None,
    }
}

/// Feed one fetch outcome into the shared per-host breaker. This is the single
/// authority mapping a [`SourceOutcomeKind`] to a breaker signal; every paced
/// caller shares it rather than re-deriving the rule.
fn record_breaker_health(
    host: &str,
    kind: SourceOutcomeKind,
    retry_after_secs: Option<u64>,
    now_unix: u64,
) {
    use crate::circuit;
    match kind {
        SourceOutcomeKind::RateLimited => circuit::record_rate_limited(
            host,
            now_unix,
            retry_after_secs.unwrap_or(circuit::COOLDOWN_SECS),
        ),
        SourceOutcomeKind::BotWaf | SourceOutcomeKind::Upstream5xx => {
            circuit::record_failure(host, now_unix);
        }
        other if other.is_transport_failure() => circuit::record_failure(host, now_unix),
        _ => circuit::record_success(host),
    }
}

fn fetch_hops_inner<T: Transport + ?Sized>(
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
    let secret_forms = credential.map(Credential::wire_forms).unwrap_or_default();
    let scrub = |text: &str| {
        let forms: Vec<&str> = secret_forms.iter().map(String::as_str).collect();
        scrub_secrets(text, &forms)
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

        // A `Location` that cannot be parsed into an http(s) URL with a host is not followed,
        // under any redirect policy: the 3xx response was received, so it is the answer (the
        // monolith's client treated it the same way), never a request refused before sending.
        // Returning it as an error here would make a caller read a sent-and-answered request as
        // "nothing reached the network".
        let Ok(next) = redirect_target(&current, &response) else {
            let refusal = Refusal {
                why: "redirect refused: unusable Location",
                redirects,
                sent,
            };
            return Ok(refusal.finish(module, now_unix, &current, response, &scrub));
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
            // A 307/308 (or any other redirect retaining a request body) must not
            // forward that body to a different origin. It may contain provider
            // secrets or personal data that header stripping cannot protect.
            // A scheme downgrade is also an origin change. Bodyless redirects
            // and same-origin 307/308 requests retain their existing behaviour.
            if !next.body.is_empty() && origin_of(&next.url) != origin_of(&current.url) {
                return Ok(Refusal {
                    why: "redirect refused: request body would cross origin",
                    redirects,
                    sent,
                }
                .finish(module, now_unix, &current, response, &scrub));
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
    let mut kind = classify_fetch(response.status, &response.text_view());
    if kind == SourceOutcomeKind::AuthRequired && sent.is_some() {
        kind = SourceOutcomeKind::AuthRejected;
    }
    let throttle = Throttle::of(&response, now_unix);
    if response.status == 403
        && kind != SourceOutcomeKind::BotWaf
        && (throttle.limited() || says_rate_limited(&response.text_view()))
    {
        kind = SourceOutcomeKind::RateLimited;
    } else if response.status == 403 && kind == SourceOutcomeKind::Upstream4xx && sent.is_some() {
        // Only a sent credential can be rejected: the same 403 to a request that carried none is
        // the provider refusing the request (a block, a policy, a plan), and stays `Upstream4xx`.
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
    let pause = match response.status {
        503 => throttle.retry_after,
        _ if kind == SourceOutcomeKind::RateLimited => throttle.pause(),
        _ => None,
    };
    if let Some(secs) = pause {
        outcome = outcome.with_retry_after(secs.min(MAX_RETRY_AFTER_SECS));
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

/// What a response says about the provider's rate limit, as GitHub documents it and other
/// providers send it: `retry-after` (delta-seconds or an HTTP-date) is the pause to take, and
/// `x-ratelimit-remaining: 0` an exhausted quota that returns at `x-ratelimit-reset` (UTC epoch
/// seconds).
struct Throttle {
    retry_after: Option<u64>,
    exhausted: bool,
    reset_in: Option<u64>,
}

impl Throttle {
    fn of(response: &Response, now_unix: u64) -> Self {
        let retry_after = response
            .header_value("retry-after")
            .and_then(|value| crate::http::retry_after_secs(value, now_unix));
        let exhausted = response
            .header_value("x-ratelimit-remaining")
            .is_some_and(|value| value.trim() == "0");
        let reset_in = response
            .header_value("x-ratelimit-reset")
            .and_then(|value| value.trim().parse::<u64>().ok())
            .map(|reset| reset.saturating_sub(now_unix));
        Self {
            retry_after,
            exhausted,
            reset_in,
        }
    }

    /// Whether the response is a rate limit whatever its status: a pause or an exhausted quota.
    const fn limited(&self) -> bool {
        self.retry_after.is_some() || self.exhausted
    }

    /// How long to wait: `retry-after` first, then the reset of an exhausted quota.
    fn pause(&self) -> Option<u64> {
        self.retry_after
            .or_else(|| self.exhausted.then_some(self.reset_in).flatten())
    }
}

/// Largest refusal body read for a rate-limit message: an API's error document is a few hundred
/// bytes, and a page is no such message.
const RATE_LIMIT_MESSAGE_MAX_BYTES: usize = 4 * 1024;

/// Whether a refusal's JSON body says, in its `message`, that a rate limit was hit, as GitHub's
/// documented secondary limit does with no `retry-after` and quota left ("You have exceeded a
/// secondary rate limit"). **Pure.**
fn says_rate_limited(body: &str) -> bool {
    body.len() <= RATE_LIMIT_MESSAGE_MAX_BYTES
        && crate::classify::is_json_body(body)
        && serde_json::from_str::<serde_json::Value>(body)
            .ok()
            .as_ref()
            .and_then(|document| document.get("message"))
            .and_then(serde_json::Value::as_str)
            .is_some_and(|message| message.to_ascii_lowercase().contains("rate limit"))
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

/// `url` without any `name=` query parameter. **Pure.**
fn without_query_param(url: &str, name: &str) -> String {
    let (no_fragment, fragment) = match url.split_once('#') {
        Some((u, f)) => (u, Some(f)),
        None => (url, None),
    };
    let Some((base, query)) = no_fragment.split_once('?') else {
        return url.to_owned();
    };
    let kept: Vec<&str> = query
        .split('&')
        .filter(|pair| pair.split_once('=').map_or(*pair, |(k, _)| k) != name)
        .collect();
    let mut out = base.to_owned();
    if !kept.is_empty() {
        out.push('?');
        out.push_str(&kept.join("&"));
    }
    if let Some(fragment) = fragment {
        out.push('#');
        out.push_str(fragment);
    }
    out
}

fn without_credentials(request: &Request) -> Request {
    let mut r = request.clone();
    r.headers
        .retain(|(k, v)| !crate::http::is_sensitive_header_value(k, v));
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

    /// A `MediaWiki` error code is carried only in its own shape: letters, digits, `_`, `-` and the
    /// `\` of a namespaced exception, one to [`MEDIAWIKI_CODE_MAX`] of them.
    #[test]
    fn a_mediawiki_error_code_is_carried_only_in_its_own_shape() {
        let code = |raw: &str| mediawiki_error_code(&serde_json::json!({ "code": raw })).to_owned();
        for kept in [
            "baduser",
            "cirrussearch-too-busy-error",
            "internal_api_error_DBQueryError",
            "internal_api_error_MediaWiki\\Revision\\RevisionAccessException",
            "a2",
        ] {
            assert_eq!(code(kept), kept);
        }
        let longest = "x".repeat(MEDIAWIKI_CODE_MAX);
        assert_eq!(code(&longest), longest);
        for refused in [
            String::new(),
            "x".repeat(MEDIAWIKI_CODE_MAX + 1),
            "<script>".to_owned(),
            "bad user".to_owned(),
            "bad\nuser".to_owned(),
            "baduser\u{e9}".to_owned(),
        ] {
            assert_eq!(code(&refused), "unknown", "{refused:?}");
        }
        assert_eq!(mediawiki_error_code(&serde_json::json!({})), "unknown");
        assert_eq!(
            mediawiki_error_code(&serde_json::json!({ "code": 7 })),
            "unknown"
        );
    }
    use crate::circuit::BreakerState;
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
    fn origin_change_drops_contact_user_agent_but_keeps_generic_agent() {
        let contact = Request::get("https://source.example/")
            .header("User-Agent", "Huntsman contact@research.example")
            .header("Accept", "application/json");
        let stripped = without_credentials(&contact);
        assert!(stripped.header_value("User-Agent").is_none());
        assert_eq!(stripped.header_value("Accept"), Some("application/json"));

        let generic = Request::get("https://source.example/")
            .header("User-Agent", crate::http::DEFAULT_USER_AGENT);
        assert_eq!(
            without_credentials(&generic).header_value("User-Agent"),
            Some(crate::http::DEFAULT_USER_AGENT)
        );
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

    /// A profile site that embeds a CAPTCHA widget, or a bot-management sensor, on every page
    /// answers 200 with content. Counting those as walls dropped every result and, after five,
    /// opened the host's circuit for a minute.
    #[test]
    fn served_pages_with_a_widget_are_content_and_keep_the_host_circuit_closed() {
        use crate::circuit::{BreakerState, FAILURE_THRESHOLD, host_state};
        let page = "<html><script src=\"https://www.google.com/recaptcha/api.js\"></script><div class=\"g-recaptcha\"></div><h1>Jane Doe</h1></html>";
        let host = "widget-on-every-page.example";
        for _ in 0..FAILURE_THRESHOLD {
            let f = Fake::new(vec![Ok(resp(200, &[], page))]);
            let r = run(&f, &format!("https://{host}/profile"), None, 0).expect("fetch");
            assert_eq!(r.outcome.kind, SourceOutcomeKind::Inconclusive);
        }
        assert_ne!(host_state(host), Some(BreakerState::Open));
    }

    /// GitHub's documented rate-limit answers, which any provider sending the same headers gives:
    /// a 403 or 429 with `retry-after` is a pause of that many seconds, and one with
    /// `x-ratelimit-remaining: 0` a pause until `x-ratelimit-reset` (UTC epoch seconds). A 403
    /// without either stays a refusal, and a challenge page stays a wall.
    #[test]
    fn an_exhausted_quota_is_a_rate_limit_until_its_reset() {
        use SourceOutcomeKind as K;
        let at = |status, headers: &[(&str, &str)], body: &str| {
            let f = Fake::new(vec![Ok(resp(status, headers, body))]);
            let r = fetch(
                &f,
                Request::get("https://quota.example/"),
                None,
                &FetchOptions::default(),
                "t",
                1_000,
            )
            .expect("fetch");
            (r.outcome.kind, r.outcome.retry_after_secs)
        };
        let exhausted = [
            ("x-ratelimit-remaining", "0"),
            ("x-ratelimit-reset", "1120"),
        ];
        assert_eq!(at(403, &exhausted, "{}"), (K::RateLimited, Some(120)));
        assert_eq!(at(429, &exhausted, "{}"), (K::RateLimited, Some(120)));
        assert_eq!(
            at(403, &[("retry-after", "45")], "{}"),
            (K::RateLimited, Some(45))
        );
        // `retry-after` is the documented first rule; it wins over the reset time.
        let both = [
            ("retry-after", "45"),
            ("x-ratelimit-remaining", "0"),
            ("x-ratelimit-reset", "1120"),
        ];
        assert_eq!(at(403, &both, "{}"), (K::RateLimited, Some(45)));
        // A reset already past is no pause; one far off is capped like any other.
        let past = [("x-ratelimit-remaining", "0"), ("x-ratelimit-reset", "900")];
        assert_eq!(at(403, &past, "{}"), (K::RateLimited, Some(0)));
        let far = [
            ("x-ratelimit-remaining", "0"),
            ("x-ratelimit-reset", "99999999"),
        ];
        assert_eq!(at(403, &far, "{}"), (K::RateLimited, Some(3600)));
        // Without a reset time the quota is still exhausted, for an unknown time.
        assert_eq!(
            at(403, &[("x-ratelimit-remaining", "0")], "{}"),
            (K::RateLimited, None)
        );
        // Quota left, or no rate-limit header at all, is a refusal: of the request, since it
        // carried no credential to reject.
        let left = [
            ("x-ratelimit-remaining", "12"),
            ("x-ratelimit-reset", "1120"),
        ];
        assert_eq!(at(403, &left, "{}"), (K::Upstream4xx, None));
        assert_eq!(at(403, &[], "{}"), (K::Upstream4xx, None));
        // GitHub's secondary limit says so only in its message, with quota left and no pause.
        let secondary = r#"{"message":"You have exceeded a secondary rate limit. Please wait a few minutes before you try again."}"#;
        assert_eq!(at(403, &left, secondary), (K::RateLimited, None));
        assert_eq!(
            at(
                403,
                &[],
                r#"{"message":"API rate limit exceeded for 192.0.2.1."}"#
            ),
            (K::RateLimited, None)
        );
        assert_eq!(
            at(403, &[], r#"{"message":"Resource not accessible"}"#),
            (K::Upstream4xx, None)
        );
        // A challenge page is a wall whatever its headers say.
        let challenge = "<html><title>Just a moment...</title>Cloudflare</html>";
        assert_eq!(at(403, &exhausted, challenge), (K::BotWaf, None));
        // Other statuses keep their own meaning; a 503 keeps the pause it asks for.
        assert_eq!(at(200, &exhausted, "{}"), (K::Inconclusive, None));
        assert_eq!(
            at(503, &[("retry-after", "30")], "{}"),
            (K::Upstream5xx, Some(30))
        );
        assert_eq!(at(404, &exhausted, "{}"), (K::Upstream4xx, None));
    }

    /// Only a sent credential can be rejected. A 403 to a request that carried one is
    /// `AuthRejected`; the same 403 to a request that carried none is the provider refusing the
    /// request (a geo-block, an address ban, a proxy's policy), never a rejected key that does
    /// not exist.
    #[test]
    fn a_403_rejects_a_credential_only_when_one_was_sent() {
        let policy = r#"{"message":"This API path is not available: sessions are bound to their configured repositories"}"#;
        let refused = |credential: Option<&Credential>| {
            let f = Fake::new(vec![Ok(resp(403, &[], policy))]);
            let fetched =
                run(&f, "https://api.example.com/users/octocat", credential, 0).expect("fetch");
            (fetched.outcome.kind, fetched.outcome.http_status)
        };
        assert_eq!(refused(None), (SourceOutcomeKind::Upstream4xx, Some(403)));
        let key = cred("sk_live_0123456789abcdef", AuthStyle::Bearer);
        assert_eq!(
            refused(Some(&key)),
            (SourceOutcomeKind::AuthRejected, Some(403))
        );
    }

    /// A paced fetch that meets an exhausted quota stops every caller sending to that host until
    /// the reset, and only that host.
    #[test]
    fn an_exhausted_quota_paces_its_host_until_the_reset_and_no_other() {
        let host = "paced-quota.invalid";
        let url = format!("https://{host}/users/a");
        let exhausted = resp(
            403,
            &[
                ("x-ratelimit-remaining", "0"),
                ("x-ratelimit-reset", "5120"),
            ],
            "{}",
        );
        let f = Fake::new(vec![Ok(exhausted)]);
        let r = fetch(&f, Request::get(&url), None, &paced(0), "t", 5_000).expect("fetch");
        assert_eq!(r.outcome.kind, SourceOutcomeKind::RateLimited);
        assert_eq!(crate::circuit::host_state(host), Some(BreakerState::Open));

        let empty = Fake::new(vec![]);
        let held = fetch(&empty, Request::get(&url), None, &paced(0), "t", 5_119).expect("fetch");
        assert!(held.response.is_none());
        assert!(empty.seen.borrow().is_empty(), "sent before the reset");

        let other = Fake::new(vec![Ok(resp(200, &[], "{}"))]);
        let elsewhere = fetch(
            &other,
            Request::get("https://paced-quota-other.invalid/users/a"),
            None,
            &paced(0),
            "t",
            5_119,
        )
        .expect("fetch");
        assert_eq!(other.seen.borrow().len(), 1, "an unrelated host was held");
        assert!(elsewhere.response.is_some());

        let after = Fake::new(vec![Ok(resp(200, &[], "{}"))]);
        let resumed =
            fetch(&after, Request::get(&url), None, &paced(0), "t", 5_120).expect("fetch");
        assert_eq!(after.seen.borrow().len(), 1, "not sent after the reset");
        assert!(resumed.response.is_some());
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
        let at = fetch(
            &f,
            Request::get("https://a.example/"),
            None,
            &FetchOptions::default(),
            "t",
            1_792_567_600,
        );
        assert_eq!(at.expect("f").outcome.retry_after_secs, Some(80));
        let f = Fake::new(vec![Ok(resp(429, &[("retry-after", "soon")], ""))]);
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
        let seen = f.seen.borrow();
        assert!(seen.is_empty(), "{seen:?}");
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
    fn a_query_key_is_added_on_send_and_never_follows_a_redirect_off_origin() {
        let c = cred("tok/abc+def 123", AuthStyle::Query("key".into()));
        let f = Fake::new(vec![
            Ok(resp(
                302,
                &[("location", "https://evil.example/steal?x=1")],
                "",
            )),
            Ok(resp(200, &[], "")),
        ]);
        // A caller-set `key=` is replaced, never sent alongside the operator's key.
        let r = run(
            &f,
            "https://a.example/q?ip=1.2.3.4&key=planted",
            Some(&c),
            1,
        )
        .expect("fetch");
        let seen = f.seen.borrow();
        assert_eq!(
            seen[0].url,
            "https://a.example/q?ip=1.2.3.4&key=tok%2Fabc%2Bdef+123"
        );
        assert_eq!(seen[1].url, "https://evil.example/steal?x=1");
        assert!(!r.final_url.contains("tok"), "{}", r.final_url);
        assert!(
            Credential::new(
                AuthenticationAuthority::operator_approved(OperatorCredentialRef {
                    provider_id: "p".into(),
                    credential_slot: "P_KEY".into(),
                    approved_at_unix: 1,
                    approval_provenance: "t".into(),
                })
                .expect("authority"),
                Secret::new("tok-abcdef-123456").expect("s"),
                AuthStyle::Query("k&x=".into()),
            )
            .is_err()
        );
    }

    #[test]
    fn a_query_key_is_scrubbed_from_transport_diagnostics_in_both_forms() {
        let c = cred("tok/abc+def 123", AuthStyle::Query("key".into()));
        let f = Fake::new(vec![Err(TransportFailure {
            kind: SourceOutcomeKind::ConnectFailure,
            detail: "failed https://a.example/q?key=tok%2Fabc%2Bdef+123 (tok/abc+def 123)".into(),
            blocked: false,
        })]);
        let r = run(&f, "https://a.example/q", Some(&c), 0).expect("fetch");
        let detail = r.outcome.detail.unwrap_or_default();
        assert!(
            !detail.contains("tok%2Fabc") && !detail.contains("tok/abc"),
            "{detail}"
        );
    }

    #[test]
    fn without_query_param_keeps_every_other_parameter() {
        assert_eq!(
            without_query_param("https://h/p?a=1&key=s&b=2#f", "key"),
            "https://h/p?a=1&b=2#f"
        );
        assert_eq!(
            without_query_param("https://h/p?key=s", "key"),
            "https://h/p"
        );
        assert_eq!(
            without_query_param("https://h/p?keys=1", "key"),
            "https://h/p?keys=1"
        );
        assert_eq!(without_query_param("https://h/p", "key"), "https://h/p");
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
    fn basic_style_sends_the_encoded_pair_and_strips_it_off_origin() {
        let c = cred("wigle-user:tok-abcdef-123456", AuthStyle::Basic);
        let f = Fake::new(vec![
            Ok(resp(302, &[("location", "https://evil.example/steal")], "")),
            Ok(resp(200, &[], "")),
        ]);
        let r = run(&f, "https://a.example/api", Some(&c), 5).expect("fetch");
        let seen = f.seen.borrow();
        assert_eq!(
            seen[0].header_value("authorization"),
            Some("Basic d2lnbGUtdXNlcjp0b2stYWJjZGVmLTEyMzQ1Ng==")
        );
        assert!(seen[1].header_value("authorization").is_none());
        assert!(!format!("{r:?}").contains("d2lnbGUtdXNlcjp0b2st"));
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
    fn query_only_redirect_keeps_the_page_and_same_origin_credential() {
        let credential = cred("tok-fixture-123456", AuthStyle::Bearer);
        let transport = Fake::new(vec![
            Ok(resp(302, &[("location", "?page=2")], "")),
            Ok(resp(200, &[], "second page")),
        ]);
        let result = run(
            &transport,
            "https://a.example/v1/search?page=1",
            Some(&credential),
            5,
        )
        .expect("fetch");
        assert_eq!(result.final_url, "https://a.example/v1/search?[redacted]");
        let seen = transport.seen.borrow();
        assert_eq!(seen[1].url, "https://a.example/v1/search?page=2");
        assert!(seen[1].header_value("authorization").is_some());
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
    fn redirect_to_a_non_http_scheme_keeps_the_3xx_as_the_answer() {
        // An unfollowable Location is not a request refused before sending: the 3xx was received,
        // so it is the answer (classified `RedirectChanged`) with the refused redirect recorded —
        // never an error a caller would read as "nothing reached the network". The target is still
        // not fetched.
        let f = Fake::new(vec![Ok(resp(
            302,
            &[("location", "file:///etc/passwd")],
            "",
        ))]);
        let r =
            run(&f, "https://a.example/", None, 5).expect("the 3xx is the answer, not an error");
        assert_eq!(r.outcome.kind, SourceOutcomeKind::RedirectChanged);
        assert!(r.response.is_some(), "the 302 response is kept");
        assert!(
            r.redirect_refused.is_some(),
            "the unusable redirect is recorded: {:?}",
            r.redirect_refused
        );
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
    fn cross_origin_307_and_308_never_forward_post_bodies() {
        for status in [307, 308] {
            let f = Fake::new(vec![
                Ok(resp(
                    status,
                    &[("location", "https://other.example/collect")],
                    "",
                )),
                Ok(resp(200, &[], "")),
            ]);
            let body = b"private-form-data".to_vec();
            let result = fetch(
                &f,
                Request::post("https://api.example/submit", body.clone()),
                Some(&cred("tok-abcdef-123456", AuthStyle::Bearer)),
                &FetchOptions::default(),
                "t",
                1,
            )
            .expect("a refused redirect preserves the original response");

            assert_eq!(
                f.seen.borrow().len(),
                1,
                "{status}: body sent to redirect target"
            );
            assert_eq!(f.seen.borrow()[0].body, body);
            assert_eq!(result.response.as_ref().map(|r| r.status), Some(status));
            assert_eq!(result.outcome.kind, SourceOutcomeKind::RedirectChanged);
            assert_eq!(
                result.redirect_refused,
                Some("redirect refused: request body would cross origin")
            );
        }
    }

    #[test]
    fn https_to_http_307_cannot_downgrade_a_post_body() {
        let f = Fake::new(vec![
            Ok(resp(307, &[("location", "http://api.example/receive")], "")),
            Ok(resp(200, &[], "")),
        ]);
        let result = fetch(
            &f,
            Request::post("https://api.example/submit", b"private-form-data".to_vec()),
            None,
            &FetchOptions::default(),
            "t",
            1,
        )
        .expect("a refused redirect preserves the original response");
        assert_eq!(f.seen.borrow().len(), 1);
        assert_eq!(result.response.as_ref().map(|r| r.status), Some(307));
        assert!(result.redirect_refused.is_some());
    }

    #[test]
    fn cross_origin_303_is_followed_without_the_post_body() {
        let f = Fake::new(vec![
            Ok(resp(303, &[("location", "https://other.example/done")], "")),
            Ok(resp(200, &[], "")),
        ]);
        let result = fetch(
            &f,
            Request::post("https://api.example/submit", b"private-form-data".to_vec()),
            None,
            &FetchOptions::default(),
            "t",
            1,
        )
        .expect("a bodyless redirect follows");
        let seen = f.seen.borrow();
        assert_eq!(seen.len(), 2);
        assert_eq!(seen[1].method, Method::Get);
        assert!(seen[1].body.is_empty());
        assert!(result.redirect_refused.is_none());
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

    /// What a source reading `sent` through `whole_response`, `answer` and `decode_json` records:
    /// the decoded document's id, or the kind, status and pause of the first gate that refused it.
    /// Whatever refused it, the outcome quotes no word of the body.
    fn through_the_gates(
        sent: Result<Response, TransportFailure>,
        credential: Option<&Credential>,
    ) -> Result<u64, (SourceOutcomeKind, Option<u16>, Option<u64>)> {
        #[derive(Debug, serde::Deserialize)]
        struct Doc {
            id: u64,
        }
        let f = Fake::new(vec![sent]);
        let fetched = run(&f, "https://a.example/", credential, 0).expect("fetch");
        if let Some(response) = &fetched.response {
            // The kind the gates read is the one each source classified for itself from the
            // lossy text, but for a rejected key.
            let own = match classify_fetch(response.status, &response.text()) {
                SourceOutcomeKind::AuthRequired if credential.is_some() => {
                    SourceOutcomeKind::AuthRejected
                }
                SourceOutcomeKind::Upstream4xx
                    if response.status == 403 && credential.is_some() =>
                {
                    SourceOutcomeKind::AuthRejected
                }
                own => own,
            };
            assert_eq!(fetched.outcome.kind, own);
        }
        let read = whole_response(&fetched, "Example").and_then(|response| {
            answer(&fetched, "Example")?;
            decode_json::<Doc>(response, "t", 100, "Example")
        });
        read.map(|doc| doc.id).map_err(|outcome| {
            assert_eq!((outcome.module.as_str(), outcome.found), ("t", None));
            let detail = outcome.detail.clone().unwrap_or_default();
            assert!(!detail.contains("secret"), "{detail}");
            (outcome.kind, outcome.http_status, outcome.retry_after_secs)
        })
    }

    #[test]
    fn the_response_gates_pass_only_a_whole_answer_and_never_quote_the_body() {
        use SourceOutcomeKind as K;
        let key = cred("tok-abcdef-123456", AuthStyle::Bearer);
        let challenge = "<html><title>Just a moment...</title>Cloudflare secret@example.com</html>";
        let timeout = TransportFailure {
            kind: K::TtfbTimeout,
            detail: "timed out".into(),
            blocked: false,
        };
        assert_eq!(
            through_the_gates(Err(timeout), None),
            Err((K::TtfbTimeout, None, None))
        );
        let limited = resp(429, &[("retry-after", "30")], "{}");
        assert_eq!(
            through_the_gates(Ok(limited), None),
            Err((K::RateLimited, Some(429), Some(30)))
        );
        assert_eq!(
            through_the_gates(Ok(resp(403, &[], challenge)), None),
            Err((K::BotWaf, Some(403), None))
        );
        let mut lossy = resp(403, &[], "");
        lossy.body = [b"\xff\xfe".as_slice(), challenge.as_bytes()].concat();
        assert_eq!(
            through_the_gates(Ok(lossy), None),
            Err((K::BotWaf, Some(403), None))
        );
        assert_eq!(
            through_the_gates(Ok(resp(401, &[], "{}")), None),
            Err((K::AuthRequired, Some(401), None))
        );
        assert_eq!(
            through_the_gates(Ok(resp(401, &[], "{}")), Some(&key)),
            Err((K::AuthRejected, Some(401), None))
        );
        let mut cut = resp(200, &[], r#"{"id":7,"secret@example.com""#);
        cut.truncated = true;
        assert_eq!(
            through_the_gates(Ok(cut), None),
            Err((K::ParserDrift, Some(200), None))
        );
        assert_eq!(
            through_the_gates(Ok(resp(503, &[], "{}")), None),
            Err((K::Upstream5xx, Some(503), None))
        );
        assert_eq!(
            through_the_gates(Ok(resp(200, &[], r#"{"id":7}"#)), None),
            Ok(7)
        );
        for body in ["secret@example.com", r#"{"id":"secret@example.com"}"#] {
            assert_eq!(
                through_the_gates(Ok(resp(200, &[], body)), None),
                Err((K::ParserDrift, Some(200), None)),
                "{body}"
            );
        }
    }

    /// With no response `answer` has nothing to read, so the outcome `fetch` gave the request is
    /// the one recorded, whatever its kind. An open circuit's `Inconclusive` is the case that would
    /// read as an answer if `answer` judged the kind alone.
    #[test]
    fn answer_without_a_response_returns_the_fetch_outcome_unchanged() {
        let f = Fake::new(vec![Err(TransportFailure {
            kind: SourceOutcomeKind::TtfbTimeout,
            detail: "timed out".into(),
            blocked: false,
        })]);
        let timed_out = run(&f, "https://a.example/", None, 0).expect("fetch");
        let held = suppressed("t", 100, "https://a.example/");
        for fetched in [timed_out, held] {
            assert!(fetched.response.is_none());
            let err = answer(&fetched, "Example").expect_err("no response is no answer");
            assert_eq!(err, fetched.outcome);
        }
    }

    #[test]
    fn a_decode_error_names_its_category_and_position_only() {
        let Err(error) = serde_json::from_str::<u64>("\"secret@example.com\"") else {
            panic!("a string is not a number");
        };
        assert_eq!(json_error_detail(&error), "data error at line 1 column 20");
        let Err(error) = serde_json::from_str::<serde_json::Value>("[1,") else {
            panic!("an unclosed array is not a document");
        };
        assert_eq!(json_error_detail(&error), "eof error at line 1 column 3");
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

    fn paced(max: u32) -> FetchOptions {
        FetchOptions {
            max_redirects: max,
            ..FetchOptions::default()
        }
        .paced()
    }

    #[test]
    fn a_paced_fetch_records_a_rate_limit_and_then_suppresses_the_next_request() {
        // A host unique to this test so the shared registry cannot be perturbed by
        // any other test in the binary.
        let host = "paced-ratelimit.invalid";
        let url = format!("https://{host}/q");
        let f = Fake::new(vec![Ok(resp(429, &[("retry-after", "30")], ""))]);
        let r = fetch(&f, Request::get(&url), None, &paced(0), "t", 1000).expect("fetch");
        assert_eq!(r.outcome.kind, SourceOutcomeKind::RateLimited);
        assert_eq!(crate::circuit::host_state(host), Some(BreakerState::Open));

        // The circuit is open, so the next paced request is not sent at all.
        let empty = Fake::new(vec![]);
        let suppressed =
            fetch(&empty, Request::get(&url), None, &paced(0), "t", 1001).expect("fetch");
        assert_eq!(suppressed.outcome.kind, SourceOutcomeKind::Inconclusive);
        assert!(suppressed.response.is_none());
        assert!(empty.seen.borrow().is_empty(), "request should not be sent");
        assert!(
            suppressed
                .outcome
                .detail
                .as_deref()
                .is_some_and(|d| d.contains("circuit is open"))
        );
    }

    #[test]
    fn five_paced_failures_open_the_circuit_and_a_success_closes_it() {
        let host = "paced-failures.invalid";
        let url = format!("https://{host}/q");
        for _ in 0..crate::circuit::FAILURE_THRESHOLD {
            let f = Fake::new(vec![Ok(resp(503, &[], ""))]);
            let r = fetch(&f, Request::get(&url), None, &paced(0), "t", 2000).expect("fetch");
            assert_eq!(r.outcome.kind, SourceOutcomeKind::Upstream5xx);
        }
        assert_eq!(crate::circuit::host_state(host), Some(BreakerState::Open));

        // After the cooldown the breaker half-opens and lets one probe through; a
        // success recorded by the paced fetch closes it again.
        let probe = Fake::new(vec![Ok(resp(200, &[], "ok"))]);
        let r = fetch(
            &probe,
            Request::get(&url),
            None,
            &paced(0),
            "t",
            2000 + crate::circuit::COOLDOWN_SECS,
        )
        .expect("fetch");
        assert_eq!(r.outcome.kind, SourceOutcomeKind::Inconclusive);
        assert_eq!(crate::circuit::host_state(host), Some(BreakerState::Closed));
    }

    #[test]
    fn an_unpaced_fetch_ignores_an_open_circuit() {
        let host = "unpaced-open.invalid";
        let url = format!("https://{host}/q");
        crate::circuit::record_rate_limited(host, 3000, 60);
        assert_eq!(crate::circuit::host_state(host), Some(BreakerState::Open));
        // Default options do not consult the breaker: the request is still sent.
        let f = Fake::new(vec![Ok(resp(200, &[], "ok"))]);
        let r = run(&f, &url, None, 0).expect("fetch");
        assert_eq!(r.outcome.kind, SourceOutcomeKind::Inconclusive);
        assert_eq!(f.seen.borrow().len(), 1);
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
                ..FetchOptions::default()
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
