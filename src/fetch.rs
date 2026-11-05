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
mod tests;
