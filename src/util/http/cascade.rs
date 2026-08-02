//! Keyed-API error classification and the API-key rotation ("cascade") retry
//! machinery: [`fetch_keyed_json`] and the general-request-shape drivers
//! [`keyed_cascade`]/[`keyed_cascade_with_key`]/[`keyed_cascade_json`], which
//! spend every pooled credential for a module before giving up. Shares
//! [`super::fetch`]'s [`breaker_gate`], [`record_breaker_outcome`], and
//! [`decode_json_body`] — the only overlap with the plain (non-keyed)
//! `fetch_json*` family.

use serde::de::DeserializeOwned;

use crate::core::error::{Error, Result};
use crate::util::circuit_breaker;

use super::fetch::{
    breaker_gate, decode_json_body, error_snippet, key_tail, record_breaker_outcome,
    retry_after_secs,
};
use super::redact::redact_credentials;
use super::url::RequestBuilderExt;

/// A reqwest transport error worth one bounded retry: a connection failure or a
/// timeout — the transient blips a healthy host recovers from on a second try.
/// A protocol/decode/redirect/body error is NOT transient and fails immediately
/// (retrying it would only waste a round-trip). This gates the single keyed-GET
/// retry so a healthy host doesn't lose a target's result — or burn a
/// circuit-breaker failure — on one connect/timeout hiccup.
fn transport_is_transient(e: &reqwest::Error) -> bool {
    e.is_timeout() || e.is_connect()
}

/// Handle a non-success HTTP response for keyed modules. Returns:
/// - `Ok(true)` if the caller should retry (429 with retries remaining)
/// - `Ok(false)` if the response is a permanent failure (report + stop)
/// - The function sleeps on 429 before returning Ok(true).
///
/// `retries_left`: mutable counter, decremented on 429.
/// `module`: stable module name for report_key_exhausted.
/// `key`: the API key value being used.
/// `ctx`: module context for key exhaustion reporting.
pub async fn handle_keyed_error(
    status: u16,
    headers: &reqwest::header::HeaderMap,
    retries_left: &mut u8,
    module: &str,
    key: &str,
    ctx: &crate::core::module::ModuleContext,
) -> bool {
    match status {
        429 if *retries_left > 0 => {
            *retries_left -= 1;
            ctx.report_key_exhausted(module, key, 429);
            // Cap at 4s: callers of this shared helper run with 8–12s module
            // budgets, so a single in-process retry sleep must stay well under
            // the tightest of those or the engine kills process() mid-wait.
            let secs = retry_after_secs(headers, 4, 4);
            tracing::warn!(
                module,
                "429 rate-limited on key …{}, retrying in {secs}s ({} left)",
                key_tail(key),
                retries_left
            );
            tokio::time::sleep(std::time::Duration::from_secs(secs)).await;
            true
        }
        429 => {
            ctx.report_key_exhausted(module, key, 429);
            false
        }
        401 | 403 => {
            ctx.report_key_exhausted(module, key, status);
            false
        }
        _ => false,
    }
}

/// HTTP status codes that indicate an API-key problem: unauthorized (401),
/// forbidden (403), or rate-limited / quota-exhausted (429). The single source
/// of the "which response codes count against a key" classification, shared by
/// [`note_keyed_error`] and matched (with per-code actions) by
/// [`handle_keyed_error`].
#[must_use]
pub fn is_keyed_error_status(code: u16) -> bool {
    matches!(code, 401 | 403 | 429)
}

/// Case-insensitive substrings that mark a `400 Bad Request` body as an
/// AUTHENTICATION / API-key failure rather than a bad *query*. Not every provider
/// signals a dead key with 401: Netlas answers a missing key with
/// `400 {"detail":"Request had invalid authorization credentials: API key not
/// found"}` and ONYPHE with `400 {..."text":"Invalid API key format"...}`. Without
/// recognising these, the dead key is never burned or rotated and the module
/// wastes itself on every scan (observed live: netlas + onyphe both erroring 400
/// every run with a stale embedded key). Deliberately narrow and auth-specific so a
/// genuine bad-query 400 — which other paths map to a clean "not found" miss — is
/// never misclassified as a key problem.
const AUTH_400_SIGNATURES: &[&str] = &[
    "api key not found",
    "invalid api key",
    "api key format",
    "invalid authorization",
    "authorization credentials",
    "authentication failed",
    "invalid token",
    "bad credentials",
    "unauthorized",
    "not authorized",
];

/// True when a `400 Bad Request` body is really an authentication / API-key
/// failure (see [`AUTH_400_SIGNATURES`]) — the ambiguous-400 providers that mean
/// 401. Callers gate this on `code == 400` so it only reinterprets that one
/// ambiguous status; every other non-2xx keeps its exact prior classification.
#[must_use]
pub fn is_auth_failure_400_body(body: &str) -> bool {
    let lower = body.to_ascii_lowercase();
    AUTH_400_SIGNATURES.iter().any(|s| lower.contains(s))
}

/// Mark `key` exhausted (so the key pool / rotation can react) when `code` is a
/// key-problem status per [`is_keyed_error_status`]; a no-op otherwise.
///
/// This is the non-retrying counterpart to [`handle_keyed_error`]: it does NOT
/// sleep, back off, or return a retry signal. It centralises the
/// `if 401/403/429 { ctx.report_key_exhausted(..) }` block that many keyed
/// modules — which surface the error immediately rather than retrying — had
/// hand-rolled identically.
pub fn note_keyed_error(
    code: u16,
    module: &str,
    key: &str,
    ctx: &crate::core::module::ModuleContext,
) {
    if is_keyed_error_status(code) {
        ctx.report_key_exhausted(module, key, code);
    }
}

/// Classify a keyed-API response by status — the full post-send operation that
/// the keyed modules repeat. `404` -> `Ok(None)` (a clean "not in this dataset"
/// miss the caller maps to empty findings); any other non-2xx ->
/// [`note_keyed_error`] (so 401/403/429 burn the key) then `Err` via
/// [`super::fetch::http_status_error`]-shaped message; `2xx` -> `Ok(Some(resp))`
/// for the caller to decode.
///
/// Composes the keyed-error building blocks so the policy — which codes are a
/// miss, which burn a key, which are a hard error — lives in one tested place.
/// Pairs with `let-else`:
///
/// ```ignore
/// let Some(resp) = http::keyed_ok_or_404(SRC, key, ctx, resp).await? else {
///     return Ok(ModuleResult::new());
/// };
/// ```
pub async fn keyed_ok_or_404(
    module: &str,
    key: &str,
    ctx: &crate::core::module::ModuleContext,
    resp: reqwest::Response,
) -> Result<Option<reqwest::Response>> {
    let status = resp.status();
    let code = status.as_u16();
    if code == 404 {
        return Ok(None);
    }
    if !status.is_success() {
        // Read the body once — it is needed for the error message regardless, and it
        // is what disambiguates a 400: some providers (Netlas) answer a dead key with
        // 400 + an auth message, not 401, so an auth-shaped 400 must burn the key like
        // a 401 would (otherwise the pool never rotates past the dead key).
        let snippet = error_snippet(resp).await;
        if is_keyed_error_status(code) || (code == 400 && is_auth_failure_400_body(&snippet)) {
            ctx.report_key_exhausted(module, key, code);
        }
        return Err(Error::module(module, format!("HTTP {status}: {snippet}")));
    }
    Ok(Some(resp))
}

/// Keyed GET: fetch JSON from a URL that requires an API key header.
/// Handles 401/403/429 uniformly via report_key_exhausted, maps 404
/// to Ok(None). Consolidates the error handling pattern duplicated
/// across 8+ keyed modules.
///
/// **In-scan key cascade.** Every consumer of this chokepoint inherits the same
/// "maximise API key usage" policy the hand-rolled keyed modules
/// (`dehashed`/`hibp`/`leakix`) implement: when the current key hits a terminal
/// key-quota/auth failure (401/403/429), the call rotates to the next USABLE
/// pooled key for `module` — the pool's service name is the module name, matching
/// [`crate::core::module::ModuleContext::report_key_exhausted`] — and retries the
/// request with it, so one call spends every credential the pool holds before it
/// fails. A service with no extra pooled keys (the common single-key case) sees
/// [`crate::core::module::ModuleContext::next_pooled_key`] return `None` on the
/// first burn and behaves
/// exactly as before, so this is behaviour-preserving for single-key setups.
pub async fn fetch_keyed_json<T: DeserializeOwned>(
    ctx: &crate::core::module::ModuleContext,
    module: &'static str,
    url: &str,
    key_env: &str,
    header_name: &str,
) -> Result<Option<T>> {
    // Keys already burned this call, so the cascade never re-hands one. Seeded
    // with the hot-injected env key before its first use below.
    let mut tried: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut key = ctx.key(key_env)?.to_string();
    loop {
        tried.insert(key.clone());
        // Per-host circuit breaker (see `breaker_gate`): short-circuit a host that has failed
        // repeatedly. Host-less/unparseable URLs are un-gated. Note the deliberate asymmetry
        // with `fetch_json_inner`: a keyed request does NOT fall back to curl on a transport
        // error (a key header can't be replayed through the curl path), so a send failure is
        // surfaced directly after recording the breaker failure.
        let host = breaker_gate(module, url)?;
        // One bounded retry of the idempotent GET on a transient connect/timeout
        // blip — the same failure class the non-keyed curl fallback rescues, extended
        // to every keyed provider at this shared chokepoint. A key header can't be
        // replayed through the curl path (hence no curl fallback here), but a plain
        // re-send is safe and costs one round-trip. The transient first failure does
        // NOT record a breaker failure; only a non-transient error or a failed retry
        // does, so a single hiccup on a healthy host neither loses the result nor
        // trips the breaker.
        let mut attempt: u8 = 0;
        let resp = loop {
            match ctx.http.get(url).header(header_name, &key).send().await {
                Ok(resp) => break resp,
                Err(e) => {
                    if attempt == 0 && transport_is_transient(&e) {
                        attempt += 1;
                        continue;
                    }
                    if let Some(h) = host.as_deref() {
                        circuit_breaker::record_failure(h, crate::core::entity::unix_now());
                    }
                    return Err(Error::module(module, redact_credentials(&e.to_string())));
                }
            }
        };
        record_breaker_outcome(host.as_deref(), resp.status());
        let status = resp.status();
        if status.as_u16() == 404 {
            return Ok(None);
        }
        if !status.is_success() {
            let code = status.as_u16();
            // Read the body once (needed for the error message regardless); for an
            // ambiguous 400 it decides whether this is really an auth/key failure —
            // some providers answer a dead key with 400, not 401.
            let snippet = error_snippet(resp).await;
            let keyed =
                is_keyed_error_status(code) || (code == 400 && is_auth_failure_400_body(&snippet));
            // Burn the key on a key problem so the pool rotates past it next scan…
            if keyed {
                ctx.report_key_exhausted(module, &key, code);
            }
            // …and, if the pool still holds an untried usable key, cascade to it now
            // rather than failing this call.
            if keyed && let Some(next) = ctx.next_pooled_key(module, &tried) {
                key = next;
                continue;
            }
            return Err(Error::module(module, format!("HTTP {status}: {snippet}")));
        }
        return Ok(Some(decode_json_body(resp, module).await?));
    }
}

/// The general form of [`fetch_keyed_json`]'s cascade for a provider whose auth
/// scheme or HTTP method the GET-plus-single-header-value shape can't express —
/// a `bearer` prefix, extra headers, or a POST body. [`fetch_keyed_json`] owns
/// the request; this owns only the cascade, and the caller supplies the request
/// via `build`.
///
/// This is the exact outer loop that 9+ modules (`onyphe`, `threatfox`,
/// `criminal_ip`, `dehashed`, `leakix`, `securitytrails`, `ipqs`, `zoomeye`,
/// `intelx`, `hibp`, `niamonx`) hand-rolled identically because
/// [`fetch_keyed_json`] couldn't cover their request shape: begin on
/// `initial_key`, retry in place on a 429 with a real `Retry-After` sleep, up
/// to twice per key (via [`handle_keyed_error`]'s own retry budget), and on a
/// terminal key failure — 401/403/429, or
/// a 400 whose body is an auth failure in disguise (some providers, e.g.
/// ONYPHE/Netlas, answer a dead key with 400 rather than 401 — see
/// [`is_auth_failure_400_body`]) — rotate to the next usable pooled key and
/// retry, so one call spends every credential the pool holds before it fails.
///
/// `build(key)` constructs a fresh [`reqwest::RequestBuilder`] for one attempt
/// (a `RequestBuilder` isn't `Clone`, so it must be rebuilt per attempt, not
/// reused). On a 2xx the caller decodes the returned `Response` itself — some
/// providers scan the body for leaked API keys ([`super::json_scanned`]), some
/// don't ([`super::json_decode`]); that choice is the caller's, not this
/// primitive's, so it isn't lost in the consolidation.
///
/// `absent_statuses` names which non-2xx codes mean "no data for this
/// selector" rather than a failure — mirrors `fetch_json_inner`'s own
/// parameter for the identical reason: not every provider agrees. ONYPHE
/// answers an unknown selector with a real `404`, but ThreatFox's fixed POST
/// endpoint never returns one for a per-query miss (a miss is signalled in
/// the response *body*, `query_status: "no_result"`), so a caller that never
/// special-cased 404 must keep not special-casing it — pass `&[]`. Returns
/// `Ok(None)` for a code in `absent_statuses`, or if the scan is cancelled
/// mid-cascade (`ctx.cancel`, checked at the top of every attempt, so a
/// cancellation before a request is sent or between retries is observed
/// promptly — the one exception is *during* a 429's own backoff sleep inside
/// [`handle_keyed_error`], which is not itself cancel-aware and runs to
/// completion, clamped to 4 s, before the next check) — externally identical
/// either way to what every hand-rolled copy already did (`return
/// Ok(ModuleResult::new())` at the `process()` level).
pub async fn keyed_cascade<F>(
    ctx: &crate::core::module::ModuleContext,
    module: &'static str,
    initial_key: &str,
    absent_statuses: &[u16],
    build: F,
) -> Result<Option<reqwest::Response>>
where
    F: FnMut(&str) -> reqwest::RequestBuilder,
{
    Ok(
        keyed_cascade_with_key(ctx, module, initial_key, absent_statuses, build)
            .await?
            .map(|(resp, _)| resp),
    )
}

/// [`keyed_cascade`], additionally returning **which key actually served the
/// response** — the cascade may have rotated away from `initial_key`, so a
/// caller that stamps key provenance onto its findings must fingerprint the
/// winning key, not the one it started with.
///
/// Split out rather than folded into [`keyed_cascade`]'s return type so the
/// common case (callers that don't care which key won) stays a plain
/// `Option<Response>` with no destructuring. `dehashed` needs this: it stamps
/// `api_key_origin` on every emitted record, and pinning that to the initial
/// key after a rotation would misattribute the finding's provenance.
pub async fn keyed_cascade_with_key<F>(
    ctx: &crate::core::module::ModuleContext,
    module: &'static str,
    initial_key: &str,
    absent_statuses: &[u16],
    mut build: F,
) -> Result<Option<(reqwest::Response, String)>>
where
    F: FnMut(&str) -> reqwest::RequestBuilder,
{
    let mut tried: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut key = initial_key.to_string();
    loop {
        // Record BEFORE attempting: a burned key must never be re-handed by
        // `next_pooled_key`, including the initial one.
        tried.insert(key.clone());
        match attempt_with_key(ctx, module, &key, absent_statuses, &mut build).await {
            Attempt::Ok(resp) => return Ok(Some((resp, key))),
            Attempt::Absent | Attempt::Cancelled => return Ok(None),
            Attempt::Failed(e) => return Err(e),
            Attempt::Rotate(e) => match ctx.next_pooled_key(module, &tried) {
                Some(next) => key = next,
                None => return Err(e),
            },
        }
    }
}

/// What one key's attempt produced. The cascade drivers
/// ([`keyed_cascade_with_key`], [`keyed_cascade_json`]) differ only in what they
/// do with a 2xx; extracting the attempt keeps the retry/burn/classification
/// policy in one place instead of duplicating it per driver.
enum Attempt {
    /// A 2xx response on this key.
    Ok(reqwest::Response),
    /// A status the caller declared absent — a clean miss, not a failure.
    Absent,
    /// This key is dead or exhausted and has already been burned. Carries the
    /// error to surface if no untried key remains to rotate to.
    Rotate(Error),
    /// Terminal and not key-related; no rotation can help.
    Failed(Error),
    /// The scan was cancelled.
    Cancelled,
}

/// Drive ONE key: send, honour a 429 backoff in place (up to
/// [`handle_keyed_error`]'s budget), and classify the outcome. Never rotates —
/// key selection belongs to the caller, which owns the `tried` set.
async fn attempt_with_key<F>(
    ctx: &crate::core::module::ModuleContext,
    module: &'static str,
    key: &str,
    absent_statuses: &[u16],
    build: &mut F,
) -> Attempt
where
    F: FnMut(&str) -> reqwest::RequestBuilder,
{
    let mut retries = 2u8;
    loop {
        if ctx.cancel.is_cancelled() {
            return Attempt::Cancelled;
        }
        let resp = match build(key).send_tagged(module).await {
            Ok(r) => r,
            Err(e) => return Attempt::Failed(e),
        };
        let status = resp.status();
        if absent_statuses.contains(&status.as_u16()) {
            return Attempt::Absent;
        }
        if status.is_success() {
            return Attempt::Ok(resp);
        }
        let code = status.as_u16();
        if handle_keyed_error(code, resp.headers(), &mut retries, module, key, ctx).await {
            continue;
        }
        let snippet = error_snippet(resp).await;
        // handle_keyed_error already burned 401/403/429 internally; the
        // ambiguous-400-as-auth-failure case is this cascade's own extra check,
        // so it burns the key itself when that's what fired.
        let keyed =
            is_keyed_error_status(code) || (code == 400 && is_auth_failure_400_body(&snippet));
        let err = Error::module(module, format!("HTTP {status}: {snippet}"));
        if keyed {
            if code == 400 {
                ctx.report_key_exhausted(module, key, code);
            }
            return Attempt::Rotate(err);
        }
        return Attempt::Failed(err);
    }
}

/// What an inspected response BODY says about the key that produced it.
///
/// Some providers answer a dead or exhausted key with `HTTP 200` and an
/// in-body status rather than a 401/403/429 — Criminal IP reports
/// `status: 401|402|429` inside the JSON, IPQS reports `success: false` with a
/// quota/auth message. Those are key failures the HTTP-status cascade cannot
/// see, so without inspecting the body a dead key is indistinguishable from a
/// clean empty result and the pool never rotates past it.
pub enum BodyVerdict {
    /// A real answer; return it.
    Accept,
    /// An auth/quota failure reported in the body.
    KeyFailure {
        /// The provider's own status, used when reporting the key to the pool.
        code: u16,
        /// The provider's own explanation, surfaced VERBATIM in the terminal
        /// error once no untried key remains. IPQS distinguishes quota
        /// exhaustion from a bad key from a plan limit only in this text, and
        /// summarising it away would leave the operator unable to tell which —
        /// so it is carried through rather than collapsed into the status code.
        /// `None` where the provider offers no detail beyond the status.
        detail: Option<String>,
    },
    /// A genuine miss for this query — not a key problem. Yields `Ok(None)`.
    Absent,
}

/// [`keyed_cascade`] for a provider that reports key failures **in the response
/// body on an HTTP 2xx**, which the status-only cascade cannot detect.
///
/// Decodes each successful response and asks `verdict` what the body means. On
/// [`BodyVerdict::KeyFailure`] it burns the key and rotates exactly as an
/// HTTP 401/403/429 would, so one call still spends every credential the pool
/// holds. Decoding uses [`super::json_decode`] — both current callers
/// (`criminal_ip`, `ipqs`) use it; a key-scanning variant belongs here only when
/// a caller actually needs one.
pub async fn keyed_cascade_json<T, F, V>(
    ctx: &crate::core::module::ModuleContext,
    module: &'static str,
    initial_key: &str,
    absent_statuses: &[u16],
    mut build: F,
    verdict: V,
) -> Result<Option<T>>
where
    T: DeserializeOwned,
    F: FnMut(&str) -> reqwest::RequestBuilder,
    V: Fn(&T) -> BodyVerdict,
{
    let mut tried: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut key = initial_key.to_string();
    loop {
        // Record BEFORE attempting — see `keyed_cascade_with_key`.
        tried.insert(key.clone());
        let rotate_err = match attempt_with_key(ctx, module, &key, absent_statuses, &mut build)
            .await
        {
            Attempt::Absent | Attempt::Cancelled => return Ok(None),
            Attempt::Failed(e) => return Err(e),
            Attempt::Rotate(e) => e,
            Attempt::Ok(resp) => {
                let decoded: T = super::json_decode(module, resp).await?;
                match verdict(&decoded) {
                    BodyVerdict::Accept => return Ok(Some(decoded)),
                    BodyVerdict::Absent => return Ok(None),
                    BodyVerdict::KeyFailure { code, detail } => {
                        ctx.report_key_exhausted(module, &key, code);
                        // Carry the provider's own words through: they are
                        // what distinguishes quota from auth from plan
                        // limit, and the status code alone cannot.
                        Error::module(
                            module,
                            match detail {
                                Some(d) => format!(
                                    "{module} reported an in-body key failure (status {code}): {d}"
                                ),
                                None => format!(
                                    "{module} reported an in-body key failure (status {code})"
                                ),
                            },
                        )
                    }
                }
            }
        };
        match ctx.next_pooled_key(module, &tried) {
            Some(next) => key = next,
            None => return Err(rotate_err),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{is_auth_failure_400_body, is_keyed_error_status};

    #[test]
    fn auth_400_body_matches_real_provider_bodies() {
        // The exact bodies observed live from a stale embedded key (see the
        // AUTH_400_SIGNATURES rationale) — Netlas and ONYPHE both answer a dead key
        // with 400, and both must be recognised as a KEY failure.
        assert!(is_auth_failure_400_body(
            r#"{"detail":"Request had invalid authorization credentials: API key not found"}"#
        ));
        assert!(is_auth_failure_400_body(
            r#"{"count":0,"error":3,"status":"nok","text":"Invalid API key format","took":0}"#
        ));
        // Case-insensitive.
        assert!(is_auth_failure_400_body("UNAUTHORIZED"));
    }

    #[test]
    fn auth_400_body_rejects_genuine_bad_query_400s() {
        // A real "bad query / not found" 400 must NOT be mistaken for a key problem,
        // or the tool would burn a perfectly good key on an unrelated failure.
        assert!(!is_auth_failure_400_body(
            r#"{"error":"InvalidRequest","message":"Profile not found"}"#
        ));
        assert!(!is_auth_failure_400_body(
            r#"{"error":"validation","message":"query parameter 'q' is required"}"#
        ));
        assert!(!is_auth_failure_400_body(""));
    }

    #[test]
    fn keyed_error_status_is_unchanged_by_the_400_path() {
        // The 400 reinterpretation is body-gated and additive: the status-only
        // classification every other caller relies on is exactly as before.
        assert!(is_keyed_error_status(401));
        assert!(is_keyed_error_status(403));
        assert!(is_keyed_error_status(429));
        assert!(!is_keyed_error_status(400));
        assert!(!is_keyed_error_status(404));
        assert!(!is_keyed_error_status(500));
    }

    #[tokio::test]
    async fn transport_is_transient_flags_a_connect_refusal() {
        // A connection to a just-closed local port is a real connect error —
        // exactly the transient class the keyed retry should re-send on. Bind a
        // listener to grab a free port, then drop it so the port is closed.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("should succeed");
        let addr = listener.local_addr().expect("should succeed");
        drop(listener);
        let err = reqwest::Client::builder()
            .no_proxy()
            .timeout(std::time::Duration::from_secs(2))
            .build()
            .expect("should succeed")
            .get(format!("http://{addr}/"))
            .send()
            .await
            .expect_err("connecting to a closed port must fail");
        assert!(
            super::transport_is_transient(&err),
            "a connect refusal must classify as transient: {err:?}"
        );
    }
}
