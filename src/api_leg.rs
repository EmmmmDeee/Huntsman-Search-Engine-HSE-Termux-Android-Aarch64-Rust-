//! The one request path of the free and free-tier JSON API legs.
//!
//! A leg is one `GET` to one provider for one selector. [`Api`] declares everything that differs
//! between providers: the source label, the only origin a key may be sent to, and how the key is
//! carried. [`get`] does the rest the same way for each of them, through [`crate::fetch`]:
//! redirects are not followed, so a key cannot leave its origin; a key is only built from an
//! operator-configured slot; any provider text kept in a diagnostic has the key scrubbed first.
//!
//! The status decides before the body: a refused key, a plan or quota refusal, a rate limit and a
//! server error are errors, never a zero. A `404` is returned as [`Answer::NotFound`] because for
//! several providers it is the documented "nothing known about this selector" answer, and only
//! the provider module knows whether it is. A `200` body is only an answer when it is not a
//! challenge page and was not cut at the body limit.
//!
//! A keyed leg runs only when its key is configured (see [`Api::wanted`]): a lookup without the
//! key makes no request to that provider, and `credential-status` names the slot.

use std::time::Duration;

use crate::credential_origin::{AuthenticationAuthority, OperatorCredentialRef};
use crate::fetch::{AuthStyle, Credential, FetchOptions, fetch};
use crate::http::{Request, Response, Transport, TransportConfig};
use crate::keys::{Keys, Secret};
use crate::redact::scrub_secrets;
use crate::source_outcome::{SourceExecutionOutcome, SourceOutcomeKind};

/// Ceiling for one leg's one request.
pub const TIMEOUT: Duration = Duration::from_secs(20);
/// Longest provider text kept in a diagnostic or an attribute, in characters.
pub const MAX_TEXT_CHARS: usize = 160;

/// How a provider takes its key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyUse {
    /// The slot the key is read from (a constant in [`crate::environment`]).
    pub slot: &'static str,
    /// The request header that carries it.
    pub header: &'static str,
    /// `false` when the provider also answers without a key, at a lower limit.
    pub required: bool,
}

/// One provider endpoint family, as a leg uses it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Api {
    /// Source label in outcomes, evidence and saved ledgers.
    pub source: &'static str,
    /// The provider's own domain, recorded with the operator approval of the key.
    pub provider: &'static str,
    /// The only origin a request goes to, written as [`crate::http::origin_of`] writes it.
    pub origin: &'static str,
    /// `None` for a keyless provider.
    pub key: Option<KeyUse>,
}

impl Api {
    /// Whether this leg runs for `keys`: a keyless or key-optional provider always does, a
    /// key-required one only when its slot holds a key. **Pure.**
    #[must_use]
    pub fn wanted(&self, keys: &Keys) -> bool {
        match self.key {
            None => true,
            Some(key) => !key.required || keys.get(key.slot).is_some(),
        }
    }
}

/// What a provider answered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Answer {
    /// A 2xx body.
    Body(Vec<u8>),
    /// A 404 body. The provider module decides whether this is "nothing known".
    NotFound(Vec<u8>),
}

/// Why a leg gave no answer. No variant carries the key or a response body.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum LegError {
    #[error("no API key configured (set {0})")]
    MissingKey(&'static str),
    #[error("request refused before sending: {0}")]
    Refused(String),
    #[error("no response ({0:?})")]
    Transport(SourceOutcomeKind),
    #[error("bad request (HTTP {0})")]
    BadRequest(u16),
    #[error("unauthorised (HTTP 401): the key was rejected")]
    Unauthorized,
    #[error("forbidden (HTTP 403): the plan or quota does not allow it")]
    Forbidden,
    #[error("rate or quota limit reached (HTTP 429){}", describe_retry(*.retry_after))]
    RateLimited { retry_after: Option<u64> },
    #[error("server error (HTTP {0})")]
    Server(u16),
    #[error("unexpected HTTP {0}")]
    Unexpected(u16),
    #[error("response is not an API answer ({0:?})")]
    NotAnAnswer(SourceOutcomeKind),
    #[error("{0}")]
    Decode(String),
}

fn describe_retry(retry_after: Option<u64>) -> String {
    retry_after.map_or_else(String::new, |secs| format!(", retry after {secs}s"))
}

impl LegError {
    /// The outcome a failed leg records.
    #[must_use]
    pub const fn outcome_kind(&self) -> SourceOutcomeKind {
        match self {
            Self::MissingKey(_) => SourceOutcomeKind::AuthRequired,
            Self::Unauthorized => SourceOutcomeKind::AuthRejected,
            Self::Forbidden => SourceOutcomeKind::EntitlementDenied,
            Self::RateLimited { .. } => SourceOutcomeKind::RateLimited,
            Self::BadRequest(_) | Self::Unexpected(_) => SourceOutcomeKind::Upstream4xx,
            Self::Server(_) => SourceOutcomeKind::Upstream5xx,
            Self::Transport(kind) | Self::NotAnAnswer(kind) => *kind,
            Self::Decode(_) => SourceOutcomeKind::SchemaDrift,
            Self::Refused(_) => SourceOutcomeKind::Inconclusive,
        }
    }

    /// The HTTP status behind the failure, when there was one.
    #[must_use]
    pub const fn http_status(&self) -> Option<u16> {
        match self {
            Self::BadRequest(status) | Self::Server(status) | Self::Unexpected(status) => {
                Some(*status)
            }
            Self::Unauthorized => Some(401),
            Self::Forbidden => Some(403),
            Self::RateLimited { .. } => Some(429),
            _ => None,
        }
    }

    /// The failed outcome of `api`'s leg, with the provider's pause when it asked for one.
    #[must_use]
    pub fn outcome(&self, api: &Api, now_unix: u64) -> SourceExecutionOutcome {
        let outcome = SourceExecutionOutcome::failed(
            api.source,
            now_unix,
            self.outcome_kind(),
            self.http_status(),
            format!("{}: {self}", api.source),
        );
        match self {
            Self::RateLimited {
                retry_after: Some(secs),
            } => outcome.with_retry_after(*secs),
            _ => outcome,
        }
    }
}

/// Transport settings for a leg: the [`TIMEOUT`] ceiling.
#[must_use]
pub fn transport_config() -> TransportConfig {
    TransportConfig {
        timeout: TIMEOUT,
        ..TransportConfig::default()
    }
}

/// `GET url` for `api`, with its key from `keys` when it has one.
///
/// # Errors
/// [`LegError::MissingKey`] before any request when a required key is not configured; otherwise
/// the refusal, missing response, status or body problem that stopped the leg.
pub fn get<T: Transport + ?Sized>(
    transport: &T,
    api: &Api,
    keys: &Keys,
    url: &str,
    now_unix: u64,
) -> Result<Answer, LegError> {
    let secret = match api.key {
        None => None,
        Some(key) => match keys.get(key.slot) {
            Some(secret) => Some((key, secret)),
            None if key.required => return Err(LegError::MissingKey(key.slot)),
            None => None,
        },
    };
    let credential = secret
        .as_ref()
        .map(|(key, secret)| credential(api, *key, secret.clone(), now_unix))
        .transpose()?;
    let scrub: Vec<&str> = secret.iter().map(|(_, s)| s.expose()).collect();
    let request = Request::get(url)
        .header("Accept", "application/json")
        .with_timeout(TIMEOUT);
    let fetched = fetch(
        transport,
        request,
        credential.as_ref(),
        &FetchOptions::no_redirects(),
        api.source,
        now_unix,
    )
    .map_err(|e| LegError::Refused(scrub_secrets(&e.to_string(), &scrub)))?;
    let Some(response) = fetched.response else {
        return Err(LegError::Transport(fetched.outcome.kind));
    };
    if response.status == 404 {
        return Ok(Answer::NotFound(response.body));
    }
    status_error(&response)?;
    if fetched.outcome.kind != SourceOutcomeKind::Inconclusive {
        return Err(LegError::NotAnAnswer(fetched.outcome.kind));
    }
    if response.truncated {
        return Err(LegError::Decode("response exceeds the body limit".into()));
    }
    Ok(Answer::Body(response.body))
}

fn credential(
    api: &Api,
    key: KeyUse,
    secret: Secret,
    now_unix: u64,
) -> Result<Credential, LegError> {
    let authority = AuthenticationAuthority::operator_approved(OperatorCredentialRef {
        provider_id: api.provider.into(),
        credential_slot: key.slot.into(),
        approved_at_unix: now_unix,
        approval_provenance: format!("operator configured {}", key.slot),
    })
    .map_err(|e| LegError::Refused(e.to_string()))?;
    Credential::new(authority, secret, AuthStyle::Header(key.header.into()))
        .map(|c| c.only_for_origin(api.origin))
        .map_err(|e| LegError::Refused(e.to_string()))
}

/// The error a non-2xx, non-404 status means. **Pure.**
fn status_error(response: &Response) -> Result<(), LegError> {
    match response.status {
        200..=299 => Ok(()),
        400 | 422 => Err(LegError::BadRequest(response.status)),
        401 => Err(LegError::Unauthorized),
        402 | 403 => Err(LegError::Forbidden),
        429 => Err(LegError::RateLimited {
            retry_after: response
                .header_value("retry-after")
                .and_then(|v| v.trim().parse::<u64>().ok()),
        }),
        status @ 500..=599 => Err(LegError::Server(status)),
        status => Err(LegError::Unexpected(status)),
    }
}

/// `body` as `D`, or a [`LegError::Decode`] naming the error's category and position, never
/// serde's message, which can quote the body. **Pure.**
///
/// # Errors
/// [`LegError::Decode`] when the body is not `D`.
pub fn decode<D: serde::de::DeserializeOwned>(body: &[u8]) -> Result<D, LegError> {
    serde_json::from_slice(body).map_err(|e| {
        let category = match e.classify() {
            serde_json::error::Category::Io => "io",
            serde_json::error::Category::Syntax => "syntax",
            serde_json::error::Category::Data => "data",
            serde_json::error::Category::Eof => "eof",
        };
        LegError::Decode(format!(
            "unexpected response shape: {category} error at line {} column {}",
            e.line(),
            e.column()
        ))
    })
}

/// Provider text as an attribute or diagnostic may keep it: trimmed, control characters
/// replaced, at most [`MAX_TEXT_CHARS`] characters, `None` when blank. **Pure.**
#[must_use]
pub fn clean(text: Option<&str>) -> Option<String> {
    let text = text?.trim();
    if text.is_empty() {
        return None;
    }
    Some(
        text.chars()
            .take(MAX_TEXT_CHARS)
            .map(|c| if c.is_control() { '\u{fffd}' } else { c })
            .collect(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::{Method, TransportFailure};
    use std::sync::Mutex;

    const KEY: &str = "leg-test-key-0123456789abcdef";
    const SLOT: &str = crate::environment::ABUSEIPDB_KEY_ENV;

    const KEYED: Api = Api {
        source: "fixture",
        provider: "example.com",
        origin: "https://api.example.com:443",
        key: Some(KeyUse {
            slot: SLOT,
            header: "Key",
            required: true,
        }),
    };
    const OPTIONAL: Api = Api {
        key: Some(KeyUse {
            slot: SLOT,
            header: "Key",
            required: false,
        }),
        ..KEYED
    };
    const KEYLESS: Api = Api { key: None, ..KEYED };

    fn keys() -> Keys {
        match Keys::parse(&format!("{SLOT}={KEY}\n")) {
            Ok(keys) => keys,
            Err(error) => panic!("fixture keys parse: {error}"),
        }
    }

    /// Answers every request with one response and records what was sent.
    struct Recorder {
        status: u16,
        headers: Vec<(String, String)>,
        body: String,
        sent: Mutex<Vec<Request>>,
    }

    impl Recorder {
        fn new(status: u16, body: &str) -> Self {
            Self {
                status,
                headers: Vec::new(),
                body: body.to_owned(),
                sent: Mutex::new(Vec::new()),
            }
        }

        fn sent(&self) -> Vec<Request> {
            match self.sent.lock() {
                Ok(sent) => sent.clone(),
                Err(poisoned) => poisoned.into_inner().clone(),
            }
        }
    }

    impl Transport for Recorder {
        fn send(&self, request: &Request) -> Result<Response, TransportFailure> {
            match self.sent.lock() {
                Ok(mut sent) => sent.push(request.clone()),
                Err(poisoned) => poisoned.into_inner().push(request.clone()),
            }
            Ok(Response {
                status: self.status,
                headers: self.headers.clone(),
                body: self.body.clone().into_bytes(),
                truncated: false,
            })
        }
    }

    const URL: &str = "https://api.example.com/v1/thing";

    #[test]
    fn a_required_key_that_is_absent_sends_nothing() {
        let transport = Recorder::new(200, "{}");
        let result = get(&transport, &KEYED, &Keys::default(), URL, 1);
        assert_eq!(result, Err(LegError::MissingKey(SLOT)));
        assert!(transport.sent().is_empty());
        assert!(!KEYED.wanted(&Keys::default()));
        assert!(KEYED.wanted(&keys()));
    }

    #[test]
    fn the_key_goes_in_the_declared_header_and_nowhere_else() {
        let transport = Recorder::new(200, "{\"ok\":true}");
        let answer = get(&transport, &KEYED, &keys(), URL, 1);
        assert_eq!(answer, Ok(Answer::Body(b"{\"ok\":true}".to_vec())));
        let sent = transport.sent();
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].method, Method::Get);
        assert_eq!(sent[0].url, URL);
        let carrying: Vec<&str> = sent[0]
            .headers
            .iter()
            .filter(|(_, value)| value.contains(KEY))
            .map(|(name, _)| name.as_str())
            .collect();
        assert_eq!(carrying, ["Key"]);
    }

    #[test]
    fn a_key_is_never_sent_to_another_origin() {
        let transport = Recorder::new(200, "{}");
        let result = get(&transport, &KEYED, &keys(), "https://evil.example.net/x", 1);
        let leaked = transport
            .sent()
            .iter()
            .any(|r| r.headers.iter().any(|(_, v)| v.contains(KEY)));
        assert!(!leaked, "{result:?}");
    }

    #[test]
    fn an_optional_key_runs_without_one_and_sends_none() {
        assert!(OPTIONAL.wanted(&Keys::default()));
        let transport = Recorder::new(200, "{}");
        assert!(get(&transport, &OPTIONAL, &Keys::default(), URL, 1).is_ok());
        assert!(transport.sent()[0].headers.iter().all(|(n, _)| n != "Key"));
        assert!(KEYLESS.wanted(&Keys::default()));
    }

    #[test]
    fn statuses_decide_before_the_body() {
        let cases: [(u16, LegError); 7] = [
            (400, LegError::BadRequest(400)),
            (401, LegError::Unauthorized),
            (402, LegError::Forbidden),
            (403, LegError::Forbidden),
            (429, LegError::RateLimited { retry_after: None }),
            (503, LegError::Server(503)),
            (418, LegError::Unexpected(418)),
        ];
        for (status, expected) in cases {
            let transport = Recorder::new(status, "{\"data\":[]}");
            assert_eq!(get(&transport, &KEYED, &keys(), URL, 1), Err(expected));
        }
    }

    #[test]
    fn a_rate_limit_carries_the_providers_pause_into_the_outcome() {
        let mut transport = Recorder::new(429, "{}");
        transport.headers = vec![("Retry-After".into(), "42".into())];
        let err = match get(&transport, &KEYED, &keys(), URL, 1) {
            Err(err) => err,
            Ok(answer) => panic!("a 429 is not an answer: {answer:?}"),
        };
        let outcome = err.outcome(&KEYED, 7);
        assert_eq!(outcome.kind, SourceOutcomeKind::RateLimited);
        assert_eq!(outcome.retry_after_secs, Some(42));
        assert_eq!(outcome.http_status, Some(429));
        assert_eq!(outcome.module, "fixture");
    }

    #[test]
    fn a_404_is_handed_to_the_provider_module() {
        let transport = Recorder::new(404, "{\"detail\":\"No information available\"}");
        assert_eq!(
            get(&transport, &KEYLESS, &Keys::default(), URL, 1),
            Ok(Answer::NotFound(
                b"{\"detail\":\"No information available\"}".to_vec()
            ))
        );
    }

    #[test]
    fn a_challenge_page_is_not_an_answer() {
        let transport = Recorder::new(
            200,
            "<html><title>Just a moment...</title><script src=\"https://challenges.cloudflare.com/x\"></script></html>",
        );
        assert!(matches!(
            get(&transport, &KEYLESS, &Keys::default(), URL, 1),
            Err(LegError::NotAnAnswer(_))
        ));
    }

    #[test]
    fn a_decode_error_never_quotes_the_body() {
        let err = match decode::<serde_json::Value>(b"{\"secret\": nope}") {
            Err(err) => err,
            Ok(value) => panic!("decoded {value}"),
        };
        assert!(!err.to_string().contains("secret"), "{err}");
        assert!(!err.to_string().contains("nope"), "{err}");
    }

    #[test]
    fn provider_text_is_trimmed_capped_and_has_no_controls() {
        assert_eq!(clean(Some("  ")), None);
        assert_eq!(clean(None), None);
        assert_eq!(clean(Some(" a\u{1b}b ")).as_deref(), Some("a\u{fffd}b"));
        assert_eq!(
            clean(Some(&"x".repeat(500))).map(|s| s.chars().count()),
            Some(MAX_TEXT_CHARS)
        );
    }
}
