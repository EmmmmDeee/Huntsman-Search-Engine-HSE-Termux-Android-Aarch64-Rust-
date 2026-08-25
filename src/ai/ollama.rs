//! Minimal client for a locally-run [Ollama](https://ollama.com) instance —
//! plain HTTP/JSON against its REST API, no SDK crate. See `src/ai/mod.rs` for
//! why this module is allowed to exist at all.

use crate::core::error::{Error, Result};
use crate::util::http::read_text;
use serde::Deserialize;
use std::time::Duration;

/// Fail-fast TCP connect budget for reaching the local Ollama instance —
/// generous for a same-host/same-LAN connection, small enough that a
/// misconfigured `base_url` (nothing listening) fails fast rather than hanging
/// the daemon's poll loop.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// Bound on [`OllamaClient::health_check`] end to end (connect + response).
/// `/api/tags` is a cheap local metadata lookup, not a generation call — it
/// should never legitimately take long, so this is fixed and short rather than
/// configurable like [`OllamaClient::generate`]'s caller-supplied timeout.
/// Deliberately NOT a client-level `read_timeout` (unlike
/// `crate::util::http::client_builder`'s): `generate()`'s response only
/// arrives after the full (non-streamed) generation completes, which can
/// legitimately take minutes, so a client-wide read timeout would break that
/// call instead of just bounding this one.
const HEALTH_CHECK_TIMEOUT: Duration = Duration::from_secs(10);

/// Build the client this module uses to reach Ollama.
///
/// Deliberately **not** [`crate::util::http::build_client`]: that client's
/// SSRF-guarded resolver exists to stop an OSINT module from being redirected
/// onto an internal/loopback address by a hostile *discovered* target, and it
/// would reject `localhost` (which resolves to loopback) for exactly that
/// reason — the wrong behaviour here, where the operator-configured Ollama
/// endpoint is loopback/private *by design* and is never attacker-influenced
/// (it comes only from `--ollama-url`/`HUNTSMAN_OLLAMA_URL`, an explicit
/// operator setting, never from scan data).
fn build_ollama_client() -> reqwest::Client {
    reqwest::Client::builder()
        .connect_timeout(CONNECT_TIMEOUT)
        .build()
        // expect justification: static, input-independent client config — a
        // failure here is a misbuilt binary (missing TLS backend, etc.), not a
        // runtime condition; every other client constructor in this crate
        // (`build_client`, `build_client_with_trace`) makes the same call.
        .expect("reqwest client failed to build")
}

/// Ollama's own documented default local bind address.
pub const DEFAULT_BASE_URL: &str = "http://127.0.0.1:11434";

/// Resolve a configured model name to the exact tag Ollama's `/api/generate`
/// will actually run, mirroring Ollama's own rule: a name with no `:tag`
/// receives an implicit `:latest` (`"qwen2.5"` → `"qwen2.5:latest"`), while a
/// name that already carries a tag is used verbatim (`"qwen2.5:7b"` stays put).
///
/// This is the single source of that resolution so [`OllamaClient::health_check`]
/// probes for the *same* tag [`OllamaClient::generate`] will later request —
/// without it the two disagree, and a config that names a bare family whose
/// only pulled variant is non-`latest` passes the health check yet 404s at
/// generate time (the opaque late failure the probe exists to pre-empt).
fn resolve_model_tag(model: &str) -> String {
    if model.contains(':') {
        model.to_string()
    } else {
        format!("{model}:latest")
    }
}

/// Module tag used for error attribution (`Error::module("ai_daemon", ...)`),
/// matching how every OSINT module names itself in a surfaced error.
const SRC: &str = "ai_daemon";

/// A response this large or larger is rejected with a clear error. Note this
/// does NOT bound peak memory the way a streaming cap would: `read_text`
/// (`crate::util::http`) already buffers the full body, up to its own 32 MiB
/// `JSON_BODY_CAP`, before this check ever runs — Ollama is a trusted local
/// service, not an untrusted OSINT target, so that isn't the threat model
/// here. This is a much narrower, deliberately small ceiling for the same
/// reason `crate::util::http` bounds JSON bodies at all: a scan-analysis
/// response is a short summary + a handful of findings, not a bulk export, so
/// anything past this size means something is wrong and a caller should get a
/// clear "too large" error rather than a confusing downstream JSON-parse one.
const MAX_RESPONSE_BYTES: usize = 1_000_000;

/// Upper bound on the tokens a single generation may emit, sent as
/// `options.num_predict`. The response contract is small and fixed — one short
/// summary paragraph plus at most [`crate::ai::analysis::MAX_FINDINGS`] findings
/// — so this sits far above any legitimate response while hard-capping the two
/// ways a generation can otherwise run for the caller's *entire* `timeout` (up
/// to minutes — see [`generate`](OllamaClient::generate)), draining a phone's
/// battery on the Termux/Android target this crate builds for: a model that
/// never emits a stop token, and Ollama's `format: "json"` mode emitting
/// unbounded whitespace when the model won't close the object. A runaway is cut
/// here instead of at the timeout. A legitimate response is never truncated —
/// which matters because `num_predict` does NOT guarantee well-formed JSON on a
/// cutoff, so truncating a real response would instead fail `parse_response`
/// closed and waste the whole call — hence the generous headroom over the
/// handful-of-findings contract rather than a tight fit.
const MAX_GENERATION_TOKENS: i32 = 2048;

/// Decoding temperature, sent as `options.temperature`. Deliberately low: this
/// task wants consistent severity calibration and adherence to the requested
/// JSON shape, not creative variety — the same rationale, and the same value,
/// that `scripts/finetune/Modelfile.example` bakes into a fine-tuned tag.
/// Setting it on the request too is what lets the README's primary *stock-model*
/// path (`ollama pull qwen2.5:7b` → `hse analyze`) share that calibration
/// instead of running at Ollama's creative-writing-oriented default (0.8). A
/// request option takes precedence over a Modelfile `PARAMETER`, so a tag built
/// from `Modelfile.example` — which sets the identical 0.3 — is unaffected.
const GENERATION_TEMPERATURE: f64 = 0.3;

/// A thin, stateless client bound to one Ollama endpoint and model.
pub struct OllamaClient {
    http: reqwest::Client,
    base_url: String,
    model: String,
}

#[derive(Deserialize)]
struct TagsResponse {
    #[serde(default)]
    models: Vec<TagEntry>,
}

#[derive(Deserialize)]
struct TagEntry {
    name: String,
}

#[derive(Deserialize)]
struct GenerateResponse {
    response: String,
}

impl OllamaClient {
    /// `base_url` is the scheme+host+port only (e.g. `http://127.0.0.1:11434`,
    /// no trailing slash expected but tolerated). `model` is the Ollama model
    /// tag to use for every [`generate`](Self::generate) call.
    #[must_use]
    pub fn new(base_url: impl Into<String>, model: impl Into<String>) -> Self {
        Self {
            http: build_ollama_client(),
            base_url: base_url.into().trim_end_matches('/').to_string(),
            model: model.into(),
        }
    }

    /// The Ollama model tag this client generates against.
    #[must_use]
    pub fn model(&self) -> &str {
        &self.model
    }

    /// Build a clear, attributable error for a failed `send()` — the crate-wide
    /// `From<reqwest::Error> for Error` (`src/core/error/mod.rs`) calls
    /// `.without_url()`, which strips both the URL and reqwest's underlying
    /// cause text (it lives on `.source()`, not the top-level `Display`), so a
    /// connect-refused/DNS-failure/timeout would otherwise surface as a
    /// content-free `"http: error sending request"`. That redaction protects
    /// API keys embedded in *other* modules' query strings; it buys nothing
    /// here, since `base_url` is operator-configured
    /// (`--ollama-url`/`HUNTSMAN_OLLAMA_URL`) and never attacker-influenced —
    /// see `build_ollama_client`'s doc comment.
    fn unreachable_err(&self, e: &reqwest::Error) -> Error {
        Error::module(
            SRC,
            format!(
                "could not reach Ollama at {}: {e}; is Ollama running? check --ollama-url / HUNTSMAN_OLLAMA_URL",
                self.base_url
            ),
        )
    }

    /// `GET /api/tags` — the cheapest possible reachability probe, and it also
    /// confirms `model` has actually been pulled, so a typo'd model name fails
    /// here with a clear, attributable message instead of surfacing as an
    /// opaque error from the first real [`generate`](Self::generate) call.
    ///
    /// The model check resolves the configured name the way Ollama itself will
    /// at generate time — a bare family name gets an implicit `:latest`
    /// (`"qwen2.5"` → `"qwen2.5:latest"`; see [`resolve_model_tag`]) — and
    /// requires that resolved tag to be served. That makes this probe agree
    /// with the [`generate`](Self::generate) call it precedes: it passes iff
    /// that call would find the model, never green-lighting a name Ollama would
    /// then 404 on.
    pub async fn health_check(&self) -> Result<()> {
        tokio::time::timeout(HEALTH_CHECK_TIMEOUT, self.health_check_inner())
            .await
            .map_err(|_| {
                Error::module(
                    SRC,
                    format!("Ollama health check timed out after {HEALTH_CHECK_TIMEOUT:?}"),
                )
            })?
    }

    async fn health_check_inner(&self) -> Result<()> {
        let url = format!("{}/api/tags", self.base_url);
        let resp = self
            .http
            .get(&url)
            .send()
            .await
            .map_err(|e| self.unreachable_err(&e))?;
        let status = resp.status();
        let text = read_text(SRC, resp).await?;
        if !status.is_success() {
            return Err(Error::module(
                SRC,
                format!(
                    "Ollama /api/tags returned HTTP {status}: {}",
                    crate::ai::truncate_chars(&text, ERROR_SNIPPET_CHARS)
                ),
            ));
        }
        let tags: TagsResponse = serde_json::from_str(&text)?;
        let served: Vec<&str> = tags.models.iter().map(|m| m.name.as_str()).collect();
        // Probe for exactly the tag `generate` will run — `resolve_model_tag`
        // applies Ollama's own bare-name → `:latest` rule — rather than
        // accepting any served tag that merely shares the configured family.
        // The looser family match reported "reachable and pulled" for a
        // `qwen2.5` config when only `qwen2.5:7b` was pulled, then `generate`
        // (asking Ollama for `qwen2.5`, i.e. `qwen2.5:latest`) 404'd — the
        // opaque, late, per-scan failure this whole probe exists to convert
        // into one clear up-front error.
        let wanted = resolve_model_tag(&self.model);
        let matches = served.iter().any(|tag| *tag == wanted);
        if !matches {
            // Name the resolved tag when it differs from what the operator
            // configured (a bare family name), so the fix — pull that tag, or
            // configure the exact variant that is pulled — is obvious.
            let named = if wanted == self.model {
                format!("model '{}'", self.model)
            } else {
                format!(
                    "model '{}' (Ollama resolves this to '{wanted}')",
                    self.model
                )
            };
            return Err(Error::module(
                SRC,
                format!(
                    "{named} is not pulled in this Ollama instance (available: {})",
                    if served.is_empty() {
                        "none".to_string()
                    } else {
                        served.join(", ")
                    }
                ),
            ));
        }
        Ok(())
    }

    /// The `POST /api/generate` request body for `prompt`. Split out as a pure
    /// function so its shape — the JSON-mode constraint and the bounded decoding
    /// options that keep this call phone-safe — is unit-tested without a network
    /// round-trip, the same pure-core/IO split the rest of this crate uses.
    fn generate_body(&self, prompt: &str) -> serde_json::Value {
        serde_json::json!({
            "model": self.model,
            "prompt": prompt,
            "stream": false,
            // Ollama's stable, broadly-supported JSON-mode: constrains decoding
            // to well-formed JSON, so a model doesn't wrap its answer in prose
            // or a markdown code fence despite the prompt asking for bare JSON.
            // This does NOT constrain to a specific *shape* (a full JSON-schema
            // `format` exists in newer Ollama releases, but isn't assumed here
            // to stay compatible with older installs) — `analysis::parse_response`
            // still validates the shape and fails closed on a mismatch.
            "format": "json",
            // Bounded decoding, set on the request so they hold for a stock
            // model too (they override any Modelfile `PARAMETER`): `num_predict`
            // hard-caps a runaway generation that would otherwise burn the whole
            // caller timeout (see `MAX_GENERATION_TOKENS`), and the low
            // `temperature` gives the stock-model path the severity-calibration
            // /shape consistency this task needs (see `GENERATION_TEMPERATURE`).
            "options": {
                "temperature": GENERATION_TEMPERATURE,
                "num_predict": MAX_GENERATION_TOKENS,
            },
        })
    }

    /// `POST /api/generate` with `stream: false`, returning the model's raw
    /// text response. Does not itself impose a timeout — an LLM generation can
    /// legitimately take anywhere from seconds to minutes depending on the
    /// model and hardware, so the caller wraps this in a `tokio::time::timeout`
    /// sized for its own context (see `analysis::analyze_scan`).
    pub async fn generate(&self, prompt: &str) -> Result<String> {
        let url = format!("{}/api/generate", self.base_url);
        let body = self.generate_body(prompt);
        let resp = self
            .http
            .post(&url)
            .json(&body)
            .send()
            .await
            .map_err(|e| self.unreachable_err(&e))?;
        let status = resp.status();
        let text = read_text(SRC, resp).await?;
        // Surface a non-2xx before the size cap: an Ollama error body (e.g. a
        // 404 `{"error":"model ... not found"}`) is the actionable failure, and
        // reporting it as "response too large" instead would bury the real
        // cause. Ollama's own error bodies are small, so this order never trades
        // away the size guard in practice — a genuine oversized body still has a
        // 2xx status and is caught immediately below.
        if !status.is_success() {
            return Err(Error::module(
                SRC,
                format!(
                    "Ollama /api/generate returned HTTP {status}: {}",
                    crate::ai::truncate_chars(&text, ERROR_SNIPPET_CHARS)
                ),
            ));
        }
        if text.len() > MAX_RESPONSE_BYTES {
            return Err(Error::module(
                SRC,
                format!(
                    "Ollama response exceeded {MAX_RESPONSE_BYTES} bytes ({} read)",
                    text.len()
                ),
            ));
        }
        let parsed: GenerateResponse = serde_json::from_str(&text)?;
        Ok(parsed.response)
    }
}

/// A response/error body is arbitrary upstream text — max chars kept when
/// truncating one for a log line or a surfaced `Error` (via
/// [`crate::ai::truncate_chars`]), mirroring `crate::util::http`'s own
/// `key_tail` discipline.
const ERROR_SNIPPET_CHARS: usize = 300;

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU32, Ordering};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// Bind an ephemeral loopback listener and hand back its address plus a
    /// handle to the spawned task that will serve exactly one raw HTTP/1.1
    /// response per connection, in order. Mirrors the loopback-listener test
    /// pattern used throughout `src/modules/*/tests.rs` (e.g. `domainsdb::tests`).
    async fn fake_server<S: Into<String>>(responses: Vec<S>) -> (String, Arc<AtomicU32>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind loopback");
        let addr = listener.local_addr().expect("local addr");
        let hits = Arc::new(AtomicU32::new(0));
        let hits_srv = Arc::clone(&hits);
        let responses: Vec<String> = responses.into_iter().map(Into::into).collect();
        tokio::spawn(async move {
            for body in responses {
                let Ok((mut sock, _)) = listener.accept().await else {
                    return;
                };
                hits_srv.fetch_add(1, Ordering::SeqCst);
                let mut buf = [0u8; 2048];
                let _ = sock.read(&mut buf).await;
                let _ = sock.write_all(body.as_bytes()).await;
                let _ = sock.flush().await;
            }
        });
        (format!("http://{addr}"), hits)
    }

    /// Build a raw HTTP/1.1 200 response with a correctly computed
    /// `Content-Length` for `json_body` — hand-counting this by eye is exactly
    /// how the earlier version of these tests broke (an off-by-N truncated the
    /// body and turned "model not pulled" assertions into JSON-parse-error
    /// assertions instead).
    fn ok_json_response(json_body: &str) -> String {
        format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{json_body}",
            json_body.len()
        )
    }

    #[tokio::test]
    async fn health_check_accepts_an_exact_tag_match() {
        let (base_url, _hits) = fake_server(vec![ok_json_response(
            "{\"models\":[{\"name\":\"qwen2.5:7b\"},{\"name\":\"x\"}]}",
        )])
        .await;
        let client = OllamaClient::new(base_url, "qwen2.5:7b");
        client
            .health_check()
            .await
            .expect("model is listed exactly");
    }

    #[tokio::test]
    async fn health_check_accepts_a_bare_family_resolved_to_latest() {
        // A bare `qwen2.5` is what Ollama resolves to `qwen2.5:latest`, and that
        // tag IS served here — so the probe passes, exactly as `generate` would.
        let (base_url, _hits) = fake_server(vec![ok_json_response(
            "{\"models\":[{\"name\":\"qwen2.5:latest\"}]}",
        )])
        .await;
        let client = OllamaClient::new(base_url, "qwen2.5");
        client
            .health_check()
            .await
            .expect("bare family name resolves to the served :latest tag");
    }

    #[tokio::test]
    async fn health_check_fails_closed_on_bare_family_when_only_a_non_latest_variant_is_pulled() {
        // The regression: a bare `qwen2.5` config with only `qwen2.5:7b` pulled.
        // Ollama resolves `qwen2.5` to `qwen2.5:latest`, which is NOT served, so
        // `generate` would 404 — the probe must catch that here, not green-light
        // it. (The old family-prefix match accepted `qwen2.5:7b` and passed.)
        let (base_url, _hits) = fake_server(vec![ok_json_response(
            "{\"models\":[{\"name\":\"qwen2.5:7b\"}]}",
        )])
        .await;
        let client = OllamaClient::new(base_url, "qwen2.5");
        let err = client
            .health_check()
            .await
            .expect_err("a bare family whose :latest is not pulled must fail closed, not pass");
        let msg = err.to_string();
        assert!(
            msg.contains("qwen2.5:latest"),
            "error must name the resolved tag Ollama would look for, got: {msg}"
        );
        assert!(
            msg.contains("qwen2.5:7b"),
            "error must list what IS available so the fix is obvious, got: {msg}"
        );
    }

    #[tokio::test]
    async fn health_check_fails_closed_when_model_is_not_pulled() {
        let (base_url, _hits) = fake_server(vec![ok_json_response(
            "{\"models\":[{\"name\":\"llama3\"}]}",
        )])
        .await;
        let client = OllamaClient::new(base_url, "qwen2.5:7b");
        let err = client
            .health_check()
            .await
            .expect_err("un-pulled model must be a surfaced error, not a silent pass");
        assert!(err.to_string().contains("qwen2.5:7b"));
    }

    #[tokio::test]
    async fn health_check_fails_closed_on_connection_refused() {
        // Bind then immediately drop the listener: the port is real but nothing
        // is listening, so the connect itself fails — the "Ollama isn't running"
        // case this whole client exists to handle without panicking.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind loopback");
        let addr = listener.local_addr().expect("local addr");
        drop(listener);
        let client = OllamaClient::new(format!("http://{addr}"), "qwen2.5:7b");
        let err = client
            .health_check()
            .await
            .expect_err("connection refused must surface as Err, never panic or a fake Ok");
        let msg = err.to_string();
        assert!(
            msg.contains(&addr.to_string()) && msg.contains("HUNTSMAN_OLLAMA_URL"),
            "error must name the unreachable base_url and point at the fix, got: {msg}"
        );
    }

    #[tokio::test]
    async fn health_check_surfaces_a_non_2xx_status() {
        let (base_url, _hits) = fake_server(vec![
            "HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\n\r\n",
        ])
        .await;
        let client = OllamaClient::new(base_url, "qwen2.5:7b");
        let err = client
            .health_check()
            .await
            .expect_err("a 500 from Ollama must be a surfaced error");
        assert!(err.to_string().contains("500"));
    }

    #[tokio::test]
    async fn generate_returns_the_response_field() {
        let (base_url, hits) = fake_server(vec![ok_json_response(
            "{\"response\":\"hello from the model\",\"done\":true}",
        )])
        .await;
        let client = OllamaClient::new(base_url, "qwen2.5:7b");
        let text = client.generate("summarise this").await.expect("generate");
        assert_eq!(text, "hello from the model");
        assert_eq!(hits.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn generate_reports_base_url_when_ollama_is_unreachable() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind loopback");
        let addr = listener.local_addr().expect("local addr");
        drop(listener);
        let client = OllamaClient::new(format!("http://{addr}"), "qwen2.5:7b");
        let err = client
            .generate("x")
            .await
            .expect_err("connection refused must surface as Err");
        let msg = err.to_string();
        assert!(
            msg.contains(&addr.to_string()) && msg.contains("HUNTSMAN_OLLAMA_URL"),
            "error must name the unreachable base_url and point at the fix, got: {msg}"
        );
    }

    #[tokio::test]
    async fn generate_fails_closed_on_malformed_json() {
        let (base_url, _hits) = fake_server(vec![
            "HTTP/1.1 200 OK\r\nContent-Length: 11\r\n\r\nnot json {}",
        ])
        .await;
        let client = OllamaClient::new(base_url, "qwen2.5:7b");
        client
            .generate("x")
            .await
            .expect_err("an unparsable body must be Err, never treated as an empty success");
    }

    #[tokio::test]
    async fn generate_surfaces_a_small_non_2xx_status() {
        // The common case: a 404 with the small model-not-found body Ollama
        // actually returns must surface as an Err naming the status and echoing
        // Ollama's own message.
        let body = "{\"error\":\"model 'gone' not found, try pulling it first\"}";
        let resp = format!(
            "HTTP/1.1 404 Not Found\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        );
        let (base_url, _hits) = fake_server(vec![resp]).await;
        let client = OllamaClient::new(base_url, "gone");
        let err = client
            .generate("x")
            .await
            .expect_err("a 404 from /api/generate must surface as an Err naming the status");
        let msg = err.to_string();
        assert!(
            msg.contains("404"),
            "error must name the HTTP status, got: {msg}"
        );
        assert!(
            msg.contains("not found"),
            "error must carry Ollama's own message snippet, got: {msg}"
        );
    }

    #[tokio::test]
    async fn generate_reports_the_http_status_even_when_the_error_body_exceeds_the_size_cap() {
        // Sensitivity guard for the check ORDER: only a >`MAX_RESPONSE_BYTES`
        // error body distinguishes the two orderings. With the size cap checked
        // first (the old order) this reports "exceeded ... bytes" and buries the
        // real cause; the status must win, so the operator sees the actionable
        // HTTP 503 instead. A small body would pass under either order and prove
        // nothing — hence the deliberately oversized one here.
        let big = "x".repeat(MAX_RESPONSE_BYTES + 100);
        let body = format!("{{\"error\":\"{big}\"}}");
        let resp = format!(
            "HTTP/1.1 503 Service Unavailable\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        );
        let (base_url, _hits) = fake_server(vec![resp]).await;
        let client = OllamaClient::new(base_url, "qwen2.5:7b");
        let err = client
            .generate("x")
            .await
            .expect_err("a 503 must surface even when its body is over the size cap");
        let msg = err.to_string();
        assert!(
            msg.contains("503"),
            "the HTTP status must win over the size cap, got: {msg}"
        );
        assert!(
            !msg.contains("exceeded"),
            "the size-cap message must not mask the real HTTP status, got: {msg}"
        );
    }

    #[test]
    fn resolve_model_tag_appends_latest_only_to_a_bare_name() {
        // A bare family name gets Ollama's implicit `:latest`...
        assert_eq!(resolve_model_tag("qwen2.5"), "qwen2.5:latest");
        // ...while an already-tagged name is used verbatim (no double suffix).
        assert_eq!(resolve_model_tag("qwen2.5:7b"), "qwen2.5:7b");
        assert_eq!(resolve_model_tag("qwen2.5:latest"), "qwen2.5:latest");
    }

    #[tokio::test]
    async fn generate_puts_the_bounded_options_on_the_wire() {
        // Independent of the `generate_body` pure-function test above: this
        // captures the raw HTTP request bytes `generate()` actually sends, so a
        // future refactor that bypassed `generate_body` (and dropped the bound)
        // would still be caught here — the runaway-generation guard must ride
        // the real request, not just a helper's return value.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind loopback");
        let addr = listener.local_addr().expect("local addr");
        let captured = Arc::new(std::sync::Mutex::new(String::new()));
        let captured_srv = Arc::clone(&captured);
        tokio::spawn(async move {
            let Ok((mut sock, _)) = listener.accept().await else {
                return;
            };
            let mut buf = vec![0u8; 65536];
            let n = sock.read(&mut buf).await.unwrap_or(0);
            *captured_srv.lock().unwrap() = String::from_utf8_lossy(&buf[..n]).to_string();
            let body = "{\"response\":\"{}\",\"done\":true}";
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
                body.len()
            );
            let _ = sock.write_all(resp.as_bytes()).await;
            let _ = sock.flush().await;
        });
        let client = OllamaClient::new(format!("http://{addr}"), "qwen2.5:7b");
        client.generate("summarise this").await.expect("generate");

        let req = captured.lock().unwrap().clone();
        assert!(
            req.contains("/api/generate"),
            "must POST to /api/generate, got:\n{req}"
        );
        assert!(
            req.contains("num_predict"),
            "the request must carry the num_predict bound, got:\n{req}"
        );
        assert!(
            req.contains("temperature"),
            "the request must carry the temperature option, got:\n{req}"
        );
    }

    #[test]
    fn generate_body_carries_bounded_json_mode_options() {
        let client = OllamaClient::new("http://127.0.0.1:11434", "qwen2.5:7b");
        let body = client.generate_body("summarise this");
        assert_eq!(body["model"], "qwen2.5:7b");
        assert_eq!(body["prompt"], "summarise this");
        assert_eq!(body["stream"], false);
        assert_eq!(body["format"], "json");
        // The bounded decoding options are what keep a stock model phone-safe
        // and shape-consistent — a missing/unbounded `num_predict` is the
        // runaway-generation defect this test guards against reintroducing.
        assert_eq!(body["options"]["num_predict"], MAX_GENERATION_TOKENS);
        assert!(
            body["options"]["num_predict"]
                .as_i64()
                .is_some_and(|n| n > 0),
            "num_predict must be a positive token bound, not unlimited (-1) or absent"
        );
        assert_eq!(
            body["options"]["temperature"].as_f64(),
            Some(GENERATION_TEMPERATURE),
            "temperature must be pinned low for calibration/shape consistency"
        );
    }

    // Char-boundary-safety of the truncation itself is covered once, at its
    // shared definition (`crate::ai::truncate_chars`'s own tests) — no need
    // to re-test that primitive here.
}
