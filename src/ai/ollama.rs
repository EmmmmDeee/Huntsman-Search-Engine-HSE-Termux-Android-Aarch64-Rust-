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

/// Module tag used for error attribution (`Error::module("ai_daemon", ...)`),
/// matching how every OSINT module names itself in a surfaced error.
const SRC: &str = "ai_daemon";

/// A response body larger than this is refused rather than buffered — mirrors
/// the size discipline `crate::util::http` already applies to every other
/// network call site (see `JSON_BODY_CAP`), scaled down: a scan-analysis
/// response is a short summary + a handful of findings, not a bulk export.
const MAX_RESPONSE_BYTES: usize = 1_000_000;

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

    #[must_use]
    pub fn model(&self) -> &str {
        &self.model
    }

    /// `GET /api/tags` — the cheapest possible reachability probe, and it also
    /// confirms `model` has actually been pulled, so a typo'd model name fails
    /// here with a clear, attributable message instead of surfacing as an
    /// opaque error from the first real [`generate`](Self::generate) call.
    ///
    /// Ollama's tag names carry an implicit `:latest` suffix when a caller
    /// configured a bare model family (e.g. `"qwen2.5"` matching the served tag
    /// `"qwen2.5:latest"`), so the match accepts either an exact tag match or a
    /// configured name that is a prefix of a served tag up to `:`.
    pub async fn health_check(&self) -> Result<()> {
        let url = format!("{}/api/tags", self.base_url);
        let resp = self.http.get(&url).send().await?;
        let status = resp.status();
        let text = read_text(SRC, resp).await?;
        if !status.is_success() {
            return Err(Error::module(
                SRC,
                format!("Ollama /api/tags returned HTTP {status}: {}", truncate(&text)),
            ));
        }
        let tags: TagsResponse = serde_json::from_str(&text)?;
        let served: Vec<&str> = tags.models.iter().map(|m| m.name.as_str()).collect();
        let matches = served
            .iter()
            .any(|tag| *tag == self.model || tag.split(':').next() == Some(self.model.as_str()));
        if !matches {
            return Err(Error::module(
                SRC,
                format!(
                    "model '{}' is not pulled in this Ollama instance (available: {})",
                    self.model,
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

    /// `POST /api/generate` with `stream: false`, returning the model's raw
    /// text response. Does not itself impose a timeout — an LLM generation can
    /// legitimately take anywhere from seconds to minutes depending on the
    /// model and hardware, so the caller wraps this in a `tokio::time::timeout`
    /// sized for its own context (see `analysis::analyze_scan`).
    pub async fn generate(&self, prompt: &str) -> Result<String> {
        let url = format!("{}/api/generate", self.base_url);
        let body = serde_json::json!({
            "model": self.model,
            "prompt": prompt,
            "stream": false,
        });
        let resp = self.http.post(&url).json(&body).send().await?;
        let status = resp.status();
        let text = read_text(SRC, resp).await?;
        if text.len() > MAX_RESPONSE_BYTES {
            return Err(Error::module(
                SRC,
                format!(
                    "Ollama response exceeded {MAX_RESPONSE_BYTES} bytes ({} read)",
                    text.len()
                ),
            ));
        }
        if !status.is_success() {
            return Err(Error::module(
                SRC,
                format!("Ollama /api/generate returned HTTP {status}: {}", truncate(&text)),
            ));
        }
        let parsed: GenerateResponse = serde_json::from_str(&text)?;
        Ok(parsed.response)
    }
}

/// A response/error body is arbitrary upstream text — truncate on a `char`
/// boundary (never a byte index) before it reaches a log line or a surfaced
/// `Error`, mirroring `crate::util::http`'s own `key_tail` discipline.
fn truncate(s: &str) -> String {
    const MAX_CHARS: usize = 300;
    match s.char_indices().nth(MAX_CHARS) {
        Some((idx, _)) => format!("{}…", &s[..idx]),
        None => s.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// Bind an ephemeral loopback listener and hand back its address plus a
    /// handle to the spawned task that will serve exactly one raw HTTP/1.1
    /// response per connection, in order. Mirrors the loopback-listener test
    /// pattern used throughout `src/modules/*/tests.rs` (e.g. `domainsdb::tests`).
    async fn fake_server(responses: Vec<&'static str>) -> (String, Arc<AtomicU32>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind loopback");
        let addr = listener.local_addr().expect("local addr");
        let hits = Arc::new(AtomicU32::new(0));
        let hits_srv = Arc::clone(&hits);
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

    #[tokio::test]
    async fn health_check_accepts_an_exact_tag_match() {
        let (base_url, _hits) = fake_server(vec![
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 45\r\n\r\n{\"models\":[{\"name\":\"qwen2.5:7b\"},{\"name\":\"x\"}]}",
        ])
        .await;
        let client = OllamaClient::new(base_url, "qwen2.5:7b");
        client.health_check().await.expect("model is listed exactly");
    }

    #[tokio::test]
    async fn health_check_accepts_a_family_prefix_match() {
        let (base_url, _hits) = fake_server(vec![
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 31\r\n\r\n{\"models\":[{\"name\":\"qwen2.5:latest\"}]}",
        ])
        .await;
        let client = OllamaClient::new(base_url, "qwen2.5");
        client
            .health_check()
            .await
            .expect("bare family name matches a tagged variant");
    }

    #[tokio::test]
    async fn health_check_fails_closed_when_model_is_not_pulled() {
        let (base_url, _hits) = fake_server(vec![
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 20\r\n\r\n{\"models\":[{\"name\":\"llama3\"}]}",
        ])
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
        client
            .health_check()
            .await
            .expect_err("connection refused must surface as Err, never panic or a fake Ok");
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
        let body = "{\"response\":\"hello from the model\",\"done\":true}";
        let (base_url, hits) = fake_server(vec![&format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        )])
        .await;
        let client = OllamaClient::new(base_url, "qwen2.5:7b");
        let text = client.generate("summarise this").await.expect("generate");
        assert_eq!(text, "hello from the model");
        assert_eq!(hits.load(Ordering::SeqCst), 1);
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

    #[test]
    fn truncate_is_char_boundary_safe_on_multibyte_text() {
        // 400 repeated multi-byte characters — truncating at a raw byte index
        // near the 300-char cut would land mid-codepoint and panic.
        let s = "é".repeat(400);
        let t = truncate(&s);
        assert!(t.ends_with('…'));
        assert!(t.chars().count() <= 301);
    }

    #[test]
    fn truncate_leaves_a_short_string_untouched() {
        assert_eq!(truncate("short"), "short");
    }
}
