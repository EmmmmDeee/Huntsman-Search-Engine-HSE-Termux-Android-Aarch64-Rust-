//! OAuth 2.0 authorization code + PKCE for HIBP, as a library flow.
//!
//! Source of truth: `https://haveibeenpwned.com/auth.md` and the metadata at
//! `https://haveibeenpwned.com/.well-known/oauth-authorization-server` (both
//! read 2026-10-02). What they say, and what this implements:
//!
//! * Discovery: [`discover`] reads the authorization-server metadata
//!   (`authorization_endpoint`, `token_endpoint`, `registration_endpoint`).
//! * Public client, no secret: [`register_client`] POSTs to
//!   `/connect/register` with `token_endpoint_auth_method: "none"` and the
//!   `authorization_code` + `refresh_token` grants; HIBP returns a `client_id`.
//!   "Client secrets are not supported."
//! * PKCE S256 is required: [`Pkce::generate`] makes a 43-char verifier from 32
//!   random bytes and its `BASE64URL(SHA256(verifier))` challenge (RFC 7636).
//! * [`authorization_url`] adds `scope=openid offline_access hibp.mcp` (all
//!   three are required) and `resource=https://haveibeenpwned.com/mcp`.
//! * [`exchange_code`] and [`refresh`] POST form bodies to `/connect/token`.
//!
//! The user must sign in and consent in a browser; this module only builds the
//! URL and handles the codes and tokens. Tokens are kept in a [`TokenStore`].
//!
//! Scope of the token: HIBP documents it as a bearer token for the MCP
//! resource `https://haveibeenpwned.com/mcp`. The REST v3 API documents only
//! the `hibp-api-key` header; whether REST v3 accepts this bearer token is NOT
//! documented and has not been verified, so [`super::client::HibpClient`]
//! keeps the API key as its REST auth.

use std::fmt;
use std::path::PathBuf;

use base64::Engine as _;
use serde::{Deserialize, Serialize};
use sha2::Digest as _;

use super::client::USER_AGENT;
use super::error::HibpError;
use super::key::REDACTED;

/// HIBP's authorization-server metadata URL.
pub const METADATA_URL: &str = "https://haveibeenpwned.com/.well-known/oauth-authorization-server";
/// HIBP's dynamic client registration endpoint.
pub const REGISTRATION_URL: &str = "https://haveibeenpwned.com/connect/register";
/// The protected resource tokens are issued for.
pub const RESOURCE: &str = "https://haveibeenpwned.com/mcp";
/// The HIBP scope.
pub const SCOPE_HIBP: &str = "hibp.mcp";
/// The full scope string auth.md requires.
pub const SCOPES: &str = "openid offline_access hibp.mcp";

/// Authorization-server metadata (RFC 8414), the fields used here.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthServerMetadata {
    /// Issuer identifier.
    pub issuer: String,
    /// Where the user is sent to authorize.
    pub authorization_endpoint: String,
    /// Where codes and refresh tokens are exchanged.
    pub token_endpoint: String,
    /// Dynamic client registration endpoint.
    #[serde(default)]
    pub registration_endpoint: Option<String>,
    /// Supported scopes.
    #[serde(default)]
    pub scopes_supported: Vec<String>,
    /// Supported PKCE methods.
    #[serde(default)]
    pub code_challenge_methods_supported: Vec<String>,
    /// Supported token endpoint auth methods.
    #[serde(default)]
    pub token_endpoint_auth_methods_supported: Vec<String>,
}

/// A registered public client.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegisteredClient {
    /// The issued client id.
    pub client_id: String,
    /// Redirect URIs the client registered.
    #[serde(default)]
    pub redirect_uris: Vec<String>,
}

/// A PKCE verifier and its S256 challenge.
#[derive(Clone)]
pub struct Pkce {
    verifier: String,
    challenge: String,
}

impl fmt::Debug for Pkce {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Pkce")
            .field("verifier", &REDACTED)
            .field("challenge", &self.challenge)
            .finish()
    }
}

impl Pkce {
    /// A fresh verifier from 32 OS-random bytes (43 base64url chars).
    pub fn generate() -> Result<Self, HibpError> {
        let mut bytes = [0u8; 32];
        getrandom::fill(&mut bytes)
            .map_err(|e| HibpError::OAuth(format!("no OS randomness: {e}")))?;
        Ok(Self::from_verifier(&b64url(&bytes)))
    }

    /// Build from an existing verifier (RFC 7636 test vectors, or a stored
    /// in-flight authorization).
    pub fn from_verifier(verifier: &str) -> Self {
        let challenge = b64url(&sha2::Sha256::digest(verifier.as_bytes()));
        Self {
            verifier: verifier.to_string(),
            challenge,
        }
    }

    /// The verifier, sent only to the token endpoint.
    pub fn verifier(&self) -> &str {
        &self.verifier
    }

    /// The S256 challenge, sent in the authorization URL.
    pub fn challenge(&self) -> &str {
        &self.challenge
    }

    /// Always `S256`.
    pub fn method(&self) -> &'static str {
        "S256"
    }
}

/// A random `state` value for CSRF protection.
pub fn random_state() -> Result<String, HibpError> {
    let mut bytes = [0u8; 16];
    getrandom::fill(&mut bytes).map_err(|e| HibpError::OAuth(format!("no OS randomness: {e}")))?;
    Ok(b64url(&bytes))
}

fn b64url(bytes: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

/// The token endpoint's answer. `Debug` redacts every token.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenSet {
    /// Bearer access token.
    pub access_token: String,
    /// Usually `Bearer`.
    #[serde(default)]
    pub token_type: Option<String>,
    /// Lifetime in seconds.
    #[serde(default)]
    pub expires_in: Option<u64>,
    /// Refresh token (issued with `offline_access`).
    #[serde(default)]
    pub refresh_token: Option<String>,
    /// Granted scopes.
    #[serde(default)]
    pub scope: Option<String>,
    /// OpenID Connect ID token.
    #[serde(default)]
    pub id_token: Option<String>,
    /// Unix seconds when the access token expires (set locally).
    #[serde(default)]
    pub expires_at: Option<u64>,
}

impl fmt::Debug for TokenSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let r = |o: &Option<String>| o.as_ref().map(|_| REDACTED);
        f.debug_struct("TokenSet")
            .field("access_token", &REDACTED)
            .field("token_type", &self.token_type)
            .field("expires_in", &self.expires_in)
            .field("refresh_token", &r(&self.refresh_token))
            .field("scope", &self.scope)
            .field("id_token", &r(&self.id_token))
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

impl TokenSet {
    /// Whether the access token expires within `skew_secs` of `now_unix`.
    pub fn is_expired(&self, now_unix: u64, skew_secs: u64) -> bool {
        self.expires_at
            .is_some_and(|at| now_unix.saturating_add(skew_secs) >= at)
    }

    fn stamp(mut self, now_unix: u64) -> Self {
        self.expires_at = self.expires_in.map(|s| now_unix.saturating_add(s));
        self
    }
}

/// Where OAuth tokens persist between runs.
pub trait TokenStore: Send + Sync {
    /// The stored tokens, if any.
    fn load(&self) -> Option<TokenSet>;
    /// Replace the stored tokens.
    fn save(&self, tokens: &TokenSet) -> Result<(), HibpError>;
    /// Forget the stored tokens.
    fn clear(&self) -> Result<(), HibpError>;
}

/// In-memory store (tests, or short-lived processes).
#[derive(Default)]
pub struct MemoryTokenStore(std::sync::Mutex<Option<TokenSet>>);

impl TokenStore for MemoryTokenStore {
    fn load(&self) -> Option<TokenSet> {
        self.0.lock().ok()?.clone()
    }
    fn save(&self, tokens: &TokenSet) -> Result<(), HibpError> {
        if let Ok(mut g) = self.0.lock() {
            *g = Some(tokens.clone());
        }
        Ok(())
    }
    fn clear(&self) -> Result<(), HibpError> {
        if let Ok(mut g) = self.0.lock() {
            *g = None;
        }
        Ok(())
    }
}

/// A JSON file store, written with mode 600 on Unix. Default path:
/// `~/.config/hibp/oauth_tokens.json`.
pub struct FileTokenStore {
    path: PathBuf,
}

impl FileTokenStore {
    /// A store at `path`.
    pub fn new(path: PathBuf) -> Self {
        Self { path }
    }

    /// `~/.config/hibp/oauth_tokens.json`, when `HOME` is set.
    pub fn default_path() -> Option<PathBuf> {
        Some(
            PathBuf::from(std::env::var_os("HOME")?)
                .join(".config")
                .join("hibp")
                .join("oauth_tokens.json"),
        )
    }
}

impl TokenStore for FileTokenStore {
    fn load(&self) -> Option<TokenSet> {
        let text = std::fs::read_to_string(&self.path).ok()?;
        serde_json::from_str(&text).ok()
    }

    fn save(&self, tokens: &TokenSet) -> Result<(), HibpError> {
        let io = |e: std::io::Error| HibpError::OAuth(format!("token store: {}", e.kind()));
        if let Some(dir) = self.path.parent() {
            std::fs::create_dir_all(dir).map_err(io)?;
        }
        let json = serde_json::to_string(tokens).map_err(|e| HibpError::OAuth(e.to_string()))?;
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        use std::io::Write as _;
        let mut f = opts.open(&self.path).map_err(io)?;
        f.write_all(json.as_bytes()).map_err(io)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&self.path, std::fs::Permissions::from_mode(0o600))
                .map_err(io)?;
        }
        Ok(())
    }

    fn clear(&self) -> Result<(), HibpError> {
        match std::fs::remove_file(&self.path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(HibpError::OAuth(format!("token store: {}", e.kind()))),
        }
    }
}

/// `GET` the authorization-server metadata at `metadata_url`
/// ([`METADATA_URL`] in production).
pub async fn discover(
    http: &reqwest::Client,
    metadata_url: &str,
) -> Result<AuthServerMetadata, HibpError> {
    let resp = http
        .get(metadata_url)
        .header(reqwest::header::USER_AGENT, USER_AGENT)
        .header(reqwest::header::ACCEPT, "application/json")
        .send()
        .await
        .map_err(|_| HibpError::Transport("metadata request failed".into()))?;
    json_or_error(resp).await
}

/// Register a public client (no secret) at `registration_endpoint`.
pub async fn register_client(
    http: &reqwest::Client,
    registration_endpoint: &str,
    client_name: &str,
    redirect_uris: &[String],
) -> Result<RegisteredClient, HibpError> {
    let body = serde_json::json!({
        "client_name": client_name,
        "redirect_uris": redirect_uris,
        "grant_types": ["authorization_code", "refresh_token"],
        "response_types": ["code"],
        "token_endpoint_auth_method": "none",
    });
    let resp = http
        .post(registration_endpoint)
        .header(reqwest::header::USER_AGENT, USER_AGENT)
        .json(&body)
        .send()
        .await
        .map_err(|_| HibpError::Transport("registration request failed".into()))?;
    json_or_error(resp).await
}

/// The URL to send the user to. Carries `response_type=code`, the client id,
/// redirect URI, [`SCOPES`], [`RESOURCE`], the S256 challenge and `state`.
pub fn authorization_url(
    meta: &AuthServerMetadata,
    client_id: &str,
    redirect_uri: &str,
    pkce: &Pkce,
    state: &str,
) -> Result<String, HibpError> {
    let mut url = url::Url::parse(&meta.authorization_endpoint)
        .map_err(|e| HibpError::OAuth(format!("bad authorization_endpoint: {e}")))?;
    url.query_pairs_mut()
        .append_pair("response_type", "code")
        .append_pair("client_id", client_id)
        .append_pair("redirect_uri", redirect_uri)
        .append_pair("scope", SCOPES)
        .append_pair("resource", RESOURCE)
        .append_pair("code_challenge", pkce.challenge())
        .append_pair("code_challenge_method", pkce.method())
        .append_pair("state", state);
    Ok(url.into())
}

/// Exchange an authorization `code` for tokens.
pub async fn exchange_code(
    http: &reqwest::Client,
    meta: &AuthServerMetadata,
    client_id: &str,
    redirect_uri: &str,
    code: &str,
    pkce: &Pkce,
    now_unix: u64,
) -> Result<TokenSet, HibpError> {
    let form = [
        ("grant_type", "authorization_code"),
        ("client_id", client_id),
        ("code", code),
        ("redirect_uri", redirect_uri),
        ("code_verifier", pkce.verifier()),
    ];
    token_request(http, &meta.token_endpoint, &form)
        .await
        .map(|t| t.stamp(now_unix))
}

/// Trade a refresh token for new tokens. Keeps the old refresh token when the
/// server does not rotate it.
pub async fn refresh(
    http: &reqwest::Client,
    meta: &AuthServerMetadata,
    client_id: &str,
    refresh_token: &str,
    now_unix: u64,
) -> Result<TokenSet, HibpError> {
    let form = [
        ("grant_type", "refresh_token"),
        ("client_id", client_id),
        ("refresh_token", refresh_token),
    ];
    let mut t = token_request(http, &meta.token_endpoint, &form)
        .await?
        .stamp(now_unix);
    if t.refresh_token.is_none() {
        t.refresh_token = Some(refresh_token.to_string());
    }
    Ok(t)
}

async fn token_request(
    http: &reqwest::Client,
    endpoint: &str,
    form: &[(&str, &str)],
) -> Result<TokenSet, HibpError> {
    let body: String = url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs(form.iter().copied())
        .finish();
    let resp = http
        .post(endpoint)
        .header(reqwest::header::USER_AGENT, USER_AGENT)
        .header(
            reqwest::header::CONTENT_TYPE,
            "application/x-www-form-urlencoded",
        )
        .body(body)
        .send()
        .await
        .map_err(|_| HibpError::Transport("token request failed".into()))?;
    json_or_error(resp).await
}

async fn json_or_error<T: serde::de::DeserializeOwned>(
    resp: reqwest::Response,
) -> Result<T, HibpError> {
    let status = resp.status().as_u16();
    let text = resp
        .text()
        .await
        .map_err(|_| HibpError::Transport("body read failed".into()))?;
    if (200..300).contains(&status) {
        return serde_json::from_str(&text).map_err(|e| HibpError::Decode(e.to_string()));
    }
    // OAuth error bodies are `{"error": "...", "error_description": "..."}`;
    // surface only those two fields, never the raw body (it could echo a code).
    #[derive(Deserialize)]
    struct OAuthErr {
        error: Option<String>,
        error_description: Option<String>,
    }
    let detail = serde_json::from_str::<OAuthErr>(&text)
        .ok()
        .map(|e| {
            format!(
                "{} {}",
                e.error.unwrap_or_default(),
                e.error_description.unwrap_or_default()
            )
            .trim()
            .to_string()
        })
        .unwrap_or_default();
    Err(HibpError::OAuth(format!("HTTP {status}: {detail}")))
}
