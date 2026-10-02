//! OAuth 2.0 authorization code + PKCE for HIBP, as a library flow.
//!
//! Source of truth: `https://haveibeenpwned.com/auth.md` and the metadata at
//! `https://haveibeenpwned.com/.well-known/oauth-authorization-server`.
//! This port is tested offline, not live-verified. The implemented contract:
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

use crate::http::{Request, Transport};
use serde::{Deserialize, Serialize};

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
        random_bytes(&mut bytes)?;
        Ok(Self::from_verifier(&b64url(&bytes)))
    }

    /// Build from an existing verifier (RFC 7636 test vectors, or a stored
    /// in-flight authorization).
    #[must_use]
    pub fn from_verifier(verifier: &str) -> Self {
        let challenge = b64url(&crate::sha256::sha256(verifier.as_bytes()));
        Self {
            verifier: verifier.to_string(),
            challenge,
        }
    }

    /// The verifier, sent only to the token endpoint.
    #[must_use]
    pub fn verifier(&self) -> &str {
        &self.verifier
    }

    /// The S256 challenge, sent in the authorization URL.
    #[must_use]
    pub fn challenge(&self) -> &str {
        &self.challenge
    }

    /// Always `S256`.
    #[must_use]
    pub fn method(&self) -> &'static str {
        "S256"
    }
}

/// A random `state` value for CSRF protection.
pub fn random_state() -> Result<String, HibpError> {
    let mut bytes = [0u8; 16];
    random_bytes(&mut bytes)?;
    Ok(b64url(&bytes))
}

fn b64url(bytes: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let a = chunk[0];
        let b = chunk.get(1).copied().unwrap_or(0);
        let c = chunk.get(2).copied().unwrap_or(0);
        out.push(char::from(TABLE[usize::from(a >> 2)]));
        out.push(char::from(TABLE[usize::from(((a & 3) << 4) | (b >> 4))]));
        if chunk.len() > 1 {
            out.push(char::from(TABLE[usize::from(((b & 15) << 2) | (c >> 6))]));
        }
        if chunk.len() > 2 {
            out.push(char::from(TABLE[usize::from(c & 63)]));
        }
    }
    out
}

fn random_bytes(bytes: &mut [u8]) -> Result<(), HibpError> {
    use std::io::Read;
    std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(bytes))
        .map_err(|_| HibpError::OAuth("OS randomness unavailable".into()))
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
    /// `OpenID` Connect ID token.
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
            .field("expires_in", &self.expires_in)
            .field("refresh_token", &r(&self.refresh_token))
            .field("id_token", &r(&self.id_token))
            .field("expires_at", &self.expires_at)
            .finish_non_exhaustive()
    }
}

impl TokenSet {
    /// Whether the access token expires within `skew_secs` of `now_unix`.
    #[must_use]
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
        let mut g = self
            .0
            .lock()
            .map_err(|_| HibpError::OAuth("token store lock".into()))?;
        *g = Some(tokens.clone());
        Ok(())
    }
    fn clear(&self) -> Result<(), HibpError> {
        let mut g = self
            .0
            .lock()
            .map_err(|_| HibpError::OAuth("token store lock".into()))?;
        *g = None;
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
    #[must_use]
    pub fn new(path: PathBuf) -> Self {
        Self { path }
    }

    /// `~/.config/hibp/oauth_tokens.json`, when `HOME` is set.
    #[must_use]
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
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if std::fs::metadata(&self.path).ok()?.permissions().mode() & 0o077 != 0 {
                return None;
            }
        }
        let text = crate::fsio::read_bounded(&self.path, 65536).ok()?;
        serde_json::from_slice(&text).ok()
    }

    fn save(&self, tokens: &TokenSet) -> Result<(), HibpError> {
        let json = serde_json::to_vec(tokens)
            .map_err(|_| HibpError::OAuth("token encode failed".into()))?;
        crate::fsio::write_atomic_private(&self.path, &json, 65536)
            .map_err(|_| HibpError::OAuth("token store write failed".into()))
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
pub fn discover(http: &dyn Transport, metadata_url: &str) -> Result<AuthServerMetadata, HibpError> {
    endpoint(metadata_url)?;
    let meta = json_or_error(super::send(
        http,
        Request::get(metadata_url)
            .header("User-Agent", USER_AGENT)
            .header("Accept", "application/json"),
    )?)?;
    validate_metadata(&meta)?;
    Ok(meta)
}

/// Register a public client (no secret) at `registration_endpoint`.
pub fn register_client(
    http: &dyn Transport,
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
    endpoint(registration_endpoint)?;
    let body = serde_json::to_vec(&body)
        .map_err(|_| HibpError::OAuth("registration encode failed".into()))?;
    json_or_error(super::send(
        http,
        Request::post(registration_endpoint, body)
            .header("User-Agent", USER_AGENT)
            .header("Content-Type", "application/json"),
    )?)
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
    validate_metadata(meta)?;
    validate_pkce(pkce)?;
    if state.is_empty() {
        return Err(HibpError::OAuth("state required".into()));
    }
    let mut url = meta.authorization_endpoint.clone();
    for (name, value) in [
        ("response_type", "code"),
        ("client_id", client_id),
        ("redirect_uri", redirect_uri),
        ("scope", SCOPES),
        ("resource", RESOURCE),
        ("code_challenge", pkce.challenge()),
        ("code_challenge_method", pkce.method()),
        ("state", state),
    ] {
        url = crate::http::append_query_param(&url, name, value);
    }
    Ok(url)
}

/// Exchange an authorization `code` for tokens.
#[allow(clippy::too_many_arguments)]
pub fn exchange_code(
    http: &dyn Transport,
    meta: &AuthServerMetadata,
    client_id: &str,
    redirect_uri: &str,
    code: &str,
    pkce: &Pkce,
    now_unix: u64,
) -> Result<TokenSet, HibpError> {
    validate_metadata(meta)?;
    validate_pkce(pkce)?;
    let form = [
        ("grant_type", "authorization_code"),
        ("client_id", client_id),
        ("code", code),
        ("redirect_uri", redirect_uri),
        ("code_verifier", pkce.verifier()),
    ];
    token_request(http, &meta.token_endpoint, &form).map(|t| t.stamp(now_unix))
}

/// Trade a refresh token for new tokens. Keeps the old refresh token when the
/// server does not rotate it.
pub fn refresh(
    http: &dyn Transport,
    meta: &AuthServerMetadata,
    client_id: &str,
    refresh_token: &str,
    now_unix: u64,
) -> Result<TokenSet, HibpError> {
    validate_metadata(meta)?;
    let form = [
        ("grant_type", "refresh_token"),
        ("client_id", client_id),
        ("refresh_token", refresh_token),
    ];
    let mut t = token_request(http, &meta.token_endpoint, &form)?.stamp(now_unix);
    if t.refresh_token.is_none() {
        t.refresh_token = Some(refresh_token.to_string());
    }
    Ok(t)
}

fn token_request(
    http: &dyn Transport,
    endpoint: &str,
    form: &[(&str, &str)],
) -> Result<TokenSet, HibpError> {
    self::endpoint(endpoint)?;
    let body = form
        .iter()
        .map(|(k, v)| format!("{}={}", super::encode(k), super::encode(v)))
        .collect::<Vec<_>>()
        .join("&");
    let tokens: TokenSet = json_or_error(super::send(
        http,
        Request::post(endpoint, body.into_bytes())
            .header("User-Agent", USER_AGENT)
            .header("Content-Type", "application/x-www-form-urlencoded"),
    )?)?;
    crate::keys::Secret::new(&tokens.access_token)
        .map_err(|_| HibpError::OAuth("invalid access token".into()))?;
    Ok(tokens)
}

fn json_or_error<T: serde::de::DeserializeOwned>(
    resp: crate::http::Response,
) -> Result<T, HibpError> {
    let status = resp.status;
    if (200..300).contains(&status) {
        return serde_json::from_reader(std::io::Cursor::new(resp.body))
            .map_err(|_| HibpError::Decode("invalid OAuth response".into()));
    }
    Err(HibpError::OAuth(format!("HTTP {status} (body omitted)")))
}

fn endpoint(url: &str) -> Result<(), HibpError> {
    super::trusted_url(url)?;
    if crate::http::origin_of(url).as_deref() != Some("https://haveibeenpwned.com:443") {
        return Err(HibpError::OAuth("untrusted authorization server".into()));
    }
    Ok(())
}

fn validate_metadata(meta: &AuthServerMetadata) -> Result<(), HibpError> {
    endpoint(&meta.issuer)?;
    endpoint(&meta.authorization_endpoint)?;
    endpoint(&meta.token_endpoint)?;
    if let Some(url) = &meta.registration_endpoint {
        endpoint(url)?;
    }
    if !meta
        .code_challenge_methods_supported
        .iter()
        .any(|m| m == "S256")
    {
        return Err(HibpError::OAuth("S256 support required".into()));
    }
    Ok(())
}

fn validate_pkce(pkce: &Pkce) -> Result<(), HibpError> {
    let value = pkce.verifier();
    if !(43..=128).contains(&value.len())
        || !value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~'))
    {
        return Err(HibpError::OAuth("invalid PKCE verifier".into()));
    }
    Ok(())
}
