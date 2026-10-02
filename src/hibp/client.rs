//! Library client for the HIBP API v3 and the Pwned Passwords range API.
//!
//! [`HibpClient`] covers every read endpoint documented at
//! haveibeenpwned.com/API/v3 except the domain-verification and
//! email-sending endpoints, which are deliberately not implemented:
//!
//! | Method | Path | Auth |
//! | --- | --- | --- |
//! | [`HibpClient::breaches`] | `GET /breaches?Domain=&IsSpamList=` | none |
//! | [`HibpClient::breach`] | `GET /breach/{name}` | none |
//! | [`HibpClient::latest_breach`] | `GET /latestbreach` | none |
//! | [`HibpClient::data_classes`] | `GET /dataclasses` | none |
//! | [`HibpClient::breached_account`] | `GET /breachedaccount/{email}` | key |
//! | [`HibpClient::breached_account_range`] | `GET /breachedaccount/range/{6 hex}` | key, k-anon plan |
//! | [`HibpClient::paste_account`] | `GET /pasteaccount/{email}` | key |
//! | [`HibpClient::breached_domain`] | `GET /breacheddomain/{domain}` | key |
//! | [`HibpClient::subscribed_domains`] | `GET /subscribeddomains` | key |
//! | [`HibpClient::subscription_status`] | `GET /subscription/status` | key |
//! | [`HibpClient::stealer_logs_by_email`] | `GET /stealerlogsbyemail/{email}` | key, stealer-log plan |
//! | [`HibpClient::stealer_logs_by_website_domain`] | `GET /stealerlogsbywebsitedomain/{domain}` | key, stealer-log plan |
//! | [`HibpClient::stealer_logs_by_email_domain`] | `GET /stealerlogsbyemaildomain/{domain}` | key, stealer-log plan |
//! | [`HibpClient::pwned_passwords_range`] | `GET api.pwnedpasswords.com/range/{5 hex}` | none |
//!
//! Paths are written lower-case; the docs say every path is case-insensitive.
//!
//! Every request carries a `user-agent` (a missing one is a 403 per the docs)
//! and, when keyed, the `hibp-api-key` header. Keyed calls pass the shared
//! client-side [`RateLimiter`] first (default 10/min). A 429 pauses the limiter
//! for the server's `retry-after` and retries a bounded number of times before
//! returning [`HibpError::RateLimited`]. A 404 on a search endpoint means "not
//! found" and returns `Ok(None)` (or an empty collection).
//!
//! Plan gating: the stealer-log and breached-account-range calls first read
//! `/subscription/status` (cached for the client's life) and return
//! [`HibpError::PlanNotEntitled`] without calling the gated endpoint when the
//! plan lacks `IncludesStealerLogs` / `IncludesKAnon`.

use crate::http::{Request, Response, Transport, TransportConfig, UreqTransport};
use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;

use serde::de::DeserializeOwned;

use super::error::HibpError;
use super::key::ApiKey;
use super::rate_limit::RateLimiter;
use super::types::{
    AccountRangeEntry, BreachModel, BreachedAccountOptions, BreachedDomain, BreachesFilter,
    PasteModel, StealerLogsByEmailDomain, SubscribedDomain, SubscriptionStatus,
};
use super::{passwords, passwords::PasswordHashMode, passwords::RangeEntry};

/// Production base URL of the HIBP v3 API.
pub const HIBP_API_BASE: &str = "https://haveibeenpwned.com/api/v3";
/// Production base URL of the Pwned Passwords API.
pub const PWNED_PASSWORDS_BASE: &str = "https://api.pwnedpasswords.com";
/// The user agent HIBP sees: the app name, version and contact URL.
pub const USER_AGENT: &str = concat!(
    "huntsman-search-engine/",
    env!("CARGO_PKG_VERSION"),
    " (+https://github.com/EmmmmDeee/Huntsman-Search-Engine-HSE-Termux-Android-Aarch64-Rust-)"
);

/// How a keyed request authenticates.
#[derive(Clone, Debug)]
pub enum Auth {
    /// No credential (public endpoints only).
    None,
    /// The classic `hibp-api-key` header.
    ApiKey(ApiKey),
}

/// Client configuration.
#[derive(Clone, Debug)]
pub struct HibpConfig {
    /// v3 base URL (overridable for tests).
    pub api_base: String,
    /// Pwned Passwords base URL (overridable for tests).
    pub passwords_base: String,
    /// User agent sent on every request.
    pub user_agent: String,
    /// Per-request timeout.
    pub timeout: Duration,
    /// How many 429 retries before giving up.
    pub max_429_retries: u8,
    /// Ceiling on any single `retry-after` sleep.
    pub max_retry_after: Duration,
}

impl Default for HibpConfig {
    fn default() -> Self {
        Self {
            api_base: HIBP_API_BASE.to_string(),
            passwords_base: PWNED_PASSWORDS_BASE.to_string(),
            user_agent: USER_AGENT.to_string(),
            timeout: Duration::from_secs(15),
            max_429_retries: 3,
            max_retry_after: Duration::from_secs(60),
        }
    }
}

/// The HIBP client. Cheap to clone.
#[derive(Clone)]
pub struct HibpClient {
    http: Arc<dyn Transport + Send + Sync>,
    auth: Auth,
    config: HibpConfig,
    limiter: Arc<RateLimiter>,
    status: Arc<Mutex<Option<SubscriptionStatus>>>,
}

impl std::fmt::Debug for HibpClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HibpClient")
            .field("auth", &self.auth)
            .field("config", &self.config)
            .field("rate_limit_per_minute", &self.limiter.limit())
            .finish_non_exhaustive()
    }
}

impl HibpClient {
    #[cfg(test)]
    pub(super) fn config_for_tests(&mut self, retries: u8, delay: Duration) {
        self.config.max_429_retries = retries;
        self.config.max_retry_after = delay;
    }
    /// A client over `http` with `auth`, the default config and the shared
    /// process-wide limiter.
    pub fn new(http: Arc<dyn Transport + Send + Sync>, auth: Auth) -> Self {
        Self::with_config(http, auth, HibpConfig::default(), RateLimiter::shared())
    }

    /// A fully specified client.
    pub fn with_config(
        http: Arc<dyn Transport + Send + Sync>,
        auth: Auth,
        config: HibpConfig,
        limiter: Arc<RateLimiter>,
    ) -> Self {
        Self {
            http,
            auth,
            config,
            limiter,
            status: Arc::new(Mutex::new(None)),
        }
    }

    /// Production transport with the configured timeout, byte cap and guarded resolver.
    #[must_use]
    pub fn production(auth: Auth, config: HibpConfig) -> Self {
        let transport = UreqTransport::new(&TransportConfig {
            timeout: config.timeout,
            user_agent: config.user_agent.clone(),
            ..TransportConfig::default()
        });
        Self::with_config(Arc::new(transport), auth, config, RateLimiter::shared())
    }

    /// The configured auth.
    #[must_use]
    pub fn auth(&self) -> &Auth {
        &self.auth
    }

    // ── Breaches (public) ───────────────────────────────────────────────

    /// `GET /breaches`, optionally filtered by domain and spam-list flag.
    pub fn breaches(&self, filter: &BreachesFilter) -> Result<Vec<BreachModel>, HibpError> {
        let mut q = Vec::new();
        if let Some(d) = &filter.domain {
            q.push(("Domain", d.clone()));
        }
        if let Some(s) = filter.is_spam_list {
            q.push(("IsSpamList", s.to_string()));
        }
        let url = self.url("/breaches", &q);
        Ok(self.get_json(&url, false)?.unwrap_or_default())
    }

    /// `GET /breach/{name}`. `Ok(None)` when no breach has that name.
    pub fn breach(&self, name: &str) -> Result<Option<BreachModel>, HibpError> {
        let name = non_empty(name, "breach name")?;
        let url = self.url(&format!("/breach/{}", seg(name)), &[]);
        self.get_json(&url, false)
    }

    /// `GET /latestbreach`.
    pub fn latest_breach(&self) -> Result<Option<BreachModel>, HibpError> {
        let url = self.url("/latestbreach", &[]);
        self.get_json(&url, false)
    }

    /// `GET /dataclasses`.
    pub fn data_classes(&self) -> Result<Vec<String>, HibpError> {
        let url = self.url("/dataclasses", &[]);
        Ok(self.get_json(&url, false)?.unwrap_or_default())
    }

    // ── Accounts and pastes (keyed) ─────────────────────────────────────

    /// `GET /breachedaccount/{email}`. Empty when the address is in no breach
    /// (404). With the API default (`truncate_response: None`) only `Name` is
    /// populated.
    pub fn breached_account(
        &self,
        email: &str,
        opts: &BreachedAccountOptions,
    ) -> Result<Vec<BreachModel>, HibpError> {
        let email = non_empty(email, "email")?;
        let mut q = Vec::new();
        if let Some(t) = opts.truncate_response {
            q.push(("truncateResponse", t.to_string()));
        }
        if let Some(d) = &opts.domain {
            q.push(("domain", d.clone()));
        }
        if let Some(u) = opts.include_unverified {
            q.push(("IncludeUnverified", u.to_string()));
        }
        let url = self.url(&format!("/breachedaccount/{}", seg(email)), &q);
        Ok(self.get_json(&url, true)?.unwrap_or_default())
    }

    /// `GET /breachedaccount/range/{prefix}` with the first 6 hex chars of an
    /// address's SHA-1. Plan-gated on `IncludesKAnon`.
    pub fn breached_account_range(
        &self,
        prefix: &str,
    ) -> Result<Vec<AccountRangeEntry>, HibpError> {
        let prefix = hex_prefix(prefix, 6)?;
        self.require_entitlement(Entitlement::KAnon)?;
        let url = self.url(&format!("/breachedaccount/range/{prefix}"), &[]);
        let entries: Vec<AccountRangeEntry> = self.get_json(&url, true)?.unwrap_or_default();
        if entries.iter().any(|entry| {
            entry.hash_suffix.len() != 34
                || !entry.hash_suffix.bytes().all(|b| b.is_ascii_hexdigit())
        }) {
            return Err(HibpError::Decode("invalid account hash range".into()));
        }
        Ok(entries)
    }

    /// Hash `email` locally (SHA-1 of the trimmed, lower-cased address), query
    /// its 6-char range and return the matching entry's breach names. Every
    /// non-matching entry is discarded at once, as HIBP's terms require.
    pub fn breached_account_by_hash(&self, email: &str) -> Result<Vec<String>, HibpError> {
        non_empty(email, "email")?;
        let hash = account_sha1_hex(email);
        let (prefix, suffix) = hash.split_at(6);
        let entries = self.breached_account_range(prefix)?;
        Ok(entries
            .into_iter()
            .find(|e| e.hash_suffix.eq_ignore_ascii_case(suffix))
            .map(|e| e.websites)
            .unwrap_or_default())
    }

    /// `GET /pasteaccount/{email}`. Empty when there are no pastes (404).
    pub fn paste_account(&self, email: &str) -> Result<Vec<PasteModel>, HibpError> {
        let email = non_empty(email, "email")?;
        let url = self.url(&format!("/pasteaccount/{}", seg(email)), &[]);
        Ok(self.get_json(&url, true)?.unwrap_or_default())
    }

    // ── Domains and subscription (keyed) ────────────────────────────────

    /// `GET /breacheddomain/{domain}` (verified domains only; 403 otherwise).
    pub fn breached_domain(&self, domain: &str) -> Result<BreachedDomain, HibpError> {
        let domain = non_empty(domain, "domain")?;
        let url = self.url(&format!("/breacheddomain/{}", seg(domain)), &[]);
        Ok(self.get_json(&url, true)?.unwrap_or_default())
    }

    /// `GET /subscribeddomains`.
    pub fn subscribed_domains(&self) -> Result<Vec<SubscribedDomain>, HibpError> {
        let url = self.url("/subscribeddomains", &[]);
        Ok(self.get_json(&url, true)?.unwrap_or_default())
    }

    /// `GET /subscription/status`. Not cached; see [`Self::cached_subscription_status`].
    pub fn subscription_status(&self) -> Result<SubscriptionStatus, HibpError> {
        let url = self.url("/subscription/status", &[]);
        self.get_json(&url, true)?
            .ok_or_else(|| HibpError::UnexpectedStatus {
                status: 404,
                body: "subscription status not found".into(),
            })
    }

    /// The subscription status, fetched once per client and reused.
    pub fn cached_subscription_status(&self) -> Result<SubscriptionStatus, HibpError> {
        let mut status = self
            .status
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(value) = &*status {
            return Ok(value.clone());
        }
        let value = self.subscription_status()?;
        *status = Some(value.clone());
        Ok(value)
    }

    // ── Stealer logs (keyed, plan-gated) ────────────────────────────────

    /// `GET /stealerlogsbyemail/{email}`: website domains. Plan-gated.
    pub fn stealer_logs_by_email(&self, email: &str) -> Result<Vec<String>, HibpError> {
        let email = non_empty(email, "email")?;
        self.require_entitlement(Entitlement::StealerLogs)?;
        let url = self.url(&format!("/stealerlogsbyemail/{}", seg(email)), &[]);
        Ok(self.get_json(&url, true)?.unwrap_or_default())
    }

    /// `GET /stealerlogsbywebsitedomain/{domain}`: email addresses. Plan-gated.
    pub fn stealer_logs_by_website_domain(&self, domain: &str) -> Result<Vec<String>, HibpError> {
        let domain = non_empty(domain, "domain")?;
        self.require_entitlement(Entitlement::StealerLogs)?;
        let url = self.url(&format!("/stealerlogsbywebsitedomain/{}", seg(domain)), &[]);
        Ok(self.get_json(&url, true)?.unwrap_or_default())
    }

    /// `GET /stealerlogsbyemaildomain/{domain}`: alias → website domains.
    /// Plan-gated.
    pub fn stealer_logs_by_email_domain(
        &self,
        domain: &str,
    ) -> Result<StealerLogsByEmailDomain, HibpError> {
        let domain = non_empty(domain, "domain")?;
        self.require_entitlement(Entitlement::StealerLogs)?;
        let url = self.url(&format!("/stealerlogsbyemaildomain/{}", seg(domain)), &[]);
        Ok(self.get_json(&url, true)?.unwrap_or_default())
    }

    // ── Pwned Passwords (free, ungated, not rate-limited) ───────────────

    /// `GET {passwords_base}/range/{prefix}` (5 hex chars), SHA-1 or NTLM
    /// (`?mode=ntlm`). With `add_padding` the `Add-Padding: true` header is
    /// sent and the zero-count padding entries are dropped. The API has no
    /// rate limit, so a 429 (from the CDN) is not retried: it returns
    /// [`HibpError::RateLimited`] with the server's `retry-after`.
    pub fn pwned_passwords_range(
        &self,
        prefix: &str,
        mode: PasswordHashMode,
        add_padding: bool,
    ) -> Result<Vec<RangeEntry>, HibpError> {
        let prefix = hex_prefix(prefix, 5)?;
        let mut url = format!("{}/range/{prefix}", self.config.passwords_base);
        if mode == PasswordHashMode::Ntlm {
            url.push_str("?mode=ntlm");
        }
        super::trusted_url(&url)?;
        let mut req = Request::get(&url).header("User-Agent", &self.config.user_agent);
        if add_padding {
            req = req.header("Add-Padding", "true");
        }
        let resp = super::send(self.http.as_ref(), req)?;
        match resp.status {
            200 => passwords::parse_range(&resp.body, mode, add_padding),
            429 => Err(HibpError::RateLimited {
                retry_after: retry_after(&resp),
            }),
            status => Err(Self::classify(status)),
        }
    }

    /// Hash `password` locally and look it up in its range. Returns how many
    /// times it appears in Pwned Passwords (0 = not found). Only the 5-char
    /// prefix leaves the process; padding is always requested.
    pub fn check_password(&self, password: &str, mode: PasswordHashMode) -> Result<u64, HibpError> {
        let hash = passwords::hash_password(password, mode);
        let (prefix, suffix) = hash.split_at(5);
        let count = self
            .pwned_passwords_range(prefix, mode, true)
            .map(|entries| passwords::count_for(&entries, suffix));
        passwords::wipe(hash.into_bytes());
        count
    }

    // ── Internals ───────────────────────────────────────────────────────

    fn require_entitlement(&self, which: Entitlement) -> Result<(), HibpError> {
        let status = self.cached_subscription_status()?;
        let (ok, feature) = match which {
            Entitlement::StealerLogs => (status.includes_stealer_logs, "stealer logs"),
            Entitlement::KAnon => (
                status.includes_k_anon,
                "k-anonymity breached-account range search",
            ),
        };
        if ok == Some(true) {
            Ok(())
        } else {
            Err(HibpError::PlanNotEntitled {
                plan: "configured subscription".into(),
                feature,
            })
        }
    }

    fn url(&self, path: &str, query: &[(&str, String)]) -> String {
        let mut url = format!("{}{path}", self.config.api_base);
        if !query.is_empty() {
            url.push('?');
            let qs: Vec<String> = query
                .iter()
                .map(|(k, v)| format!("{k}={}", super::encode(v)))
                .collect();
            url.push_str(&qs.join("&"));
        }
        url
    }

    /// GET a JSON endpoint. `keyed` requests need auth and pass the limiter.
    /// `Ok(None)` on 404.
    fn get_json<T: DeserializeOwned>(
        &self,
        url: &str,
        keyed: bool,
    ) -> Result<Option<T>, HibpError> {
        super::trusted_url(url)?;
        if crate::http::origin_of(url).as_deref() != Some("https://haveibeenpwned.com:443") {
            return Err(HibpError::InvalidInput("untrusted HIBP origin".into()));
        }
        let key = match (&self.auth, keyed) {
            (Auth::ApiKey(k), true) => Some(k),
            (Auth::None, true) => return Err(HibpError::MissingKey),
            (_, false) => None,
        };
        let mut retries = 0u8;
        loop {
            if keyed {
                self.limiter.acquire();
            }
            let mut req = Request::get(url)
                .header("User-Agent", &self.config.user_agent)
                .header("Accept", "application/json");
            if let Some(k) = key {
                req = req.header("hibp-api-key", k.expose());
            }
            let resp = super::send(self.http.as_ref(), req)?;
            let status = resp.status;
            if status == 429 {
                let retry_after = retry_after(&resp);
                let wait = retry_after.unwrap_or(Duration::from_secs(2));
                self.limiter.block_for(wait)?;
                if wait <= self.config.max_retry_after && retries < self.config.max_429_retries {
                    retries += 1;
                    if !keyed {
                        std::thread::sleep(wait);
                    }
                    continue;
                }
                return Err(HibpError::RateLimited { retry_after });
            }
            return match status {
                200 => serde_json::from_slice(&resp.body)
                    .map(Some)
                    .map_err(|_| HibpError::Decode("invalid response shape".into())),
                404 => Ok(None),
                _ => Err(Self::classify(status)),
            };
        }
    }

    fn classify(status: u16) -> HibpError {
        let text = "upstream response omitted".into();
        match status {
            400 => HibpError::BadRequest(text),
            401 => HibpError::Unauthorized(text),
            403 => HibpError::Forbidden(text),
            500..=599 => HibpError::Server { status, body: text },
            _ => HibpError::UnexpectedStatus { status, body: text },
        }
    }
}

#[derive(Clone, Copy)]
enum Entitlement {
    StealerLogs,
    KAnon,
}

/// SHA-1 (upper-case hex) of a trimmed, lower-cased email address, as the
/// breached-account range search expects.
#[must_use]
pub fn account_sha1_hex(email: &str) -> String {
    let norm = email.trim().to_lowercase();
    passwords::sha1_hex(norm.as_bytes())
}

/// A 429's `retry-after` in whole seconds, when the server sent one.
fn retry_after(resp: &Response) -> Option<Duration> {
    resp.header_value("retry-after")
        .and_then(|s| s.trim().parse::<u64>().ok())
        .map(Duration::from_secs)
}

fn seg(s: &str) -> String {
    super::encode(s.trim())
}

fn non_empty<'a>(s: &'a str, what: &str) -> Result<&'a str, HibpError> {
    let t = s.trim();
    if t.is_empty() {
        Err(HibpError::InvalidInput(format!("{what} is empty")))
    } else {
        Ok(t)
    }
}

fn hex_prefix(p: &str, len: usize) -> Result<String, HibpError> {
    let p = p.trim();
    if p.len() == len && p.chars().all(|c| c.is_ascii_hexdigit()) {
        Ok(p.to_ascii_uppercase())
    } else {
        Err(HibpError::InvalidInput(format!(
            "prefix must be exactly {len} hex characters"
        )))
    }
}
