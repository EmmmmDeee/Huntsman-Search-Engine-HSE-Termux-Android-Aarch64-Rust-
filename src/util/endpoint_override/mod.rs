//! Safe resolution of the operator's base-URL override env vars
//! (`HUNTSMAN_OATHNET_BASE`, `HUNTSMAN_SEEKNOW_BASE`).
//!
//! Both feed the [`crate::util::curl_client::CurlClient`] paid-provider path,
//! which — unlike the reqwest path in [`crate::util::http`] — deliberately skips
//! the private-IP SSRF pin, on the documented assumption that the request host is
//! a hardcoded provider base and therefore never attacker-controlled. A base-URL
//! override breaks that invariant: a single env var can silently redirect a
//! *key-bearing* request (the API key rides in the auth header, and query data
//! carries the scan target's PII) to any host — a look-alike domain that harvests
//! the key, or an internal address. This guard restores the invariant for the
//! override case:
//!
//! * a non-`https` override is refused — an API key must never travel cleartext;
//! * an override whose host is a private/reserved IP literal or an IANA-local
//!   domain is refused, restoring the SSRF pin the curl path skips;
//! * an override that redirects to a **different host** than the built-in default
//!   is honoured (self-hosting or an alternate instance is legitimate) but logged
//!   at WARN, so a redirect can never be *silent*;
//! * anything unparseable falls back to the built-in default.
//!
//! The policy lives in the pure [`classify`]; [`resolve`] is the thin env-reading,
//! logging wrapper the provider modules call.

use url::Url;

/// The outcome of vetting a base-URL override against its built-in default.
/// Returned by the pure [`classify`] so the policy is unit-testable with no env
/// read and no logging.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OverrideDecision {
    /// No override set (or all-whitespace) — use the built-in default.
    UseDefault,
    /// Override accepted; its host equals the default's (only path/port differ).
    AcceptSameHost,
    /// Override accepted but redirects to a different host — the caller must WARN
    /// so the redirect is never silent.
    AcceptDivergentHost {
        /// The override's host, surfaced in the WARN message.
        host: String,
    },
    /// Override refused as unsafe; the caller falls back to the default.
    Reject {
        /// Human-readable reason, surfaced in the WARN message.
        reason: &'static str,
    },
}

/// Vet a raw override value against the built-in `default_base`. Pure: no env
/// read, no logging — the whole policy in one testable function.
///
/// `raw_override` is the env var's value (already `Option`-wrapped by the
/// caller); `None` or an all-whitespace value yields [`OverrideDecision::UseDefault`].
#[must_use]
pub fn classify(raw_override: Option<&str>, default_base: &str) -> OverrideDecision {
    let Some(raw) = raw_override.map(str::trim).filter(|s| !s.is_empty()) else {
        return OverrideDecision::UseDefault;
    };
    let Ok(parsed) = Url::parse(raw) else {
        return OverrideDecision::Reject {
            reason: "not a valid absolute URL",
        };
    };
    if parsed.scheme() != "https" {
        return OverrideDecision::Reject {
            reason: "scheme is not https (an API key must never travel over cleartext)",
        };
    }
    let Some(host) = parsed.host_str() else {
        return OverrideDecision::Reject {
            reason: "URL has no host",
        };
    };
    // Restore the SSRF pin the CurlClient path skips: a private/reserved host or a
    // local domain must never receive a keyed request via an override.
    if crate::util::preflight::url_host_is_private(raw) {
        return OverrideDecision::Reject {
            reason: "host is a private/reserved address or a local domain",
        };
    }
    match Url::parse(default_base)
        .ok()
        .and_then(|u| u.host_str().map(str::to_owned))
    {
        Some(default_host) if default_host == host => OverrideDecision::AcceptSameHost,
        _ => OverrideDecision::AcceptDivergentHost {
            host: host.to_owned(),
        },
    }
}

/// Resolve `env_var` into an effective base URL, applying the [`classify`] policy
/// and emitting the appropriate WARN. Returns the built-in `default_base`
/// whenever the override is absent or refused, so callers get a safe value with
/// no extra branching.
#[must_use]
pub fn resolve(env_var: &str, default_base: &str) -> String {
    let raw = std::env::var(env_var).ok();
    let trimmed = raw.as_deref().map(str::trim).filter(|s| !s.is_empty());
    match classify(trimmed, default_base) {
        OverrideDecision::UseDefault => default_base.to_owned(),
        // `trimmed` is `Some` on both accept branches (classify only accepts a
        // present, non-empty value), so `unwrap_or` never falls back here.
        OverrideDecision::AcceptSameHost => trimmed.unwrap_or(default_base).to_owned(),
        OverrideDecision::AcceptDivergentHost { host } => {
            tracing::warn!(
                env_var,
                override_host = %host,
                default_base,
                "base-URL override active: the API key and query data will be sent to a \
                 NON-DEFAULT host — confirm it is the legitimate provider, not a look-alike"
            );
            trimmed.unwrap_or(default_base).to_owned()
        }
        OverrideDecision::Reject { reason } => {
            tracing::warn!(
                env_var,
                reason,
                "ignoring unsafe base-URL override; using the built-in default"
            );
            default_base.to_owned()
        }
    }
}

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
