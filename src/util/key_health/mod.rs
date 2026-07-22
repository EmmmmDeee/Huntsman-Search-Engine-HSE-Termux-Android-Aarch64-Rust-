//! Observed key-authentication health — the *grounded* answer to "is this
//! configured key actually working?".
//!
//! Deliberately NOT a synthetic live probe. Per-provider validation endpoints
//! have irreducibly fuzzy semantics (a valid Netlas key 401s if probed with the
//! wrong header; domainsDB must be 400ed; some providers 200 an invalid key with
//! an error body — see `util::service_defs` tests), so a synthetic validator
//! would routinely mis-report a *working* key as invalid. Instead this reads what
//! real scans already OBSERVED: a keyed source that drifts with an auth-shaped
//! error (`HTTP 401`, `HTTP 400 … API key not found`, `Invalid API key format`,
//! …) is a key the upstream itself is rejecting — authoritative, zero-mis-report
//! signal that would otherwise be scattered across the loaded-keys list and the
//! per-source drift errors, forcing a human (or Claude Code) to correlate them by
//! hand. Fusing them here is the unified debug depth `hse doctor` and the system
//! debug bundle both surface.

use crate::util::scraper_health::SourceHealth;

/// One keyed source whose most recent failures are authentication-shaped — i.e.
/// the upstream is rejecting the configured credential, not merely timing out or
/// returning no data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyAuthIssue {
    /// The source/module name that stamped the failing outcomes.
    pub module: String,
    /// Current unbroken failure streak (from [`SourceHealth`]).
    pub consecutive_failures: u32,
    /// The exact auth-shaped error the upstream returned — the actionable detail
    /// ("Invalid API key format", "No user found for the API key supplied", …).
    pub detail: String,
    /// Best-effort `HUNTSMAN_*` env var this source's key most likely lives in,
    /// resolved from the [`crate::util::service_defs`] registry. `None` when the
    /// source name doesn't map to a known service — the auth failure is still
    /// real and reported; only the "which env var to fix" hint is absent.
    pub likely_env_var: Option<&'static str>,
}

/// True when an error message looks like an authentication/credential rejection
/// rather than a transport blip (timeout, DNS) or an empty-but-valid response.
///
/// Works on the free-text `last_error` string a source records — which embeds the
/// HTTP status and the upstream's own body — so it catches the shapes real
/// providers actually return: a bare `401`/`403`, and the auth-shaped `400`s that
/// providers like Netlas/ONYPHE use instead of a 401 (the same class
/// [`crate::util::http::is_auth_failure_400_body`] burns a pooled key on).
#[must_use]
pub fn looks_like_auth_failure(msg: &str) -> bool {
    let lower = msg.to_ascii_lowercase();
    // Unambiguous HTTP auth statuses.
    if lower.contains("401") || lower.contains("403") || lower.contains("unauthorized") {
        return true;
    }
    // Auth-shaped 400 / provider-specific credential-rejection phrasing. These
    // are the exact bodies observed in the field (ONYPHE "Invalid API key
    // format", Netlas "API key not found", Hunter "No user found for the API key
    // supplied", generic "authentication failed" / "invalid credentials").
    const AUTH_PHRASES: &[&str] = &[
        "api key not found",
        "invalid api key",
        "invalid authorization",
        "invalid credentials",
        "authentication failed",
        "authentication_failed",
        "no user found for the api key",
        "api key format",
        "missing api key",
        "invalid token",
        "forbidden",
    ];
    AUTH_PHRASES.iter().any(|p| lower.contains(p))
}

/// Diagnose which keyed sources are being rejected by their upstream, from the
/// observed per-source health. Pure: given the same health slice it returns the
/// same diagnosis, so it is unit-tested without a store or network. Output is
/// ordered by descending failure streak (most-broken first), ties by module name
/// for determinism.
#[must_use]
pub fn auth_failing_sources(health: &[SourceHealth]) -> Vec<KeyAuthIssue> {
    let mut issues: Vec<KeyAuthIssue> = health
        .iter()
        .filter(|h| h.is_drifted())
        .filter_map(|h| {
            let detail = h.last_error.as_deref()?;
            if !looks_like_auth_failure(detail) {
                return None;
            }
            Some(KeyAuthIssue {
                module: h.module.clone(),
                consecutive_failures: h.consecutive_failures,
                detail: detail.to_string(),
                likely_env_var: likely_env_var(&h.module),
            })
        })
        .collect();
    issues.sort_by(|a, b| {
        b.consecutive_failures
            .cmp(&a.consecutive_failures)
            .then_with(|| a.module.cmp(&b.module))
    });
    issues
}

/// Best-effort map a source/module name to the `HUNTSMAN_*` env var carrying its
/// key, via the service-def registry. Matches on an exact service-name hit first,
/// then a prefix relationship in either direction (module `hunter_io` ↔ service
/// `hunter`), so the common naming skew between a module and its service still
/// resolves without a hand-maintained table.
#[must_use]
fn likely_env_var(module: &str) -> Option<&'static str> {
    let defs = crate::util::service_defs::service_defs();
    // Exact name match wins.
    if let Some(d) = defs.iter().find(|d| d.name == module) {
        return Some(d.env_var);
    }
    // Prefix relationship either way (module "hunter_io" ↔ service "hunter").
    defs.iter()
        .find(|d| module.starts_with(d.name) || d.name.starts_with(module))
        .map(|d| d.env_var)
}

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
