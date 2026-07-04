//! Key validation: async endpoint-probe and add-and-validate helpers.

use std::time::Duration;

use super::pool::KeyPool;
use super::types::{KeyEntry, KeyStatus};
use crate::util::service_defs::{KeyPlacement, ServiceDef, find_service};

/// Add a key and validate it immediately against the service endpoint.
/// If valid, marks it Active and stores it. If invalid, marks it Invalid
/// but still stores it (won't be used by next_key).
/// Returns true if the key is valid and was stored.
pub async fn add_and_validate(service: &str, key_value: &str, notes: Option<String>) -> bool {
    let pool = super::global_pool();

    // Validate once: if the pool already holds this exact key with a settled
    // verdict, don't re-probe it. Re-running an import (or any repeated add)
    // must not spend the operator's quota re-confirming a known-good (Active)
    // or known-bad (Invalid/Revoked) credential. Untested / Exhausted /
    // RateLimited are unsettled, so they fall through to a fresh live check.
    if let Some(status) = pool.entry_status(service, key_value) {
        match status {
            KeyStatus::Active => return true,
            KeyStatus::Invalid | KeyStatus::Revoked => return false,
            KeyStatus::Untested | KeyStatus::Exhausted | KeyStatus::RateLimited => {}
        }
    }

    let mut entry = KeyEntry::new(key_value);
    entry.notes = notes;

    if let Some(valid) = validate_key(service, key_value).await {
        if valid {
            entry.status = KeyStatus::Active;
            entry.last_validated = Some(crate::core::entity::unix_now());
            let added = pool.add(service, entry);
            if added {
                super::persistence::save_pool_best_effort(&pool);
                tracing::info!(service, "validated and stored API key");
            }
            true
        } else {
            entry.status = KeyStatus::Invalid;
            entry.last_validated = Some(crate::core::entity::unix_now());
            pool.add(service, entry);
            super::persistence::save_pool_best_effort(&pool);
            tracing::warn!(service, "API key failed validation — stored as invalid");
            false
        }
    } else {
        pool.add(service, entry);
        super::persistence::save_pool_best_effort(&pool);
        false
    }
}

/// Validate `key` against `service`'s endpoint.
///
/// Three-way verdict: `Some(true)` = the credential authenticated, `Some(false)`
/// = the server DEFINITIVELY rejected it (HTTP 401/403), `None` = the outcome is
/// indeterminate — an unknown service, a transient error (429 rate-limit [the key
/// DID authenticate], 5xx outage, connect failure/timeout), or a half-configured
/// paired credential. Callers must leave a key's status UNCHANGED on `None`
/// rather than marking it invalid, so a rate-limited or network-blipped probe
/// can't permanently poison a valid key.
pub async fn validate_key(service: &str, key: &str) -> Option<bool> {
    let sdef = find_service(service)?;
    validate_against_endpoint(sdef, key).await
}

/// Pure: given which half of a paired Basic-auth credential `key` represents
/// (`env_var`, compared against the pair's `username_env`/`password_env`),
/// combine it with the other half's already-resolved `other_value` into a
/// `user:pass` string for `curl -u`. Split out from
/// [`validate_against_endpoint`] so the ordering logic is testable without a
/// network call.
pub(crate) fn combine_basic_auth_pair(
    env_var: &str,
    username_env: &str,
    password_env: &str,
    key: &str,
    other_value: &str,
) -> String {
    if env_var == password_env {
        format!("{other_value}:{key}")
    } else {
        debug_assert_eq!(
            env_var, username_env,
            "ServiceDef.env_var not in its own pair"
        );
        format!("{key}:{other_value}")
    }
}

async fn validate_against_endpoint(sdef: &ServiceDef, key: &str) -> Option<bool> {
    let timeout_ms = 10_000u64;
    let secs = (timeout_ms / 1000).to_string();

    let mut cmd = tokio::process::Command::new("curl");
    cmd.args([
        "-s",
        "-o",
        "/dev/null",
        "-w",
        "%{http_code}",
        "--max-time",
        &secs,
    ]);

    match sdef.key_header {
        KeyPlacement::QueryParam(param) => {
            let url = if sdef.test_url.contains('?') {
                if sdef.test_url.ends_with('=') {
                    format!("{}{}", sdef.test_url, key)
                } else {
                    format!("{}&{}={}", sdef.test_url, param, key)
                }
            } else {
                format!("{}?{}={}", sdef.test_url, param, key)
            };
            cmd.args(["--", &url]);
        }
        KeyPlacement::Header(header) => {
            let h = format!("{header}: {key}");
            cmd.args(["-H", &h, "--", sdef.test_url]);
        }
        KeyPlacement::BasicAuth => {
            cmd.args(["-u", key, "--", sdef.test_url]);
        }
        KeyPlacement::BasicAuthPair {
            username_env,
            password_env,
        } => {
            let other_env = if sdef.env_var == username_env {
                password_env
            } else {
                username_env
            };
            // The other half of the pair must come from the CURRENT key
            // store (env file + process env), not the pool — a paired
            // credential's two halves are validated independently (one per
            // `ServiceDef`) but only ever authenticate together.
            let keys = crate::util::keys::load();
            let Some(other_value) = keys.get(other_env).filter(|v| !v.is_empty()) else {
                // Can't probe one half of a pair without the other configured —
                // indeterminate, not a rejection, so the key keeps its status.
                return None;
            };
            let userpass =
                combine_basic_auth_pair(sdef.env_var, username_env, password_env, key, other_value);
            cmd.args(["-u", &userpass, "--", sdef.test_url]);
        }
        KeyPlacement::BearerAuth => {
            let h = format!("Authorization: bearer {key}");
            cmd.args(["-H", &h, "--", sdef.test_url]);
        }
        KeyPlacement::UrlTemplate => {
            let url = sdef.test_url.replace("{key}", key);
            cmd.args(["--", &url]);
        }
    }

    cmd.kill_on_drop(true);

    let output = tokio::time::timeout(Duration::from_millis(timeout_ms + 2000), cmd.output())
        .await
        .ok()
        .and_then(std::result::Result::ok);

    // A timeout or a curl spawn/transport failure is indeterminate — the key may
    // be perfectly valid; the probe just couldn't reach a verdict, so `?` yields
    // `None` (leave status unchanged) rather than a false rejection.
    let output = output?;
    let code = String::from_utf8_lossy(&output.stdout);
    let code = code.trim();
    classify_validation_code(code)
}

/// Map the HTTP status string curl reports (`%{http_code}`, or `"000"` on a
/// connect/transport failure) to a validation verdict.
///
/// * `Some(true)` — the credential authenticated: a 2xx, or a 3xx redirect the
///   probe treats as "reached an authenticated resource".
/// * `Some(false)` — the server DEFINITIVELY rejected the credential: 401
///   (Unauthorized) or 403 (Forbidden). Only these mark a key invalid.
/// * `None` — indeterminate, so the key's status is left unchanged. Critically
///   this covers **429** (rate-limited — the key *did* authenticate), **5xx**
///   (server outage), curl's **`"000"`** (could not connect), and any other
///   4xx/unexpected code (e.g. a wrong `test_url` yielding 404): none of these
///   prove the credential is bad, and collapsing them to "invalid" permanently
///   poisoned valid keys on a rate-limit or a flaky mobile link.
///
/// Pure, so the classification is unit-tested without a network probe.
fn classify_validation_code(code: &str) -> Option<bool> {
    match code {
        "200" | "201" | "204" | "301" | "302" => Some(true),
        "401" | "403" => Some(false),
        _ => None,
    }
}

/// Merge pool keys into an env-var map, filling any gaps.
pub fn merge_pool_into_env(pool: &KeyPool, keys: &mut std::collections::HashMap<String, String>) {
    let defs = crate::util::service_defs::service_defs();
    for sdef in defs {
        if keys.contains_key(sdef.env_var) {
            continue;
        }
        if let Some(val) = pool.next_key(sdef.name) {
            keys.insert(sdef.env_var.to_string(), val);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::classify_validation_code;

    #[test]
    fn only_a_definitive_rejection_invalidates_a_key() {
        // Authenticated → valid.
        for ok in ["200", "201", "204", "301", "302"] {
            assert_eq!(
                classify_validation_code(ok),
                Some(true),
                "{ok} is a successful auth"
            );
        }
        // The server explicitly rejected the credential → invalid.
        assert_eq!(classify_validation_code("401"), Some(false));
        assert_eq!(classify_validation_code("403"), Some(false));
    }

    #[test]
    fn transient_and_ambiguous_outcomes_never_invalidate_a_key() {
        // 429 rate-limit: the key DID authenticate — must NOT be marked invalid
        // (this was the poisoning bug — every non-2xx/3xx code collapsed to
        // "invalid", so a rate-limited or outage-blipped probe killed a good key).
        assert_eq!(classify_validation_code("429"), None);
        // Server-side outages are the endpoint's fault, not the key's.
        for outage in ["500", "502", "503", "504"] {
            assert_eq!(
                classify_validation_code(outage),
                None,
                "{outage} is a transient outage"
            );
        }
        // curl's connect/transport failure sentinel, and other ambiguous codes
        // (e.g. a wrong test_url → 404, or a 400) prove nothing about the key.
        for ambiguous in ["000", "404", "400", "418", ""] {
            assert_eq!(
                classify_validation_code(ambiguous),
                None,
                "{ambiguous:?} is indeterminate, not a rejection"
            );
        }
    }
}
