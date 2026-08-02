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

    // `add_and_validate` is itself `pub async fn`, already run on a tokio worker
    // — persist off the runtime (`persist_off_thread`) rather than the blocking
    // `save_pool_best_effort` directly, so a validation call never stalls the
    // executor other concurrently-dispatched modules share.
    if let Some(valid) = validate_key(service, key_value).await {
        if valid {
            entry.status = KeyStatus::Active;
            entry.last_validated = Some(crate::core::entity::unix_now());
            let added = pool.add(service, entry);
            if added {
                super::persistence::persist_off_thread(pool);
                tracing::info!(service, "validated and stored API key");
            }
            true
        } else {
            entry.status = KeyStatus::Invalid;
            entry.last_validated = Some(crate::core::entity::unix_now());
            pool.add(service, entry);
            super::persistence::persist_off_thread(pool);
            tracing::warn!(service, "API key failed validation — stored as invalid");
            false
        }
    } else {
        pool.add(service, entry);
        super::persistence::persist_off_thread(pool);
        false
    }
}

pub async fn validate_key(service: &str, key: &str) -> Option<bool> {
    let sdef = find_service(service)?;
    // Map the three-way probe outcome to the caller's Option<bool>: only a
    // DEFINITIVE auth rejection (401/403) marks a key invalid. Indeterminate
    // outcomes — transport failure, timeout, 429, 5xx, any non-auth status —
    // return None so add_and_validate leaves the key Untested for a later re-probe
    // instead of writing a sticky Invalid on a transient outage.
    match validate_against_endpoint(sdef, key).await {
        ProbeOutcome::Valid => Some(true),
        ProbeOutcome::Rejected => Some(false),
        ProbeOutcome::Indeterminate => None,
    }
}

/// The three distinguishable outcomes of a key-validation probe. `Indeterminate`
/// (transport failure, timeout, 429, 5xx, or any non-auth status) is deliberately
/// NOT a rejection: only a definitive 401/403 proves a key bad. Conflating the two
/// previously marked a valid key permanently Invalid on a transient outage.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProbeOutcome {
    Valid,
    Rejected,
    Indeterminate,
}

async fn validate_against_endpoint(sdef: &ServiceDef, key: &str) -> ProbeOutcome {
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
        KeyPlacement::BearerAuth => {
            let h = format!("Authorization: bearer {key}");
            cmd.args(["-H", &h, "--", sdef.test_url]);
        }
        KeyPlacement::HeaderPrefixed(header, prefix) => {
            let h = format!("{header}: {prefix}{key}");
            cmd.args(["-H", &h, "--", sdef.test_url]);
        }
    }

    cmd.kill_on_drop(true);

    let output = tokio::time::timeout(Duration::from_millis(timeout_ms + 2000), cmd.output())
        .await
        .ok()
        .and_then(std::result::Result::ok);

    let Some(output) = output else {
        return ProbeOutcome::Indeterminate;
    };
    let code = String::from_utf8_lossy(&output.stdout);
    match code.trim() {
        "200" | "201" | "204" | "301" | "302" => ProbeOutcome::Valid,
        // A definitive auth rejection — the only outcome that proves the key bad.
        "401" | "403" => ProbeOutcome::Rejected,
        // Connect failure (curl writes "000"), rate-limit (429), 5xx, or any other
        // status: the key's validity could not be determined, so don't condemn it.
        _ => ProbeOutcome::Indeterminate,
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
