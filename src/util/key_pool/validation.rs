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
        "-w",
        "\n%{http_code}",
        "--max-time",
        &secs,
        // The body is now inspected (see `classify_probe_response`'s 400
        // handling below), so — unlike the old `-o /dev/null` version — it is
        // no longer discarded; cap it exactly as every other curl invocation
        // in this codebase does (`util::curl::FETCH_HARDENING_ARGS`'s own
        // `--max-filesize`), so a misbehaving endpoint can't make this probe
        // buffer an unbounded response.
        "--max-filesize",
        crate::util::curl::CURL_MAX_DOWNLOAD_BYTES,
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
    let raw = String::from_utf8_lossy(&output.stdout);
    // `-w "\n%{http_code}"` unconditionally appends a newline then the status
    // code after the body, so the LAST newline in the stream is always that
    // separator — `rsplit_once` finds it regardless of any newlines the body
    // itself contains (JSON bodies are typically single-line, but this must
    // not assume it). No output at all (e.g. curl killed before writing
    // anything) leaves no separator to find, which the `None` arm treats the
    // same as any other unparseable response: indeterminate, never a rejection.
    let (body, code) = raw.rsplit_once('\n').unwrap_or(("", raw.as_ref()));
    classify_probe_response(sdef.name, body, code.trim())
}

/// Classify a validation probe's outcome from the response body and status
/// code — pure, so the 400-as-auth-rejection case is unit-tested directly
/// without a live round-trip.
///
/// Split from [`validate_against_endpoint`] because that function's curl
/// subprocess call previously discarded the body (`-o /dev/null`) and
/// classified on the status code alone. That missed a real, already-diagnosed
/// gap: Netlas and ONYPHE both answer a missing/invalid key with a `400 Bad
/// Request` rather than 401/403 (see
/// [`crate::util::http::is_auth_failure_400_body`], added when the *live scan*
/// cascade hit this same ambiguity — `AUTH_400_SIGNATURES`'s doc comment
/// carries the real observed bodies). This probe runs earlier, when an
/// operator adds the key (`add_and_validate`) or `hse doctor` re-checks it: a
/// bad Netlas/ONYPHE key fell through every arm to `Indeterminate`, so
/// `add_and_validate` stored it `Untested` — silently omitting the one
/// diagnostic (the pool's `Invalid` status) that would have told the operator
/// their key doesn't work — instead of catching it at the point they can
/// still fix it, before a scan burns a `next_key` selection on it.
///
/// `service` (the registry name, e.g. `"criminal_ip"`) additionally gates a
/// second, narrower gap on the `"200"` arm: some providers report a
/// dead/exhausted key INSIDE a 200 body rather than via the status code at
/// all — see [`crate::util::service_defs::body_rejects_key`] for exactly
/// which services and why it is deliberately not every service with an
/// always-200 shape.
fn classify_probe_response(service: &str, body: &str, code: &str) -> ProbeOutcome {
    match code {
        "200" => {
            // A 200 whose BODY says the key was actually rejected (see
            // `body_rejects_key`'s doc for the narrow, confirmed set this
            // covers) — parse failure or no match both mean "not this case",
            // falling through to the ordinary 2xx-is-valid reading below.
            let rejected = serde_json::from_str::<serde_json::Value>(body)
                .is_ok_and(|v| crate::util::service_defs::body_rejects_key(service, &v));
            if rejected {
                ProbeOutcome::Rejected
            } else {
                ProbeOutcome::Valid
            }
        }
        "201" | "204" | "301" | "302" => ProbeOutcome::Valid,
        // A definitive auth rejection — the only outcome that proves the key bad.
        "401" | "403" => ProbeOutcome::Rejected,
        // Netlas/ONYPHE-shaped: a 400 whose body carries an auth-failure
        // signature is a rejection in disguise, not an ambiguous bad-request.
        // Gated on the body check so a genuine bad-query 400 (no such
        // signature) still falls through to `Indeterminate`, unchanged.
        "400" if crate::util::http::is_auth_failure_400_body(body) => ProbeOutcome::Rejected,
        // Connect failure (curl writes "000"), rate-limit (429), 5xx, an
        // ordinary bad-query 400, or any other status: the key's validity
        // could not be determined, so don't condemn it.
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

#[cfg(test)]
mod tests {
    use super::*;

    // A service with no registered `body_rejects_key` check — the common
    // case (48+ of the 49 registered services). Named distinctly from
    // "criminal_ip" so these generic tests can't accidentally pass because
    // they happened to match that one special-cased service.
    const GENERIC_SERVICE: &str = "shodan";

    #[test]
    fn a_2xx_or_redirect_status_is_valid_regardless_of_body() {
        for code in ["200", "201", "204", "301", "302"] {
            assert_eq!(
                classify_probe_response(GENERIC_SERVICE, "", code),
                ProbeOutcome::Valid
            );
        }
    }

    #[test]
    fn a_200_body_that_would_reject_criminal_ip_is_valid_for_an_unregistered_service() {
        // The exact in-body shape that DOES flip criminal_ip to `Rejected`
        // below must NOT do so for a service `body_rejects_key` has no entry
        // for — this is what proves the check is opt-in per service, not a
        // blanket "any {"status":401} body is a rejection" rule that could
        // misfire on an unrelated field some other provider's 200 happens to
        // carry.
        assert_eq!(
            classify_probe_response(GENERIC_SERVICE, r#"{"status":401}"#, "200"),
            ProbeOutcome::Valid
        );
    }

    #[test]
    fn a_401_or_403_is_rejected_regardless_of_body() {
        assert_eq!(
            classify_probe_response(GENERIC_SERVICE, "irrelevant", "401"),
            ProbeOutcome::Rejected
        );
        assert_eq!(
            classify_probe_response(GENERIC_SERVICE, "irrelevant", "403"),
            ProbeOutcome::Rejected
        );
    }

    // The exact bodies `AUTH_400_SIGNATURES` documents as observed live from a
    // dead key — Netlas and ONYPHE both answer with 400, not 401/403.
    #[test]
    fn a_400_with_an_auth_failure_body_is_rejected_not_indeterminate() {
        assert_eq!(
            classify_probe_response(
                GENERIC_SERVICE,
                r#"{"detail":"Request had invalid authorization credentials: API key not found"}"#,
                "400"
            ),
            ProbeOutcome::Rejected,
            "Netlas' dead-key 400 must be recognised as a rejection, so a bad \
             key is reported Invalid at add-time instead of sitting Untested"
        );
        assert_eq!(
            classify_probe_response(
                GENERIC_SERVICE,
                r#"{"count":0,"error":3,"status":"nok","text":"Invalid API key format","took":0}"#,
                "400"
            ),
            ProbeOutcome::Rejected,
            "ONYPHE's dead-key 400 must be recognised as a rejection"
        );
    }

    #[test]
    fn a_400_without_an_auth_signature_stays_indeterminate() {
        // A genuine bad-query 400 must NOT be misread as a key rejection —
        // only the documented auth-failure phrasing flips the verdict.
        assert_eq!(
            classify_probe_response(GENERIC_SERVICE, r#"{"error":"malformed request"}"#, "400"),
            ProbeOutcome::Indeterminate
        );
    }

    #[test]
    fn an_unrecognised_or_transient_status_is_indeterminate() {
        // "000" is curl's own marker for a connect failure (no HTTP response
        // at all); 429/5xx are transient, not a verdict on the key itself.
        for code in ["000", "429", "500", "503"] {
            assert_eq!(
                classify_probe_response(GENERIC_SERVICE, "", code),
                ProbeOutcome::Indeterminate
            );
        }
    }

    // Criminal IP reports a dead/exhausted key as an in-body `status` on an
    // HTTP 200 (`modules::criminal_ip`'s own live-scan `keyed_cascade_json`
    // verdict already treats 401/402/429 there as a key failure) — a
    // status-only classifier reads that response as an unconditional
    // `Valid`, so a bad Criminal IP key was never caught at add-time.
    #[test]
    fn criminal_ip_200_with_an_in_body_401_is_rejected() {
        for status in [401, 402, 429] {
            assert_eq!(
                classify_probe_response("criminal_ip", &format!(r#"{{"status":{status}}}"#), "200"),
                ProbeOutcome::Rejected,
                "in-body status {status} must be recognised as a rejection"
            );
        }
    }

    #[test]
    fn criminal_ip_200_with_a_real_status_is_valid() {
        // Status 200 in the body (a genuine successful lookup) must NOT be
        // misread as a rejection just because the service has a check at all.
        assert_eq!(
            classify_probe_response("criminal_ip", r#"{"status":200}"#, "200"),
            ProbeOutcome::Valid
        );
    }

    #[test]
    fn criminal_ip_200_with_an_unparseable_body_is_valid_not_indeterminate() {
        // A parse failure must fall through to the ordinary 2xx-is-valid
        // reading, exactly as if no `body_rejects_key` check existed at all —
        // never silently downgrade a plain success to `Indeterminate`.
        assert_eq!(
            classify_probe_response("criminal_ip", "not json", "200"),
            ProbeOutcome::Valid
        );
    }
}
