//! API key identification and reporting module.
//!
//! Accepts a raw API key as a seed, probes it against all known OSINT
//! service endpoints in parallel, identifies which service(s) it belongs
//! to, and extracts account metadata (plan, credits, quotas) as a
//! reportable finding.
//!
//! This intentionally does NOT auto-enroll a validated key into
//! [`crate::util::key_pool`] for HSE's own future reuse: a discovered
//! `ApiKey` target can come from anywhere with no ownership check (a
//! crawled page, a breach dump, an import), so auto-pooling would mean HSE
//! authenticates against real third-party services with a credential of
//! unverified ownership on its own initiative, then keeps using it in
//! later scans. The full validation result (service, category, plan/quota
//! metadata) is still reported as an entity below; an operator who reviews
//! it and wants the key available for future scans can pool it explicitly
//! (`hse keys add`).

use std::time::Duration;

use async_trait::async_trait;
use serde_json::Value;

use crate::core::{
    confidence,
    entity::{Entity, EntityKind, Evidence},
    error::{Error, Result},
    module::{Module, ModuleCategory, ModuleContext, ModuleCost, ModuleResult},
    scan::{Target, TargetKind},
};
use crate::util::key_pool::validation::{ProbeOutcome as KeyVerdict, classify_probe_response};

const SRC: &str = "api_key_probe";

pub struct ApiKeyProbe;

mod probes;
use probes::probes;

#[async_trait]
impl Module for ApiKeyProbe {
    fn name(&self) -> &'static str {
        "api_key_probe"
    }

    fn description(&self) -> &'static str {
        "API key probe — identifies and validates API keys against known OSINT services, reporting the match as a finding (never auto-pooled for reuse)"
    }

    fn priority(&self) -> u8 {
        200
    }

    fn cost(&self) -> ModuleCost {
        ModuleCost::Free
    }

    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::ApiKey)
    }

    fn max_timeout_ms(&self) -> u64 {
        90_000
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Other
    }

    fn attack_techniques(&self) -> &'static [&'static str] {
        // Confirms which discovered API keys are live against their provider —
        // gathering/validating the subject's exposed credentials. ATT&CK
        // Gather Victim Identity Information: Credentials (T1589.001).
        &["T1589.001"]
    }

    fn produces(&self) -> &'static [EntityKind] {
        const KINDS: &[EntityKind] = &[EntityKind::ApiKey, EntityKind::Domain];
        KINDS
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let key = target.value.trim();
        if key.is_empty() || key.len() < 8 {
            return Ok(ModuleResult::new());
        }

        let mut result = ModuleResult::new();
        let all_probes = probes();
        // `JoinSet`, not a `Vec<JoinHandle<_>>`: dropping a `JoinSet` aborts
        // every task still running in it, whereas dropping a `Vec` of bare
        // `JoinHandle`s only detaches them — the spawned tasks (and their
        // `kill_on_drop` curl subprocesses) keep running. The engine wraps
        // this whole `process()` future in `tokio::time::timeout` at
        // `max_timeout_ms` (90s); without this, a `process()` future dropped
        // by that outer timeout left every still-in-flight probe (each its
        // own curl subprocess, independently bounded only by its own 12s
        // budget) running for up to 12 more unaccounted-for seconds on the
        // runtime after the engine had already moved on. The index travels
        // with each result since `join_next` resolves in completion order,
        // not spawn order, but the probe lookup below needs the original.
        let mut tasks: tokio::task::JoinSet<(usize, ProbeOutcome)> = tokio::task::JoinSet::new();

        for (i, probe) in all_probes.iter().enumerate() {
            let key = key.to_string();
            let (url, headers) = probes::request_for(probe.def, &key);
            tasks.spawn(async move { (i, probe_endpoint(&url, &key, &headers).await) });
        }

        let mut identified = Vec::new();
        // Probes that never got an answer (no network, DNS/TLS failure, timeout)
        // are counted separately from probes that ran and simply didn't match, so
        // a total transport failure can be told apart from a genuine "matches no
        // known service" after the loop (T2.123).
        let mut transport_failures = 0usize;

        while let Some(joined) = tasks.join_next().await {
            let Ok((i, outcome)) = joined else {
                continue;
            };
            let probe = &all_probes[i];
            let answer = match outcome {
                ProbeOutcome::Executed(Some(answer)) => answer,
                // The host answered but with nothing usable — a real negative.
                ProbeOutcome::Executed(None) => continue,
                // The probe never executed — count it, don't treat it as a miss.
                ProbeOutcome::TransportFailure => {
                    transport_failures += 1;
                    continue;
                }
            };

            // Only an answer that ACCEPTS the key names its service. A refusal,
            // or an answer that settles nothing, is a real negative.
            let Some(json) = accepted_body(probe.service, &answer) else {
                continue;
            };

            let info = (probe.parse_info)(&json);

            let mut entity = Entity::new(
                EntityKind::ApiKey,
                format!(
                    "{}:{}",
                    probe.service,
                    crate::util::str_util::truncate_safe(key, 12)
                ),
                confidence::VERY_HIGH_PLUSPLUS,
                &ctx.scan_id,
            );
            entity.tag(format!("service:{}", probe.service));
            entity.tag(format!("category:{}", probe.category));
            entity.tag("api-key");
            entity.tag("validated");

            let mut ev = Evidence::new(
                SRC,
                format!(
                    "API key identified as {} ({})",
                    probe.service, probe.category
                ),
            )
            .with_attr("service", probe.service)
            .with_attr("category", probe.category)
            .with_attr("env_var", probe.env_var);

            for (k, v) in &info {
                ev = ev.with_attr(k, v);
            }

            entity.add_evidence(ev);
            result.push(entity);

            // Emit a Domain entity for the service so expansion can pivot
            // through DNS/IP/geo pipelines.
            let service_domain = match probe.service {
                "shodan" => Some("shodan.io"),
                "virustotal" => Some("virustotal.com"),
                "censys" => Some("censys.io"),
                "greynoise" => Some("greynoise.io"),
                "urlscan" => Some("urlscan.io"),
                "securitytrails" => Some("securitytrails.com"),
                "hunter" => Some("hunter.io"),
                "intelx" => Some("intelx.io"),
                "dehashed" => Some("dehashed.com"),
                "leakix" => Some("leakix.net"),
                "ipqs" => Some("ipqualityscore.com"),
                "numverify" => Some("numverify.com"),
                "wigle" => Some("wigle.net"),
                "abuseipdb" => Some("abuseipdb.com"),
                _ => None,
            };
            if let Some(domain) = service_domain {
                let mut d = Entity::new(
                    EntityKind::Domain,
                    domain,
                    confidence::MEDIUM_PLUS,
                    &ctx.scan_id,
                );
                d.tag("api-key-derived");
                d.tag(format!("service:{}", probe.service));
                d.add_evidence(Evidence::new(
                    SRC,
                    format!("Service domain for identified {} API key", probe.service),
                ));
                result.push(d);
            }

            identified.push((probe.service, probe.category, info));
        }

        // If NOTHING was identified and EVERY probe failed to even execute (e.g.
        // no network on-device), that is a total transport failure — surface it
        // as a real error rather than the same clean empty result a genuine
        // "this key matches no known service" produces (T2.123). If even one
        // probe ran (match or not), the empty result is an honest negative.
        if all_probes_failed_to_execute(transport_failures, all_probes.len(), identified.len()) {
            return Err(Error::module(
                SRC,
                "every API-key probe failed at the transport level (no network reachable?) — \
                 cannot determine whether this key matches any known service",
            ));
        }

        sort_identified_for_report(&mut identified);

        if !identified.is_empty() {
            // `EntityKind::ApiKey`, not `Other`: `util::redact::is_credential_kind`
            // gates the export-redaction path (`hse export --redact`, `?redact=1`)
            // purely on entity KIND, and `Other` matches none of its arms. An
            // `Other`-kind summary carrying the complete, still-valid key in
            // `value` survived a redacted export in full plaintext — the exact
            // credential-disclosure harm that gate exists to prevent — even
            // though the per-service entity two dozen lines above already does
            // this correctly. Truncated too, as defense in depth, so the full
            // secret is never held in an entity value regardless of kind.
            let mut summary = Entity::new(
                EntityKind::ApiKey,
                format!(
                    "api_key_report:{}",
                    crate::util::str_util::truncate_safe(key, 12)
                ),
                confidence::CERTAIN,
                &ctx.scan_id,
            );
            summary.tag("api-key-probe");

            let svc_list: Vec<&str> = identified.iter().map(|(s, _, _)| *s).collect();
            let mut ev = Evidence::new(
                SRC,
                format!(
                    "Key identified across {} service(s): {}",
                    identified.len(),
                    svc_list.join(", ")
                ),
            )
            .with_attr("services_matched", svc_list.join(", "))
            .with_attr("total_matches", identified.len().to_string());

            for (svc, _cat, info) in &identified {
                for (k, v) in info {
                    ev = ev.with_attr(format!("{svc}_{k}"), v);
                }
            }

            summary.add_evidence(ev);
            result.push(summary);
        }

        Ok(result)
    }
}

/// The outcome of a single [`probe_endpoint`] call, distinguishing a probe that
/// COULD NOT EXECUTE — no answer from the host: a timeout, a curl spawn failure,
/// or curl's own non-zero exit (a connection/DNS/TLS failure) — from one that
/// RAN and got an answer (whether or not that answer is a usable match). This
/// distinction is what lets `process()` tell a total network outage (every probe
/// failing to execute) apart from a genuine "this key matches no known service"
/// (T2.123); collapsing both into `None` hid the former as the latter.
enum ProbeOutcome {
    /// The host answered. `Some(answer)` carries its HTTP status and a usable
    /// body to evaluate; `None` is an empty / too-short / non-UTF-8 response —
    /// the host replied, but with nothing to match (a legitimate negative).
    Executed(Option<Answer>),
    /// The probe never got an answer — it could not execute at all.
    TransportFailure,
}

/// What a host that answered a probe sent back.
struct Answer {
    /// The HTTP status curl reported (`%{http_code}`, e.g. `"401"`): where a
    /// provider that follows HTTP conventions refuses a wrong key, in the one
    /// shape all such providers share.
    status: String,
    /// The response body, without the status curl wrote after it.
    body: String,
}

/// Whether `process()` should surface a hard error instead of a clean empty
/// result: true only when NOTHING was identified AND every probe failed at the
/// transport level (none even got an answer). A total network outage must not
/// masquerade as "this key matches no known service" (T2.123); but if even one
/// probe executed — a match, or an honest negative — the empty result is a
/// genuine no-match and stays a clean `Ok`. Pure, so it is unit-tested.
#[must_use]
fn all_probes_failed_to_execute(
    transport_failures: usize,
    total_probes: usize,
    identified: usize,
) -> bool {
    identified == 0 && total_probes > 0 && transport_failures == total_probes
}

async fn probe_endpoint(url: &str, key: &str, headers: &[(&str, String)]) -> ProbeOutcome {
    let secs = 10u64.to_string();
    let mut cmd = tokio::process::Command::new("curl");
    cmd.args(["-s", "--max-time", &secs]);
    // Single-sourced OOM/SSRF hardening — chiefly `--max-filesize` (32 MiB) so a
    // hostile probe endpoint can't stream an unbounded body into a low-RAM Termux
    // device's memory; the proto/redirect flags are inert here (no `-L`, https
    // URLs) but keep the cap single-sourced with curl_exec/curl_client.
    cmd.args(crate::util::curl::FETCH_HARDENING_ARGS);

    for (name, prefix) in headers {
        if *name == "_basic_auth" {
            cmd.args(["-u", key]);
            continue;
        }
        let val = if !prefix.is_empty() {
            format!("{prefix} {key}")
        } else {
            key.to_string()
        };
        let h = format!("{name}: {val}");
        cmd.args(["-H", &h]);
    }

    cmd.args(["-H", "Accept: application/json"]);
    // Write the HTTP status after the body. Without `-f` curl exits 0 for a 401
    // exactly as for a 200 (see below), and the status is the one place a
    // refusal takes the same shape for every provider; each body has its own.
    // The same sentinel `key_pool::validation` reads for the same `ServiceDef`.
    cmd.args(["-w", "\n%{http_code}"]);
    cmd.args(["--", url]);
    cmd.kill_on_drop(true);

    // Timeout elapsed, or curl failed to spawn — the probe never executed.
    let output = match tokio::time::timeout(Duration::from_secs(12), cmd.output()).await {
        Ok(Ok(output)) => output,
        Ok(Err(_)) | Err(_) => return ProbeOutcome::TransportFailure,
    };

    // curl exits non-zero on a connection-refused / DNS / TLS / curl-timeout
    // failure. It returns 0 for ANY HTTP response actually received (no `-f`
    // flag), so a non-zero exit means the request never completed — a genuine
    // transport failure, NOT a "the host answered 401/404" negative.
    if !output.status.success() {
        return ProbeOutcome::TransportFailure;
    }

    // The host answered. A non-UTF-8 or too-short body is a real (if unusable)
    // response — a negative, not a failure to execute.
    let Ok(raw) = String::from_utf8(output.stdout) else {
        return ProbeOutcome::Executed(None);
    };
    // `-w` appends a newline and then the status, so the LAST newline in the
    // output is always that separator, whatever newlines the body holds.
    let Some((body, status)) = raw.rsplit_once('\n') else {
        return ProbeOutcome::Executed(None);
    };
    if body.len() < 2 {
        return ProbeOutcome::Executed(None);
    }
    ProbeOutcome::Executed(Some(Answer {
        status: status.trim().to_string(),
        body: body.to_string(),
    }))
}

/// The parsed body of an answer in which `service` ACCEPTED the key, or `None`
/// when it did not. **Pure.** The one gate between a probe's answer and a
/// `validated` finding at `VERY_HIGH_PLUSPLUS`, with its service-domain pivot.
///
/// The verdict is [`classify_probe_response`]'s: `key_pool::validation`'s
/// reading of an answer from the same `ServiceDef` test endpoint — the status
/// first, then its narrow in-body and auth-shaped-400 checks — so this module
/// never calls a key validated on an answer the key pool reads as a refusal or
/// as settling nothing. It used to discard the status and judge the body alone,
/// and no body heuristic knows every provider's error shape: VirusTotal's `401`
/// with an `{"error": {…}}` object, Hunter's `401` with an `{"errors": […]}`
/// list and Netlas' auth-failure `400` all read as success, so a key belonging
/// to none of them was reported as a live credential for each
/// (REQ-KEYPROBE-002). [`is_error_response`] still runs on an accepted answer,
/// for a provider that reports a dead key inside a `200` body.
fn accepted_body(service: &str, answer: &Answer) -> Option<Value> {
    if classify_probe_response(service, &answer.body, &answer.status) != KeyVerdict::Valid {
        return None;
    }
    let json: Value = serde_json::from_str(&answer.body).ok()?;
    if is_error_response(&json) {
        return None;
    }
    Some(json)
}

/// Whether the body of an answer the status verdict ACCEPTED still reports a
/// failure — the second gate in [`accepted_body`], for a provider that answers
/// a dead key with a `200` and says so only in the body.
fn is_error_response(v: &Value) -> bool {
    if let Some(code) = v.get("status_code").and_then(serde_json::Value::as_u64)
        && (code == 401 || code == 403 || code == 429)
    {
        return true;
    }
    if let Some(err) = v.get("error").and_then(|e| e.as_str()) {
        let lower = err.to_lowercase();
        if lower.contains("invalid")
            || lower.contains("unauthorized")
            || lower.contains("denied")
            || lower.contains("forbidden")
            || lower.contains("authentication")
        {
            return true;
        }
    }
    // An `error` OBJECT is an error envelope whatever its words — VirusTotal's
    // documented `{"error": {"code": "WrongCredentialsError", …}}` matches none
    // of the words above, and the string arm read it as no error at all. A
    // scalar marker is not one: ONYPHE's success body carries `"error": 0`.
    if let Some(err) = v.get("error").and_then(Value::as_object)
        && !err.is_empty()
    {
        return true;
    }
    if let Some(msg) = v.get("message").and_then(|m| m.as_str()) {
        let lower = msg.to_lowercase();
        if lower.contains("authentication error")
            || lower.contains("invalid api key")
            || lower.contains("api key required")
            || lower.contains("rate limit")
        {
            return true;
        }
    }
    if v.get("success").and_then(serde_json::Value::as_bool) == Some(false) {
        return true;
    }
    if v.get("valid").and_then(serde_json::Value::as_bool) == Some(false) {
        return true;
    }
    false
}

/// Put the identified services into a deterministic, reproducible order for the
/// operator-facing report. **Pure.**
///
/// `identified` is filled inside the `join_next` loop, which resolves in
/// COMPLETION order — network-race order, not spawn order (the `JoinSet`
/// declaration above already names this). That order reached the operator
/// verbatim in both the evidence headline and the `services_matched` attribute,
/// so two runs against the same key and the same services could print them in
/// different orders, and a diff of two reports showed a change where nothing had
/// changed.
///
/// Sorts by service name. The service strings are unique per probe, so this is a
/// total order and needs no secondary tie-break.
fn sort_identified_for_report<C, I>(identified: &mut [(&'static str, C, I)]) {
    identified.sort_by(|a, b| a.0.cmp(b.0));
}

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
