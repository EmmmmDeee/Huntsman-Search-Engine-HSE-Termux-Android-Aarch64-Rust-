//! API key identification and cataloging module.
//!
//! Accepts a raw API key as a seed, probes it against all known OSINT
//! service endpoints in parallel, identifies which service(s) it
//! belongs to, extracts account metadata (plan, credits, quotas),
//! and auto-stores valid keys in the key pool for future use.

use std::time::Duration;

use async_trait::async_trait;
use serde_json::Value;

use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::{Module, ModuleCategory, ModuleContext, ModuleCost, ModuleResult},
    scan::{Target, TargetKind},
};
use crate::util::key_pool::{self, KeyEntry, KeyStatus};

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
        "Identify, validate, and catalog API keys across OSINT services"
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

    fn is_passive(&self) -> bool {
        true
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
        let mut tasks = Vec::new();

        for probe in &all_probes {
            let key = key.to_string();
            let (url, headers) = (probe.url_builder)(&key);
            // Clone the shared rustls reqwest client (cheap — Arc inside) into
            // each task. No `curl` subprocess: Termux/aarch64 (no root) may not
            // ship curl, and spawning ~24 processes to validate one key is far
            // heavier on a phone than 24 pooled HTTPS requests on one client.
            let http = ctx.http.clone();
            tasks.push(tokio::spawn(async move {
                probe_endpoint(&http, &url, &key, &headers).await
            }));
        }

        let pool = key_pool::global_pool();
        let mut identified = Vec::new();

        for (i, task) in tasks.into_iter().enumerate() {
            let probe = &all_probes[i];
            let response = match task.await {
                Ok(Some(body)) => body,
                _ => continue,
            };

            let json: Value = match serde_json::from_str(&response) {
                Ok(v) => v,
                Err(_) => continue,
            };

            if is_error_response(&json) {
                continue;
            }

            let info = (probe.parse_info)(&json);

            let mut entry = KeyEntry::new(key);
            entry.status = KeyStatus::Active;
            entry.last_validated = Some(crate::core::entity::unix_now());
            entry.notes = Some("Auto-identified by api_key_probe".to_string());
            pool.add(probe.service, entry);

            let mut entity = Entity::new(
                EntityKind::ApiKey,
                format!(
                    "{}:{}",
                    probe.service,
                    crate::util::str_util::truncate_safe(key, 12)
                ),
                0.95,
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
            // through DNS/IP/geo pipelines. The brand domain is single-sourced
            // in `probes::service_domain` (complete for every probe, enforced by
            // a test) — it is NOT derived from the probe URL, because several
            // APIs are served from an unrelated host (numverify validates via
            // `apilayer.net`, but the subject's service is `numverify.com`).
            if let Some(domain) = probes::service_domain(probe.service) {
                let mut d = Entity::new(EntityKind::Domain, domain, 0.60, &ctx.scan_id);
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

        if let Err(e) = key_pool::save_pool(&pool) {
            tracing::warn!("failed to save key pool: {e}");
        }

        if !identified.is_empty() {
            let mut summary = Entity::new(
                EntityKind::Other("api_key_report".into()),
                key,
                0.99,
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

/// Split a Censys/PassiveTotal-style `id:secret` credential into HTTP Basic
/// Auth parts. A value with no `:` is treated as the username with an empty
/// password — identical to `curl -u value` semantics.
fn basic_auth_parts(key: &str) -> (&str, &str) {
    key.split_once(':').unwrap_or((key, ""))
}

/// Build the value for a prefixed auth header: `"Bearer <key>"`,
/// `"Basic <token>"`, or the bare key when the prefix is empty.
fn auth_header_value(prefix: &str, key: &str) -> String {
    if prefix.is_empty() {
        key.to_string()
    } else {
        format!("{prefix} {key}")
    }
}

/// Send one validation request for a candidate key against a service endpoint,
/// using the shared rustls reqwest client.
///
/// Returns the response body **only on an HTTP 2xx**. This is the authoritative
/// validity gate: a non-success status (401/403/429/5xx) means the key is
/// invalid, blocked, or the service is down for that probe — so we never feed a
/// failed response into the body-content parser, which previously had to *guess*
/// validity from JSON shape because the `curl -s` subprocess hid the status code.
async fn probe_endpoint(
    http: &reqwest::Client,
    url: &str,
    key: &str,
    headers: &[(&str, String)],
) -> Option<String> {
    let mut req = http
        .get(url)
        .header(reqwest::header::ACCEPT, "application/json");

    for (name, prefix) in headers {
        if *name == "_basic_auth" {
            let (user, pass) = basic_auth_parts(key);
            req = req.basic_auth(user, Some(pass));
            continue;
        }
        req = req.header(*name, auth_header_value(prefix, key));
    }

    // Bound every probe independently so one slow service can't stall the sweep
    // past the module's budget on a mobile/captive link.
    let resp = tokio::time::timeout(Duration::from_secs(10), req.send())
        .await
        .ok()?
        .ok()?;

    if !resp.status().is_success() {
        return None;
    }

    let body = tokio::time::timeout(Duration::from_secs(5), resp.text())
        .await
        .ok()?
        .ok()?;
    if body.len() < 2 {
        return None;
    }
    Some(body)
}

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
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_api_key_only() {
        let m = ApiKeyProbe;
        assert!(m.accepts(&Target::new(TargetKind::ApiKey, "test-key-12345678")));
        assert!(!m.accepts(&Target::new(TargetKind::Email, "a@b.com")));
        assert!(!m.accepts(&Target::new(TargetKind::Domain, "example.com")));
    }

    #[test]
    fn probe_count_matches_services() {
        let p = probes();
        assert!(p.len() >= 23);
        for probe in &p {
            assert!(!probe.service.is_empty());
            assert!(!probe.env_var.is_empty());
            assert!(probe.env_var.starts_with("HUNTSMAN_"));
        }
    }

    #[test]
    fn every_probe_transmits_its_key_only_over_https() {
        // These probes send a LIVE secret API key to a validation endpoint —
        // whether in the URL query or an auth header. A plaintext `http://`
        // endpoint would leak the credential to any on-path observer, so the
        // table must be https-only (it is; this guards against a future
        // contributor adding an http endpoint), and every probe must actually
        // carry the key — via the URL or at least one header — or it would send
        // an unauthenticated request and report a valid key as invalid.
        const SENTINEL: &str = "SENTINELKEY0123456789";
        for probe in &probes() {
            let (url, headers) = (probe.url_builder)(SENTINEL);
            assert!(
                url.starts_with("https://"),
                "{}: probe URL is not https ({url}) — would leak the key in plaintext",
                probe.service
            );
            assert!(
                url.contains(SENTINEL) || !headers.is_empty(),
                "{}: probe carries the key neither in the URL nor a header — it would \
                 send an unauthenticated request",
                probe.service
            );
            assert!(
                !probe.category.is_empty(),
                "{}: empty category",
                probe.service
            );
        }
    }

    #[test]
    fn probe_services_and_env_vars_are_unique() {
        // A duplicate service or env var means one probe shadows the other:
        // wasted requests, or a key validated against the wrong endpoint.
        let p = probes();
        let mut services = std::collections::HashSet::new();
        let mut env_vars = std::collections::HashSet::new();
        for probe in &p {
            assert!(
                services.insert(probe.service),
                "duplicate probe service: {}",
                probe.service
            );
            assert!(
                env_vars.insert(probe.env_var),
                "duplicate probe env var: {}",
                probe.env_var
            );
        }
    }

    #[test]
    fn error_detection() {
        let err1: Value = serde_json::json!({"error": "Invalid API key"});
        assert!(is_error_response(&err1));

        let err2: Value = serde_json::json!({"success": false});
        assert!(is_error_response(&err2));

        let ok: Value = serde_json::json!({"plan": "free", "credits": 100});
        assert!(!is_error_response(&ok));
    }

    #[test]
    fn is_free_and_passive() {
        let m = ApiKeyProbe;
        assert!(m.is_passive());
        assert_eq!(m.cost(), ModuleCost::Free);
    }

    #[test]
    fn basic_auth_parts_splits_id_secret() {
        // Censys/PassiveTotal "id:secret" → (id, secret), matching `curl -u`.
        assert_eq!(basic_auth_parts("apiid:apisecret"), ("apiid", "apisecret"));
        // A value with no colon is the username with an empty password.
        assert_eq!(basic_auth_parts("lonekey"), ("lonekey", ""));
        // Only the FIRST colon splits (a secret may itself contain ':').
        assert_eq!(basic_auth_parts("id:sec:ret"), ("id", "sec:ret"));
    }

    #[test]
    fn auth_header_value_applies_scheme_prefix() {
        // Prefixed schemes (wigle "Basic", onyphe "bearer") → "<prefix> <key>".
        assert_eq!(auth_header_value("Basic", "TOKEN"), "Basic TOKEN");
        assert_eq!(auth_header_value("bearer", "TOKEN"), "bearer TOKEN");
        // No prefix → the bare key is the whole header value (e.g. `x-apikey`).
        assert_eq!(auth_header_value("", "TOKEN"), "TOKEN");
    }
}
