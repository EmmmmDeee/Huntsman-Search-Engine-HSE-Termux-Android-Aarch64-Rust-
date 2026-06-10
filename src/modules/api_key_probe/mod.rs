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
            tasks.push(tokio::spawn(async move {
                probe_endpoint(&url, &key, &headers).await
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

async fn probe_endpoint(url: &str, key: &str, headers: &[(&str, String)]) -> Option<String> {
    let secs = 10u64.to_string();
    let mut cmd = tokio::process::Command::new("curl");
    cmd.args(["-s", "--max-time", &secs]);

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
    cmd.args(["--", url]);
    cmd.kill_on_drop(true);

    let output = tokio::time::timeout(Duration::from_secs(12), cmd.output())
        .await
        .ok()?
        .ok()?;

    if !output.status.success() {
        return None;
    }

    let body = String::from_utf8(output.stdout).ok()?;
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
}
