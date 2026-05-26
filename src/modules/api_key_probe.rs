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
    module::{Module, ModuleContext, ModuleCost, ModuleResult},
    scan::{Target, TargetKind},
};
use crate::util::key_pool::{self, KeyEntry, KeyStatus};

pub struct ApiKeyProbe;

fn truncate_safe(s: &str, max: usize) -> &str {
    if s.len() <= max {
        return s;
    }
    let mut end = max;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

type UrlBuilderFn = fn(&str) -> (String, Vec<(&'static str, String)>);

struct Probe {
    service: &'static str,
    category: &'static str,
    env_var: &'static str,
    url_builder: UrlBuilderFn,
    parse_info: fn(&Value) -> Vec<(String, String)>,
}

fn probes() -> Vec<Probe> {
    vec![
        Probe {
            service: "shodan",
            category: "infrastructure",
            env_var: "HUNTSMAN_SHODAN_KEY",
            url_builder: |key| (format!("https://api.shodan.io/api-info?key={key}"), vec![]),
            parse_info: |v| {
                let mut out = Vec::new();
                if let Some(p) = v.get("plan").and_then(|v| v.as_str()) {
                    out.push(("plan".into(), p.to_string()));
                }
                if let Some(c) = v.get("query_credits").and_then(serde_json::Value::as_u64) {
                    out.push(("query_credits".into(), c.to_string()));
                }
                if let Some(c) = v.get("scan_credits").and_then(serde_json::Value::as_u64) {
                    out.push(("scan_credits".into(), c.to_string()));
                }
                out
            },
        },
        Probe {
            service: "virustotal",
            category: "threat_intel",
            env_var: "HUNTSMAN_VIRUSTOTAL_KEY",
            url_builder: |_key| {
                (
                    "https://www.virustotal.com/api/v3/users/me".into(),
                    vec![("x-apikey", String::new())],
                )
            },
            parse_info: |v| {
                let mut out = Vec::new();
                if let Some(data) = v.get("data").and_then(|d| d.get("attributes")) {
                    if let Some(q) = data.get("quotas")
                        && let Some(api) = q.get("api_requests_daily")
                        && let Some(allowed) =
                            api.get("allowed").and_then(serde_json::Value::as_u64)
                    {
                        out.push(("daily_quota".into(), allowed.to_string()));
                    }
                    if let Some(p) = data.get("privileges") {
                        out.push(("privileges".into(), format!("{p}")));
                    }
                }
                out
            },
        },
        Probe {
            service: "intelx",
            category: "breach",
            env_var: "HUNTSMAN_INTELX_KEY",
            url_builder: |_key| {
                (
                    "https://2.intelx.io/authenticate/info".into(),
                    vec![("x-key", String::new())],
                )
            },
            parse_info: |v| {
                let mut out = Vec::new();
                if let Some(n) = v.get("Name").and_then(|v| v.as_str()) {
                    out.push(("account_name".into(), n.to_string()));
                }
                if let Some(c) = v.get("CreditBalance").and_then(serde_json::Value::as_i64) {
                    out.push(("credit_balance".into(), c.to_string()));
                }
                if let Some(p) = v.get("MaxCredits").and_then(serde_json::Value::as_i64) {
                    out.push(("max_credits".into(), p.to_string()));
                }
                out
            },
        },
        Probe {
            service: "securitytrails",
            category: "infrastructure",
            env_var: "HUNTSMAN_SECTRAILS_KEY",
            url_builder: |_key| {
                (
                    "https://api.securitytrails.com/v1/ping".into(),
                    vec![("APIKEY", String::new())],
                )
            },
            parse_info: |v| {
                let mut out = Vec::new();
                if v.get("success").and_then(serde_json::Value::as_bool) == Some(true) {
                    out.push(("status".into(), "authenticated".into()));
                }
                out
            },
        },
        Probe {
            service: "hunter",
            category: "identity",
            env_var: "HUNTSMAN_HUNTER_KEY",
            url_builder: |key| {
                (
                    format!("https://api.hunter.io/v2/account?api_key={key}"),
                    vec![],
                )
            },
            parse_info: |v| {
                let mut out = Vec::new();
                if let Some(data) = v.get("data") {
                    if let Some(p) = data.get("plan_name").and_then(|v| v.as_str()) {
                        out.push(("plan".into(), p.to_string()));
                    }
                    if let Some(r) = data.get("requests")
                        && let Some(avail) = r
                            .get("searches")
                            .and_then(|s| s.get("available"))
                            .and_then(serde_json::Value::as_u64)
                    {
                        out.push(("searches_available".into(), avail.to_string()));
                    }
                }
                out
            },
        },
        Probe {
            service: "leakix",
            category: "breach",
            env_var: "HUNTSMAN_LEAKIX_KEY",
            url_builder: |_key| {
                (
                    "https://leakix.net/api/subdomains/example.com".into(),
                    vec![("api-key", String::new())],
                )
            },
            parse_info: |_v| vec![("status".into(), "authenticated".into())],
        },
        Probe {
            service: "ipqs",
            category: "threat_intel",
            env_var: "HUNTSMAN_IPQS_KEY",
            url_builder: |key| {
                (
                    format!("https://ipqualityscore.com/api/json/account/{key}"),
                    vec![],
                )
            },
            parse_info: |v| {
                let mut out = Vec::new();
                if let Some(c) = v.get("credits").and_then(serde_json::Value::as_u64) {
                    out.push(("credits".into(), c.to_string()));
                }
                if let Some(p) = v.get("plan").and_then(|v| v.as_str()) {
                    out.push(("plan".into(), p.to_string()));
                }
                out
            },
        },
        Probe {
            service: "criminal_ip",
            category: "threat_intel",
            env_var: "HUNTSMAN_CRIMINALIP_KEY",
            url_builder: |_key| {
                (
                    "https://api.criminalip.io/v1/user/me".into(),
                    vec![("x-api-key", String::new())],
                )
            },
            parse_info: |v| {
                let mut out = Vec::new();
                if let Some(data) = v.get("data")
                    && let Some(p) = data.get("plan").and_then(|v| v.as_str())
                {
                    out.push(("plan".into(), p.to_string()));
                }
                out
            },
        },
        Probe {
            service: "numverify",
            category: "identity",
            env_var: "HUNTSMAN_NUMVERIFY_KEY",
            url_builder: |key| {
                (
                    format!(
                        "https://apilayer.net/api/validate?number=14158586273&access_key={key}"
                    ),
                    vec![],
                )
            },
            parse_info: |v| {
                let mut out = Vec::new();
                if v.get("valid").and_then(serde_json::Value::as_bool) == Some(true) {
                    out.push(("status".into(), "authenticated".into()));
                }
                out
            },
        },
        Probe {
            service: "wigle",
            category: "geoint",
            env_var: "HUNTSMAN_WIGLE_TOKEN",
            url_builder: |_key| {
                (
                    "https://api.wigle.net/api/v2/profile/user".into(),
                    vec![("Authorization", "Basic".to_string())],
                )
            },
            parse_info: |v| {
                let mut out = Vec::new();
                if let Some(u) = v.get("userid").and_then(|v| v.as_str()) {
                    out.push(("userid".into(), u.to_string()));
                }
                out
            },
        },
        Probe {
            service: "hibp",
            category: "breach",
            env_var: "HUNTSMAN_HIBP_KEY",
            url_builder: |_key| {
                (
                    "https://haveibeenpwned.com/api/v3/breaches".into(),
                    vec![("hibp-api-key", String::new())],
                )
            },
            parse_info: |_v| vec![("status".into(), "authenticated".into())],
        },
        Probe {
            service: "abuseipdb",
            category: "threat_intel",
            env_var: "HUNTSMAN_ABUSEIPDB_KEY",
            url_builder: |_key| {
                (
                    "https://api.abuseipdb.com/api/v2/check?ipAddress=8.8.8.8&maxAgeInDays=1"
                        .into(),
                    vec![("Key", String::new())],
                )
            },
            parse_info: |v| {
                let mut out = Vec::new();
                if v.get("data").is_some() {
                    out.push(("status".into(), "authenticated".into()));
                }
                out
            },
        },
        Probe {
            service: "censys",
            category: "infrastructure",
            env_var: "HUNTSMAN_CENSYS_KEY",
            url_builder: |_key| {
                // Censys uses HTTP Basic Auth with API_ID:API_SECRET
                // The key value should be "id:secret" format
                (
                    "https://search.censys.io/api/v2/hosts/1.1.1.1".into(),
                    vec![("_basic_auth", String::new())],
                )
            },
            parse_info: |v| {
                let mut out = Vec::new();
                if let Some(ip) = v.get("ip").and_then(|v| v.as_str()) {
                    out.push(("status".into(), "authenticated".into()));
                    out.push(("test_ip".into(), ip.to_string()));
                }
                out
            },
        },
        Probe {
            service: "binaryedge",
            category: "infrastructure",
            env_var: "HUNTSMAN_BINARYEDGE_KEY",
            url_builder: |_key| {
                (
                    "https://api.binaryedge.io/v2/user/subscription".into(),
                    vec![("X-Key", String::new())],
                )
            },
            parse_info: |v| {
                let mut out = Vec::new();
                if let Some(p) = v
                    .get("subscription")
                    .and_then(|s| s.get("name"))
                    .and_then(|v| v.as_str())
                {
                    out.push(("plan".into(), p.to_string()));
                }
                if let Some(c) = v.get("requests_left").and_then(serde_json::Value::as_u64) {
                    out.push(("requests_left".into(), c.to_string()));
                }
                out
            },
        },
        Probe {
            service: "greynoise",
            category: "threat_intel",
            env_var: "HUNTSMAN_GREYNOISE_KEY",
            url_builder: |_key| {
                // Use the paid v3 IP endpoint — community endpoint works
                // without auth and would cause false positives
                (
                    "https://api.greynoise.io/v3/ip/8.8.8.8".into(),
                    vec![("key", String::new())],
                )
            },
            parse_info: |v| {
                let mut out = Vec::new();
                if v.get("ip").is_some() && v.get("seen").is_some() {
                    out.push(("status".into(), "authenticated".into()));
                    if let Some(c) = v.get("classification").and_then(|v| v.as_str()) {
                        out.push(("classification".into(), c.to_string()));
                    }
                }
                out
            },
        },
        Probe {
            service: "fullhunt",
            category: "infrastructure",
            env_var: "HUNTSMAN_FULLHUNT_KEY",
            url_builder: |_key| {
                (
                    "https://fullhunt.io/api/v1/auth/status".into(),
                    vec![("X-API-KEY", String::new())],
                )
            },
            parse_info: |v| {
                let mut out = Vec::new();
                if let Some(u) = v
                    .get("user")
                    .and_then(|u| u.get("plan"))
                    .and_then(|v| v.as_str())
                {
                    out.push(("plan".into(), u.to_string()));
                }
                if let Some(c) = v
                    .get("user")
                    .and_then(|u| u.get("credits"))
                    .and_then(|u| u.get("remaining"))
                    .and_then(serde_json::Value::as_u64)
                {
                    out.push(("credits_remaining".into(), c.to_string()));
                }
                out
            },
        },
        Probe {
            service: "urlscan",
            category: "threat_intel",
            env_var: "HUNTSMAN_URLSCAN_KEY",
            url_builder: |_key| {
                (
                    "https://urlscan.io/api/v1/search/?q=domain:example.com&size=1".into(),
                    vec![("API-Key", String::new())],
                )
            },
            parse_info: |v| {
                let mut out = Vec::new();
                if v.get("results").is_some() {
                    out.push(("status".into(), "authenticated".into()));
                }
                out
            },
        },
        Probe {
            service: "passivetotal",
            category: "infrastructure",
            env_var: "HUNTSMAN_PASSIVETOTAL_KEY",
            url_builder: |_key| {
                (
                    "https://api.passivetotal.org/v2/account/quota".into(),
                    vec![("_basic_auth", String::new())],
                )
            },
            parse_info: |v| {
                let mut out = Vec::new();
                if let Some(u) = v
                    .get("user")
                    .and_then(|u| u.get("owner"))
                    .and_then(|v| v.as_str())
                {
                    out.push(("owner".into(), u.to_string()));
                }
                out
            },
        },
        Probe {
            service: "onyphe",
            category: "infrastructure",
            env_var: "HUNTSMAN_ONYPHE_KEY",
            url_builder: |_key| {
                (
                    "https://www.onyphe.io/api/v2/simple/whois/best/8.8.8.8".into(),
                    vec![("Authorization", "bearer".to_string())],
                )
            },
            parse_info: |v| {
                let mut out = Vec::new();
                if v.get("count").is_some() {
                    out.push(("status".into(), "authenticated".into()));
                }
                out
            },
        },
        Probe {
            service: "zoomeye",
            category: "infrastructure",
            env_var: "HUNTSMAN_ZOOMEYE_KEY",
            url_builder: |_key| {
                (
                    "https://api.zoomeye.org/resources-info".into(),
                    vec![("API-KEY", String::new())],
                )
            },
            parse_info: |v| {
                let mut out = Vec::new();
                if let Some(p) = v.get("plan").and_then(|v| v.as_str()) {
                    out.push(("plan".into(), p.to_string()));
                }
                if let Some(c) = v
                    .get("resources")
                    .and_then(|r| r.get("search"))
                    .and_then(serde_json::Value::as_u64)
                {
                    out.push(("search_credits".into(), c.to_string()));
                }
                out
            },
        },
        Probe {
            service: "netlas",
            category: "infrastructure",
            env_var: "HUNTSMAN_NETLAS_KEY",
            url_builder: |_key| {
                (
                    "https://app.netlas.io/api/users/current/".into(),
                    vec![("X-API-Key", String::new())],
                )
            },
            parse_info: |v| {
                let mut out = Vec::new();
                if v.get("email").is_some() {
                    out.push(("status".into(), "authenticated".into()));
                }
                out
            },
        },
        Probe {
            service: "pulsedive",
            category: "threat_intel",
            env_var: "HUNTSMAN_PULSEDIVE_KEY",
            url_builder: |key| {
                (
                    format!("https://pulsedive.com/api/info.php?indicator=pulsedive.com&key={key}"),
                    vec![],
                )
            },
            parse_info: |v| {
                let mut out = Vec::new();
                if v.get("indicator").is_some() {
                    out.push(("status".into(), "authenticated".into()));
                }
                out
            },
        },
        Probe {
            service: "emailrep",
            category: "identity",
            env_var: "HUNTSMAN_EMAILREP_KEY",
            url_builder: |_key| {
                (
                    "https://emailrep.io/test@example.com".into(),
                    vec![("Key", String::new())],
                )
            },
            parse_info: |v| {
                let mut out = Vec::new();
                if v.get("reputation").is_some() {
                    out.push(("status".into(), "authenticated".into()));
                }
                out
            },
        },
    ]
}

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
                format!("{}:{}", probe.service, truncate_safe(key, 12)),
                0.95,
                &ctx.scan_id,
            );
            entity.tag(format!("service:{}", probe.service));
            entity.tag(format!("category:{}", probe.category));
            entity.tag("api-key");
            entity.tag("validated");

            let mut ev = Evidence::new(
                "api_key_probe",
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
                "api_key_probe",
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
