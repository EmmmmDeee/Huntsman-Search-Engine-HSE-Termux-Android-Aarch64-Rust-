//! LeakIX host / domain exposure check. Key-gated; free tier available.
//!
//! Endpoints:
//!   * `GET https://leakix.net/host/{ip}`     (Accept: application/json)
//!   * `GET https://leakix.net/domain/{domain}` (Accept: application/json)
//!
//! Auth: `api-key: <key>` request header.
//!
//! Returns service-by-service exposure events (open SSH, leaks, known
//! vulnerabilities). We summarise the count by event type and surface
//! the most recent timestamps; individual service banners are NOT
//! stored verbatim (some include credentials).

use async_trait::async_trait;
use serde::Deserialize;

use crate::core::{
    entity::Evidence,
    error::{Error, Result},
    module::{Module, ModuleContext, ModuleCost, ModuleResult},
    scan::{Target, TargetKind},
};
use crate::util::http::error_snippet;

const KEY_ENV: &str = "HUNTSMAN_LEAKIX_KEY";

/// Subset of the LeakIX event fields we actually consume.
#[derive(Deserialize)]
struct Event {
    #[serde(default)]
    event_type: Option<String>,
    #[serde(default)]
    event_source: Option<String>,
    #[serde(default)]
    protocol: Option<String>,
    #[serde(default)]
    time: Option<String>,
    #[serde(default)]
    port: Option<i64>,
}

#[derive(Deserialize)]
struct HostResp {
    #[serde(default)]
    services: Vec<Event>,
    #[serde(default)]
    leaks: Vec<Event>,
}

pub struct LeakIx;

#[async_trait]
impl Module for LeakIx {
    fn name(&self) -> &'static str {
        "leakix"
    }
    fn description(&self) -> &'static str {
        "Host and domain exposure event analysis"
    }
    fn priority(&self) -> u8 {
        102
    }

    fn description(&self) -> &'static str {
        "LeakIX exposure events for an IP or domain — service banners (count-only) and known leaks. Key-gated."
    }
    fn cost(&self) -> ModuleCost {
        ModuleCost::KeyGated
    }
    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::IpAddress | TargetKind::Domain)
    }
    fn max_timeout_ms(&self) -> u64 {
        10_000
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let key = ctx.key(KEY_ENV)?;
        let value = target.value.trim();
        if value.is_empty() {
            return Ok(ModuleResult::new());
        }
        let path = match target.kind {
            TargetKind::IpAddress => "host",
            TargetKind::Domain => "domain",
            _ => return Ok(ModuleResult::new()),
        };
        let url = format!("https://leakix.net/{path}/{value}");
        let resp = ctx
            .http
            .get(&url)
            .header("api-key", key)
            .header("Accept", "application/json")
            .send()
            .await
            .map_err(|e| Error::module("leakix", e.to_string()))?;
        let status = resp.status();
        if status.as_u16() == 404 {
            return Ok(ModuleResult::new());
        }
        if !status.is_success() {
            return Err(Error::module(
                "leakix",
                format!("HTTP {status}: {}", error_snippet(resp).await),
            ));
        }
        let body: HostResp = resp
            .json()
            .await
            .map_err(|e| Error::module("leakix", e.to_string()))?;
        if body.services.is_empty() && body.leaks.is_empty() {
            return Ok(ModuleResult::new());
        }

        let mut entity = target.to_entity(0.88, &ctx.scan_id);
        entity.tag("leakix");
        if !body.leaks.is_empty() {
            entity.tag("leak");
        }
        if body.services.iter().any(|e| {
            e.event_type
                .as_deref()
                .is_some_and(|t| t.eq_ignore_ascii_case("ssh"))
        }) {
            entity.tag("ssh-exposed");
        }

        // Aggregate event-type counts so the evidence row stays compact
        // even when leakix returns dozens of services.
        let types: Vec<String> = body
            .services
            .iter()
            .chain(body.leaks.iter())
            .filter_map(|e| e.event_type.clone())
            .collect();
        let top = crate::util::freq::top_n(types.iter().map(String::as_str), 8);

        // Open ports across services.
        let mut ports: std::collections::BTreeSet<i64> = std::collections::BTreeSet::new();
        for e in &body.services {
            if let Some(p) = e.port {
                ports.insert(p);
            }
        }
        let port_str = ports
            .iter()
            .take(20)
            .map(i64::to_string)
            .collect::<Vec<_>>()
            .join(",");

        let mut ev = Evidence::new(
            "leakix",
            format!(
                "LeakIX exposure: {} service event(s), {} leak event(s)",
                body.services.len(),
                body.leaks.len()
            ),
        )
        .with_attr("service_count", body.services.len().to_string())
        .with_attr("leak_count", body.leaks.len().to_string());
        if !top.is_empty() {
            ev = ev.with_attr("top_event_types", top);
        }
        if !port_str.is_empty() {
            ev = ev.with_attr("ports", port_str);
        }
        // Most-recent and earliest timestamps across all events.
        let all_times: Vec<&str> = body
            .services
            .iter()
            .chain(body.leaks.iter())
            .filter_map(|e| e.time.as_deref())
            .collect();
        if let Some(t) = all_times.iter().copied().max() {
            ev = ev.with_attr("most_recent", t);
        }
        if let Some(t) = all_times.iter().copied().min() {
            ev = ev.with_attr("earliest", t);
        }

        // Aggregate event_source values across all events.
        let sources: Vec<String> = body
            .services
            .iter()
            .chain(body.leaks.iter())
            .filter_map(|e| e.event_source.clone())
            .collect();
        let top_sources = crate::util::freq::top_n(sources.iter().map(String::as_str), 8);
        if !top_sources.is_empty() {
            ev = ev.with_attr("event_sources", top_sources);
        }

        // Aggregate protocol values across all events.
        let protocols: Vec<String> = body
            .services
            .iter()
            .chain(body.leaks.iter())
            .filter_map(|e| e.protocol.clone())
            .collect();
        let top_protocols = crate::util::freq::top_n(protocols.iter().map(String::as_str), 8);
        if !top_protocols.is_empty() {
            ev = ev.with_attr("protocols", top_protocols);
        }

        entity.add_evidence(ev);
        let mut result = ModuleResult::new();
        result.push(entity);
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn accepts_ip_and_domain() {
        let m = LeakIx;
        assert!(m.accepts(&Target::new(TargetKind::IpAddress, "1.1.1.1")));
        assert!(m.accepts(&Target::new(TargetKind::Domain, "x")));
        assert!(!m.accepts(&Target::new(TargetKind::Email, "a@b")));
    }
    #[test]
    fn cost_is_key_gated() {
        assert!(matches!(LeakIx.cost(), ModuleCost::KeyGated));
    }
}
