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
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::{Module, ModuleCategory, ModuleContext, ModuleCost, ModuleResult},
    scan::{Target, TargetKind},
};
use crate::util::http::RequestBuilderExt;
use crate::util::http::handle_keyed_error;

const KEY_ENV: &str = "HUNTSMAN_LEAKIX_KEY";
const SRC: &str = "leakix";

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

/// Per-attribute cap: a top-N frequency list (event types, sources, protocols)
/// this long is plenty of signal without letting a noisy host bloat the row.
const TOP_N: usize = 8;
/// Cap on the open-port list — same rationale.
const MAX_PORTS: usize = 20;

/// Build the exposure entity from a LeakIX host/domain response. **Pure** (no
/// network/IO): summarises the service + leak events into compact, capped,
/// deterministically-ordered evidence attributes (top event types / sources /
/// protocols by frequency, the sorted open-port set, and the earliest/most-recent
/// timestamps), and raises the `leak` / `ssh-exposed` tags. Caller guarantees the
/// response carries at least one service or leak event.
fn build_exposure_entity(kind: EntityKind, value: &str, body: &HostResp, scan_id: &str) -> Entity {
    let mut entity = Entity::new(kind, value, 0.88, scan_id);
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

    let all = || body.services.iter().chain(body.leaks.iter());

    // Aggregate event-type counts so the evidence row stays compact even when
    // leakix returns dozens of services.
    let top = crate::util::freq::top_n(all().filter_map(|e| e.event_type.as_deref()), TOP_N);

    // Open ports across services, sorted + deduplicated.
    let ports: std::collections::BTreeSet<i64> =
        body.services.iter().filter_map(|e| e.port).collect();
    let port_str = ports
        .iter()
        .take(MAX_PORTS)
        .map(i64::to_string)
        .collect::<Vec<_>>()
        .join(",");

    let mut ev = Evidence::new(
        SRC,
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
    if let Some(t) = all().filter_map(|e| e.time.as_deref()).max() {
        ev = ev.with_attr("most_recent", t);
    }
    if let Some(t) = all().filter_map(|e| e.time.as_deref()).min() {
        ev = ev.with_attr("earliest", t);
    }

    let top_sources =
        crate::util::freq::top_n(all().filter_map(|e| e.event_source.as_deref()), TOP_N);
    if !top_sources.is_empty() {
        ev = ev.with_attr("event_sources", top_sources);
    }

    let top_protocols =
        crate::util::freq::top_n(all().filter_map(|e| e.protocol.as_deref()), TOP_N);
    if !top_protocols.is_empty() {
        ev = ev.with_attr("protocols", top_protocols);
    }

    entity.add_evidence(ev);
    entity
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

    fn cost(&self) -> ModuleCost {
        ModuleCost::KeyGated
    }
    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::IpAddress | TargetKind::Domain)
    }
    fn max_timeout_ms(&self) -> u64 {
        10_000
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Breach
    }

    fn attack_techniques(&self) -> &'static [&'static str] {
        // LeakIX is an internet-wide scan-results / exposure database, so beyond
        // the Breach default (T1589.001 Credentials + T1589.002 Email, for the
        // leak events) it is Search Open Technical Databases: Scan Databases
        // (T1596.005). The exposed-service host is also surfaced as an IpAddress
        // entity → T1590.005 IP Addresses. Superset of the default.
        &["T1589.001", "T1589.002", "T1590.005", "T1596.005"]
    }

    fn produces(&self) -> &'static [crate::core::entity::EntityKind] {
        use crate::core::entity::EntityKind;
        const KINDS: &[EntityKind] = &[EntityKind::IpAddress, EntityKind::Domain];
        KINDS
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let initial_key = match ctx.key_opt(KEY_ENV) {
            Some(k) => k,
            None => return Ok(ModuleResult::new()),
        };
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
        // Key cascade: start on the hot-injected key and, on a terminal
        // 401/403/429, rotate to the next usable pooled LeakIX key and retry, so
        // one process() call spends every credential the pool holds before it
        // gives up. `tried` prevents re-handing a burned key.
        let mut tried: std::collections::HashSet<String> = std::collections::HashSet::new();
        let mut key = initial_key.to_string();
        let body: HostResp = 'cascade: loop {
            tried.insert(key.clone());
            let mut retries = 2u8;
            loop {
                if ctx.cancel.is_cancelled() {
                    return Ok(ModuleResult::new());
                }
                let resp = ctx
                    .http
                    .get(&url)
                    .header("api-key", &key)
                    .header("Accept", "application/json")
                    .send_tagged(SRC)
                    .await?;
                let status = resp.status();
                if status.as_u16() == 404 {
                    return Ok(ModuleResult::new());
                }
                if !status.is_success() {
                    let code = status.as_u16();
                    if handle_keyed_error(code, resp.headers(), &mut retries, SRC, &key, ctx).await {
                        continue;
                    }
                    if crate::util::http::is_keyed_error_status(code)
                        && let Some(next) = ctx.next_pooled_key(SRC, &tried)
                    {
                        key = next;
                        continue 'cascade;
                    }
                    return Err(crate::util::http::http_status_error(SRC, resp).await);
                }
                // json_scanned: leakix responses contain exposure/credential data —
                // scan the raw body for embedded API keys.
                break 'cascade crate::util::http::json_scanned(resp, SRC)
                    .await
                    .map_err(|e| crate::core::error::Error::module(SRC, e))?;
            }
        };
        if body.services.is_empty() && body.leaks.is_empty() {
            return Ok(ModuleResult::new());
        }

        let mut result = ModuleResult::new();
        result.push(build_exposure_entity(
            target.kind.to_entity_kind(),
            value,
            &body,
            &ctx.scan_id,
        ));
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
