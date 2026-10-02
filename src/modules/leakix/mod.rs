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
    confidence,
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::{Module, ModuleCategory, ModuleContext, ModuleCost, ModuleResult},
    scan::{Target, TargetKind},
};

const KEY_ENV: &str = "HUNTSMAN_LEAKIX_KEY";
const SRC: &str = "leakix";

/// Subset of the LeakIX event fields we actually consume. The wire schema is
/// LeakIX's `l9format` `L9Event`, whose `port` is a STRING (`"22"`).
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
    #[serde(default, deserialize_with = "port_scalar")]
    port: Option<i64>,
}

/// A port given as a JSON string (the `L9Event` wire type) or a number. Any
/// other shape is no port, never a decode failure of the whole event.
fn port_scalar<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> std::result::Result<Option<i64>, D::Error> {
    let v = Option::<serde_json::Value>::deserialize(d)?;
    Ok(v.as_ref()
        .and_then(crate::util::json::scalar_str)
        .and_then(|s| s.trim().parse::<i64>().ok()))
}

/// The host/domain response. LeakIX's wire keys are **`Services`** and
/// **`Leaks`**, capitalised and nullable: its server serialises the Go
/// `HostResult` struct's untagged fields, and its official Python client
/// (`leakix` 1.1.0, `HostResult.Services` / `.Leaks`) reads exactly those. The
/// struct read lowercase `services`/`leaks` only, so every real response
/// decoded as two empty lists and every lookup was a clean "no exposure"
/// (REQ-LEAKIX-001). The lowercase spellings are kept as aliases.
#[derive(Deserialize)]
struct HostResp {
    #[serde(rename = "Services", alias = "services", default)]
    services: Option<Vec<Event>>,
    #[serde(rename = "Leaks", alias = "leaks", default)]
    leaks: Option<Vec<Event>>,
}

impl HostResp {
    fn services(&self) -> &[Event] {
        self.services.as_deref().unwrap_or(&[])
    }

    fn leaks(&self) -> &[Event] {
        self.leaks.as_deref().unwrap_or(&[])
    }
}

/// The module's result for one 2xx body. **Pure** — the seam `process()`
/// returns through.
///
/// Fails closed on a body that carries NEITHER key, in either spelling. That is
/// not "no exposure": it is a shape this decoder does not recognise (an error
/// envelope, schema drift, a challenge page that happens to be JSON), and
/// reading it as an empty answer is exactly how the capitalisation defect stayed
/// invisible. A body that carries the keys with `null` or `[]` is the real
/// "nothing indexed" answer and stays a clean negative.
fn leakix_result(
    kind: EntityKind,
    value: &str,
    raw: serde_json::Value,
    scan_id: &str,
) -> Result<ModuleResult> {
    let recognised = raw.as_object().is_some_and(|o| {
        ["Services", "Leaks", "services", "leaks"]
            .iter()
            .any(|k| o.contains_key(*k))
    });
    if !recognised {
        return Err(crate::core::error::Error::module(
            SRC,
            "LeakIX answered 200 with a body carrying neither `Services` nor `Leaks` — an unrecognised shape, not a clean \"no exposure\"",
        ));
    }
    let body: HostResp = serde_json::from_value(raw).map_err(|e| {
        crate::core::error::Error::module(SRC, format!("LeakIX body did not decode: {e}"))
    })?;
    let mut result = ModuleResult::new();
    if body.services().is_empty() && body.leaks().is_empty() {
        return Ok(result);
    }
    result.push(build_exposure_entity(kind, value, &body, scan_id));
    Ok(result)
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
    let mut entity = Entity::new(kind, value, confidence::EXPERT, scan_id);
    entity.tag("leakix");
    if !body.leaks().is_empty() {
        entity.tag("leak");
    }
    // In L9 events the service is named by `protocol` (`"ssh"`); `event_type`
    // is the event class (`"service"`, `"leak"`). Both are read, so neither
    // spelling can hide an exposed SSH service.
    if body.services().iter().any(|e| {
        [e.protocol.as_deref(), e.event_type.as_deref()]
            .into_iter()
            .flatten()
            .any(|t| t.eq_ignore_ascii_case("ssh"))
    }) {
        entity.tag("ssh-exposed");
    }

    let all = || body.services().iter().chain(body.leaks().iter());

    // Aggregate event-type counts so the evidence row stays compact even when
    // leakix returns dozens of services.
    let top = crate::util::freq::top_n(all().filter_map(|e| e.event_type.as_deref()), TOP_N);

    // Open ports across services, sorted + deduplicated.
    let ports: std::collections::BTreeSet<i64> =
        body.services().iter().filter_map(|e| e.port).collect();
    let total_ports = ports.len();
    let ports_capped = total_ports > MAX_PORTS;
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
            body.services().len(),
            body.leaks().len()
        ),
    )
    .with_attr("service_count", body.services().len().to_string())
    .with_attr("leak_count", body.leaks().len().to_string());
    if !top.is_empty() {
        ev = ev.with_attr("top_event_types", top);
    }
    if !port_str.is_empty() {
        ev = ev.with_attr("ports", port_str);
        ev = ev.with_attr("total_ports", total_ports.to_string());
        if ports_capped {
            ev = ev.with_attr("ports_capped", "true");
            entity.tag("truncated");
        }
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
        "LeakIX exposure recon — correlates host and domain exposure events to surface leaks"
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
            // PROVIDER FAILURE != ZERO EVIDENCE: returning Ok(empty) here made
            // dispatch record ModuleDone { found: 0 }, which coverage reads as a
            // CleanNegative -- "queried, holds nothing on this subject" -- for a
            // provider that was never asked. Error::MissingKey is the contract
            // (REQ-KEYSKIP-001).
            None => return Err(crate::core::error::Error::MissingKey(KEY_ENV.into())),
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
        // Key cascade via the shared primitive: on a terminal key quota/auth
        // failure, rotate to the next untried usable pooled key so one call
        // spends every credential the pool holds. `absent_statuses: &[404]` —
        // LeakIX answers an unindexed host with 404, a clean miss rather than
        // an error, exactly as this module treated it before.
        let Some(resp) =
            crate::util::http::keyed_cascade(ctx, SRC, KEY_ENV, initial_key, &[404], |key| {
                ctx.http
                    .get(&url)
                    .header("api-key", key)
                    .header("Accept", "application/json")
            })
            .await?
        else {
            return Ok(ModuleResult::new());
        };
        // json_scanned: leakix responses contain exposure/credential data —
        // scan the raw body for embedded API keys.
        let raw: serde_json::Value = crate::util::http::json_scanned(resp, SRC).await?;
        leakix_result(target.kind.to_entity_kind(), value, raw, &ctx.scan_id)
    }
}

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
