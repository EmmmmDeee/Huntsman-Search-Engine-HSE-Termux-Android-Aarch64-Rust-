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
        let key = match ctx.key_opt(KEY_ENV) {
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
        let mut retries = 2u8;
        let body: HostResp = loop {
            let resp = ctx
                .http
                .get(&url)
                .header("api-key", key)
                .header("Accept", "application/json")
                .send_tagged(SRC)
                .await?;
            let status = resp.status();
            if status.as_u16() == 404 {
                return Ok(ModuleResult::new());
            }
            if !status.is_success() {
                let code = status.as_u16();
                if handle_keyed_error(code, resp.headers(), &mut retries, SRC, key, ctx).await {
                    continue;
                }
                return Err(crate::util::http::http_status_error(SRC, resp).await);
            }
            break crate::util::http::json_decode(SRC, resp).await?;
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

    fn body(json: &str) -> HostResp {
        serde_json::from_str(json).unwrap()
    }

    fn attr<'a>(e: &'a crate::core::entity::Entity, k: &str) -> Option<&'a str> {
        e.evidence[0].attributes.get(k).map(String::as_str)
    }

    #[test]
    fn summarises_counts_ports_and_window() {
        let b = body(
            r#"{
              "services":[
                {"event_type":"http","protocol":"tcp","event_source":"HttpPlugin",
                 "time":"2024-02-01T00:00:00Z","port":80},
                {"event_type":"http","protocol":"tcp","event_source":"HttpPlugin",
                 "time":"2024-05-01T00:00:00Z","port":443}
              ],
              "leaks":[
                {"event_type":"leak","event_source":"GitConfigPlugin",
                 "time":"2024-01-01T00:00:00Z"}
              ]
            }"#,
        );
        let e = build_exposure_entity(EntityKind::IpAddress, "1.2.3.4", &b, "s");
        assert_eq!(e.kind, EntityKind::IpAddress);
        assert!(e.has_tag("leakix") && e.has_tag("leak"));
        assert!(!e.has_tag("ssh-exposed"));
        assert_eq!(attr(&e, "service_count"), Some("2"));
        assert_eq!(attr(&e, "leak_count"), Some("1"));
        assert_eq!(attr(&e, "ports"), Some("80,443")); // sorted
        // top_event_types ranks by frequency: http(2) before leak(1).
        assert_eq!(attr(&e, "top_event_types"), Some("http×2, leak×1"));
        // Window spans every event, leaks included.
        assert_eq!(attr(&e, "most_recent"), Some("2024-05-01T00:00:00Z"));
        assert_eq!(attr(&e, "earliest"), Some("2024-01-01T00:00:00Z"));
        assert_eq!(attr(&e, "protocols"), Some("tcp×2"));
        assert_eq!(
            attr(&e, "event_sources"),
            Some("HttpPlugin×2, GitConfigPlugin×1")
        );
    }

    #[test]
    fn ssh_service_raises_ssh_exposed_tag_case_insensitively() {
        let b = body(r#"{"services":[{"event_type":"SSH","port":22}],"leaks":[]}"#);
        let e = build_exposure_entity(EntityKind::IpAddress, "1.2.3.4", &b, "s");
        assert!(e.has_tag("ssh-exposed"));
        // No leaks → no `leak` tag.
        assert!(!e.has_tag("leak"));
    }

    #[test]
    fn services_only_omits_leak_and_optional_attrs() {
        // Bare service with no metadata: counts present, every optional
        // aggregate omitted rather than emitted blank.
        let b = body(r#"{"services":[{"port":8080}],"leaks":[]}"#);
        let e = build_exposure_entity(EntityKind::Domain, "x.test", &b, "s");
        assert_eq!(e.kind, EntityKind::Domain);
        assert!(!e.has_tag("leak") && !e.has_tag("ssh-exposed"));
        assert_eq!(attr(&e, "ports"), Some("8080"));
        assert_eq!(attr(&e, "top_event_types"), None);
        assert_eq!(attr(&e, "protocols"), None);
        assert_eq!(attr(&e, "event_sources"), None);
        assert_eq!(attr(&e, "most_recent"), None);
    }

    #[test]
    fn port_list_is_capped() {
        let services: String = (0..40)
            .map(|p| format!(r#"{{"port":{}}}"#, 1000 + p))
            .collect::<Vec<_>>()
            .join(",");
        let b = body(&format!(r#"{{"services":[{services}],"leaks":[]}}"#));
        let e = build_exposure_entity(EntityKind::IpAddress, "1.2.3.4", &b, "s");
        assert_eq!(attr(&e, "ports").unwrap().split(',').count(), MAX_PORTS);
    }
}
