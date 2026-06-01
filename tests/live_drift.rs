//! Live-API drift detection — OPT-IN, NON-BLOCKING (all tests `#[ignore]`d).
//!
//! These hit **real** third-party endpoints to catch wire-format drift in the
//! free / keyless modules: when a provider silently changes its JSON/text
//! shape, the module's parser yields nothing while the unit tests — which run
//! against canned fixtures — stay green. A non-empty result is the drift signal.
//!
//! They are `#[ignore]`d so the hermetic default suite (`cargo test --all`,
//! what PR CI runs) never touches the network. The dedicated
//! `.github/workflows/live-drift.yml` job runs them weekly + on manual dispatch
//! with `--ignored`, so a third-party outage can never fail a pull request.
//! Run locally:
//!
//! ```text
//! cargo test --test live_drift -- --ignored --nocapture
//! ```
//!
//! Scope: only free, keyless modules whose endpoints are stable enough for a
//! scheduled check. Keyed modules need a secrets-gated variant (not here).
//! Each module runs through the **real** SSRF-guarded `build_client()` — the
//! same client production uses — so this also exercises the live transport
//! path, not just parsing.

use std::collections::HashMap;
use std::sync::Arc;

use huntsman_search_engine::{
    core::{
        cancel::CancelHandle,
        module::{Module, ModuleContext, ModuleResult},
        scan::{Target, TargetKind},
    },
    modules,
    util::{http::build_client, proxy::ProxyPool},
};

/// A real, network-capable module context — the production SSRF-guarded client,
/// no API keys (these modules are all free / keyless).
fn live_ctx() -> ModuleContext {
    let (bus, _rx) = tokio::sync::broadcast::channel(8);
    ModuleContext {
        scan_id: "live-drift".into(),
        bus,
        http: build_client(),
        keys: HashMap::new(),
        cancel: CancelHandle::new(),
        proxy_pool: Arc::new(ProxyPool::new()),
    }
}

/// Run a module against a live target. A transport error (timeout, DNS, TLS)
/// is reported distinctly from a drift (a clean response that parsed to zero
/// entities) so a failing scheduled run is diagnosable at a glance.
async fn run_live(m: &dyn Module, kind: TargetKind, value: &str) -> ModuleResult {
    match m.process(&Target::new(kind, value), &live_ctx()).await {
        Ok(r) => r,
        Err(e) => panic!(
            "{}: transport error against its live API (not necessarily drift): {e}",
            m.name()
        ),
    }
}

/// Assert a live module produced at least one entity, with a drift-specific
/// message naming the provider so a scheduled-run failure is actionable.
fn assert_no_drift(m_name: &str, provider: &str, r: &ModuleResult) {
    assert!(
        !r.entities.is_empty(),
        "{m_name} DRIFT: {provider} returned a response that parsed to zero \
         entities — the upstream wire shape likely changed"
    );
}

#[tokio::test]
#[ignore = "live network — run via the live-drift workflow or `--ignored`"]
async fn ip_geo_drift() {
    // ip-api.com IP geolocation for a stable, well-known public IP.
    let r = run_live(&modules::ip_geo::IpGeo, TargetKind::IpAddress, "8.8.8.8").await;
    assert_no_drift("ip_geo", "ip-api.com", &r);
}

// NOTE — why only ip_geo (for now):
// The drift tests run through the production `build_client()`, whose 5 s
// `connect_timeout` is tuned for real mobile links. In throttled / sandboxed
// CI networks, plain-HTTP `ip_geo` (ip-api.com) connects reliably, but several
// HTTPS free endpoints (e.g. api.hackertarget.com, dns.google DoH) intermittently
// exceed that connect budget — a transport flake indistinguishable from genuine
// drift, which would make a scheduled job noisy. Additional modules are added
// here only once verified to run cleanly through the real client end to end, so
// a red live-drift run always means "upstream changed", never "CI network was
// slow". (The HTTPS endpoints are reachable — confirmed via raw curl — so this
// is purely a connect-budget interaction, not a defect in those modules.)
