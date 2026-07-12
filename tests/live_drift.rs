//! Live-API drift detection — OPT-IN, NON-BLOCKING (all tests `#[ignore]`d).
//!
//! These hit **real** third-party endpoints to catch wire-format drift in the
//! free / keyless modules: when a provider silently changes its JSON/text
//! shape, the module's parser yields nothing while the unit tests — which run
//! against canned fixtures — stay green. So a **non-empty** result means the
//! parser still understands the live response (healthy); an **empty** result
//! is the drift signal that fails the test.
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

use huntsman_search_engine::{
    core::{
        cancel::CancelHandle,
        module::{Module, ModuleContext, ModuleResult},
        scan::{Target, TargetKind},
    },
    modules,
    util::http::build_client,
};

/// A real, network-capable module context — the production SSRF-guarded client,
/// no API keys (these modules are all free / keyless). The client is built once
/// and cheaply cloned (`reqwest::Client` is internally `Arc`), so repeated
/// calls reuse one connection pool / DNS resolver rather than re-initialising.
fn live_ctx() -> ModuleContext {
    static CLIENT: std::sync::OnceLock<reqwest::Client> = std::sync::OnceLock::new();
    let (bus, _rx) = tokio::sync::broadcast::channel(8);
    ModuleContext {
        scan_id: "live-drift".into(),
        bus,
        http: CLIENT.get_or_init(build_client).clone(),
        keys: HashMap::new(),
        cancel: CancelHandle::new(),
    }
}

/// Run a module against a live target, bounded by the module's own
/// `max_timeout_ms()` — mirroring how the engine wraps `process()` in
/// production (`build_client()` only bounds *connection* establishment, so a
/// server that accepts then stalls would otherwise hang the scheduled job until
/// GitHub's multi-hour default). The three failure modes are reported
/// distinctly so a red weekly run is triageable at a glance:
///   * timeout  — provider slow/hung (not necessarily drift),
///   * transport error (DNS/TLS/connect) — provider down (not drift),
///   * Ok(result) — handed to `assert_no_drift`, where empty == drift.
async fn run_live(m: &dyn Module, kind: TargetKind, value: &str) -> ModuleResult {
    let budget = std::time::Duration::from_millis(m.max_timeout_ms());
    // Bind target + ctx so they outlive the borrowed future (a bare temporary
    // would be dropped at the end of the `let fut = …` statement).
    let target = Target::new(kind, value);
    let ctx = live_ctx();
    match tokio::time::timeout(budget, m.process(&target, &ctx)).await {
        Ok(Ok(r)) => r,
        Ok(Err(e)) => panic!(
            "{}: transport error against its live API (provider down? not necessarily drift): {e}",
            m.name()
        ),
        Err(_) => panic!(
            "{}: timed out after {} ms (provider slow/hung? not necessarily drift)",
            m.name(),
            m.max_timeout_ms()
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
// exceed that connect budget — a transport flake that would make a scheduled
// job noisy. Additional modules are added here only once verified to run
// cleanly through the real client end to end, to keep transport flakiness low.
// (Those endpoints are reachable — confirmed via raw curl — so this is purely a
// connect-budget interaction, not a defect in those modules.)
//
// Triage when this job goes red: `run_live` distinguishes the cases — a DRIFT
// assertion (empty parse) means the upstream wire shape changed and the module
// needs updating; a "transport error" / "timed out" panic means the provider
// was down or slow, which is informational, not a code defect.
