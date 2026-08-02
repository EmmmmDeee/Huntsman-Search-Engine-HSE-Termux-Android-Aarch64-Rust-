//! Live-API drift detection — OPT-IN, NON-BLOCKING (all tests `#[ignore]`d).
//!
//! These hit **real** third-party endpoints to catch wire-format drift in the
//! free / keyless modules: when a provider silently changes its JSON/text
//! shape, the module's parser yields nothing while the unit tests — which run
//! against canned fixtures — stay green. A drifted parser is invisible until a
//! real scan comes back empty, so this sweep surfaces it up front.
//!
//! The whole fleet is swept through one shared implementation,
//! [`huntsman_search_engine::selftest::capability_probe`], the same code that backs
//! `hse doctor --live`. Each keyless, network module is probed against a
//! canonical stable target and its outcome classified:
//!   * **alive**       — provider reached, parser produced ≥1 entity (healthy).
//!   * **empty**       — provider reached, parser produced 0 entities.
//!   * **unreachable** — transport error (provider down / device offline).
//!   * **timed-out**   — exceeded the module's own budget (provider slow/hung).
//!
//! Only a curated **canary** set (`capability_probe::CANARY_PROBES`, e.g.
//! `ip_geo` / `crtsh` / `bgpview` / `ripestat`) asserts must-yield: an `empty`
//! there is confirmed wire-format drift and **fails** the run. A non-canary
//! `empty` is only informational — its sample may legitimately have no data
//! (e.g. a breach lookup for a clean address) — so it never fails. Transport
//! and timeout outcomes are always **skips**, never failures: a third-party
//! outage or a throttled CI network can't redden the sweep, only real drift can.
//! That keeps the scheduled `.github/workflows/live-drift.yml` run's contract
//! intact — a red run is an actionable drift, never a flaky endpoint.
//!
//! The tests are `#[ignore]`d so the hermetic default suite (`cargo test --all`,
//! what PR CI runs) never touches the network. Run the live sweep with:
//!
//! ```text
//! cargo test --test live_drift -- --ignored --nocapture
//! ```

use huntsman_search_engine::selftest::capability_probe::{self, ProbeOutcome};

/// Sweep the whole keyless module fleet against live providers. Fails only on a
/// **confirmed** drift (a canary that reached its provider yet parsed nothing);
/// everything else is reported and tolerated. `--nocapture` shows the full
/// per-module table so a red run — or a healthy one — is triageable at a glance.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "live network — run via the live-drift workflow or `--ignored`"]
async fn fleet_capability_drift() {
    // Modest concurrency: enough to finish a ~100-module sweep quickly without
    // opening a socket storm on a constrained CI / mobile network.
    let reports = capability_probe::probe_keyless_fleet(8).await;
    assert!(
        !reports.is_empty(),
        "the sweep probed zero modules — registry or sample table is broken"
    );

    let mut alive = 0usize;
    let mut empty = 0usize;
    let mut unreachable = 0usize;
    let mut timed_out = 0usize;
    let mut drifted: Vec<String> = Vec::new();

    for r in &reports {
        let canary = if capability_probe::is_canary(r.module) {
            " [canary]"
        } else {
            ""
        };
        match &r.outcome {
            ProbeOutcome::Alive { found } => {
                alive += 1;
                println!("  alive        {:<22} {found} found{canary}", r.module);
            }
            ProbeOutcome::Empty => {
                empty += 1;
                println!(
                    "  empty        {:<22} ({} {}){canary}",
                    r.module,
                    r.kind.canonical_str(),
                    r.value
                );
                if r.is_confirmed_drift() {
                    drifted.push(format!(
                        "{} — {} returned 0 entities for {} {}",
                        r.module,
                        r.module,
                        r.kind.canonical_str(),
                        r.value
                    ));
                }
            }
            ProbeOutcome::Unreachable { reason } => {
                unreachable += 1;
                println!("  unreachable  {:<22} {reason}{canary}", r.module);
            }
            ProbeOutcome::TimedOut => {
                timed_out += 1;
                println!("  timed-out    {:<22}{canary}", r.module);
            }
        }
    }

    println!(
        "\nlive-drift sweep: {} probed — {alive} alive, {empty} empty, \
         {unreachable} unreachable, {timed_out} timed-out",
        reports.len()
    );

    assert!(
        drifted.is_empty(),
        "DRIFT: {} canary module(s) reached their provider but parsed zero \
         entities — the upstream wire shape likely changed:\n  {}",
        drifted.len(),
        drifted.join("\n  ")
    );
}

/// `beacondb` must never turn an unknown BSSID into a location.
///
/// This is a *safety* drift test, not a coverage one, and it is the inverse of
/// the sweep above: it asserts the module yields **nothing**. beaconDB's
/// documented fallback chain ends in an IP-based estimate of whoever is asking,
/// and that path is live — querying two BSSIDs it had never seen returned a
/// well-formed `HTTP 200` carrying the *caller's own* position, 25 km wide, on
/// another continent from the access points:
///
/// ```text
/// {"accuracy":25000,"fallback":"ipf","location":{"lat":37.7901,"lng":-122.401}}
/// ```
///
/// The module suppresses that two ways — it pins `considerIp:false` on the
/// request, and it discards any response carrying a `fallback` marker — but the
/// first of those is a promise the *server* keeps, and a unit test with a canned
/// fixture cannot notice the server breaking it. This can. A failure here means
/// live scans are at risk of reporting the operator's own location as a target
/// access point's, which is far worse than returning nothing.
///
/// The probe MAC is locally-administered (the `x2` first octet), so it belongs
/// to no manufacturer and cannot legitimately appear in a wardriving corpus —
/// any location returned for it is fabricated by definition. An outage or
/// transport error is tolerated (that is coverage, not a safety regression);
/// only an actual location is a failure.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "live network — run via the live-drift workflow or `--ignored`"]
async fn beacondb_never_fabricates_a_location_for_an_unknown_bssid() {
    use huntsman_search_engine::core::module::Module as _;
    use huntsman_search_engine::core::scan::{Target, TargetKind};

    let module = huntsman_search_engine::modules::beacondb::BeaconDb;
    let http = huntsman_search_engine::util::http::build_client();
    let ctx = huntsman_search_engine::core::module::ModuleContext {
        scan_id: "beacondb-safety-probe".into(),
        bus: tokio::sync::broadcast::channel(8).0,
        http,
        keys: std::collections::HashMap::new(),
        cancel: huntsman_search_engine::core::cancel::CancelHandle::new(),
    };
    let target = Target::new(TargetKind::MacAddress, "02:00:5e:10:00:00");

    match module.process(&target, &ctx).await {
        Ok(result) => assert!(
            result.is_empty(),
            "SAFETY DRIFT: beaconDB returned {} entit(ies) for a locally-administered \
             BSSID that cannot exist in any wardriving corpus. The IP/cell fallback \
             suppression has broken — a live scan may now report the OPERATOR's own \
             position as a target access point's. Entities: {:?}",
            result.len(),
            result
                .entities
                .iter()
                .map(|e| e.value.as_str())
                .collect::<Vec<_>>()
        ),
        // Provider down or network throttled: coverage, not a safety regression.
        Err(e) => println!("beacondb unreachable ({e}) — skipping safety assertion"),
    }
}
