//! Live-API drift detection — OPT-IN, NON-BLOCKING (all tests `#[ignore]`d).
//!
//! These hit **real** third-party endpoints to catch wire-format drift in the
//! free / keyless modules: when a provider silently changes its JSON/text
//! shape, the module's parser yields nothing while the unit tests — which run
//! against canned fixtures — stay green. A drifted parser is invisible until a
//! real scan comes back empty, so this sweep surfaces it up front.
//!
//! The whole fleet is swept through one shared implementation,
//! [`huntsman_search_engine::util::capability_probe`], the same code that backs
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

use huntsman_search_engine::util::capability_probe::{self, ProbeOutcome};

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
