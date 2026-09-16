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
//!   * **rate-limited** — the provider answered with a throttle (alive, asking
//!     for less): never drift, never a dead canary, never retried within a run.
//!   * **blocked**     — the provider's edge refused this client with an
//!     anti-bot challenge / WAF block page (alive, refusing): never drift,
//!     never a dead canary, never retried within a run — a wall is per client.
//!   * **skipped**     — the module declined the sample target in-band (a typed
//!     skip: an Australia-only register with the fleet's New York point, auDA's
//!     RDAP with a `.com`): never asked, so never drift, never a dead canary.
//!   * **panicked**    — the module's parser crashed on the live response.
//!
//! Only a curated **canary** set (`capability_probe::CANARY_PROBES`, e.g.
//! `ip_geo` / `crtsh` / `ip_registry` / `ripestat`) asserts must-yield: an `empty`
//! there is confirmed wire-format drift and **fails** the run. A non-canary
//! `empty` is only informational — its sample may legitimately have no data
//! (e.g. a breach lookup for a clean address) — so it never fails. A
//! non-canary's transport or timeout outcome is always a **skip**, never a
//! failure: a third-party outage or a throttled CI network can't redden the
//! sweep. A canary that answers nothing on any of its retried attempts is a
//! **dead canary** reading — an outage or a retired endpoint — and the run
//! fails on it only once the memory of earlier sweeps
//! (`capability_probe::judge_dead_canaries`; the workflow carries the memory
//! between runs as an artifact) shows the same canary dead at least
//! `DEAD_CANARY_CONFIRMATION_SECS` earlier with no answer between: a first
//! reading is reported (a warning annotation on the runner) and tolerated,
//! and a sweep that reached no provider at all fails as an offline vantage,
//! never as dead providers. A **panicked** outcome always **fails**, canary or
//! not — unlike `empty`, there is no legitimate reason a live response should
//! crash the parser. Every keyless network module is also probed, for each
//! kind it consumes among Username, Domain, Email and FullName, with a
//! well-formed target nobody holds (`capability_probe::probe_negative_controls`,
//! the sweep's **known-negative controls**): the only honest yield is nothing,
//! or the target itself carrying an annotation below the rung at which a
//! module asserts a target is real, and a module that mints anything else for
//! it is a **fabrication**, which **fails** the run like drift does. That keeps the scheduled
//! `.github/workflows/live-drift.yml` run's contract intact — a red run is an
//! actionable drift, a confirmed dead canary or a fabrication, never a flaky
//! endpoint.
//!
//! The tests are `#[ignore]`d so the hermetic default suite (`cargo test --all`,
//! what PR CI runs) never touches the network. Run the live sweep with:
//!
//! ```text
//! cargo test --test live_drift -- --ignored --nocapture
//! ```

use huntsman_search_engine::selftest::capability_probe::{self, ProbeOutcome};

/// Sweep the whole keyless module fleet against live providers. Fails on a
/// **confirmed** drift (a canary that reached its provider yet parsed nothing,
/// or any module that panicked) and on a **confirmed dead canary** (a canary
/// whose provider gave no answer on any of its retried attempts, in this sweep
/// and in one at least a day earlier — down across sweeps, or retired); a first
/// dead reading and everything else is reported and tolerated. `--nocapture`
/// shows the full per-module table so a red run — or a healthy one — is
/// triageable at a glance.
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
    let mut rate_limited = 0usize;
    let mut blocked = 0usize;
    let mut skipped = 0usize;
    let mut panicked = 0usize;
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
            ProbeOutcome::RateLimited { reason } => {
                rate_limited += 1;
                println!("  rate-limited {:<22} {reason}{canary}", r.module);
            }
            ProbeOutcome::Blocked { reason } => {
                blocked += 1;
                println!("  blocked      {:<22} {reason}{canary}", r.module);
            }
            ProbeOutcome::Skipped { class, reason } => {
                skipped += 1;
                println!(
                    "  skipped      {:<22} ({}) {reason}{canary}",
                    r.module,
                    class.as_str()
                );
            }
            ProbeOutcome::Panicked { message } => {
                panicked += 1;
                println!("  panicked     {:<22} {message}{canary}", r.module);
                // Unconditional, canary or not — see the module doc comment.
                drifted.push(format!(
                    "{} — panicked while probing {} {}: {message}",
                    r.module,
                    r.kind.canonical_str(),
                    r.value
                ));
            }
        }
    }

    println!(
        "\nlive-drift sweep: {} probed — {alive} alive, {empty} empty, \
         {unreachable} unreachable, {timed_out} timed-out, {rate_limited} rate-limited, \
         {blocked} blocked, {skipped} skipped, {panicked} panicked",
        reports.len()
    );

    let drift_msg = if drifted.is_empty() {
        String::new()
    } else {
        format!(
            "DRIFT: {} module(s) confirmed broken against their live provider — a \
             canary that parsed zero entities, and/or a module that panicked — the \
             upstream wire shape likely changed:\n  {}\n",
            drifted.len(),
            drifted.join("\n  ")
        )
    };
    // A sweep that reached no provider at all is a reading of this vantage
    // (no egress, no signal), not of the providers: it must never pass as
    // "nothing confirmed dead", and it is not their verdict either.
    assert!(
        alive > 0,
        "the sweep reached no provider at all — this vantage is offline, not the providers"
    );

    // A canary that gave no answer on any attempt is not drift (its wire shape
    // was never seen) and not a flaky endpoint either (the probe already
    // retried). But one sweep's reading — three attempts over six seconds —
    // cannot tell an outage from a retired endpoint: `crtsh` answered `502`
    // three times at 22:01 on 2026-09-15 and `200` four minutes later. The
    // judgement is the memory's (`judge_dead_canaries`, carried between runs
    // by the workflow as an artifact): a first reading is reported here and
    // tolerated, and only a canary dead now and on a sweep at least
    // `DEAD_CANARY_CONFIRMATION_SECS` earlier, with no answer between, is the
    // confirmed verdict this test fails on. That verdict used to be one
    // reading, and before REQ-DRIFT-001 there was none at all —
    // `api.bgpview.io` lost its DNS and the (since retired) `bgpview` canary
    // read "unreachable" on every weekly run while this test stayed green.
    let verdicts = capability_probe::judge_dead_canaries(&reports);
    let (confirmed, provisional): (Vec<_>, Vec<_>) =
        verdicts.iter().partition(|d| d.is_confirmed());
    for d in &provisional {
        println!("  provisional dead canary: {}", d.describe());
        // A warning annotation on the run's summary page, so a first reading
        // is visible without opening the log; a plain line anywhere else.
        if std::env::var_os("GITHUB_ACTIONS").is_some() {
            println!(
                "::warning title=Dead canary, first reading::{}",
                d.describe()
            );
        }
    }
    let dead_msg = if confirmed.is_empty() {
        String::new()
    } else {
        format!(
            "DEAD CANARY: {} curated known-positive provider(s) gave no answer on any \
             attempt, in this sweep and in one at least {} h earlier with no answer \
             between — down across sweeps, or the endpoint is retired. Not drift, and \
             not tolerable: migrate the endpoint or retire the capability honestly:\n  {}",
            confirmed.len(),
            capability_probe::DEAD_CANARY_CONFIRMATION_SECS / 3600,
            confirmed
                .iter()
                .map(|d| d.describe())
                .collect::<Vec<_>>()
                .join("\n  ")
        )
    };
    // Known-negative controls (REQ-CANARY-002, REQ-CANARY-003): the same
    // parsers asked, per kind they consume, about a target nobody holds. A
    // canary proves a parser yields for a target its provider holds; only a
    // control can show it yields nothing for one it does not — the
    // false-evidence class REQ-PROBE-001 found in three presence probes.
    // Never fed to the dead-canary memory or the drift store: a control is
    // not a canary reading.
    let controls = capability_probe::probe_negative_controls(8).await;
    let nobody = capability_probe::CONTROLLED_KINDS
        .iter()
        .filter_map(|k| {
            Some(format!(
                "{} `{}`",
                k.canonical_str(),
                capability_probe::control_value(*k)?
            ))
        })
        .collect::<Vec<_>>()
        .join(", ");
    println!(
        "\nknown-negative controls — every keyless network module asked, per kind it consumes, \
         about a target nobody holds ({nobody}):"
    );
    let mut control_empty = 0usize;
    let mut control_annotated = 0usize;
    let mut control_other = 0usize;
    for c in &controls {
        let r = &c.report;
        match &r.outcome {
            ProbeOutcome::Empty => {
                control_empty += 1;
                println!("  empty        {:<22} {}", r.module, r.kind.canonical_str());
            }
            ProbeOutcome::Alive { .. } if c.is_annotation() => {
                control_annotated += 1;
                println!(
                    "  annotated    {:<22} {} the target alone, below the present rung: {}",
                    r.module,
                    r.kind.canonical_str(),
                    c.minted.join("; ")
                );
            }
            ProbeOutcome::Alive { found } => {
                println!(
                    "  FABRICATED   {:<22} {} {found} entities for `{}`, a target nobody holds: {}",
                    r.module,
                    r.kind.canonical_str(),
                    r.value,
                    c.fabricated.join("; ")
                );
            }
            other => {
                control_other += 1;
                println!(
                    "  {:<12} {:<22} {} (no reading of the parser)",
                    other.label(),
                    r.module,
                    r.kind.canonical_str()
                );
            }
        }
    }
    let fabricated = capability_probe::fabrications(&controls);
    println!(
        "controls: {} probed — {control_empty} empty, {control_annotated} annotated, {} \
         fabricated, {control_other} without a reading",
        controls.len(),
        fabricated.len()
    );
    let fabrication_msg = if fabricated.is_empty() {
        String::new()
    } else {
        format!(
            "FABRICATION: {} control(s) minted entities for a target nobody holds — false \
             evidence on every scan of that kind until the parser is repaired:\n  {}\n",
            fabricated.len(),
            fabricated
                .iter()
                .map(|c| {
                    format!(
                        "{} {} `{}` — {}",
                        c.report.module,
                        c.report.kind.canonical_str(),
                        c.report.value,
                        c.fabricated.join("; ")
                    )
                })
                .collect::<Vec<_>>()
                .join("\n  ")
        )
    };

    assert!(
        drifted.is_empty() && confirmed.is_empty() && fabricated.is_empty(),
        "{drift_msg}{dead_msg}{fabrication_msg}"
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
