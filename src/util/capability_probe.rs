//! Proactive capability self-audit — probe keyless modules against their real
//! providers and classify each as alive / drifted / unreachable.
//!
//! ## Why this exists
//!
//! Every collector module parses a third-party response into entities. A
//! module's unit tests run against **canned fixtures**, so when a provider
//! silently changes its wire shape the parser starts yielding nothing while the
//! fixture tests stay green — the capability is gone and nothing says so. HSE
//! already catches this **reactively**: [`crate::util::scraper_health`]
//! aggregates real-scan outcomes and flags a source as
//! [`is_yield_drifted`](crate::util::scraper_health::SourceHealth::is_yield_drifted)
//! after ≥3 trailing zero-yield runs on a source that once produced data. That
//! only fires *after* an operator has already run several fruitless scans.
//!
//! This module is the **proactive** complement: it fires one bounded probe per
//! keyless module against a canonical, stable sample target and reports the
//! outcome up front, before an investigation is staked on a dead capability.
//! One implementation backs both callers:
//!   * `hse doctor --live` — an on-device capability preflight (opt-in; the
//!     default `hse doctor` never touches the network).
//!   * `tests/live_drift.rs` — the weekly CI drift sweep.
//!
//! ## Outcome semantics (why empty ≠ always drift)
//!
//! Reaching a provider and parsing **zero** entities only means *drift* when the
//! sample target is one the healthy provider is **guaranteed** to answer. A
//! generic `test@example.com` legitimately returns no breaches from a breach
//! module — an empty result there is normal, not drift. So the fleet sweep is a
//! **reachability + parse-sanity** signal for every keyless module, and a
//! strict **must-yield drift assertion** only for the curated [`CANARY_PROBES`]
//! whose `(module, target)` pair a live provider cannot answer emptily. That
//! keeps the CI sweep faithful to the workflow's contract — a red run is an
//! actionable drift, never a flaky endpoint — while giving the operator a
//! full-fleet view in `doctor --live`.

use std::collections::HashMap;
use std::time::Duration;

use crate::core::{
    cancel::CancelHandle,
    module::{Module, ModuleContext, ModuleCost},
    scan::{Target, TargetKind},
};
use crate::util::http::build_client;

/// Result of probing one module against its live provider.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProbeOutcome {
    /// Provider reached; its parser produced ≥1 entity — capability healthy.
    Alive { found: usize },
    /// Provider reached but the parse yielded **zero** entities. For a
    /// [`CANARY_PROBES`] module this is drift (the wire shape likely changed);
    /// for any other module it is only *suspected* — the sample may simply have
    /// no data. [`ProbeReport::is_confirmed_drift`] draws that line.
    Empty,
    /// Transport failure (DNS/TLS/connect/HTTP) — provider down or the device is
    /// offline. **Never** treated as drift.
    Unreachable { reason: String },
    /// Exceeded the module's own timeout budget — provider slow/hung. **Never**
    /// treated as drift.
    TimedOut,
}

impl ProbeOutcome {
    /// Compact, stable label for the `doctor --live` table.
    pub fn label(&self) -> &'static str {
        match self {
            Self::Alive { .. } => "alive",
            Self::Empty => "empty",
            Self::Unreachable { .. } => "unreachable",
            Self::TimedOut => "timed-out",
        }
    }
}

/// One module's probe result, with the target it was probed against.
#[derive(Debug, Clone)]
pub struct ProbeReport {
    pub module: &'static str,
    pub kind: TargetKind,
    pub value: &'static str,
    pub outcome: ProbeOutcome,
}

impl ProbeReport {
    /// True only when this module is a [`CANARY_PROBES`] entry that reached its
    /// provider yet parsed zero entities — the one case a healthy system can
    /// never produce, so it is real wire-format drift. A non-canary `Empty`, or
    /// any transport/timeout outcome, is **not** confirmed drift.
    pub fn is_confirmed_drift(&self) -> bool {
        self.outcome == ProbeOutcome::Empty && is_canary(self.module)
    }
}

/// Canonical, stable, public sample value for a target kind, used to exercise a
/// module's live parser. `None` for kinds with no safe fixed public sample
/// (opaque credentials/identifiers, or free-form values that no provider keys
/// on) — a module consuming only those kinds is skipped by the sweep.
///
/// Values are deliberately well-known and long-lived (Google's public DNS,
/// RFC/IANA example domains, the Bitcoin genesis address) so a probe exercises
/// the transport + parser without depending on volatile data.
pub fn canonical_sample(kind: TargetKind) -> Option<&'static str> {
    Some(match kind {
        TargetKind::Email => "test@example.com",
        TargetKind::Username => "torvalds",
        TargetKind::Phone => "+12025550123",
        TargetKind::FullName => "Linus Torvalds",
        TargetKind::IpAddress => "8.8.8.8",
        TargetKind::Domain => "example.com",
        TargetKind::Url => "https://example.com",
        TargetKind::Asn => "AS15169",
        TargetKind::Cidr => "8.8.8.0/24",
        TargetKind::Coordinates => "40.7128,-74.0060",
        TargetKind::Organisation => "Google LLC",
        // ATO's published sample ABN (Australian Business Number).
        TargetKind::AbnAcn => "51824753556",
        TargetKind::MacAddress => "00:1A:2B:3C:4D:5E",
        // Bitcoin genesis address — permanent, always present on-chain.
        TargetKind::CryptoAddress => "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
        // Free-form / opaque / device-local kinds: no fixed public value that a
        // provider would resolve, so a probe would be meaningless.
        TargetKind::Address
        | TargetKind::ApiKey
        | TargetKind::DeviceId
        | TargetKind::Ssid
        | TargetKind::TrackingId => return None,
    })
}

/// Curated **must-yield** probes: `(module name, kind, value)` triples where a
/// healthy provider is guaranteed to return ≥1 entity, so an `Empty` outcome is
/// unambiguous wire-format drift. This is the set `tests/live_drift.rs` asserts
/// on — the generalisation of the file's original single hand-picked probe
/// (`ip_geo` / ip-api.com / `8.8.8.8`) into a list.
///
/// Grow it by adding a module here **only** once its `(kind, value)` pair is
/// verified to yield deterministically against a stable public target — a
/// mis-chosen canary would make the weekly sweep flap. Everything not listed is
/// still probed by the fleet sweep for reachability; it simply isn't asserted.
pub const CANARY_PROBES: &[(&str, TargetKind, &str)] = &[
    // ip-api.com geolocation of a stable, well-known public IP — the original.
    ("ip_geo", TargetKind::IpAddress, "8.8.8.8"),
    // crt.sh Certificate Transparency logs for a domain that has issued certs.
    ("crtsh", TargetKind::Domain, "example.com"),
    // BGPView ASN → prefix enumeration for Google's well-known ASN.
    ("bgpview", TargetKind::Asn, "AS15169"),
    // RIPEstat network info for a public IP — always resolves a holder/prefix.
    ("ripestat", TargetKind::IpAddress, "8.8.8.8"),
];

/// Whether `module` is a curated must-yield canary (see [`CANARY_PROBES`]).
pub fn is_canary(module: &str) -> bool {
    CANARY_PROBES.iter().any(|(name, _, _)| *name == module)
}

/// A real, network-capable, keyless module context: the production
/// SSRF-guarded client and an empty key set (these probes only ever run keyless
/// modules). The client is cloned per context — `reqwest::Client` is internally
/// `Arc`, so the connection pool / DNS resolver are shared, not rebuilt.
fn probe_ctx(http: &reqwest::Client) -> ModuleContext {
    ModuleContext {
        scan_id: "capability-probe".into(),
        bus: tokio::sync::broadcast::channel(8).0,
        http: http.clone(),
        keys: HashMap::new(),
        cancel: CancelHandle::new(),
    }
}

/// Pick the `(kind, value)` this module should be probed with: the first kind it
/// [`consumes`](Module::consumes) that has a [`canonical_sample`] **and** that
/// the module actually [`accepts`](Module::accepts). A canary's curated pair
/// wins outright so its assertion probes exactly the intended target.
///
/// Returns `None` when no consumed kind has a usable sample — the module is then
/// skipped (not an error): there is simply no safe fixed target to probe it on.
fn probe_target(m: &dyn Module) -> Option<(TargetKind, &'static str)> {
    if let Some((_, kind, value)) = CANARY_PROBES.iter().find(|(name, ..)| *name == m.name()) {
        return Some((*kind, value));
    }
    m.consumes().into_iter().find_map(|k| {
        let v = canonical_sample(k)?;
        m.accepts(&Target::new(k, v)).then_some((k, v))
    })
}

/// Probe a single module, if it is a network keyless module with a usable
/// sample target. Returns `None` when the module is skipped — key-gated/paid,
/// [passive](Module::is_passive) (local sensor, no network), or without a
/// canonical sample for any kind it consumes.
///
/// The probe is bounded by the module's own [`max_timeout_ms`](Module::max_timeout_ms),
/// mirroring how the engine wraps `process()` in production, so a stalled
/// provider can never hang the sweep.
pub async fn probe_module(m: &dyn Module, http: &reqwest::Client) -> Option<ProbeReport> {
    probe_module_impl(m, http).await
}

/// Owned-`Arc` wrapper so the fleet sweep's stream closure captures no borrow of
/// the trait object — passing `Arc<dyn Module>` (which is `'static`) by value
/// sidesteps the higher-ranked-lifetime inference failure a `|m| async move {
/// probe_module(m.as_ref(), …) }` closure hits over `&dyn Module`.
async fn probe_arc(m: std::sync::Arc<dyn Module>, http: reqwest::Client) -> Option<ProbeReport> {
    probe_module_impl(m.as_ref(), &http).await
}

async fn probe_module_impl(m: &dyn Module, http: &reqwest::Client) -> Option<ProbeReport> {
    if m.cost() != ModuleCost::Free || m.is_passive() {
        return None;
    }
    let (kind, value) = probe_target(m)?;
    let target = Target::new(kind, value);
    let ctx = probe_ctx(http);
    let budget = Duration::from_millis(m.max_timeout_ms());
    let outcome = match tokio::time::timeout(budget, m.process(&target, &ctx)).await {
        Ok(Ok(r)) if r.entities.is_empty() => ProbeOutcome::Empty,
        Ok(Ok(r)) => ProbeOutcome::Alive {
            found: r.entities.len(),
        },
        Ok(Err(e)) => ProbeOutcome::Unreachable {
            reason: e.to_string(),
        },
        Err(_) => ProbeOutcome::TimedOut,
    };
    Some(ProbeReport {
        module: m.name(),
        kind,
        value,
        outcome,
    })
}

/// Probe every keyless, network module in the registry, `concurrency` at a time,
/// and return one [`ProbeReport`] per probed module (skipped modules omitted).
///
/// Results are sorted by module name so the output is stable run-to-run
/// (`registry()` order is construction-defined, not alphabetical). Bounded
/// concurrency keeps a full-fleet sweep from opening ~100 sockets at once on a
/// low-power phone while still finishing far faster than a serial pass.
pub async fn probe_keyless_fleet(concurrency: usize) -> Vec<ProbeReport> {
    use std::sync::Arc;
    use tokio::{sync::Semaphore, task::JoinSet};

    let http = build_client();
    let sem = Arc::new(Semaphore::new(concurrency.max(1)));
    // Each probe future is `Send + 'static` — `dyn Module: Send + Sync` so
    // `Arc<dyn Module>` and the cloned client both cross the spawn boundary — so
    // a JoinSet gives bounded concurrency without the higher-ranked-lifetime
    // inference a `buffer_unordered` stream trips over `Arc<dyn Module>`.
    let mut set: JoinSet<Option<ProbeReport>> = JoinSet::new();
    for m in crate::modules::registry() {
        let http = http.clone();
        let sem = Arc::clone(&sem);
        set.spawn(async move {
            let _permit = sem.acquire_owned().await.ok()?;
            probe_arc(m, http).await
        });
    }
    let mut reports = Vec::new();
    while let Some(joined) = set.join_next().await {
        if let Ok(Some(report)) = joined {
            reports.push(report);
        }
    }
    reports.sort_by(|a, b| a.module.cmp(b.module));
    reports
}

/// `~/.huntsman/capability_drift.json` — module name → unix timestamp of the
/// most recent live probe that confirmed drift on it.
fn drift_path() -> std::path::PathBuf {
    crate::util::paths::data_file("capability_drift.json")
}

/// Read the persisted drift map from `path`. Empty on missing/corrupt — this
/// is a cache of past confirmations, never load-bearing state, so a parse
/// error is non-fatal (mirrors [`crate::util::settings::read_map`]).
fn read_drift_map(path: &std::path::Path) -> HashMap<String, u64> {
    std::fs::read_to_string(path)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

fn write_drift_map_at(path: &std::path::Path, map: &HashMap<String, u64>) -> std::io::Result<()> {
    let json = serde_json::to_string_pretty(map).map_err(std::io::Error::other)?;
    crate::util::atomic_file::write(path, json.as_bytes())
}

/// Merge this sweep's confirmed-drift modules into the map at `path`, stamped
/// `now`, and persist. A module absent from THIS sweep (probed clean, or not
/// probed at all) keeps whatever it already had — a single clean re-probe
/// should not erase a real drift history the operator hasn't acted on yet;
/// [`recent_confirmed_drift_at`]'s TTL is what ages an entry out, not a
/// same-run overwrite.
fn record_confirmed_drift_at(path: &std::path::Path, reports: &[ProbeReport], now: u64) {
    if !reports.iter().any(ProbeReport::is_confirmed_drift) {
        return;
    }
    let mut map = read_drift_map(path);
    for r in reports.iter().filter(|r| r.is_confirmed_drift()) {
        map.insert(r.module.to_string(), now);
    }
    let _ = write_drift_map_at(path, &map);
}

/// Persist this sweep's confirmed-drift modules to the on-device store. Called
/// after every live probe run — `hse doctor --live` and the Web UI's
/// `POST /api/v1/capabilities/probe` alike — so a drift finding survives past
/// the single response/printout that reported it, and the next (offline, free)
/// `hse doctor` can surface it without re-touching the network. Best-effort:
/// a write failure here must never fail the probe request itself.
pub fn record_confirmed_drift(reports: &[ProbeReport]) {
    record_confirmed_drift_at(&drift_path(), reports, crate::core::entity::unix_now());
}

/// Confirmed-drift modules still within `ttl_secs` of when a live probe last
/// caught them, sorted by module name. Pure over an explicit map + `now` so
/// the aging logic is unit-testable without touching the filesystem or clock.
fn recent_confirmed_drift_pure(
    map: &HashMap<String, u64>,
    ttl_secs: u64,
    now: u64,
) -> Vec<(String, u64)> {
    let mut out: Vec<(String, u64)> = map
        .iter()
        .filter(|&(_, &ts)| now.saturating_sub(ts) <= ttl_secs)
        .map(|(m, &ts)| (m.clone(), ts))
        .collect();
    out.sort_by(|a, b| a.0.cmp(&b.0));
    out
}

/// Confirmed-drift modules a live probe caught within the last `ttl_secs`,
/// read from the on-device store, sorted by module name. Empty if no live
/// probe has ever run, or every prior finding has aged out — a stale entry
/// past `ttl_secs` (the provider may well have been fixed since) is silently
/// dropped rather than nagging the operator forever about a possibly-resolved
/// issue.
#[must_use]
pub fn recent_confirmed_drift(ttl_secs: u64) -> Vec<(String, u64)> {
    let map = read_drift_map(&drift_path());
    recent_confirmed_drift_pure(&map, ttl_secs, crate::core::entity::unix_now())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn canary_report(module: &'static str) -> ProbeReport {
        // `is_confirmed_drift` requires BOTH a canary module AND `Empty` — use
        // a real curated canary name so these tests exercise the real gate,
        // not a hand-picked module the drift persistence doesn't actually see
        // in production.
        ProbeReport {
            module,
            kind: TargetKind::IpAddress,
            value: "8.8.8.8",
            outcome: ProbeOutcome::Empty,
        }
    }

    #[test]
    fn record_confirmed_drift_persists_only_confirmed_entries() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("capability_drift.json");
        let reports = vec![
            canary_report("ip_geo"),
            ProbeReport {
                module: "some_breach_module",
                kind: TargetKind::Email,
                value: "test@example.com",
                outcome: ProbeOutcome::Empty, // not a canary — not confirmed drift
            },
            ProbeReport {
                module: "ip_geo",
                kind: TargetKind::IpAddress,
                value: "8.8.8.8",
                outcome: ProbeOutcome::Alive { found: 3 }, // healthy — no entry
            },
        ];
        record_confirmed_drift_at(&path, &reports, 1_000);
        let map = read_drift_map(&path);
        assert_eq!(map.get("ip_geo"), Some(&1_000));
        assert!(
            !map.contains_key("some_breach_module"),
            "a non-canary Empty outcome must never be persisted as drift"
        );
    }

    #[test]
    fn record_confirmed_drift_is_a_no_op_when_nothing_confirmed() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("capability_drift.json");
        let reports = vec![ProbeReport {
            module: "ip_geo",
            kind: TargetKind::IpAddress,
            value: "8.8.8.8",
            outcome: ProbeOutcome::Alive { found: 1 },
        }];
        record_confirmed_drift_at(&path, &reports, 1_000);
        assert!(
            !path.exists(),
            "a clean sweep must not create the drift file at all"
        );
    }

    #[test]
    fn record_confirmed_drift_keeps_a_prior_entry_a_clean_resweep_did_not_touch() {
        // A single re-probe run where module A comes back clean must not erase
        // module B's still-unresolved drift from an earlier run.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("capability_drift.json");
        record_confirmed_drift_at(&path, &[canary_report("crtsh")], 1_000);
        record_confirmed_drift_at(
            &path,
            &[ProbeReport {
                module: "ip_geo",
                kind: TargetKind::IpAddress,
                value: "8.8.8.8",
                outcome: ProbeOutcome::Alive { found: 1 },
            }],
            2_000,
        );
        let map = read_drift_map(&path);
        assert_eq!(
            map.get("crtsh"),
            Some(&1_000),
            "crtsh's earlier drift finding must survive an unrelated clean re-probe"
        );
    }

    #[test]
    fn record_confirmed_drift_updates_the_timestamp_on_repeat_confirmation() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("capability_drift.json");
        record_confirmed_drift_at(&path, &[canary_report("ip_geo")], 1_000);
        record_confirmed_drift_at(&path, &[canary_report("ip_geo")], 5_000);
        let map = read_drift_map(&path);
        assert_eq!(
            map.get("ip_geo"),
            Some(&5_000),
            "must reflect the LATEST confirmation"
        );
    }

    #[test]
    fn recent_confirmed_drift_pure_keeps_within_ttl_and_drops_stale() {
        let mut map = HashMap::new();
        map.insert("fresh".to_string(), 9_500u64);
        map.insert("stale".to_string(), 1_000u64);
        let now = 10_000u64;
        let ttl = 1_000u64; // window: [9_000, 10_000]
        let out = recent_confirmed_drift_pure(&map, ttl, now);
        assert_eq!(out, vec![("fresh".to_string(), 9_500u64)]);
    }

    #[test]
    fn recent_confirmed_drift_pure_is_sorted_by_module_name() {
        let mut map = HashMap::new();
        map.insert("zeta".to_string(), 100u64);
        map.insert("alpha".to_string(), 100u64);
        let out = recent_confirmed_drift_pure(&map, 1_000, 100);
        assert_eq!(
            out,
            vec![("alpha".to_string(), 100u64), ("zeta".to_string(), 100u64)]
        );
    }

    #[test]
    fn read_drift_map_is_empty_on_missing_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("does_not_exist.json");
        assert!(read_drift_map(&path).is_empty());
    }

    #[test]
    fn every_canary_has_a_sample_and_is_flagged() {
        for (name, kind, value) in CANARY_PROBES {
            assert!(!name.is_empty(), "canary module name must be non-empty");
            assert!(!value.is_empty(), "canary {name} must have a probe value");
            // A canary's kind must be a real, sample-backed kind so the sweep
            // can construct its target.
            assert!(
                canonical_sample(*kind).is_some(),
                "canary {name} uses a kind with no canonical sample"
            );
            assert!(is_canary(name), "{name} must report as a canary");
        }
    }

    #[test]
    fn non_canary_is_not_flagged() {
        assert!(!is_canary("definitely_not_a_module"));
    }

    #[test]
    fn empty_is_confirmed_drift_only_for_canaries() {
        let canary = ProbeReport {
            module: "ip_geo",
            kind: TargetKind::IpAddress,
            value: "8.8.8.8",
            outcome: ProbeOutcome::Empty,
        };
        assert!(canary.is_confirmed_drift());

        let non_canary = ProbeReport {
            module: "some_breach_module",
            kind: TargetKind::Email,
            value: "test@example.com",
            outcome: ProbeOutcome::Empty,
        };
        assert!(!non_canary.is_confirmed_drift());

        // Transport failures are never drift, even for a canary.
        let unreachable = ProbeReport {
            module: "ip_geo",
            kind: TargetKind::IpAddress,
            value: "8.8.8.8",
            outcome: ProbeOutcome::Unreachable {
                reason: "connect".into(),
            },
        };
        assert!(!unreachable.is_confirmed_drift());
    }

    #[test]
    fn canonical_samples_cover_the_network_kinds() {
        // Opaque / device-local / free-form kinds intentionally have no sample.
        for kind in [
            TargetKind::Address,
            TargetKind::ApiKey,
            TargetKind::DeviceId,
            TargetKind::Ssid,
            TargetKind::TrackingId,
        ] {
            assert!(canonical_sample(kind).is_none());
        }
        // Everything a public provider keys on must have one.
        for kind in [
            TargetKind::Email,
            TargetKind::Username,
            TargetKind::IpAddress,
            TargetKind::Domain,
            TargetKind::Url,
            TargetKind::Asn,
            TargetKind::Cidr,
        ] {
            assert!(canonical_sample(kind).is_some(), "{kind:?} needs a sample");
        }
    }
}
