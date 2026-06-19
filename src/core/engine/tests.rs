//! Unit tests for the scan engine.
//!
//! Split out of the module file (mechanical, behaviour-preserving) so the
//! source reads as implementation; tests reach private items via `use super::*`.

use super::*;

#[test]
fn consolidate_address_localities_folds_postcode_variants_codebase_wide() {
    use crate::core::entity::{Entity, EntityKind, Evidence};

    // Two granularities of ONE suburb, from DIFFERENT modules (as if one came
    // from search_engines and the postcode form from a geocode API in a later
    // expansion round) — plus a genuinely different locality that must survive.
    let mut bare = Entity::new(EntityKind::Address, "Murrumbateman, NSW", 0.45, "s");
    bare.add_evidence(Evidence::new("search_engines", "near truelocal"));
    let mut withpc = Entity::new(EntityKind::Address, "Murrumbateman, NSW 2582", 0.50, "s");
    withpc.add_evidence(Evidence::new("geocode", "geocoded"));
    let other = Entity::new(EntityKind::Address, "Brisbane, QLD 4000", 0.45, "s");
    let unrelated = Entity::new(EntityKind::Email, "x@y.com", 0.9, "s");

    let mut entities = vec![bare, withpc, other, unrelated];
    consolidate_address_localities(&mut entities);

    let addrs: Vec<&Entity> = entities
        .iter()
        .filter(|e| e.kind == EntityKind::Address)
        .collect();
    // The two Murrumbateman variants collapse to ONE; Brisbane survives → 2.
    assert_eq!(addrs.len(), 2, "postcode variants must fold: {addrs:?}");
    let murrum = addrs
        .iter()
        .find(|e| e.value.contains("Murrumbateman"))
        .expect("murrumbateman survives");
    // The most-specific (postcode-bearing) spelling is kept...
    assert_eq!(murrum.value, "Murrumbateman, NSW 2582");
    // ...and BOTH sources' evidence folded in (confidence took the max).
    let srcs: std::collections::BTreeSet<&str> =
        murrum.evidence.iter().map(|e| e.source.as_str()).collect();
    assert!(srcs.contains("search_engines") && srcs.contains("geocode"));
    assert!((murrum.confidence - 0.50).abs() < 1e-9);
    // The unrelated email is untouched.
    assert!(entities.iter().any(|e| e.kind == EntityKind::Email));
}

/// FTA invariant (cuts MCS-A): the local/environmental sensor modules read
/// the OPERATOR's own device/network, so they must never engage on a
/// remote-subject seed — otherwise the operator's GPS/Wi-Fi/cell/LAN data is
/// attributed to the subject (e.g. a device GPS fix surfacing as the
/// subject's Verified location on a `name` scan). They run only on a
/// deliberately-local seed (coordinates / MAC). Pinning the whole gate set
/// here stops a future sensor module silently reopening the cut.
#[test]
fn local_passive_sensor_modules_reject_remote_subject_seeds() {
    use crate::core::scan::{Target, TargetKind};
    let reg = crate::modules::registry();
    for name in LOCAL_PASSIVE_MODULES {
        let m = reg
            .iter()
            .find(|m| m.name() == *name)
            .unwrap_or_else(|| panic!("{name} not in registry"));
        for k in [
            TargetKind::FullName,
            TargetKind::Email,
            TargetKind::Username,
            TargetKind::Phone,
            TargetKind::Domain,
            TargetKind::IpAddress,
            TargetKind::Url,
            TargetKind::Organisation,
        ] {
            assert!(
                !m.accepts(&Target::new(k, "x")),
                "{name} must reject remote-subject seed {k:?} (fault-tree MCS-A)"
            );
        }
        assert!(
            m.accepts(&Target::new(TargetKind::Coordinates, "-27.47,153.02")),
            "{name} must still engage on a deliberately-local coordinates seed"
        );
    }
}

#[tokio::test]
async fn module_panic_is_contained_as_error_not_process_abort() {
    // Error-tree ECS-1: a panicking module (bad/hostile upstream tripping an
    // unwrap/slice) must be caught at the dispatch boundary and reported as a
    // normal, counted module error — never unwind into the loop / JoinSet or
    // abort the process. Requires panic = "unwind" (set for every profile).
    let out = run_module_guarded(5_000, "boom", async { panic!("kaboom on bad upstream") }).await;
    match out {
        Ok(Err(Error::Module { module, message })) => {
            assert_eq!(module, "boom");
            assert!(message.contains("panicked"), "msg: {message}");
            assert!(message.contains("kaboom on bad upstream"), "msg: {message}");
        }
        other => panic!("expected a contained module error, got {other:?}"),
    }
}

#[tokio::test]
async fn run_module_guarded_passes_success_and_error_through() {
    use crate::core::module::ModuleResult;
    // Success and a returned error flow through unchanged (the guard only
    // intercepts panics, matching a returned error's shape exactly).
    let ok = run_module_guarded(5_000, "ok", async { Ok(ModuleResult::new()) }).await;
    assert!(matches!(ok, Ok(Ok(_))));
    let err = run_module_guarded(5_000, "e", async {
        Err(Error::module("e", "regular failure"))
    })
    .await;
    assert!(matches!(err, Ok(Err(Error::Module { .. }))));
}

#[test]
fn visit_key_normalises_email() {
    let t = Target::new(TargetKind::Email, "ALICE@Example.COM");
    let (kind, val) = visit_key(&t);
    assert_eq!(kind, TargetKind::Email);
    assert_eq!(val, "alice@example.com");
}

#[test]
fn cmp_expansion_candidates_is_a_consistent_total_order() {
    // CORRECTNESS: `cmp_expansion_candidates` is handed to `sort_by`, which
    // requires a *total order* — an inconsistent comparator can panic
    // ("comparator violates total order") or silently mis-sort. The tricky
    // part is f64 weights including NaN. Prove the contract generatively over
    // a deterministic pseudo-random corpus (deterministic so the test itself
    // is reproducible): the relation must be a total order, and sorting must
    // be idempotent and self-consistent.
    use std::cmp::Ordering;

    // splitmix64 — a tiny deterministic PRNG (no dev-dependency, reproducible).
    let mut state = 0x1234_5678_9abc_def0u64;
    let mut next = || {
        state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    };
    // Small value/kind domains so ties (and the tie-breaks) actually occur.
    let kinds = [
        TargetKind::Email,
        TargetKind::Username,
        TargetKind::Domain,
        TargetKind::IpAddress,
    ];
    let weights = [f64::NAN, 0.0, 0.5, 0.5, 0.9, -1.0, f64::INFINITY];
    let values = ["a", "b", "c", "a"];
    let mk = |r: &mut dyn FnMut() -> u64| {
        let k = kinds[(r() % kinds.len() as u64) as usize];
        let w = weights[(r() % weights.len() as u64) as usize];
        let v = values[(r() % values.len() as u64) as usize];
        (Target::new(k, v), w, "p".to_string())
    };

    // 1. The relation is a TOTAL ORDER over a random sample: antisymmetric,
    //    transitive, and total (every pair is comparable, which Ordering is).
    let sample: Vec<_> = (0..40).map(|_| mk(&mut next)).collect();
    for a in &sample {
        assert_eq!(
            cmp_expansion_candidates(a, a),
            Ordering::Equal,
            "reflexivity"
        );
        for b in &sample {
            let ab = cmp_expansion_candidates(a, b);
            let ba = cmp_expansion_candidates(b, a);
            assert_eq!(ab, ba.reverse(), "antisymmetry");
            for c in &sample {
                let bc = cmp_expansion_candidates(b, c);
                // Transitivity: a<=b and b<=c ⇒ a<=c.
                if ab != Ordering::Greater && bc != Ordering::Greater {
                    assert_ne!(
                        cmp_expansion_candidates(a, c),
                        Ordering::Greater,
                        "transitivity"
                    );
                }
            }
        }
    }

    // 2. Sorting many random vectors never panics, is idempotent, and the
    //    output is non-decreasing under the comparator.
    for _ in 0..200 {
        let n = (next() % 30) as usize;
        let mut v: Vec<_> = (0..n).map(|_| mk(&mut next)).collect();
        v.sort_by(cmp_expansion_candidates);
        for w in v.windows(2) {
            assert_ne!(
                cmp_expansion_candidates(&w[0], &w[1]),
                Ordering::Greater,
                "sorted output must be non-decreasing"
            );
        }
        let once: Vec<_> = v.iter().map(|c| (c.0.value.clone(), c.1)).collect();
        v.sort_by(cmp_expansion_candidates); // idempotent
        let twice: Vec<_> = v.iter().map(|c| (c.0.value.clone(), c.1)).collect();
        // NaN != NaN, so compare structurally with NaN normalised.
        let norm = |xs: &[(String, f64)]| {
            xs.iter()
                .map(|(s, w)| {
                    (
                        s.clone(),
                        if w.is_nan() {
                            "nan".into()
                        } else {
                            w.to_string()
                        },
                    )
                })
                .collect::<Vec<_>>()
        };
        assert_eq!(norm(&once), norm(&twice), "sort must be idempotent");
    }
}

#[test]
fn allowlist_applies_on_expansion_rounds_not_just_the_seed() {
    // Regression: the allowlist ("only these modules run", docs/USAGE.md) was
    // gated by `!is_expansion`, so non-allowlisted modules ran on discovered
    // entities during expansion — a real defect (focused/offline scans fanned
    // out to every network module the moment they expanded).
    use crate::core::scan::{ScanOptions, Target, TargetKind};
    let reg = crate::modules::registry();
    let hibp = reg
        .iter()
        .find(|m| m.name() == "hibp")
        .expect("hibp registered");
    let target = Target::new(TargetKind::Email, "a@b.com");

    // Not in the allowlist → skipped on the seed round AND every expansion round.
    let only_name_intel = ScanOptions {
        modules: Some(vec!["name_intel".into()]),
        ..Default::default()
    };
    for is_expansion in [false, true] {
        assert_eq!(
            module_skip_reason(hibp.as_ref(), &target, &only_name_intel, is_expansion, 0),
            Some("not in allowlist"),
            "a non-allowlisted module must be skipped (is_expansion={is_expansion})"
        );
    }

    // In the allowlist → the allowlist gate must pass on expansion too (other
    // gates are independent, so assert only that this reason is not returned).
    let only_hibp = ScanOptions {
        modules: Some(vec!["hibp".into()]),
        ..Default::default()
    };
    assert_ne!(
        module_skip_reason(hibp.as_ref(), &target, &only_hibp, true, 9),
        Some("not in allowlist"),
        "an allowlisted module must not be skipped for the allowlist reason"
    );
}

#[test]
fn module_dispatch_is_logged_keyed_by_module_name() {
    // OBSERVABILITY: every module's *start* must appear in the raw debug log,
    // keyed by `module=<name>` so a single file's whole lifecycle is greppable.
    // `log_module_dispatch` is synchronous, so a scoped capturing subscriber
    // proves the line is emitted without touching the global subscriber.
    use std::io::Write;
    use std::sync::{Arc, Mutex};

    #[derive(Clone)]
    struct VecWriter(Arc<Mutex<Vec<u8>>>);
    impl Write for VecWriter {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    impl tracing_subscriber::fmt::MakeWriter<'_> for VecWriter {
        type Writer = VecWriter;
        fn make_writer(&self) -> Self::Writer {
            self.clone()
        }
    }

    let buf = Arc::new(Mutex::new(Vec::new()));
    let subscriber = tracing_subscriber::fmt()
        .with_writer(VecWriter(Arc::clone(&buf)))
        .with_max_level(tracing::Level::DEBUG)
        .without_time()
        .finish();
    tracing::subscriber::with_default(subscriber, || {
        log_module_dispatch("hibp", &Target::new(TargetKind::Email, "a@b.com"));
    });
    let out = String::from_utf8(buf.lock().unwrap().clone()).unwrap();
    assert!(
        out.contains("dispatch"),
        "dispatch event missing; got: {out:?}"
    );
    assert!(
        out.contains("module") && out.contains("hibp"),
        "dispatch line must be keyed by module name; got: {out:?}"
    );
}

#[test]
fn expansion_candidate_order_is_deterministic_under_input_permutation() {
    // DETERMINISM REQUIREMENT (evidence): the candidate ranking must not
    // depend on the HashMap-iteration order it is built from. Three candidates
    // share the SAME weight; whatever order they arrive in, the comparator
    // must produce one fixed order (by kind, then value), so a budget
    // `truncate` keeps the same set every run.
    let mk = |k: TargetKind, v: &str, w: f64| (Target::new(k, v), w, "p".to_string());
    let canonical = {
        let mut v = [
            mk(TargetKind::Email, "a@x.com", 0.5),
            mk(TargetKind::Email, "b@x.com", 0.5),
            mk(TargetKind::Username, "a@x.com", 0.5),
        ];
        v.sort_by(cmp_expansion_candidates);
        v.iter().map(|c| c.0.value.clone()).collect::<Vec<_>>()
    };
    // Every permutation of the same tied candidates yields the same order.
    for perm in [[2, 0, 1], [1, 2, 0], [0, 2, 1], [2, 1, 0]] {
        let src = [
            mk(TargetKind::Email, "a@x.com", 0.5),
            mk(TargetKind::Email, "b@x.com", 0.5),
            mk(TargetKind::Username, "a@x.com", 0.5),
        ];
        let mut v: Vec<_> = perm.iter().map(|&i| src[i].clone()).collect();
        v.sort_by(cmp_expansion_candidates);
        let got: Vec<_> = v.iter().map(|c| c.0.value.clone()).collect();
        assert_eq!(got, canonical, "ranking depended on input order");
    }
    // Higher weight always wins regardless of tie-break, and NaN sorts last.
    let mut wv = [
        mk(TargetKind::Email, "z@x.com", 0.9),
        mk(TargetKind::Email, "a@x.com", f64::NAN),
        mk(TargetKind::Email, "m@x.com", 0.5),
    ];
    wv.sort_by(cmp_expansion_candidates);
    assert_eq!(wv[0].0.value, "z@x.com"); // 0.9 first
    assert_eq!(wv[2].0.value, "a@x.com"); // NaN last
}

#[test]
fn visit_key_normalises_domain_trailing_dot() {
    let t = Target::new(TargetKind::Domain, "example.com.");
    let (_, val) = visit_key(&t);
    assert_eq!(val, "example.com");
}

#[test]
fn budget_check_none_when_no_limits() {
    let opts = ScanOptions::default();
    let started = Instant::now();
    assert!(budget_check(&opts, started, 1000).is_none());
}

#[test]
fn budget_check_max_entities_triggers() {
    let opts = ScanOptions {
        max_entities: Some(5),
        ..Default::default()
    };
    let started = Instant::now();
    assert!(budget_check(&opts, started, 4).is_none());
    assert!(budget_check(&opts, started, 5).is_some());
}

#[test]
fn budget_check_wall_time_triggers() {
    let opts = ScanOptions {
        max_wall_time_secs: Some(0),
        ..Default::default()
    };
    let started = Instant::now() - Duration::from_secs(1);
    assert!(budget_check(&opts, started, 0).is_some());
}

#[test]
fn stop_reason_labels_are_descriptive() {
    assert!(StopReason::NoMoreCandidates.label().contains("candidate"));
    assert!(StopReason::DepthExhausted.label().contains("depth"));
    assert!(StopReason::MaxEntities(10).label().contains("10"));
    assert!(StopReason::MaxWallTime(60).label().contains("60"));
    assert!(StopReason::Cancelled.label().contains("cancel"));
}

// -- dispatch tests (from former dispatch.rs) --

struct StubModule {
    name: &'static str,
    cost: ModuleCost,
    passive: bool,
}

#[async_trait::async_trait]
impl Module for StubModule {
    fn name(&self) -> &'static str {
        self.name
    }
    fn priority(&self) -> u8 {
        50
    }
    fn accepts(&self, _: &Target) -> bool {
        true
    }
    fn cost(&self) -> ModuleCost {
        self.cost
    }
    fn is_passive(&self) -> bool {
        self.passive
    }
    async fn process(
        &self,
        _: &Target,
        _: &ModuleContext,
    ) -> crate::core::error::Result<crate::core::module::ModuleResult> {
        Ok(crate::core::module::ModuleResult::new())
    }
}

/// Neutral public IP target used by skip-reason tests so the
/// universal preflight gate doesn't fire on the test fixture.
fn pub_target() -> Target {
    Target::new(TargetKind::IpAddress, "1.1.1.1")
}

#[test]
fn circuit_breaker_trip_skips_the_module_at_the_dispatch_gate() {
    // Wiring proof for the circuit breaker: once a module trips (a rate-limit /
    // quota wall, as the debug log showed hackertarget/urlscan hitting every
    // round), `module_skip_reason` must skip it so the rest of the scan stops
    // re-dispatching a dead provider and hands that budget to working sources.
    // A unique module name keeps this independent of the process-global breaker
    // state the circuit unit tests touch.
    let m = StubModule {
        name: "test_circuit_gate",
        cost: ModuleCost::Free,
        passive: false,
    };
    let opts = ScanOptions::default();

    // Healthy → not skipped for circuit reasons.
    assert!(
        module_skip_reason(&m, &pub_target(), &opts, false, 0).is_none(),
        "a healthy module must not be gated"
    );

    // Trip it as a 429/quota response would, then the gate skips it.
    super::circuit::record_rate_limit(m.name());
    assert_eq!(
        module_skip_reason(&m, &pub_target(), &opts, false, 0),
        Some("circuit-open — rate-limited/quota/repeated failure (cooling down)"),
        "a tripped module must be skipped at the dispatch gate"
    );

    // A success clears the trip — the gate trusts a recovered provider again.
    super::circuit::record_success(m.name());
    assert!(
        module_skip_reason(&m, &pub_target(), &opts, false, 0).is_none(),
        "a recovered module must dispatch again"
    );
}

fn free_active() -> StubModule {
    StubModule {
        name: "test_free",
        cost: ModuleCost::Free,
        passive: false,
    }
}

fn keygated() -> StubModule {
    StubModule {
        name: "test_keygated",
        cost: ModuleCost::KeyGated,
        passive: false,
    }
}

fn paid_passive() -> StubModule {
    StubModule {
        name: "test_paid",
        cost: ModuleCost::Paid,
        passive: true,
    }
}

#[test]
fn skip_reason_none_for_default_opts() {
    let m = free_active();
    let opts = ScanOptions::default();
    assert!(module_skip_reason(&m, &pub_target(), &opts, false, 0).is_none());
}

#[test]
fn skip_reason_not_in_allowlist() {
    let m = free_active();
    let opts = ScanOptions {
        modules: Some(vec!["other_module".into()]),
        ..Default::default()
    };
    assert_eq!(
        module_skip_reason(&m, &pub_target(), &opts, false, 0),
        Some("not in allowlist")
    );
}

#[test]
fn skip_reason_in_allowlist_passes() {
    let m = free_active();
    let opts = ScanOptions {
        modules: Some(vec!["test_free".into()]),
        ..Default::default()
    };
    assert!(module_skip_reason(&m, &pub_target(), &opts, false, 0).is_none());
}

#[test]
fn skip_reason_gates_live_sensors_to_radar_only() {
    // A live device-sensor module (name in LOCAL_PASSIVE_MODULES) reads the
    // OPERATOR's own environment, so it must NEVER run on a manual scan — only
    // under `hse radar`'s `allow_live_sensors` activation.
    let sensor = StubModule {
        name: "signal_radar",
        cost: ModuleCost::Free,
        passive: true,
    };
    // Default manual scan → skipped.
    assert_eq!(
        module_skip_reason(&sensor, &pub_target(), &ScanOptions::default(), false, 0),
        Some("live sensor — radar-only activation"),
    );
    // Even an explicit `hse scan --modules signal_radar` keeps it off: the
    // activation is `hse radar`, not an allowlist on an ordinary scan.
    let allowlisted = ScanOptions {
        modules: Some(vec!["signal_radar".into()]),
        ..Default::default()
    };
    assert_eq!(
        module_skip_reason(&sensor, &pub_target(), &allowlisted, false, 0),
        Some("live sensor — radar-only activation"),
    );
    // Radar activation → the sensor passes the gate.
    let radar = ScanOptions {
        modules: Some(vec!["signal_radar".into()]),
        allow_live_sensors: true,
        ..Default::default()
    };
    assert!(module_skip_reason(&sensor, &pub_target(), &radar, false, 0).is_none());
    // A non-sensor module is unaffected by the gate.
    assert!(
        module_skip_reason(&free_active(), &pub_target(), &ScanOptions::default(), false, 0)
            .is_none()
    );
}

#[test]
fn skip_reason_excluded() {
    let m = free_active();
    let opts = ScanOptions {
        exclude_modules: vec!["test_free".into()],
        ..Default::default()
    };
    assert_eq!(
        module_skip_reason(&m, &pub_target(), &opts, false, 0),
        Some("excluded")
    );
}

#[test]
fn skip_reason_outside_category_focus() {
    // A non-empty category focus that omits the module's category skips it on
    // every round. `free_active` is a StubModule, whose `category()` defaults to
    // `Other`; a focus of People/Phone/Geo therefore excludes it.
    use crate::core::module::ModuleCategory;
    let m = free_active();
    let opts = ScanOptions {
        category_focus: vec![
            ModuleCategory::People,
            ModuleCategory::Phone,
            ModuleCategory::Geo,
        ],
        ..Default::default()
    };
    assert_eq!(
        module_skip_reason(&m, &pub_target(), &opts, false, 0),
        Some("outside category focus")
    );
}

#[test]
fn skip_reason_inside_category_focus_passes() {
    // The same module passes when its category IS in the focus, and an empty
    // focus (the default) never restricts.
    use crate::core::module::ModuleCategory;
    let m = free_active(); // category() defaults to Other
    let focused = ScanOptions {
        category_focus: vec![ModuleCategory::Other],
        ..Default::default()
    };
    assert!(module_skip_reason(&m, &pub_target(), &focused, false, 0).is_none());
    let unfocused = ScanOptions {
        category_focus: Vec::new(),
        ..Default::default()
    };
    assert!(module_skip_reason(&m, &pub_target(), &unfocused, false, 0).is_none());
}

#[test]
fn skip_reason_free_only_skips_keygated() {
    let m = keygated();
    let opts = ScanOptions {
        free_only: true,
        ..Default::default()
    };
    assert_eq!(
        module_skip_reason(&m, &pub_target(), &opts, false, 0),
        Some("requires key/payment")
    );
}

#[test]
fn skip_reason_free_only_passes_free() {
    let m = free_active();
    let opts = ScanOptions {
        free_only: true,
        ..Default::default()
    };
    assert!(module_skip_reason(&m, &pub_target(), &opts, false, 0).is_none());
}

#[test]
fn skip_reason_passive_only_skips_active() {
    let m = free_active();
    let opts = ScanOptions {
        passive_only: true,
        ..Default::default()
    };
    assert_eq!(
        module_skip_reason(&m, &pub_target(), &opts, false, 0),
        Some("not passive")
    );
}

#[test]
fn skip_reason_passive_only_passes_passive() {
    let m = paid_passive();
    let opts = ScanOptions {
        passive_only: true,
        ..Default::default()
    };
    assert!(module_skip_reason(&m, &pub_target(), &opts, false, 0).is_none());
}

// ── high-value-API cross-correlation gate (oathnet_pro) ────────────────

/// Stub standing in for the high-value paid module by name.
fn high_value() -> StubModule {
    StubModule {
        name: "oathnet_pro",
        cost: ModuleCost::Paid,
        passive: false,
    }
}

#[test]
fn high_value_module_runs_on_seed_regardless_of_sources() {
    // Seed round (is_expansion=false): always allowed, even with 0 sources
    // (the seed target isn't an entity yet).
    let m = high_value();
    let opts = ScanOptions::default();
    assert!(
        module_skip_reason(&m, &pub_target(), &opts, false, 0).is_none(),
        "high-value module must run on the initial seed query"
    );
}

#[test]
fn high_value_module_skipped_on_expansion_below_cross_correlation() {
    // Expansion, target corroborated by only 1 distinct source → skip.
    let m = high_value();
    let opts = ScanOptions::default();
    assert_eq!(
        module_skip_reason(&m, &pub_target(), &opts, true, 1),
        Some("high-value API — awaiting cross-correlation (>=2 sources)"),
        "single-source discovered entity must NOT trigger the high-value API"
    );
    // 0 sources (not yet in map) on expansion is likewise gated.
    assert!(module_skip_reason(&m, &pub_target(), &opts, true, 0).is_some());
}

#[test]
fn high_value_module_runs_on_expansion_when_cross_correlated() {
    // Expansion, target corroborated by >=2 distinct sources → allowed.
    let m = high_value();
    let opts = ScanOptions::default();
    assert!(
        module_skip_reason(&m, &pub_target(), &opts, true, 2).is_none(),
        "cross-correlated (>=2 sources) entity must reach the high-value API on expansion"
    );
    assert!(module_skip_reason(&m, &pub_target(), &opts, true, 5).is_none());
}

#[test]
fn non_high_value_module_unaffected_by_source_gate() {
    // A normal module is never subject to the high-value cross-correlation
    // gate, even at 0 sources on expansion.
    let m = free_active();
    let opts = ScanOptions::default();
    assert!(module_skip_reason(&m, &pub_target(), &opts, true, 0).is_none());
}

fn wigle() -> StubModule {
    StubModule {
        name: "wigle",
        cost: ModuleCost::KeyGated,
        passive: false,
    }
}

fn coords_target() -> Target {
    Target::new(TargetKind::Coordinates, "-27.47,153.02")
}

#[test]
fn wigle_finaliser_gated_on_uncorroborated_coordinate() {
    // The GEOINT-finaliser rule: on EXPANSION, WiGLE must not spend a query on
    // a Coordinates target the free geo layer hasn't corroborated (>=2 distinct
    // sources). 0 or 1 source → skip; >=2 (recursion agreed, high confidence)
    // → allowed.
    let m = wigle();
    let opts = ScanOptions::default();
    assert_eq!(
        module_skip_reason(&m, &coords_target(), &opts, true, 1),
        Some("WiGLE finaliser — awaiting GEOINT corroboration (>=2 geo sources)"),
        "single-source coordinate must not reach the paid WiGLE finaliser"
    );
    assert!(module_skip_reason(&m, &coords_target(), &opts, true, 0).is_some());
    assert!(
        module_skip_reason(&m, &coords_target(), &opts, true, 2).is_none(),
        "a coordinate >=2 geo sources agree on (high confidence) reaches WiGLE"
    );
}

#[test]
fn target_distinct_sources_excludes_geo_normalize_enrichment() {
    // The WiGLE finaliser gate keys on this count. A Coordinates entity always
    // receives a `geo_normalize` evidence row from the enrichment pass, but that
    // is deterministic self-enrichment, NOT an independent geo source — so a
    // coordinate produced by ONE real module must count as 1, not 2. Counting
    // raw evidence_sources would credit it as 2 and fire WiGLE on an
    // uncorroborated coordinate, defeating the gate.
    use crate::core::entity::{Entity, EntityKind, Evidence};
    use std::collections::HashMap;

    let mut coord = Entity::new(EntityKind::Coordinates, "-27.470000,153.020000", 0.8, "s");
    coord.add_evidence(Evidence::new("ip_geo", "Geolocation for 1.2.3.4"));
    coord.add_evidence(Evidence::new("geo_normalize", "Geospatial enrichment"));
    let mut map: HashMap<String, Entity> = HashMap::new();
    map.insert(coord.uid.clone(), coord.clone());

    let target = Target::new(TargetKind::Coordinates, "-27.470000,153.020000");
    assert_eq!(
        target_distinct_sources(&map, &target),
        1,
        "one real geo source + geo_normalize must count as 1, not 2"
    );

    // A genuine second geo source lifts it to 2 → WiGLE may fire.
    let e = map.get_mut(&coord.uid).unwrap();
    e.add_evidence(Evidence::new("geocode", "reverse geocode"));
    assert_eq!(target_distinct_sources(&map, &target), 2);

    // An absent target is 0.
    let absent = Target::new(TargetKind::Coordinates, "10.0,20.0");
    assert_eq!(target_distinct_sources(&map, &absent), 0);
}

#[test]
fn wigle_runs_on_seed_coordinate_and_on_any_bssid() {
    let m = wigle();
    let opts = ScanOptions::default();
    // Seed round: a Coordinates seed is the operator's explicit target.
    assert!(
        module_skip_reason(&m, &coords_target(), &opts, false, 0).is_none(),
        "WiGLE runs on a coordinate SEED regardless of corroboration"
    );
    // A MacAddress/BSSID is WiGLE's PRIMARY pivot — exempt from the
    // geo-corroboration precondition even on expansion at 0 sources (its own
    // BSSID budget bounds it). The universal-preflight gate doesn't touch MACs.
    let mac = Target::new(TargetKind::MacAddress, "aa:bb:cc:dd:ee:ff");
    assert!(
        module_skip_reason(&m, &mac, &opts, true, 0).is_none(),
        "a discovered BSSID must reach WiGLE — it is the primary resolver"
    );
}

#[test]
fn skip_reason_allowlist_takes_priority_over_exclude() {
    let m = free_active();
    let opts = ScanOptions {
        modules: Some(vec!["test_free".into()]),
        exclude_modules: vec!["test_free".into()],
        ..Default::default()
    };
    assert_eq!(
        module_skip_reason(&m, &pub_target(), &opts, false, 0),
        Some("excluded")
    );
}

// -- universal preflight gate (private IP / local domain) --

#[test]
fn skip_reason_rejects_private_ip_for_external_module() {
    let m = free_active();
    let private = Target::new(TargetKind::IpAddress, "192.168.1.1");
    let opts = ScanOptions::default();
    assert_eq!(
        module_skip_reason(&m, &private, &opts, false, 0),
        Some("private/reserved IP — external API would reject")
    );
}

#[test]
fn skip_reason_rejects_local_domain_for_external_module() {
    let m = free_active();
    let local = Target::new(TargetKind::Domain, "router.local");
    let opts = ScanOptions::default();
    assert_eq!(
        module_skip_reason(&m, &local, &opts, false, 0),
        Some("local/reserved domain — external API would reject")
    );
}

#[test]
fn skip_reason_lets_local_passive_module_see_private_ip() {
    // local_net, device_sensors, wifi_intel, cell_intel are
    // listed in LOCAL_PASSIVE_MODULES and bypass the preflight.
    let m = StubModule {
        name: "local_net",
        cost: ModuleCost::Free,
        passive: true,
    };
    let private = Target::new(TargetKind::IpAddress, "192.168.1.1");
    // The private-IP preflight bypass only matters when the sensor is actually
    // active (`hse radar`); on a manual scan the radar-only gate skips it first.
    let opts = ScanOptions {
        allow_live_sensors: true,
        ..Default::default()
    };
    assert!(module_skip_reason(&m, &private, &opts, false, 0).is_none());
}

#[test]
fn skip_reason_passes_public_ip_through() {
    let m = free_active();
    let opts = ScanOptions::default();
    assert!(module_skip_reason(&m, &pub_target(), &opts, false, 0).is_none());
}

#[test]
fn skip_reason_passes_public_ipv6_through() {
    // Regression: the universal preflight previously rejected
    // every `:`-containing string via should_skip_external_ipv4,
    // silently breaking IPv6 lookups for v6-capable modules
    // (shodan, censys, abuseipdb, RDAP, etc.). The v6-tolerant
    // gate must let public IPv6 pass through to module dispatch.
    let m = free_active();
    let opts = ScanOptions::default();
    for v6 in [
        "2606:4700:4700::1111", // Cloudflare
        "2001:4860:4860::8888", // Google
        "2620:fe::fe",          // Quad9
    ] {
        let t = Target::new(TargetKind::IpAddress, v6);
        assert!(
            module_skip_reason(&m, &t, &opts, false, 0).is_none(),
            "public IPv6 {v6} should NOT be rejected by the universal gate",
        );
    }
}

#[test]
fn skip_reason_rejects_url_with_private_host_ssrf_gate() {
    // SSRF gate: a Url target whose host parses as a private IP
    // or a local domain must not reach external-API modules.
    // Without this, autonomous expansion that yields
    // `http://192.168.1.1/admin` would coerce HSE into hitting
    // the operator's internal LAN.
    let m = free_active();
    let opts = ScanOptions::default();
    for hostile in [
        "http://192.168.1.1/admin",
        "http://10.0.0.1:8080/",
        "http://127.0.0.1/health",
        "http://[::1]/",
        // IPv4-mapped IPv6 literal: the OS connects this to the underlying
        // IPv4 metadata host, so the bracket-stripped host must canonicalise
        // to v4 and be refused (regression guard for the to_canonical fix).
        "http://[::ffff:169.254.169.254]/latest/meta-data/",
        "http://router.local/",
        "https://intra.internal/api",
    ] {
        let t = Target::new(TargetKind::Url, hostile);
        let reason = module_skip_reason(&m, &t, &opts, false, 0);
        assert!(
            reason.is_some_and(|r| r.contains("SSRF") || r.contains("private")),
            "Url {hostile} should be SSRF-rejected, got {reason:?}",
        );
    }
}

#[test]
fn skip_reason_lets_public_url_through() {
    let m = free_active();
    let opts = ScanOptions::default();
    for benign in [
        "https://example.com/",
        "https://api.github.com/users/octocat",
        "http://[2606:4700:4700::1111]/",
    ] {
        let t = Target::new(TargetKind::Url, benign);
        assert!(
            module_skip_reason(&m, &t, &opts, false, 0).is_none(),
            "Url {benign} should pass through",
        );
    }
}

#[test]
fn skip_reason_still_rejects_private_ipv6() {
    // Loopback / unique-local / link-local IPv6 are private and
    // should still be skipped by the universal gate.
    let m = free_active();
    let opts = ScanOptions::default();
    for private_v6 in ["::1", "fc00::1", "fe80::1"] {
        let t = Target::new(TargetKind::IpAddress, private_v6);
        assert!(
            module_skip_reason(&m, &t, &opts, false, 0).is_some(),
            "private IPv6 {private_v6} should be rejected",
        );
    }
}

// -- dispatch dedup tests --

#[test]
fn dispatch_key_normalises_consistently() {
    let t1 = Target::new(TargetKind::Email, "ALICE@Example.COM");
    let t2 = Target::new(TargetKind::Email, "alice@example.com");
    assert_eq!(dispatch_key("hibp", &t1), dispatch_key("hibp", &t2));
}

#[test]
fn dispatch_key_differs_across_modules() {
    let t = Target::new(TargetKind::Email, "alice@example.com");
    assert_ne!(dispatch_key("hibp", &t), dispatch_key("shodan", &t));
}

#[test]
fn dispatch_key_differs_across_target_kinds() {
    let email = Target::new(TargetKind::Email, "alice@example.com");
    let domain = Target::new(TargetKind::Domain, "alice@example.com");
    assert_ne!(dispatch_key("hibp", &email), dispatch_key("hibp", &domain));
}

#[test]
fn dispatch_log_prevents_duplicate_keyed_module() {
    let mut log: DispatchLog = DispatchLog::new();
    let t = Target::new(TargetKind::Email, "alice@example.com");
    let key = dispatch_key("hibp", &t);
    assert!(log.insert(key.clone()), "first insert should succeed");
    assert!(!log.insert(key), "second insert should be rejected");
}

#[test]
fn dispatch_log_allows_same_module_on_different_targets() {
    let mut log: DispatchLog = DispatchLog::new();
    let t1 = Target::new(TargetKind::Email, "alice@example.com");
    let t2 = Target::new(TargetKind::Domain, "example.com");
    assert!(log.insert(dispatch_key("hibp", &t1)));
    assert!(log.insert(dispatch_key("hibp", &t2)));
}

#[test]
fn dispatch_log_allows_different_modules_on_same_target() {
    let mut log: DispatchLog = DispatchLog::new();
    let t = Target::new(TargetKind::IpAddress, "1.2.3.4");
    assert!(log.insert(dispatch_key("shodan", &t)));
    assert!(log.insert(dispatch_key("greynoise", &t)));
}

// ── End-to-end engine throughput benchmark (ignored; opt-in) ──────────────
//
// Drives a full multi-round expansion scan over the in-memory store with a
// deterministic fan-out module (no network, no SQLite), so the measured time
// is pure engine orchestration: per-round dispatch, entity merge, incremental
// correlation, ranking, and checkpointing. Run on demand:
//   cargo test -p huntsman-search-engine --lib core::engine::tests::bench_ -- \
//     --ignored --nocapture
//
// Finding (debug build, ~10x slower than release): orchestration scales
// ~O(n^1.4) in the entity count — superlinear (the incremental correlation
// and checkpoint each re-touch the whole working set per round) but firmly
// sub-quadratic. In release that is ~tens of ms for a few thousand entities,
// which is negligible against a real scan's network time (every module awaits
// HTTP for 100s of ms–seconds; HSE is IO-bound by design). So this is a
// baseline/diagnostic, NOT an assertive guard: end-to-end timing carries too
// much tokio-scheduling variance for a stable threshold, and the dominant
// pure-CPU cost (the correlation pass) is already guarded by
// `correlator::perf::pass_is_subquadratic`. Re-run this if the orchestration
// is ever reworked, to confirm it stays sub-quadratic.
use crate::core::entity::EntityKind;
use std::sync::atomic::{AtomicU64, Ordering};

/// Emits `WIDTH` fresh Username entities per dispatch (unique values via a
/// global counter), at a confidence above the expansion threshold — so the
/// scan fans out every round until it hits the `max_entities` budget. That
/// budget is the knob the benchmark sweeps to expose end-to-end scaling.
struct FanoutModule {
    width: u64,
}

static FANOUT_SEQ: AtomicU64 = AtomicU64::new(0);

#[async_trait::async_trait]
impl Module for FanoutModule {
    fn name(&self) -> &'static str {
        "bench_fanout"
    }
    fn priority(&self) -> u8 {
        50
    }
    fn accepts(&self, _: &Target) -> bool {
        true
    }
    fn produces(&self) -> &'static [EntityKind] {
        const K: &[EntityKind] = &[EntityKind::Username];
        K
    }
    async fn process(
        &self,
        _: &Target,
        ctx: &ModuleContext,
    ) -> crate::core::error::Result<crate::core::module::ModuleResult> {
        let mut r = crate::core::module::ModuleResult::new();
        for _ in 0..self.width {
            let n = FANOUT_SEQ.fetch_add(1, Ordering::Relaxed);
            let mut e = Entity::new(EntityKind::Username, format!("user{n}"), 0.9, &ctx.scan_id);
            e.tag("bench");
            e.add_evidence(crate::core::entity::Evidence::new(
                "bench_fanout",
                "synthetic",
            ));
            r.push(e);
        }
        Ok(r)
    }
}

async fn run_bench_scan(max_entities: usize) -> (usize, std::time::Duration) {
    use crate::core::test_support::InMemoryStore;
    let store = Arc::new(InMemoryStore::new());
    let store_port: Arc<dyn StoragePort> = store.clone();
    let (bus, _rx) = tokio::sync::broadcast::channel(4096);
    let engine = ScanEngine::new(
        vec![Arc::new(FanoutModule { width: 8 })],
        store_port,
        bus.clone(),
    );
    let opts = ScanOptions {
        depth: 12,
        max_entities: Some(max_entities),
        max_concurrent: 4,
        ..Default::default()
    };
    let target = Target::new(TargetKind::Username, "seed");
    let scan = Scan::new(
        crate::core::entity::scan_id("username", "seed"),
        target.clone(),
    )
    .with_options(opts);
    let ctx = ModuleContext {
        scan_id: scan.id.clone(),
        bus,
        http: crate::util::http::build_client(),
        keys: std::collections::HashMap::new(),
        cancel: crate::core::cancel::CancelHandle::new(),
        proxy_pool: std::sync::Arc::new(crate::util::proxy::ProxyPool::new()),
    };
    let start = std::time::Instant::now();
    let _ = engine.run(scan, target, ctx).await;
    let elapsed = start.elapsed();
    (store.entity_count(), elapsed)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "engine throughput baseline; run with --ignored --nocapture"]
async fn bench_end_to_end_scan_scaling() {
    // Warm up allocator / code paths so the first sample isn't penalised.
    FANOUT_SEQ.store(0, Ordering::Relaxed);
    let _ = run_bench_scan(1000).await;

    eprintln!("end-to-end scan — min-of-3 total time by entity budget (debug build):");
    for &cap in &[1000usize, 2000, 4000] {
        let mut best = std::time::Duration::MAX;
        let mut n = 0;
        for _ in 0..3 {
            FANOUT_SEQ.store(0, Ordering::Relaxed);
            let (c, dt) = run_bench_scan(cap).await;
            best = best.min(dt);
            n = c;
        }
        eprintln!(
            "  max_entities={cap:5}  entities={n:5}  {:8.1} ms",
            best.as_secs_f64() * 1e3
        );
    }
}

/// ROI truncation must RELEASE the visited keys of the candidates it cuts.
/// A cut candidate was queued but never dispatched, so leaving its key in
/// `visited` excluded the same lead as `already_dispatched_this_scan` in
/// every later round — a lead whose weight rises with corroboration was
/// silently lost for the rest of the scan. The kept (still-queued) heads
/// stay visited.
#[test]
fn roi_cutoff_releases_visited_keys_of_truncated_candidates() {
    let mk = |v: &str| Target::new(TargetKind::Domain, v.to_string());
    let mut next: Vec<(Target, f64, String)> = vec![
        (mk("leader.com"), 50.0, "p".to_string()),
        (mk("kept.com"), 40.0, "p".to_string()),
        (mk("tail-a.com"), 0.5, "p".to_string()),
        (mk("tail-b.com"), 0.2, "p".to_string()),
    ];
    let mut visited: HashSet<(TargetKind, String)> =
        next.iter().map(|(t, _, _)| visit_key(t)).collect();

    apply_roi_cutoff(&mut next, &mut visited, 0);

    // Knee at 5% of the leader (2.5): the two tail candidates are cut even
    // though top-K (10 at max_concurrent=0) would have kept them.
    assert_eq!(next.len(), 2, "knee should cut the sub-2.5-weight tail");
    assert!(visited.contains(&visit_key(&mk("leader.com"))));
    assert!(visited.contains(&visit_key(&mk("kept.com"))));
    assert!(
        !visited.contains(&visit_key(&mk("tail-a.com"))),
        "cut candidate must be released to compete in a later round"
    );
    assert!(!visited.contains(&visit_key(&mk("tail-b.com"))));
}

/// The persistent store is a SOURCE, not just a sink: prior-scan findings for a
/// target are pulled back at scan start, stamped as observed this scan, and
/// tagged `recalled` (provenance) while keeping their original tags/evidence.
/// Exercises `recall_prior_entities` directly (no full `run`, so the global
/// search-regional toggle the engine sets is left untouched).
#[tokio::test]
async fn recall_prior_entities_pulls_and_tags_prior_scan_findings() {
    use crate::core::entity::{Entity, EntityKind, Evidence};
    use crate::core::test_support::InMemoryStore;

    let store = Arc::new(InMemoryStore::new());
    let store_port: Arc<dyn StoragePort> = store.clone();

    // A prior scan ("prior-scan") of this Username: the seed anchor plus a
    // discovered email that NO live module will re-emit.
    let mut seed = Entity::new(EntityKind::Username, "recallsubject", 0.9, "prior-scan");
    seed.add_evidence(Evidence::new("anchor", "seed"));
    let mut email = Entity::new(
        EntityKind::Email,
        "plantedlead@gmail.com",
        0.8,
        "prior-scan",
    );
    email.tag("planted");
    email.add_evidence(Evidence::new("plant", "found in an earlier scan"));
    store.upsert_entity(&seed).unwrap();
    store.upsert_entity(&email).unwrap();

    let (bus, _rx) = tokio::sync::broadcast::channel(8);
    let engine = ScanEngine::new(vec![], store_port, bus);
    let target = Target::new(TargetKind::Username, "recallsubject");

    // Recall for a NEW scan id surfaces the prior email, re-stamped + tagged.
    let recalled = engine.recall_prior_entities(&target, "current-scan", true);
    let got = recalled
        .iter()
        .find(|e| e.value == "plantedlead@gmail.com")
        .expect("recall surfaces the prior scan's email from the database");
    assert!(
        got.has_tag("recalled"),
        "recalled node carries the provenance tag"
    );
    assert!(got.has_tag("planted"), "original tags survive recall");
    assert_eq!(
        got.scan_id, "current-scan",
        "recalled node is stamped as observed in the current scan"
    );
    assert_eq!(
        got.corroboration, 0,
        "recalled nodes contribute zero corroboration so re-persisting is \
         idempotent — the DB already holds the true count; re-scans must not \
         compound it"
    );

    // A scan never recalls its own rows: asking as "prior-scan" (the only scan
    // that observed the seed) excludes itself ⇒ nothing to recall.
    assert!(
        engine
            .recall_prior_entities(&target, "prior-scan", true)
            .is_empty(),
        "the sole prior scan is the requesting scan ⇒ empty recall"
    );
}

/// A FullName seed must recall prior intel even though the stored Person anchor
/// is reformatted by name parsing: the `seed_uid` derives from the raw,
/// un-title-cased input and misses, so the value-match fallback's token-set key
/// has to rescue case, comma order, and a trailing year. Run against a REAL
/// SQLite store because the fallback depends on FTS token matching, which the
/// in-memory test double's substring search can't model.
#[tokio::test]
async fn recall_resolves_a_fullname_seed_despite_reformatting() {
    use crate::core::entity::{Entity, EntityKind, Evidence};
    use crate::storage::Store;

    let path = format!(
        "{}/.hse-recall-name-{}.db",
        std::env::temp_dir().to_string_lossy(),
        std::process::id()
    );
    let cleanup = |p: &str| {
        let _ = std::fs::remove_file(p);
        let _ = std::fs::remove_file(format!("{p}-wal"));
        let _ = std::fs::remove_file(format!("{p}-shm"));
    };
    cleanup(&path);
    let store: Arc<dyn StoragePort> = Arc::new(Store::open(&path).unwrap());

    // A prior scan stored the Person anchor TITLE-CASED (as name parsing does)
    // plus a discovered email no live module will re-emit.
    store
        .upsert_scan(&Scan::new(
            "prior",
            Target::new(TargetKind::FullName, "Jordan Meyers"),
        ))
        .unwrap();
    let mut person = Entity::new(EntityKind::Person, "Jordan Meyers", 0.9, "prior");
    person.add_evidence(Evidence::new("name_intel", "seed"));
    let mut email = Entity::new(EntityKind::Email, "jordanlead@gmail.com", 0.8, "prior");
    email.add_evidence(Evidence::new("hibp", "breach"));
    store.upsert_entity(&person).unwrap();
    store.upsert_entity(&email).unwrap();

    let (bus, _rx) = tokio::sync::broadcast::channel(8);
    let engine = ScanEngine::new(vec![], store, bus);

    // Each input mismatches the stored title-case `seed_uid`, so recall depends
    // on the token-set fallback: lower-case, "Last, First" order, trailing year.
    for input in ["jordan meyers", "Meyers, Jordan", "Jordan Meyers 1987"] {
        let target = Target::new(TargetKind::FullName, input);
        let recalled = engine.recall_prior_entities(&target, "current", true);
        assert!(
            recalled
                .iter()
                .any(|e| e.value == "jordanlead@gmail.com" && e.has_tag("recalled")),
            "recall must resolve FullName '{input}' to the prior scan's email via the token-set fallback"
        );
    }

    cleanup(&path);
}
