//! End-to-end smoke tests: synthetic modules, real engine, real SQLite.
//! Proves the trait + engine + store + autonomous-expansion wire together.

use std::sync::Arc;

use async_trait::async_trait;
use huntsman_search_engine::{
    core::{
        engine::ScanEngine,
        entity::{Entity, EntityKind},
        error::Result,
        module::{Module, ModuleContext, ModuleResult},
        scan::{Scan, ScanOptions, Target, TargetKind},
    },
    storage::store::Store,
    util::{http::build_client, uid::scan_id},
};

/// Echoes the seed back as an entity of the same kind.
struct SyntheticModule;

#[async_trait]
impl Module for SyntheticModule {
    fn name(&self) -> &'static str {
        "synthetic"
    }
    fn priority(&self) -> u8 {
        100
    }
    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::Email)
    }
    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let mut r = ModuleResult::new();
        let mut e = Entity::new(EntityKind::Email, &target.value, 0.95, &ctx.scan_id);
        e.tag("synthetic");
        r.push(e);
        Ok(r)
    }
}

/// Accepts Email, produces ONE Username derived from the local part.
struct EmailToUsernameSynth;

#[async_trait]
impl Module for EmailToUsernameSynth {
    fn name(&self) -> &'static str {
        "synth_e2u"
    }
    fn priority(&self) -> u8 {
        80
    }
    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::Email)
    }
    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let mut r = ModuleResult::new();
        let local = target.value.split('@').next().unwrap_or("anon");
        // High base confidence so c_effective() ≥ 0.75 expansion threshold.
        let mut e = Entity::new(EntityKind::Username, local, 0.95, &ctx.scan_id);
        e.tag("derived");
        r.push(e);
        Ok(r)
    }
}

/// Accepts Username, produces ONE Phone (synthetic).
struct UsernameToPhoneSynth;

#[async_trait]
impl Module for UsernameToPhoneSynth {
    fn name(&self) -> &'static str {
        "synth_u2p"
    }
    fn priority(&self) -> u8 {
        70
    }
    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::Username)
    }
    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let mut r = ModuleResult::new();
        let phone = format!("+1{:0>10}", target.value.len() * 1111);
        let mut e = Entity::new(EntityKind::Phone, &phone, 0.95, &ctx.scan_id);
        e.tag("synthetic");
        r.push(e);
        Ok(r)
    }
}

/// Per-call chatty module — emits 5 distinct Email entities every call.
/// Used to verify the in-flight budget gate. Three named copies exist
/// (`ChattyA` / `ChattyB` / `ChattyC`) because `Module::name()` returns
/// a fixed `&'static str`, so we can't reuse a single struct.
macro_rules! chatty_module {
    ($Ty:ident, $name:literal, $prio:literal) => {
        struct $Ty;
        #[async_trait]
        impl Module for $Ty {
            fn name(&self) -> &'static str {
                $name
            }
            fn priority(&self) -> u8 {
                $prio
            }
            fn accepts(&self, t: &Target) -> bool {
                matches!(t.kind, TargetKind::Email)
            }
            async fn process(&self, _target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
                let mut r = ModuleResult::new();
                for i in 0..5 {
                    let v = format!("{}-{i}@chatty.example", $name);
                    let mut e = Entity::new(EntityKind::Email, &v, 0.95, &ctx.scan_id);
                    e.tag("chatty");
                    r.push(e);
                }
                Ok(r)
            }
        }
    };
}
chatty_module!(ChattyA, "chatty_a", 110);
chatty_module!(ChattyB, "chatty_b", 100);
chatty_module!(ChattyC, "chatty_c", 90);

/// Accepts Email, produces a low-confidence Username — should be ignored
/// by expansion when min_expand_confidence is 0.75.
struct LowConfidenceModule;

#[async_trait]
impl Module for LowConfidenceModule {
    fn name(&self) -> &'static str {
        "synth_low"
    }
    fn priority(&self) -> u8 {
        60
    }
    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::Email)
    }
    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let mut r = ModuleResult::new();
        let local = target.value.split('@').next().unwrap_or("anon");
        // Base confidence 0.3 → c_effective 0.3 → below 0.75 threshold.
        let mut e = Entity::new(EntityKind::Username, local, 0.3, &ctx.scan_id);
        e.tag("low");
        r.push(e);
        Ok(r)
    }
}

#[tokio::test]
async fn engine_dispatches_synthetic_module_end_to_end() {
    let (engine, store, sid, target, ctx) = setup(
        vec![Arc::new(SyntheticModule)],
        "end_to_end",
        TargetKind::Email,
        "test@example.com",
    );
    let scan = Scan::new(sid.clone(), target.clone());

    let result = engine.run(scan, target, ctx).await.unwrap();
    assert_eq!(result.entity_count, 1);

    let stored = store.entities_for_scan(&sid).unwrap();
    assert_eq!(stored.len(), 1);
    assert_eq!(stored[0].value, "test@example.com");
    assert!(stored[0].has_tag("synthetic"));
}

#[tokio::test]
async fn scan_options_allowlist_excludes_module() {
    let (engine, store, sid, target, ctx) = setup(
        vec![Arc::new(SyntheticModule)],
        "allowlist",
        TargetKind::Email,
        "test@example.com",
    );
    let opts = ScanOptions {
        modules: Some(vec!["nonexistent".into()]),
        ..Default::default()
    };
    let scan = Scan::new(sid.clone(), target.clone()).with_options(opts);

    let result = engine.run(scan, target, ctx).await.unwrap();
    assert_eq!(result.entity_count, 0, "synthetic should be skipped");
    drop(store);
}

#[tokio::test]
async fn expansion_depth_zero_is_single_round() {
    let (engine, _store, sid, target, ctx) = setup(
        vec![
            Arc::new(EmailToUsernameSynth),
            Arc::new(UsernameToPhoneSynth),
        ],
        "depth_zero",
        TargetKind::Email,
        "alice@example.com",
    );
    // depth=0 — username produced, but never re-dispatched.
    let scan = Scan::new(sid.clone(), target.clone());
    let result = engine.run(scan, target, ctx).await.unwrap();
    assert_eq!(
        result.entity_count, 1,
        "depth 0 should not expand username to phone"
    );
}

#[tokio::test]
async fn expansion_depth_one_chains_two_modules() {
    let (engine, store, sid, target, ctx) = setup(
        vec![
            Arc::new(EmailToUsernameSynth),
            Arc::new(UsernameToPhoneSynth),
        ],
        "depth_one",
        TargetKind::Email,
        "alice@example.com",
    );
    let opts = ScanOptions {
        depth: 1,
        ..Default::default()
    };
    let scan = Scan::new(sid.clone(), target.clone()).with_options(opts);
    let result = engine.run(scan, target, ctx).await.unwrap();
    assert_eq!(
        result.entity_count, 2,
        "expansion should yield username + phone"
    );
    let entities = store.entities_for_scan(&sid).unwrap();
    let kinds: Vec<&EntityKind> = entities.iter().map(|e| &e.kind).collect();
    assert!(kinds.contains(&&EntityKind::Username));
    assert!(kinds.contains(&&EntityKind::Phone));
}

#[tokio::test]
async fn expansion_respects_min_expand_confidence() {
    let (engine, _store, sid, target, ctx) = setup(
        vec![
            Arc::new(LowConfidenceModule),
            Arc::new(UsernameToPhoneSynth),
        ],
        "low_conf",
        TargetKind::Email,
        "alice@example.com",
    );
    let opts = ScanOptions {
        depth: 1,
        min_expand_confidence: 0.75,
        ..Default::default()
    };
    let scan = Scan::new(sid.clone(), target.clone()).with_options(opts);
    let result = engine.run(scan, target, ctx).await.unwrap();
    assert_eq!(
        result.entity_count, 1,
        "low-confidence username should not trigger expansion"
    );
}

#[tokio::test]
async fn seed_round_in_flight_budget_caps_emission() {
    // Three chatty modules each emit 5 entities per call. Without the
    // in-flight gate, the seed round would accumulate 15 entities even
    // when the user declared `max_entities = 6`. With the gate, the
    // dispatcher short-circuits after the first chatty module's merge
    // pushes the running count past the cap — so the persisted count
    // is bounded by `(cap + 4)` in the worst case (one full module's
    // 5-entity yield can land before the gate kicks in for the next
    // module).
    let (engine, store, sid, target, ctx) = setup(
        vec![Arc::new(ChattyA), Arc::new(ChattyB), Arc::new(ChattyC)],
        "seed_budget",
        TargetKind::Email,
        "seed@example.com",
    );
    let opts = ScanOptions {
        depth: 0,
        max_entities: Some(6),
        ..Default::default()
    };
    let scan = Scan::new(sid.clone(), target.clone()).with_options(opts);
    let result = engine.run(scan, target, ctx).await.unwrap();
    // Without the fix this would be 15 (3 modules × 5 entities each).
    // With the fix: ChattyA emits 5 → entity_map=5; gate before ChattyB
    // sees 5 < 6, doesn't fire; ChattyB emits 5 → entity_map=10; gate
    // before ChattyC sees 10 ≥ 6, fires → ChattyC skipped. Total = 10.
    assert!(
        result.entity_count < 15,
        "in-flight gate should bound emission below the no-gate 15 (got {})",
        result.entity_count
    );
    assert!(
        result.entity_count <= 10,
        "in-flight gate should cap after 2 modules merge past budget (got {})",
        result.entity_count
    );
    let stored = store.entities_for_scan(&sid).unwrap();
    assert_eq!(stored.len(), result.entity_count);
}

#[tokio::test]
async fn seed_round_in_flight_budget_caps_emission_concurrent() {
    // Mirror of `seed_round_in_flight_budget_caps_emission` but exercises
    // the concurrent dispatcher (max_concurrent > 0) — the gate lives in
    // `dispatch_target_concurrent`'s join_next loop and is distinct from
    // the sequential path's pre-process gate, so it needs its own
    // regression test.
    //
    // The concurrent gate's bound is looser than sequential because all
    // accepting modules get SPAWNED upfront (semaphore-bounded) before
    // the consumer loop runs — the gate stops *merging* further results
    // once the cap is hit, but already-spawned modules may still complete
    // and have their futures dropped via JoinSet::Drop.
    let (engine, store, sid, target, ctx) = setup(
        vec![Arc::new(ChattyA), Arc::new(ChattyB), Arc::new(ChattyC)],
        "seed_budget_conc",
        TargetKind::Email,
        "seed@example.com",
    );
    let opts = ScanOptions {
        depth: 0,
        max_concurrent: 4,
        max_entities: Some(6),
        ..Default::default()
    };
    let scan = Scan::new(sid.clone(), target.clone()).with_options(opts);
    let result = engine.run(scan, target, ctx).await.unwrap();
    // Without the concurrent-path gate this would be 15; with the gate,
    // emission stops once entity_map crosses the cap.
    assert!(
        result.entity_count < 15,
        "concurrent in-flight gate should bound emission below the no-gate 15 (got {})",
        result.entity_count
    );
    let stored = store.entities_for_scan(&sid).unwrap();
    assert_eq!(stored.len(), result.entity_count);
}

#[tokio::test]
async fn expansion_respects_max_entities_budget() {
    // 3 modules chain forever in principle, but max_entities=1 stops after seed round.
    let (engine, _store, sid, target, ctx) = setup(
        vec![
            Arc::new(EmailToUsernameSynth),
            Arc::new(UsernameToPhoneSynth),
        ],
        "max_ent",
        TargetKind::Email,
        "alice@example.com",
    );
    let opts = ScanOptions {
        depth: 5,
        max_entities: Some(1),
        ..Default::default()
    };
    let scan = Scan::new(sid.clone(), target.clone()).with_options(opts);
    let result = engine.run(scan, target, ctx).await.unwrap();
    // Seed produces 1 entity; budget hits at depth 1 entry → no expansion.
    assert!(
        result.entity_count <= 1,
        "max_entities=1 should cap at 1 (got {})",
        result.entity_count
    );
}

#[tokio::test]
async fn expansion_visited_prevents_cycle() {
    // SyntheticModule echoes the seed email back as the same email entity.
    // With depth>0, expansion would try to re-scan it — visited set must stop that.
    let (engine, _store, sid, target, ctx) = setup(
        vec![Arc::new(SyntheticModule)],
        "cycle",
        TargetKind::Email,
        "loop@example.com",
    );
    let opts = ScanOptions {
        depth: 3,
        ..Default::default()
    };
    let scan = Scan::new(sid.clone(), target.clone()).with_options(opts);
    let result = engine.run(scan, target, ctx).await.unwrap();
    // Seed scanned once → 1 entity; expansion sees only the seed (visited) → 0 new targets.
    assert_eq!(result.entity_count, 1, "cycle should terminate");
}

/// Sleeps for `delay_ms`, then emits a tagged Email entity. Used to prove
/// that v0.8 concurrent dispatch actually overlaps module wall-time.
struct SlowEchoModule {
    name_str: &'static str,
    delay_ms: u64,
    in_flight: Arc<std::sync::atomic::AtomicUsize>,
    peak_in_flight: Arc<std::sync::atomic::AtomicUsize>,
}

#[async_trait]
impl Module for SlowEchoModule {
    fn name(&self) -> &'static str {
        self.name_str
    }
    fn priority(&self) -> u8 {
        100
    }
    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::Email)
    }
    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        // Track concurrent in-flight count for the cap test.
        let now = self
            .in_flight
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst)
            + 1;
        self.peak_in_flight
            .fetch_max(now, std::sync::atomic::Ordering::SeqCst);
        tokio::time::sleep(std::time::Duration::from_millis(self.delay_ms)).await;
        self.in_flight
            .fetch_sub(1, std::sync::atomic::Ordering::SeqCst);

        let mut r = ModuleResult::new();
        let mut e = Entity::new(EntityKind::Email, &target.value, 0.9, &ctx.scan_id);
        e.tag(self.name_str);
        r.push(e);
        Ok(r)
    }
}

#[tokio::test]
async fn concurrent_dispatch_is_faster_than_sequential() {
    // Four 200 ms modules. Sequential ≈ 800 ms wall-time; concurrent
    // with max_concurrent=4 should complete in ≈ 200 ms.
    let counters = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let peak = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let modules: Vec<Arc<dyn Module>> = (0..4)
        .map(|i| {
            let name: &'static str = match i {
                0 => "slow0",
                1 => "slow1",
                2 => "slow2",
                _ => "slow3",
            };
            Arc::new(SlowEchoModule {
                name_str: name,
                delay_ms: 200,
                in_flight: Arc::clone(&counters),
                peak_in_flight: Arc::clone(&peak),
            }) as Arc<dyn Module>
        })
        .collect();

    let (engine, _store, sid, target, ctx) =
        setup(modules, "concurrent_fast", TargetKind::Email, "x@y.com");

    let opts = ScanOptions {
        max_concurrent: 4,
        ..Default::default()
    };
    let scan = Scan::new(sid.clone(), target.clone()).with_options(opts);

    let started = std::time::Instant::now();
    let result = engine.run(scan, target, ctx).await.unwrap();
    let elapsed = started.elapsed();

    assert_eq!(result.entity_count, 1, "4 modules echo the same email UID");
    // Sequential would be 800 ms; concurrent should clear well under 600 ms.
    assert!(
        elapsed < std::time::Duration::from_millis(600),
        "concurrent dispatch took {elapsed:?} — expected < 600ms"
    );
}

#[tokio::test]
async fn concurrent_dispatch_respects_max_concurrent_cap() {
    // 6 modules, max_concurrent=2: peak in-flight should be ≤ 2.
    let counters = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let peak = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let modules: Vec<Arc<dyn Module>> = (0..6)
        .map(|i| {
            let name: &'static str = match i {
                0 => "m0",
                1 => "m1",
                2 => "m2",
                3 => "m3",
                4 => "m4",
                _ => "m5",
            };
            Arc::new(SlowEchoModule {
                name_str: name,
                delay_ms: 50,
                in_flight: Arc::clone(&counters),
                peak_in_flight: Arc::clone(&peak),
            }) as Arc<dyn Module>
        })
        .collect();

    let (engine, _store, sid, target, ctx) =
        setup(modules, "concurrent_cap", TargetKind::Email, "x@y.com");

    let opts = ScanOptions {
        max_concurrent: 2,
        ..Default::default()
    };
    let scan = Scan::new(sid.clone(), target.clone()).with_options(opts);
    let _ = engine.run(scan, target, ctx).await.unwrap();

    let observed = peak.load(std::sync::atomic::Ordering::SeqCst);
    assert!(
        observed <= 2,
        "peak in-flight was {observed}, expected ≤ max_concurrent=2"
    );
    assert!(
        observed >= 2,
        "peak in-flight was {observed}, expected ≥ 2 (semaphore should let two run)"
    );
}

#[tokio::test]
async fn max_concurrent_zero_uses_sequential_path() {
    // With max_concurrent=0, peak in-flight should be exactly 1 — modules
    // run one at a time in priority order (the v0.1 behaviour).
    let counters = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let peak = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let modules: Vec<Arc<dyn Module>> = (0..4)
        .map(|i| {
            let name: &'static str = match i {
                0 => "s0",
                1 => "s1",
                2 => "s2",
                _ => "s3",
            };
            Arc::new(SlowEchoModule {
                name_str: name,
                delay_ms: 10,
                in_flight: Arc::clone(&counters),
                peak_in_flight: Arc::clone(&peak),
            }) as Arc<dyn Module>
        })
        .collect();

    let (engine, _store, sid, target, ctx) =
        setup(modules, "sequential_zero", TargetKind::Email, "x@y.com");

    let scan = Scan::new(sid.clone(), target.clone()); // default opts → max_concurrent = 0
    let _ = engine.run(scan, target, ctx).await.unwrap();

    let observed = peak.load(std::sync::atomic::Ordering::SeqCst);
    assert_eq!(
        observed, 1,
        "sequential path should never have two in-flight"
    );
}

// ── Regression: per-module max_timeout_ms override ──────────────────────────
//
// Bug repro: a module that sleeps longer than the crate-wide
// `MODULE_TIMEOUT_MS = 3 s` ceiling was killed before `process()`
// returned. gps_fix observed this on Termux 0.118.x — internal
// 15 s timeout for `termux-location`, outer 3 s engine cap won,
// `WARN timeout module="gps_fix"` every iteration.
//
// Fix: Module trait gained `fn max_timeout_ms() -> u64` with default
// `MODULE_TIMEOUT_MS`; engine consults the module's override when
// the user hasn't pinned `ScanOptions::module_timeout_ms`.
//
// This test enforces that contract — a 3.5 s sleep inside a module
// that declares `max_timeout_ms() == 6_000` must succeed (would have
// timed out under the old behaviour).

struct SlowModule;

#[async_trait]
impl Module for SlowModule {
    fn name(&self) -> &'static str {
        "slow_module"
    }
    fn priority(&self) -> u8 {
        50
    }
    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::Email)
    }
    fn max_timeout_ms(&self) -> u64 {
        6_000
    }
    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        tokio::time::sleep(std::time::Duration::from_millis(3_500)).await;
        let mut r = ModuleResult::new();
        let mut e = Entity::new(EntityKind::Email, &target.value, 0.9, &ctx.scan_id);
        e.tag("slow-completed");
        r.push(e);
        Ok(r)
    }
}

#[tokio::test]
async fn module_max_timeout_override_extends_engine_cap() {
    let (engine, store, sid, target, ctx) = setup(
        vec![Arc::new(SlowModule)],
        "slow_timeout",
        TargetKind::Email,
        "slow@example.com",
    );
    let scan = Scan::new(sid.clone(), target.clone()); // no opts.module_timeout_ms

    let result = engine.run(scan, target, ctx).await.unwrap();
    assert_eq!(
        result.entity_count, 1,
        "slow module should complete because it declared a 6 s ceiling, \
         not be killed by the default 3 s"
    );
    let entities = store.entities_for_scan(&sid).unwrap();
    assert!(entities.iter().any(|e| e.has_tag("slow-completed")));
}

#[tokio::test]
async fn user_timeout_override_still_wins_over_module_max() {
    // The user-pinned `--timeout` must override the module's declared
    // ceiling — that's how an operator throttles a misbehaving module
    // without recompiling.
    let (engine, _store, sid, target, ctx) = setup(
        vec![Arc::new(SlowModule)],
        "user_timeout_wins",
        TargetKind::Email,
        "slow@example.com",
    );
    let opts = ScanOptions {
        module_timeout_ms: Some(500), // user says "kill at 500ms"
        ..Default::default()
    };
    let scan = Scan::new(sid, target.clone()).with_options(opts);
    let result = engine.run(scan, target, ctx).await.unwrap();
    assert_eq!(
        result.entity_count, 0,
        "user-set 500 ms ceiling must override module's 6 s declaration; \
         slow module's 3.5 s sleep should be killed"
    );
}

// ── Helpers ─────────────────────────────────────────────────────────────────

fn setup(
    modules: Vec<Arc<dyn Module>>,
    suffix: &str,
    kind: TargetKind,
    value: &str,
) -> (ScanEngine, Arc<Store>, String, Target, ModuleContext) {
    let tmp = tempfile_path(suffix);
    let _ = std::fs::remove_file(&tmp);
    let store = Arc::new(Store::open(&tmp).unwrap());
    let (bus, _rx) = tokio::sync::broadcast::channel(64);
    let engine = ScanEngine::new(modules, Arc::clone(&store), bus.clone());
    let sid = scan_id(kind.canonical_str(), value);
    let target = Target::new(kind, value.to_string());
    let ctx = ModuleContext {
        scan_id: sid.clone(),
        bus,
        http: build_client(),
        keys: Default::default(),
    };
    (engine, store, sid, target, ctx)
}

fn tempfile_path(suffix: &str) -> String {
    let mut p = std::env::temp_dir();
    p.push(format!("hse-smoke-{}-{}.db", std::process::id(), suffix));
    p.to_string_lossy().into_owned()
}
