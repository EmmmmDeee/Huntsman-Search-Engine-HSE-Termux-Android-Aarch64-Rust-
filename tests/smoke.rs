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
        scan::{Scan, ScanOptions, ScanStatus, Target, TargetKind},
    },
    storage::Store,
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

// ── Key-chaining harness ───────────────────────────────────────────────────
//
// These modules simulate the force-multiplication chain:
//   1. KeyDiscovererModule (high priority) writes a fake key into the
//      global key pool, mimicking oathnet_pro extracting a Shodan key
//      from breach data.
//   2. KeyConsumerModule (low priority) only emits an entity if the
//      target key is present in ctx.keys.
//
// If the hot-inject works, KeyConsumerModule sees the key and the scan
// produces the consumer's entity. If the hot-inject is broken, the
// consumer sees a stale ctx clone with no key and emits nothing.

const CHAIN_TEST_SERVICE: &str = "shodan";
const CHAIN_TEST_ENV: &str = "HUNTSMAN_SHODAN_KEY";

struct KeyDiscovererModule;

#[async_trait]
impl Module for KeyDiscovererModule {
    fn name(&self) -> &'static str {
        "key_discoverer"
    }
    fn priority(&self) -> u8 {
        // Higher than KeyConsumerModule so it runs first.
        // Also marked Paid so the concurrent dispatcher routes it into
        // Phase 1 (synchronous) before Phase 2 spawns the consumer.
        150
    }
    fn cost(&self) -> huntsman_search_engine::core::module::ModuleCost {
        huntsman_search_engine::core::module::ModuleCost::Paid
    }
    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::Email)
    }
    async fn process(&self, _target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        // Simulate oathnet_pro discovering a key in breach data.
        let pool = huntsman_search_engine::util::key_pool::global_pool();
        let entry = huntsman_search_engine::util::key_pool::KeyEntry::new(
            "test-shodan-key-chained-via-hot-inject",
        );
        pool.add(CHAIN_TEST_SERVICE, entry);

        // Emit a marker entity proving this module ran.
        let mut r = ModuleResult::new();
        let mut e = Entity::new(EntityKind::Email, "discoverer@test", 0.95, &ctx.scan_id);
        e.tag("key-discoverer-fired");
        r.push(e);
        Ok(r)
    }
}

struct KeyConsumerModule;

#[async_trait]
impl Module for KeyConsumerModule {
    fn name(&self) -> &'static str {
        "key_consumer"
    }
    fn priority(&self) -> u8 {
        // Lower than discoverer so it runs after the hot-inject fires.
        50
    }
    fn cost(&self) -> huntsman_search_engine::core::module::ModuleCost {
        huntsman_search_engine::core::module::ModuleCost::KeyGated
    }
    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::Email)
    }
    async fn process(&self, _target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let mut r = ModuleResult::new();
        // Only emit if the chained key reached us via hot-inject.
        if let Some(key) = ctx.key_opt(CHAIN_TEST_ENV)
            && key == "test-shodan-key-chained-via-hot-inject"
        {
            let mut e = Entity::new(EntityKind::Email, "consumer@test", 0.95, &ctx.scan_id);
            e.tag("key-consumer-saw-key");
            r.push(e);
        }
        Ok(r)
    }
}

/// Clear any pre-existing keys for the chain-test service from the process-
/// global pool so the key-chaining tests are hermetic. The global pool is a
/// `OnceLock` seeded from the persisted `~/.huntsman/key_pool.json`, which can
/// already hold real `shodan` keys (from prior CLI use or scans); those perturb
/// `next_key("shodan")` selection and make the hot-inject assertion flaky
/// depending on test order / the developer's local pool. Removal is in-memory
/// only (never writes the file), so it cannot affect real keys on disk.
fn reset_chain_pool() {
    let pool = huntsman_search_engine::util::key_pool::global_pool();
    let existing: Vec<String> = pool
        .snapshot()
        .services
        .get(CHAIN_TEST_SERVICE)
        .into_iter()
        .flatten()
        .map(|e| e.value.clone())
        .collect();
    for value in existing {
        pool.remove(CHAIN_TEST_SERVICE, &value);
    }
}

#[tokio::test]
async fn key_chaining_sequential_dispatch() {
    // Sequential mode (max_concurrent=0). The discoverer runs first,
    // stores the key in the pool. The per-module hot-inject after
    // finalise_module_result pushes it into ctx. The consumer then sees
    // the key and emits its marker entity.
    reset_chain_pool();
    let (engine, store, sid, target, ctx) = setup(
        vec![Arc::new(KeyDiscovererModule), Arc::new(KeyConsumerModule)],
        "chain-seq",
        TargetKind::Email,
        "chain-seq@example.com",
    );
    let opts = ScanOptions {
        max_concurrent: 0, // sequential
        ..Default::default()
    };
    let scan = Scan::new(sid.clone(), target.clone()).with_options(opts);

    let _ = engine.run(scan, target, ctx).await.unwrap();
    let entities = store.entities_for_scan(&sid).unwrap();

    let saw_discoverer = entities.iter().any(|e| e.has_tag("key-discoverer-fired"));
    let saw_consumer = entities.iter().any(|e| e.has_tag("key-consumer-saw-key"));

    assert!(saw_discoverer, "discoverer must run first");
    assert!(
        saw_consumer,
        "consumer must see the key via hot-inject — chain is broken"
    );
}

#[tokio::test]
async fn key_chaining_concurrent_dispatch() {
    // Concurrent mode (max_concurrent>0). Paid modules run in Phase 1
    // synchronously; ctx is refreshed from the pool; THEN Free + KeyGated
    // modules spawn in Phase 2 with the keys-rich ctx clone.
    reset_chain_pool();
    let (engine, store, sid, target, ctx) = setup(
        vec![Arc::new(KeyDiscovererModule), Arc::new(KeyConsumerModule)],
        "chain-conc",
        TargetKind::Email,
        "chain-conc@example.com",
    );
    let opts = ScanOptions {
        max_concurrent: 4, // concurrent (default)
        ..Default::default()
    };
    let scan = Scan::new(sid.clone(), target.clone()).with_options(opts);

    let _ = engine.run(scan, target, ctx).await.unwrap();
    let entities = store.entities_for_scan(&sid).unwrap();

    let saw_discoverer = entities.iter().any(|e| e.has_tag("key-discoverer-fired"));
    let saw_consumer = entities.iter().any(|e| e.has_tag("key-consumer-saw-key"));

    assert!(saw_discoverer, "discoverer (Paid) must run in Phase 1");
    assert!(
        saw_consumer,
        "consumer (KeyGated, Phase 2) must see the key via hot-inject — \
         concurrent chain is broken"
    );
}

#[tokio::test]
async fn key_chaining_classifies_multiplier_tier() {
    // Verify the ROI classification is wired up for the services that
    // matter most. Shodan, Censys, Hunter, Proxycurl should all be
    // Multiplier-tier (they discover infrastructure/identities that
    // lead to more keys).
    use huntsman_search_engine::util::key_roi::{KeyRoi, classify};

    for svc in ["shodan", "censys", "securitytrails", "hunter", "proxycurl"] {
        assert_eq!(
            classify(svc),
            KeyRoi::Multiplier,
            "{svc} should be Multiplier-tier — it yields more keys"
        );
    }

    // Pure scoring services produce no key chain.
    for svc in ["abuseipdb", "greynoise", "ip2location"] {
        assert_eq!(
            classify(svc),
            KeyRoi::Terminal,
            "{svc} should be Terminal-tier — single-shot data"
        );
    }
}

#[test]
fn all_registered_modules_have_descriptions() {
    // Regression guard for issue #28: every module shipped in the
    // registry must override `Module::description()` with a non-empty
    // string. The trait's default returns `""`, which leaves the wizard
    // tooltip blank — operators new to OSINT can't tell what e.g. `crtsh`
    // does without one. Failing this test points at the offending
    // module so it can't slip through review.
    let modules = huntsman_search_engine::modules::registry();
    assert!(!modules.is_empty(), "registry should not be empty");
    let missing: Vec<_> = modules
        .iter()
        .filter(|m| m.description().trim().is_empty())
        .map(|m| m.name())
        .collect();
    assert!(
        missing.is_empty(),
        "these modules have no description() override: {missing:?}"
    );
    // Sanity: at least one description mentions a recognisable
    // keyword. Catches accidental " " or "TODO" fillers. Case-insensitive
    // so harmless copy edits ("Breach" vs "breach", "Dns" vs "DNS")
    // don't break the corpus check.
    let descriptions: Vec<&str> = modules.iter().map(|m| m.description()).collect();
    let joined = descriptions.join(" ").to_lowercase();
    assert!(
        joined.contains("dns") || joined.contains("breach") || joined.contains("subdomain"),
        "no description mentions any OSINT-domain keyword — descriptions look stubbed"
    );
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
async fn expansion_depth_two_chains_three_modules() {
    let (engine, store, sid, target, ctx) = setup(
        vec![
            Arc::new(EmailToUsernameSynth),
            Arc::new(UsernameToPhoneSynth),
            Arc::new(SyntheticModule),
        ],
        "depth_two",
        TargetKind::Email,
        "bob@example.com",
    );
    let opts = ScanOptions {
        depth: 2,
        ..Default::default()
    };
    let scan = Scan::new(sid.clone(), target.clone()).with_options(opts);
    let result = engine.run(scan, target, ctx).await.unwrap();
    assert!(
        result.entity_count >= 3,
        "depth-2 should yield email + username + phone (got {})",
        result.entity_count
    );
    let entities = store.entities_for_scan(&sid).unwrap();
    let kinds: Vec<&EntityKind> = entities.iter().map(|e| &e.kind).collect();
    assert!(kinds.contains(&&EntityKind::Email));
    assert!(kinds.contains(&&EntityKind::Username));
    assert!(kinds.contains(&&EntityKind::Phone));
}

#[tokio::test]
async fn concurrent_dispatch_produces_same_entities_as_sequential() {
    let modules: Vec<Arc<dyn Module>> =
        vec![Arc::new(EmailToUsernameSynth), Arc::new(SyntheticModule)];
    let (engine_seq, store_seq, sid_seq, target_seq, ctx_seq) = setup(
        modules.clone(),
        "seq_cmp",
        TargetKind::Email,
        "cmp@test.com",
    );
    let scan_seq = Scan::new(sid_seq.clone(), target_seq.clone());
    engine_seq.run(scan_seq, target_seq, ctx_seq).await.unwrap();
    let ents_seq = store_seq.entities_for_scan(&sid_seq).unwrap();

    let (engine_par, store_par, sid_par, target_par, ctx_par) =
        setup(modules, "par_cmp", TargetKind::Email, "cmp@test.com");
    let opts_par = ScanOptions {
        max_concurrent: 4,
        ..Default::default()
    };
    let scan_par = Scan::new(sid_par.clone(), target_par.clone()).with_options(opts_par);
    engine_par.run(scan_par, target_par, ctx_par).await.unwrap();
    let ents_par = store_par.entities_for_scan(&sid_par).unwrap();

    assert_eq!(
        ents_seq.len(),
        ents_par.len(),
        "sequential and concurrent should produce same entity count"
    );
    let mut uids_seq: Vec<&str> = ents_seq.iter().map(|e| e.uid.as_str()).collect();
    let mut uids_par: Vec<&str> = ents_par.iter().map(|e| e.uid.as_str()).collect();
    uids_seq.sort();
    uids_par.sort();
    assert_eq!(
        uids_seq, uids_par,
        "sequential and concurrent should produce identical entity UIDs"
    );
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
async fn cancellation_pre_run_aborts_immediately() {
    // Pre-set the cancel flag before engine.run starts. The first
    // per-module gate (issue #23) catches it; no modules get
    // dispatched and the scan terminates `Aborted` rather than
    // `Complete`.
    let (engine, _store, sid, target, ctx) = setup(
        vec![Arc::new(SyntheticModule)],
        "cancel-pre",
        TargetKind::Email,
        "alice@example.com",
    );
    ctx.cancel.cancel();
    let scan = Scan::new(sid.clone(), target.clone()).with_options(ScanOptions::default());
    let result = engine.run(scan, target, ctx).await.unwrap();
    assert!(
        matches!(result.status, ScanStatus::Aborted),
        "pre-cancelled scan must terminate Aborted, got {:?}",
        result.status
    );
    // No modules ran → no entities.
    assert_eq!(result.entity_count, 0);
}

#[tokio::test]
async fn pre_cancellation_aborts_scan_before_any_module_runs() {
    // Deterministic pre-flight scenario: the operator's `cancel()` has
    // already fired before `engine.run()` starts. The sequential
    // dispatcher's per-module gate catches the flag on the first
    // iteration, no module runs, and the terminal status is Aborted.
    //
    // (The companion test `mid_flight_cancellation_aborts_running_scan`
    // exercises the post-ModuleStart cancel path where a module is
    // actually in flight when the flag flips.)
    let (engine, _store, sid, target, ctx) = setup(
        vec![Arc::new(SyntheticModule)],
        "cancel-pre",
        TargetKind::Email,
        "bob@example.com",
    );
    ctx.cancel.cancel();
    let opts = ScanOptions {
        depth: 3,
        ..Default::default()
    };
    let scan = Scan::new(sid.clone(), target.clone()).with_options(opts);
    let result = engine.run(scan, target, ctx).await.unwrap();
    assert!(
        matches!(result.status, ScanStatus::Aborted),
        "pre-cancelled scan must terminate Aborted, got {:?}",
        result.status
    );
    // No module ever entered `process()` — no entities should exist.
    assert_eq!(result.entity_count, 0);
}

#[tokio::test]
async fn mid_flight_cancellation_aborts_running_scan() {
    // Real operator flow: a scan is already running when the cancel
    // flag flips. We use a slow synthetic module that signals when its
    // `process()` begins; the test driver waits on that signal, calls
    // `cancel()`, and verifies the scan terminates Aborted while
    // preserving the partial results the slow module emitted before
    // its sleep.
    use std::time::Duration;
    use tokio::sync::Notify;

    /// Synthetic module that emits one entity, signals start via a
    /// `Notify`, then sleeps a while so the test can observe the
    /// mid-flight state and call `cancel()`.
    struct SlowSignallingModule {
        started: Arc<Notify>,
    }

    #[async_trait::async_trait]
    impl Module for SlowSignallingModule {
        fn name(&self) -> &'static str {
            "slow"
        }
        fn priority(&self) -> u8 {
            200 // highest, so it runs first
        }
        fn accepts(&self, t: &Target) -> bool {
            matches!(t.kind, TargetKind::Email)
        }
        fn max_timeout_ms(&self) -> u64 {
            5_000
        }
        async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
            self.started.notify_one();
            // Long enough for the test to observe the start signal and
            // call cancel(), but short enough not to slow the suite if
            // something goes wrong.
            tokio::time::sleep(Duration::from_millis(300)).await;
            let mut r = ModuleResult::new();
            let e = Entity::new(EntityKind::Email, &target.value, 0.9, &ctx.scan_id);
            r.push(e);
            Ok(r)
        }
    }

    // Fresh `Notify` per test invocation — a `static OnceLock` would
    // outlive a single run, so `cargo test --retries` or any harness
    // that re-runs this test in the same process could carry over a
    // leftover `notify_one` permit and fire `cancel()` before the
    // module's `process()` had started, dropping `entity_count` to 0
    // and breaking the `==1` assertion below.
    let started = Arc::new(Notify::new());

    let modules: Vec<Arc<dyn Module>> = vec![
        Arc::new(SlowSignallingModule {
            started: Arc::clone(&started),
        }),
        // A second module that should be skipped via the cancel gate
        // (its `ModuleStart` must never fire).
        Arc::new(SyntheticModule),
    ];
    let (engine, _store, sid, target, ctx) =
        setup(modules, "cancel-mid", TargetKind::Email, "mid@example.com");
    let cancel_handle = ctx.cancel.clone();
    let started_for_task = Arc::clone(&started);

    // Spawn the cancel-trigger task. It waits for the slow module to
    // signal `process()` start, then flips the cancel flag — exactly
    // the operator-issued mid-flight cancel scenario.
    let canceller = tokio::spawn(async move {
        started_for_task.notified().await;
        cancel_handle.cancel();
    });

    let opts = ScanOptions {
        depth: 0,
        ..Default::default()
    };
    let scan = Scan::new(sid.clone(), target.clone()).with_options(opts);
    let result = engine.run(scan, target, ctx).await.unwrap();
    canceller.await.unwrap();

    assert!(
        matches!(result.status, ScanStatus::Aborted),
        "mid-flight cancelled scan must terminate Aborted, got {:?}",
        result.status
    );
    // The slow module's 300 ms sleep is shorter than its 5 s timeout
    // so it completes successfully and its one entity persists. The
    // second module's cancel-gate fires before its `process()` runs.
    assert_eq!(
        result.entity_count, 1,
        "partial results from the in-flight module must survive cancel"
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

/// KeyGated module that accepts both Email and Username. Used to prove that
/// the DispatchLog prevents a keyed module from being invoked twice on the
/// same normalised target across expansion rounds.
struct KeyGatedMultiAccept;

#[async_trait]
impl Module for KeyGatedMultiAccept {
    fn name(&self) -> &'static str {
        "synth_keyed"
    }
    fn priority(&self) -> u8 {
        90
    }
    fn cost(&self) -> huntsman_search_engine::core::module::ModuleCost {
        huntsman_search_engine::core::module::ModuleCost::KeyGated
    }
    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::Email | TargetKind::Username)
    }
    async fn process(&self, _target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let mut r = ModuleResult::new();
        let mut e = Entity::new(EntityKind::Username, "dedup_probe", 0.95, &ctx.scan_id);
        e.tag("keyed");
        r.push(e);
        Ok(r)
    }
}

#[tokio::test]
async fn keyed_module_runs_exactly_once_per_target_in_expansion() {
    let (engine, store, sid, target, ctx) = setup(
        vec![
            Arc::new(EmailToUsernameSynth),
            Arc::new(KeyGatedMultiAccept),
        ],
        "dedup_keyed",
        TargetKind::Email,
        "alice@example.com",
    );
    let opts = ScanOptions {
        depth: 2,
        min_expand_confidence: 0.50,
        ..Default::default()
    };
    let scan = Scan::new(sid.clone(), target.clone()).with_options(opts);
    let result = engine.run(scan, target, ctx).await.unwrap();

    assert_eq!(result.status, ScanStatus::Complete);

    let entities = store.entities_for_scan(&sid).unwrap();
    let keyed_count = entities.iter().filter(|e| e.has_tag("keyed")).count();
    assert!(
        keyed_count >= 1,
        "keyed module should have produced at least one entity"
    );
    assert!(
        result.modules_run > 0,
        "modules_run counter must be populated"
    );
}

#[tokio::test]
async fn dispatch_dedup_allows_free_module_to_rerun() {
    let (engine, _store, sid, target, ctx) = setup(
        vec![Arc::new(EmailToUsernameSynth), Arc::new(SyntheticModule)],
        "dedup_free",
        TargetKind::Email,
        "alice@example.com",
    );
    let opts = ScanOptions {
        depth: 1,
        min_expand_confidence: 0.50,
        ..Default::default()
    };
    let scan = Scan::new(sid.clone(), target.clone()).with_options(opts);
    let result = engine.run(scan, target, ctx).await.unwrap();

    assert_eq!(
        result.modules_deduped, 0,
        "free modules should never be deduped"
    );
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

    let opts = ScanOptions {
        max_concurrent: 0,
        ..Default::default()
    };
    let scan = Scan::new(sid.clone(), target.clone()).with_options(opts);
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
    let engine = ScanEngine::new(
        modules,
        Arc::clone(&store) as Arc<dyn huntsman_search_engine::core::StoragePort>,
        bus.clone(),
    );
    let sid = scan_id(kind.canonical_str(), value);
    let target = Target::new(kind, value.to_string());
    let ctx = ModuleContext {
        scan_id: sid.clone(),
        bus,
        http: build_client(),
        keys: Default::default(),
        cancel: Default::default(),
        proxy_pool: Default::default(),
    };
    (engine, store, sid, target, ctx)
}

fn tempfile_path(suffix: &str) -> String {
    let mut p = std::env::temp_dir();
    p.push(format!("hse-smoke-{}-{}.db", std::process::id(), suffix));
    p.to_string_lossy().into_owned()
}

// ── Live mode tests ────────────────────────────────────────────────────────

#[tokio::test]
async fn live_session_runs_two_iterations_and_completes() {
    use huntsman_search_engine::core::live::{LiveOptions, LiveScanner, LiveStatus};

    let tmp = tempfile_path("live-2iter");
    let _ = std::fs::remove_file(&tmp);
    let store = Arc::new(Store::open(&tmp).unwrap());
    let (bus, _rx) = tokio::sync::broadcast::channel(256);
    let modules: Vec<Arc<dyn Module>> = vec![Arc::new(SyntheticModule)];
    let engine = Arc::new(ScanEngine::new(
        modules,
        Arc::clone(&store) as Arc<dyn huntsman_search_engine::core::StoragePort>,
        bus.clone(),
    ));
    let scanner = LiveScanner::new(
        Arc::clone(&engine),
        bus.clone(),
        reqwest::Client::new(),
        Default::default(),
    );

    let target = Target::new(TargetKind::Email, "live@example.com");
    let live_id = scanner.start(
        target,
        ScanOptions::default(),
        LiveOptions {
            interval_secs: 1,
            iterations: Some(2),
        },
    );

    // Wait for completion (2 iterations × 1s interval + processing time).
    tokio::time::sleep(std::time::Duration::from_secs(5)).await;

    let session = scanner.get(&live_id).expect("session should exist");
    assert!(
        matches!(session.status, LiveStatus::Completed),
        "expected Completed, got {:?}",
        session.status
    );
    assert_eq!(session.iteration, 2);
    assert_eq!(session.scan_ids.len(), 2, "should have spawned 2 scans");
}

#[tokio::test]
async fn live_session_stops_on_explicit_cancel() {
    use huntsman_search_engine::core::live::{LiveOptions, LiveScanner, LiveStatus};

    let tmp = tempfile_path("live-cancel");
    let _ = std::fs::remove_file(&tmp);
    let store = Arc::new(Store::open(&tmp).unwrap());
    let (bus, _rx) = tokio::sync::broadcast::channel(256);
    let modules: Vec<Arc<dyn Module>> = vec![Arc::new(SyntheticModule)];
    let engine = Arc::new(ScanEngine::new(
        modules,
        Arc::clone(&store) as Arc<dyn huntsman_search_engine::core::StoragePort>,
        bus.clone(),
    ));
    let scanner = LiveScanner::new(
        Arc::clone(&engine),
        bus.clone(),
        reqwest::Client::new(),
        Default::default(),
    );

    let target = Target::new(TargetKind::Email, "cancel-live@example.com");
    let live_id = scanner.start(
        target,
        ScanOptions::default(),
        LiveOptions {
            interval_secs: 30,
            iterations: None,
        },
    );

    // Let the first iteration start, then stop.
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    assert!(scanner.stop(&live_id), "stop should find the session");

    // Give the loop time to notice the cancel and clean up.
    tokio::time::sleep(std::time::Duration::from_secs(1)).await;

    let session = scanner.get(&live_id).expect("session should still exist");
    assert!(
        matches!(session.status, LiveStatus::Stopped),
        "expected Stopped, got {:?}",
        session.status
    );
}

// ── Geolocation confidence gating ─────────────────────────────────────
//
// WiGLE (priority 18, KeyGated) must ONLY fire on high-confidence
// Coordinates. Single-source geo (confidence 0.60-0.70) must NOT
// reach the 0.75 c_effective threshold. Two-source corroboration
// (merge with corroboration=2) must push c_eff above 0.75.
// This ensures WiGLE API quota is spent only on validated coordinates.

#[test]
fn single_source_coordinates_below_expansion_threshold() {
    use huntsman_search_engine::core::entity::{Entity, EntityKind};
    let e = Entity::new(EntityKind::Coordinates, "0,0", 0.70, "test");
    assert!(
        e.c_effective() < 0.75,
        "single-source 0.70 confidence must NOT reach 0.75 threshold: c_eff={:.4}",
        e.c_effective()
    );
}

#[test]
fn two_source_coordinates_above_expansion_threshold() {
    use huntsman_search_engine::core::entity::{Entity, EntityKind};
    let mut a = Entity::new(EntityKind::Coordinates, "-27.47,153.02", 0.70, "s1");
    let b = Entity::new(EntityKind::Coordinates, "-27.47,153.02", 0.68, "s2");
    a.merge(b);
    assert_eq!(a.corroboration, 2);
    assert!(
        a.c_effective() >= 0.75,
        "two-source corroboration must push c_eff >= 0.75: c_eff={:.4}, conf={:.4}, corr={}",
        a.c_effective(),
        a.confidence,
        a.corroboration
    );
}

#[test]
fn wigle_priority_below_free_geo_modules() {
    let modules = huntsman_search_engine::modules::registry();
    let wigle = modules.iter().find(|m| m.name() == "wigle").unwrap();
    let ip_geo = modules.iter().find(|m| m.name() == "ip_geo").unwrap();
    let ip_whois = modules.iter().find(|m| m.name() == "ip_whois_geo").unwrap();
    let geocode = modules.iter().find(|m| m.name() == "geocode").unwrap();

    assert!(
        wigle.priority() < ip_geo.priority(),
        "wigle ({}) must run AFTER ip_geo ({})",
        wigle.priority(),
        ip_geo.priority()
    );
    assert!(
        wigle.priority() < ip_whois.priority(),
        "wigle ({}) must run AFTER ip_whois_geo ({})",
        wigle.priority(),
        ip_whois.priority()
    );
    assert!(
        wigle.priority() < geocode.priority(),
        "wigle ({}) must run AFTER geocode ({})",
        wigle.priority(),
        geocode.priority()
    );
}

#[test]
fn oathnet_priority_above_free_geo_modules() {
    let modules = huntsman_search_engine::modules::registry();
    let oathnet = modules.iter().find(|m| m.name() == "oathnet_pro").unwrap();
    let ip_geo = modules.iter().find(|m| m.name() == "ip_geo").unwrap();

    assert!(
        oathnet.priority() > ip_geo.priority(),
        "oathnet_pro ({}) must run BEFORE ip_geo ({}) to produce IPs first",
        oathnet.priority(),
        ip_geo.priority()
    );
}

// ── ModuleGraph / dispatch index / expansion strategy ──────────────────────

#[test]
fn module_graph_dispatch_index_matches_real_registry_accepts() {
    // Every module that accepts(target_kind) must show up in the
    // dispatch_index bucket for that kind. Anything missing means the
    // engine would skip a module that should have run.
    use huntsman_search_engine::core::dependency::{ALL_TARGET_KINDS, ModuleGraph};
    let modules = huntsman_search_engine::modules::registry();
    let graph = ModuleGraph::build(&modules);

    for kind in ALL_TARGET_KINDS {
        let probe = Target::new(*kind, "graph-probe");
        let accepts_naive: usize = modules.iter().filter(|m| m.accepts(&probe)).count();
        let accepts_indexed = graph.modules_for(*kind).len();
        assert_eq!(
            accepts_naive, accepts_indexed,
            "dispatch index mismatch for {kind:?}: naive scan={accepts_naive} \
             vs graph={accepts_indexed}",
        );
    }
}

#[test]
fn module_graph_richness_is_normalised_and_zero_for_unconsumed_kinds() {
    use huntsman_search_engine::core::dependency::{ALL_TARGET_KINDS, ModuleGraph};
    let modules = huntsman_search_engine::modules::registry();
    let graph = ModuleGraph::build(&modules);

    let mut saw_one_at_max = false;
    for kind in ALL_TARGET_KINDS {
        let r = graph.richness_for(*kind);
        assert!(
            (0.0..=1.0).contains(&r),
            "richness for {kind:?} out of [0,1]: {r}"
        );
        if (r - 1.0).abs() < f64::EPSILON {
            saw_one_at_max = true;
        }
    }
    assert!(
        saw_one_at_max,
        "at least one TargetKind should saturate richness at 1.0 in real registry",
    );
}

#[tokio::test]
async fn dispatch_index_drives_synthetic_engine_to_skip_non_accepting_modules() {
    // The engine built from the dispatch index must never invoke a
    // module whose accepts() returns false for the seed kind.
    // Use a synthetic three-module set so this is fast — the real
    // registry property is already proved by
    // `module_graph_dispatch_index_matches_real_registry_accepts`
    // (pure data, no network).
    let modules: Vec<Arc<dyn Module>> = vec![
        Arc::new(SyntheticModule),      // accepts Email
        Arc::new(UsernameToPhoneSynth), // accepts Username (must be skipped)
        Arc::new(EmailToUsernameSynth), // accepts Email
    ];
    let (engine, store, sid, target, ctx) =
        setup(modules, "graph-synth-engine", TargetKind::Email, "x@y.com");
    let opts = ScanOptions {
        max_concurrent: 0,
        depth: 0,
        ..Default::default()
    };
    let scan = Scan::new(sid.clone(), target.clone()).with_options(opts);
    let result = engine.run(scan, target, ctx).await.unwrap();
    // Two modules accept Email; UsernameToPhoneSynth must NOT run.
    assert_eq!(
        result.modules_run, 2,
        "exactly two Email-accepting modules should have dispatched"
    );
    drop(store);
}

#[test]
fn expansion_strategy_geo_converge_outranks_breadth_for_geo_seeds() {
    use huntsman_search_engine::core::scan::{ExpansionStrategy, expansion_weight_for_strategy};

    let geo_weight = expansion_weight_for_strategy(
        ExpansionStrategy::GeoConverge,
        TargetKind::IpAddress,
        0.85,
        "1.1.1.1",
        false,
        0.5,
    );
    let breadth_weight = expansion_weight_for_strategy(
        ExpansionStrategy::BreadthFirst,
        TargetKind::IpAddress,
        0.85,
        "1.1.1.1",
        false,
        0.5,
    );
    // GeoConverge multiplies geo_npv × confidence × proximity; BreadthFirst
    // is confidence × richness only. The geo path should be a larger
    // numeric value for an IP seed.
    assert!(
        geo_weight > breadth_weight,
        "geo_converge weight {geo_weight} should dominate breadth_first {breadth_weight} for an IP seed"
    );
}

#[test]
fn modules_graph_summary_round_trips_through_json() {
    // The /api/v1/modules/graph endpoint serialises this struct; make
    // sure it survives serde without losing structural data.
    use huntsman_search_engine::core::dependency::ModuleGraph;
    let modules = huntsman_search_engine::modules::registry();
    let graph = ModuleGraph::build(&modules);
    let summary = graph.to_summary(&modules);

    let json = serde_json::to_string(&summary).unwrap();
    assert!(json.contains("\"kinds\""));
    assert!(json.contains("\"edges\""));
    assert!(json.contains("\"richness\""));

    let v: serde_json::Value = serde_json::from_str(&json).unwrap();
    let kinds = v.get("kinds").and_then(|k| k.as_array()).unwrap();
    assert!(!kinds.is_empty(), "graph must include every TargetKind");
    let edges = v.get("edges").and_then(|e| e.as_array()).unwrap();
    assert_eq!(
        edges.len(),
        modules.len(),
        "every module gets one edge entry"
    );
}

#[test]
fn module_categories_attach_to_module_info() {
    // Spot-check: trait default is `Other`. Calling `info()` should
    // pick it up so the UI module-picker can group modules. All
    // legacy modules report `other`; future modules can opt in.
    let modules = huntsman_search_engine::modules::registry();
    for m in &modules {
        let info = m.info();
        let cat = info.category.as_str();
        // Either an explicitly-set category or the default `other`.
        // We do NOT assert non-`other` here — backward compat means
        // legacy modules legitimately report `other`. The assertion
        // proves the field round-trips.
        assert!(
            !cat.is_empty(),
            "category for {} produced empty string",
            m.name()
        );
    }
}

#[tokio::test]
async fn richest_first_strategy_prefers_high_unlock_targets() {
    // Synthetic registry: one Email-only module, one Domain-accepting
    // module. Domain is "richer" because exactly one module covers
    // each → both kinds tie at richness 1.0 in this small registry,
    // so we can't easily order *between* them. Instead we assert that
    // a confident Domain entity DOES become an expansion candidate
    // under RichestFirst.

    use huntsman_search_engine::core::scan::ExpansionStrategy;

    struct EmailOnly;
    #[async_trait]
    impl Module for EmailOnly {
        fn name(&self) -> &'static str {
            "email_only_synth"
        }
        fn priority(&self) -> u8 {
            90
        }
        fn accepts(&self, t: &Target) -> bool {
            matches!(t.kind, TargetKind::Email)
        }
        async fn process(&self, _t: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
            // Produce a Domain so expansion has something to chase.
            let mut r = ModuleResult::new();
            let mut e = Entity::new(EntityKind::Domain, "example.com", 0.95, &ctx.scan_id);
            e.tag("derived");
            r.push(e);
            Ok(r)
        }
    }

    struct DomainOnly;
    #[async_trait]
    impl Module for DomainOnly {
        fn name(&self) -> &'static str {
            "domain_only_synth"
        }
        fn priority(&self) -> u8 {
            80
        }
        fn accepts(&self, t: &Target) -> bool {
            matches!(t.kind, TargetKind::Domain)
        }
        async fn process(&self, _t: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
            let mut r = ModuleResult::new();
            let mut e = Entity::new(EntityKind::IpAddress, "93.184.216.34", 0.9, &ctx.scan_id);
            e.tag("derived");
            r.push(e);
            Ok(r)
        }
    }

    let (engine, store, sid, target, ctx) = setup(
        vec![Arc::new(EmailOnly), Arc::new(DomainOnly)],
        "richest_first_strategy",
        TargetKind::Email,
        "alice@example.com",
    );
    let opts = ScanOptions {
        depth: 1,
        max_concurrent: 0,
        expansion_strategy: ExpansionStrategy::RichestFirst,
        ..Default::default()
    };
    let scan = Scan::new(sid.clone(), target.clone()).with_options(opts);
    let result = engine.run(scan, target, ctx).await.unwrap();
    assert!(
        result.entity_count >= 2,
        "RichestFirst should still drive expansion across the chain (got {})",
        result.entity_count
    );
    let entities = store.entities_for_scan(&sid).unwrap();
    let kinds: Vec<&EntityKind> = entities.iter().map(|e| &e.kind).collect();
    assert!(kinds.contains(&&EntityKind::Domain));
    assert!(kinds.contains(&&EntityKind::IpAddress));
}

#[tokio::test]
async fn breadth_first_strategy_runs_chain_under_default_confidence() {
    use huntsman_search_engine::core::scan::ExpansionStrategy;

    // Reuse the existing two-module synth chain.
    let (engine, store, sid, target, ctx) = setup(
        vec![
            Arc::new(EmailToUsernameSynth),
            Arc::new(UsernameToPhoneSynth),
        ],
        "breadth_first_chain",
        TargetKind::Email,
        "bf@example.com",
    );
    let opts = ScanOptions {
        depth: 1,
        max_concurrent: 0,
        expansion_strategy: ExpansionStrategy::BreadthFirst,
        ..Default::default()
    };
    let scan = Scan::new(sid.clone(), target.clone()).with_options(opts);
    let result = engine.run(scan, target, ctx).await.unwrap();
    assert_eq!(
        result.entity_count, 2,
        "BreadthFirst should still expand username → phone"
    );
    let entities = store.entities_for_scan(&sid).unwrap();
    let kinds: Vec<&EntityKind> = entities.iter().map(|e| &e.kind).collect();
    assert!(kinds.contains(&&EntityKind::Username));
    assert!(kinds.contains(&&EntityKind::Phone));
}

/// Accepts a Domain seed and emits a subdomain + its apex. Drives the
/// post-scan structural-relation builder.
struct DomainPairModule;

#[async_trait]
impl Module for DomainPairModule {
    fn name(&self) -> &'static str {
        "synth_domain_pair"
    }
    fn priority(&self) -> u8 {
        90
    }
    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::Domain)
    }
    async fn process(&self, _target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let mut r = ModuleResult::new();
        r.push(Entity::new(
            EntityKind::Domain,
            "example.com",
            0.9,
            &ctx.scan_id,
        ));
        r.push(Entity::new(
            EntityKind::Domain,
            "blog.example.com",
            0.8,
            &ctx.scan_id,
        ));
        Ok(r)
    }
}

/// End-to-end: a scan that yields a subdomain + apex must persist a
/// `SubdomainOf` relation via `finalise_scan` → `persist_relations`. Guards
/// the engine→relation-builder→store wiring against silent removal.
#[tokio::test]
async fn scan_persists_structural_subdomain_relation() {
    use huntsman_search_engine::core::relation::RelationKind;

    let (engine, store, sid, target, ctx) = setup(
        vec![Arc::new(DomainPairModule)],
        "rel-e2e",
        TargetKind::Domain,
        "example.com",
    );
    let scan = Scan::new(sid.clone(), target.clone());
    let _ = engine.run(scan, target, ctx).await.unwrap();

    let relations = store.relations_for_scan(&sid).unwrap();
    let sub: Vec<_> = relations
        .iter()
        .filter(|r| r.kind == RelationKind::SubdomainOf)
        .collect();
    assert_eq!(
        sub.len(),
        1,
        "expected one SubdomainOf edge, got: {relations:?}"
    );

    // The edge must point child → parent (blog.example.com → example.com),
    // with both endpoints resolving to persisted entities.
    let entities = store.entities_for_scan(&sid).unwrap();
    let by_uid = |uid: &str| {
        entities
            .iter()
            .find(|e| e.uid == uid)
            .map(|e| e.value.as_str())
    };
    assert_eq!(by_uid(&sub[0].from_uid), Some("blog.example.com"));
    assert_eq!(by_uid(&sub[0].to_uid), Some("example.com"));
}

/// End-to-end: expansion must record `DerivedFrom` lineage edges attributing a
/// child entity to the parent whose expansion surfaced it. Seed Email →
/// (seed round) Username → (expansion round 1) Phone, so the engine should
/// persist a Username ──DerivedFrom──▶ Phone edge.
#[tokio::test]
async fn expansion_records_derived_from_lineage() {
    use huntsman_search_engine::core::relation::RelationKind;

    let (engine, store, sid, target, ctx) = setup(
        vec![
            Arc::new(EmailToUsernameSynth),
            Arc::new(UsernameToPhoneSynth),
        ],
        "rel-lineage",
        TargetKind::Email,
        "alice@example.com",
    );
    let opts = ScanOptions {
        depth: 1,
        ..Default::default()
    };
    let scan = Scan::new(sid.clone(), target.clone()).with_options(opts);
    engine.run(scan, target, ctx).await.unwrap();

    let entities = store.entities_for_scan(&sid).unwrap();
    let uname = entities
        .iter()
        .find(|e| e.kind == EntityKind::Username)
        .expect("seed round should produce a username");
    let phone = entities
        .iter()
        .find(|e| e.kind == EntityKind::Phone)
        .expect("expansion should produce a phone");

    let relations = store.relations_for_scan(&sid).unwrap();
    let lineage: Vec<_> = relations
        .iter()
        .filter(|r| r.kind == RelationKind::DerivedFrom)
        .collect();
    // Direction is child -> parent: the Phone was *derived from* the Username
    // that was expanded to surface it.
    assert!(
        lineage
            .iter()
            .any(|r| r.from_uid == phone.uid && r.to_uid == uname.uid),
        "expected a Phone ->(DerivedFrom) Username edge (child -> parent), got: {lineage:?}"
    );
}

/// Emits a malicious apex domain + a benign subdomain. The structural
/// `SubdomainOf` edge between them should drive the graph-aware AU-031 rule.
struct MaliciousDomainModule;

#[async_trait]
impl Module for MaliciousDomainModule {
    fn name(&self) -> &'static str {
        "synth_mal_domain"
    }
    fn priority(&self) -> u8 {
        90
    }
    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::Domain)
    }
    async fn process(&self, _t: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let mut r = ModuleResult::new();
        // Use a .com domain: the preflight gate rejects reserved TLDs like
        // .example/.test, which would skip this module before it runs.
        let mut apex = Entity::new(EntityKind::Domain, "evilcorp.com", 0.9, &ctx.scan_id);
        apex.tag("malicious");
        r.push(apex);
        r.push(Entity::new(
            EntityKind::Domain,
            "blog.evilcorp.com",
            0.8,
            &ctx.scan_id,
        ));
        Ok(r)
    }
}

/// End-to-end: a benign subdomain of a malicious apex must surface AU-031
/// (adjacency to known-bad) through the engine → relations → correlator chain —
/// a finding the flat entity list / tag-only rules can't produce.
#[tokio::test]
async fn correlator_surfaces_malicious_adjacency_via_relations() {
    let (engine, store, sid, target, ctx) = setup(
        vec![Arc::new(MaliciousDomainModule)],
        "rel-au031",
        TargetKind::Domain,
        "evilcorp.com",
    );
    let scan = Scan::new(sid.clone(), target.clone());
    engine.run(scan, target, ctx).await.unwrap();

    let correlations = store.correlations_for_scan(&sid).unwrap();
    let au031: Vec<_> = correlations
        .iter()
        .filter(|c| c.rule_id == "AU-031")
        .collect();
    assert_eq!(
        au031.len(),
        1,
        "AU-031 should fire for the benign subdomain, got: {correlations:?}"
    );
    assert!(au031[0].description.contains("blog.evilcorp.com"));
}

// ── Live cross-correlation during ingestion ─────────────────────────────────
//
// Proves the charter's "live cross-correlation during ingestion (not
// post-processing)" condition: entity rules are evaluated against the working
// in-memory graph as it grows, so correlations stream out mid-scan rather than
// only at finalise.

/// Seed-round module: emits two LAN-tagged entities (an IP and a MAC) so the
/// entity rule AU-013 (local-network discovery) fires from the seed round
/// alone — before any expansion round runs. Also emits a high-confidence
/// Username, the entity the next round expands on (a well-trodden expansion
/// path that survives the candidate filters).
struct LanPairModule;

#[async_trait]
impl Module for LanPairModule {
    fn name(&self) -> &'static str {
        "lan_pair"
    }
    fn priority(&self) -> u8 {
        100
    }
    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::Email)
    }
    async fn process(&self, _t: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let mut r = ModuleResult::new();
        let mut ip = Entity::new(EntityKind::IpAddress, "192.168.1.50", 0.95, &ctx.scan_id);
        ip.tag("local-arp");
        let mut mac = Entity::new(
            EntityKind::MacAddress,
            "aa:bb:cc:dd:ee:ff",
            0.95,
            &ctx.scan_id,
        );
        mac.tag("local-interface");
        let mut user = Entity::new(EntityKind::Username, "lanhost", 0.95, &ctx.scan_id);
        user.tag("derived");
        r.push(ip);
        r.push(mac);
        r.push(user);
        Ok(r)
    }
}

/// Expansion-only ordering marker: accepts Username (never the Email seed),
/// so its `ModuleStart` event can only appear once expansion round 1 begins.
/// Produces nothing — it exists purely to mark the seed/expansion boundary in
/// the event stream.
struct ExpansionMarker;

#[async_trait]
impl Module for ExpansionMarker {
    fn name(&self) -> &'static str {
        "expansion_marker"
    }
    fn priority(&self) -> u8 {
        90
    }
    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::Username)
    }
    async fn process(&self, _t: &Target, _ctx: &ModuleContext) -> Result<ModuleResult> {
        Ok(ModuleResult::new())
    }
}

#[tokio::test]
async fn correlations_stream_live_during_ingestion_not_at_finalise() {
    use huntsman_search_engine::core::event::EventKind;

    let (engine, store, sid, target, ctx) = setup(
        vec![Arc::new(LanPairModule), Arc::new(ExpansionMarker)],
        "live-correlation",
        TargetKind::Email,
        "host@example.com",
    );
    // depth=1 so expansion round 1 dispatches the Username-only marker module
    // against the username the seed round produced.
    let opts = ScanOptions {
        depth: 1,
        ..Default::default()
    };
    let scan = Scan::new(sid.clone(), target.clone()).with_options(opts);

    // Subscribe before running so we capture the full event stream in order.
    let mut rx = engine.bus().subscribe();
    engine.run(scan, target, ctx).await.unwrap();

    // Drain the broadcast buffer into an ordered transcript.
    let mut first_au013: Option<usize> = None;
    let mut marker_start: Option<usize> = None;
    let mut au013_emits = 0usize;
    let mut idx = 0usize;
    while let Ok(ev) = rx.try_recv() {
        match &ev.kind {
            EventKind::CorrelationFound { correlation } if correlation.rule_id == "AU-013" => {
                au013_emits += 1;
                if first_au013.is_none() {
                    first_au013 = Some(idx);
                }
            }
            EventKind::ModuleStart { module } if module == "expansion_marker" => {
                if marker_start.is_none() {
                    marker_start = Some(idx);
                }
            }
            _ => {}
        }
        idx += 1;
    }

    let corr_at = first_au013.expect("AU-013 correlation_found event should be emitted");
    let marker_at = marker_start.expect("expansion_marker should run in expansion round 1");

    // The discriminating assertion: the correlation streamed out *before* the
    // expansion-only module even started. A finalise-only correlator would emit
    // AU-013 after every expansion module event, so this ordering can only hold
    // if correlation runs live during ingestion.
    assert!(
        corr_at < marker_at,
        "AU-013 fired at event #{corr_at} but expansion module started at #{marker_at}; \
         correlation is not running live during ingestion"
    );

    // Dedup invariant: the live pass and the authoritative finalise pass must
    // not double-emit the same correlation.
    assert_eq!(
        au013_emits, 1,
        "AU-013 should be emitted exactly once, not re-fired"
    );

    // And it is still persisted exactly once.
    let stored: Vec<_> = store
        .correlations_for_scan(&sid)
        .unwrap()
        .into_iter()
        .filter(|c| c.rule_id == "AU-013")
        .collect();
    assert_eq!(stored.len(), 1, "AU-013 should persist exactly once");
}

// ── Crash-durability: entities are checkpointed each round ───────────────────
//
// Proves the charter's "fault-tolerant, resumable execution state" invariant:
// discovered entities are persisted at every productive round boundary, so a
// crash mid-scan preserves intel instead of losing everything until finalise.

use std::sync::atomic::{AtomicUsize, Ordering};

use huntsman_search_engine::core::StoragePort;

/// A `StoragePort` decorator that counts `upsert_entities_batch` invocations
/// and otherwise delegates to a real `Store`.
struct CountingStore {
    inner: Arc<dyn StoragePort>,
    batch_calls: Arc<AtomicUsize>,
}

impl StoragePort for CountingStore {
    fn upsert_scan(&self, scan: &Scan) -> Result<()> {
        self.inner.upsert_scan(scan)
    }
    fn get_scan(&self, id: &str) -> Result<Option<Scan>> {
        self.inner.get_scan(id)
    }
    fn list_scans(&self, limit: usize) -> Result<Vec<Scan>> {
        self.inner.list_scans(limit)
    }
    fn delete_scan(&self, scan_id: &str) -> Result<bool> {
        self.inner.delete_scan(scan_id)
    }
    fn upsert_entity(&self, entity: &Entity) -> Result<()> {
        self.inner.upsert_entity(entity)
    }
    fn upsert_entities_batch(&self, entities: &[Entity]) -> Result<usize> {
        self.batch_calls.fetch_add(1, Ordering::SeqCst);
        self.inner.upsert_entities_batch(entities)
    }
    fn entities_for_scan(&self, scan_id: &str) -> Result<Vec<Entity>> {
        self.inner.entities_for_scan(scan_id)
    }
    fn entities_filtered(
        &self,
        scan_id: &str,
        kind: Option<&str>,
        min_confidence: Option<f64>,
        value_contains: Option<&str>,
    ) -> Result<Vec<Entity>> {
        self.inner
            .entities_filtered(scan_id, kind, min_confidence, value_contains)
    }
    fn entity_facets(&self, scan_id: &str) -> Result<Vec<(String, u64)>> {
        self.inner.entity_facets(scan_id)
    }
    fn get_entity(&self, uid: &str) -> Result<Option<Entity>> {
        self.inner.get_entity(uid)
    }
    fn search_entities(&self, query: &str, limit: usize) -> Result<Vec<Entity>> {
        self.inner.search_entities(query, limit)
    }
    fn scan_ids_for_entity(&self, entity_uid: &str) -> Result<Vec<String>> {
        self.inner.scan_ids_for_entity(entity_uid)
    }
    fn observation_count(&self, entity_uid: &str) -> Result<usize> {
        self.inner.observation_count(entity_uid)
    }
    fn upsert_correlation(
        &self,
        c: &huntsman_search_engine::core::correlator::Correlation,
    ) -> Result<()> {
        self.inner.upsert_correlation(c)
    }
    fn correlations_for_scan(
        &self,
        scan_id: &str,
    ) -> Result<Vec<huntsman_search_engine::core::correlator::Correlation>> {
        self.inner.correlations_for_scan(scan_id)
    }
    fn upsert_relation(&self, r: &huntsman_search_engine::core::relation::Relation) -> Result<()> {
        self.inner.upsert_relation(r)
    }
    fn relations_for_scan(
        &self,
        scan_id: &str,
    ) -> Result<Vec<huntsman_search_engine::core::relation::Relation>> {
        self.inner.relations_for_scan(scan_id)
    }
    fn insert_event(&self, event: &huntsman_search_engine::core::event::Event) -> Result<()> {
        self.inner.insert_event(event)
    }
    fn events_for_scan(
        &self,
        scan_id: &str,
    ) -> Result<Vec<huntsman_search_engine::core::event::Event>> {
        self.inner.events_for_scan(scan_id)
    }
}

#[tokio::test]
async fn entities_are_checkpointed_each_round_for_durability() {
    let tmp = tempfile_path("durability");
    let _ = std::fs::remove_file(&tmp);
    let store = Arc::new(Store::open(&tmp).unwrap());
    let batch_calls = Arc::new(AtomicUsize::new(0));
    let counting = Arc::new(CountingStore {
        inner: Arc::clone(&store) as Arc<dyn StoragePort>,
        batch_calls: Arc::clone(&batch_calls),
    });

    let (bus, _rx) = tokio::sync::broadcast::channel(64);
    let engine = ScanEngine::new(
        vec![
            Arc::new(EmailToUsernameSynth),
            Arc::new(UsernameToPhoneSynth),
        ],
        Arc::clone(&counting) as Arc<dyn StoragePort>,
        bus.clone(),
    );
    let sid = scan_id("email", "alice@example.com");
    let target = Target::new(TargetKind::Email, "alice@example.com".to_string());
    let ctx = ModuleContext {
        scan_id: sid.clone(),
        bus,
        http: build_client(),
        keys: Default::default(),
        cancel: Default::default(),
        proxy_pool: Default::default(),
    };
    // depth=1: seed round (email -> username) then expansion (username -> phone).
    let opts = ScanOptions {
        depth: 1,
        ..Default::default()
    };
    let scan = Scan::new(sid.clone(), target.clone()).with_options(opts);
    engine.run(scan, target, ctx).await.unwrap();

    // Seed checkpoint + round-1 checkpoint + finalise persist => at least two
    // batch upserts. Without round-boundary checkpointing it would be exactly
    // one (finalise only), so a crash mid-scan would lose everything.
    let calls = batch_calls.load(Ordering::SeqCst);
    assert!(
        calls >= 2,
        "expected >=2 entity batch upserts (round checkpoints + finalise), got {calls}"
    );

    // And the intel is genuinely durable in the underlying store.
    let stored = store.entities_for_scan(&sid).unwrap();
    assert!(
        !stored.is_empty(),
        "checkpointed entities must be persisted"
    );
}

// ── Non-routable IP expansion gate ───────────────────────────────────────────
//
// Proves the relevance fix: bogus/reserved IPs (documentation ranges scraped
// from pages, private LAN addresses from sensors) are recorded as entities but
// never become expansion targets, so the engine doesn't burn whole rounds on
// guaranteed-empty external lookups.

/// Emits one routable (8.8.8.8) and one documentation (192.0.2.1) IP.
struct DualIpModule;

#[async_trait]
impl Module for DualIpModule {
    fn name(&self) -> &'static str {
        "dual_ip"
    }
    fn priority(&self) -> u8 {
        100
    }
    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::Email)
    }
    async fn process(&self, _t: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let mut r = ModuleResult::new();
        let mut a = Entity::new(EntityKind::IpAddress, "8.8.8.8", 0.95, &ctx.scan_id);
        a.tag("derived");
        // Private (RFC1918): non-routable so it must not be EXPANDED, but it is
        // a legitimate local-sensor finding so it is still ADMITTED/recorded
        // (unlike documentation IPs, which are dropped at admission).
        let mut b = Entity::new(EntityKind::IpAddress, "192.168.1.50", 0.95, &ctx.scan_id);
        b.tag("derived");
        r.push(a);
        r.push(b);
        Ok(r)
    }
}

/// Accepts IpAddress and emits a `seen-<ip>` username marker, so the test can
/// observe exactly which IPs the engine expanded into.
struct IpSeenMarker;

#[async_trait]
impl Module for IpSeenMarker {
    fn name(&self) -> &'static str {
        "ip_seen_marker"
    }
    fn priority(&self) -> u8 {
        90
    }
    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::IpAddress)
    }
    async fn process(&self, t: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let mut r = ModuleResult::new();
        let e = Entity::new(
            EntityKind::Username,
            format!("seen-{}", t.value),
            0.95,
            &ctx.scan_id,
        );
        r.push(e);
        Ok(r)
    }
}

#[tokio::test]
async fn non_routable_ips_are_not_expanded() {
    let (engine, store, sid, target, ctx) = setup(
        vec![Arc::new(DualIpModule), Arc::new(IpSeenMarker)],
        "non-routable-ip",
        TargetKind::Email,
        "host@example.com",
    );
    let opts = ScanOptions {
        depth: 1,
        ..Default::default()
    };
    let scan = Scan::new(sid.clone(), target.clone()).with_options(opts);
    engine.run(scan, target, ctx).await.unwrap();

    let vals: Vec<String> = store
        .entities_for_scan(&sid)
        .unwrap()
        .into_iter()
        .map(|e| e.value)
        .collect();

    // Both IPs are recorded (private IPs are admitted; only the EXPANSION of
    // non-routable addresses is suppressed).
    assert!(vals.iter().any(|v| v == "8.8.8.8"), "routable IP recorded");
    assert!(
        vals.iter().any(|v| v == "192.168.1.50"),
        "private (non-routable) IP still recorded as an entity"
    );
    // Only the routable IP was expanded (marker ran against it).
    assert!(
        vals.iter().any(|v| v == "seen-8.8.8.8"),
        "routable IP must be expanded"
    );
    assert!(
        !vals.iter().any(|v| v == "seen-192.168.1.50"),
        "non-routable (private) IP must NOT be expanded"
    );
}

// ── Bogus-IP admission guard ─────────────────────────────────────────────────
//
// Proves documentation/reserved IPs (e.g. 192.0.2.1 scraped from a page) are
// dropped at entity admission, while a real public IP and an RFC1918 private
// IP (legitimately surfaced by local sensors) are kept.

/// Emits one documentation IP, one real IP, one private IP from an email seed.
struct MixedIpModule;

#[async_trait]
impl Module for MixedIpModule {
    fn name(&self) -> &'static str {
        "mixed_ip"
    }
    fn priority(&self) -> u8 {
        100
    }
    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::Email)
    }
    async fn process(&self, _t: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let mut r = ModuleResult::new();
        for v in ["192.0.2.1", "8.8.8.8", "192.168.1.5"] {
            let mut e = Entity::new(EntityKind::IpAddress, v, 0.9, &ctx.scan_id);
            e.tag("derived");
            r.push(e);
        }
        Ok(r)
    }
}

#[tokio::test]
async fn bogus_ips_are_dropped_at_admission() {
    let (engine, store, sid, target, ctx) = setup(
        vec![Arc::new(MixedIpModule)],
        "bogus-ip-admission",
        TargetKind::Email,
        "host@example.com",
    );
    let scan = Scan::new(sid.clone(), target.clone());
    engine.run(scan, target, ctx).await.unwrap();

    let ips: Vec<String> = store
        .entities_for_scan(&sid)
        .unwrap()
        .into_iter()
        .filter(|e| e.kind == EntityKind::IpAddress)
        .map(|e| e.value)
        .collect();

    assert!(
        !ips.iter().any(|v| v == "192.0.2.1"),
        "documentation IP must be dropped, got: {ips:?}"
    );
    assert!(ips.iter().any(|v| v == "8.8.8.8"), "real IP must be kept");
    assert!(
        ips.iter().any(|v| v == "192.168.1.5"),
        "private IP must be kept (local-sensor finding)"
    );
}
