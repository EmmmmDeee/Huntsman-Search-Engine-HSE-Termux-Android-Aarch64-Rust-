//! Reactive Directed Acyclic Graph (DAG) state machine with backpressure and cycle mitigation.

use crate::error::HuntsmanError;
use crate::governor::NetworkGovernor;
use crate::model::{Entity, EntityId, EntityKind};
use crate::transport::Transport;
use async_trait::async_trait;
use std::collections::{HashSet, VecDeque};
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

/// Upper bound on discovered entities awaiting expansion, keeping traversal within the memory
/// ceiling. Seeds are never subject to it: [`DagEngine::execute`] drains them lazily from the
/// caller's vector and queues every one, so operator input is never dropped from expansion.
pub const MAX_FRONTIER: usize = 4096;

/// Trait implemented by modular collectors.
#[async_trait]
pub trait Collector: Send + Sync {
    /// Human-readable module identifier.
    fn name(&self) -> &'static str;

    /// Evaluates if this collector can process the provided entity kind.
    fn can_consume(&self, kind: &EntityKind) -> bool;

    /// Execute the protocol interrogation or analysis, emitting new discovered entities.
    ///
    /// # Errors
    /// Returns a [`HuntsmanError`] when the collector's wire dialogue or decode fails; the DAG
    /// isolates the failure to this module and continues the remaining frontier.
    async fn process(
        &self,
        input: &Entity,
        transport: Arc<dyn Transport>,
        governor: NetworkGovernor,
    ) -> Result<Vec<Entity>, HuntsmanError>;
}

/// Registration envelope for active modules.
pub struct ModuleRegistration {
    collector: Arc<dyn Collector>,
}

impl ModuleRegistration {
    /// Bind an implementation to an execution envelope.
    #[must_use]
    pub fn new(collector: Arc<dyn Collector>) -> Self {
        Self { collector }
    }

    /// Consume the envelope, yielding the registered collector handle.
    #[must_use]
    pub fn into_collector(self) -> Arc<dyn Collector> {
        self.collector
    }
}

/// Counts describing how one [`DagEngine::execute`] run ended, so a caller can tell a complete
/// traversal from one whose expansion was cut short.
///
/// Every emitted entity is accounted for exactly once: `emitted` equals `expanded` plus
/// `overflow_unexpanded`, `depth_limited` and `no_consumer`. The counts, like the deduplication
/// state behind them, belong to that run alone; a later run on the same engine starts from zero.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ExecutionReport {
    /// Distinct entities delivered to the sink: seeds and discoveries, each once per run.
    pub emitted: usize,
    /// Entities handed to the collectors that consume their kind.
    pub expanded: usize,
    /// Discoveries emitted but never expanded because the frontier was at [`MAX_FRONTIER`].
    /// Non-zero means the graph below those entities is missing from this run.
    pub overflow_unexpanded: usize,
    /// Collector invocations that returned an error. Each was isolated and traversal continued,
    /// so whatever that invocation would have discovered is missing from this run.
    pub collector_failures: usize,
    /// Entities emitted but not expanded because they sit at the engine's maximum hop depth.
    pub depth_limited: usize,
    /// Entities emitted but not expanded because no registered collector consumes their kind.
    pub no_consumer: usize,
}

/// Where an entity entering a run came from, which decides whether the frontier cap applies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Origin {
    /// Supplied by the caller: always queued for expansion.
    Seed,
    /// Produced by a collector: queued only while the frontier is below [`MAX_FRONTIER`].
    Discovery,
}

/// What becomes of an admitted entity once it has been emitted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Disposition {
    /// Queued on the frontier for the collectors to expand.
    Expand,
    /// At the engine's maximum hop depth; a leaf by configuration.
    DepthLimited,
    /// No registered collector consumes its kind; a leaf by construction.
    NoConsumer,
    /// A discovery that found the frontier full; its subtree is missing from this run.
    Overflow,
}

/// Mutable state of one traversal. It is owned by the `execute` call, so runs on the same engine
/// never share it, a cancelled run leaves nothing behind, and its memory is freed on return.
struct Run {
    seen: HashSet<EntityId>,
    frontier: VecDeque<Entity>,
    report: ExecutionReport,
}

/// Core reactive DAG execution engine.
pub struct DagEngine {
    modules: Vec<Arc<dyn Collector>>,
    transport: Arc<dyn Transport>,
    governor: NetworkGovernor,
    max_hop_depth: u8,
}

impl DagEngine {
    /// Construct a new DAG instance.
    #[must_use]
    pub fn new(
        transport: Arc<dyn Transport>,
        governor: NetworkGovernor,
        max_hop_depth: u8,
    ) -> Self {
        Self {
            modules: Vec::new(),
            transport,
            governor,
            max_hop_depth,
        }
    }

    /// Register a collector into the processing graph.
    pub fn register_module(&mut self, registration: ModuleRegistration) {
        self.modules.push(registration.into_collector());
    }

    /// Decide whether `entity` can be queued for expansion in `run`.
    fn disposition(&self, run: &Run, entity: &Entity, origin: Origin) -> Disposition {
        if entity.hop_depth >= self.max_hop_depth {
            return Disposition::DepthLimited;
        }
        if !self
            .modules
            .iter()
            .any(|module| module.can_consume(&entity.kind))
        {
            return Disposition::NoConsumer;
        }
        if origin == Origin::Discovery && run.frontier.len() >= MAX_FRONTIER {
            return Disposition::Overflow;
        }
        Disposition::Expand
    }

    /// Deduplicate `entity` within `run`, emit it, and queue it for expansion when its depth, a
    /// consuming collector and (for discoveries) frontier capacity allow.
    async fn admit(
        &self,
        run: &mut Run,
        entity: Entity,
        origin: Origin,
        outbound_sink: &mpsc::Sender<Entity>,
    ) -> Result<(), HuntsmanError> {
        if !run.seen.insert(entity.provenance.entity_id) {
            return Ok(());
        }
        let queued = match self.disposition(run, &entity, origin) {
            Disposition::Expand => Some(entity.clone()),
            Disposition::DepthLimited => {
                debug!(
                    "Entity {} reached max depth ({})",
                    entity.kind.canonical_value(),
                    self.max_hop_depth
                );
                run.report.depth_limited += 1;
                None
            }
            Disposition::NoConsumer => {
                debug!(
                    "No registered collector consumes {}",
                    entity.kind.canonical_value()
                );
                run.report.no_consumer += 1;
                None
            }
            Disposition::Overflow => {
                warn!(
                    "Frontier at capacity ({MAX_FRONTIER}); {} emitted but not expanded",
                    entity.kind.canonical_value()
                );
                run.report.overflow_unexpanded += 1;
                None
            }
        };
        outbound_sink
            .send(entity)
            .await
            .map_err(|e| HuntsmanError::ChannelCongestion(e.to_string()))?;
        run.report.emitted += 1;
        if let Some(next) = queued {
            run.frontier.push_back(next);
        }
        Ok(())
    }

    /// Hand `current` to every collector that consumes its kind and admit what they discover.
    async fn expand(
        &self,
        run: &mut Run,
        current: &Entity,
        outbound_sink: &mpsc::Sender<Entity>,
    ) -> Result<(), HuntsmanError> {
        run.report.expanded += 1;
        for collector in &self.modules {
            if !collector.can_consume(&current.kind) {
                continue;
            }
            match collector
                .process(current, self.transport.clone(), self.governor.clone())
                .await
            {
                Ok(discovered) => {
                    for mut item in discovered {
                        item.hop_depth = current.hop_depth.saturating_add(1);
                        info!(
                            "Discovered node [{}] via {}",
                            item.kind.canonical_value(),
                            collector.name()
                        );
                        self.admit(run, item, Origin::Discovery, outbound_sink)
                            .await?;
                    }
                }
                Err(err) => {
                    run.report.collector_failures += 1;
                    error!(
                        "Module {} failed on {}: {}",
                        collector.name(),
                        current.kind.canonical_value(),
                        err
                    );
                }
            }
        }
        Ok(())
    }

    /// Seed the pipeline and expand breadth-first until every seed's frontier drains.
    ///
    /// All traversal state (the deduplication set, the frontier and the counts) lives inside
    /// this call and is freed when it returns, so re-running the same seeds on one engine,
    /// retrying after a failure or cancellation, and running several executes concurrently on a
    /// shared engine are independent runs. Within a run every entity is emitted to
    /// `outbound_sink` once, deduplicated by its deterministic id, and queued for expansion
    /// while it is below `max_hop_depth` and some registered collector consumes its kind.
    ///
    /// Seeds are drained lazily: the next one is admitted only once the previous seed's
    /// discoveries are exhausted, so the frontier holds discoveries alone and every seed is
    /// expanded. The frontier is capped at [`MAX_FRONTIER`] pending discoveries to bound memory;
    /// a discovery past the cap is still emitted but not expanded, and the returned
    /// [`ExecutionReport`] counts it so the incomplete expansion is visible to the caller.
    ///
    /// # Errors
    /// Returns [`HuntsmanError::ChannelCongestion`] if `outbound_sink` closes, since discoveries
    /// would otherwise be lost silently.
    pub async fn execute(
        &self,
        seeds: Vec<Entity>,
        outbound_sink: mpsc::Sender<Entity>,
    ) -> Result<ExecutionReport, HuntsmanError> {
        let mut run = Run {
            seen: HashSet::new(),
            frontier: VecDeque::new(),
            report: ExecutionReport::default(),
        };
        let mut seeds = seeds.into_iter();

        loop {
            let current = match run.frontier.pop_front() {
                Some(entity) => entity,
                None => match seeds.next() {
                    Some(seed) => {
                        self.admit(&mut run, seed, Origin::Seed, &outbound_sink)
                            .await?;
                        continue;
                    }
                    None => break,
                },
            };
            self.expand(&mut run, &current, &outbound_sink).await?;
        }

        Ok(run.report)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Entity, EntityKind, EpistemicLevel, ProvenanceEnvelope};
    use crate::transport::MockTransport;
    use std::time::Duration;

    struct DummySubdomainCollector;

    #[async_trait]
    impl Collector for DummySubdomainCollector {
        fn name(&self) -> &'static str {
            "dummy-dns"
        }

        fn can_consume(&self, kind: &EntityKind) -> bool {
            matches!(kind, EntityKind::Domain(_))
        }

        async fn process(
            &self,
            input: &Entity,
            _transport: Arc<dyn Transport>,
            _governor: NetworkGovernor,
        ) -> Result<Vec<Entity>, HuntsmanError> {
            if let EntityKind::Domain(ref d) = input.kind {
                if d == "example.com" {
                    let sub = EntityKind::new_domain("api.example.com")?;
                    let prov = ProvenanceEnvelope::new(
                        self.name(),
                        1_710_000_000,
                        b"dns-response-mock",
                        &sub,
                        EpistemicLevel::DirectObservation,
                    );
                    return Ok(vec![Entity {
                        provenance: prov,
                        kind: sub,
                        hop_depth: input.hop_depth + 1,
                    }]);
                }
            }
            Ok(vec![])
        }
    }

    #[tokio::test]
    async fn hermetic_dag_execution_emits_seed_and_discovery() {
        let mock_transport = Arc::new(MockTransport::new());
        let governor = NetworkGovernor::new(crate::governor::GovernorConfig::default());
        let mut engine = DagEngine::new(mock_transport, governor, 3);

        engine.register_module(ModuleRegistration::new(Arc::new(DummySubdomainCollector)));

        let seed_kind = match EntityKind::new_domain("example.com") {
            Ok(kind) => kind,
            Err(err) => panic!("seed domain must canonicalize: {err}"),
        };

        let seed_prov = ProvenanceEnvelope::new(
            "seed",
            1_710_000_000,
            b"manual-seed",
            &seed_kind,
            EpistemicLevel::DirectObservation,
        );
        let seed = Entity {
            provenance: seed_prov,
            kind: seed_kind,
            hop_depth: 0,
        };

        let (sink_tx, mut sink_rx) = mpsc::channel(16);
        let report = match engine.execute(vec![seed], sink_tx).await {
            Ok(report) => report,
            Err(err) => panic!("execute failed: {err}"),
        };
        assert_eq!(
            report,
            ExecutionReport {
                emitted: 2,
                expanded: 2,
                ..ExecutionReport::default()
            }
        );

        let mut collected = Vec::new();
        while let Ok(item) = sink_rx.try_recv() {
            collected.push(item);
        }

        // Must observe the seed plus the discovered sub-domain.
        assert_eq!(collected.len(), 2);
        assert_eq!(collected[0].kind.canonical_value(), "example.com");
        assert_eq!(collected[1].kind.canonical_value(), "api.example.com");
        assert_eq!(collected[1].hop_depth, 1);
    }

    /// Maps `dN.example` to `d(N+1).example`, so expansion depth is directly observable.
    struct ChainCollector;

    #[async_trait]
    impl Collector for ChainCollector {
        fn name(&self) -> &'static str {
            "chain"
        }

        fn can_consume(&self, kind: &EntityKind) -> bool {
            matches!(kind, EntityKind::Domain(_))
        }

        async fn process(
            &self,
            input: &Entity,
            _transport: Arc<dyn Transport>,
            _governor: NetworkGovernor,
        ) -> Result<Vec<Entity>, HuntsmanError> {
            let EntityKind::Domain(ref d) = input.kind else {
                return Ok(vec![]);
            };
            let Some(n) = d
                .strip_prefix('d')
                .and_then(|rest| rest.strip_suffix(".example"))
                .and_then(|num| num.parse::<u32>().ok())
            else {
                return Ok(vec![]);
            };
            Ok(vec![domain_entity(&format!("d{}.example", n + 1), 0)])
        }
    }

    /// Produces `sub.{name}` for any domain not already under a `sub.` label; leaf otherwise.
    struct SubdomainCollector;

    #[async_trait]
    impl Collector for SubdomainCollector {
        fn name(&self) -> &'static str {
            "subdomain"
        }

        fn can_consume(&self, kind: &EntityKind) -> bool {
            matches!(kind, EntityKind::Domain(_))
        }

        async fn process(
            &self,
            input: &Entity,
            _transport: Arc<dyn Transport>,
            _governor: NetworkGovernor,
        ) -> Result<Vec<Entity>, HuntsmanError> {
            let EntityKind::Domain(ref d) = input.kind else {
                return Ok(vec![]);
            };
            if d.starts_with("sub.") {
                return Ok(vec![]);
            }
            Ok(vec![domain_entity(&format!("sub.{d}"), 0)])
        }
    }

    /// Fans `fanout.example` out to `MAX_FRONTIER + 5` children; each child yields one leaf.
    struct FanoutCollector;

    #[async_trait]
    impl Collector for FanoutCollector {
        fn name(&self) -> &'static str {
            "fanout"
        }

        fn can_consume(&self, kind: &EntityKind) -> bool {
            matches!(kind, EntityKind::Domain(_))
        }

        async fn process(
            &self,
            input: &Entity,
            _transport: Arc<dyn Transport>,
            _governor: NetworkGovernor,
        ) -> Result<Vec<Entity>, HuntsmanError> {
            let EntityKind::Domain(ref d) = input.kind else {
                return Ok(vec![]);
            };
            if d == "fanout.example" {
                return Ok((0..MAX_FRONTIER + 5)
                    .map(|i| domain_entity(&format!("c{i}.fanout.example"), 0))
                    .collect());
            }
            if d.ends_with(".fanout.example") && !d.starts_with("leaf.") {
                return Ok(vec![domain_entity(&format!("leaf.{d}"), 0)]);
            }
            Ok(vec![])
        }
    }

    /// Fails on every domain it is handed.
    struct FailingCollector;

    #[async_trait]
    impl Collector for FailingCollector {
        fn name(&self) -> &'static str {
            "failing"
        }

        fn can_consume(&self, kind: &EntityKind) -> bool {
            matches!(kind, EntityKind::Domain(_))
        }

        async fn process(
            &self,
            _input: &Entity,
            _transport: Arc<dyn Transport>,
            _governor: NetworkGovernor,
        ) -> Result<Vec<Entity>, HuntsmanError> {
            Err(HuntsmanError::Protocol("injected failure".to_owned()))
        }
    }

    fn domain_entity(name: &str, hop_depth: u8) -> Entity {
        let kind = match EntityKind::new_domain(name) {
            Ok(kind) => kind,
            Err(err) => panic!("domain must canonicalize: {err}"),
        };
        let provenance = ProvenanceEnvelope::new(
            "test",
            1_710_000_000,
            name.as_bytes(),
            &kind,
            EpistemicLevel::DirectObservation,
        );
        Entity {
            provenance,
            kind,
            hop_depth,
        }
    }

    fn engine(max_hop_depth: u8) -> DagEngine {
        DagEngine::new(
            Arc::new(MockTransport::new()),
            NetworkGovernor::new(crate::governor::GovernorConfig::default()),
            max_hop_depth,
        )
    }

    /// Drains `rx` on its own task so `execute` never blocks on sink capacity.
    fn drain(mut rx: mpsc::Receiver<Entity>) -> tokio::task::JoinHandle<Vec<Entity>> {
        tokio::spawn(async move {
            let mut items = Vec::new();
            while let Some(item) = rx.recv().await {
                items.push(item);
            }
            items
        })
    }

    async fn collected(handle: tokio::task::JoinHandle<Vec<Entity>>) -> Vec<String> {
        match handle.await {
            Ok(items) => items.iter().map(|e| e.kind.canonical_value()).collect(),
            Err(err) => panic!("drain task failed: {err}"),
        }
    }

    /// Run `seeds` through `engine` with a drained sink of `capacity`, returning the report and
    /// the canonical values the sink received, in order.
    async fn execute_and_collect(
        engine: &DagEngine,
        seeds: Vec<Entity>,
        capacity: usize,
    ) -> (ExecutionReport, Vec<String>) {
        let (tx, rx) = mpsc::channel(capacity);
        let drained = drain(rx);
        let report = match engine.execute(seeds, tx).await {
            Ok(report) => report,
            Err(err) => panic!("execute failed: {err}"),
        };
        (report, collected(drained).await)
    }

    /// The report accounts for every emitted entity exactly once.
    fn assert_accounted(report: ExecutionReport) {
        assert_eq!(
            report.emitted,
            report.expanded
                + report.overflow_unexpanded
                + report.depth_limited
                + report.no_consumer,
            "{report:?}"
        );
    }

    #[tokio::test]
    async fn discoveries_are_expanded_until_the_depth_limit() {
        let mut engine = engine(2);
        engine.register_module(ModuleRegistration::new(Arc::new(ChainCollector)));
        let (sink_tx, mut sink_rx) = mpsc::channel(16);

        let report = match engine
            .execute(vec![domain_entity("d0.example", 0)], sink_tx)
            .await
        {
            Ok(report) => report,
            Err(err) => panic!("execute failed: {err}"),
        };

        let mut names = Vec::new();
        while let Ok(item) = sink_rx.try_recv() {
            names.push((item.kind.canonical_value(), item.hop_depth));
        }
        // d0 (depth 0) expands to d1 (depth 1), which expands to d2 (depth 2) — the limit.
        assert_eq!(
            names,
            vec![
                ("d0.example".to_owned(), 0),
                ("d1.example".to_owned(), 1),
                ("d2.example".to_owned(), 2),
            ]
        );
        assert_eq!(
            report,
            ExecutionReport {
                emitted: 3,
                expanded: 2,
                depth_limited: 1,
                ..ExecutionReport::default()
            }
        );
    }

    #[tokio::test]
    async fn more_seeds_than_the_old_channel_capacity_do_not_deadlock() {
        let engine = engine(3);
        let seeds: Vec<Entity> = (0..600)
            .map(|i| domain_entity(&format!("seed{i}.example"), 0))
            .collect();
        let (sink_tx, mut sink_rx) = mpsc::channel(1024);

        let outcome =
            tokio::time::timeout(Duration::from_secs(5), engine.execute(seeds, sink_tx)).await;
        let report = match outcome {
            Ok(Ok(report)) => report,
            Ok(Err(err)) => panic!("execute failed: {err}"),
            Err(_) => panic!("execute deadlocked on 600 seeds"),
        };
        let mut count = 0;
        while sink_rx.try_recv().is_ok() {
            count += 1;
        }
        assert_eq!(count, 600);
        // No collector is registered, so every seed is emitted and none can be expanded.
        assert_eq!(
            report,
            ExecutionReport {
                emitted: 600,
                no_consumer: 600,
                ..ExecutionReport::default()
            }
        );
    }

    #[tokio::test]
    async fn a_closed_sink_is_an_error_not_silent_loss() {
        let engine = engine(3);
        let (sink_tx, sink_rx) = mpsc::channel(4);
        drop(sink_rx);
        let result = engine
            .execute(vec![domain_entity("lost.example", 0)], sink_tx)
            .await;
        assert!(matches!(result, Err(HuntsmanError::ChannelCongestion(_))));
    }

    #[tokio::test]
    async fn a_second_execute_on_the_same_engine_re_emits_and_re_expands_the_seed() {
        let mut engine = engine(3);
        engine.register_module(ModuleRegistration::new(Arc::new(DummySubdomainCollector)));
        let expected = vec!["example.com".to_owned(), "api.example.com".to_owned()];
        for run in 0..2 {
            let (report, names) =
                execute_and_collect(&engine, vec![domain_entity("example.com", 0)], 16).await;
            assert_eq!(
                names, expected,
                "run {run} must emit the seed and its discovery"
            );
            assert_eq!(
                report,
                ExecutionReport {
                    emitted: 2,
                    expanded: 2,
                    ..ExecutionReport::default()
                },
                "run {run} must expand from scratch"
            );
        }
    }

    #[tokio::test]
    async fn concurrent_executes_on_a_shared_engine_are_independent() {
        let mut engine = engine(3);
        engine.register_module(ModuleRegistration::new(Arc::new(DummySubdomainCollector)));
        let engine = Arc::new(engine);
        let (tx_a, rx_a) = mpsc::channel(16);
        let (tx_b, rx_b) = mpsc::channel(16);
        let (drained_a, drained_b) = (drain(rx_a), drain(rx_b));

        let (a, b) = tokio::join!(
            engine.execute(vec![domain_entity("example.com", 0)], tx_a),
            engine.execute(vec![domain_entity("example.com", 0)], tx_b),
        );
        let complete = ExecutionReport {
            emitted: 2,
            expanded: 2,
            ..ExecutionReport::default()
        };
        assert!(
            matches!(a, Ok(report) if report == complete),
            "run A: {a:?}"
        );
        assert!(
            matches!(b, Ok(report) if report == complete),
            "run B: {b:?}"
        );
        let expected = vec!["example.com".to_owned(), "api.example.com".to_owned()];
        assert_eq!(collected(drained_a).await, expected, "run A");
        assert_eq!(collected(drained_b).await, expected, "run B");
    }

    #[tokio::test]
    async fn a_cancelled_run_leaves_nothing_behind_for_the_retry() {
        let mut engine = engine(3);
        engine.register_module(ModuleRegistration::new(Arc::new(DummySubdomainCollector)));
        // A sink nobody drains: the seed fits, the discovery blocks, the timeout cancels the run.
        let (stuck_tx, _stuck_rx) = mpsc::channel(1);
        let cancelled = tokio::time::timeout(
            Duration::from_millis(100),
            engine.execute(vec![domain_entity("example.com", 0)], stuck_tx),
        )
        .await;
        assert!(
            cancelled.is_err(),
            "the first run must be cancelled by the timeout"
        );

        let (report, names) =
            execute_and_collect(&engine, vec![domain_entity("example.com", 0)], 16).await;
        assert_eq!(
            names,
            vec!["example.com".to_owned(), "api.example.com".to_owned()],
            "the retry must redo everything the cancelled run started"
        );
        assert_eq!(
            report,
            ExecutionReport {
                emitted: 2,
                expanded: 2,
                ..ExecutionReport::default()
            }
        );
    }

    #[tokio::test]
    async fn more_seeds_than_max_frontier_are_all_expanded() {
        let mut engine = engine(1);
        engine.register_module(ModuleRegistration::new(Arc::new(SubdomainCollector)));
        let total = MAX_FRONTIER + 1;
        let seeds: Vec<Entity> = (0..total)
            .map(|i| domain_entity(&format!("seed{i}.example"), 0))
            .collect();

        let (report, names) = execute_and_collect(&engine, seeds, 64).await;

        let children = names.iter().filter(|n| n.starts_with("sub.")).count();
        assert_eq!(children, total, "every seed must be expanded, none dropped");
        // Each child sits at depth 1, the limit, so it is emitted but not expanded.
        assert_eq!(
            report,
            ExecutionReport {
                emitted: 2 * total,
                expanded: total,
                depth_limited: total,
                ..ExecutionReport::default()
            }
        );
        assert_accounted(report);
    }

    #[tokio::test]
    async fn discovery_overflow_is_reported_rather_than_lost() {
        let mut engine = engine(3);
        engine.register_module(ModuleRegistration::new(Arc::new(FanoutCollector)));

        let (report, names) =
            execute_and_collect(&engine, vec![domain_entity("fanout.example", 0)], 64).await;

        let children = names.iter().filter(|n| n.starts_with('c')).count();
        let leaves = names.iter().filter(|n| n.starts_with("leaf.")).count();
        assert_eq!(
            children,
            MAX_FRONTIER + 5,
            "every discovery is still emitted"
        );
        assert_eq!(report.overflow_unexpanded, 5, "{report:?}");
        assert_eq!(
            leaves,
            children - report.overflow_unexpanded,
            "exactly the reported discoveries went unexpanded"
        );
        assert_eq!(
            report,
            ExecutionReport {
                emitted: 1 + children + leaves,
                expanded: 1 + MAX_FRONTIER + leaves,
                overflow_unexpanded: 5,
                ..ExecutionReport::default()
            }
        );
        assert_accounted(report);
    }

    #[tokio::test]
    async fn collector_failures_are_counted_not_hidden() {
        let mut engine = engine(3);
        engine.register_module(ModuleRegistration::new(Arc::new(FailingCollector)));

        let (report, names) =
            execute_and_collect(&engine, vec![domain_entity("broken.example", 0)], 16).await;

        assert_eq!(names, vec!["broken.example".to_owned()]);
        assert_eq!(
            report,
            ExecutionReport {
                emitted: 1,
                expanded: 1,
                collector_failures: 1,
                ..ExecutionReport::default()
            }
        );
        assert_accounted(report);
    }
}
