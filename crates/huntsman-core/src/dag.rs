//! Reactive Directed Acyclic Graph (DAG) state machine with backpressure and cycle mitigation.

use crate::error::HuntsmanError;
use crate::governor::NetworkGovernor;
use crate::model::{Entity, EntityId, EntityKind};
use crate::transport::Transport;
use async_trait::async_trait;
use std::collections::{HashSet, VecDeque};
use std::sync::Arc;
use tokio::sync::{mpsc, Mutex};
use tracing::{debug, error, info, warn};

/// Upper bound on entities awaiting expansion, keeping traversal within the memory ceiling.
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

/// Core reactive DAG execution engine.
pub struct DagEngine {
    modules: Vec<Arc<dyn Collector>>,
    transport: Arc<dyn Transport>,
    governor: NetworkGovernor,
    seen_entities: Arc<Mutex<HashSet<EntityId>>>,
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
            seen_entities: Arc::new(Mutex::new(HashSet::new())),
            max_hop_depth,
        }
    }

    /// Register a collector into the processing graph.
    pub fn register_module(&mut self, registration: ModuleRegistration) {
        self.modules.push(registration.into_collector());
    }

    /// Deduplicate `entity`, emit it, and queue it for expansion if depth and capacity allow.
    async fn admit(
        &self,
        entity: Entity,
        frontier: &mut VecDeque<Entity>,
        outbound_sink: &mpsc::Sender<Entity>,
    ) -> Result<(), HuntsmanError> {
        if !self
            .seen_entities
            .lock()
            .await
            .insert(entity.provenance.entity_id)
        {
            return Ok(());
        }
        let expandable = entity.hop_depth < self.max_hop_depth;
        let queued = if expandable && frontier.len() < MAX_FRONTIER {
            Some(entity.clone())
        } else {
            if expandable {
                warn!(
                    "Frontier at capacity ({MAX_FRONTIER}); {} emitted but not expanded",
                    entity.kind.canonical_value()
                );
            }
            None
        };
        outbound_sink
            .send(entity)
            .await
            .map_err(|e| HuntsmanError::ChannelCongestion(e.to_string()))?;
        if let Some(next) = queued {
            frontier.push_back(next);
        }
        Ok(())
    }

    /// Seed the pipeline and expand breadth-first until the frontier drains.
    ///
    /// Every newly discovered entity (deduplicated by its deterministic id) is emitted to
    /// `outbound_sink` and, while below `max_hop_depth`, re-enters the frontier so downstream
    /// collectors can expand it. The frontier lives in this task, so any number of seeds can be
    /// enqueued without self-deadlock; it is capped at [`MAX_FRONTIER`] entities to bound memory,
    /// and entities beyond the cap are still emitted but not expanded.
    ///
    /// # Errors
    /// Returns [`HuntsmanError::ChannelCongestion`] if `outbound_sink` closes, since discoveries
    /// would otherwise be lost silently.
    pub async fn execute(
        &self,
        seeds: Vec<Entity>,
        outbound_sink: mpsc::Sender<Entity>,
    ) -> Result<(), HuntsmanError> {
        let mut frontier: VecDeque<Entity> = VecDeque::new();

        for seed in seeds {
            self.admit(seed, &mut frontier, &outbound_sink).await?;
        }

        while let Some(current_entity) = frontier.pop_front() {
            if current_entity.hop_depth >= self.max_hop_depth {
                debug!(
                    "Entity {} reached max depth ({})",
                    current_entity.kind.canonical_value(),
                    self.max_hop_depth
                );
                continue;
            }

            for module in &self.modules {
                if module.can_consume(&current_entity.kind) {
                    let transport = self.transport.clone();
                    let governor = self.governor.clone();
                    let collector = module.clone();

                    match collector
                        .process(&current_entity, transport, governor)
                        .await
                    {
                        Ok(discovered) => {
                            for mut item in discovered {
                                item.hop_depth = current_entity.hop_depth.saturating_add(1);
                                info!(
                                    "Discovered node [{}] via {}",
                                    item.kind.canonical_value(),
                                    collector.name()
                                );
                                self.admit(item, &mut frontier, &outbound_sink).await?;
                            }
                        }
                        Err(err) => {
                            error!(
                                "Module {} failed on {}: {}",
                                collector.name(),
                                current_entity.kind.canonical_value(),
                                err
                            );
                        }
                    }
                }
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Entity, EntityKind, EpistemicLevel, ProvenanceEnvelope};
    use crate::transport::MockTransport;

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
        let exec_result = engine.execute(vec![seed], sink_tx).await;
        assert!(exec_result.is_ok());

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

    #[tokio::test]
    async fn discoveries_are_expanded_until_the_depth_limit() {
        let mut engine = engine(2);
        engine.register_module(ModuleRegistration::new(Arc::new(ChainCollector)));
        let (sink_tx, mut sink_rx) = mpsc::channel(16);

        let result = engine
            .execute(vec![domain_entity("d0.example", 0)], sink_tx)
            .await;
        assert!(result.is_ok(), "{result:?}");

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
    }

    #[tokio::test]
    async fn more_seeds_than_the_old_channel_capacity_do_not_deadlock() {
        let engine = engine(3);
        let seeds: Vec<Entity> = (0..600)
            .map(|i| domain_entity(&format!("seed{i}.example"), 0))
            .collect();
        let (sink_tx, mut sink_rx) = mpsc::channel(1024);

        let outcome = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            engine.execute(seeds, sink_tx),
        )
        .await;
        match outcome {
            Ok(Ok(())) => {}
            Ok(Err(err)) => panic!("execute failed: {err}"),
            Err(_) => panic!("execute deadlocked on 600 seeds"),
        }
        let mut count = 0;
        while sink_rx.try_recv().is_ok() {
            count += 1;
        }
        assert_eq!(count, 600);
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
}
