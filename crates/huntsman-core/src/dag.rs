//! Reactive Directed Acyclic Graph (DAG) state machine with backpressure and cycle mitigation.

use crate::error::HuntsmanError;
use crate::governor::NetworkGovernor;
use crate::model::{Entity, EntityId, EntityKind};
use crate::transport::Transport;
use async_trait::async_trait;
use std::collections::HashSet;
use std::sync::Arc;
use tokio::sync::{mpsc, Mutex};
use tracing::{debug, error, info};

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

    /// Seed the pipeline and run processing until the frontier drains or the depth limit is hit.
    ///
    /// # Errors
    /// Returns [`HuntsmanError::ChannelCongestion`] if the bounded work or outbound channels close
    /// while seeds are being enqueued.
    pub async fn execute(
        &self,
        seeds: Vec<Entity>,
        outbound_sink: mpsc::Sender<Entity>,
    ) -> Result<(), HuntsmanError> {
        let (work_tx, mut work_rx) = mpsc::channel::<Entity>(512);

        // Pre-load seeds into the ingestion channel, deduplicating by deterministic entity id.
        for seed in seeds {
            let mut seen = self.seen_entities.lock().await;
            if seen.insert(seed.provenance.entity_id) {
                outbound_sink
                    .send(seed.clone())
                    .await
                    .map_err(|e| HuntsmanError::ChannelCongestion(e.to_string()))?;
                work_tx
                    .send(seed)
                    .await
                    .map_err(|e| HuntsmanError::ChannelCongestion(e.to_string()))?;
            }
        }

        // Drop the initial handle so the channel closes once the frontier is exhausted.
        drop(work_tx);

        while let Some(current_entity) = work_rx.recv().await {
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
                    let entity = current_entity.clone();

                    match collector.process(&entity, transport, governor).await {
                        Ok(discovered) => {
                            for mut item in discovered {
                                item.hop_depth = entity.hop_depth + 1;
                                let mut seen = self.seen_entities.lock().await;
                                if seen.insert(item.provenance.entity_id) {
                                    info!(
                                        "Discovered node [{}] via {}",
                                        item.kind.canonical_value(),
                                        collector.name()
                                    );
                                    let _ = outbound_sink.send(item).await;
                                }
                            }
                        }
                        Err(err) => {
                            error!(
                                "Module {} failed on {}: {}",
                                collector.name(),
                                entity.kind.canonical_value(),
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
}
