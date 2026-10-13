//! Huntsman Pipeline: run the DAG engine and persist everything it discovers.
//!
//! [`huntsman_core::DagEngine`] emits each distinct entity (seeds and discoveries) to a bounded
//! channel; [`huntsman_storage::GraphStore`] persists entities through a background writer. This
//! crate joins the two: it runs the engine and drains its sink into the store concurrently on one
//! task, so the engine never blocks on a full channel, then flushes the store to durable storage
//! and reports what was run and persisted.
//!
//! Lint levels live in `Cargo.toml` `[lints]`, per workspace policy.

use huntsman_core::{DagEngine, Entity, ExecutionReport, HuntsmanError};
use huntsman_storage::{GraphStore, StorageError};

/// Depth of the channel between the engine's sink and the persistence drain. The engine already
/// bounds its own frontier; this only smooths the handoff to the writer.
const SINK_CAPACITY: usize = 512;

/// Failure modes of a persisting run.
#[derive(Debug, thiserror::Error)]
pub enum PipelineError {
    /// The DAG engine failed (a closed sink, which cannot happen here, or a seed-admission error).
    #[error("engine: {0}")]
    Engine(#[from] HuntsmanError),

    /// The store failed to persist or flush a discovered entity.
    #[error("store: {0}")]
    Store(#[from] StorageError),
}

/// What one [`run_and_persist`] call did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PipelineReport {
    /// The engine's own account of the traversal (emitted, expanded, overflow, failures, ...).
    pub execution: ExecutionReport,
    /// Entities drained from the sink and persisted to the store (equals `execution.emitted`
    /// on a clean run; it is tracked independently so a divergence is observable).
    pub persisted: usize,
}

/// Run `engine` over `seeds`, persisting every emitted entity into `store`, then flush the store.
///
/// The engine's traversal and the drain into the store run concurrently on the current task, so a
/// burst of discoveries cannot deadlock against the channel bound. When the engine finishes it
/// drops its sender, the drain observes the closed channel and stops, and the store is synced so
/// the returned report reflects durably committed state.
///
/// # Errors
/// Returns [`PipelineError::Store`] if persisting or flushing an entity fails (the engine is then
/// cancelled by the early return), or [`PipelineError::Engine`] if the traversal itself failed.
pub async fn run_and_persist(
    engine: &DagEngine,
    seeds: Vec<Entity>,
    store: &GraphStore,
) -> Result<PipelineReport, PipelineError> {
    let (sink, mut entities) = tokio::sync::mpsc::channel::<Entity>(SINK_CAPACITY);

    let traverse = engine.execute(seeds, sink);
    let persist = async {
        let mut persisted = 0usize;
        while let Some(entity) = entities.recv().await {
            store.put(&entity).await?;
            persisted += 1;
        }
        Ok::<usize, StorageError>(persisted)
    };

    let (execution, persisted) = tokio::join!(traverse, persist);
    let execution = execution?;
    let persisted = persisted?;
    store.sync().await?;

    Ok(PipelineReport {
        execution,
        persisted,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use huntsman_core::{
        Collector, EntityKind, EpistemicLevel, GovernorConfig, MockTransport, ModuleRegistration,
        NetworkGovernor, ProvenanceEnvelope, Transport,
    };
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::Arc;

    const OBSERVED_AT: u64 = 1_710_000_000;

    fn scratch_path(tag: &str) -> std::path::PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        std::env::temp_dir().join(format!(
            "huntsman-pipeline-{tag}-{}-{nanos}.redb",
            std::process::id()
        ))
    }

    fn entity(kind: EntityKind, source: &'static str, hop_depth: u8) -> Entity {
        let provenance = ProvenanceEnvelope::new(
            source,
            OBSERVED_AT,
            kind.canonical_value().as_bytes(),
            &kind,
            EpistemicLevel::DirectObservation,
        );
        Entity {
            provenance,
            kind,
            hop_depth,
        }
    }

    fn domain_seed(domain: &str) -> Entity {
        let kind = match EntityKind::new_domain(domain) {
            Ok(kind) => kind,
            Err(err) => panic!("seed domain must canonicalize: {err}"),
        };
        entity(kind, "seed", 0)
    }

    /// Resolves `example.com` to a fixed address, with no network at all — the pipeline's job is
    /// draining discoveries into the store, which this exercises without re-testing a collector.
    struct FixedResolver;

    #[async_trait::async_trait]
    impl Collector for FixedResolver {
        fn name(&self) -> &'static str {
            "fixed-resolver"
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
            if d != "example.com" {
                return Ok(vec![]);
            }
            Ok(vec![entity(
                EntityKind::Ip(IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))),
                "fixed-resolver",
                1,
            )])
        }
    }

    fn engine_with<C: Collector + 'static>(collector: Option<C>) -> DagEngine {
        let transport: Arc<dyn Transport> = Arc::new(MockTransport::new());
        let governor = NetworkGovernor::new(GovernorConfig::default());
        let mut engine = DagEngine::new(transport, governor, 2);
        if let Some(c) = collector {
            engine.register_module(ModuleRegistration::new(Arc::new(c)));
        }
        engine
    }

    #[tokio::test]
    async fn a_run_persists_the_seed_and_its_discoveries() {
        let engine = engine_with(Some(FixedResolver));
        let path = scratch_path("persist");
        let store = match GraphStore::open(&path) {
            Ok(store) => store,
            Err(err) => panic!("open store: {err}"),
        };

        let seed = domain_seed("example.com");
        let seed_id = seed.provenance.entity_id;
        let ip_kind = EntityKind::Ip(IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)));
        let ip_id = entity(ip_kind.clone(), "fixed-resolver", 1)
            .provenance
            .entity_id;

        let report = match run_and_persist(&engine, vec![seed], &store).await {
            Ok(report) => report,
            Err(err) => panic!("run_and_persist: {err}"),
        };

        assert_eq!(report.execution.emitted, 2, "{report:?}");
        assert_eq!(report.persisted, 2, "{report:?}");

        match store.get(&seed_id) {
            Ok(Some(found)) => assert_eq!(found.kind.canonical_value(), "example.com"),
            other => panic!("seed not persisted: {other:?}"),
        }
        match store.get(&ip_id) {
            Ok(Some(found)) => {
                assert_eq!(found.kind, ip_kind);
                assert_eq!(found.provenance.observed_at_utc, OBSERVED_AT);
                assert_eq!(found.hop_depth, 1);
            }
            other => panic!("discovered ip not persisted: {other:?}"),
        }

        if let Err(err) = store.shutdown() {
            panic!("shutdown: {err}");
        }
        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn an_empty_run_persists_only_the_seed() {
        let engine = engine_with::<FixedResolver>(None);
        let path = scratch_path("seed-only");
        let store = match GraphStore::open(&path) {
            Ok(store) => store,
            Err(err) => panic!("open store: {err}"),
        };
        let seed = domain_seed("lonely.example");
        let seed_id = seed.provenance.entity_id;
        let report = match run_and_persist(&engine, vec![seed], &store).await {
            Ok(report) => report,
            Err(err) => panic!("run_and_persist: {err}"),
        };
        assert_eq!(report.persisted, 1);
        assert_eq!(report.execution.emitted, 1);
        assert_eq!(report.execution.no_consumer, 1);
        match store.get(&seed_id) {
            Ok(Some(_)) => {}
            other => panic!("seed not persisted: {other:?}"),
        }
        let _ = store.shutdown();
        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn many_discoveries_do_not_deadlock_against_the_channel_bound() {
        // One seed fanning out to more than SINK_CAPACITY addresses would block the engine if the
        // drain were not concurrent; this proves the join() handoff keeps draining.
        struct FanOut;
        #[async_trait::async_trait]
        impl Collector for FanOut {
            fn name(&self) -> &'static str {
                "fan-out"
            }
            fn can_consume(&self, kind: &EntityKind) -> bool {
                matches!(kind, EntityKind::Domain(_))
            }
            async fn process(
                &self,
                _input: &Entity,
                _t: Arc<dyn Transport>,
                _g: NetworkGovernor,
            ) -> Result<Vec<Entity>, HuntsmanError> {
                let mut out = Vec::new();
                for i in 0..(SINK_CAPACITY * 3) {
                    let octets = (i as u32).to_be_bytes();
                    out.push(entity(
                        EntityKind::Ip(IpAddr::V4(Ipv4Addr::new(
                            octets[0], octets[1], octets[2], octets[3],
                        ))),
                        "fan-out",
                        1,
                    ));
                }
                Ok(out)
            }
        }

        let engine = engine_with(Some(FanOut));
        let path = scratch_path("fanout");
        let store = match GraphStore::open(&path) {
            Ok(store) => store,
            Err(err) => panic!("open store: {err}"),
        };
        let report = match tokio::time::timeout(
            std::time::Duration::from_secs(10),
            run_and_persist(&engine, vec![domain_seed("fan.example")], &store),
        )
        .await
        {
            Ok(Ok(report)) => report,
            Ok(Err(err)) => panic!("run_and_persist: {err}"),
            Err(_) => panic!("pipeline deadlocked on a wide fan-out"),
        };
        // seed + SINK_CAPACITY*3 distinct addresses.
        assert_eq!(report.persisted, 1 + SINK_CAPACITY * 3);
        assert_eq!(report.execution.emitted, 1 + SINK_CAPACITY * 3);
        let _ = store.shutdown();
        let _ = std::fs::remove_file(&path);
    }
}
