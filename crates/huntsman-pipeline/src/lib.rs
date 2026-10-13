//! Huntsman Pipeline: run the DAG engine and persist everything it discovers.
//!
//! [`huntsman_core::DagEngine`] emits each distinct entity (seeds and discoveries) to a bounded
//! channel; [`huntsman_storage::GraphStore`] persists entities through a background writer. This
//! crate joins the two: it runs the engine and drains its sink into the store concurrently on one
//! task, so the engine never blocks on a full channel, then flushes the store to durable storage
//! and reports what was run and persisted.
//!
//! Lint levels live in `Cargo.toml` `[lints]`, per workspace policy.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use huntsman_collectors::{DnsResolveCollector, PtrResolveCollector};
use huntsman_core::{
    DagEngine, EpistemicLevel, ExecutionReport, GovernorConfig, HuntsmanError, ModuleRegistration,
    NetworkGovernor, ProvenanceEnvelope, Transport, UnprivilegedPosixTransport,
};
use huntsman_storage::{GraphStore, StorageError};

pub use huntsman_core::{Entity, EntityKind};

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

    /// A seed is not a well-formed domain; nothing was opened or sent.
    #[error("invalid seed {seed:?}: {source}")]
    InvalidSeed {
        /// The seed as supplied.
        seed: String,
        /// Why it was refused.
        source: HuntsmanError,
    },

    /// The async runtime behind the blocking entry point could not be built.
    #[error("runtime: {0}")]
    Runtime(#[source] std::io::Error),
}

/// One blocking DNS-topology run: forward and reverse resolution from domain seeds, persisted.
#[derive(Debug, Clone)]
pub struct DnsGraphRequest {
    /// Domain seeds; each is canonicalised and must be a well-formed domain.
    pub seeds: Vec<String>,
    /// The only host the collectors send to: a recursive resolver on UDP.
    pub resolver: SocketAddr,
    /// Maximum hop depth from a seed (0 persists the seeds alone).
    pub max_depth: u8,
    /// The redb graph store; created if absent, appended to if present.
    pub store_path: PathBuf,
    /// Observation time stamped onto seeds and discoveries, microseconds since the Unix epoch
    /// (the unit of [`huntsman_core::ProvenanceEnvelope::observed_at_utc`]).
    pub observed_at_utc: u64,
}

/// Run [`DnsResolveCollector`] and [`PtrResolveCollector`] over `request.seeds` through the real
/// unprivileged transport, persisting every distinct entity into the store at
/// `request.store_path` and streaming each to `observe`.
///
/// Every seed is validated before the store is opened or a socket is created. The run owns a
/// current-thread runtime, so callers stay synchronous. The store is shut down before return,
/// so an `Ok` report means every persisted entity is durably committed.
///
/// # Errors
/// [`PipelineError::InvalidSeed`] for a malformed seed, [`PipelineError::Runtime`] if the
/// runtime cannot start, [`PipelineError::Store`] if the store cannot open, persist or flush,
/// and [`PipelineError::Engine`] if the traversal fails.
pub fn run_dns_graph(
    request: &DnsGraphRequest,
    observe: impl FnMut(&Entity),
) -> Result<PipelineReport, PipelineError> {
    let seeds = request
        .seeds
        .iter()
        .map(|raw| {
            let kind =
                EntityKind::new_domain(raw).map_err(|source| PipelineError::InvalidSeed {
                    seed: raw.clone(),
                    source,
                })?;
            let provenance = ProvenanceEnvelope::new(
                "seed",
                request.observed_at_utc,
                kind.canonical_value().as_bytes(),
                &kind,
                EpistemicLevel::DirectObservation,
            );
            Ok(Entity {
                provenance,
                kind,
                hop_depth: 0,
            })
        })
        .collect::<Result<Vec<_>, PipelineError>>()?;

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(PipelineError::Runtime)?;
    let store = GraphStore::open(&request.store_path)?;

    let host = request.resolver.ip().to_string();
    let port = request.resolver.port();
    let transport: Arc<dyn Transport> = Arc::new(UnprivilegedPosixTransport::new());
    let governor = NetworkGovernor::new(GovernorConfig::default());
    let mut engine = DagEngine::new(transport, governor, request.max_depth);
    engine.register_module(ModuleRegistration::new(Arc::new(
        DnsResolveCollector::new(host.clone(), request.observed_at_utc).with_resolver_port(port),
    )));
    engine.register_module(ModuleRegistration::new(Arc::new(
        PtrResolveCollector::new(host, request.observed_at_utc).with_resolver_port(port),
    )));

    let run = runtime.block_on(run_and_persist_observing(&engine, seeds, &store, observe));
    let closed = store.shutdown();
    let report = run?;
    closed?;
    Ok(report)
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
    run_and_persist_observing(engine, seeds, store, |_| {}).await
}

/// [`run_and_persist`], also handing each entity to `observe` once it has been enqueued to the
/// store, in emission order, so a caller can stream results without buffering the whole run.
///
/// # Errors
/// As [`run_and_persist`].
pub async fn run_and_persist_observing(
    engine: &DagEngine,
    seeds: Vec<Entity>,
    store: &GraphStore,
    mut observe: impl FnMut(&Entity),
) -> Result<PipelineReport, PipelineError> {
    let (sink, mut entities) = tokio::sync::mpsc::channel::<Entity>(SINK_CAPACITY);

    let traverse = engine.execute(seeds, sink);
    let persist = async {
        let mut persisted = 0usize;
        while let Some(entity) = entities.recv().await {
            store.put(&entity).await?;
            persisted += 1;
            observe(&entity);
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

    const RESOLVED: Ipv4Addr = Ipv4Addr::new(93, 184, 216, 34);

    /// A loopback UDP resolver answering every A query with [`RESOLVED`] and every other type
    /// with an empty NOERROR, until it has been idle for a second.
    fn fake_resolver() -> (std::net::SocketAddr, std::thread::JoinHandle<usize>) {
        let socket = match std::net::UdpSocket::bind("127.0.0.1:0") {
            Ok(socket) => socket,
            Err(err) => panic!("bind fake resolver: {err}"),
        };
        let addr = match socket.local_addr() {
            Ok(addr) => addr,
            Err(err) => panic!("fake resolver addr: {err}"),
        };
        let _ = socket.set_read_timeout(Some(std::time::Duration::from_secs(1)));
        let handle = std::thread::spawn(move || {
            let mut served = 0usize;
            let mut buf = [0u8; 4096];
            while let Ok((len, peer)) = socket.recv_from(&mut buf) {
                let query = &buf[..len];
                let mut end = 12;
                while end < len && query[end] != 0 {
                    end += 1 + usize::from(query[end]);
                }
                let question_end = end + 5;
                let qtype = u16::from_be_bytes([query[end + 1], query[end + 2]]);
                let answers = u16::from(qtype == 1);
                let mut reply = Vec::with_capacity(question_end + 16);
                reply.extend_from_slice(&query[..2]);
                reply.extend_from_slice(&[0x81, 0x80, 0, 1]);
                reply.extend_from_slice(&answers.to_be_bytes());
                reply.extend_from_slice(&[0, 0, 0, 0]);
                reply.extend_from_slice(&query[12..question_end]);
                if answers == 1 {
                    reply.extend_from_slice(&[0xC0, 0x0C, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4]);
                    reply.extend_from_slice(&RESOLVED.octets());
                }
                let _ = socket.send_to(&reply, peer);
                served += 1;
            }
            served
        });
        (addr, handle)
    }

    fn graph_request(tag: &str, resolver: std::net::SocketAddr, seeds: &[&str]) -> DnsGraphRequest {
        DnsGraphRequest {
            seeds: seeds.iter().map(|s| (*s).to_owned()).collect(),
            resolver,
            max_depth: 2,
            store_path: scratch_path(tag),
            observed_at_utc: OBSERVED_AT,
        }
    }

    #[test]
    fn dns_graph_resolves_reverses_and_persists_through_real_sockets() {
        let (resolver, server) = fake_resolver();
        let request = graph_request("dns-graph", resolver, &["Example.COM"]);
        let mut streamed = Vec::new();
        let report = match run_dns_graph(&request, |e| streamed.push(e.kind.clone())) {
            Ok(report) => report,
            Err(err) => panic!("run_dns_graph: {err}"),
        };
        let served = server.join().unwrap_or(0);

        let ip = EntityKind::Ip(IpAddr::V4(RESOLVED));
        assert_eq!(
            streamed,
            vec![EntityKind::Domain("example.com".into()), ip.clone()]
        );
        assert_eq!(report.persisted, 2, "{report:?}");
        assert_eq!(report.execution.collector_failures, 0, "{report:?}");
        // A + AAAA for the domain, then one PTR for the discovered address.
        assert_eq!(served, 3);

        // The store was shut down by the run; reopening proves the entities are durable.
        let store = match GraphStore::open(&request.store_path) {
            Ok(store) => store,
            Err(err) => panic!("reopen store: {err}"),
        };
        match store.get(&ip.entity_id()) {
            Ok(Some(found)) => {
                assert_eq!(found.hop_depth, 1);
                assert_eq!(found.provenance.source_module, "dns-resolve");
                assert_eq!(found.provenance.observed_at_utc, OBSERVED_AT);
            }
            other => panic!("resolved address not durable: {other:?}"),
        }
        let _ = store.shutdown();
        let _ = std::fs::remove_file(&request.store_path);
    }

    #[test]
    fn dns_graph_refuses_a_malformed_seed_before_touching_disk_or_network() {
        let unused = std::net::SocketAddr::from(([127, 0, 0, 1], 9));
        let request = graph_request("bad-seed", unused, &["ok.example", "not a domain"]);
        match run_dns_graph(&request, |_| {}) {
            Err(PipelineError::InvalidSeed { seed, .. }) => assert_eq!(seed, "not a domain"),
            other => panic!("expected InvalidSeed, got {other:?}"),
        }
        assert!(
            !request.store_path.exists(),
            "store created for a refused run"
        );
    }

    #[test]
    fn dns_graph_counts_an_unreachable_resolver_as_a_collector_failure() {
        // Bound and immediately dropped: nothing answers on this port.
        let dead = match std::net::UdpSocket::bind("127.0.0.1:0").and_then(|s| s.local_addr()) {
            Ok(addr) => addr,
            Err(err) => panic!("reserve port: {err}"),
        };
        let request = graph_request("dead-resolver", dead, &["example.com"]);
        let report = match run_dns_graph(&request, |_| {}) {
            Ok(report) => report,
            Err(err) => panic!("run_dns_graph: {err}"),
        };
        assert_eq!(report.persisted, 1, "{report:?}");
        assert_eq!(report.execution.collector_failures, 1, "{report:?}");
        let _ = std::fs::remove_file(&request.store_path);
    }
}
