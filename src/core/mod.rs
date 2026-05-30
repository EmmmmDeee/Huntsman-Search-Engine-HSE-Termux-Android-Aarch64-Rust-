//! Core types: entity, scan, event, module trait, engine.
//!
//! Nothing in `core` imports from `modules/` — modules depend on core, never
//! the other way around. This keeps the engine module-agnostic.

pub mod correlator;
pub mod dependency;
pub mod engine;
pub mod entity;
pub mod gexf;
pub mod live;
pub mod module;
pub mod profiles;
pub mod relation;
pub mod roi;
pub mod scan;
pub mod validation;
pub mod webhook;

pub mod tags {
    pub const BREACH: &str = "breach";
    pub const STEALER_LOG: &str = "stealer-log";
    pub const WEB: &str = "web";
    pub const CRAWLED: &str = "crawled";
    pub const SUBDOMAIN: &str = "subdomain";
    pub const EXTERNAL: &str = "external";
    pub const WEB_SCRAPED: &str = "web-scraped";
    pub const CT_LOG: &str = "ct-log";
    pub const PTR: &str = "ptr";
    pub const HIGH_EXPOSURE: &str = "high-exposure";
    pub const PASTE_EXPOSED: &str = "paste-exposed";
    pub const PASSWORD_AT_RISK: &str = "password-at-risk";
    pub const MULTI_DEVICE: &str = "multi-device";
    pub const MISSING_SECURITY_HEADERS: &str = "missing-security-headers";

    // Geolocation
    pub const GEOINT: &str = "geoint";
    pub const GEOLOCATION_LEAD: &str = "geolocation-lead";
    pub const COARSE: &str = "coarse";

    // Device / local
    pub const WIFI_AP: &str = "wifi-ap";
    pub const CELL_TOWER: &str = "cell-tower";
    pub const LOCAL_ARP: &str = "local-arp";
    pub const LOCAL_INTERFACE: &str = "local-interface";

    // Reputation / threat
    pub const THREAT_INTEL: &str = "threat-intel";
    pub const MALICIOUS: &str = "malicious";
    pub const TOR_EXIT: &str = "tor-exit";
    pub const PROXY: &str = "proxy";
    pub const VPN: &str = "vpn";
    pub const VULNERABLE: &str = "vulnerable";

    // Identity
    pub const DERIVED: &str = "derived";
    pub const SOCIAL_PROFILE: &str = "social-profile";
    pub const CANDIDATE: &str = "candidate";

    // Discovery method
    pub const SEARCH_DISCOVERED: &str = "search-discovered";
    pub const BREACH_DERIVED: &str = "breach-derived";
}

pub mod cancel {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    #[derive(Clone, Debug, Default)]
    pub struct CancelHandle {
        flag: Arc<AtomicBool>,
    }

    impl CancelHandle {
        pub fn new() -> Self {
            Self::default()
        }
        pub fn cancel(&self) {
            self.flag.store(true, Ordering::Release);
        }
        pub fn is_cancelled(&self) -> bool {
            self.flag.load(Ordering::Acquire)
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn new_handle_is_not_cancelled() {
            assert!(!CancelHandle::new().is_cancelled());
        }

        #[test]
        fn cancel_is_observable_through_clones() {
            let a = CancelHandle::new();
            let b = a.clone();
            b.cancel();
            assert!(a.is_cancelled());
            assert!(b.is_cancelled());
        }

        #[test]
        fn cancel_is_idempotent() {
            let h = CancelHandle::new();
            h.cancel();
            h.cancel();
            assert!(h.is_cancelled());
        }

        #[test]
        fn default_is_uncancelled() {
            let h: CancelHandle = Default::default();
            assert!(!h.is_cancelled());
        }
    }
}

pub mod error {
    use thiserror::Error;

    #[derive(Debug, Error)]
    pub enum Error {
        #[error("storage: {0}")]
        Storage(#[from] rusqlite::Error),
        #[error("io: {0}")]
        Io(#[from] std::io::Error),
        #[error("json: {0}")]
        Json(#[from] serde_json::Error),
        #[error("http: {0}")]
        Http(#[from] reqwest::Error),
        #[error("invalid target: {0}")]
        InvalidTarget(String),
        #[error("missing key: {0}")]
        MissingKey(String),
        #[error("[{module}] {message}")]
        Module { module: String, message: String },
        #[error("{0}")]
        Other(String),
    }

    impl Error {
        pub fn module(module: impl Into<String>, message: impl Into<String>) -> Self {
            Self::Module {
                module: module.into(),
                message: message.into(),
            }
        }
    }

    pub type Result<T> = std::result::Result<T, Error>;

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn error_module_constructor() {
            let e = Error::module("dns_resolver", "connection refused");
            let s = e.to_string();
            assert!(s.contains("dns_resolver"));
            assert!(s.contains("connection refused"));
        }

        #[test]
        fn error_missing_key_display() {
            let e = Error::MissingKey("HUNTSMAN_SHODAN_KEY".into());
            assert!(e.to_string().contains("HUNTSMAN_SHODAN_KEY"));
        }

        #[test]
        fn error_from_json() {
            let bad = serde_json::from_str::<serde_json::Value>("not json");
            let e: Error = bad.unwrap_err().into();
            assert!(e.to_string().contains("json"));
        }
    }
}

pub mod event {
    // Event bus + event types. Modules and the engine emit events; consumers
    // (CLI verbose mode, future SSE endpoint, future live UI) subscribe via
    // `EventBus::subscribe()`.

    use serde::{Deserialize, Serialize};
    use tokio::sync::broadcast;

    use crate::core::entity::{Entity, unix_now};

    /// Cloneable sender shared across the engine, modules, and consumers.
    pub type EventBus = broadcast::Sender<Event>;

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct Event {
        pub scan_id: String,
        pub ts: u64,
        pub kind: EventKind,
    }

    impl Event {
        pub fn new(scan_id: impl Into<String>, kind: EventKind) -> Self {
            Self {
                scan_id: scan_id.into(),
                ts: unix_now(),
                kind,
            }
        }
    }

    /// Event variants. JSON tag = `type`, snake_case — matches the future SPA's
    /// `evt.type === 'module_start'` checks.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    #[serde(tag = "type", rename_all = "snake_case")]
    pub enum EventKind {
        ScanStart {
            target_kind: String,
            target_value: String,
        },
        ModuleStart {
            module: String,
        },
        ModuleDone {
            module: String,
            found: usize,
        },
        ModuleError {
            module: String,
            error: String,
        },
        ModuleSkipped {
            module: String,
            reason: String,
        },
        EntityFound {
            entity: Entity,
        },
        /// Autonomous expansion round about to start.
        ExpansionTick {
            depth: u32,
            queued: usize,
            visited: usize,
        },
        /// Autonomous expansion stopped early (budget, no candidates, etc.).
        ExpansionStop {
            reason: String,
        },
        /// Correlator rule fired post-scan (v0.4+).
        CorrelationFound {
            correlation: crate::core::correlator::Correlation,
        },
        /// Correlator finished evaluating all rules (v0.4+).
        CorrelationsDone {
            count: usize,
        },
        /// Live session started (v0.5+). `scan_id` field on the wrapping
        /// `Event` carries the live_id, not a scan_id.
        LiveStart {
            live_id: String,
            target_kind: String,
            target_value: String,
            interval_secs: u64,
        },
        /// A live iteration is about to begin (v0.5+). `scan_id` field on the
        /// wrapping `Event` carries the live_id; the iteration's own scan_id
        /// is in this variant's `scan_id` field.
        LiveTick {
            live_id: String,
            iteration: u32,
            scan_id: String,
        },
        /// Live session ended (v0.5+).
        LiveStop {
            live_id: String,
            reason: String,
        },
        ScanComplete {
            scan_id: String,
            entity_count: usize,
        },
    }

    impl EventKind {
        pub fn event_type_str(&self) -> &'static str {
            match self {
                Self::ScanStart { .. } => "scan_start",
                Self::ModuleStart { .. } => "module_start",
                Self::ModuleDone { .. } => "module_done",
                Self::ModuleError { .. } => "module_error",
                Self::ModuleSkipped { .. } => "module_skipped",
                Self::EntityFound { .. } => "entity_found",
                Self::ExpansionTick { .. } => "expansion_tick",
                Self::ExpansionStop { .. } => "expansion_stop",
                Self::CorrelationFound { .. } => "correlation_found",
                Self::CorrelationsDone { .. } => "correlations_done",
                Self::LiveStart { .. } => "live_start",
                Self::LiveTick { .. } => "live_tick",
                Self::LiveStop { .. } => "live_stop",
                Self::ScanComplete { .. } => "scan_complete",
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        // ── Event::new ──────────────────────────────────────────────────────

        #[test]
        fn event_new_sets_scan_id_and_ts() {
            let before = unix_now();
            let evt = Event::new(
                "scan-42",
                EventKind::ScanComplete {
                    scan_id: "scan-42".into(),
                    entity_count: 0,
                },
            );
            let after = unix_now();

            assert_eq!(evt.scan_id, "scan-42");
            assert!(evt.ts >= before && evt.ts <= after);
        }

        // ── EventKind round-trips ───────────────────────────────────────────

        #[test]
        fn scan_start_json_round_trip() {
            let kind = EventKind::ScanStart {
                target_kind: "email".into(),
                target_value: "a@b.com".into(),
            };
            let json = serde_json::to_string(&kind).unwrap();
            assert!(json.contains("\"type\":\"scan_start\""));

            let back: EventKind = serde_json::from_str(&json).unwrap();
            match back {
                EventKind::ScanStart {
                    target_kind,
                    target_value,
                } => {
                    assert_eq!(target_kind, "email");
                    assert_eq!(target_value, "a@b.com");
                }
                other => panic!("expected ScanStart, got: {other:?}"),
            }
        }

        #[test]
        fn module_done_json_round_trip() {
            let kind = EventKind::ModuleDone {
                module: "whois".into(),
                found: 7,
            };
            let json = serde_json::to_string(&kind).unwrap();
            let back: EventKind = serde_json::from_str(&json).unwrap();
            match back {
                EventKind::ModuleDone { module, found } => {
                    assert_eq!(module, "whois");
                    assert_eq!(found, 7);
                }
                other => panic!("expected ModuleDone, got: {other:?}"),
            }
        }

        #[test]
        fn module_error_json_round_trip() {
            let kind = EventKind::ModuleError {
                module: "dns_resolve".into(),
                error: "timeout".into(),
            };
            let json = serde_json::to_string(&kind).unwrap();
            let back: EventKind = serde_json::from_str(&json).unwrap();
            match back {
                EventKind::ModuleError { module, error } => {
                    assert_eq!(module, "dns_resolve");
                    assert_eq!(error, "timeout");
                }
                other => panic!("expected ModuleError, got: {other:?}"),
            }
        }

        #[test]
        fn scan_complete_json_round_trip() {
            let kind = EventKind::ScanComplete {
                scan_id: "scan-99".into(),
                entity_count: 42,
            };
            let json = serde_json::to_string(&kind).unwrap();
            let back: EventKind = serde_json::from_str(&json).unwrap();
            match back {
                EventKind::ScanComplete {
                    scan_id,
                    entity_count,
                } => {
                    assert_eq!(scan_id, "scan-99");
                    assert_eq!(entity_count, 42);
                }
                other => panic!("expected ScanComplete, got: {other:?}"),
            }
        }

        // ── Full Event round-trip ───────────────────────────────────────────

        #[test]
        fn full_event_json_round_trip() {
            let evt = Event::new(
                "scan-7",
                EventKind::ModuleDone {
                    module: "shodan".into(),
                    found: 3,
                },
            );
            let json = serde_json::to_string(&evt).unwrap();
            let back: Event = serde_json::from_str(&json).unwrap();

            assert_eq!(back.scan_id, evt.scan_id);
            assert_eq!(back.ts, evt.ts);
            match back.kind {
                EventKind::ModuleDone { module, found } => {
                    assert_eq!(module, "shodan");
                    assert_eq!(found, 3);
                }
                other => panic!("expected ModuleDone, got: {other:?}"),
            }
        }
    }
}

pub mod port {
    // Storage port — trait-based boundary between the engine and its
    // persistence layer.
    //
    // # Architecture
    //
    // `StoragePort` defines the minimal contract the scan engine and
    // correlator need from storage. The concrete `Store` (SQLite WAL)
    // implements this trait. By depending on the trait rather than the
    // concrete type, the engine becomes:
    //
    // - **Testable** without SQLite: tests can inject a mock/stub.
    // - **Replaceable**: a future PostgreSQL or in-memory backend only
    //   needs to implement `StoragePort`.
    // - **Boundary-explicit**: the engine's storage needs are enumerated
    //   in one place.
    //
    // # Boundary enforcement
    //
    // `core/` and `api/` never import `storage::Store` directly —
    // architecture tests in `tests/architecture.rs` scan the source tree
    // and fail CI if a direct import is introduced. The only legitimate
    // `Store::open()` call sites are the CLI composition roots
    // (`cli/mod.rs`, `cli/provision.rs`) which construct the concrete
    // instance and immediately upcast to `Arc<dyn StoragePort>`.

    use crate::core::{
        correlator::Correlation, entity::Entity, error::Result, event::Event, relation::Relation,
        scan::Scan,
    };

    pub trait StoragePort: Send + Sync {
        // ── Scans ──────────────────────────────────────────────────────────────
        fn upsert_scan(&self, scan: &Scan) -> Result<()>;
        fn get_scan(&self, id: &str) -> Result<Option<Scan>>;
        fn list_scans(&self, limit: usize) -> Result<Vec<Scan>>;
        fn delete_scan(&self, scan_id: &str) -> Result<bool>;

        // ── Entities ───────────────────────────────────────────────────────────
        fn upsert_entity(&self, entity: &Entity) -> Result<()>;
        /// Persist many entities in a single transaction. Takes a slice (not
        /// an owned `Vec`) so the caller retains ownership and can fall back
        /// to per-entity `upsert_entity` if the batch rolls back.
        fn upsert_entities_batch(&self, entities: &[Entity]) -> Result<usize>;
        fn entities_for_scan(&self, scan_id: &str) -> Result<Vec<Entity>>;
        fn entities_filtered(
            &self,
            scan_id: &str,
            kind: Option<&str>,
            min_confidence: Option<f64>,
            value_contains: Option<&str>,
        ) -> Result<Vec<Entity>>;
        fn entity_facets(&self, scan_id: &str) -> Result<Vec<(String, u64)>>;
        fn get_entity(&self, uid: &str) -> Result<Option<Entity>>;
        fn search_entities(&self, query: &str, limit: usize) -> Result<Vec<Entity>>;
        fn scan_ids_for_entity(&self, entity_uid: &str) -> Result<Vec<String>>;
        fn observation_count(&self, entity_uid: &str) -> Result<usize>;

        // ── Correlations ───────────────────────────────────────────────────────
        fn upsert_correlation(&self, c: &Correlation) -> Result<()>;
        fn correlations_for_scan(&self, scan_id: &str) -> Result<Vec<Correlation>>;

        // ── Relations (typed entity-to-entity edges) ────────────────────────────
        fn upsert_relation(&self, r: &Relation) -> Result<()>;
        fn relations_for_scan(&self, scan_id: &str) -> Result<Vec<Relation>>;

        // ── Events ─────────────────────────────────────────────────────────────
        fn insert_event(&self, event: &Event) -> Result<()>;
        fn events_for_scan(&self, scan_id: &str) -> Result<Vec<Event>>;

        // ── Maintenance ─────────────────────────────────────────────────────────
        /// Bound the backing store's write-ahead footprint at a safe boundary
        /// (e.g. a completed scan). Default is a no-op for backends without a
        /// WAL; the SQLite store truncates its `-wal` file. Best-effort.
        fn checkpoint_truncate(&self) -> Result<()> {
            Ok(())
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::sync::Arc;

        use crate::core::entity::EntityKind;
        use crate::core::scan::{Target, TargetKind};

        fn tmp_store() -> Arc<dyn StoragePort> {
            use std::sync::atomic::{AtomicUsize, Ordering};
            static CTR: AtomicUsize = AtomicUsize::new(0);
            let n = CTR.fetch_add(1, Ordering::SeqCst);
            let path = format!(
                "{}/.hse-port-test-{}-{}.db",
                std::env::temp_dir().to_string_lossy(),
                std::process::id(),
                n
            );
            let _ = std::fs::remove_file(&path);
            Arc::new(crate::storage::Store::open(&path).unwrap())
        }

        #[test]
        fn trait_object_scan_round_trip() {
            let store = tmp_store();
            let target = Target::new(TargetKind::Email, "x@y.com");
            let scan = Scan::new("port-scan-1", target);
            store.upsert_scan(&scan).unwrap();
            let got = store.get_scan("port-scan-1").unwrap().unwrap();
            assert_eq!(got.id, "port-scan-1");
        }

        #[test]
        fn trait_object_entity_round_trip() {
            let store = tmp_store();
            let target = Target::new(TargetKind::Email, "x@y.com");
            let scan = Scan::new("port-ent", target);
            store.upsert_scan(&scan).unwrap();

            let e = crate::core::entity::Entity::new(EntityKind::Email, "a@b.com", 0.8, "port-ent");
            store.upsert_entity(&e).unwrap();

            let entities = store.entities_for_scan("port-ent").unwrap();
            assert_eq!(entities.len(), 1);
            assert_eq!(entities[0].value, "a@b.com");

            let got = store.get_entity(&e.uid).unwrap().unwrap();
            assert_eq!(got.uid, e.uid);
        }

        #[test]
        fn trait_object_list_and_delete() {
            let store = tmp_store();
            let t = Target::new(TargetKind::Domain, "example.com");
            store.upsert_scan(&Scan::new("ld-1", t.clone())).unwrap();
            store.upsert_scan(&Scan::new("ld-2", t)).unwrap();

            assert_eq!(store.list_scans(10).unwrap().len(), 2);
            assert!(store.delete_scan("ld-1").unwrap());
            assert_eq!(store.list_scans(10).unwrap().len(), 1);
        }

        #[test]
        fn trait_object_events_round_trip() {
            let store = tmp_store();
            let t = Target::new(TargetKind::Email, "x@y.com");
            store.upsert_scan(&Scan::new("evt-port", t)).unwrap();

            let event = Event::new(
                "evt-port",
                crate::core::event::EventKind::ModuleStart {
                    module: "test".into(),
                },
            );
            store.insert_event(&event).unwrap();

            let events = store.events_for_scan("evt-port").unwrap();
            assert_eq!(events.len(), 1);
        }

        #[test]
        fn trait_object_search_and_facets() {
            let store = tmp_store();
            let t = Target::new(TargetKind::Email, "x@y.com");
            store.upsert_scan(&Scan::new("sf-scan", t)).unwrap();

            let e1 =
                crate::core::entity::Entity::new(EntityKind::Email, "alice@x.com", 0.9, "sf-scan");
            let e2 = crate::core::entity::Entity::new(EntityKind::Domain, "x.com", 0.8, "sf-scan");
            store.upsert_entity(&e1).unwrap();
            store.upsert_entity(&e2).unwrap();

            let results = store.search_entities("alice", 10).unwrap();
            assert_eq!(results.len(), 1);

            let facets = store.entity_facets("sf-scan").unwrap();
            assert!(!facets.is_empty());
        }
    }
}

pub use cancel::CancelHandle;
pub use correlator::{Correlation, Correlator, Severity};
pub use dependency::{ModuleGraph, ModuleGraphSummary};
pub use engine::ScanEngine;
pub use entity::{Classification, Entity, EntityKind, Evidence, scan_id, unix_now};
pub use error::{Error, Result};
pub use event::{Event, EventBus, EventKind};
pub use live::{LiveOptions, LiveRequest, LiveScanner, LiveSession, LiveStatus};
pub use module::{Module, ModuleCategory, ModuleContext, ModuleCost, ModuleInfo, ModuleResult};
pub use port::StoragePort;
pub use relation::{Relation, RelationKind};
pub use scan::{ExpansionStrategy, Scan, ScanOptions, ScanRequest, ScanStatus, Target, TargetKind};
