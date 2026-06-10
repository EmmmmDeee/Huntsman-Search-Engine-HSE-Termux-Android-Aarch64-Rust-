//! Core types: entity, scan, event, module trait, engine.
//!
//! Nothing in `core` imports from `modules/` — modules depend on core, never
//! the other way around. This keeps the engine module-agnostic.

pub mod convex;
pub mod correlator;
pub mod crypto;
pub mod dependency;
pub mod diff;
pub mod engine;
pub mod entity;
pub mod event;
pub mod gexf;
pub mod live;
pub mod module;
pub mod port;
pub mod profiles;
pub mod relation;
pub mod roi;
pub mod scan;
#[cfg(test)]
pub mod test_support;
pub mod timeline;
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
    /// Datacenter / CDN / cloud-host location, not a residence. Carried by
    /// coordinates that geolocate a hosting IP (e.g. a Cloudflare edge), so the
    /// area-of-operation rule (AU-052) can exclude them from a person's footprint.
    pub const HOSTING: &str = "hosting";

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
