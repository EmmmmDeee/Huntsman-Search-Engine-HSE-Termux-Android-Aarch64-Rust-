//! Scan request, target, status, and per-scan customisation options.

use serde::{Deserialize, Serialize};

use crate::core::entity::{EntityKind, unix_now};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TargetKind {
    Email,
    Username,
    Phone,
    FullName,
    IpAddress,
    Domain,
    Asn,
    Coordinates,
    Address,
}

impl TargetKind {
    /// Map an entity kind to a target kind, so an entity produced by one
    /// module can become the input target for another module.
    ///
    /// Returns `None` for entity kinds that have no natural scan target
    /// (organisations, MACs, raw URLs, credentials, etc.).
    pub fn from_entity_kind(kind: &EntityKind) -> Option<Self> {
        match kind {
            EntityKind::Email => Some(Self::Email),
            EntityKind::Username => Some(Self::Username),
            EntityKind::Phone => Some(Self::Phone),
            EntityKind::Person => Some(Self::FullName),
            EntityKind::IpAddress => Some(Self::IpAddress),
            EntityKind::Domain => Some(Self::Domain),
            EntityKind::Asn => Some(Self::Asn),
            EntityKind::Coordinates => Some(Self::Coordinates),
            EntityKind::Address => Some(Self::Address),
            EntityKind::Organisation
            | EntityKind::AbnAcn
            | EntityKind::MacAddress
            | EntityKind::DeviceId
            | EntityKind::Url
            | EntityKind::Credential
            | EntityKind::Password
            | EntityKind::Other(_) => None,
        }
    }

    /// The matching entity kind for normalisation purposes. Always defined.
    pub fn to_entity_kind(self) -> EntityKind {
        match self {
            Self::Email => EntityKind::Email,
            Self::Username => EntityKind::Username,
            Self::Phone => EntityKind::Phone,
            Self::FullName => EntityKind::Person,
            Self::IpAddress => EntityKind::IpAddress,
            Self::Domain => EntityKind::Domain,
            Self::Asn => EntityKind::Asn,
            Self::Coordinates => EntityKind::Coordinates,
            Self::Address => EntityKind::Address,
        }
    }

    /// Canonical lowercase snake_case identifier — matches the serde-serialised
    /// form (`#[serde(rename_all = "snake_case")]`). Use this everywhere a
    /// machine-readable target-kind string is required (notably `scan_id`
    /// derivation, which must be identical across CLI and HTTP paths so the
    /// same target always yields the same id).
    pub fn canonical_str(&self) -> &'static str {
        match self {
            Self::Email => "email",
            Self::Username => "username",
            Self::Phone => "phone",
            Self::FullName => "full_name",
            Self::IpAddress => "ip_address",
            Self::Domain => "domain",
            Self::Asn => "asn",
            Self::Coordinates => "coordinates",
            Self::Address => "address",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Target {
    pub kind: TargetKind,
    pub value: String,
}

impl Target {
    pub fn new(kind: TargetKind, value: impl Into<String>) -> Self {
        Self {
            kind,
            value: value.into(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ScanStatus {
    Pending,
    Running,
    Complete,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Scan {
    pub id: String,
    pub target: Target,
    pub status: ScanStatus,
    pub started_at: u64,
    pub finished_at: Option<u64>,
    pub entity_count: usize,
    pub error: Option<String>,
    #[serde(default)]
    pub options: ScanOptions,
}

impl Scan {
    pub fn new(id: impl Into<String>, target: Target) -> Self {
        Self {
            id: id.into(),
            target,
            status: ScanStatus::Pending,
            started_at: unix_now(),
            finished_at: None,
            entity_count: 0,
            error: None,
            options: ScanOptions::default(),
        }
    }

    pub fn with_options(mut self, options: ScanOptions) -> Self {
        self.options = options;
        self
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanRequest {
    pub kind: TargetKind,
    pub value: String,
    #[serde(default)]
    pub options: ScanOptions,
}

/// Per-scan customisation. All fields optional; defaults preserve plain-scan
/// behaviour. The engine respects every field at dispatch time.
///
/// Adding a knob = add a field here; CLI/API/UI surface it as needed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanOptions {
    /// Allowlist of module names. None = run every module that accepts the target.
    pub modules: Option<Vec<String>>,

    /// Modules to exclude after allowlist filtering.
    #[serde(default)]
    pub exclude_modules: Vec<String>,

    /// Delay between module dispatches, in milliseconds. 0 = no throttle.
    #[serde(default)]
    pub throttle_ms: u64,

    /// Concurrent module cap. 0 = sequential (default for v0.1).
    /// Reserved for v0.3+ parallel dispatcher.
    #[serde(default)]
    pub max_concurrent: usize,

    /// Per-module timeout override (ms). None = `MODULE_TIMEOUT_MS`.
    pub module_timeout_ms: Option<u64>,

    /// Drop entities whose base `confidence` is below this. None = no filter.
    pub min_confidence: Option<f64>,

    /// Skip modules whose `cost()` is `KeyGated` or `Paid`.
    #[serde(default)]
    pub free_only: bool,

    /// Skip modules where `is_passive()` returns false.
    #[serde(default)]
    pub passive_only: bool,

    // ── Autonomous expansion (v0.2+) ────────────────────────────────────────
    /// Recursive expansion depth. 0 = no expansion (single round, v0.1 behaviour).
    /// Each round picks high-confidence entities from prior rounds, converts
    /// them to scan targets, and runs all accepting modules on them.
    #[serde(default)]
    pub depth: u32,

    /// Only expand entities whose `c_effective()` is at least this. Default 0.75
    /// (Verified tier) — keeps expansion focused on the data the engine itself
    /// rates as solid. Stronger filter than `min_confidence`, which gates the
    /// base confidence at first encounter.
    #[serde(default = "default_min_expand_confidence")]
    pub min_expand_confidence: f64,

    /// Hard cap on total entities. Stops expansion once reached. `None` = no cap.
    pub max_entities: Option<usize>,

    /// Hard cap on total wall-time, in seconds. Stops expansion once exceeded. `None` = no cap.
    pub max_wall_time_secs: Option<u64>,
}

impl Default for ScanOptions {
    fn default() -> Self {
        Self {
            modules: None,
            exclude_modules: Vec::new(),
            throttle_ms: 0,
            max_concurrent: 0,
            module_timeout_ms: None,
            min_confidence: None,
            free_only: false,
            passive_only: false,
            depth: 0,
            min_expand_confidence: default_min_expand_confidence(),
            max_entities: None,
            max_wall_time_secs: None,
        }
    }
}

fn default_min_expand_confidence() -> f64 {
    0.75
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn options_default_is_inert() {
        let o = ScanOptions::default();
        assert!(o.modules.is_none());
        assert_eq!(o.throttle_ms, 0);
        assert!(!o.free_only);
        assert!(!o.passive_only);
        assert_eq!(o.depth, 0);
        assert!((o.min_expand_confidence - 0.75).abs() < 1e-9);
    }

    #[test]
    fn target_kind_round_trips_via_entity_kind() {
        for tk in [
            TargetKind::Email,
            TargetKind::Username,
            TargetKind::Phone,
            TargetKind::FullName,
            TargetKind::IpAddress,
            TargetKind::Domain,
            TargetKind::Asn,
            TargetKind::Coordinates,
            TargetKind::Address,
        ] {
            let ek = tk.to_entity_kind();
            assert_eq!(TargetKind::from_entity_kind(&ek), Some(tk));
        }
    }

    #[test]
    fn unscannable_entity_kinds_return_none() {
        assert!(TargetKind::from_entity_kind(&EntityKind::Organisation).is_none());
        assert!(TargetKind::from_entity_kind(&EntityKind::MacAddress).is_none());
        assert!(TargetKind::from_entity_kind(&EntityKind::Credential).is_none());
        assert!(TargetKind::from_entity_kind(&EntityKind::Password).is_none());
    }

    #[test]
    fn options_round_trip_json() {
        let o = ScanOptions {
            modules: Some(vec!["hibp".into(), "crtsh".into()]),
            throttle_ms: 250,
            free_only: true,
            ..Default::default()
        };
        let s = serde_json::to_string(&o).unwrap();
        let back: ScanOptions = serde_json::from_str(&s).unwrap();
        assert_eq!(back.modules.as_ref().unwrap().len(), 2);
        assert_eq!(back.throttle_ms, 250);
        assert!(back.free_only);
    }

    #[test]
    fn scan_request_round_trip() {
        let req = ScanRequest {
            kind: TargetKind::Email,
            value: "x@y.com".into(),
            options: ScanOptions::default(),
        };
        let s = serde_json::to_string(&req).unwrap();
        assert!(s.contains("\"kind\":\"email\""));
    }
}
