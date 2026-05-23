//! Scan request, target, status, and per-scan customisation options.

use serde::{Deserialize, Serialize};

use crate::core::entity::unix_now;

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
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
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

    /// Recursive expansion depth (live-mode use, v0.5+). 0 = no recursion.
    #[serde(default)]
    pub depth: u32,
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
