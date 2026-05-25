//! Correlator — rule-based post-scan analysis.
//!
//! Runs after all modules complete (engine hook). Loads the entities the
//! scan produced and evaluates a fixed set of declarative rules. Each
//! firing rule produces a [`Correlation`] record persisted alongside the
//! scan and emitted on the event bus.

mod rules;

use std::sync::Arc;

use serde::{Deserialize, Serialize};
use tracing::debug;

use crate::core::error::Result;
use crate::storage::store::Store;

// ─── Severity ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn as_canonical(&self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Low => write!(f, "LOW"),
            Self::Medium => write!(f, "MEDIUM"),
            Self::High => write!(f, "HIGH"),
            Self::Critical => write!(f, "CRITICAL"),
        }
    }
}

// ─── Correlation ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Correlation {
    pub rule_id: String,
    pub rule_name: String,
    pub severity: Severity,
    pub description: String,
    pub entity_uids: Vec<String>,
    pub scan_id: String,
    pub ts: u64,
}

impl Correlation {
    pub(crate) fn new(
        rule_id: &str,
        rule_name: &str,
        severity: Severity,
        description: String,
        entity_uids: Vec<String>,
        scan_id: &str,
        ts: u64,
    ) -> Self {
        Self {
            rule_id: rule_id.into(),
            rule_name: rule_name.into(),
            severity,
            description,
            entity_uids,
            scan_id: scan_id.into(),
            ts,
        }
    }
}

// ─── Correlator ────────────────────────────────────────────────────────────

pub struct Correlator {
    store: Arc<Store>,
}

impl Correlator {
    pub fn new(store: Arc<Store>) -> Self {
        Self { store }
    }

    pub fn run(&self, scan_id: &str) -> Result<Vec<Correlation>> {
        let entities = self.store.entities_for_scan(scan_id)?;
        if entities.is_empty() {
            return Ok(Vec::new());
        }
        let firings = rules::evaluate_rules(&entities, scan_id);
        for c in &firings {
            self.store.upsert_correlation(c)?;
        }
        debug!(scan_id, fired = firings.len(), "correlator done");
        Ok(firings)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Severity::as_canonical ──────────────────────────────────────────

    #[test]
    fn as_canonical_returns_lowercase() {
        assert_eq!(Severity::Low.as_canonical(), "low");
        assert_eq!(Severity::Medium.as_canonical(), "medium");
        assert_eq!(Severity::High.as_canonical(), "high");
        assert_eq!(Severity::Critical.as_canonical(), "critical");
    }

    // ── Severity Display ────────────────────────────────────────────────

    #[test]
    fn display_returns_uppercase() {
        assert_eq!(Severity::Low.to_string(), "LOW");
        assert_eq!(Severity::Medium.to_string(), "MEDIUM");
        assert_eq!(Severity::High.to_string(), "HIGH");
        assert_eq!(Severity::Critical.to_string(), "CRITICAL");
    }

    // ── Severity ordering ───────────────────────────────────────────────

    #[test]
    fn severity_ordering() {
        assert!(Severity::Low < Severity::Medium);
        assert!(Severity::Medium < Severity::High);
        assert!(Severity::High < Severity::Critical);
    }

    // ── Severity serde ──────────────────────────────────────────────────

    #[test]
    fn severity_json_round_trip() {
        for (variant, expected_str) in [
            (Severity::Low, "\"low\""),
            (Severity::Medium, "\"medium\""),
            (Severity::High, "\"high\""),
            (Severity::Critical, "\"critical\""),
        ] {
            let json = serde_json::to_string(&variant).unwrap();
            assert_eq!(json, expected_str);
            let back: Severity = serde_json::from_str(&json).unwrap();
            assert_eq!(back, variant);
        }
    }

    // ── Correlation::new ────────────────────────────────────────────────

    #[test]
    fn correlation_new_sets_all_fields() {
        let uids = vec!["uid-a".to_string(), "uid-b".to_string()];
        let c = Correlation::new(
            "R001",
            "test rule",
            Severity::High,
            "something suspicious".to_string(),
            uids.clone(),
            "scan-1",
            1700000000,
        );

        assert_eq!(c.rule_id, "R001");
        assert_eq!(c.rule_name, "test rule");
        assert_eq!(c.severity, Severity::High);
        assert_eq!(c.description, "something suspicious");
        assert_eq!(c.entity_uids, uids);
        assert_eq!(c.scan_id, "scan-1");
        assert_eq!(c.ts, 1700000000);
    }

    // ── Correlation serde round-trip ────────────────────────────────────

    #[test]
    fn correlation_json_round_trip() {
        let original = Correlation::new(
            "R002",
            "exposed creds",
            Severity::Critical,
            "credentials found in breach db".to_string(),
            vec!["uid-x".to_string()],
            "scan-99",
            1700000001,
        );

        let json = serde_json::to_string(&original).unwrap();
        let back: Correlation = serde_json::from_str(&json).unwrap();

        assert_eq!(back.rule_id, original.rule_id);
        assert_eq!(back.rule_name, original.rule_name);
        assert_eq!(back.severity, original.severity);
        assert_eq!(back.description, original.description);
        assert_eq!(back.entity_uids, original.entity_uids);
        assert_eq!(back.scan_id, original.scan_id);
        assert_eq!(back.ts, original.ts);
    }
}
