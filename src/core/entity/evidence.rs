use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use super::unix_now;

// ─── Evidence ────────────────────────────────────────────────────────────────

/// A single piece of evidence attached to an entity.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Evidence {
    /// Module that produced this evidence.
    pub source: String,
    /// Human-readable summary / label for the record (not the raw data itself).
    pub summary: String,
    /// Raw key/value pairs from the module — the FULL source record, preserved
    /// verbatim for traceability (operator full-fidelity policy: nothing
    /// redacted or omitted, credentials included). The canonical leaked
    /// secret is additionally surfaced as a first-class `Password`/`Credential`
    /// entity so it is searchable and expandable, not just an attribute.
    /// `BTreeMap` (not `HashMap`) so the serialised evidence has a stable,
    /// sorted key order — identical findings must produce byte-identical JSON
    /// (reproducibility / hashable evidence chains), and HashMap iteration order
    /// is randomised per instance.
    #[serde(default)]
    pub attributes: BTreeMap<String, String>,
    /// Unix timestamp (seconds) when evidence was recorded.
    pub recorded_at: u64,
}

impl Evidence {
    pub fn new(source: impl Into<String>, summary: impl Into<String>) -> Self {
        Self {
            source: source.into(),
            summary: summary.into(),
            attributes: BTreeMap::new(),
            recorded_at: unix_now(),
        }
    }

    /// Attach a key/value attribute, **accumulating** rather than clobbering
    /// when the key is already present.
    ///
    /// Operator full-fidelity policy: a repeated key must not silently lose its
    /// earlier value — e.g. several breach rows folded into one evidence record,
    /// each carrying a different `gender`, `date_of_birth`, or `country`. On
    /// collision the new value is appended after `"; "`, **de-duplicated** so
    /// re-asserting an identical value is idempotent and the merged cell never
    /// bloats with repeats. The first-seen value stays first and single-set
    /// callers — the overwhelming majority — are byte-for-byte unchanged.
    pub fn with_attr(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        let key = key.into();
        let value = value.into();
        match self.attributes.get_mut(&key) {
            Some(existing) => {
                if !existing.split("; ").any(|seen| seen == value) {
                    existing.push_str("; ");
                    existing.push_str(&value);
                }
            }
            None => {
                self.attributes.insert(key, value);
            }
        }
        self
    }
}
