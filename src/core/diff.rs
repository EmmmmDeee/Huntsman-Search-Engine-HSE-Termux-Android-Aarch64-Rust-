//! Scan comparison — the entity-level difference between two scans.
//!
//! Computes what one entity graph found that the other didn't (`added` /
//! `removed`), what they share (`common`), and which shared entities were
//! re-scored (`confidence_shifts`). Pure — no storage or I/O; the `hse diff`
//! CLI loads the two entity sets (from scan ids or JSON snapshots) and hands
//! them here. Two use cases: **link analysis** between two targets (the
//! `common` set is their shared infrastructure / identity surface), and
//! **time-series monitoring** (snapshot a graph, re-scan later, diff).
//!
//! Entities are matched by their deterministic uid (`SHA-256(kind:value)`), so
//! the same logical entity lines up across scans regardless of which sources
//! found it or when. Output vectors are uid-sorted for stable, diffable output.

use serde::Serialize;

use crate::core::entity::Entity;

/// A `C_eff` change between scans must move at least this much to be reported —
/// filters sub-noise jitter from the corroboration log term.
const SHIFT_EPS: f64 = 0.05;

/// Compact reference to an entity in a diff result.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct EntityRef {
    pub uid: String,
    pub kind: String,
    pub value: String,
    pub c_effective: f64,
}

impl EntityRef {
    fn of(e: &Entity) -> Self {
        Self {
            uid: e.uid.clone(),
            kind: e.kind.to_string(),
            value: e.value.clone(),
            c_effective: e.c_effective(),
        }
    }
}

/// An entity present in both scans whose effective confidence moved materially.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ConfidenceShift {
    pub uid: String,
    pub kind: String,
    pub value: String,
    pub before: f64,
    pub after: f64,
}

/// Entity-level difference of a baseline scan vs a later one.
#[derive(Debug, Clone, Default, Serialize)]
pub struct ScanDiff {
    /// In the later scan, absent from the baseline — newly discovered.
    pub added: Vec<EntityRef>,
    /// In the baseline, gone from the later scan.
    pub removed: Vec<EntityRef>,
    /// Number of entities present in both scans (matched by uid).
    pub common: usize,
    /// Entities present in both whose `C_eff` moved by ≥ `SHIFT_EPS`.
    pub confidence_shifts: Vec<ConfidenceShift>,
}

impl ScanDiff {
    /// True when the two scans are entity-identical (nothing added, removed, or
    /// materially re-scored).
    pub fn is_empty(&self) -> bool {
        self.added.is_empty() && self.removed.is_empty() && self.confidence_shifts.is_empty()
    }

    /// One-line human summary.
    pub fn summary(&self) -> String {
        format!(
            "{} added, {} removed, {} common ({} re-scored)",
            self.added.len(),
            self.removed.len(),
            self.common,
            self.confidence_shifts.len()
        )
    }
}

/// Compute the [`ScanDiff`] of `baseline` vs `later`. Entities are matched by
/// uid; a persisted scan holds at most one entity per uid (the merge dedups),
/// so the keying is collision-free.
pub fn diff_entities(baseline: &[Entity], later: &[Entity]) -> ScanDiff {
    use std::collections::HashMap;

    let a: HashMap<&str, &Entity> = baseline.iter().map(|e| (e.uid.as_str(), e)).collect();
    let b: HashMap<&str, &Entity> = later.iter().map(|e| (e.uid.as_str(), e)).collect();

    let mut added: Vec<EntityRef> = later
        .iter()
        .filter(|e| !a.contains_key(e.uid.as_str()))
        .map(EntityRef::of)
        .collect();
    let mut removed: Vec<EntityRef> = baseline
        .iter()
        .filter(|e| !b.contains_key(e.uid.as_str()))
        .map(EntityRef::of)
        .collect();

    let mut common = 0usize;
    let mut confidence_shifts = Vec::new();
    for e in later {
        if let Some(prev) = a.get(e.uid.as_str()) {
            common += 1;
            let (before, after) = (prev.c_effective(), e.c_effective());
            if (after - before).abs() >= SHIFT_EPS {
                confidence_shifts.push(ConfidenceShift {
                    uid: e.uid.clone(),
                    kind: e.kind.to_string(),
                    value: e.value.clone(),
                    before,
                    after,
                });
            }
        }
    }

    added.sort_by(|x, y| x.uid.cmp(&y.uid));
    removed.sort_by(|x, y| x.uid.cmp(&y.uid));
    confidence_shifts.sort_by(|x, y| x.uid.cmp(&y.uid));
    ScanDiff {
        added,
        removed,
        common,
        confidence_shifts,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::entity::{Entity, EntityKind};

    fn email(v: &str, c: f64) -> Entity {
        Entity::new(EntityKind::Email, v, c, "s")
    }

    #[test]
    fn classifies_added_removed_and_common() {
        let baseline = vec![email("keep@x.com", 0.6), email("gone@x.com", 0.6)];
        let later = vec![email("keep@x.com", 0.6), email("new@x.com", 0.6)];
        let d = diff_entities(&baseline, &later);
        assert_eq!(
            d.added.iter().map(|e| e.value.as_str()).collect::<Vec<_>>(),
            ["new@x.com"]
        );
        assert_eq!(
            d.removed
                .iter()
                .map(|e| e.value.as_str())
                .collect::<Vec<_>>(),
            ["gone@x.com"]
        );
        assert_eq!(d.common, 1);
        assert!(d.confidence_shifts.is_empty());
    }

    #[test]
    fn detects_confidence_shift_on_common_entity() {
        // Same uid (same kind+value), C_eff 0.40 → 0.90 (a candidate confirmed).
        let baseline = vec![email("a@x.com", 0.40)];
        let later = vec![email("a@x.com", 0.90)];
        let d = diff_entities(&baseline, &later);
        assert!(d.added.is_empty() && d.removed.is_empty());
        assert_eq!(d.common, 1);
        assert_eq!(d.confidence_shifts.len(), 1);
        let s = &d.confidence_shifts[0];
        assert!((s.before - 0.40).abs() < 1e-9, "before {s:?}");
        assert!((s.after - 0.90).abs() < 1e-9, "after {s:?}");
    }

    #[test]
    fn sub_eps_jitter_is_not_a_shift() {
        let d = diff_entities(&[email("a@x.com", 0.50)], &[email("a@x.com", 0.52)]);
        assert!(
            d.confidence_shifts.is_empty(),
            "0.02 < SHIFT_EPS must not report"
        );
        assert_eq!(d.common, 1);
    }

    #[test]
    fn identical_scans_diff_empty() {
        let e = vec![Entity::new(EntityKind::Domain, "x.com", 0.7, "s")];
        let d = diff_entities(&e, &e);
        assert!(d.is_empty());
        assert_eq!(d.common, 1);
        assert!(d.summary().starts_with("0 added, 0 removed, 1 common"));
    }

    #[test]
    fn output_is_uid_sorted_deterministic() {
        let later = vec![email("z@x.com", 0.6), email("a@x.com", 0.6)];
        let d = diff_entities(&[], &later);
        // uid-sorted, not insertion-order — deterministic across runs.
        let uids: Vec<&str> = d.added.iter().map(|e| e.uid.as_str()).collect();
        let mut sorted = uids.clone();
        sorted.sort_unstable();
        assert_eq!(uids, sorted);
        assert_eq!(d.added.len(), 2);
    }
}
