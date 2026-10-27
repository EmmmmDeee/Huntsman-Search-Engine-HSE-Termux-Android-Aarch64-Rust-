//! Which saved scans a retention pass may delete, so a store that keeps collecting (continuous
//! mode on a phone, a scheduled `scans watch`) stays under its capacity by the operator's choice.
//!
//! Scans are grouped by what they looked up: one target by one lookup kind. In each group the
//! newest `keep` scans are kept, by creation time, and at least one always is. Of the rest only
//! scans that have ended may go, because an active scan still has a worker writing to it. The
//! plan deletes nothing itself: `scans prune` shows it and deletes only when told to.

use std::collections::BTreeMap;

use crate::scan_store::ScanRecord;

/// The scans a pass keeping the newest `keep` of each target and lookup kind would delete, oldest
/// first. A `keep` of 0 keeps one, so a target's newest scan is never planned for deletion.
#[must_use]
pub fn prunable(records: &[ScanRecord], keep: usize) -> Vec<&ScanRecord> {
    let keep = keep.max(1);
    let mut groups: BTreeMap<(&str, &str), Vec<&ScanRecord>> = BTreeMap::new();
    for record in records {
        groups
            .entry((record.kind.as_str(), record.target.as_str()))
            .or_default()
            .push(record);
    }
    let mut plan: Vec<&ScanRecord> = Vec::new();
    for mut group in groups.into_values() {
        group.sort_by(|a, b| b.created.cmp(&a.created).then_with(|| b.id.cmp(&a.id)));
        plan.extend(
            group
                .into_iter()
                .skip(keep)
                .filter(|record| !record.status.is_active()),
        );
    }
    plan.sort_by(|a, b| a.created.cmp(&b.created).then_with(|| a.id.cmp(&b.id)));
    plan
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan_store::{FORMAT_VERSION, RiskCounts, ScanOptions, ScanStatus};

    fn record(id: &str, target: &str, kind: &str, created: u64, status: ScanStatus) -> ScanRecord {
        ScanRecord {
            format_version: FORMAT_VERSION,
            id: id.into(),
            name: String::new(),
            target: target.into(),
            target_type: String::new(),
            kind: kind.into(),
            options: ScanOptions::default(),
            status,
            created,
            started: None,
            ended: None,
            elements: 0,
            unique: 0,
            correlations: RiskCounts::default(),
            errors: 0,
            modules_run: Vec::new(),
            owner: None,
            owner_started: None,
        }
    }

    fn ids(plan: &[&ScanRecord]) -> Vec<String> {
        plan.iter().map(|record| record.id.clone()).collect()
    }

    #[test]
    fn the_newest_of_each_target_and_kind_are_kept_and_the_rest_planned_oldest_first() {
        let records = vec![
            record("a1", "example.com", "domain", 1, ScanStatus::Finished),
            record("a2", "example.com", "domain", 2, ScanStatus::Finished),
            record("a3", "example.com", "domain", 3, ScanStatus::Finished),
            record("b1", "1.1.1.1", "ip", 4, ScanStatus::Finished),
            record("b2", "1.1.1.1", "ip", 5, ScanStatus::Finished),
            // The same target by another lookup is its own line of evidence.
            record("c1", "example.com", "email", 6, ScanStatus::Finished),
        ];
        assert_eq!(ids(&prunable(&records, 1)), vec!["a1", "a2", "b1"]);
        assert_eq!(ids(&prunable(&records, 2)), vec!["a1"]);
        assert!(prunable(&records, 3).is_empty());
    }

    #[test]
    fn an_active_scan_is_never_planned() {
        let records = vec![
            record("old", "example.com", "domain", 1, ScanStatus::Running),
            record(
                "older",
                "example.com",
                "domain",
                0,
                ScanStatus::AbortRequested,
            ),
            record("new", "example.com", "domain", 2, ScanStatus::Finished),
        ];
        assert!(prunable(&records, 1).is_empty());
    }

    #[test]
    fn keeping_none_still_keeps_the_newest() {
        let records = vec![
            record("a1", "example.com", "domain", 1, ScanStatus::Finished),
            record("a2", "example.com", "domain", 2, ScanStatus::ErrorFailed),
        ];
        assert_eq!(ids(&prunable(&records, 0)), vec!["a1"]);
    }

    #[test]
    fn ties_in_creation_time_are_broken_by_id() {
        let records = vec![
            record("a", "example.com", "domain", 1, ScanStatus::Finished),
            record("b", "example.com", "domain", 1, ScanStatus::Finished),
        ];
        assert_eq!(ids(&prunable(&records, 1)), vec!["a"]);
    }
}
