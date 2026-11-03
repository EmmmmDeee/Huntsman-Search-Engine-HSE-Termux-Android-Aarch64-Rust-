//! Conservative, deterministic temporal consistency checks over existing OSINT timeline events.
//! No network requests or new identity assertions. Conflicts are leads, not proof of wrongdoing.
use std::collections::BTreeMap;
use serde::{Deserialize, Serialize};
use crate::timeline::{TimelineEvent, TimelineEventKind};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TemporalConflict {
    pub entity_uid: String,
    pub rule: String,
    pub earlier_kind: String,
    pub earlier_ts: i64,
    pub later_kind: String,
    pub later_ts: i64,
    pub sources: Vec<String>,
}

/// Identify impossible ordering of *comparable* event kinds for the same entity.
/// Sources are retained verbatim; multiple collectors are not treated as independent
/// corroboration. The output contains no invented confidence or identity linkage.
#[must_use]
pub fn detect(events: &[TimelineEvent]) -> Vec<TemporalConflict> {
    let mut by_entity: BTreeMap<&str, Vec<&TimelineEvent>> = BTreeMap::new();
    for event in events {
        if !event.entity_uid.is_empty() {
            by_entity.entry(&event.entity_uid).or_default().push(event);
        }
    }
    let mut conflicts = Vec::new();
    for (uid, items) in by_entity {
        for (start_kind, end_kind, rule) in [
            (TimelineEventKind::FirstSeen, TimelineEventKind::LastSeen, "first_seen_after_last_seen"),
            (TimelineEventKind::Registered, TimelineEventKind::Expiry, "registered_after_expiry"),
            (TimelineEventKind::Incorporation, TimelineEventKind::Dissolution, "incorporation_after_dissolution"),
        ] {
            let starts: Vec<_> = items.iter().copied().filter(|e| e.kind == start_kind).collect();
            let ends: Vec<_> = items.iter().copied().filter(|e| e.kind == end_kind).collect();
            // A cross-product can be misleading when sources refer to different
            // records. Require matching provenance source prefix before comparison.
            for start in &starts {
                for end in &ends {
                    let start_source = start.source.split(':').next().unwrap_or("");
                    let end_source = end.source.split(':').next().unwrap_or("");
                    if start_source.is_empty() || start_source != end_source || start.ts <= end.ts {
                        continue;
                    }
                    conflicts.push(TemporalConflict {
                        entity_uid: uid.to_owned(),
                        rule: rule.to_owned(),
                        earlier_kind: end_kind.as_str().to_owned(),
                        earlier_ts: end.ts,
                        later_kind: start_kind.as_str().to_owned(),
                        later_ts: start.ts,
                        sources: vec![start.source.clone(), end.source.clone()],
                    });
                }
            }
        }
    }
    conflicts.sort_by(|a,b| (&a.entity_uid, &a.rule, a.earlier_ts, a.later_ts, &a.sources)
        .cmp(&(&b.entity_uid, &b.rule, b.earlier_ts, b.later_ts, &b.sources)));
    conflicts.dedup();
    conflicts
}

#[cfg(test)]
mod tests {
    use super::*;
    fn event(uid: &str, source: &str, kind: TimelineEventKind, ts: i64) -> TimelineEvent {
        TimelineEvent {
            ts, iso: String::new(), kind, label: String::new(),
            entity_uid: uid.into(), entity_value: String::new(),
            entity_kind: String::new(), source: source.into(), confidence: 0.5,
        }
    }
    #[test]
    fn flags_same_source_inverted_bounds() {
        let items = vec![
            event("a", "rdap:first_seen", TimelineEventKind::FirstSeen, 20),
            event("a", "rdap:last_seen", TimelineEventKind::LastSeen, 10),
        ];
        let found = detect(&items);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].rule, "first_seen_after_last_seen");
    }
    #[test]
    fn does_not_join_entities_or_unrelated_sources() {
        let items = vec![
            event("a", "rdap:first_seen", TimelineEventKind::FirstSeen, 20),
            event("b", "rdap:last_seen", TimelineEventKind::LastSeen, 10),
            event("a", "archive:last_seen", TimelineEventKind::LastSeen, 10),
        ];
        assert!(detect(&items).is_empty());
    }
    #[test]
    fn equal_bounds_are_not_conflicts() {
        let items = vec![
            event("a", "rdap:registered", TimelineEventKind::Registered, 10),
            event("a", "rdap:expires", TimelineEventKind::Expiry, 10),
        ];
        assert!(detect(&items).is_empty());
    }
}
