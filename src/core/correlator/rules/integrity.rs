//! AU-069 — High-integrity connection (max-bottleneck route).
//!
//! AU-060 reports that two identities are *connected*; this reports that the
//! connection is *reliable end to end*. Using the shared
//! [`crate::core::relation::strongest_path`] max-bottleneck finder, it fires when
//! the strongest route between two identities (≥2 hops) has every link at or above
//! a high-confidence floor — so even the weakest step is strong. Where AU-062
//! rewards REDUNDANCY (independent routes) and AU-060 rewards mere reachability
//! (the shortest route, weak links and all), this rewards INTEGRITY: a single
//! route you can trust at every hop. The three are complementary lenses on a
//! discovered connection's quality.

use std::collections::HashMap;

use super::*;
use crate::core::relation::{identity_uids, sorted_confined_adjacency, strongest_path_in};

/// AU-069 — High-integrity connection.
pub(in crate::core::correlator) fn rule_au_069_high_integrity_connection(
    entities: &[Entity],
    relations: &[Relation],
    scan_id: &str,
    now: u64,
) -> Vec<Correlation> {
    const MAX_HOPS: usize = 5;
    // Every link on the strongest route must clear this floor for the connection
    // to count as reliable end to end.
    const STRONG: f64 = 0.70;
    const VERY_STRONG: f64 = 0.85;

    let by_uid: HashMap<&str, &Entity> = entities.iter().map(|e| (e.uid.as_str(), e)).collect();
    let ids = identity_uids(entities);
    // Build the traversal graph ONCE and reuse it for every pair's widest-path
    // search (vs rebuilding + re-sorting it per `strongest_path` call).
    let adj = sorted_confined_adjacency(entities, relations);

    let mut out = Vec::new();
    for (i, &a) in ids.iter().enumerate() {
        for &b in &ids[i + 1..] {
            let Some(path) = strongest_path_in(&adj, a, b, MAX_HOPS) else {
                continue;
            };
            // Multi-hop only — a direct edge is trivially high-integrity and is
            // covered by the direct-link rules — and reliable at every hop.
            if path.hops < 2 || path.min_confidence < STRONG {
                continue;
            }
            let (Some(&ea), Some(&eb)) = (by_uid.get(a), by_uid.get(b)) else {
                continue;
            };
            let severity = if path.min_confidence >= VERY_STRONG {
                Severity::High
            } else {
                Severity::Medium
            };

            // Every node on the strongest route, sorted/deduped for a stable set.
            let mut uids: Vec<String> = Vec::with_capacity(path.hops + 1);
            uids.push(path.from_uid.clone());
            uids.extend(path.steps.iter().map(|s| s.to_uid.clone()));
            uids.sort_unstable();
            uids.dedup();

            out.push(Correlation::new(
                "AU-069",
                "High-integrity connection",
                severity,
                format!(
                    "{} ({}) and {} ({}) are connected by a {}-hop route whose every link is ≥ {:.2} \
                     (weakest {:.2}) — a connection reliable end to end, not merely present",
                    ea.value,
                    ea.kind,
                    eb.value,
                    eb.kind,
                    path.hops,
                    STRONG,
                    path.min_confidence,
                ),
                uids,
                scan_id,
                now,
            ));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::relation::{Relation, RelationKind};

    fn mk(kind: EntityKind, value: &str) -> Entity {
        Entity::new(kind, value, 0.8, "s")
    }

    fn edge(from: &Entity, to: &Entity, c: f64) -> Relation {
        Relation::new(
            from.uid.clone(),
            to.uid.clone(),
            RelationKind::DerivedFrom,
            c,
            "s",
        )
    }

    #[test]
    fn au069_fires_on_an_end_to_end_strong_route() {
        // email —0.9— person —0.9— username: a 2-hop route strong at every hop.
        let a = mk(EntityKind::Email, "a@x.com");
        let mid = mk(EntityKind::Person, "Alice");
        let b = mk(EntityKind::Username, "alice");
        let rels = [edge(&a, &mid, 0.9), edge(&mid, &b, 0.9)];
        let out =
            rule_au_069_high_integrity_connection(&[a.clone(), mid, b.clone()], &rels, "s", 0);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].rule_id, "AU-069");
        assert_eq!(out[0].severity, Severity::High);
        assert!(out[0].entity_uids.contains(&a.uid));
        assert!(out[0].entity_uids.contains(&b.uid));
    }

    #[test]
    fn au069_silent_when_a_link_is_weak() {
        // The only route has a weak hop (0.3) — present but not reliable end to end.
        let a = mk(EntityKind::Email, "a@x.com");
        let mid = mk(EntityKind::Person, "Alice");
        let b = mk(EntityKind::Username, "alice");
        let rels = [edge(&a, &mid, 0.9), edge(&mid, &b, 0.3)];
        assert!(rule_au_069_high_integrity_connection(&[a, mid, b], &rels, "s", 0).is_empty());
    }

    #[test]
    fn au069_silent_on_a_direct_one_hop_link() {
        // A direct edge is not a transitive high-integrity finding.
        let a = mk(EntityKind::Email, "a@x.com");
        let b = mk(EntityKind::Username, "alice");
        let rels = [edge(&a, &b, 0.95)];
        assert!(rule_au_069_high_integrity_connection(&[a, b], &rels, "s", 0).is_empty());
    }
}
