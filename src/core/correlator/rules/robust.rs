//! AU-071 — Robustly-corroborated identity cluster (no single point of failure).
//!
//! AU-067 reports a *resolved* identity cluster — every identity transitively
//! linked into one — but such a cluster can be held together fragilely, by a
//! single connector node (the AU-070 broker). This is the REDUNDANCY counterpart:
//! a resolved cluster that survives the removal of ANY single connector, because
//! its identities are bound by independent routes rather than one linchpin. It is
//! the cluster-level synthesis of AU-062's pairwise redundancy (as AU-067 is of
//! AU-060's reachability), and the highest-confidence "these are one identity"
//! conclusion: no broker can fragment it.
//!
//! Composed from the shared [`crate::core::relation::resolve_identity_clusters`]
//! (the very clusters AU-067 emits) and [`crate::core::relation::connection_brokers`]
//! (the AU-070 articulation finder), at the same Probable floor — so "robust" means
//! exactly "an AU-067 cluster that no AU-070 broker splits", with no drift between
//! the three rules.

use std::collections::{BTreeMap, HashSet};

use super::*;
use crate::core::relation::{
    connection_brokers, identity_uids, resolve_identity_clusters, sorted_confined_adjacency,
};

/// AU-071 — Robustly-corroborated identity cluster.
///
/// Emits one correlation per resolved identity cluster of ≥3 members that no
/// connection broker can split — i.e. removing any single connector leaves the
/// identities mutually reachable. Always High severity: a redundantly-bound
/// cluster is the strongest single-identity finding the graph can produce.
pub(in crate::core::correlator) fn rule_au_071_robust_identity_cluster(
    context: &RuleContext,
    relations: &[Relation],
    scan_id: &str,
    now: u64,
) -> Vec<Correlation> {
    let entities = context.entities();
    const MAX_HOPS: usize = 4;
    const MIN_MEMBERS: usize = 3;
    // The same Probable floor AU-067/AU-070 resolve under, so the cluster set and
    // the broker set are computed over the identical binding-link graph.
    const MIN_CONF: f64 = 0.50;

    let clusters = resolve_identity_clusters(entities, relations, MAX_HOPS, MIN_CONF);
    if clusters.is_empty() {
        return Vec::new();
    }

    // The AU-070 brokers over the same graph: each carries the identity set whose
    // mutual reachability depends on it. A cluster is FRAGILE if some broker holds
    // together ≥2 of its members (removing that broker would split them), ROBUST if
    // none does.
    let by_uid = context.by_uid();
    let ids = identity_uids(entities);
    let adj = sorted_confined_adjacency(entities, relations);
    let brokers = connection_brokers(&adj, &ids, MIN_CONF);

    let mut out = Vec::new();
    for cluster in clusters {
        if cluster.members.len() < MIN_MEMBERS {
            continue;
        }
        let members: HashSet<&str> = cluster.members.iter().map(String::as_str).collect();
        let fragile = brokers.iter().any(|b| {
            b.brokered
                .iter()
                .filter(|u| members.contains(u.as_str()))
                .count()
                >= 2
        });
        if fragile {
            continue;
        }

        // Member-kind breakdown for the description (deterministic by kind name).
        let mut kinds: BTreeMap<String, usize> = BTreeMap::new();
        for uid in &cluster.members {
            if let Some(e) = by_uid.get(uid.as_str()) {
                *kinds.entry(e.kind.to_string()).or_insert(0) += 1;
            }
        }
        let breakdown = kinds
            .iter()
            .map(|(k, n)| format!("{n} {k}"))
            .collect::<Vec<_>>()
            .join(", ");
        let n = cluster.members.len();

        out.push(Correlation::new(
            "AU-071",
            "Robustly-corroborated identity cluster",
            Severity::High,
            format!(
                "{n} identities resolve to one and stay connected after removing ANY single \
                 connector (weakest binding link {:.2}): {breakdown} — a redundantly-corroborated \
                 cluster with no single point of failure, the highest-confidence single-identity \
                 conclusion",
                cluster.min_confidence,
            ),
            cluster.members.clone(),
            scan_id,
            now,
        ));
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

    fn rel(from: &Entity, to: &Entity) -> Relation {
        Relation::new(
            from.uid.clone(),
            to.uid.clone(),
            RelationKind::DerivedFrom,
            0.8,
            "s",
        )
    }

    #[test]
    fn au071_fires_on_a_redundantly_bound_cluster() {
        // Three identities each linked to TWO shared anchors: removing either anchor
        // leaves them connected via the other — no single point of failure.
        let email = mk(EntityKind::Email, "a@x.com");
        let uname = mk(EntityKind::Username, "alice");
        let person = mk(EntityKind::Person, "Alice");
        let d1 = mk(EntityKind::Domain, "x.com");
        let d2 = mk(EntityKind::Domain, "y.com");
        let rels = [
            rel(&email, &d1),
            rel(&uname, &d1),
            rel(&person, &d1),
            rel(&email, &d2),
            rel(&uname, &d2),
            rel(&person, &d2),
        ];
        let ents = [email.clone(), uname.clone(), person.clone(), d1, d2];

        let out = rule_au_071_robust_identity_cluster(&RuleContext::new(&ents), &rels, "s", 0);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].rule_id, "AU-071");
        assert_eq!(out[0].severity, Severity::High);
        for id in [&email.uid, &uname.uid, &person.uid] {
            assert!(out[0].entity_uids.contains(id), "identity must be a member");
        }
    }

    #[test]
    fn au071_silent_on_a_fragile_star_cluster() {
        // Three identities all hang off ONE domain: removing it isolates all three —
        // that domain is a broker (AU-070), so the cluster is NOT robust.
        let email = mk(EntityKind::Email, "a@x.com");
        let uname = mk(EntityKind::Username, "alice");
        let person = mk(EntityKind::Person, "Alice");
        let hub = mk(EntityKind::Domain, "x.com");
        let rels = [rel(&email, &hub), rel(&uname, &hub), rel(&person, &hub)];
        assert!(
            rule_au_071_robust_identity_cluster(
                &RuleContext::new(&[email, uname, person, hub]),
                &rels,
                "s",
                0
            )
            .is_empty(),
            "a star cluster hangs on one broker — not robust"
        );
    }
}
