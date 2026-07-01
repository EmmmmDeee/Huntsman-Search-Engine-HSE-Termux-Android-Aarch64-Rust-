//! AU-070 — Connection broker (identity articulation point).
//!
//! AU-062 rewards a pair's REDUNDANCY (independent routes), AU-069 its INTEGRITY
//! (one route strong end to end), and AU-063 flags a fragile *pair* link (a single
//! route). This is the NODE-level counterpart that none of them capture: an entity
//! that is the **sole** point holding ≥3 identities together — remove it and the
//! identity network fragments. It is the analyst's prime pivot (the linchpin) and
//! the highest-value gap-fill target: corroborate the broker and you harden every
//! connection that runs through it.
//!
//! Built on the shared [`crate::core::relation::connection_brokers`] primitive over
//! the same confined adjacency the other relation rules traverse (one graph, no
//! drift). Fires only for a broker of ≥3 identities — a 2-identity split is a single
//! fragile pair, already AU-063's job.

use std::collections::{BTreeMap, HashMap};

use super::*;
use crate::core::relation::{connection_brokers, identity_uids, sorted_confined_adjacency};

/// AU-070 — Connection broker.
///
/// Delegates articulation detection to [`connection_brokers`], then emits one
/// correlation per node that brokers ≥3 identities. Severity rises with the number
/// of identities the broker holds together (a larger fan-out is a more critical
/// single point of failure).
pub(in crate::core::correlator) fn rule_au_070_connection_broker(
    entities: &[Entity],
    relations: &[Relation],
    scan_id: &str,
    now: u64,
) -> Vec<Correlation> {
    // A 2-identity split is a fragile *pair* (AU-063); a broker is a genuine ≥3-way
    // linchpin.
    const MIN_BROKERED: usize = 3;
    // Only links at or above the Probable tier may *bind* identities — the same
    // floor AU-067 resolves under. Without it a single weak edge makes a common-name
    // node look like the linchpin of dozens of unrelated namesakes.
    const MIN_CONF: f64 = 0.50;

    let by_uid: HashMap<&str, &Entity> = entities.iter().map(|e| (e.uid.as_str(), e)).collect();
    let ids = identity_uids(entities);
    // Build the traversal graph ONCE and reuse it across the articulation search.
    let adj = sorted_confined_adjacency(entities, relations);

    let mut out = Vec::new();
    for broker in connection_brokers(&adj, &ids, MIN_CONF) {
        if broker.brokered.len() < MIN_BROKERED {
            continue;
        }
        let Some(&node) = by_uid.get(broker.uid.as_str()) else {
            continue;
        };

        // Human breakdown of the brokered identities by kind (deterministic order).
        let mut kinds: BTreeMap<String, usize> = BTreeMap::new();
        for uid in &broker.brokered {
            if let Some(e) = by_uid.get(uid.as_str()) {
                *kinds.entry(e.kind.to_string()).or_insert(0) += 1;
            }
        }
        let breakdown = kinds
            .iter()
            .map(|(k, n)| format!("{n} {k}"))
            .collect::<Vec<_>>()
            .join(", ");

        let n = broker.brokered.len();
        let severity = if n >= 5 {
            Severity::High
        } else {
            Severity::Medium
        };

        // The broker first, then every identity it holds together.
        let mut uids = Vec::with_capacity(n + 1);
        uids.push(broker.uid.clone());
        uids.extend(broker.brokered.iter().cloned());
        uids.sort_unstable();
        uids.dedup();

        out.push(Correlation::new(
            "AU-070",
            "Connection broker",
            severity,
            format!(
                "{} ({}) is the sole link binding {n} identities ({breakdown}) — removing it \
                 fragments the network: a single point of failure, and the prime pivot to corroborate",
                node.value, node.kind,
            ),
            uids,
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

    fn edge(from: &Entity, to: &Entity) -> Relation {
        Relation::new(
            from.uid.clone(),
            to.uid.clone(),
            RelationKind::DerivedFrom,
            0.8,
            "s",
        )
    }

    /// Regression guard for `PROBLEM_TREE` T2.24: a dense hub-and-spoke identity
    /// graph (many identities, each linked to every one of a handful of shared
    /// domain hubs — a common OSINT shape, e.g. a breach dump of one company's
    /// staff) drove `connection_brokers`' O(V·(V+E)) articulation search past
    /// `MAX_GRAPH_NODES_FOR_BROKER_SEARCH` graph nodes without this ceiling; this
    /// proves the rule now returns fast rather than running the unbounded search.
    #[test]
    fn au070_returns_fast_on_a_graph_above_the_broker_ceiling() {
        use crate::core::relation::MAX_GRAPH_NODES_FOR_BROKER_SEARCH;

        let n_hubs = 80;
        // One more identity than needed to push the total node count past the
        // ceiling, so the guard is proven to trip by exactly one node.
        let n_identities = MAX_GRAPH_NODES_FOR_BROKER_SEARCH - n_hubs + 1;
        let mut ents: Vec<Entity> = Vec::new();
        let hubs: Vec<Entity> = (0..n_hubs)
            .map(|h| mk(EntityKind::Domain, &format!("hub{h}.example")))
            .collect();
        let mut rels: Vec<Relation> = Vec::new();
        for i in 0..n_identities {
            let ident = mk(EntityKind::Username, &format!("user{i}"));
            for h in &hubs {
                rels.push(edge(&ident, h));
            }
            ents.push(ident);
        }
        ents.extend(hubs);
        assert!(
            ents.len() > MAX_GRAPH_NODES_FOR_BROKER_SEARCH,
            "test setup must exceed the ceiling"
        );

        let start = std::time::Instant::now();
        let out = rule_au_070_connection_broker(&ents, &rels, "s", 0);
        assert!(
            out.is_empty(),
            "above the ceiling, the articulation search must skip rather than run unbounded"
        );
        assert!(
            start.elapsed() < std::time::Duration::from_secs(2),
            "the guard must return well before the unbounded search would (elapsed: {:?})",
            start.elapsed()
        );
    }

    #[test]
    fn au070_fires_on_a_hub_brokering_three_identities() {
        // A domain hub is the sole connection between three identities.
        let hub = mk(EntityKind::Domain, "x.com");
        let email = mk(EntityKind::Email, "a@x.com");
        let uname = mk(EntityKind::Username, "alice");
        let person = mk(EntityKind::Person, "Bob");
        let rels = [edge(&email, &hub), edge(&uname, &hub), edge(&person, &hub)];
        let ents = [hub.clone(), email.clone(), uname.clone(), person.clone()];

        let out = rule_au_070_connection_broker(&ents, &rels, "s", 0);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].rule_id, "AU-070");
        // The finding references the broker and every brokered identity.
        for uid in [&hub.uid, &email.uid, &uname.uid, &person.uid] {
            assert!(out[0].entity_uids.contains(uid));
        }
    }

    #[test]
    fn au070_silent_on_a_two_identity_bridge() {
        // The hub joins only two identities — a single fragile pair, AU-063's job,
        // below the ≥3 broker floor.
        let hub = mk(EntityKind::Domain, "x.com");
        let email = mk(EntityKind::Email, "a@x.com");
        let uname = mk(EntityKind::Username, "alice");
        let rels = [edge(&email, &hub), edge(&uname, &hub)];
        assert!(
            rule_au_070_connection_broker(&[hub, email, uname], &rels, "s", 0).is_empty(),
            "a 2-identity bridge is not a broker"
        );
    }

    #[test]
    fn au070_silent_when_identities_are_redundantly_linked() {
        // Three identities forming a triangle: no single removal disconnects them.
        let a = mk(EntityKind::Email, "a@x.com");
        let b = mk(EntityKind::Username, "alice");
        let c = mk(EntityKind::Phone, "+61400000000");
        let rels = [edge(&a, &b), edge(&b, &c), edge(&a, &c)];
        assert!(rule_au_070_connection_broker(&[a, b, c], &rels, "s", 0).is_empty());
    }
}
