//! AU-060 — Transitive identity closure.
//!
//! Finds pairs of identity entities (Person, Username, Email, Phone) that are
//! linked through 2–4 relation-graph hops but have no direct single-edge
//! connection. These multi-hop chains surface the "identity thread" hidden in
//! the attribution graph — e.g. an email linked to a domain via DerivedFrom,
//! the domain to a registrant Person via RegisteredBy, the person to a second
//! username via SubdomainOf — four nodes, three hops, one hidden identity link.
//!
//! Severity decays with path length: Medium at 2–3 hops (a tight chain with
//! few intermediate nodes), Low at 4 hops (longer, noisier path). Every node
//! on the shortest path is included in the correlation's `entity_uids` so the
//! SPA Correlations view can render the chain.

use super::*;

fn is_identity_kind(kind: &EntityKind) -> bool {
    matches!(
        kind,
        EntityKind::Person | EntityKind::Email | EntityKind::Phone | EntityKind::Username
    )
}

/// AU-060 — Transitive identity closure.
///
/// BFS from each confirmed identity entity; fires for every other identity
/// entity reachable in 2–4 hops with no direct single-edge shortcut. Emits
/// one correlation per unique pair (deduplicated across BFS roots).
pub(in crate::core::correlator) fn rule_au_060_transitive_identity_closure(
    entities: &[Entity],
    relations: &[Relation],
    scan_id: &str,
    now: u64,
) -> Vec<Correlation> {
    use std::collections::{HashMap, HashSet, VecDeque};

    const MAX_HOPS: usize = 4;

    if entities
        .iter()
        .filter(|e| is_identity_kind(&e.kind))
        .count()
        < 2
        || relations.is_empty()
    {
        return Vec::new();
    }

    // Index confirmed entities by uid (String keys to unify lifetimes).
    let by_uid: HashMap<String, &Entity> = entities.iter().map(|e| (e.uid.clone(), e)).collect();

    // Undirected adjacency list: only edges where both endpoints are confirmed.
    let mut adj: HashMap<String, Vec<String>> = HashMap::new();
    for r in relations {
        if !by_uid.contains_key(&r.from_uid) || !by_uid.contains_key(&r.to_uid) {
            continue;
        }
        adj.entry(r.from_uid.clone())
            .or_default()
            .push(r.to_uid.clone());
        adj.entry(r.to_uid.clone())
            .or_default()
            .push(r.from_uid.clone());
    }

    let identity_uid_set: HashSet<String> = entities
        .iter()
        .filter(|e| is_identity_kind(&e.kind))
        .map(|e| e.uid.clone())
        .collect();

    // Direct identity↔identity edges: skip these in AU-060 (covered by other rules).
    let mut direct_pairs: HashSet<[String; 2]> = HashSet::new();
    for r in relations {
        if identity_uid_set.contains(&r.from_uid) && identity_uid_set.contains(&r.to_uid) {
            let mut p = [r.from_uid.clone(), r.to_uid.clone()];
            p.sort_unstable();
            direct_pairs.insert(p);
        }
    }

    let identity_uids: Vec<String> = entities
        .iter()
        .filter(|e| is_identity_kind(&e.kind))
        .map(|e| e.uid.clone())
        .collect();

    let mut emitted: HashSet<[String; 2]> = HashSet::new();
    let mut out = Vec::new();

    for start in &identity_uids {
        // BFS up to MAX_HOPS from `start`, recording shortest-path predecessors.
        let mut dist: HashMap<String, usize> = HashMap::new();
        let mut prev: HashMap<String, String> = HashMap::new();
        dist.insert(start.clone(), 0);
        let mut queue: VecDeque<String> = VecDeque::new();
        queue.push_back(start.clone());

        while let Some(uid) = queue.pop_front() {
            let d = dist[&uid];
            if d >= MAX_HOPS {
                continue;
            }
            for nbr in adj.get(&uid).into_iter().flatten() {
                if !dist.contains_key(nbr) {
                    dist.insert(nbr.clone(), d + 1);
                    prev.insert(nbr.clone(), uid.clone());
                    queue.push_back(nbr.clone());
                }
            }
        }

        for dest in &identity_uids {
            if dest == start {
                continue;
            }
            let Some(&hops) = dist.get(dest) else {
                continue;
            };
            if hops < 2 {
                continue; // directly linked (1 hop) — not a transitive chain
            }

            // Skip pairs with a direct single-edge shortcut.
            let mut direct_key = [start.clone(), dest.clone()];
            direct_key.sort_unstable();
            if direct_pairs.contains(&direct_key) {
                continue;
            }

            // Emit each pair once regardless of which BFS root finds it first.
            let mut pair_key = [start.clone(), dest.clone()];
            pair_key.sort_unstable();
            if !emitted.insert(pair_key) {
                continue;
            }

            // Reconstruct the shortest path: dest ← … ← start, then reverse.
            let mut path: Vec<String> = Vec::new();
            let mut cur = dest.clone();
            path.push(cur.clone());
            while &cur != start {
                let p = prev[&cur].clone();
                path.push(p.clone());
                cur = p;
            }
            path.reverse();

            let severity = if hops <= 3 {
                Severity::Medium
            } else {
                Severity::Low
            };
            let src_e = by_uid[start];
            let dst_e = by_uid[dest];
            let intermediates = hops - 1;

            let mut entity_uids = path;
            entity_uids.sort_unstable();

            out.push(Correlation::new(
                "AU-060",
                "Transitive identity closure",
                severity,
                format!(
                    "{} ({}) linked to {} ({}) via {} intermediate node{} — \
                     transitive identity path ({} hops)",
                    src_e.value,
                    src_e.kind,
                    dst_e.value,
                    dst_e.kind,
                    intermediates,
                    if intermediates == 1 { "" } else { "s" },
                    hops,
                ),
                entity_uids,
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

    fn rel(from: &Entity, to: &Entity, kind: RelationKind) -> Relation {
        Relation::new(from.uid.clone(), to.uid.clone(), kind, 0.8, "s")
    }

    #[test]
    fn au060_fires_on_two_hop_chain() {
        // email → domain → person: 2 hops, identity endpoints, 1 intermediate
        let email = mk(EntityKind::Email, "alice@example.com");
        let domain = mk(EntityKind::Domain, "example.com");
        let person = mk(EntityKind::Person, "Alice Doe");
        let rels = [
            rel(&email, &domain, RelationKind::BelongsToDomain),
            rel(&domain, &person, RelationKind::RegisteredBy),
        ];
        let r = rule_au_060_transitive_identity_closure(
            &[email.clone(), domain.clone(), person.clone()],
            &rels,
            "s",
            0,
        );
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].rule_id, "AU-060");
        assert_eq!(r[0].severity, Severity::Medium);
        assert!(r[0].entity_uids.contains(&email.uid));
        assert!(r[0].entity_uids.contains(&person.uid));
        assert!(r[0].entity_uids.contains(&domain.uid));
    }

    #[test]
    fn au060_fires_low_severity_at_four_hops() {
        // email → n1 → n2 → n3 → username: 4 hops → Low
        let email = mk(EntityKind::Email, "a@x.com");
        let n1 = mk(EntityKind::Domain, "x.com");
        let n2 = mk(EntityKind::IpAddress, "1.2.3.4");
        let n3 = mk(EntityKind::Domain, "other.com");
        let uname = mk(EntityKind::Username, "alice");
        let rels = [
            rel(&email, &n1, RelationKind::BelongsToDomain),
            rel(&n1, &n2, RelationKind::HostedOn),
            rel(&n2, &n3, RelationKind::CoLocatedWith),
            rel(&n3, &uname, RelationKind::DerivedFrom),
        ];
        let entities = [email.clone(), n1, n2, n3, uname.clone()];
        let r = rule_au_060_transitive_identity_closure(&entities, &rels, "s", 0);
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].severity, Severity::Low);
        assert!(r[0].entity_uids.contains(&email.uid));
        assert!(r[0].entity_uids.contains(&uname.uid));
    }

    #[test]
    fn au060_skips_directly_connected_identity_pair() {
        // email → person: 1 hop (direct) — not a transitive chain
        let email = mk(EntityKind::Email, "alice@example.com");
        let person = mk(EntityKind::Person, "Alice Doe");
        let rels = [rel(&email, &person, RelationKind::DerivedFrom)];
        assert!(
            rule_au_060_transitive_identity_closure(&[email, person], &rels, "s", 0).is_empty()
        );
    }

    #[test]
    fn au060_skips_direct_shortcut_even_with_longer_path() {
        // email → person (direct), AND email → domain → person (2-hop path).
        // The direct edge takes precedence; AU-060 must stay silent.
        let email = mk(EntityKind::Email, "alice@example.com");
        let domain = mk(EntityKind::Domain, "example.com");
        let person = mk(EntityKind::Person, "Alice Doe");
        let rels = [
            rel(&email, &person, RelationKind::DerivedFrom), // direct
            rel(&email, &domain, RelationKind::BelongsToDomain),
            rel(&domain, &person, RelationKind::RegisteredBy),
        ];
        assert!(
            rule_au_060_transitive_identity_closure(&[email, domain, person], &rels, "s", 0)
                .is_empty()
        );
    }

    #[test]
    fn au060_no_fire_with_only_one_identity_entity() {
        // Only one identity entity — no pair possible
        let email = mk(EntityKind::Email, "a@x.com");
        let domain = mk(EntityKind::Domain, "x.com");
        let rels = [rel(&email, &domain, RelationKind::BelongsToDomain)];
        assert!(
            rule_au_060_transitive_identity_closure(&[email, domain], &rels, "s", 0).is_empty()
        );
    }

    #[test]
    fn au060_emits_each_pair_exactly_once() {
        // Three identity nodes in a chain: A → mid → B → mid2 → C
        // BFS from A finds B (2 hops) and C (4 hops); from B finds A and C;
        // from C finds B and A. Each pair (A,B), (A,C), (B,C) must appear once.
        let a = mk(EntityKind::Email, "a@x.com");
        let mid = mk(EntityKind::Domain, "x.com");
        let b = mk(EntityKind::Username, "alice");
        let mid2 = mk(EntityKind::Domain, "y.com");
        let c = mk(EntityKind::Person, "Alice Doe");
        let rels = [
            rel(&a, &mid, RelationKind::BelongsToDomain),
            rel(&mid, &b, RelationKind::DerivedFrom),
            rel(&b, &mid2, RelationKind::BelongsToDomain),
            rel(&mid2, &c, RelationKind::RegisteredBy),
        ];
        let entities = [a, mid, b, mid2, c];
        let r = rule_au_060_transitive_identity_closure(&entities, &rels, "s", 0);
        // (A,B) at 2 hops, (B,C) at 2 hops, (A,C) at 4 hops → 3 correlations
        assert_eq!(r.len(), 3);
        // Rule ids all AU-060
        assert!(r.iter().all(|c| c.rule_id == "AU-060"));
        // No duplicate entity_uids sets
        let mut uid_sets: Vec<Vec<String>> = r.iter().map(|c| c.entity_uids.clone()).collect();
        uid_sets.dedup();
        assert_eq!(uid_sets.len(), 3, "each pair must emit exactly once");
    }

    #[test]
    fn au060_no_fire_when_relations_empty() {
        let email = mk(EntityKind::Email, "a@x.com");
        let person = mk(EntityKind::Person, "Alice");
        assert!(rule_au_060_transitive_identity_closure(&[email, person], &[], "s", 0).is_empty());
    }

    #[test]
    fn au060_ignores_edges_with_missing_endpoints() {
        // A relation pointing to a uid not in the entity list
        let email = mk(EntityKind::Email, "a@x.com");
        let phantom_uid = "phantom-uid-not-in-entity-list".to_string();
        let person = mk(EntityKind::Person, "Bob");
        // rel: email → phantom → person (phantom not in entities)
        let r1 = Relation::new(
            email.uid.clone(),
            phantom_uid.clone(),
            RelationKind::DerivedFrom,
            0.8,
            "s",
        );
        let r2 = Relation::new(
            phantom_uid,
            person.uid.clone(),
            RelationKind::DerivedFrom,
            0.8,
            "s",
        );
        // No path exists (phantom filtered out) → no firing
        assert!(
            rule_au_060_transitive_identity_closure(&[email, person], &[r1, r2], "s", 0).is_empty()
        );
    }
}
