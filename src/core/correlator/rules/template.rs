//! AU-064 — Generalized pathway template (a reusable attribution route).
//!
//! Backward synthesis: take the connections a scan *confirmed* and reason back to
//! the general *means* that produced them. When the same abstract pathway — the
//! ordered sequence of entity kinds and the relation kinds joining them — links
//! two or more distinct identity pairs, that route has proven itself repeatable.
//! It is no longer a one-off chain but a **template**: a confirmed way to connect
//! *that class* of identity to *that class* of identity, which the operator can
//! re-apply, and which (persisted across scans by the engine) lets every future
//! scan arrive at the same class of connection by a route already known to work.
//!
//! The generalisation itself is the shared [`crate::core::relation::connection_templates`]
//! primitive, so the routes this rule fires on *within* a scan are exactly the
//! ones the engine learns *across* scans — one definition, no drift.

use std::collections::BTreeSet;

use super::*;
use crate::core::relation::connection_templates;

/// AU-064 — Generalized pathway template.
pub(in crate::core::correlator) fn rule_au_064_generalized_pathway_template(
    entities: &[Entity],
    relations: &[Relation],
    scan_id: &str,
    now: u64,
) -> Vec<Correlation> {
    const MAX_HOPS: usize = 4;

    let mut out = Vec::new();
    for ct in connection_templates(entities, relations, MAX_HOPS) {
        if ct.pairs.len() < 2 {
            continue; // a single instance is not yet a generalised pattern
        }
        let mut uids: BTreeSet<String> = BTreeSet::new();
        for (f, t) in &ct.pairs {
            uids.insert(f.clone());
            uids.insert(t.clone());
        }
        let n = ct.pairs.len();
        let severity = if n >= 3 {
            Severity::Medium
        } else {
            Severity::Low
        };
        out.push(Correlation::new(
            "AU-064",
            "Generalized pathway template",
            severity,
            format!(
                "the route [{}] linked {n} distinct identity pairs this scan — a reusable \
                 attribution pattern, not a one-off chain; the same template is a confirmed \
                 means to connect that class of identity again",
                ct.template,
            ),
            uids.into_iter().collect(),
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

    fn id(kind: EntityKind, value: &str) -> Entity {
        Entity::new(kind, value, 0.8, "s")
    }

    fn rel(from: &Entity, to: &Entity, kind: RelationKind) -> Relation {
        Relation::new(from.uid.clone(), to.uid.clone(), kind, 0.8, "s")
    }

    #[test]
    fn au064_fires_when_a_route_repeats_across_pairs() {
        // Two pairs share the route Email →belongs_to_domain→ Domain
        // →registered_by→ Person.
        let e1 = id(EntityKind::Email, "a@x.com");
        let d1 = id(EntityKind::Domain, "x.com");
        let p1 = id(EntityKind::Person, "Alice");
        let e2 = id(EntityKind::Email, "b@y.com");
        let d2 = id(EntityKind::Domain, "y.com");
        let p2 = id(EntityKind::Person, "Bob");
        let rels = [
            rel(&e1, &d1, RelationKind::BelongsToDomain),
            rel(&d1, &p1, RelationKind::RegisteredBy),
            rel(&e2, &d2, RelationKind::BelongsToDomain),
            rel(&d2, &p2, RelationKind::RegisteredBy),
        ];
        let out =
            rule_au_064_generalized_pathway_template(&[e1, d1, p1, e2, d2, p2], &rels, "s", 0);
        assert_eq!(
            out.len(),
            1,
            "one generalised template across the two pairs"
        );
        assert_eq!(out[0].rule_id, "AU-064");
        assert!(out[0].description.contains("2 distinct identity pairs"));
    }

    #[test]
    fn au064_silent_on_a_single_instance() {
        // One pair, one route — nothing to generalise yet.
        let e1 = id(EntityKind::Email, "a@x.com");
        let d1 = id(EntityKind::Domain, "x.com");
        let p1 = id(EntityKind::Person, "Alice");
        let rels = [
            rel(&e1, &d1, RelationKind::BelongsToDomain),
            rel(&d1, &p1, RelationKind::RegisteredBy),
        ];
        assert!(rule_au_064_generalized_pathway_template(&[e1, d1, p1], &rels, "s", 0).is_empty());
    }
}
