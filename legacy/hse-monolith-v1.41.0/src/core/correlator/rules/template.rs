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
use crate::core::relation::{IDENTITY_LINK_MIN_CONF, connection_templates};

/// AU-064 — Generalized pathway template.
pub(in crate::core::correlator) fn rule_au_064_generalized_pathway_template(
    context: &RuleContext,
    relations: &[Relation],
    scan_id: &str,
    now: u64,
) -> Vec<Correlation> {
    let entities = context.entities();
    const MAX_HOPS: usize = 4;

    let mut out = Vec::new();
    // IDENTITY_LINK_MIN_CONF: repeating a weak, damped-confidence route across
    // two pairs does not make it a proven attribution pattern — the floor
    // that keeps AU-060's transitive closure off same-surname-stranger kin
    // hops applies here too, so connection_templates only generalises over
    // routes trustworthy enough to repeat.
    for ct in connection_templates(entities, relations, MAX_HOPS, IDENTITY_LINK_MIN_CONF) {
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

    fn rel_conf(from: &Entity, to: &Entity, kind: RelationKind, conf: f64) -> Relation {
        Relation::new(from.uid.clone(), to.uid.clone(), kind, conf, "s")
    }

    #[test]
    fn au064_silent_when_the_repeated_route_is_built_from_damped_edges() {
        // The same route (Email →belongs_to_domain→ Domain →registered_by→
        // Person) repeats across two pairs, but every hop is a DAMPED (0.40)
        // edge — the same magnitude `derive_kinship` produces for a
        // same-surname pair. Before IDENTITY_LINK_MIN_CONF applied to
        // connection_templates, repeating this weak route twice was enough to
        // call it a "reusable attribution pattern" and assert it as proven —
        // but a weak coincidence repeated twice is still weak, not strong (see
        // this rule's module doc). With the floor, `identity_paths` still
        // finds both paths (it does not itself drop low-confidence edges),
        // but connection_templates excludes any path below the floor from
        // being grouped, so the template accumulates ZERO pairs and AU-064
        // never fires.
        let e1 = id(EntityKind::Email, "a@x.com");
        let d1 = id(EntityKind::Domain, "x.com");
        let p1 = id(EntityKind::Person, "Alice");
        let e2 = id(EntityKind::Email, "b@y.com");
        let d2 = id(EntityKind::Domain, "y.com");
        let p2 = id(EntityKind::Person, "Bob");
        let rels = [
            rel_conf(&e1, &d1, RelationKind::BelongsToDomain, 0.40),
            rel_conf(&d1, &p1, RelationKind::RegisteredBy, 0.40),
            rel_conf(&e2, &d2, RelationKind::BelongsToDomain, 0.40),
            rel_conf(&d2, &p2, RelationKind::RegisteredBy, 0.40),
        ];
        assert!(
            rule_au_064_generalized_pathway_template(
                &RuleContext::new(&[e1, d1, p1, e2, d2, p2]),
                &rels,
                "s",
                0
            )
            .is_empty(),
            "a route built entirely from sub-floor damped edges must not \
             generalise into a proven attribution pattern, however many times \
             it repeats"
        );
    }

    #[test]
    fn au064_still_fires_when_the_repeated_route_clears_the_floor() {
        // The same shape, but every hop is a legitimate 0.60 (>=
        // IDENTITY_LINK_MIN_CONF) — a genuinely repeated, trustworthy route,
        // which AU-064 must still generalise.
        let e1 = id(EntityKind::Email, "a@x.com");
        let d1 = id(EntityKind::Domain, "x.com");
        let p1 = id(EntityKind::Person, "Alice");
        let e2 = id(EntityKind::Email, "b@y.com");
        let d2 = id(EntityKind::Domain, "y.com");
        let p2 = id(EntityKind::Person, "Bob");
        let rels = [
            rel_conf(&e1, &d1, RelationKind::BelongsToDomain, 0.60),
            rel_conf(&d1, &p1, RelationKind::RegisteredBy, 0.60),
            rel_conf(&e2, &d2, RelationKind::BelongsToDomain, 0.60),
            rel_conf(&d2, &p2, RelationKind::RegisteredBy, 0.60),
        ];
        assert_eq!(
            rule_au_064_generalized_pathway_template(
                &RuleContext::new(&[e1, d1, p1, e2, d2, p2]),
                &rels,
                "s",
                0
            )
            .len(),
            1,
            "a route whose edges all clear the floor must still generalise \
             when repeated"
        );
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
        let out = rule_au_064_generalized_pathway_template(
            &RuleContext::new(&[e1, d1, p1, e2, d2, p2]),
            &rels,
            "s",
            0,
        );
        assert_eq!(
            out.len(),
            1,
            "one generalised template across the two pairs"
        );
        assert_eq!(out[0].rule_id, "AU-064");
        assert!(out[0].description.contains("2 distinct identity pairs"));
    }

    #[test]
    fn au064_escalates_to_medium_when_the_route_repeats_across_three_pairs() {
        // Three pairs share the route Email →belongs_to_domain→ Domain
        // →registered_by→ Person → ct.pairs.len() == 3 → severity escalates
        // Low→Medium. The two-pair sibling above covers the base Low arm.
        let e1 = id(EntityKind::Email, "a@x.com");
        let d1 = id(EntityKind::Domain, "x.com");
        let p1 = id(EntityKind::Person, "Alice");
        let e2 = id(EntityKind::Email, "b@y.com");
        let d2 = id(EntityKind::Domain, "y.com");
        let p2 = id(EntityKind::Person, "Bob");
        let e3 = id(EntityKind::Email, "c@z.com");
        let d3 = id(EntityKind::Domain, "z.com");
        let p3 = id(EntityKind::Person, "Carol");
        let rels = [
            rel(&e1, &d1, RelationKind::BelongsToDomain),
            rel(&d1, &p1, RelationKind::RegisteredBy),
            rel(&e2, &d2, RelationKind::BelongsToDomain),
            rel(&d2, &p2, RelationKind::RegisteredBy),
            rel(&e3, &d3, RelationKind::BelongsToDomain),
            rel(&d3, &p3, RelationKind::RegisteredBy),
        ];
        let out = rule_au_064_generalized_pathway_template(
            &RuleContext::new(&[e1, d1, p1, e2, d2, p2, e3, d3, p3]),
            &rels,
            "s",
            0,
        );
        assert_eq!(
            out.len(),
            1,
            "one generalised template across the three pairs"
        );
        assert_eq!(out[0].rule_id, "AU-064");
        assert_eq!(out[0].severity, Severity::Medium);
        assert!(out[0].description.contains("3 distinct identity pairs"));
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
        assert!(
            rule_au_064_generalized_pathway_template(
                &RuleContext::new(&[e1, d1, p1]),
                &rels,
                "s",
                0
            )
            .is_empty()
        );
    }
}
