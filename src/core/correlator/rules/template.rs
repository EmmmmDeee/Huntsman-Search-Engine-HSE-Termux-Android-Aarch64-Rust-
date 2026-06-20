//! AU-064 — Generalized pathway template (a reusable attribution route).
//!
//! Backward synthesis: take the connections a scan *confirmed* and reason back to
//! the general *means* that produced them. When the same abstract pathway — the
//! ordered sequence of entity kinds and the relation kinds joining them — links
//! two or more distinct identity pairs, that route has proven itself repeatable.
//! It is no longer a one-off chain but a **template**: a confirmed way to connect
//! *that class* of identity to *that class* of identity, which the operator can
//! re-apply, and which (persisted across scans) lets every future scan arrive at
//! the same class of connection by a route already known to work.
//!
//! Built on the shared [`crate::core::relation::identity_paths`] primitive, so
//! the routes it generalises are exactly the ones the dossier renders and the
//! transitive/multi-pathway rules fire on. The template is direction-canonical
//! (a route and its reverse are one template), so `Email→…→Person` and
//! `Person→…→Email` group together regardless of which endpoint hashed smaller.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use super::*;
use crate::core::relation::identity_paths;

/// The canonical string form of a pathway: the interleaved node-kind / relation
/// sequence, oriented to the lexicographically-smaller of the route and its
/// reverse so a connection and its mirror are one template.
fn canonical_template(node_kinds: &[String], rel_strs: &[&str]) -> String {
    debug_assert_eq!(node_kinds.len(), rel_strs.len() + 1);
    let render = |fwd: bool| -> String {
        let n = node_kinds.len();
        let mut s = String::new();
        for i in 0..n {
            let k = if fwd {
                &node_kinds[i]
            } else {
                &node_kinds[n - 1 - i]
            };
            s.push_str(k);
            if i < rel_strs.len() {
                let r = if fwd {
                    rel_strs[i]
                } else {
                    rel_strs[rel_strs.len() - 1 - i]
                };
                s.push_str(" →");
                s.push_str(r);
                s.push_str("→ ");
            }
        }
        s
    };
    let forward = render(true);
    let reverse = render(false);
    forward.min(reverse)
}

/// AU-064 — Generalized pathway template.
pub(in crate::core::correlator) fn rule_au_064_generalized_pathway_template(
    entities: &[Entity],
    relations: &[Relation],
    scan_id: &str,
    now: u64,
) -> Vec<Correlation> {
    const MAX_HOPS: usize = 4;

    let by_uid: HashMap<&str, &Entity> = entities.iter().map(|e| (e.uid.as_str(), e)).collect();
    let kind_of = |uid: &str| -> String {
        by_uid
            .get(uid)
            .map_or_else(|| "?".to_string(), |e| e.kind.to_string())
    };

    // Group identity connections by their direction-canonical template. The
    // pair list per template is the evidence that the route repeats.
    let mut by_template: BTreeMap<String, Vec<(String, String)>> = BTreeMap::new();
    for path in identity_paths(entities, relations, MAX_HOPS) {
        if path.hops < 2 {
            continue; // a direct one-hop link is not a multi-step route to generalise
        }
        let mut node_kinds: Vec<String> = Vec::with_capacity(path.hops + 1);
        node_kinds.push(kind_of(&path.from_uid));
        let mut rel_strs: Vec<&str> = Vec::with_capacity(path.hops);
        for step in &path.steps {
            rel_strs.push(step.kind.as_str());
            node_kinds.push(kind_of(&step.to_uid));
        }
        let template = canonical_template(&node_kinds, &rel_strs);
        by_template
            .entry(template)
            .or_default()
            .push((path.from_uid.clone(), path.to_uid.clone()));
    }

    let mut out = Vec::new();
    for (template, pairs) in by_template {
        if pairs.len() < 2 {
            continue; // a single instance is not yet a generalised pattern
        }
        let mut uids: BTreeSet<String> = BTreeSet::new();
        for (f, t) in &pairs {
            uids.insert(f.clone());
            uids.insert(t.clone());
        }
        let n = pairs.len();
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
                "the route [{template}] linked {n} distinct identity pairs this scan — a \
                 reusable attribution pattern, not a one-off chain; the same template is a \
                 confirmed means to connect that class of identity again",
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

    #[test]
    fn canonical_template_is_direction_invariant() {
        // The route and its mirror canonicalise to one string.
        let fwd = canonical_template(
            &["email".into(), "domain".into(), "person".into()],
            &["belongs_to_domain", "registered_by"],
        );
        let rev = canonical_template(
            &["person".into(), "domain".into(), "email".into()],
            &["registered_by", "belongs_to_domain"],
        );
        assert_eq!(fwd, rev);
    }
}
