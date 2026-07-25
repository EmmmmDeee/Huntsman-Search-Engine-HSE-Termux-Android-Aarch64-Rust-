//! AU-060 — Transitive identity closure.
//!
//! Finds pairs of identity entities (Person, Username, Email, Phone) that are
//! linked through 2–4 relation-graph hops but have no direct single-edge
//! connection. These multi-hop chains surface the "identity thread" hidden in
//! the attribution graph — e.g. an email linked to a domain via BelongsToDomain,
//! the domain to a registrant Person via RegisteredBy, the person to a second
//! username via DerivedFrom — four nodes, three hops, one hidden identity link.
//!
//! The shortest-path search itself is the canonical
//! [`crate::core::relation::identity_paths`] primitive — the *same* finder the
//! dossier's CONNECTIONS section renders, so the rule's verdict and the chain
//! shown to the operator can never drift (Rule 4: delegate, never copy). This
//! rule keeps only the *transitive* cases (≥2 hops); a 1-hop direct link is
//! another rule's job.
//!
//! Severity decays with path length: Medium at 2–3 hops (a tight chain with
//! few intermediate nodes), Low at 4 hops (longer, noisier path). Every node
//! on the shortest path is included in the correlation's `entity_uids` so the
//! SPA Correlations view can render the chain.

use std::collections::HashMap;

use super::*;
use crate::core::relation::identity_paths;

/// AU-060 — Transitive identity closure.
///
/// Delegates the shortest-path search to [`identity_paths`], then emits one
/// correlation per identity pair connected through 2–4 hops (a 1-hop direct
/// link is filtered — it is covered by the direct-edge rules). Pair
/// deduplication and deterministic ordering come from the primitive.
pub(in crate::core::correlator) fn rule_au_060_transitive_identity_closure(
    context: &RuleContext,
    relations: &[Relation],
    scan_id: &str,
    now: u64,
) -> Vec<Correlation> {
    let entities = context.entities();
    const MAX_HOPS: usize = 4;
    // Weakest-link confidence floor, mirroring AU-067's `MIN_CONF`. A transitive
    // chain is only as trustworthy as its weakest edge, so a path that routes
    // through a DELIBERATELY-DAMPED lead-grade edge — a bare surname `derive_kinship`
    // link (`min(conf) * 0.5`), a co-mention/affiliation lead — must not surface as
    // an ASSERTED identity link. Without this floor AU-060 ignored the damps the
    // relation builders apply, cross-linking same-surname strangers through a kin
    // hop. `identity_paths` already computes the minimum edge confidence along each
    // path (`IdentityPath::min_confidence`, the same field AU-067 floors on), so the
    // check is a single comparison — no per-edge lookup, no drift from the primitive.
    const MIN_CONF: f64 = 0.50;

    let by_uid: HashMap<&str, &Entity> = entities.iter().map(|e| (e.uid.as_str(), e)).collect();

    let mut out = Vec::new();
    for path in identity_paths(entities, relations, MAX_HOPS) {
        // Transitive only: a 1-hop direct edge is covered by the direct-link rules.
        if path.hops < 2 {
            continue;
        }
        // A chain is only as strong as its weakest edge (see `MIN_CONF` above).
        if path.min_confidence < MIN_CONF {
            continue;
        }
        let (Some(src_e), Some(dst_e)) = (
            by_uid.get(path.from_uid.as_str()),
            by_uid.get(path.to_uid.as_str()),
        ) else {
            continue;
        };

        // Every node on the path (both endpoints + each intermediate), sorted so
        // the correlation's entity set is order-stable.
        let mut entity_uids: Vec<String> = Vec::with_capacity(path.hops + 1);
        entity_uids.push(path.from_uid.clone());
        entity_uids.extend(path.steps.iter().map(|s| s.to_uid.clone()));
        entity_uids.sort_unstable();
        entity_uids.dedup();

        let intermediates = path.hops - 1;
        let severity = if path.hops <= 3 {
            Severity::Medium
        } else {
            Severity::Low
        };

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
                path.hops,
            ),
            entity_uids,
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

    fn rel(from: &Entity, to: &Entity, kind: RelationKind) -> Relation {
        Relation::new(from.uid.clone(), to.uid.clone(), kind, 0.8, "s")
    }

    fn rel_conf(from: &Entity, to: &Entity, kind: RelationKind, conf: f64) -> Relation {
        Relation::new(from.uid.clone(), to.uid.clone(), kind, conf, "s")
    }

    #[test]
    fn au060_suppresses_chain_through_a_damped_lead_edge() {
        // email → person (strong 0.8) → person2 via a DAMPED kinship edge (0.40,
        // what `derive_kinship` emits for a 0.8 surname pair: 0.8 * 0.5). The 2-hop
        // path email→person2 has weakest-link confidence 0.40 < 0.50, so AU-060 must
        // NOT assert the stranger person2 as a transitively-linked identity.
        let email = mk(EntityKind::Email, "alice@example.com");
        let person = mk(EntityKind::Person, "Alice Smith");
        let person2 = mk(EntityKind::Person, "Bob Smith");
        let rels = [
            rel(&email, &person, RelationKind::DerivedFrom),
            rel_conf(&person, &person2, RelationKind::AssociatedWith, 0.40),
        ];
        let entities = [email, person, person2];
        assert!(
            rule_au_060_transitive_identity_closure(&RuleContext::new(&entities), &rels, "s", 0)
                .is_empty(),
            "a chain through a sub-0.50 damped edge must be suppressed"
        );
    }

    #[test]
    fn au060_still_fires_when_every_edge_clears_the_floor() {
        // The same shape but the second edge is a strong 0.6 link (≥ 0.50): the
        // transitive pair is legitimate and still fires — the floor gates only the
        // damped leads, not honest mid-confidence structural edges.
        let email = mk(EntityKind::Email, "alice@example.com");
        let person = mk(EntityKind::Person, "Alice Smith");
        let username = mk(EntityKind::Username, "asmith");
        let rels = [
            rel(&email, &person, RelationKind::DerivedFrom),
            rel_conf(&person, &username, RelationKind::AssociatedWith, 0.60),
        ];
        let entities = [email, person, username];
        let r =
            rule_au_060_transitive_identity_closure(&RuleContext::new(&entities), &rels, "s", 0);
        assert_eq!(
            r.len(),
            1,
            "a chain whose weakest edge is ≥ 0.50 still fires"
        );
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
            &RuleContext::new(&[email.clone(), domain.clone(), person.clone()]),
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
        let r =
            rule_au_060_transitive_identity_closure(&RuleContext::new(&entities), &rels, "s", 0);
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
            rule_au_060_transitive_identity_closure(
                &RuleContext::new(&[email, person]),
                &rels,
                "s",
                0
            )
            .is_empty()
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
            rule_au_060_transitive_identity_closure(
                &RuleContext::new(&[email, domain, person]),
                &rels,
                "s",
                0
            )
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
            rule_au_060_transitive_identity_closure(
                &RuleContext::new(&[email, domain]),
                &rels,
                "s",
                0
            )
            .is_empty()
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
        let r =
            rule_au_060_transitive_identity_closure(&RuleContext::new(&entities), &rels, "s", 0);
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
        assert!(
            rule_au_060_transitive_identity_closure(
                &RuleContext::new(&[email, person]),
                &[],
                "s",
                0
            )
            .is_empty()
        );
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
            rule_au_060_transitive_identity_closure(
                &RuleContext::new(&[email, person]),
                &[r1, r2],
                "s",
                0
            )
            .is_empty()
        );
    }
}
