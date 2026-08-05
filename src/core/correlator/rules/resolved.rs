//! AU-067 — Resolved identity cluster (transitive equivalence class).
//!
//! Where AU-060 reports a single transitive link ("A is connected to B"), this
//! rule reports the whole **resolved identity**: the connected component of the
//! identity-link graph — every Person / Email / Username / Phone that collapses,
//! through forward and backward transitive closure, into one identity. It is the
//! cluster-level synthesis the recursive linker builds toward: many orthogonal
//! pairwise links joined into a single "these are all one identity" conclusion.
//!
//! Built on the shared [`crate::core::relation::resolve_identity_clusters`]
//! union-find primitive (over the same `identity_paths` link set AU-060 and the
//! dossier render), so a cluster can never disagree with the pairwise links —
//! one finder, no drift. Fires only for clusters of ≥3 identities (a 2-member
//! cluster is a single pair, already AU-060's job) whose weakest binding link
//! clears a confidence floor, so a resolved identity rests on trustworthy links.

use std::collections::{BTreeMap, HashMap};

use super::*;
use crate::core::relation::resolve_identity_clusters;

/// AU-067 — Resolved identity cluster.
///
/// Delegates the equivalence-class resolution to
/// [`resolve_identity_clusters`], then emits one correlation per resolved
/// identity of ≥3 members whose weakest binding link clears the floor. Severity
/// rises with cluster size (a larger resolved identity is a stronger finding).
pub(in crate::core::correlator) fn rule_au_067_resolved_identity_cluster(
    context: &RuleContext,
    relations: &[Relation],
    scan_id: &str,
    now: u64,
) -> Vec<Correlation> {
    let entities = context.entities();
    const MAX_HOPS: usize = 4;
    const MIN_MEMBERS: usize = 3;
    const MIN_CONF: f64 = crate::core::relation::IDENTITY_LINK_MIN_CONF;

    let by_uid: HashMap<&str, &Entity> = entities.iter().map(|e| (e.uid.as_str(), e)).collect();

    let mut out = Vec::new();
    for cluster in resolve_identity_clusters(entities, relations, MAX_HOPS, MIN_CONF) {
        // The weakest-link floor is now applied *at resolution* (passed above), so
        // every cluster already clears MIN_CONF and rests on trustworthy links — a
        // weak bridge can no longer fuse strangers into one identity. Only the size
        // gate remains: a 2-member cluster is one pair (AU-060's job); a resolved
        // identity is a genuine ≥3-way collapse.
        if cluster.members.len() < MIN_MEMBERS {
            continue;
        }

        // Tally member kinds for a human description (deterministic by kind name).
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
        let severity = if n >= 4 {
            Severity::High
        } else {
            Severity::Medium
        };

        out.push(Correlation::new(
            "AU-067",
            "Resolved identity cluster",
            severity,
            format!(
                "{n} identities resolve to one (weakest-link confidence {:.2}): {breakdown} — \
                 joined into a single identity by transitive closure across orthogonal links",
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

    fn rel(from: &Entity, to: &Entity, kind: RelationKind, conf: f64) -> Relation {
        Relation::new(from.uid.clone(), to.uid.clone(), kind, conf, "s")
    }

    #[test]
    fn au067_resolves_three_identities_into_one_cluster() {
        // email, username, person all hang off one domain (a non-identity hub),
        // so the three identities form a single transitive equivalence class.
        let email = mk(EntityKind::Email, "a@x.com");
        let domain = mk(EntityKind::Domain, "x.com");
        let person = mk(EntityKind::Person, "Alice");
        let uname = mk(EntityKind::Username, "alice");
        let rels = [
            rel(&email, &domain, RelationKind::BelongsToDomain, 0.8),
            rel(&domain, &person, RelationKind::RegisteredBy, 0.8),
            rel(&domain, &uname, RelationKind::DerivedFrom, 0.8),
        ];
        let ents = [email.clone(), domain.clone(), person.clone(), uname.clone()];

        let out = rule_au_067_resolved_identity_cluster(&RuleContext::new(&ents), &rels, "s", 0);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].rule_id, "AU-067");
        // All three identities are members; the conduit domain is not.
        for id in [&email.uid, &person.uid, &uname.uid] {
            assert!(out[0].entity_uids.contains(id), "identity must be a member");
        }
        assert!(
            !out[0].entity_uids.contains(&domain.uid),
            "a conduit hub is not part of the resolved identity"
        );
    }

    #[test]
    fn au067_silent_on_a_single_pair() {
        // Only two identities (email, person) — a pair is AU-060's job, not a cluster.
        let email = mk(EntityKind::Email, "a@x.com");
        let domain = mk(EntityKind::Domain, "x.com");
        let person = mk(EntityKind::Person, "Alice");
        let rels = [
            rel(&email, &domain, RelationKind::BelongsToDomain, 0.8),
            rel(&domain, &person, RelationKind::RegisteredBy, 0.8),
        ];
        assert!(
            rule_au_067_resolved_identity_cluster(
                &RuleContext::new(&[email, domain, person]),
                &rels,
                "s",
                0
            )
            .is_empty()
        );
    }

    #[test]
    fn au067_silent_below_confidence_floor() {
        // Three identities, but every binding link is weak (< 0.50) — the resolved
        // identity rests on untrustworthy links, so nothing is emitted.
        let email = mk(EntityKind::Email, "a@x.com");
        let domain = mk(EntityKind::Domain, "x.com");
        let person = mk(EntityKind::Person, "Alice");
        let uname = mk(EntityKind::Username, "alice");
        let rels = [
            rel(&email, &domain, RelationKind::BelongsToDomain, 0.2),
            rel(&domain, &person, RelationKind::RegisteredBy, 0.2),
            rel(&domain, &uname, RelationKind::DerivedFrom, 0.2),
        ];
        assert!(
            rule_au_067_resolved_identity_cluster(
                &RuleContext::new(&[email, domain, person, uname]),
                &rels,
                "s",
                0
            )
            .is_empty()
        );
    }
}
