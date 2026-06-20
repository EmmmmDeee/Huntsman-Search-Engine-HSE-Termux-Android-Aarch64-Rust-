//! AU-063 — Single-pathway corroboration gap (the gap-analysis lead).
//!
//! The dual of multi-pathway corroboration: where that rule rewards a link
//! confirmed by independent routes, this one flags a link that rests on a
//! *single* route and spells out the **logical requirement** that would
//! corroborate it from another pathway — which orthogonal OSINT source family is
//! missing. It is the engine reasoning backwards from a found-but-fragile
//! connection to *what would make it solid*, so the operator (and, later, the
//! recursive expansion) knows exactly which angle to pursue.
//!
//! Fires only for *transitive* single routes (≥2 hops): a direct one-hop link is
//! already solid and needs no corroboration. Built on the shared
//! [`crate::core::relation::disjoint_pathways`] primitive, so its notion of "one
//! route" is exactly the multi-pathway rule's.

use std::collections::{BTreeSet, HashMap};

use super::*;
use crate::core::relation::{PathStep, disjoint_pathways, identity_uids};

/// Orthogonal source families worth seeking to lift a single-route link to
/// multi-pathway corroboration, ordered by how decisive each is for identity
/// attribution. `infra` is deliberately excluded — it is usually the *existing*
/// route (shared hosting/DNS), so suggesting it would rarely be orthogonal.
const CORROBORATING_FAMILIES: &[&str] = &[
    "breach",
    "social",
    "presence",
    "identity_registry",
    "code",
    "forum",
    "email_intel",
];

/// One identity pair joined by exactly ONE transitive route (≥2 hops) — a
/// fragile, single-pathway link no independent route corroborates. The shared
/// core of the AU-063 gap lead and the engine's cross-scan gap resolution, so
/// "one route" means the same thing to the rule that *flags* the gap and the
/// engine logic that *fills* it (one finder, no drift).
#[derive(Debug, Clone)]
pub(in crate::core) struct SingleRouteLink {
    /// The identity endpoints, `a_uid < b_uid` (the pair-scan visits each
    /// unordered pair once, lexicographically-smaller UID first).
    pub a_uid: String,
    pub b_uid: String,
    /// The single transitive pathway joining them (`route.len() >= 2`).
    pub route: Vec<PathStep>,
}

/// Find every identity pair connected by exactly one transitive route (≥2 hops)
/// — a link that no independent pathway corroborates. A direct one-hop link is
/// already solid and is excluded. Built on the shared [`disjoint_pathways`]
/// primitive, so its notion of "one route" is exactly the multi-pathway rule's;
/// the hop / path caps keep the pair-wise search bounded on a phone.
pub(in crate::core) fn single_route_identity_links(
    entities: &[Entity],
    relations: &[Relation],
) -> Vec<SingleRouteLink> {
    const MAX_HOPS: usize = 5;
    const MAX_PATHS: usize = 4;

    let identity_uids = identity_uids(entities);

    let mut out = Vec::new();
    for (i, &a) in identity_uids.iter().enumerate() {
        for &b in &identity_uids[i + 1..] {
            let mut pathways = disjoint_pathways(entities, relations, a, b, MAX_HOPS, MAX_PATHS);
            // Connected by exactly ONE route, and it is a transitive chain (≥2
            // hops): a direct one-hop link is already solid.
            if pathways.len() != 1 || pathways[0].len() < 2 {
                continue;
            }
            out.push(SingleRouteLink {
                a_uid: a.to_string(),
                b_uid: b.to_string(),
                route: pathways.pop().expect("exactly one pathway"),
            });
        }
    }
    out
}

/// AU-063 — Single-pathway corroboration gap. Delegates the detection to
/// [`single_route_identity_links`] — the same finder the engine's cross-scan
/// gap resolution uses — and, for each fragile link, names the strongest
/// orthogonal source families absent from its single route: the logical
/// requirement that would corroborate the connection from another pathway.
pub(in crate::core::correlator) fn rule_au_063_corroboration_gap(
    entities: &[Entity],
    relations: &[Relation],
    scan_id: &str,
    now: u64,
) -> Vec<Correlation> {
    let by_uid: HashMap<&str, &Entity> = entities.iter().map(|e| (e.uid.as_str(), e)).collect();

    let families_of = |uid: &str| -> BTreeSet<&'static str> {
        by_uid
            .get(uid)
            .map(|&e| source_families(e))
            .unwrap_or_default()
    };

    let mut out = Vec::new();
    for link in single_route_identity_links(entities, relations) {
        let (a, b) = (link.a_uid.as_str(), link.b_uid.as_str());

        // Families already represented on the single link.
        let mut present: BTreeSet<&'static str> = families_of(a);
        present.extend(families_of(b));
        let mut nodes: BTreeSet<String> = [a.to_string(), b.to_string()].into_iter().collect();
        for step in &link.route {
            present.extend(families_of(&step.to_uid));
            nodes.insert(step.to_uid.clone());
        }
        present.remove("other");

        // The fill: the strongest orthogonal families NOT yet on the link — the
        // logical requirement that would corroborate it independently.
        let absent: Vec<&str> = CORROBORATING_FAMILIES
            .iter()
            .copied()
            .filter(|f| !present.contains(f))
            .take(2)
            .collect();
        if absent.is_empty() {
            continue; // already broad — no obvious orthogonal angle to seek
        }

        let (ea, eb) = (by_uid[a], by_uid[b]);
        let present_list = if present.is_empty() {
            "infra".to_string()
        } else {
            present.iter().copied().collect::<Vec<_>>().join(", ")
        };
        let hops = link.route.len();
        let mut entity_uids: Vec<String> = nodes.into_iter().collect();
        entity_uids.sort_unstable();

        out.push(Correlation::new(
            "AU-063",
            "Single-pathway corroboration gap",
            Severity::Low,
            format!(
                "{} ({}) and {} ({}) are linked by a single {}-hop pathway resting on [{}]; \
                 no independent route corroborates it — a pathway through an orthogonal \
                 source ({}) would confirm the connection",
                ea.value,
                ea.kind,
                eb.value,
                eb.kind,
                hops,
                present_list,
                absent.join(" or "),
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
    use crate::core::entity::Evidence;
    use crate::core::relation::{Relation, RelationKind};

    fn id(kind: EntityKind, value: &str) -> Entity {
        Entity::new(kind, value, 0.8, "s")
    }

    fn sourced(kind: EntityKind, value: &str, source: &str) -> Entity {
        let mut e = Entity::new(kind, value, 0.8, "s");
        e.add_evidence(Evidence::new(source, "ev"));
        e
    }

    fn rel(from: &Entity, to: &Entity, kind: RelationKind) -> Relation {
        Relation::new(from.uid.clone(), to.uid.clone(), kind, 0.8, "s")
    }

    #[test]
    fn au063_flags_a_lone_transitive_link_and_names_the_gap() {
        // a—domain(infra)—b: one transitive route, resting only on infra.
        let a = id(EntityKind::Email, "a@x.com");
        let b = id(EntityKind::Username, "bob");
        let d = sourced(EntityKind::Domain, "x.com", "dns_intel"); // infra
        let rels = [
            rel(&a, &d, RelationKind::BelongsToDomain),
            rel(&d, &b, RelationKind::DerivedFrom),
        ];
        let out = rule_au_063_corroboration_gap(&[a.clone(), b.clone(), d], &rels, "s", 0);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].rule_id, "AU-063");
        assert_eq!(out[0].severity, Severity::Low);
        // Names an orthogonal family to seek (breach leads the priority list).
        assert!(out[0].description.contains("breach"));
        assert!(out[0].entity_uids.contains(&a.uid));
    }

    #[test]
    fn au063_silent_when_two_routes_already_corroborate() {
        // Two independent routes → AU-062's job, not a gap.
        let a = id(EntityKind::Email, "a@x.com");
        let b = id(EntityKind::Username, "bob");
        let d = sourced(EntityKind::Domain, "x.com", "dns_intel");
        let o = sourced(EntityKind::Organisation, "Acme", "opencorporates");
        let rels = [
            rel(&a, &d, RelationKind::BelongsToDomain),
            rel(&d, &b, RelationKind::DerivedFrom),
            rel(&a, &o, RelationKind::RegisteredBy),
            rel(&o, &b, RelationKind::DerivedFrom),
        ];
        assert!(rule_au_063_corroboration_gap(&[a, b, d, o], &rels, "s", 0).is_empty());
    }

    #[test]
    fn au063_silent_on_a_direct_one_hop_link() {
        // A direct edge needs no corroboration.
        let a = id(EntityKind::Email, "a@x.com");
        let b = id(EntityKind::Username, "bob");
        let rels = [rel(&a, &b, RelationKind::AliasOf)];
        assert!(rule_au_063_corroboration_gap(&[a, b], &rels, "s", 0).is_empty());
    }
}
