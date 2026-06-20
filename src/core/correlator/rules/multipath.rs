//! AU-062 — Multi-pathway identity corroboration.
//!
//! SpiderFoot stops at "A links to B". Huntsman asks *how many independent ways*
//! A reaches B — because a link you can re-derive down several orthogonal routes
//! is a link you can believe, and one you can rebuild when any single source goes
//! dark. This rule fires when two identity entities are joined by **two or more
//! edge-disjoint pathways** that span **≥2 distinct OSINT source families** (a
//! breach pool *and* a registry, say — not two echoes of one source). Graph
//! redundancy alone is not enough; the corroboration must be genuinely
//! orthogonal.
//!
//! Built on the shared [`crate::core::relation::disjoint_pathways`] graph
//! primitive, so it stays consistent with the transitive-closure rule and the
//! dossier's CONNECTIONS view (one finder, no drift).

use std::collections::{BTreeSet, HashMap};

use super::*;
use crate::core::relation::{disjoint_pathways, is_identity_kind};

/// One identity pair whose connection is corroborated by **≥2 edge-disjoint,
/// source-orthogonal pathways** — the shared core of the AU-062 rule and the
/// engine's `promote_multipath_corroborated` pass. Both read this one detector,
/// so the correlation finding and the confidence boost can never disagree on
/// what a corroborated link is (one finder, no drift).
#[derive(Debug, Clone)]
pub(in crate::core) struct MultipathLink {
    /// The two identity endpoints. The pair-scan visits each unordered pair once
    /// with the lexicographically-smaller UID first, so `a_uid < b_uid` always.
    pub a_uid: String,
    pub b_uid: String,
    /// Number of independent (edge-disjoint) routes joining the endpoints — the
    /// corroboration multiplicity. Always `>= 2`.
    pub pathways: usize,
    /// The distinct, orthogonal source families those routes span, sorted. The
    /// unclassified `"other"` family is excluded, and this is always `>= 2`.
    pub families: Vec<&'static str>,
    /// Every node on every route — endpoints and intermediates — sorted; the
    /// correlation's `entity_uids` and the boost's promotion set are drawn from
    /// here (the boost lifts only the two identity endpoints).
    pub nodes: Vec<String>,
}

/// Find every identity pair joined by **two or more edge-disjoint pathways**
/// that span **≥2 distinct OSINT source families** — the corroboration test at
/// the heart of multi-pathway linking. Graph redundancy alone is not enough: two
/// routes through the same source family (two breach echoes of one record) can
/// agree spuriously, so the corroboration must be genuinely *orthogonal*.
///
/// The shared finder behind both the AU-062 correlation and the engine's
/// multipath-corroboration boost, built on [`disjoint_pathways`] so it stays
/// consistent with the transitive-closure rule and the dossier's CONNECTIONS
/// view. The hop / path caps keep the pair-wise search bounded on a phone.
pub(in crate::core) fn multipath_corroborated_links(
    entities: &[Entity],
    relations: &[Relation],
) -> Vec<MultipathLink> {
    const MAX_HOPS: usize = 5;
    const MAX_PATHS: usize = 4;

    let by_uid: HashMap<&str, &Entity> = entities.iter().map(|e| (e.uid.as_str(), e)).collect();
    let mut identity_uids: Vec<&str> = entities
        .iter()
        .filter(|e| is_identity_kind(&e.kind))
        .map(|e| e.uid.as_str())
        .collect();
    identity_uids.sort_unstable();
    identity_uids.dedup();

    // Source families resting under one entity (its evidence providers), the
    // measure of orthogonality between routes.
    let families_of = |uid: &str| -> BTreeSet<&'static str> {
        by_uid
            .get(uid)
            .map(|e| {
                e.evidence_sources()
                    .into_iter()
                    .map(source_family)
                    .collect()
            })
            .unwrap_or_default()
    };

    let mut out = Vec::new();
    for (i, &a) in identity_uids.iter().enumerate() {
        for &b in &identity_uids[i + 1..] {
            let pathways = disjoint_pathways(entities, relations, a, b, MAX_HOPS, MAX_PATHS);
            if pathways.len() < 2 {
                continue; // a single route is not multi-pathway corroboration
            }

            // Orthogonality: distinct source families across every node on every
            // route (endpoints included), excluding the unclassified "other".
            let mut families: BTreeSet<&'static str> = families_of(a);
            let mut nodes: BTreeSet<String> = [a.to_string(), b.to_string()].into_iter().collect();
            for path in &pathways {
                for step in path {
                    families.extend(families_of(&step.to_uid));
                    nodes.insert(step.to_uid.clone());
                }
            }
            families.remove("other");
            if families.len() < 2 {
                continue; // graph-redundant but not source-orthogonal
            }

            out.push(MultipathLink {
                a_uid: a.to_string(),
                b_uid: b.to_string(),
                pathways: pathways.len(),
                families: families.into_iter().collect(),
                nodes: nodes.into_iter().collect(),
            });
        }
    }

    out
}

/// AU-062 — Multi-pathway identity corroboration.
///
/// Confidence rises with both the number of independent pathways and the number
/// of distinct source families they cross. Delegates the detection to
/// [`multipath_corroborated_links`] — the same finder the engine's promotion
/// pass uses — and formats each corroborated pair as a [`Correlation`].
pub(in crate::core::correlator) fn rule_au_062_multipath_corroboration(
    entities: &[Entity],
    relations: &[Relation],
    scan_id: &str,
    now: u64,
) -> Vec<Correlation> {
    let by_uid: HashMap<&str, &Entity> = entities.iter().map(|e| (e.uid.as_str(), e)).collect();

    let mut out = Vec::new();
    for link in multipath_corroborated_links(entities, relations) {
        let n = link.pathways;
        let severity = if n >= 3 || link.families.len() >= 3 {
            Severity::High
        } else {
            Severity::Medium
        };
        let (ea, eb) = (by_uid[link.a_uid.as_str()], by_uid[link.b_uid.as_str()]);

        out.push(Correlation::new(
            "AU-062",
            "Multi-pathway identity corroboration",
            severity,
            format!(
                "{} ({}) and {} ({}) are linked by {} independent pathway{} spanning {} \
                 orthogonal source famil{} [{}] — the connection is corroborated across \
                 multiple routes, not a single chain",
                ea.value,
                ea.kind,
                eb.value,
                eb.kind,
                n,
                if n == 1 { "" } else { "s" },
                link.families.len(),
                if link.families.len() == 1 { "y" } else { "ies" },
                link.families.join(", "),
            ),
            link.nodes,
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

    /// An entity whose evidence rests on a specific source (so it carries a real
    /// `source_family` for the orthogonality measure).
    fn sourced(kind: EntityKind, value: &str, source: &str) -> Entity {
        let mut e = Entity::new(kind, value, 0.8, "s");
        e.add_evidence(Evidence::new(source, "ev"));
        e
    }

    fn rel(from: &Entity, to: &Entity, kind: RelationKind) -> Relation {
        Relation::new(from.uid.clone(), to.uid.clone(), kind, 0.8, "s")
    }

    #[test]
    fn au062_fires_on_two_orthogonal_pathways() {
        let a = id(EntityKind::Email, "a@x.com");
        let b = id(EntityKind::Username, "bob");
        // Two edge-disjoint routes through NON-identity intermediates of DIFFERENT
        // source families — so the only identity pair is (a, b).
        let d = sourced(EntityKind::Domain, "x.com", "dns_intel"); // infra
        let o = sourced(EntityKind::Organisation, "Acme Pty", "opencorporates"); // identity_registry
        let rels = [
            rel(&a, &d, RelationKind::BelongsToDomain),
            rel(&d, &b, RelationKind::DerivedFrom),
            rel(&a, &o, RelationKind::RegisteredBy),
            rel(&o, &b, RelationKind::DerivedFrom),
        ];
        let ents = [a.clone(), b.clone(), d, o];
        let out = rule_au_062_multipath_corroboration(&ents, &rels, "s", 0);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].rule_id, "AU-062");
        assert!(out[0].entity_uids.contains(&a.uid));
        assert!(out[0].entity_uids.contains(&b.uid));
    }

    #[test]
    fn au062_silent_on_a_single_pathway() {
        let a = id(EntityKind::Email, "a@x.com");
        let b = id(EntityKind::Username, "bob");
        let d = sourced(EntityKind::Domain, "x.com", "dns_intel");
        let rels = [
            rel(&a, &d, RelationKind::BelongsToDomain),
            rel(&d, &b, RelationKind::DerivedFrom),
        ];
        assert!(rule_au_062_multipath_corroboration(&[a, b, d], &rels, "s", 0).is_empty());
    }

    #[test]
    fn au062_silent_when_routes_share_one_source_family() {
        // Two edge-disjoint routes, but both intermediates are the same family
        // (infra) — graph redundancy without genuine source orthogonality.
        let a = id(EntityKind::Email, "a@x.com");
        let b = id(EntityKind::Username, "bob");
        let d1 = sourced(EntityKind::Domain, "x.com", "dns_intel"); // infra
        let d2 = sourced(EntityKind::IpAddress, "1.2.3.4", "shodan"); // infra
        let rels = [
            rel(&a, &d1, RelationKind::BelongsToDomain),
            rel(&d1, &b, RelationKind::DerivedFrom),
            rel(&a, &d2, RelationKind::ResolvesTo),
            rel(&d2, &b, RelationKind::DerivedFrom),
        ];
        assert!(rule_au_062_multipath_corroboration(&[a, b, d1, d2], &rels, "s", 0).is_empty());
    }
}
