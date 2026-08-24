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

use std::collections::BTreeSet;

use super::*;
use crate::core::relation::{
    IDENTITY_LINK_MIN_CONF, IDENTITY_PAIR_PROBE_CAP, disjoint_pathways_in, identity_uids,
    sorted_confined_adjacency,
};

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
/// multipath-corroboration boost, built on [`disjoint_pathways_in`] so it stays
/// consistent with the transitive-closure rule and the dossier's CONNECTIONS
/// view. The hop / path caps keep the per-pair search bounded, and the shared
/// [`IDENTITY_PAIR_PROBE_CAP`] bounds the pair COUNT so the `O(identities²)` sweep
/// can't dominate finalise (the identical bound AU-063's single-route sweep uses).
pub(in crate::core) fn multipath_corroborated_links(
    context: &RuleContext,
    relations: &[Relation],
) -> Vec<MultipathLink> {
    multipath_corroborated_links_capped(context, relations, IDENTITY_PAIR_PROBE_CAP)
}

/// [`multipath_corroborated_links`] with an explicit pair-probe ceiling — the
/// public entry pins it to [`IDENTITY_PAIR_PROBE_CAP`]; the parameter exists so the
/// cap is unit-testable without a 6 000-entity fixture.
fn multipath_corroborated_links_capped(
    context: &RuleContext,
    relations: &[Relation],
    max_pair_probes: usize,
) -> Vec<MultipathLink> {
    const MAX_HOPS: usize = 5;
    const MAX_PATHS: usize = 4;

    let entities = context.entities();
    let by_uid = context.by_uid();
    let identity_uids = identity_uids(entities);
    // Build the traversal graph ONCE and reuse it for every pair (vs rebuilding +
    // re-sorting it per `disjoint_pathways` call).
    let adj = sorted_confined_adjacency(entities, relations);

    // Source families resting under one entity (its evidence providers), the
    // measure of orthogonality between routes — the shared `source_families`
    // detector, so AU-062 and AU-063 agree on what an entity's families are.
    let families_of = |uid: &str| -> BTreeSet<&'static str> {
        by_uid
            .get(uid)
            .map(|&e| source_families(e))
            .unwrap_or_default()
    };

    let mut out = Vec::new();
    let mut probes = 0usize;
    'outer: for (i, &a) in identity_uids.iter().enumerate() {
        for &b in &identity_uids[i + 1..] {
            if probes >= max_pair_probes {
                // Deterministic bound reached — see `IDENTITY_PAIR_PROBE_CAP`.
                break 'outer;
            }
            probes += 1;
            // IDENTITY_LINK_MIN_CONF excludes the exact class of damped,
            // low-confidence edge (e.g. a same-surname kinship guess) AU-060's
            // own weakest-link floor was added to keep out of transitive
            // closure — without it here, "multi-pathway corroboration" could
            // be built entirely from routes AU-060 itself would refuse.
            let pathways =
                disjoint_pathways_in(&adj, a, b, MAX_HOPS, MAX_PATHS, IDENTITY_LINK_MIN_CONF);
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
    context: &RuleContext,
    relations: &[Relation],
    scan_id: &str,
    now: u64,
) -> Vec<Correlation> {
    let by_uid = context.by_uid();

    let mut out = Vec::new();
    for link in multipath_corroborated_links(context, relations) {
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

    fn rel_conf(from: &Entity, to: &Entity, kind: RelationKind, conf: f64) -> Relation {
        Relation::new(from.uid.clone(), to.uid.clone(), kind, conf, "s")
    }

    #[test]
    fn au062_excludes_a_pathway_built_from_a_damped_kinship_edge() {
        // Two nominally edge-disjoint routes a→b: one via a strong (0.8) domain
        // link, one via a DAMPED (0.40) edge — the same magnitude
        // `derive_kinship` produces for a same-surname pair (`0.8 * 0.5`). Before
        // IDENTITY_LINK_MIN_CONF applied to disjoint_pathways_in, both routes
        // counted toward "≥2 independent pathways", so this pair could clear
        // AU-062's corroboration bar on the strength of a link AU-060 itself
        // refuses to trust (au060_suppresses_chain_through_a_damped_lead_edge,
        // transitive.rs). With the floor, the damped edge is excluded from the
        // adjacency before the search even starts, so only the genuine domain
        // route survives — one pathway, not enough for multi-pathway
        // corroboration.
        let a = id(EntityKind::Email, "a@x.com");
        let b = id(EntityKind::Username, "bob");
        let d = sourced(EntityKind::Domain, "x.com", "dns_intel");
        let o = sourced(EntityKind::Organisation, "Acme Pty", "opencorporates");
        let rels = [
            rel(&a, &d, RelationKind::BelongsToDomain),
            rel(&d, &b, RelationKind::DerivedFrom),
            rel_conf(&a, &o, RelationKind::RegisteredBy, 0.40),
            rel(&o, &b, RelationKind::DerivedFrom),
        ];
        let ents = [a, b, d, o];
        let context = RuleContext::new(&ents);
        assert!(
            rule_au_062_multipath_corroboration(&context, &rels, "s", 0).is_empty(),
            "a pair corroborated only via a sub-floor damped edge must not fire"
        );
    }

    #[test]
    fn au062_still_fires_when_the_second_pathway_clears_the_floor() {
        // The same shape, but the second route's edge is a legitimate mid
        // confidence (0.60, ≥ IDENTITY_LINK_MIN_CONF) rather than a damped lead —
        // the floor gates only sub-floor edges, not honest structural ones, so
        // this pair still corroborates across two genuinely independent,
        // orthogonal routes.
        let a = id(EntityKind::Email, "a@x.com");
        let b = id(EntityKind::Username, "bob");
        let d = sourced(EntityKind::Domain, "x.com", "dns_intel");
        let o = sourced(EntityKind::Organisation, "Acme Pty", "opencorporates");
        let rels = [
            rel(&a, &d, RelationKind::BelongsToDomain),
            rel(&d, &b, RelationKind::DerivedFrom),
            rel_conf(&a, &o, RelationKind::RegisteredBy, 0.60),
            rel(&o, &b, RelationKind::DerivedFrom),
        ];
        let ents = [a, b, d, o];
        let context = RuleContext::new(&ents);
        assert_eq!(
            rule_au_062_multipath_corroboration(&context, &rels, "s", 0).len(),
            1,
            "two routes whose edges both clear the floor must still corroborate"
        );
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
        let context = RuleContext::new(&ents);
        let out = rule_au_062_multipath_corroboration(&context, &rels, "s", 0);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].rule_id, "AU-062");
        assert!(out[0].entity_uids.contains(&a.uid));
        assert!(out[0].entity_uids.contains(&b.uid));
    }

    #[test]
    fn au062_escalates_to_high_on_three_pathways() {
        // Three edge-disjoint routes a→b through non-identity intermediates. Two
        // families (infra + identity_registry) is enough to EMIT; the THIRD
        // pathway is what escalates Medium→High via the first disjunct
        // (pathways >= 3). The two-pathway sibling above covers the base arm.
        let a = id(EntityKind::Email, "a@x.com");
        let b = id(EntityKind::Username, "bob");
        let d = sourced(EntityKind::Domain, "x.com", "dns_intel"); // infra
        let o = sourced(EntityKind::Organisation, "Acme Pty", "opencorporates"); // identity_registry
        let ip = sourced(EntityKind::IpAddress, "1.2.3.4", "shodan"); // infra
        let rels = [
            rel(&a, &d, RelationKind::BelongsToDomain),
            rel(&d, &b, RelationKind::DerivedFrom),
            rel(&a, &o, RelationKind::RegisteredBy),
            rel(&o, &b, RelationKind::DerivedFrom),
            rel(&a, &ip, RelationKind::ResolvesTo),
            rel(&ip, &b, RelationKind::DerivedFrom),
        ];
        let ents = [a.clone(), b.clone(), d, o, ip];
        let context = RuleContext::new(&ents);
        let out = rule_au_062_multipath_corroboration(&context, &rels, "s", 0);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].rule_id, "AU-062");
        assert_eq!(out[0].severity, Severity::High);
        assert!(out[0].entity_uids.contains(&a.uid));
        assert!(out[0].entity_uids.contains(&b.uid));
    }

    #[test]
    fn au062_escalates_to_high_on_three_source_families() {
        // Only TWO pathways, but THREE orthogonal families — the second disjunct
        // (families >= 3). The third family comes from sourcing an ENDPOINT: `a`
        // is breach-sourced, the two intermediates are infra and
        // identity_registry.
        let a = sourced(EntityKind::Email, "a@x.com", "hibp"); // breach
        let b = id(EntityKind::Username, "bob");
        let d = sourced(EntityKind::Domain, "x.com", "dns_intel"); // infra
        let o = sourced(EntityKind::Organisation, "Acme Pty", "opencorporates"); // identity_registry
        let rels = [
            rel(&a, &d, RelationKind::BelongsToDomain),
            rel(&d, &b, RelationKind::DerivedFrom),
            rel(&a, &o, RelationKind::RegisteredBy),
            rel(&o, &b, RelationKind::DerivedFrom),
        ];
        let ents = [a.clone(), b.clone(), d, o];
        let context = RuleContext::new(&ents);
        let out = rule_au_062_multipath_corroboration(&context, &rels, "s", 0);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].rule_id, "AU-062");
        assert_eq!(out[0].severity, Severity::High);
    }

    #[test]
    fn multipath_links_are_pair_probe_capped_deterministically() {
        // Two independent components, each an identity pair joined by two orthogonal
        // routes → two multipath links. The O(n²) pair sweep must honour the cap,
        // and the bound must be a deterministic prefix of sorted `identity_uids`.
        let mk = |n: usize| {
            let a = id(EntityKind::Email, &format!("a{n}@x.com"));
            let b = id(EntityKind::Username, &format!("bob{n}"));
            let d = sourced(EntityKind::Domain, &format!("x{n}.com"), "dns_intel");
            let o = sourced(
                EntityKind::Organisation,
                &format!("Acme{n}"),
                "opencorporates",
            );
            let rels = vec![
                rel(&a, &d, RelationKind::BelongsToDomain),
                rel(&d, &b, RelationKind::DerivedFrom),
                rel(&a, &o, RelationKind::RegisteredBy),
                rel(&o, &b, RelationKind::DerivedFrom),
            ];
            (vec![a, b, d, o], rels)
        };
        let (mut ents, mut rels) = mk(1);
        let (e2, r2) = mk(2);
        ents.extend(e2);
        rels.extend(r2);

        let context = RuleContext::new(&ents);
        let full = multipath_corroborated_links_capped(&context, &rels, usize::MAX);
        assert_eq!(
            full.len(),
            2,
            "two independent components → two multipath links"
        );
        assert_eq!(
            multipath_corroborated_links(&context, &rels).len(),
            full.len(),
            "the public entry runs at the production cap; this fixture is under it"
        );
        // The cap bounds the pair sweep: 0 probes → nothing; 1 probe → ≤1 link.
        assert!(multipath_corroborated_links_capped(&RuleContext::new(&ents), &rels, 0).is_empty());
        assert!(multipath_corroborated_links_capped(&RuleContext::new(&ents), &rels, 1).len() <= 1);
        // Deterministic across runs.
        let a = multipath_corroborated_links_capped(&RuleContext::new(&ents), &rels, 3);
        let b = multipath_corroborated_links_capped(&RuleContext::new(&ents), &rels, 3);
        assert_eq!(
            a.iter().map(|l| (&l.a_uid, &l.b_uid)).collect::<Vec<_>>(),
            b.iter().map(|l| (&l.a_uid, &l.b_uid)).collect::<Vec<_>>(),
            "the capped prefix is deterministic across runs"
        );
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
        let ents = [a, b, d];
        let context = RuleContext::new(&ents);
        assert!(rule_au_062_multipath_corroboration(&context, &rels, "s", 0).is_empty());
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
        let ents = [a, b, d1, d2];
        let context = RuleContext::new(&ents);
        assert!(rule_au_062_multipath_corroboration(&context, &rels, "s", 0).is_empty());
    }

    #[test]
    fn au062_excludes_non_corroborating_source_families() {
        // The orthogonality measure must rest on INDEPENDENT families only. A route
        // whose intermediate is backed solely by a non-corroborating pass — either
        // `name_intel` (the seed's own permutation engine → identity_registry) or
        // `geo_normalize` (a deterministic geo-replay → infra) — is not a second
        // independent family. Each pair below has exactly ONE genuine family, so
        // AU-062 must stay silent. Before the fix `source_families` read
        // `evidence_sources`, counted these as a 2nd family, and fired — the AU-010
        // over-credit, on the graph-orthogonality side.

        // name_intel: genuine route = infra; derivation route = name_intel only.
        let a = id(EntityKind::Email, "a@x.com");
        let b = id(EntityKind::Username, "bob");
        let infra = sourced(EntityKind::Domain, "x.com", "dns_intel");
        let derived = sourced(EntityKind::Organisation, "Acme Pty", "name_intel");
        let rels = [
            rel(&a, &infra, RelationKind::BelongsToDomain),
            rel(&infra, &b, RelationKind::DerivedFrom),
            rel(&a, &derived, RelationKind::RegisteredBy),
            rel(&derived, &b, RelationKind::DerivedFrom),
        ];
        let ents = [a, b, infra, derived];
        let context = RuleContext::new(&ents);
        assert!(
            rule_au_062_multipath_corroboration(&context, &rels, "s", 0).is_empty(),
            "a name_intel-derived family is not independent orthogonal corroboration"
        );

        // geo_normalize: genuine route = identity_registry; replay route = geo_normalize only.
        let a = id(EntityKind::Email, "a@x.com");
        let b = id(EntityKind::Username, "bob");
        let org = sourced(EntityKind::Organisation, "Acme Pty", "opencorporates");
        let replay = sourced(EntityKind::Coordinates, "-27.0,153.0", "geo_normalize");
        let rels = [
            rel(&a, &org, RelationKind::RegisteredBy),
            rel(&org, &b, RelationKind::DerivedFrom),
            rel(&a, &replay, RelationKind::LocatedAt),
            rel(&replay, &b, RelationKind::DerivedFrom),
        ];
        let ents = [a, b, org, replay];
        let context = RuleContext::new(&ents);
        assert!(
            rule_au_062_multipath_corroboration(&context, &rels, "s", 0).is_empty(),
            "a geo_normalize-replay family is not independent orthogonal corroboration"
        );
    }
}
