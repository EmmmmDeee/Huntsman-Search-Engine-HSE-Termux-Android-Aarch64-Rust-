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

use std::collections::{BTreeMap, BTreeSet, HashMap};

use super::*;
use crate::core::relation::{
    IDENTITY_PAIR_PROBE_CAP, PathStep, disjoint_pathways_in, identity_uids,
    sorted_confined_adjacency,
};

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

/// A single-route link is surfaced as its own detailed AU-063 finding only when
/// its *weaker* endpoint is this confident — the gate tests the `min` of the two
/// endpoint confidences (the `Candidate::priority` set below), so *both* ends
/// must clear it. A link that leans on even one low-confidence, name-derived
/// permutation candidate (the bulk of a broad name scan) is not individually
/// actionable; it is consolidated into the summary finding instead. This is the
/// Probable-tier floor, so a link Probable at *both* ends earns its detail — a
/// confident hub tied to a speculative permutation does not.
const AU063_DETAIL_MIN_CONF: f64 = 0.40;

/// Cap on individually-surfaced AU-063 gap findings (strongest endpoints first).
/// Beyond this the gaps are consolidated, so a name seed that derives dozens of
/// permutation links can't drown the dossier in hundreds of near-identical Low
/// notices — the single biggest source of correlation noise observed in the
/// field (a `full_name` scan fired 400+ AU-063 rows, 80% of all correlations).
const AU063_DETAIL_CAP: usize = 25;

/// Cap on the contributing entity uids attached to the consolidated summary
/// finding — enough to pivot from, bounded so the row stays small.
const AU063_SUMMARY_UID_CAP: usize = 50;

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
/// already solid and is excluded. Built on the shared [`disjoint_pathways_in`]
/// primitive, so its notion of "one route" is exactly the multi-pathway rule's;
/// the hop / path caps keep the per-pair search bounded, and the shared
/// [`IDENTITY_PAIR_PROBE_CAP`] bounds the pair COUNT so the `O(identities²)` sweep
/// can't dominate finalise (the identical bound AU-062's multipath sweep uses).
pub(in crate::core) fn single_route_identity_links(
    entities: &[Entity],
    relations: &[Relation],
) -> Vec<SingleRouteLink> {
    single_route_identity_links_capped(entities, relations, IDENTITY_PAIR_PROBE_CAP)
}

/// [`single_route_identity_links`] with an explicit pair-probe ceiling — the
/// public entry pins it to [`IDENTITY_PAIR_PROBE_CAP`]; the parameter exists so the
/// cap is unit-testable without a 6 000-entity fixture.
fn single_route_identity_links_capped(
    entities: &[Entity],
    relations: &[Relation],
    max_pair_probes: usize,
) -> Vec<SingleRouteLink> {
    const MAX_HOPS: usize = 5;
    const MAX_PATHS: usize = 4;

    let identity_uids = identity_uids(entities);
    // Build the traversal graph ONCE and reuse it across every pair.
    let adj = sorted_confined_adjacency(entities, relations);

    let mut out = Vec::new();
    let mut probes = 0usize;
    'outer: for (i, &a) in identity_uids.iter().enumerate() {
        for &b in &identity_uids[i + 1..] {
            if probes >= max_pair_probes {
                // Deterministic bound reached — stop before the O(n²) sweep can
                // run away on a permutation-heavy name scan. `identity_uids` is
                // sorted, so the examined pairs are a stable prefix.
                break 'outer;
            }
            probes += 1;
            let mut pathways = disjoint_pathways_in(&adj, a, b, MAX_HOPS, MAX_PATHS);
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

/// One active gap-fill probe: a fragile-link identity endpoint paired with the
/// orthogonal source families MISSING from its single route. The engine runs the
/// modules of those families on this endpoint to *actively pursue* the
/// corroborating pathway AU-063 only names — restricted to the missing families
/// so it seeks corroboration of an already-confirmed link, never a graph-adjacent
/// stranger's whole footprint.
pub(in crate::core) struct GapProbe {
    /// The identity endpoint to probe.
    pub endpoint_uid: String,
    /// The orthogonal source families absent from the link — the modules to run.
    pub missing_families: Vec<&'static str>,
}

/// Active gap-fill targets: for every fragile single-route identity link, both
/// endpoints paired with the strongest orthogonal source families absent from the
/// link (the AU-063 "logical requirement"). Deduplicated by endpoint (missing
/// families unioned). The shared selector behind the engine's active gap-fill, so
/// what the lead names and what the engine pursues are the same set.
pub(in crate::core) fn gap_fill_probes(
    entities: &[Entity],
    relations: &[Relation],
) -> Vec<GapProbe> {
    let by_uid: HashMap<&str, &Entity> = entities.iter().map(|e| (e.uid.as_str(), e)).collect();
    let families_of = |uid: &str| -> BTreeSet<&'static str> {
        by_uid
            .get(uid)
            .map(|&e| source_families(e))
            .unwrap_or_default()
    };

    let mut by_endpoint: BTreeMap<String, BTreeSet<&'static str>> = BTreeMap::new();
    for link in single_route_identity_links(entities, relations) {
        let mut present: BTreeSet<&'static str> = families_of(&link.a_uid);
        present.extend(families_of(&link.b_uid));
        for step in &link.route {
            present.extend(families_of(&step.to_uid));
        }
        present.remove("other");

        // The strongest two orthogonal families not yet on the link — the same
        // "what would corroborate this" set AU-063 reports.
        let absent: Vec<&'static str> = CORROBORATING_FAMILIES
            .iter()
            .copied()
            .filter(|f| !present.contains(f))
            .take(2)
            .collect();
        if absent.is_empty() {
            continue;
        }
        for ep in [&link.a_uid, &link.b_uid] {
            by_endpoint
                .entry(ep.clone())
                .or_default()
                .extend(absent.iter().copied());
        }
    }

    by_endpoint
        .into_iter()
        .map(|(endpoint_uid, fams)| GapProbe {
            endpoint_uid,
            missing_families: fams.into_iter().collect(),
        })
        .collect()
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

    // One detail candidate per fragile link: the finding itself, the priority
    // that decides which gaps are worth surfacing in full (the *weaker*
    // endpoint's effective confidence — a link is only as credible as its min
    // end, so this both ranks strong-to-strong links first and consolidates the
    // permutation tail), the orthogonal families it needs (for the consolidated
    // summary), and its endpoints (for the summary's pivot set).
    struct Candidate {
        priority: f64,
        corr: Correlation,
        absent: Vec<&'static str>,
        a: String,
        b: String,
    }
    let mut cands: Vec<Candidate> = Vec::new();
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
        let absent: Vec<&'static str> = CORROBORATING_FAMILIES
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

        let corr = Correlation::new(
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
        );
        cands.push(Candidate {
            // A link is only as credible as its WEAKER endpoint: a confident hub
            // (a real email) joined to a speculative name-permutation username via
            // shared infra is itself a weak, infra-only link — not worth a detailed
            // finding. Using the min keeps the detailed gaps to genuine
            // strong-to-strong connections and consolidates the permutation tail.
            priority: ea.c_effective().min(eb.c_effective()),
            corr,
            absent,
            a: a.to_string(),
            b: b.to_string(),
        });
    }
    if cands.is_empty() {
        return Vec::new();
    }

    // Surface the gaps most worth corroborating first (strongest endpoint), then
    // consolidate the rest. A broad name scan derives dozens of low-confidence
    // permutation links; emitting one Low finding each buries the handful of real
    // gaps under near-identical noise (observed: 400+ AU-063 rows, 80% of all
    // correlations). Detail the top, aggregate the remainder — no gap is lost,
    // the dossier stays Interpol-grade readable. Deterministic order (priority
    // desc, then uid set) so the output is reproducible across runs.
    cands.sort_by(|x, y| {
        y.priority
            .partial_cmp(&x.priority)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| x.corr.entity_uids.cmp(&y.corr.entity_uids))
    });
    let detail_n = cands
        .iter()
        .filter(|c| c.priority >= AU063_DETAIL_MIN_CONF)
        .count()
        .min(AU063_DETAIL_CAP);

    let mut out: Vec<Correlation> = Vec::with_capacity(detail_n + 1);
    let mut tally: BTreeMap<&'static str, usize> = BTreeMap::new();
    let mut remainder_uids: BTreeSet<String> = BTreeSet::new();
    let mut remainder = 0usize;
    for (i, c) in cands.into_iter().enumerate() {
        if i < detail_n {
            out.push(c.corr);
        } else {
            remainder += 1;
            for f in c.absent {
                *tally.entry(f).or_default() += 1;
            }
            remainder_uids.insert(c.a);
            remainder_uids.insert(c.b);
        }
    }
    if remainder > 0 {
        // The orthogonal family that would corroborate the most of the remainder
        // — the single highest-leverage angle to pursue for the whole tail.
        let top_family = tally
            .into_iter()
            .max_by(|x, y| x.1.cmp(&y.1).then_with(|| y.0.cmp(x.0)))
            .map_or("an orthogonal source", |(f, _)| f);
        let mut uids: Vec<String> = remainder_uids.into_iter().collect();
        uids.sort_unstable();
        uids.truncate(AU063_SUMMARY_UID_CAP);
        out.push(Correlation::new(
            "AU-063",
            "Single-pathway corroboration gaps (consolidated)",
            Severity::Low,
            format!(
                "{remainder} further identity link(s) each rest on a single, uncorroborated \
                 pathway (mostly low-confidence name-derived candidates); a pathway through an \
                 orthogonal source ({top_family}) would corroborate the most of them. Surfaced in \
                 aggregate so the detailed gaps above stay readable — none is lost."
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
    fn single_route_links_are_pair_probe_capped_deterministically() {
        // A chain of identity entities u0—u1—…—u7 makes MANY pairs single-route
        // transitive links (every pair 2–5 hops apart). The O(n²) pair sweep must
        // be bounded by `max_pair_probes`, and the bound must be a DETERMINISTIC
        // prefix (sorted `identity_uids`), not a wall-clock-dependent subset.
        let chain: Vec<Entity> = (0..8)
            .map(|i| id(EntityKind::Username, &format!("user{i}")))
            .collect();
        let rels: Vec<Relation> = chain
            .windows(2)
            .map(|w| rel(&w[0], &w[1], RelationKind::DerivedFrom))
            .collect();

        // Full (effectively uncapped) run finds many fragile links, and the public
        // entry agrees with a huge explicit cap.
        let full = single_route_identity_links_capped(&chain, &rels, usize::MAX);
        assert!(
            full.len() >= 5,
            "the chain topology must yield several single-route links, got {}",
            full.len()
        );
        assert_eq!(
            single_route_identity_links(&chain, &rels).len(),
            full.len(),
            "the public entry runs at the production cap; this fixture is under it"
        );

        // The cap bounds the pair sweep: 0 probes → no links; 1 probe → ≤1 link.
        assert!(single_route_identity_links_capped(&chain, &rels, 0).is_empty());
        assert!(single_route_identity_links_capped(&chain, &rels, 1).len() <= 1);

        // A partial cap yields a deterministic subset of the full result — same
        // bytes every run, and never more than the full sweep.
        let a = single_route_identity_links_capped(&chain, &rels, 4);
        let b = single_route_identity_links_capped(&chain, &rels, 4);
        assert_eq!(
            a.iter().map(|l| (&l.a_uid, &l.b_uid)).collect::<Vec<_>>(),
            b.iter().map(|l| (&l.a_uid, &l.b_uid)).collect::<Vec<_>>(),
            "the capped prefix is deterministic across runs"
        );
        assert!(a.len() <= full.len());
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
    fn gap_fill_probes_name_missing_families_for_both_endpoints() {
        // The active-gap-fill selector mirrors AU-063: a single infra route means
        // both identity endpoints want the strongest orthogonal families.
        let a = id(EntityKind::Email, "a@x.com");
        let b = id(EntityKind::Username, "bob");
        let d = sourced(EntityKind::Domain, "x.com", "dns_intel"); // infra
        let rels = [
            rel(&a, &d, RelationKind::BelongsToDomain),
            rel(&d, &b, RelationKind::DerivedFrom),
        ];
        let probes = gap_fill_probes(&[a.clone(), b.clone(), d], &rels);
        assert_eq!(probes.len(), 2, "both endpoints are probed");
        assert!(
            probes
                .iter()
                .all(|p| p.missing_families.contains(&"breach")),
            "breach (top orthogonal family) is sought on each endpoint"
        );
        assert!(probes.iter().any(|p| p.endpoint_uid == a.uid));
        assert!(probes.iter().any(|p| p.endpoint_uid == b.uid));
    }

    #[test]
    fn gap_fill_probes_empty_when_link_already_corroborated() {
        // Two independent routes → no gap → nothing to actively fill.
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
        assert!(gap_fill_probes(&[a, b, d, o], &rels).is_empty());
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

    #[test]
    fn au063_consolidates_a_flood_of_low_confidence_permutation_gaps() {
        // A broad name scan: many low-confidence name-derived username candidates,
        // each joined to the next only through a shared infra domain (a single
        // transitive route). Emitting one Low finding per pair would flood the
        // dossier; the rule must detail at most AU063_DETAIL_CAP and consolidate
        // the rest into ONE summary — so the total stays bounded and readable.
        let d = sourced(EntityKind::Domain, "shared.example", "dns_intel"); // infra hub
        let mut ents: Vec<Entity> = vec![d.clone()];
        let mut rels: Vec<Relation> = Vec::new();
        for i in 0..60 {
            // Low confidence (0.20) — a speculative permutation, below the detail floor.
            let mut u = Entity::new(EntityKind::Username, format!("cand{i}"), 0.20, "s");
            u.add_evidence(Evidence::new("name_intel", "permutation"));
            rels.push(rel(&u, &d, RelationKind::DerivedFrom));
            ents.push(u);
        }
        let out = rule_au_063_corroboration_gap(&ents, &rels, "s", 0);
        // Bounded: never one-per-link. At least one consolidated summary present.
        assert!(
            out.len() <= AU063_DETAIL_CAP + 1,
            "AU-063 must cap detailed gaps + one summary, got {}",
            out.len()
        );
        assert!(
            out.iter().any(|c| c.rule_name.contains("consolidated")),
            "the speculative remainder must be consolidated into a summary finding"
        );
        // Every detailed finding outranks the summary by being individually named.
        assert!(out.iter().all(|c| c.rule_id == "AU-063"));
    }

    #[test]
    fn au063_details_confident_gaps_and_summarises_only_the_weak_tail() {
        // One genuinely confident link (a real email↔username via infra) plus a
        // tail of weak permutation links sharing the same hub. The confident gap
        // is detailed individually; the weak tail is consolidated.
        let d = sourced(EntityKind::Domain, "hub.example", "dns_intel");
        let email = id(EntityKind::Email, "real@hub.example"); // conf 0.8 → detailed
        let user = id(EntityKind::Username, "realuser"); // conf 0.8 → detailed
        let mut ents = vec![d.clone(), email.clone(), user.clone()];
        let mut rels = vec![
            rel(&email, &d, RelationKind::BelongsToDomain),
            rel(&d, &user, RelationKind::DerivedFrom),
        ];
        for i in 0..40 {
            let mut u = Entity::new(EntityKind::Username, format!("weak{i}"), 0.20, "s");
            u.add_evidence(Evidence::new("name_intel", "permutation"));
            rels.push(rel(&u, &d, RelationKind::DerivedFrom));
            ents.push(u);
        }
        let out = rule_au_063_corroboration_gap(&ents, &rels, "s", 0);
        // The confident email↔user gap is surfaced in detail (names both values).
        assert!(
            out.iter().any(|c| {
                !c.rule_name.contains("consolidated")
                    && c.description.contains("realuser")
                    && c.description.contains("real@hub.example")
            }),
            "the confident gap must be detailed individually"
        );
        // The weak tail is consolidated, not emitted one-by-one.
        assert!(out.iter().any(|c| c.rule_name.contains("consolidated")));
        assert!(out.len() <= AU063_DETAIL_CAP + 1);
    }
}
