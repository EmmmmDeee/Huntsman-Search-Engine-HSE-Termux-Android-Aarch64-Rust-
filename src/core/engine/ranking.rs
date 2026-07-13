//! Out-of-scan-loop entity APIs, split out of the `engine` orchestrator so the
//! parent module reads as pure per-scan orchestration.
//!
//! These functions run OUTSIDE the live scan loop — they are consumed by the CLI
//! (`hse scan` leverage ranking, `hse import` offline enrichment), the web/API
//! layer (`api::scan_handlers` autonomous-sweep planning), and the dossier
//! renderer — never by the round loop in `mod.rs`. They are pure (no engine
//! state) and independently unit-tested. Re-exported from the parent via
//! `pub use ranking::*`, so existing `crate::core::engine::…` call paths are
//! unchanged.
//!
//! Contents: cross-investigation leverage ranking ([`rank_enrichment_leverage`]),
//! autonomous-sweep target ranking and planning ([`rank_autonomous_targets`],
//! [`plan_autonomous_sweep`], [`rank_identity_aware_targets`]), and the offline
//! geo-enrichment the import path applies ([`enrich_offline_geo`]).

// Re-uses the parent orchestrator's imports (Entity, EntityKind, StoragePort, the
// offline-geo helpers) rather than restating them — this module was lifted
// verbatim out of `mod.rs` and shares its import surface.
use super::*;

/// One retained identifier ranked by its realised cross-investigation leverage —
/// the output of [`rank_enrichment_leverage`]. The enrichment-priority asset
/// `docs/data_retention_design.md` (§3–4.1) names: an identifier observed across
/// many distinct investigations is the one that most empowers the rest, because
/// each recurrence is a join that connects two otherwise-separate dossiers.
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct LeverageRanked {
    /// SHA-256 UID of the identifier.
    pub entity_uid: String,
    /// The identifier kind (the join-key class).
    pub kind: crate::core::entity::EntityKind,
    /// The identifier value.
    pub value: String,
    /// Distinct scans in the local intelligence database that observed this value —
    /// the cross-investigation degree. `>= 1` for every returned entry.
    pub cross_scan_degree: usize,
}

/// Run the deterministic, offline geospatial enrichment a live scan's finalise
/// applies — over an arbitrary entity set, for callers outside the scan loop
/// (the `hse import` / web-upload path). For each entity it parses an `Address`
/// into its components and tags a `Coordinates` with geohash / timezone /
/// country ([`enrich_geospatial`]); then it derives a `Coordinates` from every
/// `Address` whose city resolves in the offline `city_coords` table
/// ([`address_to_coords_pass`]) and enriches those new fixes too. New
/// Coordinates are appended (deduped by uid; existing ones are never
/// duplicated). No network — pure lookup — so an imported dossier's addresses
/// feed the geo-correlation rules (AU-014/017/032/056/057/085) and co-location
/// edges identically to a live scan, instead of sitting inert. One pass.
pub fn enrich_offline_geo(entities: &mut Vec<Entity>, scan_id: &str) {
    use std::collections::{HashMap, HashSet};

    // 1) Per-entity deterministic enrichment: Address parse, Coordinates
    //    geohash/timezone/country. Other kinds are untouched.
    for e in entities.iter_mut() {
        enrich_geospatial(e);
    }

    // 2) Address → Coordinates via the offline city table; enrich each new fix
    //    and append it (the pass already skips coords that already exist).
    let map: HashMap<String, Entity> = entities
        .iter()
        .map(|e| (e.uid.clone(), e.clone()))
        .collect();
    let mut seen: HashSet<String> = map.keys().cloned().collect();
    for mut derived in address_to_coords_pass(&map, scan_id) {
        enrich_geospatial(&mut derived);
        if seen.insert(derived.uid.clone()) {
            entities.push(derived);
        }
    }
}

/// Rank the high-leverage identifiers in `entities` by how many distinct
/// investigations each one bridges — the "which of my retained data most empowers
/// the rest" query (`docs/data_retention_design.md` §4.1), and the read-only
/// counterpart to [`history::link_cross_scan_history`], which writes the same
/// bridge as evidence.
///
/// Only [`history::is_cross_scan_candidate`] identifiers are scored — the strong
/// join keys (email / phone / crypto / distinctive username / full-name person /
/// specific address), never infrastructure, coarse geo, speculative permutations
/// or already-recalled nodes — so the ranking can never be topped by noise.
/// Leverage is the *realised* cross-scan degree
/// ([`StoragePort::observation_count`] — the count of distinct scans that recorded
/// the value); there is no invented weighting, so the score is exactly "how many
/// separate dossiers this identifier already connects". Sorted strongest-first,
/// ties broken by UID for determinism, truncated to `limit`. A store error on an
/// entity skips it (never fails). Pure and offline — indexed point lookups only.
#[must_use]
pub fn rank_enrichment_leverage(
    store: &dyn StoragePort,
    entities: &[Entity],
    limit: usize,
) -> Vec<LeverageRanked> {
    let mut out: Vec<LeverageRanked> = entities
        .iter()
        .filter(|e| history::is_cross_scan_candidate(e))
        .filter_map(|e| {
            let degree = store.observation_count(&e.uid).ok()?;
            (degree > 0).then(|| LeverageRanked {
                entity_uid: e.uid.clone(),
                kind: e.kind.clone(),
                value: e.value.clone(),
                cross_scan_degree: degree,
            })
        })
        .collect();
    // Strongest-first; deterministic UID tie-break so the ranking is stable.
    out.sort_by(|a, b| {
        b.cross_scan_degree
            .cmp(&a.cross_scan_degree)
            .then_with(|| a.entity_uid.cmp(&b.entity_uid))
    });
    out.truncate(limit);
    out
}

/// Intrinsic pivot value of an identifier kind — how much investigative reach a
/// scan seeded on it tends to unlock, independent of how many investigations have
/// already touched it. The ordering encodes Interpol-style tradecraft: a unique
/// strong selector (email, phone) resolves an individual and fans out to accounts,
/// breaches and devices; a username pivots across platforms; a person name anchors
/// people-centric correlation; a specific address / ABN-ACN / organisation anchors
/// geo and registry; crypto addresses chain on-ledger; coordinates and network
/// infrastructure are weak roots (coarse, shared, or non-attributable). The scale
/// is `0.0..=1.0`; values are relative weights, not probabilities. Pure and total —
/// every [`crate::core::entity::EntityKind`] maps, unknown/weak kinds fall to the
/// `0.12` floor so they can still seed when nothing stronger exists.
#[must_use]
pub fn kind_pivot_value(kind: &crate::core::entity::EntityKind) -> f64 {
    use crate::core::entity::EntityKind;
    match kind {
        EntityKind::Email => 1.00,
        EntityKind::Phone => 0.95,
        EntityKind::Person => 0.85,
        EntityKind::Username => 0.80,
        EntityKind::Address => 0.72,
        EntityKind::AbnAcn => 0.66,
        EntityKind::Organisation => 0.58,
        EntityKind::CryptoAddress => 0.52,
        EntityKind::Coordinates => 0.40,
        EntityKind::Domain => 0.34,
        EntityKind::IpAddress | EntityKind::Asn | EntityKind::Cidr => 0.22,
        _ => 0.12,
    }
}

/// One entity ranked as a candidate for fully autonomous investigation — the
/// output of [`rank_autonomous_targets`]. Carries everything the
/// no-operator-input scan loop needs to dispatch a scan and explain *why* this
/// target was chosen, without re-deriving the score.
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct AutonomousTarget {
    /// SHA-256 UID of the chosen identifier.
    pub uid: String,
    /// The resolved scan-target kind (always pivotable — non-pivotable kinds are
    /// filtered out before ranking).
    pub kind: crate::core::scan::TargetKind,
    /// The identifier value to seed the scan with.
    pub value: String,
    /// Composite priority score (pivot-value × cross-investigation leverage ×
    /// effective confidence). Strictly higher = investigate sooner.
    pub score: f64,
    /// Distinct prior investigations that observed this value — the realised
    /// cross-scan degree fed into the leverage factor.
    pub cross_scan_degree: usize,
}

/// Composite autonomous-investigation priority for one identifier.
///
/// Three orthogonal factors multiply, so a target must score on *all three* to
/// rise — none can be faked by maxing a single axis:
/// 1. **Pivot value** ([`kind_pivot_value`]) — intrinsic reach of the kind.
/// 2. **Cross-investigation leverage** — `1 + ln(1 + degree)`. A log curve so the
///    first few corroborating investigations matter a lot (1→1.69, 4→2.61) but a
///    runaway-popular value can't dominate purely on count; degree `0` yields the
///    neutral `1.0` (no leverage, no penalty).
/// 3. **Effective confidence** — `c_eff`, clamped to `0.0..=1.0`, so a speculative
///    candidate is down-weighted versus a corroborated fact of the same kind.
///
/// Pure, total and deterministic. Higher is better.
#[must_use]
pub fn autonomous_target_score(
    kind: &crate::core::entity::EntityKind,
    cross_scan_degree: usize,
    c_eff: f64,
) -> f64 {
    let leverage = 1.0 + (1.0 + cross_scan_degree as f64).ln();
    kind_pivot_value(kind) * leverage * c_eff.clamp(0.0, 1.0)
}

/// Rank entities for fully autonomous investigation — the multi-factor,
/// no-operator-input ranking that a continuous loop drives.
///
/// Scores every pivotable [`history::is_cross_scan_candidate`] identifier by
/// [`autonomous_target_score`] (pivot-value × leverage × confidence), letting the
/// platform *classify and prioritise* the whole working set, then work down it.
/// `degree_of` supplies each UID's cross-investigation degree (typically
/// [`StoragePort::observation_count`]); `exclude` holds UIDs already investigated
/// this cycle, so the loop never re-seeds the same target and converges. Results
/// are strongest-first, ties broken by UID for determinism, truncated to `limit`.
/// Pure given `degree_of` — no I/O of its own. Also the flat-ranking oracle
/// [`plan_autonomous_sweep`] (at `diversity = 0.0`) and
/// [`rank_identity_aware_targets`] (for singleton identities) are tested against.
pub fn rank_autonomous_targets<F: Fn(&str) -> usize>(
    entities: &[Entity],
    degree_of: F,
    exclude: &std::collections::HashSet<String>,
    limit: usize,
) -> Vec<AutonomousTarget> {
    let mut out: Vec<AutonomousTarget> = entities
        .iter()
        .filter(|e| !exclude.contains(&e.uid) && history::is_cross_scan_candidate(e))
        .filter_map(|e| {
            let kind = crate::core::scan::TargetKind::from_entity_kind(&e.kind)?;
            let degree = degree_of(&e.uid);
            Some(AutonomousTarget {
                uid: e.uid.clone(),
                kind,
                value: e.value.clone(),
                score: autonomous_target_score(&e.kind, degree, e.c_effective()),
                cross_scan_degree: degree,
            })
        })
        .collect();
    out.sort_by(|a, b| {
        b.score
            .partial_cmp(&a.score)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| a.uid.cmp(&b.uid))
    });
    out.truncate(limit);
    out
}

/// Default diversity weight for [`plan_autonomous_sweep`]. `0.0` reproduces the
/// pure score ordering of [`rank_autonomous_targets`]; larger values spread
/// investigative effort across more identifier kinds. `0.5` balances "investigate
/// the single strongest target" against "don't tunnel a whole budget on one kind".
pub const DEFAULT_SWEEP_DIVERSITY: f64 = 0.5;

/// A diversity-aware autonomous investigation plan — the ordered queue the
/// continuous, no-operator-input loop works down, plus the coverage it achieves.
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct AutonomousPlan {
    /// Ordered investigation queue, strongest marginal value first.
    pub queue: Vec<AutonomousTarget>,
    /// Total pivotable candidates considered before the `limit` cut.
    pub considered: usize,
    /// Distinct identifier kinds represented in `queue` — the breadth of the
    /// intelligence base this plan develops.
    pub kinds_covered: usize,
}

/// Build a diversity-aware autonomous investigation plan over `entities`.
///
/// [`rank_autonomous_targets`] orders by raw composite score, so a base dominated
/// by one kind (say a leaked list of forty emails) would have the loop burn its
/// whole budget on emails before ever pivoting a phone or username. A real
/// investigator spreads effort to maximise the breadth of leads developed per unit
/// of work. This planner does the same with a Maximal-Marginal-Relevance–style
/// greedy selection: at each step it takes the candidate maximising
/// `score / (1 + diversity × already_selected_of_that_kind)`, so each additional
/// target of an already-represented kind is progressively discounted while a fresh
/// kind keeps its full score. `diversity = 0.0` reproduces pure score order; larger
/// values interleave kinds harder.
///
/// Same gates as [`rank_autonomous_targets`] — only pivotable
/// [`history::is_cross_scan_candidate`] identifiers, with `exclude` honoured so the
/// continuous loop converges. Deterministic: ties broken by raw score then UID.
/// Truncated to `limit`. Pure given `degree_of` — no I/O of its own. A negative
/// `diversity` is floored to `0.0`.
pub fn plan_autonomous_sweep<F: Fn(&str) -> usize>(
    entities: &[Entity],
    degree_of: F,
    exclude: &std::collections::HashSet<String>,
    limit: usize,
    diversity: f64,
) -> AutonomousPlan {
    // 1) Score every eligible candidate once (same gate as rank_autonomous_targets).
    let mut pool: Vec<AutonomousTarget> = entities
        .iter()
        .filter(|e| !exclude.contains(&e.uid) && history::is_cross_scan_candidate(e))
        .filter_map(|e| {
            let kind = crate::core::scan::TargetKind::from_entity_kind(&e.kind)?;
            let degree = degree_of(&e.uid);
            Some(AutonomousTarget {
                uid: e.uid.clone(),
                kind,
                value: e.value.clone(),
                score: autonomous_target_score(&e.kind, degree, e.c_effective()),
                cross_scan_degree: degree,
            })
        })
        .collect();
    let considered = pool.len();
    let div = diversity.max(0.0);
    let cap = limit.min(considered);

    // 2) Greedy MMR selection: take the best marginal value, discount its kind, repeat.
    let mut queue: Vec<AutonomousTarget> = Vec::with_capacity(cap);
    let mut per_kind: HashMap<crate::core::scan::TargetKind, usize> = HashMap::new();
    while queue.len() < cap && !pool.is_empty() {
        let mut best_idx = 0usize;
        let mut best_marginal = f64::NEG_INFINITY;
        let mut best_score = f64::NEG_INFINITY;
        let mut best_uid: &str = "";
        for (i, c) in pool.iter().enumerate() {
            let seen = per_kind.get(&c.kind).copied().unwrap_or(0);
            let marginal = c.score / (1.0 + div * seen as f64);
            // Deterministic precedence: higher marginal, then higher raw score, then
            // lexicographically smaller UID.
            let better = if (marginal - best_marginal).abs() > f64::EPSILON {
                marginal > best_marginal
            } else if (c.score - best_score).abs() > f64::EPSILON {
                c.score > best_score
            } else {
                c.uid.as_str() < best_uid
            };
            if best_marginal == f64::NEG_INFINITY || better {
                best_idx = i;
                best_marginal = marginal;
                best_score = c.score;
                best_uid = c.uid.as_str();
            }
        }
        let chosen = pool.swap_remove(best_idx);
        *per_kind.entry(chosen.kind).or_insert(0) += 1;
        queue.push(chosen);
    }

    AutonomousPlan {
        queue,
        considered,
        kinds_covered: per_kind.len(),
    }
}

/// Standard hop bound for identity-cluster resolution in the autonomous ranker —
/// matches the dossier and the AU correlator so the autonomous view agrees with
/// what the analyst sees.
const IDENTITY_CLUSTER_MAX_HOPS: usize = 4;
/// Weakest-link confidence floor for a co-reference cluster to bind (matches the
/// dossier / correlator): one tenuous edge can't fuse two strong sub-identities.
const IDENTITY_CLUSTER_MIN_CONF: f64 = 0.50;
/// How hard identity *breadth* lifts a clustered target: a person resolved across
/// `k` distinct identifier kinds is more actionable than one known by a single
/// selector. Multiplier is `1 + WEIGHT × ln(distinct_kinds)`, so a singleton
/// (`ln 1 = 0`) is unchanged and a 3-kind identity gets `1 + 0.5·ln3 ≈ 1.55`.
const IDENTITY_BREADTH_WEIGHT: f64 = 0.5;

/// One **identity-resolved** investigation target: a representative selector that
/// stands for a whole co-referent cluster — the output of
/// [`rank_identity_aware_targets`].
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct ClusteredTarget {
    /// The selector to actually seed the scan with (the cluster's strongest
    /// pivotable member). Its `score` and `cross_scan_degree` carry the *cluster's*
    /// aggregated priority, not the lone member's.
    pub representative: AutonomousTarget,
    /// Co-referent members present in the working set (sorted UIDs; includes the
    /// representative). `1` for a singleton identity.
    pub member_uids: Vec<String>,
    /// `member_uids.len()` — the resolved identity's breadth in selectors.
    pub cluster_size: usize,
    /// Distinct identifier *kinds* among the eligible members — the breadth signal
    /// that lifts a well-resolved identity over a single repeated selector.
    pub distinct_kinds: usize,
}

/// Rank fully-autonomous investigation targets **by resolved identity, not by raw
/// selector** — the people-centric successor to [`rank_autonomous_targets`] that
/// consumes the co-reference graph.
///
/// Where [`rank_autonomous_targets`] scores every selector independently, this
/// first resolves the identity clusters of the relation graph
/// ([`crate::core::relation::resolve_identity_clusters`] — the same clustering the
/// dossier and correlator use, now fed by the promoted co-reference edges), then
/// collapses each cluster to ONE target so the loop never spends investigative
/// breadth on three selectors of the same person. The surviving target is the
/// cluster's strongest pivotable member, but scored with the **whole identity's**
/// weight: leverage aggregated across every member's cross-scan degree, lifted by
/// a breadth bonus for the number of distinct identifier kinds the identity spans
/// ([`IDENTITY_BREADTH_WEIGHT`]) — so the person the platform knows the most about
/// is investigated first.
///
/// A singleton identity (an entity in no cluster) scores *exactly* as
/// [`rank_autonomous_targets`] would (`ln 1 = 0` breadth bonus, degree unchanged),
/// so this is a strict, additive generalisation. `exclude` is honoured per member
/// (an all-excluded cluster yields nothing, so a continuous loop converges).
/// Deterministic; strongest-first, UID tie-break, truncated to `limit`.
pub fn rank_identity_aware_targets<F: Fn(&str) -> usize>(
    entities: &[Entity],
    relations: &[Relation],
    degree_of: F,
    exclude: &std::collections::HashSet<String>,
    limit: usize,
) -> Vec<ClusteredTarget> {
    // Map each clustered UID to its cluster key (the cluster's first member UID);
    // an entity in no cluster keys to its own UID (a singleton identity). Also keep
    // every present member UID per cluster for honest `member_uids` reporting.
    let clusters = crate::core::relation::resolve_identity_clusters(
        entities,
        relations,
        IDENTITY_CLUSTER_MAX_HOPS,
        IDENTITY_CLUSTER_MIN_CONF,
    );
    let mut cluster_of: HashMap<&str, &str> = HashMap::new();
    for c in &clusters {
        if let Some(first) = c.members.first() {
            for m in &c.members {
                cluster_of.insert(m.as_str(), first.as_str());
            }
        }
    }

    // Per cluster key: the eligible (pivotable, cross-scan-candidate, not-excluded)
    // member targets, plus the full set of present member UIDs for reporting.
    struct Group<'a> {
        eligible: Vec<(AutonomousTarget, crate::core::entity::EntityKind, f64)>,
        members: HashSet<&'a str>,
    }
    let mut groups: HashMap<&str, Group> = HashMap::new();

    for e in entities {
        let key = cluster_of
            .get(e.uid.as_str())
            .copied()
            .unwrap_or(e.uid.as_str());
        let g = groups.entry(key).or_insert_with(|| Group {
            eligible: Vec::new(),
            members: HashSet::new(),
        });
        g.members.insert(e.uid.as_str());
        if exclude.contains(&e.uid) || !history::is_cross_scan_candidate(e) {
            continue;
        }
        let Some(kind) = crate::core::scan::TargetKind::from_entity_kind(&e.kind) else {
            continue;
        };
        let degree = degree_of(&e.uid);
        let individual = autonomous_target_score(&e.kind, degree, e.c_effective());
        g.eligible.push((
            AutonomousTarget {
                uid: e.uid.clone(),
                kind,
                value: e.value.clone(),
                score: individual,
                cross_scan_degree: degree,
            },
            e.kind.clone(),
            e.c_effective(),
        ));
    }

    let mut out: Vec<ClusteredTarget> = Vec::new();
    for g in groups.values() {
        if g.eligible.is_empty() {
            continue; // no investigable selector in this identity
        }
        // Representative = strongest individual member (deterministic UID tie-break).
        let rep = g
            .eligible
            .iter()
            .max_by(|a, b| {
                a.0.score
                    .partial_cmp(&b.0.score)
                    .unwrap_or(std::cmp::Ordering::Equal)
                    .then_with(|| b.0.uid.cmp(&a.0.uid)) // smaller UID wins
            })
            .expect("non-empty");
        // Aggregate the identity's reach: total cross-scan degree across selectors,
        // and the count of distinct identifier kinds it spans.
        let aggregated_degree: usize = g.eligible.iter().map(|m| m.0.cross_scan_degree).sum();
        let distinct_kinds = g
            .eligible
            .iter()
            .map(|m| &m.1)
            .collect::<HashSet<_>>()
            .len();
        let breadth = 1.0 + IDENTITY_BREADTH_WEIGHT * (distinct_kinds as f64).ln();
        let score = autonomous_target_score(&rep.1, aggregated_degree, rep.2) * breadth;

        let mut member_uids: Vec<String> = g.members.iter().copied().map(str::to_string).collect();
        member_uids.sort_unstable();
        out.push(ClusteredTarget {
            representative: AutonomousTarget {
                uid: rep.0.uid.clone(),
                kind: rep.0.kind,
                value: rep.0.value.clone(),
                score,
                cross_scan_degree: aggregated_degree,
            },
            cluster_size: member_uids.len(),
            distinct_kinds,
            member_uids,
        });
    }

    out.sort_by(|a, b| {
        b.representative
            .score
            .partial_cmp(&a.representative.score)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| a.representative.uid.cmp(&b.representative.uid))
    });
    out.truncate(limit);
    out
}
