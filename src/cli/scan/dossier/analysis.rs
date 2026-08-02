//! PART II — what the findings mean together.
//!
//! [`super::findings`] lists what was collected. This section draws the
//! conclusions an analyst would otherwise pivot a graph canvas to reach: which
//! findings fired a correlation rule, how identities link, how the scan reached
//! its deepest leads, which identifiers resolve to one person, and which single
//! nodes the whole network hangs on.
//!
//! Every renderer here reuses the very `core::relation` primitive the matching
//! correlation rule fires on, so a rendered chain and a stored finding can never
//! disagree. The traversal graph and the uid→label resolver are built ONCE in
//! [`Linkage::build`] and shared: five sections used to each construct their own,
//! which was five chances to drift and five allocations over the same slice.

use crate::core::{
    correlator::Correlation,
    entity::Entity,
    relation::{
        Adjacency, ConnectionBroker, IdentityClusterResult, IdentityPath, Relation,
        connection_brokers, identity_paths, identity_uids, provenance_chain,
        resolve_identity_clusters, sorted_confined_adjacency, strongest_path_in,
    },
};

use super::{Labeller, truncation_note};

/// The same weakest-link floor AU-067 and AU-070 fire under (Probable tier): a
/// link below it is too weak to *bind* two identities, so one tenuous edge
/// cannot fuse dozens of unrelated namesakes into "one person" here either.
const MIN_CONF: f64 = 0.50;

/// The subset of `relations` whose BOTH endpoints are present in `entities` —
/// the same confinement [`sorted_confined_adjacency`] applies for the graph
/// sections below.
///
/// The raw RELATIONS listing used to print every relation regardless, so an edge
/// to or from a platform-infra (or otherwise excluded) entity rendered as a bare
/// hex UID stub with no explanation for why that node appears nowhere else in
/// the dossier. Pure.
pub(super) fn confine_relations_to_visible<'a>(
    entities: &[Entity],
    relations: &'a [Relation],
) -> Vec<&'a Relation> {
    let visible: std::collections::HashSet<&str> =
        entities.iter().map(|e| e.uid.as_str()).collect();
    relations
        .iter()
        .filter(|r| visible.contains(r.from_uid.as_str()) && visible.contains(r.to_uid.as_str()))
        .collect()
}

/// Everything PART II renders, derived once from the working set so the
/// document's structure can be decided (see [`super::plan`]) before a line is
/// printed.
pub(super) struct Linkage<'a> {
    relations: &'a [Relation],
    /// The canonical traversal graph, confined to visible nodes. Shared by the
    /// connections and brokers sections.
    adj: Adjacency<'a>,
    confined: Vec<&'a Relation>,
    connections: Vec<IdentityPath>,
    /// Entities expansion actually reached (generation > 0), deepest first.
    trails: Vec<&'a Entity>,
    clusters: Vec<IdentityClusterResult>,
    brokers: Vec<ConnectionBroker>,
}

impl<'a> Linkage<'a> {
    pub(super) fn build(entities: &'a [Entity], relations: &'a [Relation]) -> Self {
        let adj = sorted_confined_adjacency(entities, relations);
        let ids = identity_uids(entities);

        // Only ≥3-member resolutions and ≥3-identity brokers are worth a
        // section: a 2-member cluster is a single link already rendered under
        // CONNECTIONS, and a 2-identity bridge is a single fragile pair.
        let clusters = resolve_identity_clusters(entities, relations, 4, MIN_CONF)
            .into_iter()
            .filter(|c| c.members.len() >= 3)
            .collect();
        let brokers = connection_brokers(&adj, &ids, MIN_CONF)
            .into_iter()
            .filter(|b| b.brokered.len() >= 3)
            .collect();

        let mut trails: Vec<&Entity> = entities.iter().filter(|e| e.generation > 0).collect();
        // Deepest first (the most "how did we even get here" findings), then by
        // effective confidence, then uid for a deterministic total order.
        trails.sort_by(|a, b| {
            b.generation
                .cmp(&a.generation)
                .then_with(|| {
                    b.c_effective()
                        .partial_cmp(&a.c_effective())
                        .unwrap_or(std::cmp::Ordering::Equal)
                })
                .then_with(|| a.uid.cmp(&b.uid))
        });

        Self {
            relations,
            confined: confine_relations_to_visible(entities, relations),
            connections: identity_paths(entities, relations, 4),
            trails,
            clusters,
            brokers,
            adj,
        }
    }

    /// The PART II sections that have something to show, in print order — the
    /// list the CONTENTS index is built from. Kept adjacent to [`Self::print`]
    /// so a new section cannot be rendered without also being announced.
    pub(super) fn section_titles(&self, correlations: &[Correlation]) -> Vec<&'static str> {
        let present = [
            (!correlations.is_empty(), "correlations"),
            (!self.confined.is_empty(), "relations"),
            (!self.connections.is_empty(), "connections"),
            (!self.trails.is_empty(), "derivation trails"),
            (!self.clusters.is_empty(), "resolved identities"),
            (!self.brokers.is_empty(), "connection brokers"),
        ];
        present
            .into_iter()
            .filter_map(|(has, title)| has.then_some(title))
            .collect()
    }

    pub(super) fn print(&self, correlations: &[Correlation], labels: &Labeller<'_>) {
        println!("━━━ PART II — ANALYSIS ━━━");
        println!();
        self.print_correlations(correlations);
        self.print_relations(labels);
        self.print_connections(labels);
        self.print_derivation_trails(labels);
        self.print_resolved_identities(labels);
        self.print_connection_brokers(labels);
    }

    fn print_correlations(&self, correlations: &[Correlation]) {
        if correlations.is_empty() {
            return;
        }
        println!("━━━ CORRELATIONS ({}) ━━━", correlations.len());
        println!();
        for c in correlations {
            let sev = match c.severity.to_string().as_str() {
                "CRITICAL" => "🔴 CRITICAL",
                "HIGH" => "🟠 HIGH",
                "MEDIUM" => "🟡 MEDIUM",
                _ => "🔵 LOW",
            };
            // Correlations arrive ranked (severity × max child C_eff, applied in
            // `correlations_for_scan`), and both the web view and the debug
            // bundle print that score. Printing it here as well keeps the live
            // dossier's ordering self-explanatory rather than looking arbitrary.
            println!(
                "  {} [{}] {}  (rank {:.2})",
                c.rule_id, sev, c.rule_name, c.rank
            );
            println!("    {}", c.description);
            println!();
        }
    }

    /// The raw edge list, confined to edges whose endpoints both appear above.
    /// The count of dropped edges is stated in the heading rather than left to
    /// be inferred from a short list.
    fn print_relations(&self, labels: &Labeller<'_>) {
        if self.confined.is_empty() {
            return;
        }
        let hidden = self.relations.len() - self.confined.len();
        if hidden > 0 {
            println!(
                "━━━ RELATIONS ({} of {} — {hidden} hidden, endpoint excluded from view) ━━━",
                self.confined.len(),
                self.relations.len()
            );
        } else {
            println!("━━━ RELATIONS ({}) ━━━", self.confined.len());
        }
        println!();
        for r in &self.confined {
            println!(
                "  {}  ──{}──▶  {}   (conf={:.2})",
                labels.value(&r.from_uid, 40),
                r.kind,
                labels.value(&r.to_uid, 40),
                r.confidence
            );
        }
        println!();
    }

    /// CONNECTIONS — graph-free link analysis (PROBLEM_TREE C1, the
    /// "Maltego-without-graphs" play). Renders the shortest typed *thread* tying
    /// each discovered identity back through the graph — the analytic conclusion
    /// an analyst would otherwise pivot a canvas to find. Reuses the very
    /// [`identity_paths`] primitive AU-060 fires on.
    fn print_connections(&self, labels: &Labeller<'_>) {
        if self.connections.is_empty() {
            return;
        }
        const SHOWN: usize = 25;
        println!(
            "━━━ CONNECTIONS ({}) — identity link analysis ━━━",
            self.connections.len()
        );
        println!();
        println!("  The shortest typed path tying each identity back through the graph");
        println!("  (a chain is only as strong as its weakest edge):");
        println!();
        for c in self.connections.iter().take(SHOWN) {
            let (fv, fk) = labels.parts(&c.from_uid, 36);
            let mut line = format!("  {fv} ({fk})");
            let last = c.steps.len().saturating_sub(1);
            for (i, step) in c.steps.iter().enumerate() {
                let (sv, sk) = labels.parts(&step.to_uid, 36);
                if i == last {
                    // Annotate the destination identity with its kind.
                    line.push_str(&format!("  ──{}──▶  {sv} ({sk})", step.kind));
                } else {
                    line.push_str(&format!("  ──{}──▶  {sv}", step.kind));
                }
            }
            println!("{line}");

            // Corroboration multiplicity: how many edge-disjoint routes confirm
            // this link (AU-062's signal). >1 means the connection survives any
            // single pathway going dark — the orthogonal-route robustness.
            let routes = crate::core::relation::disjoint_pathways_in(
                &self.adj,
                &c.from_uid,
                &c.to_uid,
                5,
                4,
            )
            .len();
            let corroboration = if routes >= 2 {
                format!(" · corroborated via {routes} independent pathways")
            } else {
                String::new()
            };
            // Best-achievable reliability: the widest (max-bottleneck) route's
            // weakest link, shown when it beats the shortest path's — the
            // most-trustworthy way these two connect may be stronger than the
            // shortest chain suggests (AU-069's signal).
            let best = strongest_path_in(&self.adj, &c.from_uid, &c.to_uid, 5)
                .map_or(c.min_confidence, |p| p.min_confidence);
            let best_route = if best > c.min_confidence + 1e-9 {
                format!(" · strongest route conf {best:.2}")
            } else {
                String::new()
            };
            println!(
                "    {} hop{}, weakest edge conf={:.2}{}{}",
                c.hops,
                if c.hops == 1 { "" } else { "s" },
                c.min_confidence,
                best_route,
                corroboration
            );
            println!();
        }
        if let Some(note) = truncation_note(SHOWN, self.connections.len()) {
            println!("{note}");
            println!();
        }
    }

    /// DERIVATION TRAILS — the causal chain of pivots that surfaced each of the
    /// deepest findings, seed → … → entity. Where CONNECTIONS shows how
    /// identities link to each other, this shows how the SCAN itself REACHED a
    /// finding: which entity's expansion led to which, generation by generation
    /// out from the seed. Reuses [`provenance_chain`] so the rendered path and
    /// the stored `DerivedFrom` lineage can never disagree. Only entities
    /// expansion actually reached (generation > 0) have a trail worth narrating;
    /// a seed-round find is trivially its own root.
    fn print_derivation_trails(&self, labels: &Labeller<'_>) {
        if self.trails.is_empty() {
            return;
        }
        const SHOWN: usize = 12;
        println!(
            "━━━ DERIVATION TRAILS ({}) — how the deepest leads were reached ━━━",
            self.trails.len()
        );
        println!();
        println!(
            "  The pivot chain from the seed out to each finding (gen = pivots from the seed):"
        );
        println!();
        for e in self.trails.iter().take(SHOWN) {
            // provenance_chain is entity→root; reverse it for a seed→entity read.
            let mut chain = provenance_chain(&e.uid, self.relations);
            chain.reverse();
            let rendered = chain
                .iter()
                .map(|uid| labels.value(uid, 32))
                .collect::<Vec<_>>()
                .join("  →  ");
            println!("  [gen {}] {}  ({})", e.generation, rendered, e.kind);
        }
        if let Some(note) = truncation_note(SHOWN, self.trails.len()) {
            println!("{note}");
        }
        println!();
    }

    /// RESOLVED IDENTITIES — the cluster-level synthesis of CONNECTIONS
    /// (AU-067). Where the link analysis above ties identities together
    /// pairwise, this collapses every transitively-connected identity into one
    /// *resolved identity* — the connected component of the identity graph —
    /// held together only as firmly as its weakest link. Reuses
    /// [`resolve_identity_clusters`], so the grouping cannot disagree with the
    /// pairwise threads above or the AU-067 correlation.
    fn print_resolved_identities(&self, labels: &Labeller<'_>) {
        if self.clusters.is_empty() {
            return;
        }
        println!(
            "━━━ RESOLVED IDENTITIES ({}) — distinct identifiers that are one person ━━━",
            self.clusters.len()
        );
        println!();
        println!("  Every identity transitively linked into one (weakest-link confidence):");
        println!();
        for (i, c) in self.clusters.iter().enumerate() {
            println!(
                "  #{} — {} identifiers, weakest link conf={:.2}:",
                i + 1,
                c.members.len(),
                c.min_confidence
            );
            for uid in &c.members {
                println!("      • {}", labels.with_kind(uid, 36));
            }
            println!();
        }
    }

    /// CONNECTION BROKERS — the node-criticality synthesis (AU-070). Where
    /// CONNECTIONS ties identities pairwise and RESOLVED IDENTITIES collapses
    /// them into clusters, this names the **single nodes the network hangs on**:
    /// an entity whose removal would fragment ≥3 otherwise-linked identities
    /// (the graph's articulation points, in identity terms). Reuses
    /// [`connection_brokers`] over the same confined adjacency the threads above
    /// traverse. These are the prime pivots: corroborating a broker hardens
    /// every connection that runs through it.
    fn print_connection_brokers(&self, labels: &Labeller<'_>) {
        if self.brokers.is_empty() {
            return;
        }
        println!(
            "━━━ CONNECTION BROKERS ({}) — single points that hold the network together ━━━",
            self.brokers.len()
        );
        println!();
        println!("  Remove one of these and the identities beneath it fall apart — the prime");
        println!("  pivots to corroborate (hardening a broker hardens every link through it):");
        println!();
        for (i, b) in self.brokers.iter().enumerate() {
            println!(
                "  #{} — {} brokers {} identities:",
                i + 1,
                labels.with_kind(&b.uid, 36),
                b.brokered.len()
            );
            for uid in &b.brokered {
                println!("      • {}", labels.with_kind(uid, 36));
            }
            println!();
        }
    }
}
