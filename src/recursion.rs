//! Bounded live recursion: fetch → expand → fetch across generations.
//!
//! The single-command recursive crawl Huntsman lacked. A live lookup produces one generation of
//! entities; this driver feeds the identity-bearing ones back as the next generation's seeds and
//! repeats, so "exhaustive recursion" is one invocation instead of a chain of manual scans.
//!
//! The loop is transport-agnostic: a [`SelectorCollector`] performs each live lookup, so the
//! termination, de-duplication and expansion logic are unit-tested offline with a scripted
//! collector and no network. The bounds come from the shared [`PipelineLimits`] and the stop
//! reason from the shared [`crate::termination`] contract, so this driver cannot invent a weaker
//! guarantee than the rest of the engine. Nothing here redacts: every collected entity and every
//! source outcome is carried through in full; redaction, where it exists at all, is the caller's
//! output concern, never the scan's.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::clock;
use crate::entity::{Entity, EntityKind, merge_by_uid};
use crate::pipeline_limits::PipelineLimits;
use crate::scan_route::{ScanKind, canonical_selector, infer_kind};
use crate::source_outcome::SourceExecutionOutcome;
use crate::termination::{
    FrontierState, TerminationReason, TerminationSignals, decide_termination,
};

/// One live lookup the driver can dispatch: a selector routed to one lookup kind.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    pub kind: ScanKind,
    pub selector: String,
}

impl Target {
    /// The order-stable de-duplication key: a lookup of the same selector under the same kind is
    /// the same dispatch. `ScanKind` is not `Ord`, so its stable command word carries the order.
    fn owned_key(&self) -> (String, String) {
        (self.kind.command().to_owned(), self.selector.clone())
    }
}

/// What a collector observed for one target. A failed lookup still returns `outcomes` describing
/// why (auth required, connect failure, …): the driver records every dispatch, so a source is
/// never silently dropped from the recursion.
pub struct Step {
    pub entities: Vec<Entity>,
    pub outcomes: Vec<SourceExecutionOutcome>,
}

/// Performs one live lookup. The driver owns the recursion; the collector owns the I/O.
pub trait SelectorCollector {
    fn collect(&mut self, target: &Target) -> Step;

    /// Collect a small wave of independent targets. The default preserves legacy sequential
    /// semantics; graph-aware collectors may override it to schedule the wave concurrently.
    /// Results must be returned in the same order as `targets`.
    fn collect_batch(&mut self, targets: &[Target]) -> Vec<Step> {
        targets.iter().map(|target| self.collect(target)).collect()
    }

    /// Whether `next` may join an in-flight batch of `selected` lookups.
    ///
    /// Stateful collectors can impose a sequencing boundary, so cancellation is checked again
    /// after the current batch returns rather than dispatching an otherwise dependent lookup.
    fn may_batch(&self, _selected: &[Target], _next: &Target) -> bool {
        true
    }

    /// Report mismatched collector batch output cardinality to the scan's error accounting.
    /// The recursion driver also persists a typed non-success outcome for each violation.
    fn on_batch_contract_error(&mut self, _violations: usize) {}

    /// Whether the operator asked the crawl to stop. Checked before every dispatch: the crawl
    /// then stops as `Cancelled`, keeping everything found so far.
    fn cancelled(&self) -> bool {
        false
    }
}

/// Bounds for one recursive crawl. Defaults are the shared [`PipelineLimits`], so the recursion
/// stops under the same budget as every other pathway.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct RecursionPolicy {
    /// Expansion hops beyond the seeds (generation 0). `0` runs the seeds and no expansion.
    pub max_generations: u32,
    /// Minimum confidence for an entity to be expanded into a new lookup. Keeps the crawl on real
    /// linkage and off low-confidence noise.
    pub expand_confidence_floor: f64,
    /// Total live lookups across the whole crawl.
    pub max_dispatches: usize,
    /// Total distinct entities retained before the crawl is a resource-limited stop.
    pub max_entities: usize,
    /// Distinct new targets one generation may queue for the next.
    pub max_frontier_per_generation: usize,
    /// Also run the keyed breach `exposure` lookup on every e-mail the crawl reaches, so a
    /// configured paid source is never skipped (it reports `not_configured` when no key is set).
    pub expose_emails: bool,
}

impl Default for RecursionPolicy {
    fn default() -> Self {
        let limits = PipelineLimits::default();
        Self {
            max_generations: limits.max_generation,
            expand_confidence_floor: 0.5,
            max_dispatches: limits.max_dispatches,
            max_entities: limits.max_entities,
            max_frontier_per_generation: limits.max_targets,
            expose_emails: true,
        }
    }
}

/// One generation's dispatch and growth, for the latency/depth report.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct GenerationStat {
    pub generation: u32,
    pub dispatched: usize,
    pub entities_after: usize,
}

/// One discovery edge: a dispatched lookup and an entity it produced. Chaining these edges
/// reconstructs the crawl's pivot tree — which lookup surfaced which finding, generation by
/// generation — the linkage a recursive OSINT crawl exists to produce. An entity reached by more
/// than one lookup contributes one edge per lookup, so shared findings are visible, not collapsed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PivotEdge {
    /// The dispatched lookup's kind, as its stable command word.
    pub from_kind: String,
    /// The selector that lookup ran on.
    pub from_selector: String,
    /// The produced entity's kind.
    pub to_kind: String,
    /// The produced entity's value.
    pub to_value: String,
    /// The generation the lookup ran in (seeds are generation 0).
    pub generation: u32,
}

/// The finished crawl: the full entity graph, the pivot lineage, every source outcome, the
/// per-generation shape, and why it stopped.
#[derive(Debug, Clone, PartialEq)]
pub struct RecursionReport {
    pub accepted_seeds: Vec<Target>,
    pub rejected_seeds: Vec<String>,
    pub entities: Vec<Entity>,
    pub edges: Vec<PivotEdge>,
    pub outcomes: Vec<SourceExecutionOutcome>,
    pub generations: Vec<GenerationStat>,
    pub dispatches: usize,
    pub visited: usize,
    pub termination: TerminationReason,
    pub truncated: bool,
}

/// Route a raw seed to a lookup target, or reject it when it canonicalises to nothing.
fn target_for_seed(seed: &str) -> Option<Target> {
    let kind = infer_kind(seed);
    let selector = canonical_selector(kind, seed)?;
    Some(Target { kind, selector })
}

/// The lookup kind an entity of this kind expands into. Two families re-dispatch: the
/// identity-bearing kinds (e-mail, username, domain, phone), and the specific-infrastructure kinds
/// that name one addressable node — an IP address (public-host recon: ASN, geo, open services,
/// reputation) and a MAC/BSSID (one access point on `WiGLE`). Everything else — persons,
/// organisations, URLs, free-text SSIDs, coordinates, credentials, ASNs and the rest — is retained
/// in the graph and reported, but not re-dispatched: a crawl pivots on identity and on a specific
/// node, not on broad or incidental artefacts whose lookup would be noise, not linkage.
fn expansion_kind(kind: &EntityKind) -> Option<ScanKind> {
    match kind {
        EntityKind::Email => Some(ScanKind::Email),
        EntityKind::Username => Some(ScanKind::Username),
        EntityKind::Domain => Some(ScanKind::Domain),
        EntityKind::Phone => Some(ScanKind::Phone),
        EntityKind::IpAddress => Some(ScanKind::Ip),
        EntityKind::MacAddress => Some(ScanKind::Network),
        _ => None,
    }
}

/// The new targets an entity contributes to the next generation.
fn expansions(entity: &Entity, policy: &RecursionPolicy) -> Vec<Target> {
    if entity.confidence < policy.expand_confidence_floor {
        return Vec::new();
    }
    let Some(kind) = expansion_kind(&entity.kind) else {
        return Vec::new();
    };
    let Some(selector) = canonical_selector(kind, &entity.value) else {
        return Vec::new();
    };
    let mut targets = vec![Target {
        kind,
        selector: selector.clone(),
    }];
    if policy.expose_emails && entity.kind == EntityKind::Email {
        if let Some(exposure) = canonical_selector(ScanKind::Exposure, &entity.value) {
            targets.push(Target {
                kind: ScanKind::Exposure,
                selector: exposure,
            });
        }
    }
    targets
}

/// One discovery link projected from the crawl's lineage onto the entity graph: the uid of the
/// entity whose lookup ran and the uid of the entity that lookup produced, weighted by the produced
/// entity's confidence.
#[derive(Debug, Clone, PartialEq)]
pub struct LineageLink {
    pub from_uid: String,
    pub to_uid: String,
    pub confidence: f64,
}

/// Project the crawl's discovery lineage ([`RecursionReport::edges`]) into uid→uid links over the
/// crawl's own entities, so the shared analysis graph reflects the pivots the crawl actually walked
/// — not only the linkage re-derivable from entity content.
///
/// A recursive crawl's value is cross-kind pivoting (phone → e-mail → username → domain → IP). When
/// the reached entities share no handle, address or registrant, content derivation
/// ([`relation::derive_all`](crate::relation::derive_all)) finds no edge between them, so the
/// analysis would report the very entities the crawl pivoted on as unlinked orphans, rank no pivot,
/// and understate the crawl's structure. The lineage holds that linkage authoritatively; this makes
/// it available to the graph.
///
/// Each endpoint is resolved by the SAME routing that recorded the edge — the `from` side by the
/// entity's expansion target ([`expansion_kind`] + [`canonical_selector`]), the `to` side by the
/// produced entity's kind and value — so a link is emitted only when BOTH endpoints are a retained
/// entity. No dangling edge is produced (an edge whose source was a seed never collected as an
/// entity, or whose endpoint was dropped, is skipped) and a self-link is dropped. Pairs reached by
/// several lookups collapse in [`Graph::build`](crate::graph::Graph::build), so repeats here are
/// harmless. Links are sorted and de-duplicated for a deterministic result.
#[must_use]
pub fn lineage_links(report: &RecursionReport) -> Vec<LineageLink> {
    use std::collections::HashMap;
    // The produced entity, by (kind, value) exactly as the edge recorded it.
    let mut by_value: HashMap<(&str, &str), &str> = HashMap::new();
    // The source entity, by (expansion command word, canonical selector) — the inverse of the
    // routing that built the edge's `from` fields.
    let mut by_route: HashMap<(String, String), &str> = HashMap::new();
    let mut confidence: HashMap<&str, f64> = HashMap::new();
    for entity in &report.entities {
        by_value
            .entry((entity.kind.as_str(), entity.value.as_str()))
            .or_insert_with(|| entity.uid.as_str());
        confidence
            .entry(entity.uid.as_str())
            .or_insert(entity.confidence);
        if let Some(kind) = expansion_kind(&entity.kind) {
            if let Some(selector) = canonical_selector(kind, &entity.value) {
                by_route
                    .entry((kind.command().to_owned(), selector))
                    .or_insert_with(|| entity.uid.as_str());
            }
        }
        // Mirror the one secondary expansion target: an e-mail entity also dispatches an exposure
        // lookup (see [`expansions`]), whose edges record `from_kind = exposure` — a route the
        // primary `expansion_kind` inverse never covers. Register it too, so the e-mail → breach /
        // exposure pivots resolve into the graph instead of being dropped as unroutable. Harmless
        // when the policy ran no exposure leg: no such edge then exists to match.
        if entity.kind == EntityKind::Email {
            if let Some(selector) = canonical_selector(ScanKind::Exposure, &entity.value) {
                by_route
                    .entry((ScanKind::Exposure.command().to_owned(), selector))
                    .or_insert_with(|| entity.uid.as_str());
            }
        }
    }
    let mut links: Vec<LineageLink> = Vec::new();
    for edge in &report.edges {
        let Some(&from_uid) = by_route.get(&(edge.from_kind.clone(), edge.from_selector.clone()))
        else {
            continue;
        };
        let Some(&to_uid) = by_value.get(&(edge.to_kind.as_str(), edge.to_value.as_str())) else {
            continue;
        };
        if from_uid == to_uid {
            continue;
        }
        links.push(LineageLink {
            from_uid: from_uid.to_owned(),
            to_uid: to_uid.to_owned(),
            confidence: confidence.get(to_uid).copied().unwrap_or(0.0),
        });
    }
    links.sort_by(|left, right| {
        left.from_uid
            .cmp(&right.from_uid)
            .then_with(|| left.to_uid.cmp(&right.to_uid))
    });
    links.dedup();
    links
}

/// A de-duplicated queue of targets: at most one lookup per `(kind, selector)`. Centralises the
/// crawl's dedup invariant, so the seed frontier, each generation's next frontier, and the
/// expansion queue share one definition of "the same lookup" and cannot drift apart.
#[derive(Default)]
struct Frontier {
    seen: BTreeSet<(String, String)>,
    queue: Vec<Target>,
}

impl Frontier {
    /// Queue `target` unless an equal `(kind, selector)` is already queued. Returns whether it was
    /// newly queued.
    fn push(&mut self, target: Target) -> bool {
        if self.seen.insert(target.owned_key()) {
            self.queue.push(target);
            true
        } else {
            false
        }
    }

    /// Whether this de-duplication key is already queued.
    fn contains_key(&self, key: &(String, String)) -> bool {
        self.seen.contains(key)
    }

    fn len(&self) -> usize {
        self.queue.len()
    }

    fn into_queue(self) -> Vec<Target> {
        self.queue
    }
}

/// One missing lookup result is always an unsuccessful outcome, never an empty success.
fn missing_batch_step(target: &Target, observed_at: u64) -> Step {
    Step {
        entities: Vec::new(),
        outcomes: vec![SourceExecutionOutcome::inconclusive(
            "recursion",
            observed_at,
            format!(
                "collector omitted a {} lookup result for {}",
                target.kind.command(),
                target.selector
            ),
        )],
    }
}

/// Normalize the collector's response count before deterministic, target-ordered reduction.
/// A missing lookup step or an unsolicited extra step is a contract failure, never valid-zero.
fn normalize_batch<C: SelectorCollector>(
    collector: &mut C,
    batch: &[Target],
    mut steps: Vec<Step>,
) -> Vec<Step> {
    let missing = batch.len().saturating_sub(steps.len());
    let excess = steps.len().saturating_sub(batch.len());
    if missing == 0 && excess == 0 {
        return steps;
    }

    collector.on_batch_contract_error(missing.saturating_add(excess));
    let observed_at = clock::unix_now();
    steps.truncate(batch.len());
    for target in batch.iter().skip(steps.len()) {
        steps.push(missing_batch_step(target, observed_at));
    }
    if excess > 0 {
        if let Some(last) = steps.last_mut() {
            last.outcomes.push(SourceExecutionOutcome::inconclusive(
                "recursion",
                observed_at,
                format!(
                    "collector returned {excess} unsolicited results for a batch of {} lookups",
                    batch.len()
                ),
            ));
        }
    }
    steps
}

/// Build the initial frontier: each routable seed becomes a de-duplicated target; an empty or
/// non-routable seed is rejected. Returns (accepted seeds, rejected seeds, frontier).
fn seed_frontier(seeds: &[String]) -> (Vec<Target>, Vec<String>, Vec<Target>) {
    let mut accepted = Vec::new();
    let mut rejected = Vec::new();
    let mut frontier = Frontier::default();
    for seed in seeds {
        match target_for_seed(seed) {
            Some(target) => {
                accepted.push(target.clone());
                frontier.push(target);
            }
            None => rejected.push(seed.clone()),
        }
    }
    (accepted, rejected, frontier.into_queue())
}

/// The accumulating state of one crawl, threaded across generations.
#[derive(Default)]
struct CrawlState {
    visited: BTreeSet<(String, String)>,
    entities: Vec<Entity>,
    edges: Vec<PivotEdge>,
    outcomes: Vec<SourceExecutionOutcome>,
    generations: Vec<GenerationStat>,
    dispatches: usize,
    resource_limited: bool,
    cancelled: bool,
}

impl CrawlState {
    /// Dispatch one generation's frontier and return the next generation's frontier plus whether a
    /// bound stopped this generation mid-way. A dispatch- or entity-budget hit leaves the remaining
    /// targets as admissible work, so the stop resolves to a resource limit, never a false fixed
    /// point.
    fn step<C: SelectorCollector>(
        &mut self,
        generation: u32,
        frontier: Vec<Target>,
        policy: &RecursionPolicy,
        collector: &mut C,
    ) -> (Vec<Target>, bool) {
        // Small waves bound concurrency and let the entity budget be rechecked between waves.
        const MAX_BATCH: usize = 2;
        let mut next = Frontier::default();
        let mut dispatched = 0usize;
        let mut stopped = false;
        let mut remaining = frontier.into_iter().peekable();

        while let Some(first) = remaining.next() {
            if collector.cancelled() {
                self.cancelled = true;
                stopped = true;
                next.push(first);
                for target in remaining.by_ref() {
                    next.push(target);
                }
                break;
            }
            if !self.visited.insert(first.owned_key()) {
                continue;
            }
            if self.dispatches >= policy.max_dispatches
                || self.entities.len() >= policy.max_entities
            {
                self.resource_limited = true;
                stopped = true;
                next.push(first);
                for target in remaining.by_ref() {
                    next.push(target);
                }
                break;
            }

            let mut batch = vec![first];
            while batch.len() < MAX_BATCH {
                // Peek before consuming: dependent targets must remain queued for the next
                // dispatch, where the cancellation and resource limits are checked afresh.
                let Some(candidate) = remaining.peek() else {
                    break;
                };
                if !collector.may_batch(&batch, candidate) {
                    break;
                }
                let Some(target) = remaining.next() else {
                    break;
                };
                if collector.cancelled() {
                    self.cancelled = true;
                    stopped = true;
                    next.push(target);
                    for target in remaining.by_ref() {
                        next.push(target);
                    }
                    break;
                }
                if !self.visited.insert(target.owned_key()) {
                    continue;
                }
                if self.dispatches.saturating_add(batch.len()) >= policy.max_dispatches
                    || self.entities.len() >= policy.max_entities
                {
                    self.resource_limited = true;
                    stopped = true;
                    next.push(target);
                    for target in remaining.by_ref() {
                        next.push(target);
                    }
                    break;
                }
                batch.push(target);
            }

            let steps = collector.collect_batch(&batch);
            let steps = normalize_batch(collector, &batch, steps);
            let mut steps = steps.into_iter();
            for target in batch {
                let step = steps
                    .next()
                    .unwrap_or_else(|| missing_batch_step(&target, 0));
                self.dispatches += 1;
                dispatched += 1;
                self.outcomes.extend(step.outcomes);
                for mut entity in step.entities {
                    entity.generation = generation;
                    self.edges.push(PivotEdge {
                        from_kind: target.kind.command().to_owned(),
                        from_selector: target.selector.clone(),
                        to_kind: entity.kind.as_str().to_owned(),
                        to_value: entity.value.clone(),
                        generation,
                    });
                    self.queue_expansions(&entity, policy, &mut next);
                    self.entities.push(entity);
                }
            }
            stopped |= self.record_post_batch_stop(collector, remaining.by_ref(), &mut next);
            if stopped {
                break;
            }
        }

        merge_by_uid(&mut self.entities);
        self.generations.push(GenerationStat {
            generation,
            dispatched,
            entities_after: self.entities.len(),
        });
        (next.into_queue(), stopped)
    }

    /// Record cancellation after a batch even when no further dispatch remains.
    /// Retain outstanding targets for accurate truncated-frontier accounting.
    fn record_post_batch_stop<C: SelectorCollector>(
        &mut self,
        collector: &C,
        remaining: impl Iterator<Item = Target>,
        next: &mut Frontier,
    ) -> bool {
        if !collector.cancelled() {
            return false;
        }
        self.cancelled = true;
        for target in remaining {
            next.push(target);
        }
        true
    }

    /// Queue the next-generation targets an entity contributes, honouring the per-generation
    /// frontier cap. An overflow is a resource limit, not silently lost work.
    fn queue_expansions(&mut self, entity: &Entity, policy: &RecursionPolicy, next: &mut Frontier) {
        for candidate in expansions(entity, policy) {
            let key = candidate.owned_key();
            // Already dispatched, or already queued for the next generation: skip before the cap
            // check so a duplicate never counts as overflow.
            if self.visited.contains(&key) || next.contains_key(&key) {
                continue;
            }
            if next.len() >= policy.max_frontier_per_generation {
                self.resource_limited = true;
                continue;
            }
            next.push(candidate);
        }
    }
}

/// Run a bounded recursive crawl from `seeds`, dispatching live lookups through `collector`.
///
/// The crawl dispatches each seed, feeds the identity-bearing entities it returns back as the next
/// generation's targets, and repeats until it reaches a fixed point (nothing new to dispatch) or a
/// bound stops it. The stop reason is resolved through the shared termination contract, so a bound
/// that actually halted work is reported as that bound and an exhausted frontier as a true fixed
/// point — a bound is never mislabelled as convergence.
pub fn run<C: SelectorCollector>(
    seeds: &[String],
    policy: &RecursionPolicy,
    collector: &mut C,
) -> RecursionReport {
    let (accepted_seeds, rejected_seeds, frontier) = seed_frontier(seeds);
    crawl(accepted_seeds, rejected_seeds, frontier, policy, collector)
}

/// [`run`] from targets already routed, such as a saved scan's target under the kind its operator
/// chose. Duplicate targets are dispatched once.
pub fn run_targets<C: SelectorCollector>(
    targets: Vec<Target>,
    policy: &RecursionPolicy,
    collector: &mut C,
) -> RecursionReport {
    let mut frontier = Frontier::default();
    for target in &targets {
        frontier.push(target.clone());
    }
    crawl(
        targets,
        Vec::new(),
        frontier.into_queue(),
        policy,
        collector,
    )
}

fn crawl<C: SelectorCollector>(
    accepted_seeds: Vec<Target>,
    rejected_seeds: Vec<String>,
    mut frontier: Vec<Target>,
    policy: &RecursionPolicy,
    collector: &mut C,
) -> RecursionReport {
    let mut state = CrawlState::default();
    let mut generation = 0u32;
    let mut max_depth = false;

    while !frontier.is_empty() {
        if generation > policy.max_generations {
            // The next generation has work the depth bound forbids expanding: a real stop.
            max_depth = true;
            break;
        }
        let (next, stopped) = state.step(generation, frontier, policy, collector);
        frontier = next;
        generation += 1;
        if stopped {
            break;
        }
    }

    let frontier_state = FrontierState {
        admissible_work: frontier.len(),
        ..FrontierState::default()
    };
    let signals = TerminationSignals {
        cancelled: state.cancelled,
        resource_limit_reached: state.resource_limited,
        max_depth_reached: max_depth,
        ..TerminationSignals::default()
    };
    let termination =
        decide_termination(frontier_state, signals).unwrap_or(TerminationReason::FixedPoint);

    RecursionReport {
        accepted_seeds,
        rejected_seeds,
        truncated: state.resource_limited || max_depth || state.cancelled,
        visited: state.visited.len(),
        entities: state.entities,
        edges: state.edges,
        outcomes: state.outcomes,
        generations: state.generations,
        dispatches: state.dispatches,
        termination,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    #[test]
    fn lineage_links_resolve_both_endpoints_or_drop_the_edge() {
        // The crawl pivoted e-mail -> phone. The link must resolve to both entities' uids, weighted
        // by the produced entity's confidence. An edge to a value no retained entity has is dropped,
        // never projected as a dangling graph edge.
        let email = Entity::new(EntityKind::Email, "a@example.com", 0.9, "recurse");
        let mut phone = Entity::new(EntityKind::Phone, "+15551230000", 0.4, "recurse");
        phone.generation = 1;
        let good = PivotEdge {
            from_kind: ScanKind::Email.command().to_owned(),
            from_selector: canonical_selector(ScanKind::Email, &email.value)
                .expect("the e-mail canonicalises"),
            to_kind: phone.kind.as_str().to_owned(),
            to_value: phone.value.clone(),
            generation: 1,
        };
        let dangling = PivotEdge {
            from_kind: ScanKind::Email.command().to_owned(),
            from_selector: canonical_selector(ScanKind::Email, &email.value).unwrap(),
            to_kind: "phone".to_owned(),
            to_value: "+19999999999".to_owned(),
            generation: 1,
        };
        let report = RecursionReport {
            accepted_seeds: Vec::new(),
            rejected_seeds: Vec::new(),
            entities: vec![email.clone(), phone.clone()],
            edges: vec![good, dangling],
            outcomes: Vec::new(),
            generations: Vec::new(),
            dispatches: 0,
            visited: 0,
            termination: TerminationReason::FixedPoint,
            truncated: false,
        };
        let links = lineage_links(&report);
        assert_eq!(
            links.len(),
            1,
            "only the resolvable edge yields a link: {links:?}"
        );
        assert_eq!(links[0].from_uid, email.uid);
        assert_eq!(links[0].to_uid, phone.uid);
        assert!(
            (links[0].confidence - phone.confidence).abs() < f64::EPSILON,
            "the link weight is the produced entity's confidence"
        );
    }

    #[test]
    fn email_exposure_pivot_resolves_through_the_exposure_route() {
        // An e-mail entity dispatches a second lookup — the exposure leg — whose edges record
        // `from_kind = exposure`, not `email`. The lineage projection must invert THAT route too, or
        // every e-mail → breach pivot (the exposure leg's whole output) is dropped and the breach
        // findings orphan in the analysis graph. Baseline (exposure route unregistered): zero links.
        let email = Entity::new(EntityKind::Email, "a@example.com", 0.9, "recurse");
        let mut leaked = Entity::new(EntityKind::Email, "leaked@example.com", 0.5, "recurse");
        leaked.generation = 1;
        let exposure_edge = PivotEdge {
            from_kind: ScanKind::Exposure.command().to_owned(),
            from_selector: canonical_selector(ScanKind::Exposure, &email.value)
                .expect("the e-mail canonicalises as an exposure selector"),
            to_kind: leaked.kind.as_str().to_owned(),
            to_value: leaked.value.clone(),
            generation: 1,
        };
        let report = RecursionReport {
            accepted_seeds: Vec::new(),
            rejected_seeds: Vec::new(),
            entities: vec![email.clone(), leaked.clone()],
            edges: vec![exposure_edge],
            outcomes: Vec::new(),
            generations: Vec::new(),
            dispatches: 0,
            visited: 0,
            termination: TerminationReason::FixedPoint,
            truncated: false,
        };
        let links = lineage_links(&report);
        assert_eq!(
            links.len(),
            1,
            "the exposure-leg pivot resolves to a link: {links:?}"
        );
        assert_eq!(links[0].from_uid, email.uid, "the source is the e-mail");
        assert_eq!(
            links[0].to_uid, leaked.uid,
            "the target is the breach-derived entity"
        );
        assert!(
            (links[0].confidence - leaked.confidence).abs() < f64::EPSILON,
            "the link weight is the produced entity's confidence"
        );
    }

    /// A scripted collector: it returns the entities mapped to each (kind, selector) and records
    /// every dispatch, so a test can assert the exact crawl shape with no network.
    struct Scripted {
        script: BTreeMap<(String, String), Vec<Entity>>,
        calls: Vec<(String, String)>,
    }

    impl Scripted {
        fn new() -> Self {
            Self {
                script: BTreeMap::new(),
                calls: Vec::new(),
            }
        }

        fn on(mut self, kind: ScanKind, selector: &str, entities: Vec<Entity>) -> Self {
            self.script
                .insert((kind.command().to_owned(), selector.to_owned()), entities);
            self
        }
    }

    impl SelectorCollector for Scripted {
        fn collect(&mut self, target: &Target) -> Step {
            self.calls
                .push((target.kind.command().to_owned(), target.selector.clone()));
            let entities = self
                .script
                .get(&(target.kind.command().to_owned(), target.selector.clone()))
                .cloned()
                .unwrap_or_default();
            let found = entities.len();
            Step {
                entities,
                outcomes: vec![SourceExecutionOutcome::success(
                    target.kind.command(),
                    0,
                    found,
                )],
            }
        }
    }

    fn ent(kind: EntityKind, value: &str, confidence: f64) -> Entity {
        Entity::new(kind, value, confidence, "test")
    }

    fn policy() -> RecursionPolicy {
        RecursionPolicy::default()
    }

    /// Asks to stop once `limit` lookups have run, as an operator's stop would.
    struct StopAfter {
        inner: Scripted,
        limit: usize,
    }

    impl SelectorCollector for StopAfter {
        fn collect(&mut self, target: &Target) -> Step {
            self.inner.collect(target)
        }

        fn cancelled(&self) -> bool {
            self.inner.calls.len() >= self.limit
        }
    }

    #[test]
    fn batch_cardinality_violations_remain_visible_as_failed_outcomes() {
        struct BadBatch {
            returned: usize,
            violations: usize,
        }

        impl SelectorCollector for BadBatch {
            fn collect(&mut self, _target: &Target) -> Step {
                Step {
                    entities: Vec::new(),
                    outcomes: Vec::new(),
                }
            }

            fn collect_batch(&mut self, _targets: &[Target]) -> Vec<Step> {
                (0..self.returned)
                    .map(|_| Step {
                        entities: Vec::new(),
                        outcomes: vec![SourceExecutionOutcome::valid_zero("fixture", 1)],
                    })
                    .collect()
            }

            fn on_batch_contract_error(&mut self, violations: usize) {
                self.violations += violations;
            }
        }

        let targets = ["1.1.1.1", "8.8.8.8"]
            .into_iter()
            .map(|selector| Target {
                kind: ScanKind::Ip,
                selector: selector.into(),
            })
            .collect::<Vec<_>>();
        let policy = RecursionPolicy {
            max_generations: 0,
            expose_emails: false,
            ..RecursionPolicy::default()
        };
        for (returned, expected_outcomes) in [(1, 2), (3, 3)] {
            let mut collector = BadBatch {
                returned,
                violations: 0,
            };
            let report = run_targets(targets.clone(), &policy, &mut collector);
            assert_eq!(collector.violations, 1);
            assert_eq!(report.dispatches, 2);
            assert_eq!(report.outcomes.len(), expected_outcomes);
            let violations = report
                .outcomes
                .iter()
                .filter(|outcome| outcome.module == "recursion")
                .collect::<Vec<_>>();
            assert_eq!(violations.len(), 1);
            assert!(!violations[0].kind.is_accepted());
            assert!(violations[0].found.is_none());
            let detail = violations[0].detail.as_deref().unwrap();
            if returned == 1 {
                assert!(detail.contains("omitted"));
                assert!(detail.contains("8.8.8.8"));
            } else {
                assert!(detail.contains("unsolicited"));
                assert!(detail.contains('1'));
            }
        }
    }

    #[test]
    fn cancellation_during_final_batch_is_not_reported_as_fixed_point() {
        let targets = ["1.1.1.1", "8.8.8.8"]
            .into_iter()
            .map(|selector| Target {
                kind: ScanKind::Ip,
                selector: selector.into(),
            })
            .collect();
        let mut collector = StopAfter {
            inner: Scripted::new(),
            limit: 2,
        };
        let report = run_targets(targets, &policy(), &mut collector);
        assert_eq!(report.dispatches, 2);
        assert_eq!(report.termination, TerminationReason::Cancelled);
        assert!(report.truncated);
        assert_eq!(report.visited, 2);
    }

    #[test]
    fn a_cancelled_crawl_stops_before_the_next_dispatch_and_keeps_what_it_found() {
        let inner = Scripted::new().on(
            ScanKind::Domain,
            "example.org",
            vec![
                ent(EntityKind::IpAddress, "203.0.113.9", 0.9),
                ent(EntityKind::Domain, "www.example.org", 0.9),
            ],
        );
        let mut collector = StopAfter { inner, limit: 1 };
        let report = run(&["example.org".to_owned()], &policy(), &mut collector);
        assert_eq!(report.termination, TerminationReason::Cancelled);
        assert!(report.truncated);
        assert_eq!(report.dispatches, 1);
        assert_eq!(report.entities.len(), 2);
        assert_eq!(report.edges.len(), 2);
    }

    #[test]
    fn routed_targets_keep_the_kind_they_were_given_and_run_once() {
        let target = Target {
            kind: ScanKind::Username,
            selector: "example.org".to_owned(),
        };
        let mut collector = Scripted::new();
        let report = run_targets(vec![target.clone(), target], &policy(), &mut collector);
        assert_eq!(
            collector.calls,
            [("username".to_owned(), "example.org".to_owned())]
        );
        assert_eq!(report.termination, TerminationReason::FixedPoint);
        assert_eq!(report.accepted_seeds.len(), 2);
    }

    #[test]
    fn a_converging_crawl_terminates_at_a_fixed_point() {
        // email -> derives a username; the username derives nothing new.
        let mut collector = Scripted::new()
            .on(
                ScanKind::Email,
                "person@example.com",
                vec![
                    ent(EntityKind::Email, "person@example.com", 0.99),
                    ent(EntityKind::Username, "person", 0.8),
                ],
            )
            .on(
                ScanKind::Username,
                "person",
                vec![ent(EntityKind::Username, "person", 0.99)],
            )
            // the exposure pass on the e-mail returns nothing.
            .on(ScanKind::Exposure, "person@example.com", vec![]);

        let report = run(
            &["person@example.com".to_owned()],
            &policy(),
            &mut collector,
        );

        assert_eq!(report.termination, TerminationReason::FixedPoint);
        assert!(!report.truncated);
        assert_eq!(report.rejected_seeds, Vec::<String>::new());
        // email + username, de-duplicated across the two generations.
        assert_eq!(report.entities.len(), 2);
        // the username carries the generation it was first reached at.
        let username = report
            .entities
            .iter()
            .find(|e| e.kind == EntityKind::Username)
            .expect("username entity");
        assert_eq!(username.generation, 0);
        // dispatched: email, exposure(email), username — each once, none twice.
        assert_eq!(report.dispatches, 3);
    }

    #[test]
    fn de_duplication_never_redispatches_a_selector() {
        // Two seeds reach the same username; it must be dispatched once.
        let mut collector = Scripted::new()
            .on(
                ScanKind::Email,
                "a@example.com",
                vec![ent(EntityKind::Username, "shared", 0.9)],
            )
            .on(
                ScanKind::Email,
                "b@example.com",
                vec![ent(EntityKind::Username, "shared", 0.9)],
            )
            .on(ScanKind::Exposure, "a@example.com", vec![])
            .on(ScanKind::Exposure, "b@example.com", vec![])
            .on(ScanKind::Username, "shared", vec![]);

        let report = run(
            &["a@example.com".to_owned(), "b@example.com".to_owned()],
            &policy(),
            &mut collector,
        );

        let shared_dispatches = collector
            .calls
            .iter()
            .filter(|(kind, selector)| kind == "username" && selector == "shared")
            .count();
        assert_eq!(shared_dispatches, 1, "the shared username ran twice");
        assert_eq!(report.termination, TerminationReason::FixedPoint);
    }

    #[test]
    fn an_ip_finding_pivots_into_an_ip_lookup() {
        // A domain lookup surfaces a public IP; the crawl must re-dispatch it as an ip lookup, so
        // infrastructure recon (ASN, geo, services, reputation) runs in the one crawl, the way
        // SpiderFoot cross-correlates host findings rather than leaving them inert.
        let mut collector = Scripted::new()
            .on(
                ScanKind::Domain,
                "example.com",
                vec![ent(EntityKind::IpAddress, "8.8.8.8", 0.9)],
            )
            .on(ScanKind::Ip, "8.8.8.8", vec![]);

        let report = run(&["example.com".to_owned()], &policy(), &mut collector);

        assert!(
            collector
                .calls
                .iter()
                .any(|(kind, selector)| kind == "ip" && selector == "8.8.8.8"),
            "the IP finding was not re-dispatched as an ip lookup"
        );
        assert_eq!(report.termination, TerminationReason::FixedPoint);
    }

    #[test]
    fn a_bssid_finding_pivots_into_a_network_lookup() {
        // A specific MAC/BSSID names one access point, so the crawl re-dispatches it as a network
        // lookup (WiGLE), extending cross-correlation onto infrastructure.
        let mut collector = Scripted::new().on(
            ScanKind::Email,
            "person@example.com",
            vec![ent(EntityKind::MacAddress, "00:11:22:33:44:55", 0.9)],
        );

        let report = run(
            &["person@example.com".to_owned()],
            &policy(),
            &mut collector,
        );

        assert!(
            collector.calls.iter().any(|(kind, _)| kind == "network"),
            "the BSSID finding was not re-dispatched as a network lookup"
        );
        assert_eq!(report.termination, TerminationReason::FixedPoint);
    }

    #[test]
    fn incidental_artefacts_are_retained_but_not_dispatched() {
        // Broad or non-addressable findings stay in the graph and are reported, but the crawl does
        // not fan out a lookup for each: no SSID, coordinate, URL or person re-dispatch. This is
        // the discipline that keeps breadth from becoming noise — surpassing SpiderFoot, not just
        // matching its reach.
        let mut collector = Scripted::new()
            .on(
                ScanKind::Email,
                "person@example.com",
                vec![
                    ent(EntityKind::Email, "person@example.com", 0.99),
                    ent(EntityKind::Ssid, "linksys", 0.9),
                    ent(EntityKind::Coordinates, "40.712800,-74.006000", 0.9),
                    ent(EntityKind::Url, "https://example.com/a", 0.9),
                    ent(EntityKind::Person, "Jane Doe", 0.9),
                ],
            )
            .on(ScanKind::Exposure, "person@example.com", vec![]);

        let report = run(
            &["person@example.com".to_owned()],
            &policy(),
            &mut collector,
        );

        // Only the seed e-mail and its exposure pass ran; no incidental artefact was dispatched.
        let dispatched_kinds: std::collections::BTreeSet<&str> = collector
            .calls
            .iter()
            .map(|(kind, _)| kind.as_str())
            .collect();
        assert_eq!(
            dispatched_kinds,
            ["email", "exposure"].into_iter().collect()
        );
        // The incidental entities are retained and reported, never dropped.
        assert_eq!(report.entities.len(), 5);
        assert_eq!(report.termination, TerminationReason::FixedPoint);
    }

    #[test]
    fn the_report_records_the_pivot_lineage() {
        // email -> username (generation 0), then username -> domain (generation 1). The edges must
        // reconstruct that path: which lookup surfaced which finding, and in which generation.
        let mut collector = Scripted::new()
            .on(
                ScanKind::Email,
                "person@example.com",
                vec![ent(EntityKind::Username, "person", 0.9)],
            )
            .on(ScanKind::Exposure, "person@example.com", vec![])
            .on(
                ScanKind::Username,
                "person",
                vec![ent(EntityKind::Domain, "example.net", 0.9)],
            )
            .on(ScanKind::Domain, "example.net", vec![]);

        let report = run(
            &["person@example.com".to_owned()],
            &policy(),
            &mut collector,
        );

        assert!(
            report.edges.iter().any(|edge| edge.from_kind == "email"
                && edge.from_selector == "person@example.com"
                && edge.to_kind == "username"
                && edge.to_value == "person"
                && edge.generation == 0),
            "missing the email -> username discovery edge"
        );
        assert!(
            report.edges.iter().any(|edge| edge.from_kind == "username"
                && edge.from_selector == "person"
                && edge.to_kind == "domain"
                && edge.to_value == "example.net"
                && edge.generation == 1),
            "missing the username -> domain discovery edge"
        );
        assert_eq!(report.termination, TerminationReason::FixedPoint);
    }

    #[test]
    fn an_endless_chain_stops_at_the_depth_bound() {
        // Every username derives a fresh one, forever. A real engine would never converge; the
        // depth bound must stop it and report MaxDepth, not a fixed point.
        struct Endless;
        impl SelectorCollector for Endless {
            fn collect(&mut self, target: &Target) -> Step {
                let next = format!("{}x", target.selector);
                Step {
                    entities: vec![ent(EntityKind::Username, &next, 0.9)],
                    outcomes: vec![SourceExecutionOutcome::success("endless", 0, 1)],
                }
            }
        }
        let mut collector = Endless;
        let policy = RecursionPolicy {
            max_generations: 3,
            expose_emails: false,
            ..RecursionPolicy::default()
        };
        let report = run(&["@seed".to_owned()], &policy, &mut collector);
        assert_eq!(report.termination, TerminationReason::MaxDepth);
        assert!(report.truncated);
        // generation 0 (seed) plus three expansion hops.
        assert_eq!(report.generations.len(), 4);
    }

    #[test]
    fn a_dispatch_budget_is_a_resource_limit_not_convergence() {
        struct Fanout;
        impl SelectorCollector for Fanout {
            fn collect(&mut self, target: &Target) -> Step {
                // each lookup yields two fresh usernames.
                let a = format!("{}a", target.selector);
                let b = format!("{}b", target.selector);
                Step {
                    entities: vec![
                        ent(EntityKind::Username, &a, 0.9),
                        ent(EntityKind::Username, &b, 0.9),
                    ],
                    outcomes: vec![SourceExecutionOutcome::success("fanout", 0, 2)],
                }
            }
        }
        let mut collector = Fanout;
        let policy = RecursionPolicy {
            max_generations: 100,
            max_dispatches: 3,
            expose_emails: false,
            ..RecursionPolicy::default()
        };
        let report = run(&["@seed".to_owned()], &policy, &mut collector);
        assert_eq!(report.termination, TerminationReason::ResourceLimit);
        assert!(report.truncated);
        assert_eq!(report.dispatches, 3);
    }

    #[test]
    fn a_low_confidence_entity_is_not_expanded() {
        let mut collector = Scripted::new()
            .on(
                ScanKind::Email,
                "person@example.com",
                vec![ent(EntityKind::Username, "weak", 0.2)],
            )
            .on(ScanKind::Exposure, "person@example.com", vec![]);
        let policy = RecursionPolicy {
            expand_confidence_floor: 0.5,
            ..RecursionPolicy::default()
        };
        let report = run(&["person@example.com".to_owned()], &policy, &mut collector);
        // the weak username is retained but never dispatched.
        assert!(
            !collector
                .calls
                .iter()
                .any(|(kind, selector)| kind == "username" && selector == "weak")
        );
        assert_eq!(report.termination, TerminationReason::FixedPoint);
        assert!(
            report
                .entities
                .iter()
                .any(|e| e.kind == EntityKind::Username && e.value == "weak")
        );
    }

    #[test]
    fn an_email_also_runs_the_keyed_exposure_pass() {
        let mut collector = Scripted::new()
            .on(
                ScanKind::Email,
                "person@example.com",
                vec![ent(EntityKind::Email, "person@example.com", 0.99)],
            )
            .on(ScanKind::Exposure, "person@example.com", vec![]);
        let report = run(
            &["person@example.com".to_owned()],
            &policy(),
            &mut collector,
        );
        assert!(
            collector
                .calls
                .iter()
                .any(|(kind, selector)| kind == "exposure" && selector == "person@example.com"),
            "the exposure pass did not run on the e-mail"
        );
        assert_eq!(report.termination, TerminationReason::FixedPoint);
    }

    #[test]
    fn an_empty_seed_is_rejected_and_the_run_is_a_fixed_point() {
        let mut collector = Scripted::new();
        let report = run(&["   ".to_owned()], &policy(), &mut collector);
        assert_eq!(report.rejected_seeds, vec!["   ".to_owned()]);
        assert_eq!(report.accepted_seeds, Vec::new());
        assert_eq!(report.dispatches, 0);
        assert_eq!(report.termination, TerminationReason::FixedPoint);
    }

    #[test]
    fn seeds_run_even_with_no_expansion_budget() {
        let mut collector = Scripted::new().on(
            ScanKind::Email,
            "person@example.com",
            vec![ent(EntityKind::Username, "person", 0.9)],
        );
        let policy = RecursionPolicy {
            max_generations: 0,
            expose_emails: false,
            ..RecursionPolicy::default()
        };
        let report = run(&["person@example.com".to_owned()], &policy, &mut collector);
        // the seed dispatched; the derived username is queued but the depth bound forbids it.
        assert_eq!(report.dispatches, 1);
        assert_eq!(report.termination, TerminationReason::MaxDepth);
    }
}
