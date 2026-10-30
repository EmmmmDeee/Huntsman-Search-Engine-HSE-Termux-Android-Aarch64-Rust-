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

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::canonical::handle_route_key;
use crate::clock;
use crate::entity::{Entity, EntityKind, Evidence, merge_by_uid};
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
    /// the same dispatch. A handle is keyed by how it is routed ([`handle_route_key`]: ASCII case
    /// folded, separators kept), as the planner routes seeds, so a platform's echo of a handle in
    /// another case is not looked up again while `pg-smith` and `pg_smith`, which can be two
    /// accounts, are both looked up. `ScanKind` is not `Ord`, so its stable command word carries
    /// the order.
    fn owned_key(&self) -> (String, String) {
        let selector = match self.kind {
            ScanKind::Username => handle_route_key(&self.selector),
            _ => self.selector.clone(),
        };
        (self.kind.command().to_owned(), selector)
    }
}

/// The identity a routed selector names: the key the entity a lookup of it describes carries, so
/// an edge recorded under any spelling of one identity resolves to that entity. A username's
/// identity is its entity key ([`crate::entity::normalise`]: case and `.`, `_` and `-` folded);
/// every other route's canonical selector already is its identity. **Pure.**
#[must_use]
pub fn selector_identity(kind: ScanKind, selector: &str) -> String {
    match kind {
        ScanKind::Username => crate::entity::normalise(&EntityKind::Username, selector),
        _ => selector.to_owned(),
    }
}

/// What a collector observed for one target. A failed lookup still returns `outcomes` describing
/// why (auth required, connect failure, …): the driver records every dispatch, so a source is
/// never silently dropped from the recursion.
pub struct Step {
    pub entities: Vec<Entity>,
    pub outcomes: Vec<SourceExecutionOutcome>,
}

/// Everything the crawl holds after one wave of lookups: what a checkpoint of a running scan
/// saves, so a process that dies mid-crawl loses at most the wave in flight. The entities of the
/// current generation are not yet merged by uid (that happens when the generation ends), so a
/// reader that needs one record per entity merges a copy.
pub struct CrawlProgress<'a> {
    pub entities: &'a [Entity],
    pub edges: &'a [PivotEdge],
    pub outcomes: &'a [SourceExecutionOutcome],
    /// The generation whose wave just completed.
    pub generation: u32,
    /// Lookups dispatched so far, this wave included.
    pub dispatches: usize,
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

    /// Called after each wave of lookups is reduced into the crawl, with everything found so far.
    /// A collector that persists scans checkpoints here, so what a crawl has found survives the
    /// process dying before the crawl ends. The default keeps nothing.
    fn progressed(&mut self, _progress: &CrawlProgress<'_>) {}
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
            expand_confidence_floor: crate::gap::EXPAND_FLOOR,
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

impl PivotEdge {
    /// The identity of the lookup this edge was recorded under ([`selector_identity`] on its
    /// route), so an edge recorded under any spelling of one identity, by this crawl or in a scan
    /// saved before it, resolves to the same source. An unknown route keeps its selector.
    #[must_use]
    pub fn from_identity(&self) -> String {
        crate::scan_route::parse_kind(&self.from_kind).map_or_else(
            |_| self.from_selector.clone(),
            |kind| selector_identity(kind, &self.from_selector),
        )
    }
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

/// Whether an address can stand for whoever holds it. A role mailbox (`abuse@`, `hostmaster@`,
/// `info@`), a mail or hosting provider's own address, or a no-reply address names a function or
/// a service, so looking it up, or its breach exposure, finds that service rather than a person:
/// such an address stays in the graph and the report but is not dispatched. **Pure.**
fn names_a_mailbox_holder(email: &str) -> bool {
    !crate::domains::is_infrastructure_email(email)
        && !crate::domains::is_noreply_email_domain(email)
}

/// The selectors `entity` is followed by on `kind`'s route. A username is followed by every
/// spelling a source observed it under ([`Entity::observed_spellings`]) whose own confidence
/// reaches FLOOR, its `raw_value` first, each through the route's own rule as an operator's
/// selector is, once per [`handle_route_key`]. Its identity key lowercases and strips separators
/// so that `Ada-L` and `adal` share one entity, and following the key would look up an account
/// nobody observed where handles are case- or separator-sensitive (Hacker News, GitHub). A
/// username no observation of which reaches the floor, as one only guessed from an e-mail's local
/// part, is followed by its identity key, the separator-free form most platforms accept. The
/// handle a lookup was asked (its operator-seed record, which every lookup echoes back) was already
/// looked up: it is followed by what sources observed, never by the key. The crawl routes a pivot
/// lookup's echo before it forgets it ([`forget_pivot_echo`]), so this holds for a pivot too. Every other route follows the entity's canonical value. Edges resolve by
/// [`selector_identity`], so what each lookup finds joins the same entity. **Pure.**
fn route_selectors(kind: ScanKind, entity: &Entity, floor: f64) -> Vec<String> {
    if kind == ScanKind::Username && entity.kind == EntityKind::Username {
        let own = entity.raw_value.trim().trim_start_matches('@');
        let mut spellings: Vec<(String, f64)> = entity.observed_spellings().into_iter().collect();
        spellings.sort_by_key(|(spelling, _)| spelling != own);
        let mut routes = BTreeSet::new();
        let observed: Vec<String> = spellings
            .into_iter()
            .filter(|(_, confidence)| *confidence >= floor)
            .filter_map(|(spelling, _)| canonical_selector(kind, &spelling))
            .filter(|selector| routes.insert(handle_route_key(selector)))
            .collect();
        if !observed.is_empty() || entity.evidence.iter().any(Evidence::is_operator_seed) {
            return observed;
        }
    }
    canonical_selector(kind, &entity.value)
        .into_iter()
        .collect()
}

/// The new targets an entity contributes to the next generation.
fn expansions(entity: &Entity, policy: &RecursionPolicy) -> Vec<Target> {
    // A pivot that matched only by a name search — a Wikidata knowledge-base, ACNC
    // charity-register or SEC EDGAR filer hit resolved from a name alone — is a lead to review,
    // not an identity match. Its published handles/domains remain visible leads but are never
    // dispatched, even when an operator lowers the confidence floor; that setting must not
    // bypass attribution.
    // Historical saved scans may still contain the former Wikidata-specific tag.
    // Preserve the attribution gate for those records without emitting the old tag anew.
    if entity.has_tag(crate::tags::NAME_SEARCH_LEAD) || entity.has_tag("wikidata-name-lead") {
        return Vec::new();
    }
    if entity.confidence < policy.expand_confidence_floor {
        return Vec::new();
    }
    let Some(kind) = expansion_kind(&entity.kind) else {
        return Vec::new();
    };
    if entity.kind == EntityKind::Email && !names_a_mailbox_holder(&entity.value) {
        return Vec::new();
    }
    let floor = policy.expand_confidence_floor;
    let selectors = route_selectors(kind, entity, floor);
    // A value its own route refuses is not followed at all, its exposure included: an e-mail with
    // no address in it (`noemail`, a bare login a breach record put in its e-mail field) would
    // otherwise be looked up as the username the exposure route falls back to.
    if selectors.is_empty() {
        return Vec::new();
    }
    let mut targets: Vec<Target> = selectors
        .into_iter()
        .map(|selector| Target { kind, selector })
        .collect();
    if policy.expose_emails && entity.kind == EntityKind::Email {
        targets.extend(
            route_selectors(ScanKind::Exposure, entity, floor)
                .into_iter()
                .map(|selector| Target {
                    kind: ScanKind::Exposure,
                    selector,
                }),
        );
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
/// identity of the entity's expansion target ([`expansion_kind`] + [`selector_identity`], so any
/// spelling the lookup ran under resolves), the `to` side by the produced entity's kind and value
/// — so a link is emitted only when BOTH endpoints are a retained entity. No dangling edge is produced (an edge whose source was a seed never collected as an
/// entity, or whose endpoint was dropped, is skipped) and a self-link is dropped. Pairs reached by
/// several lookups collapse in [`Graph::build`](crate::graph::Graph::build), so repeats here are
/// harmless. Links are sorted and de-duplicated for a deterministic result.
#[must_use]
pub fn lineage_links(report: &RecursionReport) -> Vec<LineageLink> {
    use std::collections::HashMap;
    // The produced entity, by (kind, value) exactly as the edge recorded it.
    let mut by_value: HashMap<(&str, &str), &str> = HashMap::new();
    // The source entity, by (expansion command word, selector identity) — the inverse of the
    // routing that built the edge's `from` fields, whichever spelling it dispatched.
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
                    .entry((
                        kind.command().to_owned(),
                        selector_identity(kind, &selector),
                    ))
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
        let Some(&from_uid) = by_route.get(&(edge.from_kind.clone(), edge.from_identity())) else {
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

/// A de-duplicated queue of targets: at most one lookup per `(kind, selector identity)`.
/// Centralises the crawl's dedup invariant, so the seed frontier, each generation's next frontier, and the
/// expansion queue share one definition of "the same lookup" and cannot drift apart.
#[derive(Default)]
struct Frontier {
    seen: BTreeSet<(String, String)>,
    queue: Vec<Target>,
}

impl Frontier {
    /// Queue `target` unless one with an equal `(kind, selector identity)` is already queued.
    /// Returns whether it was newly queued.
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
    /// The highest confidence of any entity a queued target was followed from, by its key: what a
    /// pivot's lookup may hold it at, as the lookup's echo of its selector says nothing of it. An
    /// echo is followed from at no more than the pivot it echoes ([`pivot_held_at`]).
    followed_at: BTreeMap<(String, String), f64>,
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
                dispatched += 1;
                self.take_step(generation, &target, step, policy, &mut next);
            }
            stopped |= self.batch_done(collector, generation, remaining.by_ref(), &mut next);
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

    /// Reduce what one dispatch of `target` returned into the crawl: its outcomes, and each entity
    /// with the edge it was reached by and the targets it queues for the next generation. Each
    /// entity is routed and recorded as the lookup returned it, so a lookup's echo of its own
    /// selector still says that selector was looked up ([`route_selectors`]) and still shows the
    /// lookup in the lineage. Generation 0 is the operator's seeds; every later target is a pivot
    /// the crawl found, whose echo is then not kept as the operator's seed ([`forget_pivot_echo`]),
    /// and what each entity queues is followed at the confidence it is kept at ([`pivot_held_at`]).
    fn take_step(
        &mut self,
        generation: u32,
        target: &Target,
        step: Step,
        policy: &RecursionPolicy,
        next: &mut Frontier,
    ) {
        let followed_at = (generation > 0).then(|| {
            self.followed_at
                .get(&target.owned_key())
                .copied()
                .unwrap_or(policy.expand_confidence_floor)
        });
        self.dispatches += 1;
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
            let held_at = followed_at.map_or(entity.confidence, |followed_at| {
                pivot_held_at(&entity, followed_at)
            });
            self.queue_expansions(&entity, held_at, policy, next);
            if let Some(followed_at) = followed_at {
                if !forget_pivot_echo(&mut entity, followed_at) {
                    continue;
                }
            }
            self.entities.push(entity);
        }
    }

    /// After a wave is reduced into the crawl: let the collector checkpoint what the crawl holds,
    /// then record a stop requested meanwhile.
    fn batch_done<C: SelectorCollector>(
        &mut self,
        collector: &mut C,
        generation: u32,
        remaining: impl Iterator<Item = Target>,
        next: &mut Frontier,
    ) -> bool {
        collector.progressed(&CrawlProgress {
            entities: &self.entities,
            edges: &self.edges,
            outcomes: &self.outcomes,
            generation,
            dispatches: self.dispatches,
        });
        self.record_post_batch_stop(collector, remaining, next)
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

    /// Queue the next-generation targets an entity held at `held_at` contributes, honouring the
    /// per-generation frontier cap. An overflow is a resource limit, not silently lost work.
    fn queue_expansions(
        &mut self,
        entity: &Entity,
        held_at: f64,
        policy: &RecursionPolicy,
        next: &mut Frontier,
    ) {
        for candidate in expansions(entity, policy) {
            let key = candidate.owned_key();
            // Already dispatched, or already queued for the next generation: skip before the cap
            // check so a duplicate never counts as overflow. A queued target is still followed
            // at the highest confidence any entity gave it.
            if self.visited.contains(&key) {
                continue;
            }
            if next.contains_key(&key) {
                self.follow_at(key, held_at);
                continue;
            }
            if next.len() >= policy.max_frontier_per_generation {
                self.resource_limited = true;
                continue;
            }
            self.follow_at(key, held_at);
            next.push(candidate);
        }
    }

    /// Record that the target keyed `key` is followed from an entity held at `confidence`.
    fn follow_at(&mut self, key: (String, String), confidence: f64) {
        let held = self.followed_at.entry(key).or_insert(confidence);
        *held = held.max(confidence);
    }
}

/// Forget a pivot lookup's echo of its selector in `entity`, and say whether anything is left to
/// keep. Every lookup echoes its selector back as the operator's seed: tagged `seed`, at the seed's
/// confidence, with a seed record ([`Evidence::is_operator_seed`]). A pivot was found by the crawl, not supplied by the
/// operator, and its echo would fold into the entity it was followed from, so a weak lead (a handle
/// guessed from an e-mail's local part) would leave the crawl as the operator's own seed at 0.99.
/// The echo's records and tag are not kept, nor counted as observations. An echo holding nothing
/// else is not kept at all, as the crawl already holds the entity it was followed from; one a source
/// also described keeps what the source said, at no more than `followed_at`, the confidence the
/// crawl followed it at. An entity with no operator-seed record is kept as it is. **Pure.**
fn forget_pivot_echo(entity: &mut Entity, followed_at: f64) -> bool {
    if !entity.evidence.iter().any(Evidence::is_operator_seed) {
        return true;
    }
    let held_at = pivot_held_at(entity, followed_at);
    // Each echo the lookup folded in was one observation of the entity; none was a source's.
    let echoes: u32 = entity
        .evidence
        .iter()
        .filter(|evidence| evidence.is_operator_seed())
        .map(|evidence| 1 + u32::try_from(evidence.merged_provenance.len()).unwrap_or(u32::MAX))
        .fold(0, u32::saturating_add);
    entity
        .evidence
        .retain(|evidence| !evidence.is_operator_seed());
    entity.tags.retain(|tag| tag != "seed");
    entity.confidence = held_at;
    entity.corroboration = entity.corroboration.saturating_sub(echoes).max(1);
    !entity.evidence.is_empty()
}

/// The confidence a pivot lookup's `entity` is held at once its echo is forgotten
/// ([`forget_pivot_echo`]): an echo at no more than `followed_at`, the confidence the crawl followed
/// the pivot at, and any other entity at its own. What it queues is followed at the same, so a
/// target an echo queues is never held above the pivot either. **Pure.**
fn pivot_held_at(entity: &Entity, followed_at: f64) -> f64 {
    if entity.evidence.iter().any(Evidence::is_operator_seed) {
        entity.confidence.min(followed_at)
    } else {
        entity.confidence
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
    fn a_username_pivot_is_followed_by_the_spelling_it_was_observed_with() {
        // The identity key of `PG_Smith` is `pgsmith`, another account where handles are case-
        // or separator-sensitive (Hacker News, GitHub): the pivot is followed as observed.
        let observed = ent(EntityKind::Username, "PG_Smith", 0.9);
        assert_eq!(observed.value, "pgsmith");
        assert_eq!(
            expansions(&observed, &policy()),
            vec![Target {
                kind: ScanKind::Username,
                selector: "PG_Smith".to_owned(),
            }]
        );
        let mut collector = Scripted::new()
            .on(
                ScanKind::Email,
                "person@example.com",
                vec![
                    ent(EntityKind::Email, "person@example.com", 0.99),
                    ent(EntityKind::Username, "PG_Smith", 0.8),
                ],
            )
            .on(ScanKind::Exposure, "person@example.com", vec![])
            .on(
                ScanKind::Username,
                "PG_Smith",
                vec![ent(EntityKind::Domain, "pg-smith.example", 0.7)],
            );
        let report = run(
            &["person@example.com".to_owned()],
            &policy(),
            &mut collector,
        );
        assert!(
            collector
                .calls
                .contains(&("username".to_owned(), "PG_Smith".to_owned()))
        );
        assert!(
            !collector
                .calls
                .iter()
                .any(|(kind, selector)| kind == "username" && selector == "pgsmith"),
            "the identity key must never be looked up as a handle"
        );
        // The edge the dispatch recorded resolves back to the username entity, so the graph links
        // the handle to what its lookup found.
        let username = report
            .entities
            .iter()
            .find(|entity| entity.kind == EntityKind::Username)
            .expect("username entity");
        let domain = report
            .entities
            .iter()
            .find(|entity| entity.kind == EntityKind::Domain)
            .expect("domain entity");
        assert!(
            lineage_links(&report)
                .iter()
                .any(|link| link.from_uid == username.uid && link.to_uid == domain.uid),
            "the username's edge must resolve to the entity it produced"
        );
    }

    #[test]
    fn a_username_guessed_from_an_email_is_followed_by_its_identity_key() {
        // An e-mail's local part yields permutations (`jane.doe`, `jane_doe`, `janedoe`) that merge
        // into one entity, so whichever merged first is no observation. The guess is followed by
        // its identity key, the separator-free form most platforms accept, never by a separator
        // spelling no source observed.
        let mut guessed = ent(EntityKind::Username, "jane.doe", 0.6);
        guessed.add_evidence(
            crate::entity::Evidence::new(
                crate::entity::EvidenceProvenance::for_scan("email_parse", "test"),
                "local part of jane.doe@acme.example",
            )
            .inferred(),
        );
        assert_eq!(guessed.value, "janedoe");
        assert_eq!(
            expansions(&guessed, &policy()),
            vec![Target {
                kind: ScanKind::Username,
                selector: "janedoe".to_owned(),
            }]
        );
    }

    #[test]
    fn only_a_username_is_followed_by_its_observed_spelling() {
        // Every other route follows the entity's value, which its producer normalised with context
        // the raw text may lack: a UK number written nationally has no country code of its own.
        let mut phone = ent(EntityKind::Phone, "+442079460958", 0.8);
        phone.raw_value = "020 7946 0958".to_owned();
        let followed = route_selectors(ScanKind::Phone, &phone, 0.0);
        assert_eq!(
            followed,
            canonical_selector(ScanKind::Phone, &phone.value)
                .into_iter()
                .collect::<Vec<_>>()
        );
        assert_eq!(followed.len(), 1);
        assert_ne!(
            followed.first().cloned(),
            canonical_selector(ScanKind::Phone, &phone.raw_value)
        );
    }

    /// A record a source observed, as a username producer adds one.
    fn observed(kind: EntityKind, value: &str, source: &str) -> Entity {
        let mut entity = ent(kind, value, 0.8);
        entity.add_evidence(crate::entity::Evidence::new(
            crate::entity::EvidenceProvenance::for_scan(source, "test"),
            format!("{source} reports {value}"),
        ));
        entity
    }

    #[test]
    fn separator_spellings_of_a_handle_are_each_looked_up() {
        // `pg-smith` and `pg_smith` share an identity key but can be two accounts where a platform
        // keeps separators; the planner routes each, and so does the crawl, while seeds that
        // differ only in case are one lookup.
        let mut collector = Scripted::new();
        let report = run(
            &[
                "@pg-smith".to_owned(),
                "@pg_smith".to_owned(),
                "@PG_SMITH".to_owned(),
            ],
            &policy(),
            &mut collector,
        );
        let handles: Vec<&str> = collector
            .calls
            .iter()
            .filter(|(kind, _)| kind == "username")
            .map(|(_, selector)| selector.as_str())
            .collect();
        assert_eq!(handles, ["pg-smith", "pg_smith"]);
        assert_eq!(report.dispatches, 2);
    }

    #[test]
    fn every_spelling_a_handle_was_observed_under_is_followed_above_the_floor() {
        // Gravatar names a profile's own handle and a verified GitHub account under another
        // spelling of one identity, with one source and summary, so the two merge into one
        // record. Both are followed, the entity's own spelling first; GitHub refuses `pg_smith`
        // as a login, so only the account's own spelling reaches it.
        let gravatar = |value: &str, confidence: f64| {
            let mut entity = ent(EntityKind::Username, value, confidence);
            entity.add_evidence(crate::entity::Evidence::new(
                crate::entity::EvidenceProvenance::for_scan("gravatar", "test"),
                "Gravatar public profile",
            ));
            entity
        };
        let mut profile = gravatar("pg_smith", 0.8);
        profile.absorb(gravatar("PGSmith", 0.8));
        assert_eq!(profile.evidence.len(), 1, "the records merge");
        let handles = |entity: &Entity, policy: &RecursionPolicy| -> Vec<String> {
            expansions(entity, policy)
                .into_iter()
                .map(|target| target.selector)
                .collect()
        };
        assert_eq!(handles(&profile, &policy()), ["pg_smith", "PGSmith"]);
        // A spelling observed only below the operator's floor is not followed on another's
        // strength.
        let mut handle = gravatar("pgsmith", 0.9);
        handle.absorb(gravatar("pg_smith", 0.5));
        let floor = RecursionPolicy {
            expand_confidence_floor: 0.75,
            ..policy()
        };
        assert_eq!(handles(&handle, &floor), ["pgsmith"]);
        // In a crawl, a lookup's echo of the handle it was asked for is not looked up again, but
        // another spelling merged into the echo is.
        let mut echo = observed(EntityKind::Username, "pg-smith", "github_user");
        echo.absorb(observed(EntityKind::Username, "pgsmith", "github_twitter"));
        let mut collector = Scripted::new().on(ScanKind::Username, "pg-smith", vec![echo]);
        let report = run(&["@pg-smith".to_owned()], &policy(), &mut collector);
        let looked_up: Vec<&str> = collector
            .calls
            .iter()
            .filter(|(kind, _)| kind == "username")
            .map(|(_, selector)| selector.as_str())
            .collect();
        assert_eq!(looked_up, ["pg-smith", "pgsmith"]);
        assert_eq!(report.dispatches, 2);
    }

    #[test]
    fn an_observed_handle_merged_behind_email_guesses_is_followed_as_observed() {
        // An e-mail's local-part guess (`pg-smith`, inferred) merges with Gravatar's verified
        // `PG_Smith`; the entity keeps the guess's `raw_value`, but only the observed spelling,
        // case included, is followed, never the guess or the identity key `pgsmith`.
        let mut guess = ent(EntityKind::Username, "pg-smith", 0.55);
        guess.add_evidence(
            crate::entity::Evidence::new(
                crate::entity::EvidenceProvenance::for_scan("email_parse", "test"),
                "local part of pg.smith@example.com",
            )
            .inferred(),
        );
        guess.absorb(observed(EntityKind::Username, "PG_Smith", "gravatar"));
        assert_eq!(guess.raw_value, "pg-smith");
        assert_eq!(
            expansions(&guess, &policy()),
            vec![Target {
                kind: ScanKind::Username,
                selector: "PG_Smith".to_owned(),
            }]
        );
        // An observation below the operator's floor is not followed on the guesses' strength;
        // the guesses alone are followed as guesses are, by the identity key.
        let mut strong_guess = ent(EntityKind::Username, "pg-smith", 0.7);
        strong_guess.add_evidence(
            crate::entity::Evidence::new(
                crate::entity::EvidenceProvenance::for_scan("email_parse", "test"),
                "local part of pg.smith@example.com",
            )
            .inferred(),
        );
        let mut weak = observed(EntityKind::Username, "PG_Smith", "gravatar");
        weak.confidence = 0.65;
        strong_guess.absorb(weak);
        let floor = RecursionPolicy {
            expand_confidence_floor: 0.68,
            ..policy()
        };
        assert_eq!(
            expansions(&strong_guess, &floor),
            vec![Target {
                kind: ScanKind::Username,
                selector: "pgsmith".to_owned(),
            }]
        );
    }

    /// The entity a username lookup returns for the selector it was asked, as every lookup the
    /// crawl dispatches returns one (`username_cli`'s seed).
    fn asked(value: &str) -> Entity {
        let mut entity = ent(EntityKind::Username, value, 0.99);
        entity.tag("seed");
        entity.add_evidence(crate::entity::Evidence::new(
            crate::entity::EvidenceProvenance::for_scan("seed", "test"),
            "username selector the lookup was asked",
        ));
        entity
    }

    /// A username guessed from an e-mail's local part, as `email_cli` derives one.
    fn guessed(value: &str) -> Entity {
        let mut entity = ent(EntityKind::Username, value, 0.7);
        entity.add_evidence(
            crate::entity::Evidence::new(
                crate::entity::EvidenceProvenance::for_scan("email_parse", "test"),
                "local part of pg.smith@corp.example",
            )
            .inferred(),
        );
        entity
    }

    /// A pivot is something the crawl found, so the lookup of it echoing it back as the
    /// operator's seed never makes it one: a handle guessed from an e-mail's local part leaves the
    /// crawl at the confidence it was followed at, untagged and with no seed record,
    /// keeping what a source said of it. The operator's own e-mail stays the seed.
    #[test]
    fn a_pivot_the_crawl_found_never_leaves_it_as_the_operators_seed() {
        let email = "pg.smith@corp.example";
        let mailbox_only = RecursionPolicy {
            expose_emails: false,
            ..policy()
        };
        let mut seed = ent(EntityKind::Email, email, 0.99);
        seed.tag("seed");
        seed.add_evidence(crate::entity::Evidence::new(
            crate::entity::EvidenceProvenance::for_scan("seed", "test"),
            "email selector the lookup was asked",
        ));
        let find = |report: &RecursionReport, kind: EntityKind| -> Entity {
            report
                .entities
                .iter()
                .find(|entity| entity.kind == kind)
                .cloned()
                .unwrap_or_else(|| panic!("no {kind:?} in {:?}", report.entities))
        };
        let operators = |entity: &Entity| entity.evidence.iter().any(Evidence::is_operator_seed);

        // The lookup of the guess echoes it alone, and a source then describes it.
        let mut described = asked("pgsmith");
        described.absorb(observed(EntityKind::Username, "pgsmith", "github"));
        for echo in [asked("pgsmith"), described] {
            let mut collector = Scripted::new()
                .on(
                    ScanKind::Email,
                    email,
                    vec![seed.clone(), guessed("pg-smith")],
                )
                .on(ScanKind::Username, "pgsmith", vec![echo.clone()]);
            let report = run(&[email.to_owned()], &mailbox_only, &mut collector);
            let handle = find(&report, EntityKind::Username);
            assert!(!operators(&handle), "{handle:?}");
            assert!(!handle.has_tag("seed"), "{handle:?}");
            assert!(handle.confidence <= 0.7, "{handle:?}");
            let sources = handle.evidence_sources();
            assert_eq!(
                sources.contains("github"),
                echo.evidence_sources().contains("github"),
                "{sources:?}"
            );
            // The guess, and the source's observation when there is one: the echo is not counted.
            let described = u32::from(echo.evidence_sources().contains("github"));
            assert_eq!(handle.corroboration, 1 + described, "{handle:?}");
            let mailbox = find(&report, EntityKind::Email);
            assert!(
                operators(&mailbox) && mailbox.has_tag("seed"),
                "{mailbox:?}"
            );
            assert!((mailbox.confidence - 0.99).abs() < f64::EPSILON);
        }
    }

    /// A pivot lookup's echo loses its seed record and tag, is never held above the confidence the
    /// crawl followed it at, and is not counted as an observation; an echo holding nothing else is
    /// not kept, and an entity that is no echo is kept as it is.
    #[test]
    fn a_pivots_echo_keeps_only_what_sources_said_of_it() {
        let mut echo = asked("pgsmith");
        assert!(!forget_pivot_echo(&mut echo, 0.7), "{echo:?}");

        let mut described = asked("pgsmith");
        described.absorb(observed(EntityKind::Username, "pgsmith", "github"));
        assert_eq!(described.corroboration, 2);
        assert!(forget_pivot_echo(&mut described, 0.7));
        assert!(!described.evidence.iter().any(Evidence::is_operator_seed));
        assert!(!described.has_tag("seed"));
        assert!(
            (described.confidence - 0.7).abs() < f64::EPSILON,
            "{described:?}"
        );
        assert_eq!(described.corroboration, 1);
        assert_eq!(
            described.evidence_sources(),
            BTreeSet::from(["github".to_owned()])
        );

        let mut finding = observed(EntityKind::Username, "pgsmith", "github");
        let before = finding.clone();
        assert!(forget_pivot_echo(&mut finding, 0.1));
        assert_eq!(finding, before);
    }

    /// What a pivot's echo queues is followed at no more than the pivot: a spelling a source
    /// reported of a handle guessed from an e-mail's local part, looked up from the guess's echo,
    /// leaves the crawl at the guess's confidence, not at the echo's, nor as the operator's seed.
    #[test]
    fn what_a_pivots_echo_queues_is_followed_at_no_more_than_the_pivot() {
        let email = "pg.smith@corp.example";
        let mailbox_only = RecursionPolicy {
            expose_emails: false,
            ..policy()
        };
        let mut guess = asked("pgsmith");
        guess.absorb(observed(EntityKind::Username, "pg_smith", "github_twitter"));
        let mut reported = asked("pg_smith");
        reported.absorb(observed(EntityKind::Username, "pg_smith", "hacker_news"));
        let mut collector = Scripted::new()
            .on(ScanKind::Email, email, vec![guessed("pg-smith")])
            .on(ScanKind::Username, "pgsmith", vec![guess])
            .on(ScanKind::Username, "pg_smith", vec![reported]);
        let report = run(&[email.to_owned()], &mailbox_only, &mut collector);
        let handles: Vec<&str> = collector
            .calls
            .iter()
            .filter(|(kind, _)| kind == "username")
            .map(|(_, selector)| selector.as_str())
            .collect();
        assert_eq!(handles, ["pgsmith", "pg_smith"]);
        let kept: Vec<&Entity> = report
            .entities
            .iter()
            .filter(|entity| entity.kind == EntityKind::Username)
            .collect();
        assert!(!kept.is_empty());
        for handle in kept {
            assert!(handle.confidence <= 0.7, "{handle:?}");
            assert!(!handle.has_tag("seed"), "{handle:?}");
            assert!(
                !handle.evidence.iter().any(Evidence::is_operator_seed),
                "{handle:?}"
            );
        }
    }

    /// A pivot's lookup is routed and recorded as it returned, before its echo is forgotten: a
    /// handle followed by a spelling a source observed is not looked up again by its identity key
    /// when every other spelling is below the floor (the echo says it was looked up), and a lookup
    /// whose echo was all it returned still shows in the lineage.
    #[test]
    fn a_pivots_lookup_is_routed_and_recorded_before_its_echo_is_forgotten() {
        let email = "pg.smith@corp.example";
        let floor = RecursionPolicy {
            expose_emails: false,
            expand_confidence_floor: 0.8,
            ..policy()
        };
        let mut echo = asked("pg_smith");
        let mut other = observed(EntityKind::Username, "PG-Smith", "keybase");
        other.confidence = 0.7;
        echo.absorb(other);
        let mut collector = Scripted::new()
            .on(
                ScanKind::Email,
                email,
                vec![observed(EntityKind::Username, "PG_Smith", "gravatar")],
            )
            .on(ScanKind::Username, "PG_Smith", vec![echo]);
        run(&[email.to_owned()], &floor, &mut collector);
        let handles: Vec<&str> = collector
            .calls
            .iter()
            .filter(|(kind, _)| kind == "username")
            .map(|(_, selector)| selector.as_str())
            .collect();
        assert_eq!(handles, ["PG_Smith"]);

        let mailbox_only = RecursionPolicy {
            expose_emails: false,
            ..policy()
        };
        let mut collector = Scripted::new()
            .on(ScanKind::Email, email, vec![guessed("pg-smith")])
            .on(ScanKind::Username, "pgsmith", vec![asked("pgsmith")]);
        let report = run(&[email.to_owned()], &mailbox_only, &mut collector);
        assert!(
            report
                .edges
                .iter()
                .any(|edge| edge.from_kind == "username" && edge.from_selector == "pgsmith"),
            "{:?}",
            report.edges
        );
    }

    #[test]
    fn a_lookups_echo_of_the_handle_it_was_asked_is_no_observation() {
        let email = "pg.smith@corp.example";
        let mailbox_only = RecursionPolicy {
            expose_emails: false,
            ..policy()
        };
        let handle = |report: &RecursionReport| -> Entity {
            report
                .entities
                .iter()
                .find(|entity| entity.kind == EntityKind::Username)
                .cloned()
                .expect("the handle")
        };
        let handles = |collector: &Scripted| -> Vec<String> {
            collector
                .calls
                .iter()
                .filter(|(kind, _)| kind == "username")
                .map(|(_, selector)| selector.clone())
                .collect()
        };
        // A guess is followed by its identity key, and that lookup's echo of the key records no
        // spelling as observed: every source may have answered that it is not there.
        let mut collector = Scripted::new()
            .on(ScanKind::Email, email, vec![guessed("pg-smith")])
            .on(ScanKind::Username, "pgsmith", vec![asked("pgsmith")]);
        let report = run(&[email.to_owned()], &mailbox_only, &mut collector);
        assert_eq!(handles(&collector), ["pgsmith"]);
        let merged = handle(&report);
        assert!(
            merged.spellings.is_empty() && merged.observed_spellings().is_empty(),
            "{merged:?}"
        );
        // A spelling a source observed keeps the confidence it was observed at when the lookup of
        // it echoes it back, and the echo is not followed by the identity key.
        let mut gravatar = observed(EntityKind::Username, "PG_Smith", "gravatar");
        gravatar.confidence = 0.65;
        let mut seen = guessed("pg-smith");
        seen.absorb(gravatar);
        let mut collector = Scripted::new().on(ScanKind::Email, email, vec![seen]).on(
            ScanKind::Username,
            "PG_Smith",
            vec![asked("pg_smith")],
        );
        let report = run(&[email.to_owned()], &mailbox_only, &mut collector);
        assert_eq!(handles(&collector), ["PG_Smith"]);
        let spellings: Vec<(String, f64)> =
            handle(&report).observed_spellings().into_iter().collect();
        assert_eq!(spellings, [("PG_Smith".to_owned(), 0.65)]);
        // The operator's handle, whose only other spelling a source reported is below the floor,
        // is not followed by its identity key either: the handle itself was looked up.
        let mut echo = asked("pg_smith");
        let mut other = observed(EntityKind::Username, "PG-Smith", "keybase");
        other.confidence = 0.7;
        echo.absorb(other);
        let mut collector = Scripted::new().on(ScanKind::Username, "PG_Smith", vec![echo]);
        run(
            &["@PG_Smith".to_owned()],
            &RecursionPolicy {
                expand_confidence_floor: 0.8,
                ..mailbox_only
            },
            &mut collector,
        );
        assert_eq!(handles(&collector), ["PG_Smith"]);
    }

    #[test]
    fn a_handle_echoed_in_another_spelling_is_not_looked_up_again() {
        // A platform that reports the handle it was asked for in lower case echoes the seed under a
        // second spelling of one identity, which the crawl has already looked up: it neither looks
        // up the echo nor the identity key, while the echo's other findings are still followed.
        let mut collector = Scripted::new().on(
            ScanKind::Username,
            "PG_Smith",
            vec![
                ent(EntityKind::Username, "pg_smith", 0.9),
                ent(EntityKind::Domain, "pg-smith.example", 0.7),
            ],
        );
        let report = run(&["@PG_Smith".to_owned()], &policy(), &mut collector);
        let handles: Vec<&(String, String)> = collector
            .calls
            .iter()
            .filter(|(kind, _)| kind == "username")
            .collect();
        assert_eq!(handles, [&("username".to_owned(), "PG_Smith".to_owned())]);
        assert!(
            collector
                .calls
                .contains(&("domain".to_owned(), "pg-smith.example".to_owned()))
        );
        assert_eq!(report.dispatches, 2);
    }

    #[test]
    fn an_edge_resolves_to_its_source_under_any_spelling_of_its_identity() {
        // The crawl records the spelling it followed (`PG_Smith`); a scan saved before recorded the
        // identity key (`pgsmith`). Either edge, and one under another spelling of the same handle,
        // links the handle to what its lookup found.
        let mut collector = Scripted::new()
            .on(
                ScanKind::Email,
                "person@example.com",
                vec![ent(EntityKind::Username, "PG_Smith", 0.8)],
            )
            .on(ScanKind::Exposure, "person@example.com", vec![])
            .on(
                ScanKind::Username,
                "PG_Smith",
                vec![ent(EntityKind::Domain, "pg-smith.example", 0.7)],
            );
        let report = run(
            &["person@example.com".to_owned()],
            &policy(),
            &mut collector,
        );
        let uid = |kind: EntityKind| {
            report
                .entities
                .iter()
                .find(|entity| entity.kind == kind)
                .map(|entity| entity.uid.clone())
                .expect("entity")
        };
        let (handle, site) = (uid(EntityKind::Username), uid(EntityKind::Domain));
        for spelling in ["PG_Smith", "pgsmith", "pg-smith"] {
            let mut saved = report.clone();
            for edge in &mut saved.edges {
                if edge.from_kind == "username" {
                    edge.from_selector = spelling.to_owned();
                }
            }
            assert!(
                lineage_links(&saved)
                    .iter()
                    .any(|link| link.from_uid == handle && link.to_uid == site),
                "an edge recorded under {spelling} must resolve to the handle"
            );
        }
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
    fn a_role_provider_or_no_reply_address_is_kept_but_not_dispatched() {
        // A registrar's abuse mailbox, a zone's hostmaster, a provider's address and a no-reply
        // address name a function, not a person: the crawl keeps them and looks none of them up,
        // nor their breach exposure. A personal address found beside them is still followed.
        let mut collector = Scripted::new()
            .on(
                ScanKind::Domain,
                "example.com",
                vec![
                    ent(EntityKind::Email, "abuse@registrar.example", 0.95),
                    ent(EntityKind::Email, "hostmaster@example.com", 0.95),
                    ent(EntityKind::Email, "noc@amazon.com", 0.95),
                    ent(EntityKind::Email, "ada@users.noreply.github.com", 0.95),
                    ent(EntityKind::Email, "ada.lovelace@example.com", 0.95),
                ],
            )
            .on(ScanKind::Email, "ada.lovelace@example.com", vec![])
            .on(ScanKind::Exposure, "ada.lovelace@example.com", vec![]);

        let report = run(&["example.com".to_owned()], &policy(), &mut collector);

        let looked_up: Vec<&str> = collector
            .calls
            .iter()
            .filter(|(kind, _)| kind.as_str() != "domain")
            .map(|(_, selector)| selector.as_str())
            .collect();
        assert_eq!(
            looked_up,
            ["ada.lovelace@example.com", "ada.lovelace@example.com"],
            "{:?}",
            collector.calls
        );
        assert_eq!(report.entities.len(), 5, "every address is kept");
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
    fn wikidata_namesake_pivots_are_not_dispatched_even_with_zero_floor() {
        for floor in [crate::gap::EXPAND_FLOOR, 0.0] {
            let mut domain = ent(EntityKind::Domain, "stranger.example", 0.55);
            domain.tag(crate::tags::NAME_SEARCH_LEAD);
            let mut username = ent(EntityKind::Username, "unrelated_person", 0.55);
            username.tag(crate::tags::NAME_SEARCH_LEAD);
            let mut collector = Scripted::new()
                .on(
                    ScanKind::Email,
                    "person@example.com",
                    vec![
                        ent(EntityKind::Email, "person@example.com", 0.99),
                        domain,
                        username,
                    ],
                )
                .on(ScanKind::Exposure, "person@example.com", vec![]);
            let policy = RecursionPolicy {
                expand_confidence_floor: floor,
                ..RecursionPolicy::default()
            };
            let report = run(&["person@example.com".to_owned()], &policy, &mut collector);
            assert_eq!(report.dispatches, 2);
            assert!(
                collector
                    .calls
                    .iter()
                    .all(|(kind, _)| { kind != "domain" && kind != "username" })
            );
            assert!(
                report
                    .entities
                    .iter()
                    .any(|entity| entity.value == "stranger.example")
            );
            assert!(
                report
                    .entities
                    .iter()
                    .any(|entity| entity.raw_value == "unrelated_person")
            );
        }
        // The attribution gate is specific to name-search leads, not a
        // blanket prohibition on normal independently obtained pivots.
        let domain = ent(EntityKind::Domain, "verified.example", 0.55);
        assert_eq!(
            expansions(
                &domain,
                &RecursionPolicy {
                    expand_confidence_floor: 0.0,
                    ..RecursionPolicy::default()
                }
            ),
            vec![Target {
                kind: ScanKind::Domain,
                selector: "verified.example".to_owned(),
            }]
        );
    }

    #[test]
    fn a_name_search_lead_pivot_is_never_dispatched_whatever_the_floor() {
        // The shared name-search-lead tag (every name-search leg uses it) blocks dispatch even
        // when the operator lowers the floor to zero — a name-only match must not seed a
        // potentially unrelated third party.
        let mut domain = ent(EntityKind::Domain, "charity.example", 0.55);
        domain.tag(crate::tags::NAME_SEARCH_LEAD);
        for floor in [crate::gap::EXPAND_FLOOR, 0.0] {
            assert!(
                expansions(
                    &domain,
                    &RecursionPolicy {
                        expand_confidence_floor: floor,
                        ..RecursionPolicy::default()
                    }
                )
                .is_empty(),
                "a name-search-lead pivot must never be dispatched (floor {floor})"
            );
        }
    }

    #[test]
    fn historical_wikidata_name_leads_remain_non_dispatchable() {
        // A scan persisted before the tag migration can still carry the old marker.
        // A zero expansion floor must never promote its unverified third-party pivots.
        for kind in [EntityKind::Domain, EntityKind::Username] {
            let value = if kind == EntityKind::Domain {
                "namesake.example"
            } else {
                "namesake_handle"
            };
            let mut lead = ent(kind, value, 0.99);
            lead.tag("wikidata-name-lead");
            for floor in [crate::gap::EXPAND_FLOOR, 0.0] {
                assert!(
                    expansions(
                        &lead,
                        &RecursionPolicy {
                            expand_confidence_floor: floor,
                            ..RecursionPolicy::default()
                        }
                    )
                    .is_empty(),
                    "legacy Wikidata name-only lead must not dispatch at floor {floor}"
                );
            }
        }
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
    fn an_email_with_no_address_in_it_is_not_followed() {
        // A breach or people-search record can put a non-address in its e-mail field. The e-mail
        // route refuses it, so neither it nor its exposure is looked up: the exposure route would
        // read it as a username nobody reported.
        for junk in ["noemail", "null", "pgsmith"] {
            let email = ent(EntityKind::Email, junk, 0.6);
            assert_eq!(expansions(&email, &policy()), Vec::new(), "{junk}");
        }
        // An address is followed on both routes.
        let email = ent(EntityKind::Email, "Person@Example.com", 0.6);
        let followed: Vec<(ScanKind, String)> = expansions(&email, &policy())
            .into_iter()
            .map(|target| (target.kind, target.selector))
            .collect();
        assert_eq!(
            followed,
            [
                (ScanKind::Email, "person@example.com".to_owned()),
                (ScanKind::Exposure, "person@example.com".to_owned()),
            ]
        );
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
