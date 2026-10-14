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
    /// configured paid source is never skipped (it reports `auth_required` when no key is set).
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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GenerationStat {
    pub generation: u32,
    pub dispatched: usize,
    pub entities_after: usize,
}

/// The finished crawl: the full entity graph, every source outcome, the per-generation shape, and
/// why it stopped.
#[derive(Debug, Clone, PartialEq)]
pub struct RecursionReport {
    pub accepted_seeds: Vec<Target>,
    pub rejected_seeds: Vec<String>,
    pub entities: Vec<Entity>,
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

/// The lookup kind an entity of this kind expands into, for the identity-bearing kinds only. Urls,
/// persons, IPs, coordinates and the rest are retained in the graph but are not re-dispatched: a
/// recursive crawl pivots on identity, not on every incidental artefact.
fn expansion_kind(kind: &EntityKind) -> Option<ScanKind> {
    match kind {
        EntityKind::Email => Some(ScanKind::Email),
        EntityKind::Username => Some(ScanKind::Username),
        EntityKind::Domain => Some(ScanKind::Domain),
        EntityKind::Phone => Some(ScanKind::Phone),
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

/// Build the initial frontier: each routable seed becomes a de-duplicated target; an empty or
/// non-routable seed is rejected. Returns (accepted seeds, rejected seeds, frontier).
fn seed_frontier(seeds: &[String]) -> (Vec<Target>, Vec<String>, Vec<Target>) {
    let mut accepted = Vec::new();
    let mut rejected = Vec::new();
    let mut frontier = Vec::new();
    let mut queued: BTreeSet<(String, String)> = BTreeSet::new();
    for seed in seeds {
        match target_for_seed(seed) {
            Some(target) => {
                accepted.push(target.clone());
                if queued.insert(target.owned_key()) {
                    frontier.push(target);
                }
            }
            None => rejected.push(seed.clone()),
        }
    }
    (accepted, rejected, frontier)
}

/// The accumulating state of one crawl, threaded across generations.
#[derive(Default)]
struct CrawlState {
    visited: BTreeSet<(String, String)>,
    entities: Vec<Entity>,
    outcomes: Vec<SourceExecutionOutcome>,
    generations: Vec<GenerationStat>,
    dispatches: usize,
    resource_limited: bool,
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
        let mut next: Vec<Target> = Vec::new();
        let mut next_keys: BTreeSet<(String, String)> = BTreeSet::new();
        let mut dispatched = 0usize;
        let mut stopped = false;

        let mut remaining = frontier.into_iter();
        for target in remaining.by_ref() {
            if !self.visited.insert(target.owned_key()) {
                continue;
            }
            if self.dispatches >= policy.max_dispatches
                || self.entities.len() >= policy.max_entities
            {
                self.resource_limited = true;
                stopped = true;
                if next_keys.insert(target.owned_key()) {
                    next.push(target);
                }
                break;
            }
            let step = collector.collect(&target);
            self.dispatches += 1;
            dispatched += 1;
            self.outcomes.extend(step.outcomes);
            for mut entity in step.entities {
                entity.generation = generation;
                self.queue_expansions(&entity, policy, &mut next, &mut next_keys);
                self.entities.push(entity);
            }
        }
        for target in remaining {
            if next_keys.insert(target.owned_key()) {
                next.push(target);
            }
        }
        merge_by_uid(&mut self.entities);
        self.generations.push(GenerationStat {
            generation,
            dispatched,
            entities_after: self.entities.len(),
        });
        (next, stopped)
    }

    /// Queue the next-generation targets an entity contributes, honouring the per-generation
    /// frontier cap. An overflow is a resource limit, not silently lost work.
    fn queue_expansions(
        &mut self,
        entity: &Entity,
        policy: &RecursionPolicy,
        next: &mut Vec<Target>,
        next_keys: &mut BTreeSet<(String, String)>,
    ) {
        for candidate in expansions(entity, policy) {
            let key = candidate.owned_key();
            if self.visited.contains(&key) || next_keys.contains(&key) {
                continue;
            }
            if next.len() >= policy.max_frontier_per_generation {
                self.resource_limited = true;
                continue;
            }
            next_keys.insert(key);
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
    let (accepted_seeds, rejected_seeds, mut frontier) = seed_frontier(seeds);
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
        resource_limit_reached: state.resource_limited,
        max_depth_reached: max_depth,
        ..TerminationSignals::default()
    };
    let termination =
        decide_termination(frontier_state, signals).unwrap_or(TerminationReason::FixedPoint);

    RecursionReport {
        accepted_seeds,
        rejected_seeds,
        truncated: state.resource_limited || max_depth,
        visited: state.visited.len(),
        entities: state.entities,
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
