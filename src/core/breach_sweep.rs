//! Final bulk breach sweep: one query plan compiled from everything the scan
//! learned, dispatched after recursive expansion has run dry.
//!
//! # Why a final sweep at all
//!
//! Expansion queries each identifier at the moment it is discovered, so the
//! breach corpora are asked about the seed with almost nothing known, and about
//! a handle found in round three with everything known. The sweep closes that
//! asymmetry: it re-asks the corpora once, at the end, with the full identity
//! picture — every address, handle and name the scan established — so a corpus
//! that could only answer *given* a later discovery finally gets the chance.
//!
//! # Recursion, adapted
//!
//! The plan is a recursive expansion applied at two levels, both cycle-safe:
//!
//! 1. **Within an anchor** — [`crate::util::oathnet_batch::generate`] runs its
//!    own bounded breadth-first walk ([`RECURSE_DEPTH`] extra levels), so an
//!    address yields its local part, that local part yields its handle shapes,
//!    and those yield candidate addresses.
//! 2. **Across anchors** — the same discipline one level up. Anchors are folded
//!    into a single frontier against one shared visited-set, so the second
//!    anchor never re-derives what the first already produced. Without it the
//!    per-anchor plans would overlap heavily (two addresses of one person derive
//!    many of the same handles) and the cap would be spent on duplicates.
//!
//! Both walks terminate because a value is expanded at most once. The plan is
//! then bounded a third time by [`MAX_PROBES`], and what the cap drops is
//! counted, never silently discarded.
//!
//! # Purity
//!
//! Compilation performs no IO, so the whole plan can be asserted against in unit
//! tests and previewed without spending a single request. Dispatch is the
//! engine's job.

use crate::core::entity::Entity;
use crate::core::scan::{Target, TargetKind};
use crate::util::oathnet;
use crate::util::oathnet_batch::{generate, BatchOptions, Origin};
use std::collections::HashSet;

/// Identity anchors the sweep will expand, most valuable first.
///
/// Ranked by confidence, so a bounded plan spends its budget on the identifiers
/// the scan is most sure of.
pub const MAX_ANCHORS: usize = 24;

/// Hard cap on dispatched probes. The sweep runs after the scan's own budget
/// checks have already thinned the field, so this is a backstop against a
/// pathological graph, not the normal limit.
pub const MAX_PROBES: usize = 64;

/// Extra recursive levels inside each anchor's fan-out.
///
/// One. The generator's own docs call deeper recursion explosive when it
/// compounds with handle permutation, and this stage already crosses that
/// fan-out with every anchor in the scan.
pub const RECURSE_DEPTH: u32 = 1;

/// Cap on queries taken from any single anchor, so one prolific anchor cannot
/// crowd every other identifier out of a capped plan.
pub const MAX_PER_ANCHOR: usize = 16;

/// One probe the sweep will dispatch: a target, and the entity it came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SweepProbe {
    pub kind: TargetKind,
    pub value: String,
    /// The entity this probe was derived from — the parent for lineage, so a
    /// hit is attributable to the identifier that suggested looking.
    pub anchor_uid: String,
    /// How the value relates to its anchor.
    pub origin: Origin,
}

impl SweepProbe {
    /// The dispatchable target.
    #[must_use]
    pub fn target(&self) -> Target {
        Target::new(self.kind, self.value.clone())
    }
}

/// A compiled sweep, with an honest account of what was left out.
#[derive(Debug, Clone, Default)]
pub struct SweepPlan {
    pub probes: Vec<SweepProbe>,
    /// Entities eligible to anchor the sweep before the [`MAX_ANCHORS`] cut.
    pub anchors_considered: usize,
    /// Anchors that actually contributed at least one probe.
    pub anchors_used: usize,
    /// Derived values the scan had already dispatched, so re-querying them
    /// would spend quota on a known answer.
    pub skipped_already_probed: usize,
    /// Generated queries with no dispatchable target — the free-text `q`
    /// surface, which has no [`TargetKind`].
    pub skipped_free_text: usize,
    /// Probes dropped by [`MAX_PROBES`]. Surfaced so a truncated sweep is
    /// visibly truncated.
    pub dropped_over_cap: usize,
}

impl SweepPlan {
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.probes.is_empty()
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.probes.len()
    }
}

/// Inputs that vary per scan. Grouped so the signature stays readable as the
/// engine grows more knobs to pass through.
#[derive(Debug, Clone, Copy)]
pub struct SweepInputs<'a> {
    /// Targets the scan already dispatched — the engine's expansion visited-set.
    pub already_probed: &'a HashSet<(TargetKind, String)>,
    /// Entity uids held back by the candidate quarantine. Never swept: an
    /// unverified value is exactly the one that must not be sent to a third
    /// party, and a hit on it would manufacture the corroboration the
    /// quarantine exists to withhold.
    pub quarantined: &'a HashSet<String>,
    /// Confidence floor an anchor must clear — the scan's own expansion floor,
    /// so operator settings carry through to this stage unchanged.
    pub min_confidence: f64,
}

/// Compile the sweep for a finished scan.
///
/// Deterministic: the same entity set and inputs always produce the same plan,
/// in the same order. This matters because [`MAX_PROBES`] truncates — a plan
/// whose order depended on hash iteration would drop a *different* probe run to
/// run, and the scan's results with it.
#[must_use]
pub fn compile(entities: &[Entity], inputs: SweepInputs<'_>) -> SweepPlan {
    let mut plan = SweepPlan::default();

    let anchors = rank_anchors(entities, inputs);
    plan.anchors_considered = anchors.len();

    let opts = BatchOptions {
        include_stealer: true,
        permute_handles: true,
        // A synthesised address is a *question* — "does this address appear in a
        // breach?" — and the corpus answers it with real evidence either way, so
        // it earns its place in the final stage. It is also the most speculative
        // material here, which is why `cmp_probes` ranks it last: the cap trims
        // guesses before it trims anything observed.
        synthesize_emails: true,
        recurse_depth: RECURSE_DEPTH,
        max_queries: MAX_PER_ANCHOR,
    };

    // One shared visited-set across every anchor — the cross-anchor half of the
    // recursion. Seeded with what the scan already dispatched so the sweep can
    // never re-ask a question expansion already answered.
    let mut seen: HashSet<(TargetKind, String)> = inputs.already_probed.clone();
    let mut ranked: Vec<(usize, SweepProbe)> = Vec::new();

    for (anchor_rank, anchor) in anchors.iter().enumerate().take(MAX_ANCHORS) {
        let Some(anchor_kind) = TargetKind::from_entity_kind(&anchor.kind) else {
            continue;
        };

        let mut contributed = false;
        for query in generate(anchor_kind, &anchor.value, &opts) {
            let Some(kind) = kind_for_field(query.field) else {
                plan.skipped_free_text += 1;
                continue;
            };

            let key = probe_key(kind, &query.value);
            if seen.contains(&key) {
                // Distinguish "expansion already did this" from "another anchor
                // in this same plan already did this": only the former is a
                // skip worth reporting, the latter is the dedup working.
                if inputs.already_probed.contains(&key) {
                    plan.skipped_already_probed += 1;
                }
                continue;
            }
            seen.insert(key);

            ranked.push((
                anchor_rank,
                SweepProbe {
                    kind,
                    value: query.value,
                    anchor_uid: anchor.uid.clone(),
                    origin: query.origin,
                },
            ));
            contributed = true;
        }

        if contributed {
            plan.anchors_used += 1;
        }
    }

    ranked.sort_by(cmp_probes);

    if ranked.len() > MAX_PROBES {
        plan.dropped_over_cap = ranked.len() - MAX_PROBES;
        ranked.truncate(MAX_PROBES);
    }
    plan.probes = ranked.into_iter().map(|(_, probe)| probe).collect();

    plan
}

/// Entities eligible to anchor the sweep, best first.
///
/// Restricted to identity kinds. Breach corpora are indexed on people, so an IP
/// or a coordinate has nothing to match against — sweeping infrastructure would
/// spend a bounded budget on rows that cannot exist. Expansion already probed
/// the routable infrastructure with the modules built for it.
fn rank_anchors<'a>(entities: &'a [Entity], inputs: SweepInputs<'_>) -> Vec<&'a Entity> {
    let mut anchors: Vec<&Entity> = entities
        .iter()
        .filter(|e| is_identity_anchor(e))
        .filter(|e| !inputs.quarantined.contains(&e.uid))
        .filter(|e| e.c_effective() >= inputs.min_confidence)
        // A value the scan only ever saw as a recycled search snippet is not an
        // established identifier, and the expansion gate rejects it for the same
        // reason. Asking a breach corpus about it would launder a weak guess
        // into a hit against a real person.
        .filter(|e| !e.is_uncorroborated_recycled())
        .collect();

    anchors.sort_by(|a, b| {
        b.c_effective()
            .partial_cmp(&a.c_effective())
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| b.source_count().cmp(&a.source_count()))
            .then_with(|| a.uid.cmp(&b.uid))
    });
    anchors
}

/// Kinds a breach corpus can actually be asked about.
fn is_identity_anchor(entity: &Entity) -> bool {
    use crate::core::entity::EntityKind;
    matches!(
        entity.kind,
        EntityKind::Email | EntityKind::Username | EntityKind::Person | EntityKind::Phone
    )
}

/// The [`TargetKind`] a generated selector field dispatches as.
///
/// `q` (free text) has none: it is a corpus-side full-text search, not an
/// identifier, and there is no module graph to run for it. Counted as skipped
/// rather than dropped in silence.
fn kind_for_field(field: &str) -> Option<TargetKind> {
    match field {
        oathnet::FIELD_EMAIL => Some(TargetKind::Email),
        oathnet::FIELD_USERNAME => Some(TargetKind::Username),
        oathnet::FIELD_PHONE => Some(TargetKind::Phone),
        oathnet::FIELD_DOMAIN => Some(TargetKind::Domain),
        oathnet::FIELD_IP => Some(TargetKind::IpAddress),
        _ => None,
    }
}

/// Dedup key. Normalises exactly as the engine's visited-set does, so a probe
/// the scan already dispatched is recognised as the same probe however it was
/// spelled when rediscovered.
fn probe_key(kind: TargetKind, value: &str) -> (TargetKind, String) {
    let entity_kind = kind.to_entity_kind();
    (
        kind,
        crate::core::entity::normalise(&entity_kind, value),
    )
}

/// How speculative a derived value is — lower is better evidenced.
///
/// The cap trims from the bottom, so this decides what a truncated sweep gives
/// up: guesses before observations.
fn origin_rank(origin: Origin) -> u8 {
    match origin {
        Origin::Seed => 0,
        // Reformatting a number the scan observed loses nothing.
        Origin::PhoneFormat => 1,
        // Parts of an observed address — present in the data, not invented.
        Origin::EmailLocalPart | Origin::EmailDomain => 2,
        // A plausible shape of a real name; the person may never have used it.
        Origin::Handle => 3,
        // A handle crossed with a provider. Nothing observed either half together.
        Origin::EmailCandidate => 4,
    }
}

/// Total order over `(anchor_rank, probe)`: best anchor first, then least
/// speculative, then by kind and value so the order is total and reproducible.
fn cmp_probes(a: &(usize, SweepProbe), b: &(usize, SweepProbe)) -> std::cmp::Ordering {
    a.0.cmp(&b.0)
        .then_with(|| origin_rank(a.1.origin).cmp(&origin_rank(b.1.origin)))
        .then_with(|| format!("{:?}", a.1.kind).cmp(&format!("{:?}", b.1.kind)))
        .then_with(|| a.1.value.cmp(&b.1.value))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::entity::{Entity, EntityKind, Evidence};

    fn ent(kind: EntityKind, value: &str, conf: f64) -> Entity {
        let mut e = Entity::new(kind, value, conf, "scan-1");
        // Two distinct sources so `c_effective` clears any sane floor and the
        // entity is not treated as an uncorroborated snippet.
        e.add_evidence(Evidence::new("hibp", "record"));
        e.add_evidence(Evidence::new("dns_intel", "record"));
        e
    }

    fn inputs<'a>(
        probed: &'a HashSet<(TargetKind, String)>,
        quarantined: &'a HashSet<String>,
    ) -> SweepInputs<'a> {
        SweepInputs {
            already_probed: probed,
            quarantined,
            min_confidence: 0.2,
        }
    }

    fn empty() -> (HashSet<(TargetKind, String)>, HashSet<String>) {
        (HashSet::new(), HashSet::new())
    }

    #[test]
    fn an_email_anchor_yields_its_local_part_as_a_username() {
        let (p, q) = empty();
        let ents = vec![ent(EntityKind::Email, "jordanmeyers@example.com", 0.9)];

        let plan = compile(&ents, inputs(&p, &q));

        assert!(plan
            .probes
            .iter()
            .any(|pr| pr.kind == TargetKind::Username && pr.value == "jordanmeyers"));
        assert_eq!(plan.anchors_considered, 1);
        assert_eq!(plan.anchors_used, 1);
    }

    #[test]
    fn every_probe_is_attributed_to_the_anchor_that_suggested_it() {
        let (p, q) = empty();
        let ents = vec![ent(EntityKind::Email, "jordanmeyers@example.com", 0.9)];

        let plan = compile(&ents, inputs(&p, &q));

        assert!(!plan.is_empty());
        assert!(plan.probes.iter().all(|pr| pr.anchor_uid == ents[0].uid));
    }

    #[test]
    fn infrastructure_is_not_an_anchor() {
        let (p, q) = empty();
        let ents = vec![
            ent(EntityKind::IpAddress, "203.0.113.7", 0.9),
            ent(EntityKind::Domain, "example.com", 0.9),
            ent(EntityKind::Url, "https://example.com/a", 0.9),
        ];

        let plan = compile(&ents, inputs(&p, &q));

        assert_eq!(plan.anchors_considered, 0);
        assert!(plan.is_empty());
    }

    #[test]
    fn quarantined_entities_are_never_swept() {
        let (p, _) = empty();
        let ents = vec![ent(EntityKind::Email, "jordanmeyers@example.com", 0.9)];
        let mut quarantined = HashSet::new();
        quarantined.insert(ents[0].uid.clone());

        let plan = compile(&ents, inputs(&p, &quarantined));

        assert_eq!(plan.anchors_considered, 0);
        assert!(plan.is_empty());
    }

    #[test]
    fn anchors_below_the_confidence_floor_are_excluded() {
        let (p, q) = empty();
        let ents = vec![Entity::new(
            EntityKind::Email,
            "weak@example.com",
            0.05,
            "scan-1",
        )];

        let plan = compile(
            &ents,
            SweepInputs {
                already_probed: &p,
                quarantined: &q,
                min_confidence: 0.5,
            },
        );

        assert_eq!(plan.anchors_considered, 0);
    }

    #[test]
    fn values_expansion_already_dispatched_are_skipped_and_counted() {
        let (_, q) = empty();
        let mut probed = HashSet::new();
        probed.insert(probe_key(TargetKind::Username, "jordanmeyers"));
        let ents = vec![ent(EntityKind::Email, "jordanmeyers@example.com", 0.9)];

        let plan = compile(&ents, inputs(&probed, &q));

        assert!(!plan
            .probes
            .iter()
            .any(|pr| pr.kind == TargetKind::Username && pr.value == "jordanmeyers"));
        assert!(plan.skipped_already_probed >= 1);
    }

    #[test]
    fn two_anchors_sharing_a_derivation_produce_it_once() {
        let (p, q) = empty();
        // Both addresses derive the handle `jordanmeyers`.
        let ents = vec![
            ent(EntityKind::Email, "jordanmeyers@example.com", 0.9),
            ent(EntityKind::Email, "jordanmeyers@other.example", 0.8),
        ];

        let plan = compile(&ents, inputs(&p, &q));

        let handle_probes = plan
            .probes
            .iter()
            .filter(|pr| pr.kind == TargetKind::Username && pr.value == "jordanmeyers")
            .count();
        assert_eq!(handle_probes, 1);
        // The dedup is not a "skip" — nothing was withheld, it was merged.
        assert_eq!(plan.skipped_already_probed, 0);
    }

    #[test]
    fn the_plan_is_deterministic() {
        let (p, q) = empty();
        let ents = vec![
            ent(EntityKind::Email, "jordanmeyers@example.com", 0.9),
            ent(EntityKind::Username, "jmeyers", 0.7),
            ent(EntityKind::Person, "Jordan Meyers", 0.8),
        ];

        let first = compile(&ents, inputs(&p, &q));
        let second = compile(&ents, inputs(&p, &q));

        assert_eq!(first.probes, second.probes);
        assert!(first.probes.len() > 1);
    }

    #[test]
    fn better_anchors_and_less_speculative_origins_come_first() {
        let (p, q) = empty();
        let ents = vec![
            ent(EntityKind::Email, "jordanmeyers@example.com", 0.95),
            ent(EntityKind::Person, "Casey Vaughn", 0.30),
        ];

        let plan = compile(&ents, inputs(&p, &q));

        let first_synth = plan
            .probes
            .iter()
            .position(|pr| pr.origin == Origin::EmailCandidate);
        let last_observed = plan
            .probes
            .iter()
            .rposition(|pr| origin_rank(pr.origin) <= 2);
        if let (Some(synth), Some(observed)) = (first_synth, last_observed) {
            assert!(
                observed < synth,
                "a synthesised address must not outrank an observed one"
            );
        }
    }

    #[test]
    fn the_cap_is_enforced_and_the_overflow_is_reported() {
        let (p, q) = empty();
        // Many high-value anchors, each fanning out — comfortably over the cap.
        let ents: Vec<Entity> = (0..MAX_ANCHORS)
            .map(|i| ent(EntityKind::Email, &format!("jordanmeyers{i}@example.com"), 0.9))
            .collect();

        let plan = compile(&ents, inputs(&p, &q));

        assert_eq!(plan.probes.len(), MAX_PROBES);
        assert!(
            plan.dropped_over_cap > 0,
            "a truncated plan must say how much it dropped"
        );
    }

    #[test]
    fn free_text_queries_have_no_target_and_are_counted() {
        let (p, q) = empty();
        // A name generates a breach-only free-text `q` query.
        let ents = vec![ent(EntityKind::Person, "Jordan Meyers", 0.9)];

        let plan = compile(&ents, inputs(&p, &q));

        assert!(plan.skipped_free_text > 0);
        assert!(plan.probes.iter().all(|pr| pr.kind != TargetKind::Domain
            || !pr.value.contains(' ')));
    }

    #[test]
    fn an_empty_scan_compiles_an_empty_plan() {
        let (p, q) = empty();
        let plan = compile(&[], inputs(&p, &q));
        assert!(plan.is_empty());
        assert_eq!(plan.anchors_considered, 0);
        assert_eq!(plan.dropped_over_cap, 0);
    }

    #[test]
    fn probes_dispatch_as_targets_of_their_own_kind() {
        let (p, q) = empty();
        let ents = vec![ent(EntityKind::Email, "jordanmeyers@example.com", 0.9)];

        let plan = compile(&ents, inputs(&p, &q));

        for probe in &plan.probes {
            let target = probe.target();
            assert_eq!(target.kind, probe.kind);
            assert_eq!(target.value, probe.value);
        }
    }

    #[test]
    fn a_confidence_floor_of_zero_still_excludes_recycled_snippets() {
        let (p, q) = empty();
        let mut recycled = Entity::new(EntityKind::Username, "maybehandle", 0.4, "scan-1");
        recycled.add_evidence(Evidence::new("search_engines", "snippet"));
        recycled.tag("recycled");
        assert!(
            recycled.is_uncorroborated_recycled(),
            "fixture must actually be recycled, or this test proves nothing"
        );
        let ents = vec![recycled];

        let plan = compile(
            &ents,
            SweepInputs {
                already_probed: &p,
                quarantined: &q,
                min_confidence: 0.0,
            },
        );

        // Even with every confidence gate opened, a value the scan only ever saw
        // as a recycled snippet must not be sent to a breach corpus.
        assert_eq!(plan.anchors_considered, 0);
        assert!(plan.is_empty());
    }
}
