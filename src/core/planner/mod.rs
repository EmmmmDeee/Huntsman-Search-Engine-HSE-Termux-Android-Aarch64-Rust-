//! Intelligence-led collection planner — the F3EAD "next tasking" step.
//!
//! HSE already frames its collection as MITRE ATT&CK **Reconnaissance** (TA0043)
//! and reports, per scan, which techniques it *exercised* and which are *gaps*
//! ([`crate::core::attack::Assessment`]). That readout is passive: it names the
//! collection gaps but not how to close them.
//!
//! This module makes the intelligence picture **drive the next collection**. It
//! fuses three things HSE already knows —
//!
//!   1. the scan's ATT&CK Reconnaissance coverage vs. gaps (from what has
//!      already produced evidence),
//!   2. the entities already **held** (each one a scannable target), and
//!   3. every registered module's declared `attack_techniques()` and the target
//!      kinds it `consumes()` —
//!
//! into a ranked [`CollectionPlan`]: for each open gap, the concrete modules that
//! would exercise it *against entities already in hand*, ordered by intelligence
//! value. It is the difference between "you have not exercised Search Open
//! Websites/Domains (T1593)" and "run `wayback` and `crtsh` against the 3 domains
//! you already hold — that closes T1593 with free, passive collection."
//!
//! **Offensive OSINT, intelligence-led:** proactive open-source reconnaissance
//! whose targeting is led by the standing intelligence picture rather than by
//! uniform breadth-first expansion. The planner **plans open-source collection
//! only** — it never proposes exploitation, credential use, or access; entity
//! kinds that are not scannable open-source targets (`Password`, `Credential`)
//! are excluded by [`TargetKind::from_entity_kind`] and so never become tasking.
//!
//! Pure and deterministic: identical `(entities, modules)` ⇒ identical plan.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use serde::Serialize;

use crate::core::attack::{Assessment, Technique};
use crate::core::entity::Entity;
use crate::core::module::{Module, ModuleCost};
use crate::core::scan::TargetKind;

/// One recommended collection action: run `module` against the `held_targets`
/// entities of kind `target_kind` already collected, to exercise the ATT&CK
/// Reconnaissance technique(s) in `closes` that are currently gaps.
#[derive(Debug, Clone, Serialize)]
pub struct CollectionAction {
    /// Module to dispatch (its registered `name()`).
    pub module: &'static str,
    /// The held entity kind, as a scannable target, this action would run on.
    pub target_kind: TargetKind,
    /// How many distinct held targets of `target_kind` it can act on right now.
    pub held_targets: usize,
    /// The gap Reconnaissance techniques this action would exercise.
    pub closes: Vec<&'static Technique>,
    /// Access cost tier — drives the economy tie-break (cheapest first).
    pub cost: ModuleCost,
    /// Whether the module is passive (zero outbound network) — lowest footprint.
    pub passive: bool,
    /// Intelligence-led ranking score; higher is more valuable. See [`score`].
    pub score: f64,
}

/// A ranked, actionable collection plan derived from the standing intelligence
/// picture. `covered`/`gaps` mirror the scan's [`Assessment`]; `actions` are the
/// ranked next collection steps; `unclosable` are gaps no held entity + module
/// can exercise now (honest: they need a new seed kind, not more of the same).
#[derive(Debug, Clone, Serialize)]
pub struct CollectionPlan {
    /// Reconnaissance techniques already exercised by collected evidence.
    pub covered: Vec<&'static Technique>,
    /// Reconnaissance techniques not yet exercised — the collection gaps.
    pub gaps: Vec<&'static Technique>,
    /// Ranked next collection actions, most valuable first.
    pub actions: Vec<CollectionAction>,
    /// Gap techniques that no registered module can exercise against any held
    /// entity — unreachable without introducing a new target kind.
    pub unclosable: Vec<&'static Technique>,
}

impl CollectionPlan {
    /// Percentage of the Reconnaissance catalogue already exercised.
    #[must_use]
    pub fn coverage_pct(&self) -> f64 {
        let total = self.covered.len() + self.gaps.len();
        if total == 0 {
            return 100.0;
        }
        (self.covered.len() as f64 / total as f64) * 100.0
    }

    /// The `n` highest-value actions.
    #[must_use]
    pub fn top(&self, n: usize) -> &[CollectionAction] {
        &self.actions[..self.actions.len().min(n)]
    }
}

/// Cap on how much sheer volume of held targets can lift an action, so a large
/// pile of one entity kind never outranks an action that closes more gaps.
const APPLICABILITY_CAP: usize = 20;

/// Intelligence-led ranking score for a candidate action. The priority order is:
/// close the **most gaps** first; then the **most immediately actionable** (more
/// held targets, capped); then the **cheapest** collection (free before
/// key-gated before paid); then the **lowest footprint** (passive). Pure and
/// bounded so the ranking is stable and explainable.
#[must_use]
fn score(gaps_closed: usize, held_targets: usize, cost: ModuleCost, passive: bool) -> f64 {
    let gap_weight = gaps_closed as f64 * 100.0;
    let applicability = held_targets.min(APPLICABILITY_CAP) as f64 * 2.0;
    let cost_bonus = match cost {
        ModuleCost::Free => 12.0,
        ModuleCost::KeyGated => 6.0,
        ModuleCost::Paid => 0.0,
    };
    let passive_bonus = if passive { 3.0 } else { 0.0 };
    gap_weight + applicability + cost_bonus + passive_bonus
}

/// Build the intelligence-led collection plan from the entities held so far and
/// the module registry.
///
/// Coverage is derived from the modules that have already produced evidence
/// (via the same reducer the ATT&CK views use, so the covered set never
/// diverges). For every gap technique, each registered module that declares it
/// **and** accepts a target kind we already hold becomes a ranked action.
#[must_use]
pub fn plan(entities: &[Entity], modules: &[Arc<dyn Module>]) -> CollectionPlan {
    // 1. Coverage from what has already produced evidence. Derived through the
    //    `Module` trait only — `core` must not import the `modules` layer — by
    //    mapping each evidence source to its module's declared techniques. A
    //    source that is not a registered module (enrichment passes, the seed)
    //    contributes nothing, exactly as the ATT&CK assessment views treat it.
    let sources = crate::core::entity::evidence_sources(entities);
    let by_name: HashMap<&str, &Arc<dyn Module>> = modules.iter().map(|m| (m.name(), m)).collect();
    let mut covered_ids: HashSet<&str> = HashSet::new();
    for s in &sources {
        if let Some(m) = by_name.get(s) {
            covered_ids.extend(m.attack_techniques().iter().copied());
        }
    }
    let covered: Vec<&'static Technique> = crate::core::attack::RECONNAISSANCE
        .iter()
        .filter(|t| covered_ids.contains(t.id))
        .collect();
    let assessment = Assessment::from_covered(covered);
    let gap_ids: HashSet<&str> = assessment.gaps.iter().map(|t| t.id).collect();

    // 2. Held targets: distinct values per *scannable* target kind. Non-scannable
    //    entity kinds (Password/Credential/…) map to None and are excluded — the
    //    planner tasks open-source collection only, never credential use.
    let mut held: HashMap<TargetKind, HashSet<&str>> = HashMap::new();
    for e in entities {
        if let Some(tk) = TargetKind::from_entity_kind(&e.kind) {
            held.entry(tk).or_default().insert(e.value.as_str());
        }
    }

    // 3. For each module that would exercise ≥1 gap, emit one action per held
    //    target kind it can consume.
    let mut actions: Vec<CollectionAction> = Vec::new();
    let mut closable: HashSet<&str> = HashSet::new();
    for m in modules {
        let closes: Vec<&'static Technique> = m
            .attack_techniques()
            .iter()
            .filter(|id| gap_ids.contains(**id))
            .filter_map(|id| crate::core::attack::technique(id))
            .collect();
        if closes.is_empty() {
            continue;
        }
        for tk in m.consumes() {
            let Some(vals) = held.get(&tk) else { continue };
            let held_targets = vals.len();
            if held_targets == 0 {
                continue;
            }
            for t in &closes {
                closable.insert(t.id);
            }
            let cost = m.cost();
            let passive = m.is_passive();
            actions.push(CollectionAction {
                module: m.name(),
                target_kind: tk,
                held_targets,
                closes: closes.clone(),
                cost,
                passive,
                score: score(closes.len(), held_targets, cost, passive),
            });
        }
    }

    // 4. Rank most-valuable first, with a fully deterministic tie-break so an
    //    identical intelligence picture always yields an identical plan.
    actions.sort_by(|a, b| {
        b.score
            .partial_cmp(&a.score)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| a.module.cmp(b.module))
            .then_with(|| {
                a.target_kind
                    .canonical_str()
                    .cmp(b.target_kind.canonical_str())
            })
    });

    // 5. Gaps no held entity + module can exercise now — honest about the limit.
    let unclosable: Vec<&'static Technique> = assessment
        .gaps
        .iter()
        .copied()
        .filter(|t| !closable.contains(t.id))
        .collect();

    CollectionPlan {
        covered: assessment.covered,
        gaps: assessment.gaps,
        actions,
        unclosable,
    }
}

/// Render the plan as a compact, operator-facing briefing (plain text). Shows the
/// coverage headline, the top `max_actions` ranked collection steps with their
/// rationale, and the count of gaps that cannot be closed from held entities.
#[must_use]
pub fn render_briefing(plan: &CollectionPlan, max_actions: usize) -> String {
    use std::fmt::Write as _;
    let mut out = String::new();
    let _ = writeln!(
        out,
        "Intelligence-led collection plan — Recon coverage {:.0}% ({}/{} techniques), {} gap(s)",
        plan.coverage_pct(),
        plan.covered.len(),
        plan.covered.len() + plan.gaps.len(),
        plan.gaps.len(),
    );
    if plan.actions.is_empty() {
        let _ = writeln!(
            out,
            "  no actionable collection from held entities — introduce a new seed kind"
        );
        return out;
    }
    for (i, a) in plan.top(max_actions).iter().enumerate() {
        let ids: Vec<&str> = a.closes.iter().map(|t| t.id).collect();
        let cost = match a.cost {
            ModuleCost::Free => "free",
            ModuleCost::KeyGated => "key",
            ModuleCost::Paid => "paid",
        };
        let foot = if a.passive { ", passive" } else { "" };
        let _ = writeln!(
            out,
            "  {}. {} × {} {} ({}{}) → closes {} [{}]",
            i + 1,
            a.module,
            a.held_targets,
            a.target_kind.canonical_str(),
            cost,
            foot,
            a.closes.len(),
            ids.join(", "),
        );
    }
    if !plan.unclosable.is_empty() {
        let ids: Vec<&str> = plan.unclosable.iter().map(|t| t.id).collect();
        let _ = writeln!(
            out,
            "  {} gap(s) unreachable from held entities: {}",
            plan.unclosable.len(),
            ids.join(", "),
        );
    }
    out
}

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
