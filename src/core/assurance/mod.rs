//! `core::assurance` — the canonical BSI / IT-Grundschutz assurance model for
//! HSE, expressed in HSE's own evidence-and-provenance idiom.
//!
//! # What this is (and is not)
//! This layer maps external BSI framework terminology (BSI 200-x, the
//! IT-Grundschutz Compendium modules, C5) onto ONE canonical control + evidence
//! model, and derives every reported maturity **from recorded evidence**. It is
//! deliberately built so that the strong negations the directive requires hold in
//! code, not just in prose:
//!
//! - `CLAIM ≠ EVIDENCE` — a control's state is [`derive::derive_state`] over its
//!   evidence, never a field a caller can set green.
//! - `TEST PASS ≠ RUNTIME PROOF` — `A5 Observed` requires a
//!   [`RuntimeObservation`](model::EvidenceKind::RuntimeObservation), unreachable
//!   from tests alone.
//! - `RUNTIME PROOF ≠ EXTERNAL ASSURANCE` — `A6 Assured` requires imported
//!   [`ExternalAssurance`](model::EvidenceKind::ExternalAssurance) evidence.
//! - `NOT APPLICABLE ≠ FAILED` — a scoped-out control is
//!   [`NotApplicable`](model::ControlState::NotApplicable), which no gap report
//!   counts as a deficiency and which never docks maturity.
//! - `FRAMEWORK MAPPING ≠ COMPLIANCE` — a catalogued mapping earns only
//!   `A1 Defined`; every higher rung must be earned by its own evidence.
//!
//! # Scope of this unit
//! This module owns the canonical model, the evidence-derivation invariants, and
//! the built-in control catalogue (each control's identity, applicability,
//! protection-need and framework mapping, seeded with only the evidence that is a
//! verifiable static fact — never a synthesised green). Risk (BSI 200-3),
//! detection (`DetectionSpec`), business-continuity (BSI 200-4), provider
//! assurance, persistence and the CLI/API/Web surfaces are separate concepts that
//! reference a control by its `id`; they are layered on in their own units so
//! each concept keeps a single authoritative home.

mod catalog;
mod derive;
mod gap;
mod model;

pub use catalog::catalog;
pub use derive::{derive_level, derive_state};
pub use gap::{GapFinding, GapSeverity, findings, gap_severity};
pub use model::{
    Applicability, AssuranceLevel, ControlState, Evidence, EvidenceKind, Profile,
    ProtectionDimension, ProtectionLevel, ProtectionNeed,
};

use serde::{Deserialize, Serialize};

/// Operational criticality of the capability a control protects — an input to
/// risk prioritisation and gap severity (a `Critical` control at `Gap` is a
/// higher-priority finding than a `Routine` one).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Criticality {
    /// Nice-to-have; degradation is tolerable.
    Routine,
    /// Important; degradation impairs the platform.
    Important,
    /// Critical; failure breaks a core guarantee.
    Critical,
}

/// One canonical assurance control — the single registry entry mapping a BSI
/// requirement onto an HSE capability, its applicability, its protection need,
/// and the evidence recorded for it. Maturity is NOT stored here; it is derived
/// on demand by [`GermanControl::resolve`] so a stale green can never be
/// persisted as fact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GermanControl {
    /// Stable HSE control id, e.g. `HSE-OPS-1.1.5-LOG`.
    pub id: String,
    /// The BSI framework/standard this maps to, e.g. `IT-Grundschutz` or `BSI 200-4`.
    pub framework: String,
    /// The framework version/edition the mapping was read against.
    pub framework_version: String,
    /// The BSI module/building-block id, e.g. `OPS.1.1.5`.
    pub module: String,
    /// The specific requirement text (paraphrased) this control implements.
    pub requirement: String,
    /// The profile this control is assessed under.
    pub profile: Profile,
    /// Whether the control is in scope for this profile.
    pub applicability: Applicability,
    /// Why — mandatory for `Conditional`/`NotApplicable` so a scope-out is never
    /// unexplained.
    pub applicability_reason: String,
    /// Per-dimension Schutzbedarf.
    pub protection_need: ProtectionNeed,
    /// Operational criticality of the protected capability.
    pub criticality: Criticality,
    /// The recorded evidence, in record order.
    pub evidence: Vec<Evidence>,
}

/// A control together with the maturity derived from its current evidence. The
/// derived fields are computed, never stored — recomputing from evidence is the
/// mechanism that makes a regression surface automatically.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ResolvedControl {
    /// The underlying control.
    pub control: GermanControl,
    /// The evidence-derived state.
    pub state: ControlState,
    /// The evidence-derived maturity level.
    pub level: AssuranceLevel,
    /// The prioritised severity of this control's OPEN deficiency, or `None` when
    /// the control is met or correctly out of scope. Computed from the control's
    /// criticality and Schutzbedarf so those fields drive prioritisation rather
    /// than sit unused — see [`gap::gap_severity`].
    pub severity: Option<GapSeverity>,
}

impl GermanControl {
    /// Resolve this control's state and level from its evidence and a prior
    /// state (if the control has been assessed before). This is the ONLY way to
    /// obtain a control's maturity — there is no settable state field.
    #[must_use]
    pub fn resolve(&self, prior: Option<ControlState>) -> ResolvedControl {
        let level = derive_level(&self.evidence);
        let state = derive_state(self.applicability, &self.evidence, prior);
        let severity = gap_severity(state, self.criticality, &self.protection_need);
        ResolvedControl {
            control: self.clone(),
            state,
            level,
            severity,
        }
    }
}

/// Resolve the whole catalogue against no prior state — the fresh-assessment
/// view used by `hse assurance status`. Returns each control with its
/// evidence-derived state and level.
#[must_use]
pub fn resolve_catalog() -> Vec<ResolvedControl> {
    catalog().iter().map(|c| c.resolve(None)).collect()
}

/// A one-line summary of the resolved catalogue for the CLI/API: counts of
/// controls by state. Never fabricates a percentage — it reports raw counts.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct AssuranceSummary {
    /// Total catalogued controls.
    pub total: usize,
    /// Controls correctly out of scope (not counted as deficiencies).
    pub not_applicable: usize,
    /// Controls at a deficiency state (`Unknown`/`Gap`/`Regressed`).
    pub deficiencies: usize,
    /// Controls at `A4 Tested` or higher.
    pub tested_or_higher: usize,
    /// Controls at `A5 Observed` or higher.
    pub observed_or_higher: usize,
    /// Controls at `A6 Assured`.
    pub assured: usize,
    /// Open deficiencies at [`GapSeverity::Critical`] — the fix-first count.
    pub critical_findings: usize,
    /// Open deficiencies at [`GapSeverity::High`].
    pub high_findings: usize,
    /// The most severe open deficiency, or `None` when there are none.
    pub highest_open_severity: Option<GapSeverity>,
}

/// Summarise resolved controls into raw, non-fabricated counts.
#[must_use]
pub fn summarise(resolved: &[ResolvedControl]) -> AssuranceSummary {
    let mut s = AssuranceSummary {
        total: resolved.len(),
        ..AssuranceSummary::default()
    };
    for r in resolved {
        if r.state == ControlState::NotApplicable {
            s.not_applicable += 1;
        }
        if r.state.is_deficiency() {
            s.deficiencies += 1;
        }
        if r.level >= AssuranceLevel::Tested && r.state != ControlState::NotApplicable {
            s.tested_or_higher += 1;
        }
        if r.level >= AssuranceLevel::Observed && r.state != ControlState::NotApplicable {
            s.observed_or_higher += 1;
        }
        if r.level == AssuranceLevel::Assured && r.state == ControlState::Assured {
            s.assured += 1;
        }
        if let Some(sev) = r.severity {
            match sev {
                GapSeverity::Critical => s.critical_findings += 1,
                GapSeverity::High => s.high_findings += 1,
                GapSeverity::Medium | GapSeverity::Low => {}
            }
            s.highest_open_severity = Some(match s.highest_open_severity {
                Some(prev) => prev.max(sev),
                None => sev,
            });
        }
    }
    s
}

#[cfg(test)]
mod tests;
