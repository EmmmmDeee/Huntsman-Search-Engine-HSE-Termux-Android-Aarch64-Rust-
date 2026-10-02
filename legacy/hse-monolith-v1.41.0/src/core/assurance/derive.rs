//! Evidence → maturity derivation. This is the single place a control's
//! [`AssuranceLevel`] and [`ControlState`] are computed, and it is a pure
//! function of the evidence held plus the control's applicability and prior
//! state. No caller may set a state directly.
//!
//! The invariants it enforces (each covered by a falsifiable test):
//! - **Contiguous ladder.** A rung is earned only if it AND every lower rung has
//!   evidence. A control with a test but no implementation evidence is NOT
//!   `Tested`; the ladder stops at the first missing rung.
//! - **A5 needs observation.** `Observed` requires [`EvidenceKind::RuntimeObservation`];
//!   it can never be synthesised from a definition, implementation or test.
//! - **A6 needs external assurance.** `Assured` requires
//!   [`EvidenceKind::ExternalAssurance`]; internal tests can never produce it.
//! - **Not-applicable is not a deficiency.** A scoped-out control derives to
//!   [`ControlState::NotApplicable`] regardless of evidence.
//! - **Regression demotes.** If a prior state sat at or above a rung the current
//!   evidence no longer supports, the state becomes [`ControlState::Regressed`].

use super::model::{Applicability, AssuranceLevel, ControlState, Evidence, EvidenceKind};

/// The ordered ladder of rungs, lowest → highest. Derivation walks it and stops
/// at the first rung whose evidence is missing, so a higher rung can never be
/// reached over a gap in a lower one.
const LADDER: &[(EvidenceKind, AssuranceLevel)] = &[
    (EvidenceKind::Definition, AssuranceLevel::Defined),
    (EvidenceKind::Implementation, AssuranceLevel::Implemented),
    (EvidenceKind::Enforcement, AssuranceLevel::Enforced),
    (EvidenceKind::Test, AssuranceLevel::Tested),
    (EvidenceKind::RuntimeObservation, AssuranceLevel::Observed),
    (EvidenceKind::ExternalAssurance, AssuranceLevel::Assured),
];

/// True iff the evidence set contains at least one record of `kind`.
fn holds(evidence: &[Evidence], kind: EvidenceKind) -> bool {
    evidence.iter().any(|e| e.kind == kind)
}

/// Derive the maturity level from an evidence set alone: the highest rung `L`
/// such that every rung up to and including `L` has evidence. A gap in any rung
/// caps the level at the rung below it, so `A5`/`A6` are unreachable without
/// their own (runtime / external) evidence AND every prerequisite.
#[must_use]
pub fn derive_level(evidence: &[Evidence]) -> AssuranceLevel {
    let mut level = AssuranceLevel::Unknown;
    for (kind, rung) in LADDER {
        if holds(evidence, *kind) {
            level = *rung;
        } else {
            break;
        }
    }
    level
}

/// Map a from-evidence [`AssuranceLevel`] to the in-scope [`ControlState`] it
/// corresponds to (before applicability and regression are considered).
fn level_to_state(level: AssuranceLevel) -> ControlState {
    match level {
        // In scope but nothing recorded yet.
        AssuranceLevel::Unknown => ControlState::Unknown,
        AssuranceLevel::Defined => ControlState::Defined,
        AssuranceLevel::Implemented => ControlState::Implemented,
        AssuranceLevel::Enforced => ControlState::Enforced,
        AssuranceLevel::Tested => ControlState::Tested,
        AssuranceLevel::Observed => ControlState::Observed,
        AssuranceLevel::Assured => ControlState::Assured,
    }
}

/// The rung a [`ControlState`] represents, for regression comparison. The
/// non-ladder states (`NotApplicable`, `Unknown`, `Gap`, `Regressed`) map to
/// `Unknown` — they carry no earned rung.
fn state_rung(state: ControlState) -> AssuranceLevel {
    match state {
        ControlState::Defined => AssuranceLevel::Defined,
        ControlState::Implemented => AssuranceLevel::Implemented,
        ControlState::Enforced => AssuranceLevel::Enforced,
        ControlState::Tested => AssuranceLevel::Tested,
        ControlState::Observed => AssuranceLevel::Observed,
        ControlState::Assured => AssuranceLevel::Assured,
        _ => AssuranceLevel::Unknown,
    }
}

/// Derive the current control state from applicability, the evidence held, and
/// the prior recorded state.
///
/// - `NotApplicable` applicability short-circuits to
///   [`ControlState::NotApplicable`] — never a deficiency, whatever evidence exists.
/// - Otherwise the from-evidence level maps to a state, except:
///   - a level of `Unknown` (nothing recorded) becomes [`ControlState::Gap`] once
///     the control is `Applicable`/`Conditional` (in scope but unmet), NOT
///     `Unknown` — `Unknown` is reserved for a control never yet assessed
///     (`prior == None`).
///   - if `prior` sat strictly above the current from-evidence rung, the control
///     has gone backwards and becomes [`ControlState::Regressed`].
#[must_use]
pub fn derive_state(
    applicability: Applicability,
    evidence: &[Evidence],
    prior: Option<ControlState>,
) -> ControlState {
    if applicability == Applicability::NotApplicable {
        return ControlState::NotApplicable;
    }

    let level = derive_level(evidence);

    // Regression: a previously-earned rung that the current evidence no longer
    // supports. A prior `NotApplicable`/`Unknown`/`Gap`/`Regressed` carries no
    // rung, so it can never trigger a regression.
    if let Some(prior) = prior {
        let prior_rung = state_rung(prior);
        if prior_rung > level {
            return ControlState::Regressed;
        }
    }

    match level {
        // In scope, nothing met: a first assessment reads `Unknown`; a re-
        // assessment of a control we have looked at before reads `Gap` (we know
        // it is deficient, not merely unassessed).
        AssuranceLevel::Unknown => match prior {
            None => ControlState::Unknown,
            Some(_) => ControlState::Gap,
        },
        other => level_to_state(other),
    }
}
