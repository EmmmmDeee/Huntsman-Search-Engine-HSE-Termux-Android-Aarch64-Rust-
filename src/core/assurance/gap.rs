//! Gap prioritisation — the single place a control's OPEN deficiency is turned
//! into a graded severity, so `criticality` and `protection_need` (Schutzbedarf)
//! stop being passive metadata and actually drive what a reader sees first.
//!
//! # Why this exists
//! The canonical model records, per control, its operational [`Criticality`] and
//! its per-dimension [`ProtectionNeed`]. Without a consumer those fields are
//! dormant — recorded but never acted on. This module is that consumer: it maps
//! a deficiency to a [`GapSeverity`] so a `Critical`, very-high-Schutzbedarf
//! control that has **regressed** is reported as a `Critical` finding, ahead of a
//! `Routine`, normal-need control that is merely `Unknown`.
//!
//! # The invariant it locks (all falsifiable — see the unit tests)
//! Severity is a **monotone** function of the three impact drivers: raising
//! [`Criticality`], raising the Schutzbedarf [`max_level`](ProtectionNeed::max_level),
//! or deepening the deficiency (`Unknown` → `Gap` → `Regressed`) can only ever
//! *raise* severity, never lower it. A control that is not a deficiency (met, or
//! correctly [`NotApplicable`](ControlState::NotApplicable)) has **no** severity —
//! `NOT_APPLICABLE ≠ FAILED` holds here too: a scoped-out control is never a
//! finding.

use serde::Serialize;

use super::model::{ControlState, ProtectionLevel, ProtectionNeed};
use super::{Criticality, ResolvedControl};

/// The severity band of an OPEN deficiency — the prioritisation a gap report and
/// the CLI/API use to order findings. Ordered `Low < Medium < High < Critical`
/// so `max`/`>=` express "at least this urgent".
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum GapSeverity {
    /// Low — a deficiency on a low-impact, normal-need control.
    Low,
    /// Medium — a deficiency with some impact or elevated protection need.
    Medium,
    /// High — a deficiency on an important/critical or high-Schutzbedarf control.
    High,
    /// Critical — a deficiency on a critical, very-high-need control, or a
    /// regression of one: the finding to fix first.
    Critical,
}

impl GapSeverity {
    /// A stable upper-case label for the CLI/API.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::Low => "LOW",
            Self::Medium => "MEDIUM",
            Self::High => "HIGH",
            Self::Critical => "CRITICAL",
        }
    }
}

/// The impact weight of a criticality (0..=2).
fn criticality_weight(c: Criticality) -> u8 {
    match c {
        Criticality::Routine => 0,
        Criticality::Important => 1,
        Criticality::Critical => 2,
    }
}

/// The impact weight of the highest protection need across dimensions (0..=2).
fn protection_weight(need: &ProtectionNeed) -> u8 {
    match need.max_level() {
        ProtectionLevel::Normal => 0,
        ProtectionLevel::High => 1,
        ProtectionLevel::VeryHigh => 2,
    }
}

/// How deep the deficiency is (0..=2). `Regressed` (a previously-earned rung
/// lost — actively broken) outweighs `Gap` (in scope, confirmed unmet), which
/// outweighs `Unknown` (in scope, not yet assessed). Non-deficiency states carry
/// no depth (they are filtered out before this is reached).
fn deficiency_depth(state: ControlState) -> u8 {
    match state {
        ControlState::Regressed => 2,
        ControlState::Gap => 1,
        _ => 0,
    }
}

/// The severity of a control's OPEN deficiency, or `None` when the control is not
/// a deficiency (a met rung, or correctly out of scope). Severity is the monotone
/// sum of the three impact weights, banded:
///
/// - `0`      → [`GapSeverity::Low`]
/// - `1..=2`  → [`GapSeverity::Medium`]
/// - `3..=4`  → [`GapSeverity::High`]
/// - `5..=6`  → [`GapSeverity::Critical`]
#[must_use]
pub fn gap_severity(
    state: ControlState,
    criticality: Criticality,
    need: &ProtectionNeed,
) -> Option<GapSeverity> {
    if !state.is_deficiency() {
        return None;
    }
    let score = criticality_weight(criticality) + protection_weight(need) + deficiency_depth(state);
    Some(match score {
        0 => GapSeverity::Low,
        1..=2 => GapSeverity::Medium,
        3..=4 => GapSeverity::High,
        _ => GapSeverity::Critical,
    })
}

/// One prioritised open finding — a deficient control with its computed severity
/// and the impact drivers behind it, ready for a gap report / CLI / API.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct GapFinding {
    /// The control's stable id.
    pub control_id: String,
    /// The BSI module id.
    pub module: String,
    /// The deficiency state (`UNKNOWN` / `GAP` / `REGRESSED`).
    pub state: ControlState,
    /// The computed severity.
    pub severity: GapSeverity,
    /// The control's operational criticality (an impact driver).
    pub criticality: Criticality,
    /// Whether the control's Schutzbedarf demanded elevated assurance (an impact
    /// driver — `true` when any dimension is High/Very-High).
    pub high_protection_need: bool,
}

/// Collect the open findings from a resolved catalogue, most-severe first (ties
/// broken by criticality, then control id for a stable order). Met and
/// out-of-scope controls produce no finding.
#[must_use]
pub fn findings(resolved: &[ResolvedControl]) -> Vec<GapFinding> {
    let mut out: Vec<GapFinding> = resolved
        .iter()
        .filter_map(|r| {
            gap_severity(r.state, r.control.criticality, &r.control.protection_need).map(
                |severity| GapFinding {
                    control_id: r.control.id.clone(),
                    module: r.control.module.clone(),
                    state: r.state,
                    severity,
                    criticality: r.control.criticality,
                    high_protection_need: r.control.protection_need.drives_high_assurance(),
                },
            )
        })
        .collect();
    // Most severe first; then most critical; then id for determinism.
    out.sort_by(|a, b| {
        b.severity
            .cmp(&a.severity)
            .then_with(|| b.criticality.cmp(&a.criticality))
            .then_with(|| a.control_id.cmp(&b.control_id))
    });
    out
}
