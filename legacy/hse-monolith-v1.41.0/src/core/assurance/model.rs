//! Canonical BSI-assurance model types — the evidence, states, maturity levels,
//! applicability profiles and protection-need model that the whole assurance
//! layer is derived from.
//!
//! This module is **pure** (no I/O, no `crate::modules`): it defines the
//! vocabulary and the derivation invariants. The single hard rule it exists to
//! enforce, in code, is that a control's reported maturity is a **function of the
//! evidence actually held**, never presentation-layer input — so a green control
//! can never be asserted, only earned. See [`super::derive`] for the derivation.

use serde::{Deserialize, Serialize};

/// A BSI applicability profile — the deployment/scope lens a control is assessed
/// under. A control can carry different applicability under different profiles
/// (C5 is `NotApplicable` on a local Termux profile but `Applicable` on a cloud
/// one), so maturity is never docked for an irrelevant framework control that is
/// *correctly* classified as not applicable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Profile {
    /// `HSE-BSI-CORE` — controls that apply to every HSE deployment.
    Core,
    /// `HSE-BSI-DEVELOPMENT` — CON.8 / OPS.1.1.6 software development & release.
    Development,
    /// `HSE-BSI-ANDROID` — APP.1.4 mobile-application and Android-platform controls.
    Android,
    /// `HSE-BSI-BLE` — the BLE-radar sensing surface.
    Ble,
    /// `HSE-BSI-TERMUX` — the no-root Termux userland profile.
    Termux,
    /// `HSE-BSI-WEB` — APP.3.1 web-application / web-service (the embedded UI + API).
    Web,
    /// `HSE-BSI-STORAGE` — APP.4.3 relational-database (SQLite/WAL) controls.
    Storage,
    /// `HSE-BSI-CLOUD` — C5 shared-responsibility controls, only for a cloud-hosted
    /// deployment profile.
    Cloud,
    /// `HSE-BSI-INTELLIGENCE` — the OSINT/GEOINT/breach-intelligence collection surface.
    Intelligence,
}

impl Profile {
    /// The canonical `HSE-BSI-*` identifier.
    #[must_use]
    pub fn id(self) -> &'static str {
        match self {
            Self::Core => "HSE-BSI-CORE",
            Self::Development => "HSE-BSI-DEVELOPMENT",
            Self::Android => "HSE-BSI-ANDROID",
            Self::Ble => "HSE-BSI-BLE",
            Self::Termux => "HSE-BSI-TERMUX",
            Self::Web => "HSE-BSI-WEB",
            Self::Storage => "HSE-BSI-STORAGE",
            Self::Cloud => "HSE-BSI-CLOUD",
            Self::Intelligence => "HSE-BSI-INTELLIGENCE",
        }
    }

    /// Every profile, for enumeration in the CLI/API and for completeness tests.
    #[must_use]
    pub fn all() -> &'static [Profile] {
        &[
            Self::Core,
            Self::Development,
            Self::Android,
            Self::Ble,
            Self::Termux,
            Self::Web,
            Self::Storage,
            Self::Cloud,
            Self::Intelligence,
        ]
    }

    /// Parse a profile name as the CLI and API accept it — case-insensitively,
    /// as the bare word (`android`), the full id (`HSE-BSI-ANDROID`), or the
    /// `railway` alias for the cloud deployment (C5's profile). The ONE parser
    /// both surfaces share, so the accepted vocabulary can never drift between
    /// `hse assurance --profile` and `/api/v1/assurance?profile=`. `None` for
    /// an unknown name; callers report [`Self::short_names`] as the valid set.
    #[must_use]
    pub fn parse(s: &str) -> Option<Profile> {
        let want = s.trim().to_ascii_lowercase();
        if want == "railway" {
            return Some(Self::Cloud);
        }
        Self::all().iter().copied().find(|p| {
            let id = p.id().to_ascii_lowercase();
            id == want || id.strip_prefix("hse-bsi-") == Some(want.as_str())
        })
    }

    /// The bare lower-case profile words [`Self::parse`] accepts (`core`,
    /// `android`, …), for "valid values" messages — single-sourced from
    /// [`Self::all`] so the list can never fall out of step with the enum.
    #[must_use]
    pub fn short_names() -> Vec<String> {
        Self::all()
            .iter()
            .map(|p| {
                p.id()
                    .strip_prefix("HSE-BSI-")
                    .unwrap_or(p.id())
                    .to_ascii_lowercase()
            })
            .collect()
    }
}

/// Whether a control is in scope for a given deployment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Applicability {
    /// The control applies and must be assessed.
    Applicable,
    /// The control applies only under a named condition (e.g. an enterprise MDM
    /// fleet, a cloud deployment) — the `applicability_reason` records which.
    Conditional,
    /// The control does not apply to this deployment. This is **not a failure**
    /// and never reduces maturity — a correctly-scoped-out control is
    /// [`ControlState::NotApplicable`], distinct from every deficiency state.
    NotApplicable,
}

/// A protection-need dimension (Schutzbedarf axis). Protection need is assessed
/// per dimension because a control can be, e.g., availability-critical but
/// confidentiality-normal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ProtectionDimension {
    /// Disclosure sensitivity.
    Confidentiality,
    /// Correctness / tamper-resistance.
    Integrity,
    /// Uptime / recoverability.
    Availability,
    /// Genuineness of origin.
    Authenticity,
    /// Auditability — the ability to reconstruct what happened (OPS.1.1.5).
    Traceability,
    /// Personal-data protection.
    Privacy,
}

impl ProtectionDimension {
    /// Every dimension, for completeness tests and per-dimension assessment.
    #[must_use]
    pub fn all() -> &'static [ProtectionDimension] {
        &[
            Self::Confidentiality,
            Self::Integrity,
            Self::Availability,
            Self::Authenticity,
            Self::Traceability,
            Self::Privacy,
        ]
    }
}

/// The Schutzbedarf level for one dimension. Ordered so `>=` comparisons express
/// "at least this protection need"; higher need drives stronger downstream
/// control, testing, storage and recovery requirements (it is never passive
/// metadata — see [`ProtectionNeed::drives_high_assurance`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ProtectionLevel {
    /// Normal protection need.
    Normal,
    /// High protection need.
    High,
    /// Very high protection need.
    VeryHigh,
}

/// Evidence-maturity levels (A0–A6). Each higher level requires evidence of
/// **every** prerequisite level — no control may jump from documentation to
/// verified or assured. `A5`/`A6` require observed-runtime / external-assurance
/// evidence respectively and can never be produced from internal definitions or
/// tests alone.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum AssuranceLevel {
    /// A0 — unknown; no evidence of any kind.
    Unknown,
    /// A1 — defined; the control has a written definition/requirement mapping.
    Defined,
    /// A2 — implemented; an authoritative production implementation exists.
    Implemented,
    /// A3 — enforced; the implementation is actually on the production path / gated.
    Enforced,
    /// A4 — tested; a test exercises the enforced behaviour.
    Tested,
    /// A5 — observed; the behaviour has been observed at runtime.
    Observed,
    /// A6 — assured; independent (external) assurance evidence has been recorded.
    Assured,
}

impl AssuranceLevel {
    /// The `A0..A6` short code.
    #[must_use]
    pub fn code(self) -> &'static str {
        match self {
            Self::Unknown => "A0",
            Self::Defined => "A1",
            Self::Implemented => "A2",
            Self::Enforced => "A3",
            Self::Tested => "A4",
            Self::Observed => "A5",
            Self::Assured => "A6",
        }
    }
}

/// The evidence-derived state of a control. Distinct from [`AssuranceLevel`]:
/// the level is the maturity ladder; the state adds the two lifecycle outcomes a
/// ladder position can't express — a scoped-out control ([`Self::NotApplicable`])
/// and a control whose current evidence has invalidated a previously-earned
/// position ([`Self::Regressed`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ControlState {
    /// Correctly out of scope for this profile — not a deficiency.
    NotApplicable,
    /// In scope but no evidence yet (A0).
    Unknown,
    /// In scope, defined, but not yet implemented — a real deficiency to close.
    Gap,
    /// A1 — defined only.
    Defined,
    /// A2 — an authoritative implementation exists.
    Implemented,
    /// A3 — enforced on the production path.
    Enforced,
    /// A4 — tested.
    Tested,
    /// A5 — observed at runtime.
    Observed,
    /// A6 — externally assured.
    Assured,
    /// A previously-earned state that current evidence no longer supports — the
    /// control has gone backwards and must be re-verified before it can be
    /// reported green again.
    Regressed,
}

impl ControlState {
    /// The screaming-snake identifier (matches serde output).
    #[must_use]
    pub fn id(self) -> &'static str {
        match self {
            Self::NotApplicable => "NOT_APPLICABLE",
            Self::Unknown => "UNKNOWN",
            Self::Gap => "GAP",
            Self::Defined => "DEFINED",
            Self::Implemented => "IMPLEMENTED",
            Self::Enforced => "ENFORCED",
            Self::Tested => "TESTED",
            Self::Observed => "OBSERVED",
            Self::Assured => "ASSURED",
            Self::Regressed => "REGRESSED",
        }
    }

    /// Whether this state is a deficiency that a gap report should surface. A
    /// scoped-out control is NOT a deficiency; a regression IS.
    #[must_use]
    pub fn is_deficiency(self) -> bool {
        matches!(self, Self::Unknown | Self::Gap | Self::Regressed)
    }
}

/// One category of maturity evidence a control can hold. The categories are the
/// rungs of the [`AssuranceLevel`] ladder; holding a rung's evidence is the ONLY
/// way to earn that rung.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EvidenceKind {
    /// A written definition / framework-requirement mapping (earns A1).
    Definition,
    /// An authoritative production implementation reference (earns A2).
    Implementation,
    /// Proof the implementation is on the production path / gated (earns A3).
    Enforcement,
    /// A test that exercises the enforced behaviour (earns A4).
    Test,
    /// An observation of the behaviour at runtime (earns A5). Can NEVER be
    /// synthesised from a definition, implementation or test.
    RuntimeObservation,
    /// Imported or recorded INDEPENDENT assurance evidence (earns A6). Can NEVER
    /// be generated from internal evidence.
    ExternalAssurance,
}

impl EvidenceKind {
    /// The maturity rung this evidence category earns (given every lower rung is
    /// also held).
    #[must_use]
    pub fn earns(self) -> AssuranceLevel {
        match self {
            Self::Definition => AssuranceLevel::Defined,
            Self::Implementation => AssuranceLevel::Implemented,
            Self::Enforcement => AssuranceLevel::Enforced,
            Self::Test => AssuranceLevel::Tested,
            Self::RuntimeObservation => AssuranceLevel::Observed,
            Self::ExternalAssurance => AssuranceLevel::Assured,
        }
    }
}

/// A single piece of recorded evidence: what kind, where it came from, and when
/// it was recorded. Provenance (`source`) is mandatory so no rung is ever earned
/// by an unattributed assertion.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Evidence {
    /// Which maturity rung this evidence speaks to.
    pub kind: EvidenceKind,
    /// A provenance reference — a repo path, a test name, a runtime event id, or
    /// an external report identifier. Never empty for valid evidence.
    pub source: String,
    /// A one-line human description of what was observed/recorded.
    pub detail: String,
    /// Unix seconds when this evidence was recorded.
    pub recorded_at: u64,
}

impl Evidence {
    /// Construct an evidence record. `source` and `detail` are trimmed; a blank
    /// `source` yields `None` because unattributed evidence is not evidence.
    #[must_use]
    pub fn new(
        kind: EvidenceKind,
        source: impl Into<String>,
        detail: impl Into<String>,
        recorded_at: u64,
    ) -> Option<Self> {
        let source = source.into().trim().to_string();
        if source.is_empty() {
            return None;
        }
        Some(Self {
            kind,
            source,
            detail: detail.into().trim().to_string(),
            recorded_at,
        })
    }
}

/// A control's per-dimension protection need. Absent dimensions default to
/// [`ProtectionLevel::Normal`].
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProtectionNeed {
    /// The non-normal dimensions and their levels. A dimension absent here is
    /// `Normal` by definition, so the common case stores nothing.
    #[serde(default)]
    pub elevated: Vec<(ProtectionDimension, ProtectionLevel)>,
}

impl ProtectionNeed {
    /// The level for one dimension (`Normal` when unspecified).
    #[must_use]
    pub fn level(&self, dim: ProtectionDimension) -> ProtectionLevel {
        self.elevated
            .iter()
            .find(|(d, _)| *d == dim)
            .map_or(ProtectionLevel::Normal, |(_, l)| *l)
    }

    /// The highest protection need across all dimensions.
    #[must_use]
    pub fn max_level(&self) -> ProtectionLevel {
        self.elevated
            .iter()
            .map(|(_, l)| *l)
            .max()
            .unwrap_or(ProtectionLevel::Normal)
    }

    /// Whether this control's protection need demands the stronger assurance
    /// treatment (High or Very High on any dimension) — the downstream driver
    /// that makes protection need active rather than passive metadata: a
    /// High/Very-High control that has not reached [`AssuranceLevel::Tested`] is
    /// a more severe gap than a Normal one.
    #[must_use]
    pub fn drives_high_assurance(&self) -> bool {
        self.max_level() >= ProtectionLevel::High
    }
}

#[cfg(test)]
mod profile_parse_tests {
    use super::Profile;

    #[test]
    fn parse_accepts_bare_word_full_id_any_case_and_the_railway_alias() {
        assert_eq!(Profile::parse("android"), Some(Profile::Android));
        assert_eq!(Profile::parse("HSE-BSI-ANDROID"), Some(Profile::Android));
        assert_eq!(Profile::parse("  Hse-Bsi-Web "), Some(Profile::Web));
        // The cloud deployment's alias — C5's profile.
        assert_eq!(Profile::parse("railway"), Some(Profile::Cloud));
        assert_eq!(Profile::parse("RAILWAY"), Some(Profile::Cloud));
    }

    #[test]
    fn parse_rejects_unknown_names_rather_than_guessing() {
        assert_eq!(Profile::parse("bogus"), None);
        assert_eq!(Profile::parse(""), None);
        assert_eq!(Profile::parse("hse-bsi-"), None);
    }

    #[test]
    fn every_profile_round_trips_and_short_names_is_complete() {
        // `short_names` is the "valid values" list both the CLI error and the
        // API 400 print — it must name every profile, and every name must parse
        // back to its own variant (as must the full id).
        let names = Profile::short_names();
        assert_eq!(names.len(), Profile::all().len());
        for (p, name) in Profile::all().iter().zip(&names) {
            assert_eq!(Profile::parse(name), Some(*p), "{name} must parse to {p:?}");
            assert_eq!(Profile::parse(p.id()), Some(*p));
        }
    }
}
