//! Evidence ladder and claim status. Status is not implied by a catalog row.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceLevel {
    Assertion,
    DerivedEvidence,
    PrimaryEvidence,
    IndependentCorroboration,
    DirectObservation,
    Reproduction,
    EndToEndDemonstration,
}

impl EvidenceLevel {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Assertion => "assertion",
            Self::DerivedEvidence => "derived_evidence",
            Self::PrimaryEvidence => "primary_evidence",
            Self::IndependentCorroboration => "independent_corroboration",
            Self::DirectObservation => "direct_observation",
            Self::Reproduction => "reproduction",
            Self::EndToEndDemonstration => "end_to_end_demonstration",
        }
    }

    /// Interop gate floor. Below this, a claim cannot enter STIX or Navigator.
    #[must_use]
    pub fn admits_interop(self) -> bool {
        self >= Self::DirectObservation
    }
}

/// Claim classification. Only `Verified` can pass the interop gate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    Verified,
    Partial,
    Unverified,
    NotApplicable,
}

impl Status {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Verified => "verified",
            Self::Partial => "partial",
            Self::Unverified => "unverified",
            Self::NotApplicable => "not_applicable",
        }
    }
}
