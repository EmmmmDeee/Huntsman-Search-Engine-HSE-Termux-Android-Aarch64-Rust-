//! Evidence ladder and claim status. Status is not implied by a catalog row.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::error::Error;

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

impl fmt::Display for EvidenceLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for EvidenceLevel {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "assertion" => Ok(Self::Assertion),
            "derived_evidence" => Ok(Self::DerivedEvidence),
            "primary_evidence" => Ok(Self::PrimaryEvidence),
            "independent_corroboration" => Ok(Self::IndependentCorroboration),
            "direct_observation" => Ok(Self::DirectObservation),
            "reproduction" => Ok(Self::Reproduction),
            "end_to_end_demonstration" => Ok(Self::EndToEndDemonstration),
            other => Err(Error::Invalid(format!("unknown evidence level: {other}"))),
        }
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
