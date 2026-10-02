//! Evidence-backed, reversible identity-resolution decisions.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResolutionState {
    Match,
    Probable,
    Possible,
    NonMatch,
    Contradicted,
    Unresolved,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResolutionEvidence {
    pub evidence_id: String,
    /// Independent ancestry family, not merely the emitting module.
    pub source_family: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct IdentityResolutionDecision {
    pub left_entity_uid: String,
    pub right_entity_uid: String,
    pub state: ResolutionState,
    pub probability: Option<f64>,
    pub supporting: Vec<ResolutionEvidence>,
    pub contradicting: Vec<ResolutionEvidence>,
    pub temporal_conflict: bool,
    pub geographic_conflict: bool,
    pub decided_at_unix: u64,
}

impl IdentityResolutionDecision {
    #[must_use]
    pub fn is_valid(&self) -> bool {
        !self.left_entity_uid.trim().is_empty()
            && !self.right_entity_uid.trim().is_empty()
            && self.left_entity_uid != self.right_entity_uid
            && self
                .probability
                .is_none_or(|p| p.is_finite() && (0.0..=1.0).contains(&p))
            && self
                .supporting
                .iter()
                .all(|e| !e.evidence_id.trim().is_empty() && !e.source_family.trim().is_empty())
            && self
                .contradicting
                .iter()
                .all(|e| !e.evidence_id.trim().is_empty() && !e.source_family.trim().is_empty())
    }

    #[must_use]
    pub fn independent_support_families(&self) -> usize {
        self.supporting
            .iter()
            .map(|e| e.source_family.as_str())
            .collect::<BTreeSet<_>>()
            .len()
    }

    #[must_use]
    pub fn independent_contradiction_families(&self) -> usize {
        self.contradicting
            .iter()
            .map(|e| e.source_family.as_str())
            .collect::<BTreeSet<_>>()
            .len()
    }

    /// Automatic merge is deliberately stricter than "probable".  A probable
    /// link remains a hypothesis unless an operator or a later policy explicitly
    /// promotes it.
    #[must_use]
    pub fn allows_automatic_merge(&self, policy: AutoMergePolicy) -> bool {
        self.is_valid()
            && self.state == ResolutionState::Match
            && self.independent_support_families() >= policy.min_independent_support_families
            && self.independent_contradiction_families() == 0
            && !self.temporal_conflict
            && !self.geographic_conflict
            && self
                .probability
                .is_none_or(|p| p >= policy.min_match_probability)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct AutoMergePolicy {
    pub min_independent_support_families: usize,
    pub min_match_probability: f64,
}

impl Default for AutoMergePolicy {
    fn default() -> Self {
        Self {
            min_independent_support_families: 2,
            min_match_probability: 0.90,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn evidence(id: &str, family: &str) -> ResolutionEvidence {
        ResolutionEvidence {
            evidence_id: id.to_owned(),
            source_family: family.to_owned(),
        }
    }

    #[test]
    fn same_family_repetition_never_satisfies_two_source_merge_gate() {
        let decision = IdentityResolutionDecision {
            left_entity_uid: "a".into(),
            right_entity_uid: "b".into(),
            state: ResolutionState::Match,
            probability: Some(0.99),
            supporting: vec![
                evidence("e1", "same-upstream"),
                evidence("e2", "same-upstream"),
            ],
            contradicting: vec![],
            temporal_conflict: false,
            geographic_conflict: false,
            decided_at_unix: 1,
        };
        assert!(!decision.allows_automatic_merge(AutoMergePolicy::default()));
    }

    #[test]
    fn contradiction_blocks_automatic_merge() {
        let decision = IdentityResolutionDecision {
            left_entity_uid: "a".into(),
            right_entity_uid: "b".into(),
            state: ResolutionState::Match,
            probability: Some(0.99),
            supporting: vec![evidence("e1", "registry"), evidence("e2", "first-party")],
            contradicting: vec![evidence("e3", "court-record")],
            temporal_conflict: false,
            geographic_conflict: false,
            decided_at_unix: 1,
        };
        assert!(!decision.allows_automatic_merge(AutoMergePolicy::default()));
    }

    #[test]
    fn probable_is_not_an_automatic_merge() {
        let decision = IdentityResolutionDecision {
            left_entity_uid: "a".into(),
            right_entity_uid: "b".into(),
            state: ResolutionState::Probable,
            probability: Some(0.99),
            supporting: vec![evidence("e1", "registry"), evidence("e2", "first-party")],
            contradicting: vec![],
            temporal_conflict: false,
            geographic_conflict: false,
            decided_at_unix: 1,
        };
        assert!(!decision.allows_automatic_merge(AutoMergePolicy::default()));
    }
}
