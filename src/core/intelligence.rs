//! Executable intelligence-tradecraft contracts.
//!
//! This module keeps entities, claims, evidence, and inferences as distinct
//! serializable records. It also provides the conservative claim state machine
//! and bounded, deterministic path frontier used by higher-level planners.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

macro_rules! string_id {
    ($name:ident) => {
        #[derive(
            Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
        )]
        #[serde(transparent)]
        pub struct $name(pub String);

        impl From<&str> for $name {
            fn from(value: &str) -> Self {
                Self(value.to_string())
            }
        }
    };
}

string_id!(ClaimId);
string_id!(EvidenceId);
string_id!(InferenceId);
string_id!(HypothesisId);
string_id!(PathId);

/// Time bounds carried by a claim or observation. `None` means unknown, never
/// "timeless".
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TemporalValidity {
    pub valid_from_unix: Option<u64>,
    pub valid_until_unix: Option<u64>,
    pub observed_at_unix: Option<u64>,
}

/// How a location entered the graph. This is intentionally separate from its
/// numerical confidence and precision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LocationBasis {
    Observed,
    Reported,
    Derived,
    Inferred,
    Historical,
    Administrative,
    NetworkDerived,
    Approximate,
    IndependentlyVerified,
}

/// A location assertion with explicit epistemic basis and precision.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GeoAssertion {
    pub latitude: Option<f64>,
    pub longitude: Option<f64>,
    pub label: Option<String>,
    pub basis: LocationBasis,
    pub method: String,
    pub confidence: f64,
    pub uncertainty_radius_m: Option<f64>,
    pub temporal: TemporalValidity,
    pub competing_location_ids: Vec<EvidenceId>,
}

impl GeoAssertion {
    /// Whether the assertion is internally safe to persist. Unknown precision
    /// is allowed; invalid coordinates, confidence, or negative radius are not.
    #[must_use]
    pub fn is_valid(&self) -> bool {
        let coordinates_valid = match (self.latitude, self.longitude) {
            (Some(lat), Some(lon)) => {
                lat.is_finite()
                    && lon.is_finite()
                    && (-90.0..=90.0).contains(&lat)
                    && (-180.0..=180.0).contains(&lon)
            }
            (None, None) => self.label.as_ref().is_some_and(|v| !v.trim().is_empty()),
            _ => false,
        };
        coordinates_valid
            && self.confidence.is_finite()
            && (0.0..=1.0).contains(&self.confidence)
            && self
                .uncertainty_radius_m
                .is_none_or(|radius| radius.is_finite() && radius >= 0.0)
            && !self.method.trim().is_empty()
    }
}

/// Source authority is one confidence dimension, not a substitute for source
/// independence or agreement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceAuthority {
    PrimaryRecord,
    Official,
    FirstParty,
    ReputableSecondary,
    Secondary,
    Unknown,
}

/// Provenance lineage used both for attribution and copy-chain deduplication.
/// Two reports sharing an origin are one independent source regardless of how
/// many publishers repeat them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceLineage {
    pub source_id: String,
    pub publisher_id: String,
    /// Stable identifiers of the original records/corpora from which this item
    /// descends. For an original observation this contains its own record ID.
    pub origin_ids: BTreeSet<String>,
    pub retrieval_uri: Option<String>,
    pub content_digest: Option<String>,
}

impl SourceLineage {
    #[must_use]
    pub fn is_independent_of(&self, other: &Self) -> bool {
        self.publisher_id != other.publisher_id
            && self.source_id != other.source_id
            && self.origin_ids.is_disjoint(&other.origin_ids)
    }

    fn duplicate_key(&self) -> (&str, Option<&str>) {
        (self.source_id.as_str(), self.content_digest.as_deref())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceNature {
    Observed,
    Reported,
    Derived,
}

/// Evidence is an immutable source-bearing observation. It does not become a
/// claim merely by being inserted.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EvidenceRecord {
    pub id: EvidenceId,
    pub nature: EvidenceNature,
    pub summary: String,
    pub authority: SourceAuthority,
    pub source_confidence: f64,
    pub lineage: SourceLineage,
    pub temporal: TemporalValidity,
    pub jurisdiction: Option<String>,
    pub location: Option<GeoAssertion>,
}

impl EvidenceRecord {
    #[must_use]
    pub fn is_valid(&self) -> bool {
        !self.id.0.trim().is_empty()
            && !self.summary.trim().is_empty()
            && self.source_confidence.is_finite()
            && (0.0..=1.0).contains(&self.source_confidence)
            && !self.lineage.source_id.trim().is_empty()
            && !self.lineage.publisher_id.trim().is_empty()
            && self
                .location
                .as_ref()
                .is_none_or(GeoAssertion::is_valid)
    }
}

/// A claim object can reference an entity, a literal, or a qualified location.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum ClaimObject {
    EntityUid(String),
    Literal(String),
    Location(GeoAssertion),
}

/// Independent confidence dimensions. Callers must not collapse exploration
/// confidence into conclusion confidence.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct ConfidenceDimensions {
    pub exploration: f64,
    pub entity_resolution: f64,
    pub geolocation: Option<f64>,
    pub relationship: f64,
    pub conclusion: f64,
}

impl ConfidenceDimensions {
    #[must_use]
    pub fn is_valid(self) -> bool {
        [
            Some(self.exploration),
            Some(self.entity_resolution),
            self.geolocation,
            Some(self.relationship),
            Some(self.conclusion),
        ]
        .into_iter()
        .flatten()
        .all(|value| value.is_finite() && (0.0..=1.0).contains(&value))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClaimState {
    Candidate,
    Supported,
    Contested,
    Verified,
    Rejected,
}

/// A proposition about an entity. Supporting and contradicting evidence remain
/// attached independently; a conflict is never resolved by overwriting a value.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Claim {
    pub id: ClaimId,
    pub subject_entity_uid: String,
    pub predicate: String,
    pub object: ClaimObject,
    pub state: ClaimState,
    pub confidence: ConfidenceDimensions,
    pub supporting_evidence: BTreeSet<EvidenceId>,
    pub contradicting_evidence: BTreeSet<EvidenceId>,
    pub inference_ids: BTreeSet<InferenceId>,
    pub temporal: TemporalValidity,
    pub jurisdiction: Option<String>,
    pub alternative_explanations: Vec<String>,
    pub strengthening_conditions: Vec<String>,
    pub weakening_conditions: Vec<String>,
    pub falsification_conditions: Vec<String>,
    pub adjudication: Option<String>,
}

impl Claim {
    #[must_use]
    pub fn new(
        id: impl Into<ClaimId>,
        subject_entity_uid: impl Into<String>,
        predicate: impl Into<String>,
        object: ClaimObject,
        confidence: ConfidenceDimensions,
    ) -> Self {
        Self {
            id: id.into(),
            subject_entity_uid: subject_entity_uid.into(),
            predicate: predicate.into(),
            object,
            state: ClaimState::Candidate,
            confidence,
            supporting_evidence: BTreeSet::new(),
            contradicting_evidence: BTreeSet::new(),
            inference_ids: BTreeSet::new(),
            temporal: TemporalValidity::default(),
            jurisdiction: None,
            alternative_explanations: Vec::new(),
            strengthening_conditions: Vec::new(),
            weakening_conditions: Vec::new(),
            falsification_conditions: Vec::new(),
            adjudication: None,
        }
    }
}

/// An inference remains distinguishable from both its premise claims and the
/// conclusion claim it proposes.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Inference {
    pub id: InferenceId,
    pub premise_claim_ids: BTreeSet<ClaimId>,
    pub conclusion_claim_id: ClaimId,
    pub method: String,
    pub confidence: f64,
    pub alternative_explanations: Vec<String>,
    pub falsification_conditions: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HypothesisState {
    Open,
    Supported,
    Weakened,
    Falsified,
}

/// A testable competing explanation. Contradictory and exculpatory evidence is
/// first-class rather than a negative score hidden inside a conclusion.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Hypothesis {
    pub id: HypothesisId,
    pub statement: String,
    pub state: HypothesisState,
    pub supporting_claim_ids: BTreeSet<ClaimId>,
    pub contradicting_claim_ids: BTreeSet<ClaimId>,
    pub discriminating_evidence_needed: Vec<String>,
    pub falsification_conditions: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LedgerError {
    InvalidEvidence,
    InvalidClaim,
    UnknownEvidence(EvidenceId),
    UnknownClaim(ClaimId),
    UnknownInferencePremise(ClaimId),
    DuplicateId,
    RejectionRequiresEvidenceAndRationale,
}

/// In-memory canonical ledger. It is fully serializable for storage inside an
/// existing SQLite/WAL checkpoint transaction.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct IntelligenceLedger {
    pub evidence: BTreeMap<EvidenceId, EvidenceRecord>,
    pub claims: BTreeMap<ClaimId, Claim>,
    pub inferences: BTreeMap<InferenceId, Inference>,
    pub hypotheses: BTreeMap<HypothesisId, Hypothesis>,
}

impl IntelligenceLedger {
    /// Insert evidence, collapsing only an exact same-source/content duplicate.
    /// Reports with shared origins but different content remain preserved while
    /// source-independence counting correctly treats them as dependent.
    pub fn insert_evidence(
        &mut self,
        evidence: EvidenceRecord,
    ) -> Result<EvidenceId, LedgerError> {
        if !evidence.is_valid() {
            return Err(LedgerError::InvalidEvidence);
        }
        if self.evidence.contains_key(&evidence.id) {
            return Err(LedgerError::DuplicateId);
        }
        if let Some(existing) = self.evidence.values().find(|candidate| {
            candidate.lineage.duplicate_key() == evidence.lineage.duplicate_key()
                && evidence.lineage.content_digest.is_some()
        }) {
            return Ok(existing.id.clone());
        }
        let id = evidence.id.clone();
        self.evidence.insert(id.clone(), evidence);
        Ok(id)
    }

    pub fn insert_claim(&mut self, claim: Claim) -> Result<(), LedgerError> {
        if claim.id.0.trim().is_empty()
            || claim.subject_entity_uid.trim().is_empty()
            || claim.predicate.trim().is_empty()
            || !claim.confidence.is_valid()
            || claim.falsification_conditions.is_empty()
        {
            return Err(LedgerError::InvalidClaim);
        }
        if self.claims.insert(claim.id.clone(), claim).is_some() {
            return Err(LedgerError::DuplicateId);
        }
        Ok(())
    }

    pub fn attach_support(
        &mut self,
        claim_id: &ClaimId,
        evidence_id: &EvidenceId,
    ) -> Result<ClaimState, LedgerError> {
        self.attach_evidence(claim_id, evidence_id, false)
    }

    pub fn attach_contradiction(
        &mut self,
        claim_id: &ClaimId,
        evidence_id: &EvidenceId,
    ) -> Result<ClaimState, LedgerError> {
        self.attach_evidence(claim_id, evidence_id, true)
    }

    fn attach_evidence(
        &mut self,
        claim_id: &ClaimId,
        evidence_id: &EvidenceId,
        contradiction: bool,
    ) -> Result<ClaimState, LedgerError> {
        if !self.evidence.contains_key(evidence_id) {
            return Err(LedgerError::UnknownEvidence(evidence_id.clone()));
        }
        let claim = self
            .claims
            .get_mut(claim_id)
            .ok_or_else(|| LedgerError::UnknownClaim(claim_id.clone()))?;
        if contradiction {
            claim.contradicting_evidence.insert(evidence_id.clone());
        } else {
            claim.supporting_evidence.insert(evidence_id.clone());
        }
        self.recompute_claim_state(claim_id)
    }

    pub fn insert_inference(&mut self, inference: Inference) -> Result<(), LedgerError> {
        if self.inferences.contains_key(&inference.id) {
            return Err(LedgerError::DuplicateId);
        }
        for premise in &inference.premise_claim_ids {
            if !self.claims.contains_key(premise) {
                return Err(LedgerError::UnknownInferencePremise(premise.clone()));
            }
        }
        if !inference.confidence.is_finite()
            || !(0.0..=1.0).contains(&inference.confidence)
            || inference.method.trim().is_empty()
            || inference.falsification_conditions.is_empty()
        {
            return Err(LedgerError::InvalidClaim);
        }
        let conclusion = self
            .claims
            .get_mut(&inference.conclusion_claim_id)
            .ok_or_else(|| LedgerError::UnknownClaim(inference.conclusion_claim_id.clone()))?;
        conclusion.inference_ids.insert(inference.id.clone());
        self.inferences.insert(inference.id.clone(), inference);
        Ok(())
    }

    /// Explicit adjudication is the only route to `Rejected`; absence of easy
    /// supporting evidence can never reject a claim.
    pub fn reject_claim(
        &mut self,
        claim_id: &ClaimId,
        evidence_id: &EvidenceId,
        rationale: impl Into<String>,
    ) -> Result<(), LedgerError> {
        let rationale = rationale.into();
        if rationale.trim().is_empty() || !self.evidence.contains_key(evidence_id) {
            return Err(LedgerError::RejectionRequiresEvidenceAndRationale);
        }
        let claim = self
            .claims
            .get_mut(claim_id)
            .ok_or_else(|| LedgerError::UnknownClaim(claim_id.clone()))?;
        claim.contradicting_evidence.insert(evidence_id.clone());
        claim.adjudication = Some(rationale);
        claim.state = ClaimState::Rejected;
        Ok(())
    }

    pub fn recompute_claim_state(
        &mut self,
        claim_id: &ClaimId,
    ) -> Result<ClaimState, LedgerError> {
        let claim = self
            .claims
            .get(claim_id)
            .ok_or_else(|| LedgerError::UnknownClaim(claim_id.clone()))?;
        if claim.state == ClaimState::Rejected {
            return Ok(ClaimState::Rejected);
        }
        let support_ids = claim.supporting_evidence.clone();
        let has_contradiction = !claim.contradicting_evidence.is_empty();
        let conclusion_confidence = claim.confidence.conclusion;
        let inferred_only = !claim.inference_ids.is_empty() && support_ids.is_empty();
        let independent_sources = self.independent_source_count(&support_ids);
        let next = if has_contradiction {
            ClaimState::Contested
        } else if !inferred_only && independent_sources >= 3 && conclusion_confidence >= 0.8 {
            ClaimState::Verified
        } else if independent_sources >= 2 {
            ClaimState::Supported
        } else {
            ClaimState::Candidate
        };
        self.claims
            .get_mut(claim_id)
            .expect("claim was checked above")
            .state = next;
        Ok(next)
    }

    /// Greedy deterministic maximum independent subset. Evidence is sorted by
    /// ID, so persisted/reloaded ledgers produce the same answer.
    #[must_use]
    pub fn independent_source_count(&self, ids: &BTreeSet<EvidenceId>) -> usize {
        let mut independent: Vec<&SourceLineage> = Vec::new();
        for id in ids {
            let Some(candidate) = self.evidence.get(id) else {
                continue;
            };
            if independent
                .iter()
                .all(|accepted| candidate.lineage.is_independent_of(accepted))
            {
                independent.push(&candidate.lineage);
            }
        }
        independent.len()
    }
}

/// Evidence-bearing path candidate. The scheduler never assigns a global score
/// to a person or organization.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PathCandidate {
    pub id: PathId,
    pub entity_uid: String,
    pub depth: u32,
    pub expected_information_gain: f64,
    pub evidence_quality: f64,
    pub source_independence: f64,
    pub bridge_value: f64,
    pub contradiction_value: f64,
    pub novelty: f64,
    pub geo_relevance: f64,
    pub unresolved_ambiguity: f64,
    pub resource_cost: f64,
    pub privacy_proportionate: bool,
}

impl PathCandidate {
    #[must_use]
    pub fn is_valid(&self) -> bool {
        !self.id.0.trim().is_empty()
            && !self.entity_uid.trim().is_empty()
            && [
                self.expected_information_gain,
                self.evidence_quality,
                self.source_independence,
                self.bridge_value,
                self.contradiction_value,
                self.novelty,
                self.geo_relevance,
                self.unresolved_ambiguity,
                self.resource_cost,
            ]
            .into_iter()
            .all(|v| v.is_finite() && (0.0..=1.0).contains(&v))
    }

    /// Additive bounded score. GEOINT receives a modest 0.15 bonus, smaller
    /// than every primary evidence/information term and unable to override a
    /// low-value or expensive path.
    #[must_use]
    pub fn score(&self) -> f64 {
        3.0 * self.expected_information_gain
            + 1.5 * self.evidence_quality
            + 1.5 * self.source_independence
            + self.bridge_value
            + self.contradiction_value
            + self.novelty
            + self.unresolved_ambiguity
            + 0.15 * self.geo_relevance
            - self.resource_cost
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct FrontierBudget {
    pub max_pending: usize,
    pub max_depth: u32,
    pub max_dispatches: usize,
    pub max_concurrency: usize,
}

impl FrontierBudget {
    #[must_use]
    pub fn is_valid(self) -> bool {
        self.max_pending > 0 && self.max_dispatches > 0 && self.max_concurrency > 0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnqueueDecision {
    Accepted,
    ReplacedLowerValue,
    Duplicate,
    Invalid,
    DepthExceeded,
    PrivacyDisproportionate,
    LowerValueThanFrontier,
    BudgetExhausted,
}

/// Serializable frontier checkpoint. Restoring it preserves the visited set,
/// dispatch count, and deterministic pending order.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BoundedFrontier {
    budget: FrontierBudget,
    pending: Vec<PathCandidate>,
    seen: BTreeSet<PathId>,
    dispatched: usize,
}

impl BoundedFrontier {
    pub fn new(budget: FrontierBudget) -> Result<Self, EnqueueDecision> {
        if !budget.is_valid() {
            return Err(EnqueueDecision::Invalid);
        }
        Ok(Self {
            budget,
            pending: Vec::new(),
            seen: BTreeSet::new(),
            dispatched: 0,
        })
    }

    pub fn enqueue(&mut self, candidate: PathCandidate) -> EnqueueDecision {
        if self.dispatched >= self.budget.max_dispatches {
            return EnqueueDecision::BudgetExhausted;
        }
        if !candidate.is_valid() {
            return EnqueueDecision::Invalid;
        }
        if candidate.depth > self.budget.max_depth {
            return EnqueueDecision::DepthExceeded;
        }
        if !candidate.privacy_proportionate {
            return EnqueueDecision::PrivacyDisproportionate;
        }
        if self.seen.contains(&candidate.id) {
            return EnqueueDecision::Duplicate;
        }

        let mut decision = EnqueueDecision::Accepted;
        if self.pending.len() == self.budget.max_pending {
            let worst = self
                .pending
                .iter()
                .enumerate()
                .min_by(|(_, a), (_, b)| {
                    a.score()
                        .total_cmp(&b.score())
                        .then_with(|| b.id.cmp(&a.id))
                })
                .map(|(index, _)| index)
                .expect("non-empty at positive cap");
            let worst_score = self.pending[worst].score();
            if candidate.score().total_cmp(&worst_score).is_le() {
                return EnqueueDecision::LowerValueThanFrontier;
            }
            self.pending.swap_remove(worst);
            decision = EnqueueDecision::ReplacedLowerValue;
        }
        self.seen.insert(candidate.id.clone());
        self.pending.push(candidate);
        decision
    }

    pub fn pop_best(&mut self) -> Option<PathCandidate> {
        if self.dispatched >= self.budget.max_dispatches {
            return None;
        }
        let best = self
            .pending
            .iter()
            .enumerate()
            .max_by(|(_, a), (_, b)| {
                a.score()
                    .total_cmp(&b.score())
                    .then_with(|| b.id.cmp(&a.id))
            })
            .map(|(index, _)| index)?;
        self.dispatched += 1;
        Some(self.pending.swap_remove(best))
    }

    #[must_use]
    pub fn available_concurrency(&self) -> usize {
        self.budget
            .max_concurrency
            .min(self.budget.max_dispatches.saturating_sub(self.dispatched))
            .min(self.pending.len())
    }

    #[must_use]
    pub fn pending_len(&self) -> usize {
        self.pending.len()
    }

    #[must_use]
    pub fn dispatched(&self) -> usize {
        self.dispatched
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dimensions(conclusion: f64) -> ConfidenceDimensions {
        ConfidenceDimensions {
            exploration: 0.9,
            entity_resolution: 0.7,
            geolocation: None,
            relationship: 0.7,
            conclusion,
        }
    }

    fn evidence(id: &str, publisher: &str, origin: &str) -> EvidenceRecord {
        EvidenceRecord {
            id: id.into(),
            nature: EvidenceNature::Observed,
            summary: format!("observation {id}"),
            authority: SourceAuthority::PrimaryRecord,
            source_confidence: 0.9,
            lineage: SourceLineage {
                source_id: id.to_string(),
                publisher_id: publisher.to_string(),
                origin_ids: BTreeSet::from([origin.to_string()]),
                retrieval_uri: None,
                content_digest: Some(format!("digest-{id}")),
            },
            temporal: TemporalValidity::default(),
            jurisdiction: None,
            location: None,
        }
    }

    fn claim() -> Claim {
        let mut claim = Claim::new(
            "claim-1",
            "entity-1",
            "controls",
            ClaimObject::EntityUid("entity-2".to_string()),
            dimensions(0.9),
        );
        claim
            .falsification_conditions
            .push("authoritative ownership record disproves control".to_string());
        claim
    }

    #[test]
    fn copied_reporting_does_not_promote_claim() {
        let mut ledger = IntelligenceLedger::default();
        let a = ledger
            .insert_evidence(evidence("a", "publisher-a", "origin-x"))
            .expect("valid");
        let b = ledger
            .insert_evidence(evidence("b", "publisher-b", "origin-x"))
            .expect("valid");
        ledger.insert_claim(claim()).expect("valid");
        assert_eq!(
            ledger.attach_support(&"claim-1".into(), &a),
            Ok(ClaimState::Candidate)
        );
        assert_eq!(
            ledger.attach_support(&"claim-1".into(), &b),
            Ok(ClaimState::Candidate),
            "two publishers copying one origin are one independent source"
        );
    }

    #[test]
    fn independent_support_promotes_but_contradiction_is_preserved() {
        let mut ledger = IntelligenceLedger::default();
        let ids: Vec<EvidenceId> = ["a", "b", "c", "d"]
            .into_iter()
            .map(|id| {
                ledger
                    .insert_evidence(evidence(id, id, id))
                    .expect("valid")
            })
            .collect();
        ledger.insert_claim(claim()).expect("valid");
        assert_eq!(
            ledger.attach_support(&"claim-1".into(), &ids[0]),
            Ok(ClaimState::Candidate)
        );
        assert_eq!(
            ledger.attach_support(&"claim-1".into(), &ids[1]),
            Ok(ClaimState::Supported)
        );
        assert_eq!(
            ledger.attach_support(&"claim-1".into(), &ids[2]),
            Ok(ClaimState::Verified)
        );
        assert_eq!(
            ledger.attach_contradiction(&"claim-1".into(), &ids[3]),
            Ok(ClaimState::Contested)
        );
        let saved = &ledger.claims[&"claim-1".into()];
        assert_eq!(saved.supporting_evidence.len(), 3);
        assert_eq!(saved.contradicting_evidence.len(), 1);
    }

    #[test]
    fn inference_never_self_promotes_to_fact() {
        let mut ledger = IntelligenceLedger::default();
        let mut premise = Claim::new(
            "premise",
            "entity-1",
            "uses",
            ClaimObject::Literal("identifier".to_string()),
            dimensions(0.9),
        );
        premise
            .falsification_conditions
            .push("source retraction".to_string());
        ledger.insert_claim(premise).expect("valid");
        ledger.insert_claim(claim()).expect("valid");
        ledger
            .insert_inference(Inference {
                id: "inference-1".into(),
                premise_claim_ids: BTreeSet::from(["premise".into()]),
                conclusion_claim_id: "claim-1".into(),
                method: "shared identifier".to_string(),
                confidence: 0.8,
                alternative_explanations: vec!["identifier reuse".to_string()],
                falsification_conditions: vec!["different owners established".to_string()],
            })
            .expect("valid");
        assert_eq!(
            ledger
                .recompute_claim_state(&"claim-1".into())
                .expect("known"),
            ClaimState::Candidate
        );
    }

    fn path(id: &str, info: f64, geo: f64, cost: f64) -> PathCandidate {
        PathCandidate {
            id: id.into(),
            entity_uid: format!("entity-{id}"),
            depth: 1,
            expected_information_gain: info,
            evidence_quality: 0.5,
            source_independence: 0.5,
            bridge_value: 0.5,
            contradiction_value: 0.5,
            novelty: 0.5,
            geo_relevance: geo,
            unresolved_ambiguity: 0.5,
            resource_cost: cost,
            privacy_proportionate: true,
        }
    }

    #[test]
    fn frontier_is_bounded_deterministic_and_geo_is_only_a_modest_bonus() {
        let mut frontier = BoundedFrontier::new(FrontierBudget {
            max_pending: 2,
            max_depth: 3,
            max_dispatches: 2,
            max_concurrency: 1,
        })
        .expect("valid");
        assert_eq!(
            frontier.enqueue(path("low", 0.1, 0.0, 0.9)),
            EnqueueDecision::Accepted
        );
        assert_eq!(
            frontier.enqueue(path("geo", 0.5, 1.0, 0.2)),
            EnqueueDecision::Accepted
        );
        assert_eq!(
            frontier.enqueue(path("bridge", 0.9, 0.0, 0.2)),
            EnqueueDecision::ReplacedLowerValue
        );
        assert_eq!(frontier.pending_len(), 2);
        assert_eq!(frontier.pop_best().expect("candidate").id, "bridge".into());
        assert_eq!(frontier.pop_best().expect("candidate").id, "geo".into());
        assert!(frontier.pop_best().is_none());
    }

    #[test]
    fn checkpoint_round_trip_preserves_budget_and_visited_state() {
        let mut frontier = BoundedFrontier::new(FrontierBudget {
            max_pending: 4,
            max_depth: 5,
            max_dispatches: 2,
            max_concurrency: 2,
        })
        .expect("valid");
        let candidate = path("one", 0.8, 0.5, 0.1);
        assert_eq!(
            frontier.enqueue(candidate.clone()),
            EnqueueDecision::Accepted
        );
        assert!(frontier.pop_best().is_some());
        let bytes = serde_json::to_vec(&frontier).expect("serialize checkpoint");
        let mut resumed: BoundedFrontier =
            serde_json::from_slice(&bytes).expect("restore checkpoint");
        assert_eq!(resumed.dispatched(), 1);
        assert_eq!(
            resumed.enqueue(candidate),
            EnqueueDecision::Duplicate,
            "visited paths remain deduplicated after restart"
        );
        assert_eq!(
            resumed.enqueue(path("two", 0.7, 0.0, 0.1)),
            EnqueueDecision::Accepted
        );
        assert!(resumed.pop_best().is_some());
        assert!(resumed.pop_best().is_none(), "dispatch budget survives restart");
    }

    #[test]
    fn geolocation_requires_explicit_basis_and_valid_precision() {
        let location = GeoAssertion {
            latitude: Some(-33.8688),
            longitude: Some(151.2093),
            label: Some("Sydney".to_string()),
            basis: LocationBasis::Approximate,
            method: "postcode centroid".to_string(),
            confidence: 0.6,
            uncertainty_radius_m: Some(8_000.0),
            temporal: TemporalValidity::default(),
            competing_location_ids: vec![],
        };
        assert!(location.is_valid());
        let mut impossible = location;
        impossible.latitude = Some(120.0);
        assert!(!impossible.is_valid());
    }
}
