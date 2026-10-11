//! Intelligence ledger and aggregated report views.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::community::detect_communities;
use crate::entity::Entity;
use crate::exposure::{ExposureFinding, compute_exposure};
use crate::graph::{EntityRelation, Graph};
use crate::leads::{Lead, rank_leads};
use crate::profiles::{EntityProfile, build_profiles};
use crate::timeline::{TimelineEvent, reconstruct};

macro_rules! string_id {
    ($name:ident) => {
        #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
        #[serde(transparent)]
        pub struct $name(pub String);

        impl From<&str> for $name {
            fn from(value: &str) -> Self {
                Self(value.to_string())
            }
        }

        impl std::fmt::Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str(&self.0)
            }
        }
    };
}

string_id!(ClaimId);
string_id!(EvidenceId);
string_id!(InferenceId);
string_id!(HypothesisId);

const EARTH_RADIUS_M: f64 = 6_371_008.8;

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TemporalValidity {
    pub not_before_unix: Option<i64>,
    pub not_after_unix: Option<i64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LocationBasis {
    Subject,
    Infrastructure,
    Registration,
    Inference,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GeoAssertion {
    pub latitude: f64,
    pub longitude: f64,
    pub label: Option<String>,
    pub basis: LocationBasis,
    pub method: String,
    pub confidence: f32,
    pub uncertainty_radius_m: Option<f64>,
    #[serde(default)]
    pub temporal: TemporalValidity,
    #[serde(default)]
    pub competing_location_ids: BTreeSet<String>,
}

impl GeoAssertion {
    #[must_use]
    pub fn is_valid(&self) -> bool {
        (-90.0..=90.0).contains(&self.latitude)
            && (-180.0..=180.0).contains(&self.longitude)
            && (0.0..=1.0).contains(&self.confidence)
            && self
                .uncertainty_radius_m
                .is_none_or(|radius| radius.is_finite() && radius >= 0.0)
            && !self.method.trim().is_empty()
    }

    #[must_use]
    pub fn effective_uncertainty_m(&self) -> f64 {
        self.uncertainty_radius_m.unwrap_or(25_000.0)
    }

    #[must_use]
    pub fn separation_m(&self, other: &Self) -> f64 {
        let left_latitude = self.latitude.to_radians();
        let right_latitude = other.latitude.to_radians();
        let latitude_delta = (other.latitude - self.latitude).to_radians();
        let longitude_delta = (other.longitude - self.longitude).to_radians();
        let a = (latitude_delta / 2.0).sin().powi(2)
            + left_latitude.cos() * right_latitude.cos() * (longitude_delta / 2.0).sin().powi(2);
        let c = 2.0 * a.sqrt().asin();
        EARTH_RADIUS_M * c
    }

    #[must_use]
    pub fn conflicts_with(&self, other: &Self) -> bool {
        self.separation_m(other) > self.effective_uncertainty_m() + other.effective_uncertainty_m()
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum GeoResolution {
    None,
    Converged(GeoAssertion),
    Conflict(Vec<GeoAssertion>),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SourceAuthority {
    Primary,
    Secondary,
    Tertiary,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceLineage {
    pub source_id: String,
    pub origin_id: Option<String>,
    pub chain: Vec<String>,
    pub authority: SourceAuthority,
}

impl SourceLineage {
    #[must_use]
    pub fn independence_key(&self) -> String {
        self.origin_id
            .as_ref()
            .filter(|origin| !origin.trim().is_empty())
            .cloned()
            .unwrap_or_else(|| self.source_id.clone())
    }

    /// Returns a provenance root only when ancestry is actually known.
    /// Unknown ancestry must never be promoted into independence by falling
    /// back to a provider or retrieval label.
    #[must_use]
    pub fn known_origin_key(&self) -> Option<&str> {
        self.origin_id
            .as_deref()
            .map(str::trim)
            .filter(|origin| !origin.is_empty())
    }

    #[must_use]
    pub fn is_independent_of(&self, other: &Self) -> bool {
        matches!(
            (self.known_origin_key(), other.known_origin_key()),
            (Some(left), Some(right)) if left != right
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum EvidenceNature {
    Observed,
    Derived,
    Provider,
    Contradiction,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceRecord {
    pub id: EvidenceId,
    pub subject_uid: String,
    pub summary: String,
    pub lineage: SourceLineage,
    pub observed_at_unix: Option<i64>,
    pub recorded_at_unix: i64,
    pub nature: EvidenceNature,
    pub content_digest: Option<String>,
    #[serde(default)]
    pub attributes: BTreeMap<String, String>,
    #[serde(default)]
    pub ancestry_root_families: BTreeSet<String>,
}

impl EvidenceRecord {
    #[must_use]
    pub fn is_valid(&self) -> bool {
        !self.id.0.trim().is_empty()
            && !self.subject_uid.trim().is_empty()
            && !self.summary.trim().is_empty()
            && !self.lineage.source_id.trim().is_empty()
            && self
                .content_digest
                .as_ref()
                .is_none_or(|digest| !digest.trim().is_empty())
    }

    #[must_use]
    pub fn duplicate_key(&self) -> Option<(String, String, String)> {
        self.content_digest.as_ref().map(|digest| {
            (
                self.subject_uid.clone(),
                self.lineage.independence_key(),
                digest.clone(),
            )
        })
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ClaimObject {
    Attribute {
        key: String,
        value: String,
    },
    Relationship {
        relation: String,
        target_uid: String,
    },
    Location(GeoAssertion),
    Narrative(String),
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ConfidenceDimensions {
    pub exploration: f32,
    pub entity_resolution: f32,
    pub geolocation: f32,
    pub relationship: f32,
    pub conclusion: f32,
}

impl Default for ConfidenceDimensions {
    fn default() -> Self {
        Self {
            exploration: 0.0,
            entity_resolution: 0.0,
            geolocation: 0.0,
            relationship: 0.0,
            conclusion: 0.0,
        }
    }
}

impl ConfidenceDimensions {
    #[must_use]
    pub fn is_valid(&self) -> bool {
        [
            self.exploration,
            self.entity_resolution,
            self.geolocation,
            self.relationship,
            self.conclusion,
        ]
        .into_iter()
        .all(|value| (0.0..=1.0).contains(&value))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ClaimState {
    Candidate,
    Supported,
    Verified,
    Rejected,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DefeatKind {
    Rebut,
    Undermine,
    Undercut,
    Supersede,
    Compatible,
    UnknownRelation,
}

impl DefeatKind {
    #[must_use]
    pub fn blocks_verification(self) -> bool {
        matches!(self, Self::Rebut | Self::Undermine | Self::Undercut)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Defeat {
    pub evidence_id: EvidenceId,
    pub kind: DefeatKind,
    pub temporal_overlap: Option<bool>,
    pub rationale: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Claim {
    pub id: ClaimId,
    pub subject_uid: String,
    pub object: ClaimObject,
    pub state: ClaimState,
    pub confidence: ConfidenceDimensions,
    #[serde(default)]
    pub support: BTreeSet<EvidenceId>,
    #[serde(default)]
    pub contradictions: BTreeSet<EvidenceId>,
    #[serde(default)]
    pub defeats: Vec<Defeat>,
    #[serde(default)]
    pub provider_ids: BTreeSet<String>,
    #[serde(default)]
    pub notes: Vec<String>,
}

impl Claim {
    #[must_use]
    pub fn new(id: ClaimId, subject_uid: impl Into<String>, object: ClaimObject) -> Self {
        Self {
            id,
            subject_uid: subject_uid.into(),
            object,
            state: ClaimState::Candidate,
            confidence: ConfidenceDimensions::default(),
            support: BTreeSet::new(),
            contradictions: BTreeSet::new(),
            defeats: Vec::new(),
            provider_ids: BTreeSet::new(),
            notes: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Inference {
    pub id: InferenceId,
    pub claim_id: ClaimId,
    pub rule: String,
    pub premise_ids: Vec<EvidenceId>,
    pub conclusion: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum HypothesisState {
    Open,
    UnderReview,
    Accepted,
    Rejected,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Hypothesis {
    pub id: HypothesisId,
    pub statement: String,
    pub state: HypothesisState,
    #[serde(default)]
    pub related_claims: BTreeSet<ClaimId>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProviderOutcome {
    CleanNegative,
    Failed { reason: String },
    NotAttempted { reason: String },
}

impl ProviderOutcome {
    #[must_use]
    pub fn is_resolved(&self) -> bool {
        matches!(self, Self::CleanNegative)
    }

    #[must_use]
    pub fn reason(&self) -> Option<&str> {
        match self {
            Self::CleanNegative => None,
            Self::Failed { reason } | Self::NotAttempted { reason } => Some(reason.as_str()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderObservation {
    pub provider_id: String,
    pub claim_id: ClaimId,
    pub outcome: ProviderOutcome,
    pub recorded_at_unix: i64,
    pub credential_fingerprint: Option<String>,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum LedgerError {
    #[error("invalid evidence record")]
    InvalidEvidence,
    #[error("invalid claim")]
    InvalidClaim,
    #[error("duplicate claim id {0}")]
    DuplicateClaim(ClaimId),
    #[error("duplicate inference id {0}")]
    DuplicateInference(InferenceId),
    #[error("missing claim {0}")]
    MissingClaim(ClaimId),
    #[error("missing evidence {0}")]
    MissingEvidence(EvidenceId),
    #[error("claim coverage gaps must be resolved before rejection")]
    CoverageGap,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct IntelligenceLedger {
    pub evidence: BTreeMap<EvidenceId, EvidenceRecord>,
    pub claims: BTreeMap<ClaimId, Claim>,
    pub inferences: BTreeMap<InferenceId, Inference>,
    pub hypotheses: BTreeMap<HypothesisId, Hypothesis>,
    #[serde(default)]
    pub provider_coverage: BTreeMap<ClaimId, BTreeMap<String, ProviderObservation>>,
}

impl IntelligenceLedger {
    /// Inserts evidence unless it is an exact duplicate of an existing record.
    ///
    /// # Errors
    /// Returns [`LedgerError::InvalidEvidence`] for malformed records.
    pub fn insert_evidence(&mut self, evidence: EvidenceRecord) -> Result<EvidenceId, LedgerError> {
        if !evidence.is_valid() {
            return Err(LedgerError::InvalidEvidence);
        }
        if let Some(existing_id) = self.find_duplicate_evidence(&evidence) {
            return Ok(existing_id);
        }
        let id = evidence.id.clone();
        self.evidence.insert(id.clone(), evidence);
        Ok(id)
    }

    /// Inserts a new claim shell into the ledger.
    ///
    /// # Errors
    /// Returns [`LedgerError::InvalidClaim`] for malformed claims and
    /// [`LedgerError::DuplicateClaim`] when the identifier already exists.
    pub fn insert_claim(&mut self, claim: Claim) -> Result<(), LedgerError> {
        if claim.id.0.trim().is_empty()
            || claim.subject_uid.trim().is_empty()
            || !claim.confidence.is_valid()
        {
            return Err(LedgerError::InvalidClaim);
        }
        if self.claims.contains_key(&claim.id) {
            return Err(LedgerError::DuplicateClaim(claim.id));
        }
        self.claims.insert(claim.id.clone(), claim);
        Ok(())
    }

    /// Attaches supporting evidence and recomputes the claim state.
    ///
    /// # Errors
    /// Returns [`LedgerError::MissingClaim`] or [`LedgerError::MissingEvidence`]
    /// when either identifier is unknown.
    pub fn attach_support(
        &mut self,
        claim_id: &ClaimId,
        evidence_id: &EvidenceId,
    ) -> Result<(), LedgerError> {
        self.ensure_evidence(evidence_id)?;
        let claim = self
            .claims
            .get_mut(claim_id)
            .ok_or_else(|| LedgerError::MissingClaim(claim_id.clone()))?;
        claim.support.insert(evidence_id.clone());
        self.recompute_claim_state(claim_id)
    }

    /// Attaches contradicting evidence and recomputes the claim state.
    ///
    /// # Errors
    /// Returns [`LedgerError::MissingClaim`] or [`LedgerError::MissingEvidence`]
    /// when either identifier is unknown.
    pub fn attach_contradiction(
        &mut self,
        claim_id: &ClaimId,
        evidence_id: &EvidenceId,
    ) -> Result<(), LedgerError> {
        self.ensure_evidence(evidence_id)?;
        let claim = self
            .claims
            .get_mut(claim_id)
            .ok_or_else(|| LedgerError::MissingClaim(claim_id.clone()))?;
        claim.contradictions.insert(evidence_id.clone());
        self.recompute_claim_state(claim_id)
    }

    /// Attaches a structured defeater without mutating the legacy claim state.
    ///
    /// # Errors
    /// Returns [`LedgerError::MissingClaim`], [`LedgerError::MissingEvidence`],
    /// or [`LedgerError::InvalidClaim`] for an empty rationale.
    pub fn attach_defeat(&mut self, claim_id: &ClaimId, defeat: Defeat) -> Result<(), LedgerError> {
        self.ensure_evidence(&defeat.evidence_id)?;
        if defeat.rationale.trim().is_empty() {
            return Err(LedgerError::InvalidClaim);
        }
        let claim = self
            .claims
            .get_mut(claim_id)
            .ok_or_else(|| LedgerError::MissingClaim(claim_id.clone()))?;
        if !claim.defeats.contains(&defeat) {
            claim.defeats.push(defeat);
        }
        Ok(())
    }

    /// Records an inference trail for an existing claim.
    ///
    /// # Errors
    /// Returns [`LedgerError::DuplicateInference`],
    /// [`LedgerError::MissingClaim`], or [`LedgerError::MissingEvidence`].
    pub fn insert_inference(&mut self, inference: Inference) -> Result<(), LedgerError> {
        if self.inferences.contains_key(&inference.id) {
            return Err(LedgerError::DuplicateInference(inference.id));
        }
        if !self.claims.contains_key(&inference.claim_id) {
            return Err(LedgerError::MissingClaim(inference.claim_id));
        }
        for evidence_id in &inference.premise_ids {
            self.ensure_evidence(evidence_id)?;
        }
        self.inferences.insert(inference.id.clone(), inference);
        Ok(())
    }

    /// Records provider coverage for a claim using only safe provider metadata.
    ///
    /// # Errors
    /// Returns [`LedgerError::MissingClaim`] for unknown claims and
    /// [`LedgerError::InvalidClaim`] for malformed observations.
    pub fn record_provider(&mut self, observation: ProviderObservation) -> Result<(), LedgerError> {
        if !self.claims.contains_key(&observation.claim_id) {
            return Err(LedgerError::MissingClaim(observation.claim_id));
        }
        if observation.provider_id.trim().is_empty() {
            return Err(LedgerError::InvalidClaim);
        }
        if observation
            .outcome
            .reason()
            .is_some_and(|reason| reason.trim().is_empty())
        {
            return Err(LedgerError::InvalidClaim);
        }
        let claim = self
            .claims
            .get_mut(&observation.claim_id)
            .ok_or_else(|| LedgerError::MissingClaim(observation.claim_id.clone()))?;
        claim.provider_ids.insert(observation.provider_id.clone());
        self.provider_coverage
            .entry(observation.claim_id.clone())
            .or_default()
            .insert(observation.provider_id.clone(), observation);
        Ok(())
    }

    #[must_use]
    pub fn coverage_gaps(&self, claim_id: &ClaimId) -> Vec<&ProviderObservation> {
        let mut gaps = self
            .provider_coverage
            .get(claim_id)
            .into_iter()
            .flat_map(BTreeMap::values)
            .filter(|observation| !observation.outcome.is_resolved())
            .collect::<Vec<_>>();
        gaps.sort_by(|left, right| left.provider_id.cmp(&right.provider_id));
        gaps
    }

    /// Rejects a claim once contradicting evidence exists and coverage gaps are closed.
    ///
    /// # Errors
    /// Returns [`LedgerError::CoverageGap`] when unresolved provider outcomes remain,
    /// or a missing-id error when the claim/evidence is unknown.
    pub fn reject_claim(
        &mut self,
        claim_id: &ClaimId,
        evidence_id: &EvidenceId,
        rationale: impl Into<String>,
    ) -> Result<(), LedgerError> {
        self.ensure_evidence(evidence_id)?;
        if !self.coverage_gaps(claim_id).is_empty() {
            return Err(LedgerError::CoverageGap);
        }
        let claim = self
            .claims
            .get_mut(claim_id)
            .ok_or_else(|| LedgerError::MissingClaim(claim_id.clone()))?;
        claim.contradictions.insert(evidence_id.clone());
        claim.state = ClaimState::Rejected;
        claim.notes.push(rationale.into());
        Ok(())
    }

    /// Recomputes the legacy support state from proven independent roots.
    ///
    /// This compatibility path deliberately cannot produce `Verified`:
    /// verification requires an explicit claim-specific policy rather than a
    /// caller-supplied confidence threshold.
    ///
    /// # Errors
    /// Returns [`LedgerError::MissingClaim`] or [`LedgerError::MissingEvidence`]
    /// when referenced records are absent.
    pub fn recompute_claim_state(&mut self, claim_id: &ClaimId) -> Result<(), LedgerError> {
        let independent_sources = self.independent_source_count(claim_id)?;
        let claim = self
            .claims
            .get_mut(claim_id)
            .ok_or_else(|| LedgerError::MissingClaim(claim_id.clone()))?;
        if claim.state == ClaimState::Rejected || !claim.contradictions.is_empty() {
            claim.state = ClaimState::Rejected;
            return Ok(());
        }
        claim.state = match independent_sources {
            0 | 1 => ClaimState::Candidate,
            _ => ClaimState::Supported,
        };
        Ok(())
    }

    #[must_use]
    pub fn reconcile_locations(&self, subject_uid: &str) -> GeoResolution {
        let mut assertions = self
            .claims
            .values()
            .filter(|claim| claim.subject_uid == subject_uid && claim.state != ClaimState::Rejected)
            .filter_map(|claim| match &claim.object {
                ClaimObject::Location(location)
                    if !claim.support.is_empty() && claim.contradictions.is_empty() =>
                {
                    Some(location.clone())
                }
                _ => None,
            })
            .collect::<Vec<_>>();
        if assertions.is_empty() {
            return GeoResolution::None;
        }
        if assertions.len() == 1 {
            return GeoResolution::Converged(assertions.remove(0));
        }
        for left in 0..assertions.len() {
            for right in (left + 1)..assertions.len() {
                if assertions[left].conflicts_with(&assertions[right]) {
                    let left_id = format!("geo-{left}");
                    let right_id = format!("geo-{right}");
                    assertions[left]
                        .competing_location_ids
                        .insert(right_id.clone());
                    assertions[right].competing_location_ids.insert(left_id);
                }
            }
        }
        if assertions
            .iter()
            .any(|assertion| !assertion.competing_location_ids.is_empty())
        {
            GeoResolution::Conflict(assertions)
        } else {
            assertions.sort_by(|left, right| right.confidence.total_cmp(&left.confidence));
            GeoResolution::Converged(assertions.remove(0))
        }
    }

    /// Counts proven independent supporting origins for a claim.
    /// Unknown ancestry contributes zero proven roots; different provider/source
    /// labels are not evidence of independent origin.
    ///
    /// # Errors
    /// Returns [`LedgerError::MissingClaim`] or [`LedgerError::MissingEvidence`]
    /// when referenced records are absent.
    pub fn independent_source_count(&self, claim_id: &ClaimId) -> Result<usize, LedgerError> {
        let claim = self
            .claims
            .get(claim_id)
            .ok_or_else(|| LedgerError::MissingClaim(claim_id.clone()))?;
        let mut proven_roots = BTreeSet::new();
        for evidence_id in &claim.support {
            let evidence = self
                .evidence
                .get(evidence_id)
                .ok_or_else(|| LedgerError::MissingEvidence(evidence_id.clone()))?;
            if let Some(origin) = evidence.lineage.known_origin_key() {
                proven_roots.insert(origin.to_string());
            }
        }
        Ok(proven_roots.len())
    }

    fn ensure_evidence(&self, evidence_id: &EvidenceId) -> Result<(), LedgerError> {
        if self.evidence.contains_key(evidence_id) {
            Ok(())
        } else {
            Err(LedgerError::MissingEvidence(evidence_id.clone()))
        }
    }

    fn find_duplicate_evidence(&self, candidate: &EvidenceRecord) -> Option<EvidenceId> {
        let key = candidate.duplicate_key()?;
        self.evidence.iter().find_map(|(id, evidence)| {
            (evidence.duplicate_key() == Some(key.clone())).then(|| id.clone())
        })
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GraphSummary {
    pub node_count: usize,
    pub edge_count: usize,
    pub articulation_count: usize,
    pub community_count: usize,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct IntelligenceReport {
    pub graph: GraphSummary,
    pub profiles: Vec<EntityProfile>,
    pub leads: Vec<Lead>,
    pub timeline: Vec<TimelineEvent>,
    pub exposures: Vec<ExposureFinding>,
}

#[must_use]
pub fn build_intelligence_report(
    entities: &[Entity],
    relations: &[EntityRelation],
) -> IntelligenceReport {
    let graph = Graph::build(entities, relations);
    let (cuts, _) = graph.cut_vertices_and_bridges();
    let exposures = compute_exposure(entities);
    IntelligenceReport {
        graph: GraphSummary {
            node_count: graph.node_count(),
            edge_count: graph.edge_count(),
            articulation_count: cuts.len(),
            community_count: detect_communities(&graph).len(),
        },
        profiles: build_profiles(entities),
        leads: rank_leads(entities),
        timeline: reconstruct(entities),
        exposures: exposures.findings,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entity::EntityKind;

    fn evidence(id: &str, origin: &str, digest: &str, subject: &str) -> EvidenceRecord {
        EvidenceRecord {
            id: EvidenceId::from(id),
            subject_uid: subject.to_string(),
            summary: format!("evidence-{id}"),
            lineage: SourceLineage {
                source_id: origin.to_string(),
                origin_id: Some(origin.to_string()),
                chain: vec![origin.to_string()],
                authority: SourceAuthority::Primary,
            },
            observed_at_unix: Some(1),
            recorded_at_unix: 2,
            nature: EvidenceNature::Observed,
            content_digest: Some(digest.to_string()),
            attributes: BTreeMap::new(),
            ancestry_root_families: BTreeSet::new(),
        }
    }

    #[test]
    fn report_aggregates_all_views() {
        let entity = Entity::builder(EntityKind::Email, "ada@example.com", 0.8, "scan")
            .tag(crate::tags::BREACH)
            .build();
        let report = build_intelligence_report(&[entity], &[]);
        assert_eq!(report.graph.node_count, 1);
        assert_eq!(report.profiles.len(), 1);
        assert_eq!(report.exposures.len(), 1);
    }

    #[test]
    fn exact_duplicate_evidence_reuses_existing_id() {
        let mut ledger = IntelligenceLedger::default();
        let first = evidence("ev-1", "breach-a", "digest-a", "uid-1");
        let duplicate = evidence("ev-2", "breach-a", "digest-a", "uid-1");

        let first_id = ledger.insert_evidence(first).unwrap();
        let duplicate_id = ledger.insert_evidence(duplicate).unwrap();

        assert_eq!(first_id, duplicate_id);
        assert_eq!(ledger.evidence.len(), 1);
    }

    #[test]
    fn claim_support_never_auto_verifies() {
        let mut ledger = IntelligenceLedger::default();
        let claim_id = ClaimId::from("claim-1");
        let mut claim = Claim::new(
            claim_id.clone(),
            "uid-1",
            ClaimObject::Attribute {
                key: "email".to_string(),
                value: "ada@example.com".to_string(),
            },
        );
        claim.confidence.conclusion = 0.85;
        ledger.insert_claim(claim).unwrap();

        let ev1 = ledger
            .insert_evidence(evidence("ev-1", "source-a", "d1", "uid-1"))
            .unwrap();
        let mut dependent = evidence("ev-2", "source-a-copy", "d2", "uid-1");
        dependent.lineage.origin_id = Some("source-a".to_string());
        let ev2 = ledger.insert_evidence(dependent).unwrap();
        let ev3 = ledger
            .insert_evidence(evidence("ev-3", "source-b", "d3", "uid-1"))
            .unwrap();
        let ev4 = ledger
            .insert_evidence(evidence("ev-4", "source-c", "d4", "uid-1"))
            .unwrap();

        ledger.attach_support(&claim_id, &ev1).unwrap();
        ledger.attach_support(&claim_id, &ev2).unwrap();
        assert_eq!(ledger.claims[&claim_id].state, ClaimState::Candidate);

        ledger.attach_support(&claim_id, &ev3).unwrap();
        assert_eq!(ledger.claims[&claim_id].state, ClaimState::Supported);

        ledger.attach_support(&claim_id, &ev4).unwrap();
        assert_eq!(ledger.claims[&claim_id].state, ClaimState::Supported);
    }

    #[test]
    fn inference_does_not_promote_without_support() {
        let mut ledger = IntelligenceLedger::default();
        let claim_id = ClaimId::from("claim-1");
        ledger
            .insert_claim(Claim::new(
                claim_id.clone(),
                "uid-1",
                ClaimObject::Narrative("possible overlap".to_string()),
            ))
            .unwrap();
        let ev1 = ledger
            .insert_evidence(evidence("ev-1", "source-a", "d1", "uid-1"))
            .unwrap();
        ledger
            .insert_inference(Inference {
                id: InferenceId::from("inf-1"),
                claim_id: claim_id.clone(),
                rule: "same-domain".to_string(),
                premise_ids: vec![ev1],
                conclusion: "possible overlap".to_string(),
            })
            .unwrap();

        ledger.recompute_claim_state(&claim_id).unwrap();
        assert_eq!(ledger.claims[&claim_id].state, ClaimState::Candidate);
    }

    #[test]
    fn reject_claim_requires_resolved_coverage() {
        let mut ledger = IntelligenceLedger::default();
        let claim_id = ClaimId::from("claim-1");
        ledger
            .insert_claim(Claim::new(
                claim_id.clone(),
                "uid-1",
                ClaimObject::Narrative("exposed".to_string()),
            ))
            .unwrap();
        let ev1 = ledger
            .insert_evidence(evidence("ev-1", "source-a", "d1", "uid-1"))
            .unwrap();
        ledger
            .record_provider(ProviderObservation {
                provider_id: "hibp".to_string(),
                claim_id: claim_id.clone(),
                outcome: ProviderOutcome::NotAttempted {
                    reason: "quota".to_string(),
                },
                recorded_at_unix: 1,
                credential_fingerprint: Some("fp:1234".to_string()),
            })
            .unwrap();

        assert_eq!(
            ledger.reject_claim(&claim_id, &ev1, "negative control"),
            Err(LedgerError::CoverageGap)
        );

        ledger
            .record_provider(ProviderObservation {
                provider_id: "hibp".to_string(),
                claim_id: claim_id.clone(),
                outcome: ProviderOutcome::CleanNegative,
                recorded_at_unix: 2,
                credential_fingerprint: Some("fp:1234".to_string()),
            })
            .unwrap();
        ledger
            .reject_claim(&claim_id, &ev1, "clean negative after rerun")
            .unwrap();
        assert_eq!(ledger.claims[&claim_id].state, ClaimState::Rejected);
    }

    #[test]
    fn reconcile_locations_marks_conflicts() {
        let mut ledger = IntelligenceLedger::default();
        let west_claim = ClaimId::from("claim-west");
        let east_claim = ClaimId::from("claim-east");
        let west_ev = ledger
            .insert_evidence(evidence("ev-1", "source-a", "d1", "uid-1"))
            .unwrap();
        let east_ev = ledger
            .insert_evidence(evidence("ev-2", "source-b", "d2", "uid-1"))
            .unwrap();

        let mut west = Claim::new(
            west_claim.clone(),
            "uid-1",
            ClaimObject::Location(GeoAssertion {
                latitude: 37.7749,
                longitude: -122.4194,
                label: Some("San Francisco".to_string()),
                basis: LocationBasis::Subject,
                method: "profile".to_string(),
                confidence: 0.9,
                uncertainty_radius_m: Some(500.0),
                temporal: TemporalValidity::default(),
                competing_location_ids: BTreeSet::new(),
            }),
        );
        west.confidence.conclusion = 0.9;
        ledger.insert_claim(west).unwrap();
        ledger.attach_support(&west_claim, &west_ev).unwrap();

        let mut east = Claim::new(
            east_claim.clone(),
            "uid-1",
            ClaimObject::Location(GeoAssertion {
                latitude: 40.7128,
                longitude: -74.0060,
                label: Some("New York".to_string()),
                basis: LocationBasis::Subject,
                method: "profile".to_string(),
                confidence: 0.88,
                uncertainty_radius_m: Some(500.0),
                temporal: TemporalValidity::default(),
                competing_location_ids: BTreeSet::new(),
            }),
        );
        east.confidence.conclusion = 0.9;
        ledger.insert_claim(east).unwrap();
        ledger.attach_support(&east_claim, &east_ev).unwrap();

        match ledger.reconcile_locations("uid-1") {
            GeoResolution::Conflict(assertions) => {
                assert_eq!(assertions.len(), 2);
                assert!(
                    assertions
                        .iter()
                        .all(|assertion| !assertion.competing_location_ids.is_empty())
                );
            }
            other => panic!("expected conflict, got {other:?}"),
        }
    }
}
