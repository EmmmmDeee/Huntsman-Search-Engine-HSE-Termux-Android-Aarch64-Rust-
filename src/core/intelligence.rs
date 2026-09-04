//! Executable intelligence-tradecraft contracts.
//!
//! This module keeps entities, claims, evidence, and inferences as distinct
//! serializable records. It also provides the conservative claim state machine
//! and bounded, deterministic path frontier used by higher-level planners.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

macro_rules! string_id {
    ($name:ident) => {
        #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
        #[serde(transparent)]
        /// The wrapped identifier. Opaque to this module — callers choose the scheme.
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

/// Mean Earth radius in metres (IUGG), for the haversine in [`GeoAssertion`].
const EARTH_RADIUS_M: f64 = 6_371_008.8;

/// Time bounds carried by a claim or observation. `None` means unknown, never
/// "timeless".
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TemporalValidity {
    /// Start of the interval the record holds over, if known.
    pub valid_from_unix: Option<u64>,
    /// End of the interval, if known. `None` is "still open", never "forever".
    pub valid_until_unix: Option<u64>,
    /// When the observation itself was made, if known.
    pub observed_at_unix: Option<u64>,
}

/// How a location entered the graph. This is intentionally separate from its
/// numerical confidence and precision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LocationBasis {
    /// Directly observed at the location — a device fix, an EXIF tag, a survey.
    Observed,
    /// Someone asserted it. The assertion is the evidence, not the position.
    Reported,
    /// Computed from other data by a documented transformation.
    Derived,
    /// Reasoned to, not measured. The weakest basis that still names a place.
    Inferred,
    /// A past location, true then and not asserted of now.
    Historical,
    /// An administrative area — a suburb, LGA, state — not a point within it.
    Administrative,
    /// Derived from network infrastructure (IP, ASN, egress). City-grain at best,
    /// and routinely a real place that is not the subject's place.
    NetworkDerived,
    /// Explicitly coarse: a centroid standing in for an area.
    Approximate,
    /// Observed and corroborated by an independent second observation.
    IndependentlyVerified,
}

impl LocationBasis {
    /// The smallest uncertainty radius (metres) this basis can honestly carry.
    ///
    /// A coordinate without a floor is a lie of precision: "the doorway of 14
    /// Smith St" and "somewhere in the AS this address egresses from" are both
    /// expressible as a lat/lon pair to six decimal places, and once stored
    /// that way nothing downstream can tell them apart — they rank the same,
    /// cluster the same, and plot the same. The basis, not the caller, bounds
    /// how tight the radius may ever claim to be, because the basis is what
    /// determines the resolution the observation ever had.
    ///
    /// `NetworkDerived` sits at 25 km because IP geolocation is city-grain at
    /// best: an egress that resolves to a suburb centroid is a real place, and
    /// it is routinely not the subject's place.
    #[must_use]
    pub fn min_uncertainty_m(self) -> f64 {
        match self {
            Self::Observed | Self::IndependentlyVerified => 10.0,
            Self::Reported | Self::Derived | Self::Historical => 100.0,
            Self::Inferred | Self::Approximate => 1_000.0,
            Self::Administrative => 5_000.0,
            Self::NetworkDerived => 25_000.0,
        }
    }

    /// Whether this basis locates the SUBJECT or merely a place ASSOCIATED
    /// with the subject.
    ///
    /// INFRASTRUCTURE LOCATION ≠ HUMAN LOCATION. A VPN egress, a registered
    /// office, a hosting rack and a country of citizenship are all real places
    /// that need not be where the person is, and that distinction has to
    /// survive into every conclusion drawn from them — collapsing it is how a
    /// datacentre becomes a residence.
    #[must_use]
    pub fn locates_subject_directly(self) -> bool {
        matches!(self, Self::Observed | Self::IndependentlyVerified)
    }
}

/// A location assertion with explicit epistemic basis and precision.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GeoAssertion {
    /// Latitude in degrees. `None` together with `longitude` means label-only.
    pub latitude: Option<f64>,
    /// Longitude in degrees.
    pub longitude: Option<f64>,
    /// Human-readable place name. The only required position when coordinates
    /// are absent.
    pub label: Option<String>,
    /// How the location entered the graph — see [`LocationBasis`].
    pub basis: LocationBasis,
    /// The concrete technique, for the operator: "postcode centroid", "EXIF GPS".
    pub method: String,
    /// Confidence in the assertion, 0.0-1.0. Separate from precision: a country
    /// can be certain and coarse at once.
    pub confidence: f64,
    /// Radius in metres inside which the subject is believed to be. `None` is
    /// unknown precision, reasoned about at [`LocationBasis::min_uncertainty_m`].
    pub uncertainty_radius_m: Option<f64>,
    /// When the location held, and when it was observed.
    pub temporal: TemporalValidity,
    /// Evidence records asserting a location this one conflicts with. Populated
    /// by [`IntelligenceLedger::reconcile_locations`]; a disagreement is kept,
    /// never collapsed.
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
                .is_none_or(|radius| radius.is_finite() && radius >= self.basis.min_uncertainty_m())
            && !self.method.trim().is_empty()
    }

    /// The radius to reason with: the declared one, or the basis floor when
    /// precision was never stated. Never below [`LocationBasis::min_uncertainty_m`],
    /// so an unknown precision is treated as the coarsest the basis allows
    /// rather than as a point.
    #[must_use]
    pub fn effective_uncertainty_m(&self) -> f64 {
        let floor = self.basis.min_uncertainty_m();
        self.uncertainty_radius_m
            .filter(|radius| radius.is_finite())
            .map_or(floor, |radius| radius.max(floor))
    }

    /// Great-circle separation in metres, or `None` when either assertion is
    /// label-only and has no coordinates to compare.
    #[must_use]
    pub fn separation_m(&self, other: &Self) -> Option<f64> {
        let (lat1, lon1) = (self.latitude?, self.longitude?);
        let (lat2, lon2) = (other.latitude?, other.longitude?);
        let (lat1, lon1) = (lat1.to_radians(), lon1.to_radians());
        let (lat2, lon2) = (lat2.to_radians(), lon2.to_radians());
        let (dlat, dlon) = (lat2 - lat1, lon2 - lon1);
        let a = (dlat / 2.0).sin().powi(2) + lat1.cos() * lat2.cos() * (dlon / 2.0).sin().powi(2);
        Some(2.0 * EARTH_RADIUS_M * a.sqrt().clamp(0.0, 1.0).asin())
    }

    /// Combine two assertions about the SAME subject.
    ///
    /// Overlapping assertions narrow to the tighter one — its centre and its
    /// radius, never a midpoint and never a radius below what either basis can
    /// support. Two agreeing city-grain fixes corroborate the city; they do not
    /// synthesise a street. Non-overlapping assertions are a
    /// [`GeoResolution::Conflict`]: the subject was plausibly in both places at
    /// different times, or one source is wrong, and only discriminating
    /// evidence can say which. Averaging them would place the subject in a
    /// field neither source ever put them in.
    #[must_use]
    pub fn reconcile(&self, other: &Self) -> GeoResolution {
        let Some(separation_m) = self.separation_m(other) else {
            return GeoResolution::Undecidable;
        };
        let reach = self.effective_uncertainty_m() + other.effective_uncertainty_m();
        if separation_m > reach {
            return GeoResolution::Conflict { separation_m };
        }
        let tighter = if self.effective_uncertainty_m() <= other.effective_uncertainty_m() {
            self
        } else {
            other
        };
        GeoResolution::Narrowed(Box::new(tighter.clone()))
    }
}

/// The outcome of reconciling two location assertions about one subject.
#[derive(Debug, Clone, PartialEq)]
pub enum GeoResolution {
    /// The assertions overlap; the tighter constraint stands unchanged.
    Narrowed(Box<GeoAssertion>),
    /// They do not overlap. Not an error, and never resolved by averaging —
    /// both are preserved and cross-linked as competing locations.
    Conflict {
        /// Great-circle distance between the two centres, in metres.
        separation_m: f64,
    },
    /// At least one assertion is label-only, so overlap cannot be decided
    /// geometrically. Silently treating that as agreement would manufacture a
    /// corroboration that was never observed.
    Undecidable,
}

/// Source authority is one confidence dimension, not a substitute for source
/// independence or agreement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceAuthority {
    /// The record itself — a register entry, a filing, a court judgment.
    PrimaryRecord,
    /// An official body republishing or summarising a primary record.
    Official,
    /// The subject's own publication about themselves.
    FirstParty,
    /// An established secondary outlet with an editorial process.
    ReputableSecondary,
    /// Any other second-hand report.
    Secondary,
    /// Authority could not be established. Not a synonym for low quality.
    Unknown,
}

/// Provenance lineage used both for attribution and copy-chain deduplication.
/// Two reports sharing an origin are one independent source regardless of how
/// many publishers repeat them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceLineage {
    /// Identifier of this particular item as retrieved.
    pub source_id: String,
    /// Who published it. Two items from one publisher are never independent.
    pub publisher_id: String,
    /// Stable identifiers of the original records/corpora from which this item
    /// descends. For an original observation this contains its own record ID.
    pub origin_ids: BTreeSet<String>,
    /// Where it was retrieved from, when a URI is meaningful.
    pub retrieval_uri: Option<String>,
    /// Digest of the retrieved content, used to collapse exact re-retrievals.
    pub content_digest: Option<String>,
}

impl SourceLineage {
    #[must_use]
    /// Whether `self` and `other` are separate witnesses.
    ///
    /// Independence requires a different publisher, a different source, AND
    /// disjoint origins: one corpus resold under three brands is one witness,
    /// and counting it as three is how a single unverified claim becomes
    /// "corroborated by multiple sources".
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
/// Whether the evidence records a direct observation, someone's report of
/// one, or a derivation from other records.
pub enum EvidenceNature {
    /// The source saw it.
    Observed,
    /// The source relays someone else seeing it.
    Reported,
    /// The source computed it from other data.
    Derived,
}

/// Evidence is an immutable source-bearing observation. It does not become a
/// claim merely by being inserted.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EvidenceRecord {
    /// Stable identifier for this record.
    pub id: EvidenceId,
    /// Observed, reported, or derived — see [`EvidenceNature`].
    pub nature: EvidenceNature,
    /// What the evidence says, in one line, for an operator.
    pub summary: String,
    /// The standing of the source — see [`SourceAuthority`].
    pub authority: SourceAuthority,
    /// Confidence in this item's accuracy, 0.0-1.0.
    pub source_confidence: f64,
    /// Provenance, used for attribution and copy-chain deduplication.
    pub lineage: SourceLineage,
    /// When the observed fact held, and when it was observed.
    pub temporal: TemporalValidity,
    /// Legal jurisdiction the record belongs to, when that governs its meaning.
    pub jurisdiction: Option<String>,
    /// A location this evidence asserts, with its own basis and precision.
    pub location: Option<GeoAssertion>,
}

impl EvidenceRecord {
    #[must_use]
    /// Whether the record is internally consistent enough to persist: it must
    /// be identified, say something, carry a finite in-range confidence, name
    /// both a source and a publisher, and carry a valid location if any.
    pub fn is_valid(&self) -> bool {
        !self.id.0.trim().is_empty()
            && !self.summary.trim().is_empty()
            && self.source_confidence.is_finite()
            && (0.0..=1.0).contains(&self.source_confidence)
            && !self.lineage.source_id.trim().is_empty()
            && !self.lineage.publisher_id.trim().is_empty()
            && self.location.as_ref().is_none_or(GeoAssertion::is_valid)
    }
}

/// A claim object can reference an entity, a literal, or a qualified location.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum ClaimObject {
    /// Another entity in the graph, by uid.
    EntityUid(String),
    /// A literal value — an identifier, a name, a date as written.
    Literal(String),
    /// A place, with its epistemic basis and precision.
    Location(GeoAssertion),
}

/// Independent confidence dimensions. Callers must not collapse exploration
/// confidence into conclusion confidence.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct ConfidenceDimensions {
    /// How confident the search is that this path is worth pursuing. An
    /// exploration score is not a conclusion score and never becomes one.
    pub exploration: f64,
    /// Confidence that the records joined here describe ONE entity.
    pub entity_resolution: f64,
    /// Confidence in the associated location, when one is asserted.
    pub geolocation: Option<f64>,
    /// Confidence in the asserted relationship between the parties.
    pub relationship: f64,
    /// Confidence in the conclusion itself — the only dimension that may
    /// support promotion.
    pub conclusion: f64,
}

impl ConfidenceDimensions {
    #[must_use]
    /// Whether every present dimension is finite and within 0.0-1.0.
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
/// Where a claim stands against its evidence. Computed by
/// [`IntelligenceLedger::recompute_claim_state`], never assigned by a caller
/// (except an explicit adjudication via [`IntelligenceLedger::reject_claim`]).
pub enum ClaimState {
    /// Asserted, not yet independently corroborated.
    Candidate,
    /// Corroborated by at least two independent sources.
    Supported,
    /// Contradicting evidence is attached. Reportable, not assertable.
    Contested,
    /// Three or more independent sources and high conclusion confidence.
    Verified,
    /// Explicitly adjudicated false, with evidence and a rationale.
    Rejected,
}

/// A proposition about an entity. Supporting and contradicting evidence remain
/// attached independently; a conflict is never resolved by overwriting a value.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Claim {
    /// Stable identifier for this claim.
    pub id: ClaimId,
    /// The entity the claim is about.
    pub subject_entity_uid: String,
    /// The relation asserted, e.g. `controls`, `resides_at`, `uses`.
    pub predicate: String,
    /// What the predicate relates the subject to.
    pub object: ClaimObject,
    /// Current state — see [`ClaimState`]. Derived, not assigned.
    pub state: ClaimState,
    /// The independent confidence dimensions, never collapsed to one number.
    pub confidence: ConfidenceDimensions,
    /// Evidence supporting the claim.
    pub supporting_evidence: BTreeSet<EvidenceId>,
    /// Evidence contradicting it. Kept alongside the support, never netted off.
    pub contradicting_evidence: BTreeSet<EvidenceId>,
    /// Inferences that propose this claim as their conclusion.
    pub inference_ids: BTreeSet<InferenceId>,
    /// When the claim holds, and when that was observed.
    pub temporal: TemporalValidity,
    /// Jurisdiction whose law or registry governs the claim's meaning.
    pub jurisdiction: Option<String>,
    /// Other explanations that would produce the same evidence.
    pub alternative_explanations: Vec<String>,
    /// Evidence that, if found, would strengthen the claim.
    pub strengthening_conditions: Vec<String>,
    /// Evidence that, if found, would weaken it.
    pub weakening_conditions: Vec<String>,
    /// What would show the claim to be FALSE. Required: a claim that cannot be
    /// falsified cannot be tested, and [`IntelligenceLedger::insert_claim`]
    /// refuses one.
    pub falsification_conditions: Vec<String>,
    /// The rationale recorded when a claim was explicitly rejected.
    pub adjudication: Option<String>,
}

impl Claim {
    #[must_use]
    /// A new claim in [`ClaimState::Candidate`] with no evidence attached.
    ///
    /// Falsification conditions are left empty here and must be filled before
    /// [`IntelligenceLedger::insert_claim`] will accept it.
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
    /// Stable identifier for this inference.
    pub id: InferenceId,
    /// Claims the inference reasons FROM.
    pub premise_claim_ids: BTreeSet<ClaimId>,
    /// The claim it proposes. Distinct from the premises, and never promoted
    /// by the inference alone.
    pub conclusion_claim_id: ClaimId,
    /// The reasoning applied, e.g. `shared identifier`, `co-location`.
    pub method: String,
    /// Confidence in the reasoning step itself, 0.0-1.0.
    pub confidence: f64,
    /// Other explanations the same premises would equally support.
    pub alternative_explanations: Vec<String>,
    /// What would show the inference invalid. Required, as for a claim.
    pub falsification_conditions: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
/// Where a competing explanation stands against the claims for and
/// against it.
pub enum HypothesisState {
    /// Still live: neither supported enough nor ruled out.
    Open,
    /// Supported by the claims attached to it.
    Supported,
    /// Undermined, but not ruled out.
    Weakened,
    /// Ruled out by contradicting claims.
    Falsified,
}

/// A testable competing explanation. Contradictory and exculpatory evidence is
/// first-class rather than a negative score hidden inside a conclusion.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Hypothesis {
    /// Stable identifier for this hypothesis.
    pub id: HypothesisId,
    /// The explanation being tested, stated so it could be wrong.
    pub statement: String,
    /// Current state — see [`HypothesisState`].
    pub state: HypothesisState,
    /// Claims that support it.
    pub supporting_claim_ids: BTreeSet<ClaimId>,
    /// Claims that tell against it. Exculpatory evidence is first-class here,
    /// not a negative score buried in a conclusion.
    pub contradicting_claim_ids: BTreeSet<ClaimId>,
    /// What evidence would distinguish this hypothesis from its rivals.
    pub discriminating_evidence_needed: Vec<String>,
    /// What would falsify it outright.
    pub falsification_conditions: Vec<String>,
}

/// What a provider actually did about one claim.
///
/// PROVIDER FAILURE ≠ ZERO EVIDENCE. A claim with no supporting evidence looks
/// identical whether the provider was never asked, broke mid-query, or answered
/// cleanly that it holds nothing — and only the last of those is a negative.
/// Collapsing the three is the commonest way a system invents a confident clean
/// answer about a hard target: every source that would have spoken was silent
/// for a reason that had nothing to do with the subject.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ProviderOutcome {
    /// Queried successfully and produced evidence, inserted separately.
    Observed,
    /// Queried successfully; the provider holds nothing on this subject. The
    /// only outcome that is a real negative.
    CleanNegative,
    /// Never queried — budget, a missing credential, out of scope, or a
    /// circuit already open. Says nothing about the subject.
    NotAttempted {
        /// Why it was never queried, for the operator to act on.
        reason: String,
    },
    /// Queried, and the query failed — transport, quota, auth, schema drift.
    /// Says nothing about the subject either.
    Failed {
        /// Why the query failed, for the operator to act on.
        reason: String,
    },
}

impl ProviderOutcome {
    /// Whether this outcome settles what the provider had to say. Only a
    /// successful query does; an outage and an unasked question do not.
    #[must_use]
    pub fn is_resolved(&self) -> bool {
        matches!(self, Self::Observed | Self::CleanNegative)
    }

    /// Canonical wire spelling.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Observed => "observed",
            Self::CleanNegative => "clean_negative",
            Self::NotAttempted { .. } => "not_attempted",
            Self::Failed { .. } => "failed",
        }
    }

    /// The operator-facing reason an unresolved outcome carries.
    #[must_use]
    pub fn reason(&self) -> Option<&str> {
        match self {
            Self::NotAttempted { reason } | Self::Failed { reason } => Some(reason.as_str()),
            Self::Observed | Self::CleanNegative => None,
        }
    }
}

/// One provider's coverage of one claim: what was asked of it and what came
/// back. Recorded whether or not it produced anything, so the absence of
/// evidence stays distinguishable from the evidence of absence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderObservation {
    /// The provider this record is about.
    pub provider_id: String,
    /// What it did — see [`ProviderOutcome`].
    pub outcome: ProviderOutcome,
    /// When the attempt was made, if known.
    pub observed_at_unix: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
/// Why a ledger operation was refused. Every variant is a refusal to record
/// something the ledger could not stand behind.
pub enum LedgerError {
    /// The evidence record failed [`EvidenceRecord::is_valid`].
    InvalidEvidence,
    /// The claim was unidentified, incomplete, or had no falsification condition.
    InvalidClaim,
    /// No evidence with that id is in the ledger.
    UnknownEvidence(EvidenceId),
    /// No claim with that id is in the ledger.
    UnknownClaim(ClaimId),
    /// An inference named a premise claim that does not exist.
    UnknownInferencePremise(ClaimId),
    /// An id already in use. Records are never silently overwritten.
    DuplicateId,
    /// Rejection needs both contradicting evidence and a written rationale.
    RejectionRequiresEvidenceAndRationale,
    /// A provider observation named neither a provider nor, for an unresolved
    /// outcome, a reason.
    InvalidProviderObservation,
    /// A claim cannot be rejected while a provider that bears on it never
    /// answered. The named providers are the outstanding coverage gaps.
    UnresolvedCoverageGap(Vec<String>),
    /// A location reconciliation named evidence that carries no location.
    EvidenceHasNoLocation(EvidenceId),
}

/// In-memory canonical ledger. It is fully serializable for storage inside an
/// existing SQLite/WAL checkpoint transaction.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct IntelligenceLedger {
    /// Evidence records, by id.
    pub evidence: BTreeMap<EvidenceId, EvidenceRecord>,
    /// Claims, by id.
    pub claims: BTreeMap<ClaimId, Claim>,
    /// Inferences, by id.
    pub inferences: BTreeMap<InferenceId, Inference>,
    /// Competing hypotheses, by id.
    pub hypotheses: BTreeMap<HypothesisId, Hypothesis>,
    /// Per-claim provider coverage, keyed by provider id so a later attempt
    /// supersedes an earlier one. Serialised with the rest of the ledger, so a
    /// resumed scan knows which sources are still owed an answer.
    #[serde(default)]
    pub provider_coverage: BTreeMap<ClaimId, BTreeMap<String, ProviderObservation>>,
}

impl IntelligenceLedger {
    /// Insert evidence, collapsing only an exact same-source/content duplicate.
    /// Reports with shared origins but different content remain preserved while
    /// source-independence counting correctly treats them as dependent.
    pub fn insert_evidence(&mut self, evidence: EvidenceRecord) -> Result<EvidenceId, LedgerError> {
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

    /// Insert a claim.
    ///
    /// Refuses an unidentified or incomplete claim, one whose confidence
    /// dimensions are out of range, one that reuses an id, and one with no
    /// falsification condition — an untestable claim has no place here.
    pub fn insert_claim(&mut self, claim: Claim) -> Result<(), LedgerError> {
        if claim.id.0.trim().is_empty()
            || claim.subject_entity_uid.trim().is_empty()
            || claim.predicate.trim().is_empty()
            || !claim.confidence.is_valid()
            || claim.falsification_conditions.is_empty()
        {
            return Err(LedgerError::InvalidClaim);
        }
        if self.claims.contains_key(&claim.id) {
            return Err(LedgerError::DuplicateId);
        }
        self.claims.insert(claim.id.clone(), claim);
        Ok(())
    }

    /// Attach supporting evidence and recompute the claim's state.
    pub fn attach_support(
        &mut self,
        claim_id: &ClaimId,
        evidence_id: &EvidenceId,
    ) -> Result<ClaimState, LedgerError> {
        self.attach_evidence(claim_id, evidence_id, false)
    }

    /// Attach contradicting evidence and recompute the claim's state.
    ///
    /// The contradiction is kept alongside the support, never netted against it.
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

    /// Insert an inference.
    ///
    /// Every premise and the conclusion must already exist as claims, the
    /// method must be named, and falsification conditions are required. The
    /// conclusion records the inference but is NOT promoted by it.
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

    /// Record what one provider did about one claim — including doing nothing.
    ///
    /// A later record for the same (claim, provider) supersedes the earlier
    /// one, so a retry that finally succeeds closes the gap it opened. An
    /// unresolved outcome must name a reason: "it failed" with no cause is not
    /// a coverage record an operator can act on.
    pub fn record_provider(
        &mut self,
        claim_id: &ClaimId,
        observation: ProviderObservation,
    ) -> Result<(), LedgerError> {
        if !self.claims.contains_key(claim_id) {
            return Err(LedgerError::UnknownClaim(claim_id.clone()));
        }
        if observation.provider_id.trim().is_empty()
            || observation
                .outcome
                .reason()
                .is_some_and(|reason| reason.trim().is_empty())
        {
            return Err(LedgerError::InvalidProviderObservation);
        }
        self.provider_coverage
            .entry(claim_id.clone())
            .or_default()
            .insert(observation.provider_id.clone(), observation);
        Ok(())
    }

    /// The providers that bear on this claim and never answered — unqueried or
    /// broken. Deterministically ordered by provider id.
    #[must_use]
    pub fn coverage_gaps(&self, claim_id: &ClaimId) -> Vec<&ProviderObservation> {
        self.provider_coverage
            .get(claim_id)
            .into_iter()
            .flat_map(BTreeMap::values)
            .filter(|observation| !observation.outcome.is_resolved())
            .collect()
    }

    /// Explicit adjudication is the only route to `Rejected`; absence of easy
    /// supporting evidence can never reject a claim.
    ///
    /// Nor can absence that was never actually established: while a provider
    /// bearing on the claim is unqueried or failed, rejection is refused with
    /// the outstanding gaps named. ABSENCE OF EASY EVIDENCE ≠ ABSENCE OF A
    /// NEXUS — closing a hard target on the strength of sources that never
    /// answered is exactly the false clean result this ledger exists to
    /// prevent. Resolve or retry the gap first; the refusal is not advisory.
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
        let gaps: Vec<String> = self
            .coverage_gaps(claim_id)
            .into_iter()
            .map(|observation| observation.provider_id.clone())
            .collect();
        if !gaps.is_empty() {
            return Err(LedgerError::UnresolvedCoverageGap(gaps));
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

    /// Recompute a claim's state from its attached evidence.
    ///
    /// Independent support — not raw evidence count — drives promotion, and a
    /// single contradiction is enough to contest the claim. A claim whose only
    /// backing is an inference stays [`ClaimState::Candidate`]: reasoning is
    /// not a witness. An explicit rejection is never undone here.
    pub fn recompute_claim_state(&mut self, claim_id: &ClaimId) -> Result<ClaimState, LedgerError> {
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

    /// Reconcile the locations carried by two evidence records about one
    /// subject.
    ///
    /// On [`GeoResolution::Conflict`] each record is cross-linked as a
    /// competing location of the other, so the disagreement is preserved in the
    /// ledger rather than collapsed. Nothing is averaged and no radius is
    /// narrowed below what its basis supports — two city-grain fixes agreeing
    /// corroborate the city, never a street.
    pub fn reconcile_locations(
        &mut self,
        left: &EvidenceId,
        right: &EvidenceId,
    ) -> Result<GeoResolution, LedgerError> {
        let left_location = self
            .evidence
            .get(left)
            .ok_or_else(|| LedgerError::UnknownEvidence(left.clone()))?
            .location
            .clone()
            .ok_or_else(|| LedgerError::EvidenceHasNoLocation(left.clone()))?;
        let right_location = self
            .evidence
            .get(right)
            .ok_or_else(|| LedgerError::UnknownEvidence(right.clone()))?
            .location
            .as_ref()
            .ok_or_else(|| LedgerError::EvidenceHasNoLocation(right.clone()))?;
        let resolution = left_location.reconcile(right_location);
        if matches!(resolution, GeoResolution::Conflict { .. }) {
            for (holder, competitor) in [(left, right), (right, left)] {
                if let Some(location) = self
                    .evidence
                    .get_mut(holder)
                    .and_then(|record| record.location.as_mut())
                    && !location.competing_location_ids.contains(competitor)
                {
                    location.competing_location_ids.push(competitor.clone());
                }
            }
        }
        Ok(resolution)
    }

    /// Count independent lineage components. Transitive copy chains remain one
    /// source: if A shares an origin with B and B shares another with C, A/B/C
    /// are one reporting family even when A and C do not directly overlap.
    #[must_use]
    pub fn independent_source_count(&self, ids: &BTreeSet<EvidenceId>) -> usize {
        let lineages: Vec<&SourceLineage> = ids
            .iter()
            .filter_map(|id| self.evidence.get(id).map(|e| &e.lineage))
            .collect();
        let mut parent: Vec<usize> = (0..lineages.len()).collect();

        fn root(parent: &mut [usize], mut index: usize) -> usize {
            while parent[index] != index {
                parent[index] = parent[parent[index]];
                index = parent[index];
            }
            index
        }

        for left in 0..lineages.len() {
            for right in left + 1..lineages.len() {
                if !lineages[left].is_independent_of(lineages[right]) {
                    let left_root = root(&mut parent, left);
                    let right_root = root(&mut parent, right);
                    if left_root != right_root {
                        parent[right_root] = left_root;
                    }
                }
            }
        }
        (0..lineages.len())
            .map(|index| root(&mut parent, index))
            .collect::<BTreeSet<_>>()
            .len()
    }
}

/// One provider's coverage of one scan, aggregated from the engine's own
/// dispatch events.
///
/// The counts are kept alongside the verdict because they are not recoverable
/// from it: a provider that answered on four targets and broke on a fifth has
/// the same [`ProviderOutcome`] as one that broke on its only attempt, and an
/// operator deciding whether to re-run needs to tell those apart.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderCoverage {
    /// The module this row is about.
    pub provider_id: String,
    /// The aggregate verdict — see [`provider_coverage_from_events`] for how
    /// several dispatches collapse into one.
    pub outcome: ProviderOutcome,
    /// Dispatches that completed, failed, or were skipped.
    pub dispatches: u32,
    /// Entities produced across all of them.
    pub findings: u32,
    /// Dispatches that failed.
    pub failures: u32,
    /// Dispatches that were never made.
    pub skips: u32,
}

/// Aggregate a scan's provider coverage from its event log.
///
/// This is the bridge from what the engine DID to what may be concluded from
/// its silence. Each module's dispatches collapse to one verdict,
/// **failure-dominant**: any failed dispatch makes the row `Failed`, then any
/// skipped one makes it `NotAttempted`, and only a module whose every dispatch
/// completed can be `Observed` (it produced something) or `CleanNegative` (it
/// did not). A module that found five entities on one target and broke on
/// another is reported as failed, because the question this answers is not
/// "did it find anything" — the findings are in the report either way — but
/// "is this module's silence about the rest of the target set trustworthy".
/// It is not.
///
/// Rows are sorted by provider id, so the derivation is deterministic and safe
/// to embed in a byte-reproducible export.
#[must_use]
pub fn provider_coverage_from_events(
    events: &[crate::core::event::Event],
) -> Vec<ProviderCoverage> {
    use crate::core::event::EventKind;

    struct Tally {
        dispatches: u32,
        findings: u32,
        failures: u32,
        skips: u32,
        first_error: Option<String>,
        first_skip: Option<String>,
    }

    let mut tallies: BTreeMap<&str, Tally> = BTreeMap::new();
    for event in events {
        let (EventKind::ModuleDone { module, .. }
        | EventKind::ModuleError { module, .. }
        | EventKind::ModuleSkipped { module, .. }) = &event.kind
        else {
            continue;
        };
        // A skip is only a coverage gap when the provider still owes an answer.
        // A module the engine deduped because it already ran on this target, or
        // one that could never have spoken about a private IP, is not an outage
        // — counting either as unresolved reports a gap that never existed and
        // would mark almost every real scan incomplete. An event persisted
        // before the class was recorded is treated as a gap, because unknown is
        // not harmless.
        if let EventKind::ModuleSkipped { class, .. } = &event.kind
            && class.is_some_and(|c| !c.is_coverage_gap())
        {
            continue;
        }
        let module = module.as_str();
        let tally = tallies.entry(module).or_insert(Tally {
            dispatches: 0,
            findings: 0,
            failures: 0,
            skips: 0,
            first_error: None,
            first_skip: None,
        });
        tally.dispatches = tally.dispatches.saturating_add(1);
        match &event.kind {
            EventKind::ModuleDone { found, .. } => {
                tally.findings = tally
                    .findings
                    .saturating_add(u32::try_from(*found).unwrap_or(u32::MAX));
            }
            EventKind::ModuleError { error, .. } => {
                tally.failures = tally.failures.saturating_add(1);
                if tally.first_error.is_none() {
                    tally.first_error = Some(error.clone());
                }
            }
            EventKind::ModuleSkipped { reason, .. } => {
                tally.skips = tally.skips.saturating_add(1);
                if tally.first_skip.is_none() {
                    tally.first_skip = Some(reason.clone());
                }
            }
            _ => unreachable!("filtered above"),
        }
    }

    tallies
        .into_iter()
        .map(|(provider_id, tally)| {
            // A reason is always present for the branch that reads it, but an
            // event carrying an empty string must not produce an outcome that
            // `record_provider` would then reject as unreasoned.
            let outcome = if tally.failures > 0 {
                ProviderOutcome::Failed {
                    reason: non_empty(tally.first_error, "module reported an error"),
                }
            } else if tally.skips > 0 {
                ProviderOutcome::NotAttempted {
                    reason: non_empty(tally.first_skip, "module was not dispatched"),
                }
            } else if tally.findings > 0 {
                ProviderOutcome::Observed
            } else {
                ProviderOutcome::CleanNegative
            };
            ProviderCoverage {
                provider_id: provider_id.to_string(),
                outcome,
                dispatches: tally.dispatches,
                findings: tally.findings,
                failures: tally.failures,
                skips: tally.skips,
            }
        })
        .collect()
}

/// Substitute `fallback` for a missing or blank reason.
fn non_empty(value: Option<String>, fallback: &str) -> String {
    value
        .filter(|text| !text.trim().is_empty())
        .unwrap_or_else(|| fallback.to_string())
}

/// Whether every provider in `rows` actually answered.
///
/// False means at least one source was unqueried or broken, so the scan's
/// silence about whatever that source covers is not evidence of absence.
#[must_use]
pub fn coverage_is_complete(rows: &[ProviderCoverage]) -> bool {
    rows.iter().all(|row| row.outcome.is_resolved())
}

/// Evidence-bearing path candidate. The scheduler never assigns a global score
/// to a person or organization.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PathCandidate {
    /// Stable identifier for this path.
    pub id: PathId,
    /// The entity the path would expand from.
    pub entity_uid: String,
    /// Expansion depth, counted from the seed.
    pub depth: u32,
    /// Expected information gain from following it, 0.0-1.0.
    pub expected_information_gain: f64,
    /// Quality of the evidence already attached to the entity.
    pub evidence_quality: f64,
    /// How independent the evidence behind the entity is.
    pub source_independence: f64,
    /// Value of the path as a bridge between otherwise separate clusters.
    pub bridge_value: f64,
    /// Value of the path for resolving an existing contradiction.
    pub contradiction_value: f64,
    /// How much of what this path would reach is not already known.
    pub novelty: f64,
    /// How geolocation-bearing the path is. Weighted modestly in
    /// [`PathCandidate::score`] — a tilt, never an override.
    pub geo_relevance: f64,
    /// How much unresolved entity ambiguity the path would settle.
    pub unresolved_ambiguity: f64,
    /// Normalised cost of following it — time, quota, money.
    pub resource_cost: f64,
    /// Whether following it is proportionate to the investigation. A path that
    /// is not is refused entry to the frontier outright.
    pub privacy_proportionate: bool,
}

impl PathCandidate {
    #[must_use]
    /// Whether the candidate is identified and every score is finite and
    /// within 0.0-1.0.
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
/// Hard limits on a [`BoundedFrontier`], so exploration cannot run away on
/// a device with a fixed budget.
pub struct FrontierBudget {
    /// Maximum candidates held pending at once.
    pub max_pending: usize,
    /// Maximum expansion depth from the seed.
    pub max_depth: u32,
    /// Maximum candidates ever dispatched, across the frontier's whole life.
    pub max_dispatches: usize,
    /// Maximum candidates in flight at once.
    pub max_concurrency: usize,
}

impl FrontierBudget {
    #[must_use]
    /// Whether the budget permits any work at all.
    pub fn is_valid(self) -> bool {
        self.max_pending > 0 && self.max_dispatches > 0 && self.max_concurrency > 0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// What the frontier did with a candidate. Every rejection names its
/// reason, so a path never disappears silently.
pub enum EnqueueDecision {
    /// Queued.
    Accepted,
    /// Queued, displacing a lower-valued candidate at a full frontier.
    ReplacedLowerValue,
    /// Already seen; not queued again.
    Duplicate,
    /// Failed [`PathCandidate::is_valid`].
    Invalid,
    /// Beyond [`FrontierBudget::max_depth`].
    DepthExceeded,
    /// Refused as disproportionate to the investigation.
    PrivacyDisproportionate,
    /// Worth less than everything already pending at a full frontier.
    LowerValueThanFrontier,
    /// The dispatch budget is spent; the frontier accepts nothing further.
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

#[derive(Debug)]
/// Why a frontier checkpoint could not be written or restored.
pub enum CheckpointError {
    /// The underlying file operation failed.
    Io(std::io::Error),
    /// The checkpoint could not be encoded or decoded.
    Serialization(serde_json::Error),
    /// The restored checkpoint violated its own budget and was refused rather
    /// than resumed into an inconsistent state.
    InvalidBudget,
}

impl From<std::io::Error> for CheckpointError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<serde_json::Error> for CheckpointError {
    fn from(value: serde_json::Error) -> Self {
        Self::Serialization(value)
    }
}

impl BoundedFrontier {
    /// A frontier over `budget`, or [`EnqueueDecision::Invalid`] if the budget
    /// permits no work.
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

    /// Offer a candidate to the frontier. The returned decision says what
    /// happened and, on a rejection, why.
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

    /// Take the highest-scoring pending candidate, counting it against the
    /// dispatch budget. `None` once that budget is spent or nothing is pending.
    ///
    /// Ties break deterministically on path id, so a restored frontier
    /// dispatches in the same order as the one it replaced.
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
    /// How many candidates may be dispatched concurrently right now — the
    /// smallest of the concurrency cap, the dispatch budget remaining, and the
    /// candidates actually pending.
    pub fn available_concurrency(&self) -> usize {
        self.budget
            .max_concurrency
            .min(self.budget.max_dispatches.saturating_sub(self.dispatched))
            .min(self.pending.len())
    }

    #[must_use]
    /// Number of candidates currently pending.
    pub fn pending_len(&self) -> usize {
        self.pending.len()
    }

    #[must_use]
    /// Number of candidates dispatched so far, across restarts.
    pub fn dispatched(&self) -> usize {
        self.dispatched
    }

    #[must_use]
    pub(crate) fn checkpoint_is_valid(&self) -> bool {
        self.budget.is_valid()
            && self.pending.len() <= self.budget.max_pending
            && self.dispatched <= self.budget.max_dispatches
            && self.pending.iter().all(|candidate| {
                candidate.is_valid()
                    && candidate.depth <= self.budget.max_depth
                    && self.seen.contains(&candidate.id)
            })
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
    fn transitive_copy_chain_counts_as_one_source_family() {
        let mut ledger = IntelligenceLedger::default();
        let a = evidence("a", "publisher-a", "origin-x");
        let mut b = evidence("b", "publisher-b", "origin-x");
        b.lineage.origin_ids.insert("origin-y".to_string());
        let c = evidence("c", "publisher-c", "origin-y");
        let ids = [a.id.clone(), b.id.clone(), c.id.clone()]
            .into_iter()
            .collect();
        ledger.insert_evidence(a).expect("valid");
        ledger.insert_evidence(b).expect("valid");
        ledger.insert_evidence(c).expect("valid");
        assert_eq!(ledger.independent_source_count(&ids), 1);
    }

    #[test]
    fn independent_support_promotes_but_contradiction_is_preserved() {
        let mut ledger = IntelligenceLedger::default();
        let ids: Vec<EvidenceId> = ["a", "b", "c", "d"]
            .into_iter()
            .map(|id| ledger.insert_evidence(evidence(id, id, id)).expect("valid"))
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
        let dir = tempfile::tempdir().expect("tempdir");
        let checkpoint_path = dir.path().join("frontier.json");
        frontier
            .save_checkpoint(&checkpoint_path)
            .expect("durable checkpoint");
        let mut resumed =
            BoundedFrontier::load_checkpoint(&checkpoint_path).expect("restore checkpoint");
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
        assert!(
            resumed.pop_best().is_none(),
            "dispatch budget survives restart"
        );
    }

    fn located(basis: LocationBasis, lat: f64, lon: f64, radius_m: Option<f64>) -> GeoAssertion {
        GeoAssertion {
            latitude: Some(lat),
            longitude: Some(lon),
            label: None,
            basis,
            method: "test".to_string(),
            confidence: 0.6,
            uncertainty_radius_m: radius_m,
            temporal: TemporalValidity::default(),
            competing_location_ids: vec![],
        }
    }

    // Sydney CBD and Melbourne CBD — ~713 km apart, a real separation no
    // city-grain uncertainty can bridge.
    const SYD: (f64, f64) = (-33.8688, 151.2093);
    const MEL: (f64, f64) = (-37.8136, 144.9631);

    #[test]
    fn a_precision_claim_never_exceeds_what_its_basis_can_support() {
        // An IP fix asserting 50 m is a lie of precision: the basis never had
        // that resolution to give, and stored this way nothing downstream can
        // tell it apart from a doorway.
        assert!(!located(LocationBasis::NetworkDerived, SYD.0, SYD.1, Some(50.0)).is_valid());
        assert!(
            located(LocationBasis::NetworkDerived, SYD.0, SYD.1, Some(25_000.0)).is_valid(),
            "city-grain is what network derivation can honestly claim"
        );
        // An instrument-grade observation legitimately may be tight.
        assert!(located(LocationBasis::Observed, SYD.0, SYD.1, Some(10.0)).is_valid());
        assert!(!located(LocationBasis::Observed, SYD.0, SYD.1, Some(0.0)).is_valid());
        // Unknown precision stays allowed, but is reasoned about at the floor
        // rather than as a point.
        let unknown = located(LocationBasis::Administrative, SYD.0, SYD.1, None);
        assert!(unknown.is_valid());
        assert!((unknown.effective_uncertainty_m() - 5_000.0).abs() < 1e-9);
    }

    #[test]
    fn an_associated_location_is_never_the_subjects_own() {
        // INFRASTRUCTURE LOCATION != HUMAN LOCATION: an egress, a registered
        // office and an administrative area are all real places that need not
        // be where the person is.
        for basis in [
            LocationBasis::Observed,
            LocationBasis::IndependentlyVerified,
        ] {
            assert!(basis.locates_subject_directly(), "{basis:?}");
        }
        for basis in [
            LocationBasis::NetworkDerived,
            LocationBasis::Administrative,
            LocationBasis::Inferred,
            LocationBasis::Reported,
            LocationBasis::Derived,
            LocationBasis::Historical,
            LocationBasis::Approximate,
        ] {
            assert!(
                !basis.locates_subject_directly(),
                "{basis:?} locates something associated with the subject"
            );
        }
    }

    #[test]
    fn disjoint_locations_conflict_and_are_never_averaged() {
        let syd = located(LocationBasis::Reported, SYD.0, SYD.1, Some(25_000.0));
        let mel = located(LocationBasis::Reported, MEL.0, MEL.1, Some(25_000.0));
        let GeoResolution::Conflict { separation_m } = syd.reconcile(&mel) else {
            panic!("two cities 700 km apart must not narrow")
        };
        assert!(
            (700_000.0..730_000.0).contains(&separation_m),
            "Sydney-Melbourne is ~713 km, got {separation_m} m"
        );
        // And the ledger preserves both, cross-linked, rather than collapsing
        // them to a midpoint neither source ever asserted.
        let mut ledger = IntelligenceLedger::default();
        let mut here = evidence("here", "publisher-a", "origin-a");
        here.location = Some(syd);
        let mut there = evidence("there", "publisher-b", "origin-b");
        there.location = Some(mel);
        let here = ledger.insert_evidence(here).expect("valid");
        let there = ledger.insert_evidence(there).expect("valid");
        assert!(matches!(
            ledger.reconcile_locations(&here, &there),
            Ok(GeoResolution::Conflict { .. })
        ));
        for (holder, competitor) in [(&here, &there), (&there, &here)] {
            let location = ledger.evidence[holder]
                .location
                .as_ref()
                .expect("location retained");
            assert_eq!(location.competing_location_ids, vec![competitor.clone()]);
        }
        // Recording it twice does not duplicate the cross-link.
        assert!(ledger.reconcile_locations(&here, &there).is_ok());
        assert_eq!(
            ledger.evidence[&here]
                .location
                .as_ref()
                .expect("location retained")
                .competing_location_ids
                .len(),
            1
        );
    }

    #[test]
    fn agreeing_coarse_locations_corroborate_the_area_not_a_street() {
        let a = located(LocationBasis::Reported, SYD.0, SYD.1, Some(25_000.0));
        let b = located(LocationBasis::Reported, SYD.0 + 0.01, SYD.1 + 0.01, None);
        let GeoResolution::Narrowed(narrowed) = a.reconcile(&b) else {
            panic!("nearby coarse fixes overlap")
        };
        assert!(
            narrowed.effective_uncertainty_m() >= LocationBasis::Reported.min_uncertainty_m(),
            "agreement must not synthesise resolution neither source had"
        );
        // The tighter constraint stands unchanged — its own centre, never a
        // midpoint between the two.
        let tighter = located(LocationBasis::Observed, SYD.0 + 0.001, SYD.1, Some(10.0));
        let GeoResolution::Narrowed(narrowed) = a.reconcile(&tighter) else {
            panic!("the observation sits inside the reported disc")
        };
        assert!((narrowed.latitude.expect("lat") - (SYD.0 + 0.001)).abs() < 1e-12);
        assert!((narrowed.effective_uncertainty_m() - 10.0).abs() < 1e-9);
    }

    #[test]
    fn a_label_only_location_is_undecidable_not_agreement() {
        let mut label_only = located(LocationBasis::Reported, SYD.0, SYD.1, None);
        label_only.latitude = None;
        label_only.longitude = None;
        label_only.label = Some("Sydney".to_string());
        assert!(label_only.is_valid());
        let mel = located(LocationBasis::Reported, MEL.0, MEL.1, None);
        assert_eq!(label_only.reconcile(&mel), GeoResolution::Undecidable);
        assert_eq!(label_only.separation_m(&mel), None);
    }

    fn coverage_ledger() -> (IntelligenceLedger, EvidenceId) {
        let mut ledger = IntelligenceLedger::default();
        let contradicting = ledger
            .insert_evidence(evidence("against", "publisher-x", "origin-x"))
            .expect("valid");
        ledger.insert_claim(claim()).expect("valid");
        (ledger, contradicting)
    }

    #[test]
    fn a_provider_outage_is_not_a_clean_negative() {
        let (mut ledger, against) = coverage_ledger();
        let id: ClaimId = "claim-1".into();
        ledger
            .record_provider(
                &id,
                ProviderObservation {
                    provider_id: "registry".to_string(),
                    outcome: ProviderOutcome::Failed {
                        reason: "upstream 502 on every retry".to_string(),
                    },
                    observed_at_unix: None,
                },
            )
            .expect("recorded");
        assert_eq!(
            ledger.reject_claim(&id, &against, "no record found"),
            Err(LedgerError::UnresolvedCoverageGap(vec![
                "registry".to_string()
            ])),
            "a source that never answered cannot be counted as having said no"
        );
        assert_eq!(ledger.claims[&id].state, ClaimState::Candidate);

        // The retry that finally succeeds closes the gap it opened.
        ledger
            .record_provider(
                &id,
                ProviderObservation {
                    provider_id: "registry".to_string(),
                    outcome: ProviderOutcome::CleanNegative,
                    observed_at_unix: Some(1),
                },
            )
            .expect("recorded");
        assert!(ledger.coverage_gaps(&id).is_empty());
        ledger
            .reject_claim(&id, &against, "registry holds no such record")
            .expect("rejection is available once the source has actually answered");
        assert_eq!(ledger.claims[&id].state, ClaimState::Rejected);
    }

    #[test]
    fn an_unqueried_provider_blocks_rejection_and_names_itself() {
        let (mut ledger, against) = coverage_ledger();
        let id: ClaimId = "claim-1".into();
        for provider in ["asic", "austlii"] {
            ledger
                .record_provider(
                    &id,
                    ProviderObservation {
                        provider_id: provider.to_string(),
                        outcome: ProviderOutcome::NotAttempted {
                            reason: "no credential configured".to_string(),
                        },
                        observed_at_unix: None,
                    },
                )
                .expect("recorded");
        }
        assert_eq!(
            ledger.reject_claim(&id, &against, "nothing found"),
            Err(LedgerError::UnresolvedCoverageGap(vec![
                "asic".to_string(),
                "austlii".to_string(),
            ]))
        );
        // An unresolved outcome must say why; an outage with no cause is not a
        // coverage record an operator can act on.
        assert_eq!(
            ledger.record_provider(
                &id,
                ProviderObservation {
                    provider_id: "asic".to_string(),
                    outcome: ProviderOutcome::Failed {
                        reason: "  ".to_string()
                    },
                    observed_at_unix: None,
                },
            ),
            Err(LedgerError::InvalidProviderObservation)
        );
        assert_eq!(
            ledger.record_provider(
                &"unknown".into(),
                ProviderObservation {
                    provider_id: "asic".to_string(),
                    outcome: ProviderOutcome::CleanNegative,
                    observed_at_unix: None,
                },
            ),
            Err(LedgerError::UnknownClaim("unknown".into()))
        );
    }

    #[test]
    fn a_coverage_gap_never_blocks_positive_corroboration() {
        // Gaps constrain what may be concluded from SILENCE. Three independent
        // sources speaking is unaffected by a fourth that did not.
        let mut ledger = IntelligenceLedger::default();
        let ids: Vec<EvidenceId> = ["a", "b", "c"]
            .into_iter()
            .map(|id| ledger.insert_evidence(evidence(id, id, id)).expect("valid"))
            .collect();
        ledger.insert_claim(claim()).expect("valid");
        let id: ClaimId = "claim-1".into();
        ledger
            .record_provider(
                &id,
                ProviderObservation {
                    provider_id: "quota-exhausted".to_string(),
                    outcome: ProviderOutcome::NotAttempted {
                        reason: "daily quota spent".to_string(),
                    },
                    observed_at_unix: None,
                },
            )
            .expect("recorded");
        for evidence_id in &ids {
            ledger.attach_support(&id, evidence_id).expect("known");
        }
        assert_eq!(ledger.claims[&id].state, ClaimState::Verified);
        assert_eq!(ledger.coverage_gaps(&id).len(), 1);
    }

    #[test]
    fn provider_coverage_survives_a_ledger_round_trip() {
        // A resumed scan must still know which sources are owed an answer;
        // losing that on restart resurrects the false clean negative.
        let (mut ledger, against) = coverage_ledger();
        let id: ClaimId = "claim-1".into();
        ledger
            .record_provider(
                &id,
                ProviderObservation {
                    provider_id: "registry".to_string(),
                    outcome: ProviderOutcome::Failed {
                        reason: "connection reset".to_string(),
                    },
                    observed_at_unix: Some(7),
                },
            )
            .expect("recorded");
        let encoded = serde_json::to_string(&ledger).expect("serialisable");
        let mut resumed: IntelligenceLedger =
            serde_json::from_str(&encoded).expect("deserialisable");
        assert_eq!(resumed.coverage_gaps(&id).len(), 1);
        assert_eq!(
            resumed.reject_claim(&id, &against, "nothing found"),
            Err(LedgerError::UnresolvedCoverageGap(vec![
                "registry".to_string()
            ]))
        );
        // A ledger written before coverage was tracked still loads.
        let legacy: IntelligenceLedger =
            serde_json::from_str(r#"{"evidence":{},"claims":{},"inferences":{},"hypotheses":{}}"#)
                .expect("older checkpoints remain readable");
        assert!(legacy.provider_coverage.is_empty());
    }

    fn module_event(kind: crate::core::event::EventKind) -> crate::core::event::Event {
        crate::core::event::Event {
            scan_id: "scan-1".to_string(),
            ts: 0,
            kind,
        }
    }

    #[test]
    fn a_broken_provider_never_reads_as_a_clean_negative_in_coverage() {
        use crate::core::event::EventKind;
        let events = vec![
            module_event(EventKind::ModuleDone {
                module: "quiet".to_string(),
                found: 0,
            }),
            module_event(EventKind::ModuleError {
                module: "broken".to_string(),
                error: "upstream 502".to_string(),
            }),
            module_event(EventKind::ModuleSkipped {
                module: "unasked".to_string(),
                reason: "no credential configured".to_string(),
                class: Some(crate::core::event::SkipClass::Unavailable),
            }),
            module_event(EventKind::ModuleDone {
                module: "productive".to_string(),
                found: 3,
            }),
            // Not a dispatch outcome: it must not create a coverage row.
            module_event(EventKind::ExpansionStop {
                reason: "budget".to_string(),
            }),
        ];
        let rows = provider_coverage_from_events(&events);
        assert_eq!(
            rows.iter()
                .map(|row| row.provider_id.as_str())
                .collect::<Vec<_>>(),
            ["broken", "productive", "quiet", "unasked"],
            "rows are sorted by provider id, so the derivation is deterministic"
        );
        assert_eq!(
            rows[0].outcome,
            ProviderOutcome::Failed {
                reason: "upstream 502".to_string()
            }
        );
        assert_eq!(rows[1].outcome, ProviderOutcome::Observed);
        assert_eq!(
            rows[2].outcome,
            ProviderOutcome::CleanNegative,
            "a module that completed and found nothing IS a real negative"
        );
        assert_eq!(
            rows[3].outcome,
            ProviderOutcome::NotAttempted {
                reason: "no credential configured".to_string()
            }
        );
        assert!(
            !coverage_is_complete(&rows),
            "two providers never answered, so the scan's silence is not evidence of absence"
        );
        assert!(coverage_is_complete(&rows[1..3]));
    }

    #[test]
    fn a_dedup_or_inapplicable_skip_is_not_a_coverage_gap() {
        use crate::core::event::{EventKind, SkipClass};
        // The engine emits ModuleSkipped for four different situations, and only
        // two of them mean a provider still owes an answer. A module deduped
        // because it already ran on this target HAS answered; one that could
        // never have spoken about a private IP was never owed anything.
        // Counting either as unresolved reports an outage that never happened
        // and marks almost every real scan incomplete.
        let events = vec![
            module_event(EventKind::ModuleDone {
                module: "registry".to_string(),
                found: 2,
            }),
            module_event(EventKind::ModuleSkipped {
                module: "registry".to_string(),
                reason: "already dispatched for this target".to_string(),
                class: Some(SkipClass::AlreadyCovered),
            }),
            module_event(EventKind::ModuleSkipped {
                module: "shodan".to_string(),
                reason: "private/reserved IP — external API would reject".to_string(),
                class: Some(SkipClass::NotApplicable),
            }),
        ];
        let rows = provider_coverage_from_events(&events);
        assert_eq!(
            rows.len(),
            1,
            "an inapplicable provider earns no coverage row at all: {rows:?}"
        );
        assert_eq!(rows[0].provider_id, "registry");
        assert_eq!(
            rows[0].outcome,
            ProviderOutcome::Observed,
            "a provider that answered and was then deduped is not an outage"
        );
        assert_eq!(rows[0].skips, 0);
        assert!(coverage_is_complete(&rows));
    }

    #[test]
    fn an_unclassified_skip_is_treated_as_a_gap() {
        use crate::core::event::{EventKind, SkipClass};
        // An event persisted before the class was recorded says nothing about
        // which kind of skip it was. Unknown is not harmless: assuming the
        // benign case would silently manufacture a clean sweep out of an old
        // event log.
        let unclassified =
            provider_coverage_from_events(&[module_event(EventKind::ModuleSkipped {
                module: "legacy".to_string(),
                reason: "no key".to_string(),
                class: None,
            })]);
        assert_eq!(unclassified.len(), 1);
        assert!(!unclassified[0].outcome.is_resolved());
        assert!(!coverage_is_complete(&unclassified));

        // Both gap classes still report as gaps, with their reasons intact.
        for class in [SkipClass::Scoped, SkipClass::Unavailable] {
            assert!(class.is_coverage_gap(), "{class:?}");
            let rows = provider_coverage_from_events(&[module_event(EventKind::ModuleSkipped {
                module: "p".to_string(),
                reason: "because".to_string(),
                class: Some(class),
            })]);
            assert_eq!(
                rows[0].outcome,
                ProviderOutcome::NotAttempted {
                    reason: "because".to_string()
                },
                "{class:?}"
            );
        }
        for class in [SkipClass::NotApplicable, SkipClass::AlreadyCovered] {
            assert!(!class.is_coverage_gap(), "{class:?}");
        }
    }

    #[test]
    fn a_partial_outage_dominates_the_findings_it_sits_beside() {
        use crate::core::event::EventKind;
        let events = vec![
            module_event(EventKind::ModuleDone {
                module: "registry".to_string(),
                found: 5,
            }),
            module_event(EventKind::ModuleError {
                module: "registry".to_string(),
                error: "connection reset".to_string(),
            }),
            module_event(EventKind::ModuleSkipped {
                module: "registry".to_string(),
                reason: "quota spent".to_string(),
                class: Some(crate::core::event::SkipClass::Unavailable),
            }),
        ];
        let rows = provider_coverage_from_events(&events);
        assert_eq!(rows.len(), 1);
        assert_eq!(
            rows[0].outcome,
            ProviderOutcome::Failed {
                reason: "connection reset".to_string()
            },
            "finding something on one target says nothing about the targets it broke on"
        );
        assert_eq!(rows[0].dispatches, 3);
        assert_eq!(rows[0].findings, 5);
        assert_eq!(rows[0].failures, 1);
        assert_eq!(rows[0].skips, 1);
    }

    #[test]
    fn an_unreasoned_outage_still_produces_a_recordable_observation() {
        use crate::core::event::EventKind;
        // An event carrying a blank reason must not yield an outcome that
        // `record_provider` would then reject as unreasoned — the coverage row
        // and the ledger have to agree on what is well-formed.
        let rows = provider_coverage_from_events(&[module_event(EventKind::ModuleError {
            module: "terse".to_string(),
            error: "   ".to_string(),
        })]);
        let mut ledger = IntelligenceLedger::default();
        ledger.insert_claim(claim()).expect("valid");
        ledger
            .record_provider(
                &"claim-1".into(),
                ProviderObservation {
                    provider_id: rows[0].provider_id.clone(),
                    outcome: rows[0].outcome.clone(),
                    observed_at_unix: None,
                },
            )
            .expect("a derived outcome is always well-formed enough to record");
        assert_eq!(ledger.coverage_gaps(&"claim-1".into()).len(), 1);
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
