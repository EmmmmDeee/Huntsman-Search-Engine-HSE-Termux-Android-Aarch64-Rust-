//! Lineage from response data, and the identity-resolution path that consumes it.
//!
//! A collector is a relay, never an origin. Each observation's upstream dataset identity
//! is read from parsed response fields carried on its [`Evidence`]. Collector names,
//! record URLs, record ids and unverified registry labels remain provenance only: they
//! cannot manufacture an independent evidence family. Two collectors relaying one
//! dataset therefore share one root and count as one independent family.
//!
//! [`resolve_with_lineage`] is the library contract for collection front-ends:
//! observations and candidate decisions go in; every observation and every candidate
//! comes out, in input order, each candidate either auto-merged or held with its
//! reasons. Nothing is dropped, rewritten or re-attributed. The merge rule itself is
//! [`IdentityResolutionDecision::hold_reasons`].

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::canonical::canonical_url;
use crate::entity::Evidence;
use crate::evidence_ancestry::{
    AncestryError, EvidenceAncestryGraph, EvidenceAncestryNode, EvidenceNodeId, canonical_family,
};
use crate::identity_resolution::{AutoMergePolicy, HoldReason, IdentityResolutionDecision};

/// Response fields that are strong enough to identify an upstream dataset family, in
/// precedence order. The first non-blank field decides and later fields are not read.
/// The first three are the legacy `breach_corpus_key` spellings in its order.
///
/// `registry`, `source_url` and `source_id` are deliberately excluded. A registry label
/// is not independent evidence until the collector/capability is bound to a verified
/// registry origin, while a URL or source id is a record locator rather than an origin.
pub const LINEAGE_FIELDS: &[(&str, UpstreamKind)] = &[
    ("dbname", UpstreamKind::Dataset),
    ("breach", UpstreamKind::Dataset),
    ("source_db", UpstreamKind::Dataset),
    ("database_name", UpstreamKind::Dataset),
    ("dataset", UpstreamKind::Dataset),
];

/// Ancestry ids of upstream roots. Observation ids may not use it.
const ROOT_PREFIX: &str = "lineage:";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UpstreamKind {
    Dataset,
    /// Reserved for a future verified registry-origin binding. It is not currently
    /// emitted by [`Lineage::of`].
    Registry,
    /// Reserved for a future trusted source-origin binding. Record locators are not
    /// independent families and this is not currently emitted by [`Lineage::of`].
    Source,
}

/// Where one observation's data came from, as the response states it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "lineage", rename_all = "snake_case")]
pub enum Lineage {
    /// One upstream dataset. `family` is the canonical key (whitespace collapsed,
    /// lowercase). Kind prefixes are intentionally absent so aliases of the same
    /// dataset collapse onto one root.
    Upstream {
        kind: UpstreamKind,
        field: String,
        value: String,
        family: String,
    },
    /// The response names no independently countable upstream. Counts as zero families.
    Unattributed,
    /// The deciding field names several distinct upstreams (a combo list). Counts as zero
    /// families: one record cannot independently attest two origins.
    Ambiguous { field: String, values: Vec<String> },
}

impl Lineage {
    /// Read independently countable lineage from response fields on `evidence`. Never
    /// reads the collector name or treats per-record locators as evidence families.
    #[must_use]
    pub fn of(evidence: &Evidence) -> Self {
        for (field, kind) in LINEAGE_FIELDS {
            let values: Vec<&str> = evidence.attr_values(field).collect();
            if values.is_empty() {
                continue;
            }
            let families: BTreeSet<String> = values.iter().map(|v| family_key(*kind, v)).collect();
            if families.len() > 1 {
                return Self::Ambiguous {
                    field: (*field).to_owned(),
                    values: values.into_iter().map(str::to_owned).collect(),
                };
            }
            if let Some(family) = families.into_iter().next().filter(|f| !f.is_empty()) {
                return Self::Upstream {
                    kind: *kind,
                    field: (*field).to_owned(),
                    value: values.join("; "),
                    family,
                };
            }
        }
        Self::Unattributed
    }

    /// The independent family this lineage contributes, if any.
    #[must_use]
    pub fn family(&self) -> Option<&str> {
        match self {
            Self::Upstream { family, .. } => Some(family),
            Self::Unattributed | Self::Ambiguous { .. } => None,
        }
    }
}

fn family_key(kind: UpstreamKind, value: &str) -> String {
    match kind {
        UpstreamKind::Source => canonical_url(value).unwrap_or_else(|| canonical_family(value)),
        UpstreamKind::Dataset | UpstreamKind::Registry => canonical_family(value),
    }
}

/// One collected record. `id` is unique within a resolution; `evidence` carries the
/// collector (`provenance.source`) and the parsed response fields (`attributes`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Observation {
    pub id: EvidenceNodeId,
    pub evidence: Evidence,
}

/// An input observation, unchanged, with the lineage read from it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObservedLineage {
    pub observation: Observation,
    pub lineage: Lineage,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum MergeOutcome {
    AutoMerge,
    Held { reasons: Vec<HoldReason> },
}

/// One candidate as supplied, with what the merge rule saw and decided.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CandidateOutcome {
    pub decision: IdentityResolutionDecision,
    /// Independent root families behind the attributed support, sorted.
    pub independent_families: Vec<String>,
    /// Supporting observations whose response named no single independently countable
    /// upstream. Kept, not counted.
    pub unattributed_support: Vec<EvidenceNodeId>,
    pub outcome: MergeOutcome,
}

/// Everything that went in, in input order, plus the policy that decided it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Resolution {
    pub policy: AutoMergePolicy,
    pub observations: Vec<ObservedLineage>,
    pub candidates: Vec<CandidateOutcome>,
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum LineageError {
    /// The policy floor is NaN, infinite, or outside `[0, 1]`. Rejected so a stored
    /// `Resolution` always reloads (JSON has no NaN or infinity).
    #[error("policy min_match_probability {0} is not a probability")]
    InvalidPolicy(String),
    #[error("observation {index} has an empty id")]
    EmptyObservationId { index: usize },
    #[error("observation id {} uses the reserved `lineage:` prefix", .0.0)]
    ReservedObservationId(EvidenceNodeId),
    #[error("duplicate observation id {}", .0.0)]
    DuplicateObservation(EvidenceNodeId),
    #[error(transparent)]
    Ancestry(#[from] AncestryError),
}

/// Derive lineage for every observation, build the ancestry graph from it, and run the
/// merge rule on every candidate. Candidate support must name observation ids; an id
/// that is not an observation is unknown ancestry and holds the candidate.
///
/// # Errors
/// An invalid policy floor, or an empty, reserved or duplicate observation id. The
/// input is rejected whole rather than partly dropped.
pub fn resolve_with_lineage(
    observations: Vec<Observation>,
    candidates: Vec<IdentityResolutionDecision>,
    policy: AutoMergePolicy,
) -> Result<Resolution, LineageError> {
    let floor = policy.min_match_probability;
    if !(floor.is_finite() && (0.0..=1.0).contains(&floor)) {
        return Err(LineageError::InvalidPolicy(floor.to_string()));
    }
    let mut seen = BTreeSet::new();
    for (index, observation) in observations.iter().enumerate() {
        let id = &observation.id;
        if id.0.trim().is_empty() {
            return Err(LineageError::EmptyObservationId { index });
        }
        if id.0.starts_with(ROOT_PREFIX) {
            return Err(LineageError::ReservedObservationId(id.clone()));
        }
        if !seen.insert(id.clone()) {
            return Err(LineageError::DuplicateObservation(id.clone()));
        }
    }

    let observed: Vec<ObservedLineage> = observations
        .into_iter()
        .map(|observation| ObservedLineage {
            lineage: Lineage::of(&observation.evidence),
            observation,
        })
        .collect();

    let mut graph = EvidenceAncestryGraph::default();
    let mut roots = BTreeSet::new();
    let mut unattributed = BTreeSet::new();
    for item in &observed {
        let Some(family) = item.lineage.family() else {
            unattributed.insert(item.observation.id.clone());
            continue;
        };
        let root = EvidenceNodeId(format!("{ROOT_PREFIX}{family}"));
        if roots.insert(root.clone()) {
            graph.insert(EvidenceAncestryNode {
                id: root.clone(),
                source_family: family.to_owned(),
                parents: BTreeSet::new(),
                derived: false,
            })?;
        }
        // The relay node is derived, so its collector label can never become a root.
        graph.insert(EvidenceAncestryNode {
            id: item.observation.id.clone(),
            source_family: format!("relay {}", item.observation.evidence.provenance.source),
            parents: BTreeSet::from([root]),
            derived: true,
        })?;
    }

    let candidates = candidates
        .into_iter()
        .map(|decision| assess(decision, &graph, &seen, &unattributed, policy))
        .collect();
    Ok(Resolution {
        policy,
        observations: observed,
        candidates,
    })
}

fn assess(
    decision: IdentityResolutionDecision,
    graph: &EvidenceAncestryGraph,
    observation_ids: &BTreeSet<EvidenceNodeId>,
    unattributed: &BTreeSet<EvidenceNodeId>,
    policy: AutoMergePolicy,
) -> CandidateOutcome {
    let mut unknown = Vec::new();
    let mut unattributed_support = Vec::new();
    let mut families = BTreeSet::new();
    let mut ancestry_error = None;
    for id in &decision.supporting {
        if !observation_ids.contains(id) {
            unknown.push(format!("{:?}", id.0));
        } else if unattributed.contains(id) {
            unattributed_support.push(id.clone());
        } else {
            match graph.root_families(id) {
                Ok(roots) => families.extend(roots),
                Err(e) => ancestry_error = ancestry_error.or(Some(e.to_string())),
            }
        }
    }
    // Unattributed support is kept but not counted; unknown support is unknown
    // ancestry, exactly as a missing node is for `hold_reasons`.
    let count = if !unknown.is_empty() {
        Err(format!(
            "support {} is not an observation",
            unknown.join(", ")
        ))
    } else if let Some(e) = ancestry_error {
        Err(e)
    } else {
        Ok(families.len())
    };
    let reasons = decision.hold_reasons_given(count, policy);
    CandidateOutcome {
        decision,
        independent_families: families.into_iter().collect(),
        unattributed_support,
        outcome: if reasons.is_empty() {
            MergeOutcome::AutoMerge
        } else {
            MergeOutcome::Held { reasons }
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entity::EvidenceProvenance;

    fn evidence(collector: &str, attrs: &[(&str, &str)]) -> Evidence {
        attrs.iter().fold(
            Evidence::new(EvidenceProvenance::new(collector), "record"),
            |e, (k, v)| e.with_attr(*k, *v),
        )
    }

    #[test]
    fn lineage_ignores_the_collector_name() {
        let a = Lineage::of(&evidence("hibp", &[("breach", "Adobe")]));
        let b = Lineage::of(&evidence("dehashed", &[("dbname", " ADOBE ")]));
        assert_eq!(a.family(), Some("adobe"));
        assert_eq!(a.family(), b.family());
        assert_eq!(Lineage::of(&evidence("adobe", &[])), Lineage::Unattributed);
    }

    #[test]
    fn first_present_dataset_field_decides_in_legacy_order() {
        let e = evidence("oathnet", &[("breach", "LinkedIn"), ("dbname", "Adobe")]);
        assert!(matches!(
            Lineage::of(&e),
            Lineage::Upstream { ref field, ref family, kind: UpstreamKind::Dataset, .. }
                if field == "dbname" && family == "adobe"
        ));
        let unverified = evidence("x", &[("dbname", "  "), ("registry", "ABR")]);
        assert_eq!(Lineage::of(&unverified), Lineage::Unattributed);
    }

    #[test]
    fn combo_record_is_ambiguous_not_two_families() {
        let e = evidence("x", &[("breach", "Adobe"), ("breach", "LinkedIn")]);
        assert_eq!(
            Lineage::of(&e),
            Lineage::Ambiguous {
                field: "breach".into(),
                values: vec!["Adobe".into(), "LinkedIn".into()],
            }
        );
        let same = evidence("x", &[("breach", "Adobe"), ("breach", "adobe")]);
        assert_eq!(Lineage::of(&same).family(), Some("adobe"));
    }

    #[test]
    fn record_locators_are_not_independent_lineage() {
        assert_eq!(
            Lineage::of(&evidence(
                "a",
                &[("source_url", "https://Example.com/p/1")]
            )),
            Lineage::Unattributed
        );
        assert_eq!(
            Lineage::of(&evidence("a", &[("source_id", "row-1")])),
            Lineage::Unattributed
        );
    }

    #[test]
    fn bad_observation_ids_reject_the_whole_input() {
        let obs = |id: &str| Observation {
            id: id.into(),
            evidence: evidence("c", &[("breach", "Adobe")]),
        };
        let policy = AutoMergePolicy::default();
        assert_eq!(
            resolve_with_lineage(vec![obs(" ")], vec![], policy),
            Err(LineageError::EmptyObservationId { index: 0 })
        );
        assert_eq!(
            resolve_with_lineage(vec![obs("a"), obs("a")], vec![], policy),
            Err(LineageError::DuplicateObservation("a".into()))
        );
        assert!(matches!(
            resolve_with_lineage(vec![obs("lineage:adobe")], vec![], policy),
            Err(LineageError::ReservedObservationId(_))
        ));
    }
}
