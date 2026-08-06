//! Final breach consensus: grade every finding by how many DISTINCT breach
//! corpora independently attest it, then audit that grading autonomously.
//!
//! This runs last, after [`crate::core::breach_sweep`] has put the whole
//! identity picture back through the breach modules, so it grades the richest
//! evidence chain the scan will ever have.
//!
//! # What it does NOT do
//!
//! It does not query anything, and it does not raise confidence. Both are
//! deliberate, and both were mistakes in an earlier draft of this file:
//!
//! * **It reads evidence rather than asserting it.** `confirming_sources` is
//!   the set of breach sources actually present in the entity's evidence chain,
//!   classified by the correlator's own [`is_breach_source`]. An earlier version
//!   hardcoded `source_count: 2` under the comment "Assume 2 sources confirmed
//!   it" — a number no observation supported, which then drove a confidence
//!   boost. Nothing here may state a count it cannot point at evidence for.
//! * **Grading is not corroboration.** The pass attaches its verdict under
//!   [`CONSENSUS_SOURCE`], which [`crate::core::entity::is_non_corroborating_source`]
//!   rejects, so summarising an entity's corroboration can never *become* more
//!   of it. Real uplift comes from the sweep finding real new sources; that
//!   flows through `c_effective` on its own, with no thumb on the scale here.
//!
//! The audit is therefore adversarial toward the scan's own output: every flag
//! it raises is a reason to trust a finding *less*.

use crate::core::correlator::{DOB_KEYS, is_breach_source, normalise_dob};
use crate::core::entity::{CONSENSUS_SOURCE, Classification, Entity, Evidence};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// Tag marking an entity that only the final breach sweep found.
pub const SWEEP_TAG: &str = "breach-sweep";

/// Base confidence a finding may state, given how many distinct breach corpora
/// attest it, when breach corpora are its ONLY provenance.
///
/// One corpus is one observation however large it is: breach dumps are copied,
/// merged and resold between aggregators, so a lone hit is the *weakest* claim
/// in OSINT, not the strongest. The ceiling stays below
/// [`Classification::VERIFIED_MIN`] until a second, independent corpus agrees.
#[must_use]
pub fn supported_ceiling(distinct_sources: usize) -> f64 {
    match distinct_sources {
        0 | 1 => 0.70,
        2 => 0.90,
        _ => 1.0,
    }
}

/// Consensus for a single entity: who attests it, and what looks wrong.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsensusResult {
    pub entity_uid: String,
    /// Distinct breach sources present in the evidence chain, sorted. Real
    /// source names, never a synthesised count.
    pub confirming_sources: Vec<String>,
    /// True when every corroborating source is a breach corpus, so the ceiling
    /// in [`supported_ceiling`] is the whole story for this entity.
    pub breach_only: bool,
    pub audit_flags: Vec<AuditFlag>,
}

impl ConsensusResult {
    /// Number of distinct attesting breach corpora — derived, never stored, so
    /// it cannot drift from the sources it counts.
    #[must_use]
    pub fn source_count(&self) -> usize {
        self.confirming_sources.len()
    }

    /// Two or more independent corpora agree.
    #[must_use]
    pub fn is_corroborated(&self) -> bool {
        self.source_count() >= 2
    }
}

/// A reason to trust a finding less. Every variant carries the specifics that
/// justify it, so a reader can check the call rather than take it on faith.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "flag", rename_all = "snake_case")]
pub enum AuditFlag {
    /// Stated confidence exceeds what the attesting corpora support.
    ConfidenceDiscrepancy { stated: f64, supported: f64 },
    /// Two breach corpora disagree on an attribute that has exactly one true
    /// value, so at least one of them is wrong about this entity.
    ConflictingAttributes {
        attribute: String,
        left_source: String,
        left: String,
        right_source: String,
        right: String,
    },
    /// Only the final sweep saw this — nothing else in the scan reached it.
    NewFinding { source: String },
    /// Graded at or above VERIFIED on the word of a single corpus.
    SingleSourceElevated { source: String, c_effective: f64 },
}

impl AuditFlag {
    /// True for a flag that impeaches the finding outright, as opposed to one
    /// that merely asks for a second look. Only a genuine contradiction
    /// qualifies: exactly one of the two values can be true.
    #[must_use]
    pub fn is_hard_conflict(&self) -> bool {
        matches!(self, Self::ConflictingAttributes { .. })
    }

    /// Stable snake_case discriminant for reports and JSON summaries.
    #[must_use]
    pub fn kind(&self) -> &'static str {
        match self {
            Self::ConfidenceDiscrepancy { .. } => "confidence_discrepancy",
            Self::ConflictingAttributes { .. } => "conflicting_attributes",
            Self::NewFinding { .. } => "new_finding",
            Self::SingleSourceElevated { .. } => "single_source_elevated",
        }
    }
}

/// The autonomous audit's conclusion about the consensus grading.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AuditVerdict {
    Pass,
    PassWithWarnings,
    PassWithConcerns,
    FailsAudit,
    /// The audit has not run. A report only reaches a real verdict by going
    /// through [`BreachConsensusReport::audit_autonomous`].
    PendingReview,
}

impl AuditVerdict {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pass => "PASS",
            Self::PassWithWarnings => "PASS_WITH_WARNINGS",
            Self::PassWithConcerns => "PASS_WITH_CONCERNS",
            Self::FailsAudit => "FAILS_AUDIT",
            Self::PendingReview => "PENDING_REVIEW",
        }
    }

    /// Whether downstream correlation may lean on this consensus.
    ///
    /// `PendingReview` is excluded: an un-run audit is not a clean one.
    #[must_use]
    pub fn can_use_for_correlation(self) -> bool {
        matches!(self, Self::Pass | Self::PassWithWarnings)
    }
}

/// The consensus grading for one scan, plus its autonomous audit.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BreachConsensusReport {
    pub scan_id: String,
    pub results: Vec<ConsensusResult>,
    /// Entities carrying at least one breach source — the graded population.
    pub entities_examined: usize,
    /// Of those, how many two or more distinct corpora agree on.
    pub entities_corroborated: usize,
    /// Entities only the final sweep found.
    pub new_findings: usize,
    pub verdict: AuditVerdict,
}

impl BreachConsensusReport {
    #[must_use]
    pub fn new(scan_id: &str) -> Self {
        Self {
            scan_id: scan_id.to_string(),
            results: Vec::new(),
            entities_examined: 0,
            entities_corroborated: 0,
            new_findings: 0,
            verdict: AuditVerdict::PendingReview,
        }
    }

    /// Every flag raised across every entity, in entity order.
    pub fn flags(&self) -> impl Iterator<Item = &AuditFlag> {
        self.results.iter().flat_map(|r| r.audit_flags.iter())
    }

    /// How many flags of each kind — the audit summary line.
    #[must_use]
    pub fn flag_counts(&self) -> BTreeMap<&'static str, usize> {
        let mut counts = BTreeMap::new();
        for flag in self.flags() {
            *counts.entry(flag.kind()).or_insert(0) += 1;
        }
        counts
    }

    /// Grade the grading. Hard conflicts fail outright — a contradiction means a
    /// finding in this scan is wrong, and which one is not yet known. Softer
    /// flags accumulate into warnings, then concerns.
    pub fn audit_autonomous(&mut self) {
        let mut conflicts = 0usize;
        let mut concerns = 0usize;
        for flag in self.flags() {
            if flag.is_hard_conflict() {
                conflicts += 1;
            } else {
                concerns += 1;
            }
        }

        self.verdict = match (conflicts, concerns) {
            (0, 0) => AuditVerdict::Pass,
            (0, 1..=2) => AuditVerdict::PassWithWarnings,
            (0, _) => AuditVerdict::PassWithConcerns,
            _ => AuditVerdict::FailsAudit,
        };
    }
}

/// Grade `entities` against the breach evidence they already carry, attach the
/// grading as (non-corroborating) evidence, and audit the result.
///
/// Pure with respect to the network — it queries nothing. Entities without a
/// single breach source are skipped entirely rather than graded at zero, so the
/// population the verdict speaks for is exactly the breach-derived findings.
pub fn run_consensus_pass(entities: &mut [Entity], scan_id: &str) -> BreachConsensusReport {
    let mut report = BreachConsensusReport::new(scan_id);

    for entity in entities.iter_mut() {
        let confirming = breach_sources_of(entity);
        if confirming.is_empty() {
            continue;
        }

        let result = grade(entity, confirming);
        report.entities_examined += 1;
        if result.is_corroborated() {
            report.entities_corroborated += 1;
        }
        if result
            .audit_flags
            .iter()
            .any(|f| matches!(f, AuditFlag::NewFinding { .. }))
        {
            report.new_findings += 1;
        }

        entity.add_evidence(consensus_evidence(&result));
        report.results.push(result);
    }

    report.audit_autonomous();
    report
}

/// Distinct breach corpora attesting `entity`, sorted.
///
/// Reads only sources that already count toward corroboration, so a source the
/// entity model deliberately discounts (recall replay, cross-scan history, this
/// pass's own summary) can never be mistaken for an attesting corpus.
fn breach_sources_of(entity: &Entity) -> Vec<String> {
    let sources: BTreeSet<&str> = entity
        .corroborating_sources()
        .into_iter()
        .filter(|s| is_breach_source(s))
        .collect();
    sources.into_iter().map(str::to_string).collect()
}

/// Build the consensus verdict for one entity, flags and all.
fn grade(entity: &Entity, confirming_sources: Vec<String>) -> ConsensusResult {
    let corroborating = entity.corroborating_sources();
    let breach_only = corroborating.iter().all(|s| is_breach_source(s));
    let mut audit_flags = Vec::new();

    // Sole-corpus finding graded as though verified.
    let c_eff = entity.c_effective();
    if confirming_sources.len() == 1 && c_eff >= Classification::VERIFIED_MIN {
        audit_flags.push(AuditFlag::SingleSourceElevated {
            source: confirming_sources[0].clone(),
            c_effective: c_eff,
        });
    }

    // Stated confidence beyond what the corpora support. Only when breach
    // corpora are the entity's whole provenance — an entity a registry and a
    // breach both attest is not overstated just because the breach half is thin.
    if breach_only {
        let supported = supported_ceiling(confirming_sources.len());
        if entity.confidence > supported {
            audit_flags.push(AuditFlag::ConfidenceDiscrepancy {
                stated: entity.confidence,
                supported,
            });
        }
    }

    if entity.has_tag(SWEEP_TAG) && confirming_sources.len() == 1 {
        audit_flags.push(AuditFlag::NewFinding {
            source: confirming_sources[0].clone(),
        });
    }

    audit_flags.extend(conflicting_attributes(entity));

    ConsensusResult {
        entity_uid: entity.uid.clone(),
        confirming_sources,
        breach_only,
        audit_flags,
    }
}

/// Attribute keys with exactly one true value per person, so two different
/// values are a contradiction rather than a history.
///
/// Deliberately narrow. An address or an employer legitimately changes over
/// time and a breach corpus is a snapshot, so disagreement there is expected
/// and flagging it would bury the real conflicts in noise. Date of birth and
/// government identifiers do not change; if two corpora disagree, one has the
/// wrong person. The DOB spellings come from the correlator's own vocabulary
/// ([`DOB_KEYS`]) so a newly-observed spelling is picked up in both places at
/// once.
fn single_valued_keys() -> impl Iterator<Item = &'static str> {
    DOB_KEYS
        .iter()
        .copied()
        .chain(["ssn", "national_id", "tax_file_number", "passport_number"])
}

/// Flag single-valued attributes on which two distinct breach corpora disagree.
///
/// Compares the FIRST value each source reported for a key: the point is that
/// two corpora contradict each other, so one differing pair is the finding, and
/// emitting a flag per differing pair would multiply one disagreement into many.
fn conflicting_attributes(entity: &Entity) -> Vec<AuditFlag> {
    let mut flags = Vec::new();

    for key in single_valued_keys() {
        // Source → first value that source gave for `key`. BTreeMap so the pair
        // chosen for the flag is deterministic rather than hash-order dependent.
        let mut by_source: BTreeMap<&str, &str> = BTreeMap::new();
        for ev in &entity.evidence {
            if !is_breach_source(&ev.source) {
                continue;
            }
            let Some(value) = ev.attributes.get(key) else {
                continue;
            };
            let value = value.trim();
            if value.is_empty() {
                continue;
            }
            by_source.entry(ev.source.as_str()).or_insert(value);
        }

        if by_source.len() < 2 {
            continue;
        }

        // Date-of-birth values are compared through the canonical `normalise_dob`
        // (the same one AU-073 groups by), so the SAME date in two breach
        // spellings — `1980-11-08` vs the dominant ISO date-time `1980-11-08T00:00:00`
        // — reads as agreement, not a hard contradiction that would wrongly fail
        // the audit and block a genuinely corroborated finding from correlation.
        // Government-ID keys have no canonical normaliser, so they keep the
        // case-insensitive raw compare.
        let is_dob = DOB_KEYS.contains(&key);
        let differs = |a: &str, b: &str| -> bool {
            if is_dob {
                normalise_dob(a) != normalise_dob(b)
            } else {
                !a.eq_ignore_ascii_case(b)
            }
        };

        // One flag per key: the first pair, in sorted-source order, that differs.
        let entries: Vec<(&&str, &&str)> = by_source.iter().collect();
        'outer: for (i, (left_source, left)) in entries.iter().enumerate() {
            for (right_source, right) in entries.iter().skip(i + 1) {
                if differs(left, right) {
                    flags.push(AuditFlag::ConflictingAttributes {
                        attribute: key.to_string(),
                        left_source: (*left_source).to_string(),
                        left: (*left).to_string(),
                        right_source: (*right_source).to_string(),
                        right: (*right).to_string(),
                    });
                    break 'outer;
                }
            }
        }
    }

    flags
}

/// The evidence record documenting a consensus verdict.
///
/// Named the sources rather than merely counted them: an operator reading the
/// chain can go and check each corpus, which a bare "confirmed by 2 sources"
/// does not allow.
fn consensus_evidence(result: &ConsensusResult) -> Evidence {
    let summary = if result.confirming_sources.is_empty() {
        "no breach corpus attests this".to_string()
    } else {
        format!(
            "attested by {} breach {}: {}",
            result.source_count(),
            if result.source_count() == 1 {
                "corpus"
            } else {
                "corpora"
            },
            result.confirming_sources.join(", ")
        )
    };

    let mut ev = Evidence::new(CONSENSUS_SOURCE, summary);
    ev = ev.with_attr("distinct_breach_sources", result.source_count().to_string());
    ev = ev.with_attr("breach_only_provenance", result.breach_only.to_string());
    for flag in &result.audit_flags {
        ev = ev.with_attr("audit_flag", flag.kind());
    }
    ev
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::confidence;
    use crate::core::entity::{CROSS_SCAN_SOURCE, EntityKind};

    fn entity(confidence: f64) -> Entity {
        Entity::new(EntityKind::Email, "a@example.com", confidence, "scan-1")
    }

    fn breach_ev(source: &str, key: &str, value: &str) -> Evidence {
        Evidence::new(source, "breach record").with_attr(key, value)
    }

    #[test]
    fn entities_with_no_breach_source_are_not_graded() {
        let mut e = entity(confidence::HIGH);
        e.add_evidence(Evidence::new("dns_intel", "A record"));
        let mut ents = vec![e];

        let report = run_consensus_pass(&mut ents, "scan-1");

        assert_eq!(report.entities_examined, 0);
        assert!(report.results.is_empty());
        // Nothing attached, so the chain is untouched.
        assert!(
            !ents[0]
                .evidence
                .iter()
                .any(|ev| ev.source == CONSENSUS_SOURCE)
        );
    }

    #[test]
    fn confirming_sources_are_the_real_distinct_corpora() {
        let mut e = entity(0.6);
        e.add_evidence(Evidence::new("hibp", "pwned"));
        e.add_evidence(Evidence::new("dehashed", "record"));
        // Same corpus twice is still one corpus.
        e.add_evidence(Evidence::new("hibp", "pwned again"));
        // Non-breach and non-corroborating sources must not be counted.
        e.add_evidence(Evidence::new("dns_intel", "A record"));
        e.add_evidence(Evidence::new(CROSS_SCAN_SOURCE, "seen before"));
        let mut ents = vec![e];

        let report = run_consensus_pass(&mut ents, "scan-1");

        let r = &report.results[0];
        assert_eq!(r.confirming_sources, vec!["dehashed", "hibp"]);
        assert_eq!(r.source_count(), 2);
        assert!(r.is_corroborated());
        // A registry source is in the chain, so breach corpora are not the whole story.
        assert!(!r.breach_only);
        assert_eq!(report.entities_corroborated, 1);
    }

    #[test]
    fn the_pass_never_raises_confidence() {
        let mut e = entity(0.6);
        e.add_evidence(Evidence::new("hibp", "pwned"));
        e.add_evidence(Evidence::new("dehashed", "record"));
        let before_conf = e.confidence;
        let before_ceff = e.c_effective();
        let mut ents = vec![e];

        run_consensus_pass(&mut ents, "scan-1");

        assert!((ents[0].confidence - before_conf).abs() < f64::EPSILON);
        // The summary is attached but discounted, so C_eff is unmoved too.
        assert!(
            ents[0]
                .evidence
                .iter()
                .any(|ev| ev.source == CONSENSUS_SOURCE)
        );
        assert!((ents[0].c_effective() - before_ceff).abs() < 1e-12);
    }

    #[test]
    fn lone_corpus_graded_as_verified_is_flagged() {
        let mut e = entity(0.95);
        e.add_evidence(Evidence::new("hibp", "pwned"));
        let mut ents = vec![e];

        let report = run_consensus_pass(&mut ents, "scan-1");

        let kinds = report.flag_counts();
        assert_eq!(kinds.get("single_source_elevated"), Some(&1));
        // Breach-only provenance at 0.95 also exceeds the one-corpus ceiling.
        assert_eq!(kinds.get("confidence_discrepancy"), Some(&1));
        assert_eq!(report.verdict, AuditVerdict::PassWithWarnings);
    }

    #[test]
    fn mixed_provenance_is_not_held_to_the_breach_only_ceiling() {
        let mut e = entity(0.95);
        e.add_evidence(Evidence::new("hibp", "pwned"));
        e.add_evidence(Evidence::new("au_electoral", "roll entry"));
        let mut ents = vec![e];

        let report = run_consensus_pass(&mut ents, "scan-1");

        assert!(!report.results[0].breach_only);
        assert!(
            !report
                .flags()
                .any(|f| matches!(f, AuditFlag::ConfidenceDiscrepancy { .. }))
        );
    }

    #[test]
    fn contradictory_dob_between_corpora_fails_the_audit() {
        let mut e = entity(0.8);
        e.add_evidence(breach_ev("hibp", "dob", "1980-11-08"));
        e.add_evidence(breach_ev("dehashed", "dob", "1975-02-01"));
        let mut ents = vec![e];

        let report = run_consensus_pass(&mut ents, "scan-1");

        let conflict = report
            .flags()
            .find(|f| f.is_hard_conflict())
            .expect("contradiction should be flagged");
        assert_eq!(
            *conflict,
            AuditFlag::ConflictingAttributes {
                attribute: "dob".to_string(),
                left_source: "dehashed".to_string(),
                left: "1975-02-01".to_string(),
                right_source: "hibp".to_string(),
                right: "1980-11-08".to_string(),
            }
        );
        assert_eq!(report.verdict, AuditVerdict::FailsAudit);
        assert!(!report.verdict.can_use_for_correlation());
    }

    #[test]
    fn same_dob_in_two_formats_is_not_a_contradiction() {
        // Regression: the dominant ISO date-time breach spelling and the plain
        // date are the SAME birth date. Comparing raw strings once flagged this as
        // a hard contradiction (FailsAudit), impeaching a genuinely corroborated
        // finding and blocking it from correlation; `normalise_dob` (the same
        // canonical form AU-073 groups by) collapses both to `1980-11-08`.
        let mut e = entity(0.8);
        e.add_evidence(breach_ev("hibp", "dob", "1980-11-08"));
        e.add_evidence(breach_ev("dehashed", "dob", "1980-11-08T00:00:00"));
        let mut ents = vec![e];

        let report = run_consensus_pass(&mut ents, "scan-1");

        assert!(
            !report.flags().any(AuditFlag::is_hard_conflict),
            "same date in two breach spellings must not be a contradiction"
        );
        assert!(report.verdict.can_use_for_correlation());
    }

    #[test]
    fn agreeing_corpora_raise_no_conflict() {
        let mut e = entity(0.8);
        e.add_evidence(breach_ev("hibp", "dob", "1980-11-08"));
        e.add_evidence(breach_ev("dehashed", "dob", "1980-11-08"));
        let mut ents = vec![e];

        let report = run_consensus_pass(&mut ents, "scan-1");

        assert!(!report.flags().any(AuditFlag::is_hard_conflict));
        assert_eq!(report.verdict, AuditVerdict::Pass);
    }

    #[test]
    fn one_corpus_reporting_a_dob_is_not_a_conflict() {
        let mut e = entity(0.6);
        e.add_evidence(breach_ev("hibp", "dob", "1980-11-08"));
        e.add_evidence(breach_ev("hibp", "dob", "1975-02-01"));
        let mut ents = vec![e];

        let report = run_consensus_pass(&mut ents, "scan-1");

        // One corpus is internally inconsistent — real, but not cross-corpus
        // disagreement, and not what this flag claims.
        assert!(!report.flags().any(AuditFlag::is_hard_conflict));
    }

    #[test]
    fn a_changed_address_is_not_treated_as_a_contradiction() {
        let mut e = entity(0.6);
        e.add_evidence(breach_ev("hibp", "address", "1 Old St"));
        e.add_evidence(breach_ev("dehashed", "address", "2 New Rd"));
        let mut ents = vec![e];

        let report = run_consensus_pass(&mut ents, "scan-1");

        assert!(!report.flags().any(AuditFlag::is_hard_conflict));
    }

    #[test]
    fn sweep_only_single_source_finding_is_flagged_new() {
        let mut e = entity(0.5);
        e.tag(SWEEP_TAG);
        e.add_evidence(Evidence::new("dehashed", "record"));
        let mut ents = vec![e];

        let report = run_consensus_pass(&mut ents, "scan-1");

        assert_eq!(report.new_findings, 1);
        assert!(
            report
                .flags()
                .any(|f| matches!(f, AuditFlag::NewFinding { .. }))
        );
    }

    #[test]
    fn ceiling_rises_only_with_independent_corpora() {
        assert!(supported_ceiling(0) < Classification::VERIFIED_MIN);
        assert!(supported_ceiling(1) < Classification::VERIFIED_MIN);
        assert!(supported_ceiling(2) > Classification::VERIFIED_MIN);
        assert!(supported_ceiling(3) >= supported_ceiling(2));
    }

    #[test]
    fn an_unrun_audit_is_not_a_clean_one() {
        let report = BreachConsensusReport::new("scan-1");
        assert_eq!(report.verdict, AuditVerdict::PendingReview);
        assert!(!report.verdict.can_use_for_correlation());
    }

    #[test]
    fn the_pass_always_leaves_a_real_verdict() {
        let mut ents: Vec<Entity> = Vec::new();
        let report = run_consensus_pass(&mut ents, "scan-1");
        assert_ne!(report.verdict, AuditVerdict::PendingReview);
        assert_eq!(report.verdict, AuditVerdict::Pass);
    }

    #[test]
    fn many_soft_flags_escalate_to_concerns() {
        let mut ents: Vec<Entity> = (0..3)
            .map(|i| {
                let mut e = Entity::new(
                    EntityKind::Email,
                    format!("user{i}@example.com"),
                    0.95,
                    "scan-1",
                );
                e.add_evidence(Evidence::new("hibp", "pwned"));
                e
            })
            .collect();

        let report = run_consensus_pass(&mut ents, "scan-1");

        assert_eq!(report.verdict, AuditVerdict::PassWithConcerns);
        assert!(!report.flags().any(AuditFlag::is_hard_conflict));
    }
}
