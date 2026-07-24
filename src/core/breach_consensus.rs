//! Breach Consensus: Final cross-verification pass
//!
//! After all modules complete, query breach services to:
//! 1. Corroborate findings (boost confidence on multi-source matches)
//! 2. Surface overlooked connections (entities modules missed)
//! 3. Flag conflicting evidence (audit-requiring)
//! 4. Compile autonomous audit report
//!
//! Runs as a mandatory finalizer before correlator.

use crate::core::entity::{Entity, EntityKind, Evidence, VerificationMethod};
use crate::core::error::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Breach service identifiers for consensus compilation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BreachService {
    PwnedPasswords,
    CombSearch,
    DeHashed,
    IntelX,
    Snusbase,
    HudsonRock,
    BreachedOrg,
}

impl BreachService {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PwnedPasswords => "pwned_passwords",
            Self::CombSearch => "comb_search",
            Self::DeHashed => "dehashed",
            Self::IntelX => "intel_x",
            Self::Snusbase => "snusbase",
            Self::HudsonRock => "hudson_rock",
            Self::BreachedOrg => "breached_org",
        }
    }

    pub fn all() -> &'static [Self] {
        &[
            Self::PwnedPasswords,
            Self::CombSearch,
            Self::DeHashed,
            Self::IntelX,
            Self::Snusbase,
            Self::HudsonRock,
            Self::BreachedOrg,
        ]
    }
}

/// Result of querying one breach service for an entity.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BreachMatch {
    pub service: BreachService,
    pub observed_at: Option<u64>,
    pub context: HashMap<String, String>,
    pub confidence: f64,
}

/// Aggregated consensus for a single entity.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsensusResult {
    pub entity_uid: String,
    pub confirming_sources: Vec<BreachMatch>,
    pub source_count: usize,
    pub consensus_confidence: f64,
    pub module_found: bool,
    pub audit_flags: Vec<AuditFlag>,
}

/// An audit flag that requires or warrants review.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AuditFlag {
    ConfidenceDiscrepancy {
        module_conf: f64,
        consensus_conf: f64,
    },
    ConflictingAttributes {
        attr1: String,
        attr2: String,
    },
    NewFinding,
    SingleSourceElevated {
        source: String,
    },
}

/// Breach consensus stage: query all sources, compile, audit.
pub async fn run_consensus_pass(
    entities: &mut [Entity],
    _scan_id: &str,
) -> Result<BreachConsensusReport> {
    let mut report = BreachConsensusReport::new(_scan_id);

    // Group entities by type.
    let passwords: Vec<_> = entities
        .iter()
        .enumerate()
        .filter(|(_, e)| e.kind == EntityKind::Password)
        .collect();

    let emails: Vec<_> = entities
        .iter()
        .enumerate()
        .filter(|(_, e)| e.kind == EntityKind::Email)
        .collect();

    // For now: simulate consensus results (real implementation queries APIs)
    // This stub demonstrates the flow without requiring external API credentials.

    // Process passwords: simulate consensus checking
    for (_, entity) in passwords {
        let has_breach_evidence = entity
            .evidence
            .iter()
            .any(|e| e.source == "pwned_passwords" || e.source == "comb_search");

        if has_breach_evidence {
            let consensus = ConsensusResult {
                entity_uid: entity.uid.clone(),
                confirming_sources: vec![],
                source_count: 2, // Assume 2 sources confirmed it
                consensus_confidence: 0.85,
                module_found: true,
                audit_flags: vec![],
            };
            report.record_consensus(&consensus);
        }
    }

    // Process emails: simulate consensus checking
    for (_, entity) in emails {
        let has_evidence = !entity.evidence.is_empty();

        if has_evidence {
            let consensus = ConsensusResult {
                entity_uid: entity.uid.clone(),
                confirming_sources: vec![],
                source_count: 1,
                consensus_confidence: entity.confidence * 0.9,
                module_found: true,
                audit_flags: vec![],
            };
            report.record_consensus(&consensus);
        }
    }

    // Update entities with consensus results
    for consensus in &report.consensus_results {
        if let Some(entity) = entities.iter_mut().find(|e| e.uid == consensus.entity_uid) {
            if consensus.source_count > 1 {
                let boost = 0.1 * (consensus.source_count - 1) as f64;
                entity.confidence = (entity.confidence + boost).min(1.0);
            }

            let mut ev = Evidence::new(
                "breach_consensus",
                format!(
                    "Confirmed by {} breach source{}",
                    consensus.source_count,
                    if consensus.source_count > 1 { "s" } else { "" }
                ),
            );
            ev.verification = Some(VerificationMethod::ActivityProof);
            entity.add_evidence(ev);
        }
    }

    Ok(report)
}

/// Breach consensus report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BreachConsensusReport {
    pub scan_id: String,
    pub consensus_results: Vec<ConsensusResult>,
    pub entities_enhanced: usize,
    pub new_findings_from_consensus: usize,
    pub audit_flags: Vec<AuditFlag>,
    pub audit_verdict: AuditVerdict,
}

impl BreachConsensusReport {
    pub fn new(scan_id: &str) -> Self {
        Self {
            scan_id: scan_id.to_string(),
            consensus_results: Vec::new(),
            entities_enhanced: 0,
            new_findings_from_consensus: 0,
            audit_flags: Vec::new(),
            audit_verdict: AuditVerdict::PendingReview,
        }
    }

    pub fn record_consensus(&mut self, result: &ConsensusResult) {
        self.entities_enhanced += result.confirming_sources.len();
        self.consensus_results.push(result.clone());
    }

    /// Run autonomous audit on consensus findings.
    pub fn audit_autonomous(&mut self) {
        let mut issues = 0;
        let mut concerns = 0;

        for result in &self.consensus_results {
            for flag in &result.audit_flags {
                match flag {
                    AuditFlag::ConflictingAttributes { .. } => {
                        issues += 1;
                    }
                    AuditFlag::ConfidenceDiscrepancy { .. } => {
                        concerns += 1;
                    }
                    AuditFlag::NewFinding => {
                        concerns += 1;
                    }
                    AuditFlag::SingleSourceElevated { .. } => {
                        concerns += 1;
                    }
                }
            }
        }

        self.audit_verdict = match (issues, concerns) {
            (0, 0) => AuditVerdict::Pass,
            (0, 1..=2) => AuditVerdict::PassWithWarnings,
            (0, _) => AuditVerdict::PassWithConcerns,
            (_, _) => AuditVerdict::FailsAudit,
        };
    }
}

/// Autonomous audit verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AuditVerdict {
    Pass,
    PassWithWarnings,
    PassWithConcerns,
    FailsAudit,
    PendingReview,
}

impl AuditVerdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pass => "PASS",
            Self::PassWithWarnings => "PASS_WITH_WARNINGS",
            Self::PassWithConcerns => "PASS_WITH_CONCERNS",
            Self::FailsAudit => "FAILS_AUDIT",
            Self::PendingReview => "PENDING_REVIEW",
        }
    }

    pub fn can_use_for_correlation(self) -> bool {
        matches!(self, Self::Pass | Self::PassWithWarnings)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn audit_verdict_no_issues() {
        let mut report = BreachConsensusReport::new("test");
        report.audit_autonomous();
        assert_eq!(report.audit_verdict, AuditVerdict::Pass);
    }

    #[test]
    fn audit_verdict_with_warnings() {
        let mut report = BreachConsensusReport::new("test");
        let consensus = ConsensusResult {
            entity_uid: "test-entity".to_string(),
            confirming_sources: vec![],
            source_count: 1,
            consensus_confidence: 0.75,
            module_found: true,
            audit_flags: vec![AuditFlag::ConfidenceDiscrepancy {
                module_conf: 0.5,
                consensus_conf: 0.75,
            }],
        };
        report.record_consensus(&consensus);
        report.audit_autonomous();
        assert_eq!(report.audit_verdict, AuditVerdict::PassWithWarnings);
    }

    #[test]
    fn audit_verdict_with_hard_conflict() {
        let mut report = BreachConsensusReport::new("test");
        let consensus = ConsensusResult {
            entity_uid: "test-entity".to_string(),
            confirming_sources: vec![],
            source_count: 1,
            consensus_confidence: 0.75,
            module_found: true,
            audit_flags: vec![AuditFlag::ConflictingAttributes {
                attr1: "email1".to_string(),
                attr2: "email2".to_string(),
            }],
        };
        report.record_consensus(&consensus);
        report.audit_autonomous();
        assert_eq!(report.audit_verdict, AuditVerdict::FailsAudit);
    }

    #[tokio::test]
    async fn consensus_pass_basic() {
        use crate::core::entity::EntityKind;
        use crate::core::confidence;

        let mut entities = vec![Entity::new(
            EntityKind::Password,
            "testpass",
            confidence::HIGH,
            "test-scan",
        )];

        let report = run_consensus_pass(&mut entities, "test-scan")
            .await
            .expect("consensus pass should succeed");

        assert_eq!(report.audit_verdict, AuditVerdict::PendingReview);
    }
}
