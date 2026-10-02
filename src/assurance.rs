use std::io;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Profile {
    Core,
    Development,
    Cloud,
}

impl Profile {
    #[must_use]
    pub const fn id(self) -> &'static str {
        match self {
            Self::Core => "HRECON-CORE",
            Self::Development => "HRECON-DEVELOPMENT",
            Self::Cloud => "HRECON-CLOUD",
        }
    }

    #[must_use]
    pub const fn all() -> &'static [Self] {
        &[Self::Core, Self::Development, Self::Cloud]
    }

    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        let want = value.trim().to_ascii_lowercase();
        Self::all().iter().copied().find(|profile| {
            let id = profile.id().to_ascii_lowercase();
            id == want || id.strip_prefix("hrecon-") == Some(want.as_str())
        })
    }

    #[must_use]
    pub fn short_names() -> Vec<String> {
        Self::all()
            .iter()
            .map(|profile| {
                profile
                    .id()
                    .trim_start_matches("HRECON-")
                    .to_ascii_lowercase()
            })
            .collect()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Applicability {
    Applicable,
    Conditional,
    NotApplicable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ProtectionDimension {
    Confidentiality,
    Integrity,
    Availability,
    Authenticity,
    Traceability,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ProtectionLevel {
    Normal,
    High,
    VeryHigh,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum AssuranceLevel {
    Unknown,
    Defined,
    Implemented,
    Enforced,
    Tested,
    Observed,
    Assured,
}

impl AssuranceLevel {
    #[must_use]
    pub const fn code(self) -> &'static str {
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ControlState {
    NotApplicable,
    Unknown,
    Gap,
    Defined,
    Implemented,
    Enforced,
    Tested,
    Observed,
    Assured,
    Regressed,
}

impl ControlState {
    #[must_use]
    pub const fn is_deficiency(self) -> bool {
        matches!(self, Self::Unknown | Self::Gap | Self::Regressed)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EvidenceKind {
    Definition,
    Implementation,
    Enforcement,
    Test,
    RuntimeObservation,
    ExternalAssurance,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Evidence {
    pub kind: EvidenceKind,
    pub source: String,
    pub detail: String,
    pub recorded_at: u64,
}

impl Evidence {
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

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProtectionNeed {
    #[serde(default)]
    pub elevated: Vec<(ProtectionDimension, ProtectionLevel)>,
}

impl ProtectionNeed {
    #[must_use]
    pub fn level(&self, dimension: ProtectionDimension) -> ProtectionLevel {
        self.elevated
            .iter()
            .find(|(current, _)| *current == dimension)
            .map_or(ProtectionLevel::Normal, |(_, level)| *level)
    }

    #[must_use]
    pub fn max_level(&self) -> ProtectionLevel {
        self.elevated
            .iter()
            .map(|(_, level)| *level)
            .max()
            .unwrap_or(ProtectionLevel::Normal)
    }

    #[must_use]
    pub fn drives_high_assurance(&self) -> bool {
        self.max_level() >= ProtectionLevel::High
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Criticality {
    Routine,
    Important,
    Critical,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GermanControl {
    pub id: String,
    pub framework: String,
    pub framework_version: String,
    pub module: String,
    pub requirement: String,
    pub profile: Profile,
    pub applicability: Applicability,
    pub applicability_reason: String,
    pub protection_need: ProtectionNeed,
    pub criticality: Criticality,
    pub evidence: Vec<Evidence>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ResolvedControl {
    pub control: GermanControl,
    pub state: ControlState,
    pub level: AssuranceLevel,
    pub severity: Option<GapSeverity>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum GapSeverity {
    Low,
    Medium,
    High,
    Critical,
}

impl GapSeverity {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Low => "LOW",
            Self::Medium => "MEDIUM",
            Self::High => "HIGH",
            Self::Critical => "CRITICAL",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct GapFinding {
    pub control_id: String,
    pub module: String,
    pub state: ControlState,
    pub severity: GapSeverity,
    pub criticality: Criticality,
    pub high_protection_need: bool,
}

const LADDER: &[(EvidenceKind, AssuranceLevel)] = &[
    (EvidenceKind::Definition, AssuranceLevel::Defined),
    (EvidenceKind::Implementation, AssuranceLevel::Implemented),
    (EvidenceKind::Enforcement, AssuranceLevel::Enforced),
    (EvidenceKind::Test, AssuranceLevel::Tested),
    (EvidenceKind::RuntimeObservation, AssuranceLevel::Observed),
    (EvidenceKind::ExternalAssurance, AssuranceLevel::Assured),
];

fn holds(evidence: &[Evidence], kind: EvidenceKind) -> bool {
    evidence.iter().any(|item| item.kind == kind)
}

#[must_use]
pub fn derive_level(evidence: &[Evidence]) -> AssuranceLevel {
    let mut level = AssuranceLevel::Unknown;
    for (kind, rung) in LADDER {
        if holds(evidence, *kind) {
            level = *rung;
        } else {
            break;
        }
    }
    level
}

fn level_to_state(level: AssuranceLevel) -> ControlState {
    match level {
        AssuranceLevel::Unknown => ControlState::Unknown,
        AssuranceLevel::Defined => ControlState::Defined,
        AssuranceLevel::Implemented => ControlState::Implemented,
        AssuranceLevel::Enforced => ControlState::Enforced,
        AssuranceLevel::Tested => ControlState::Tested,
        AssuranceLevel::Observed => ControlState::Observed,
        AssuranceLevel::Assured => ControlState::Assured,
    }
}

fn state_rung(state: ControlState) -> AssuranceLevel {
    match state {
        ControlState::Defined => AssuranceLevel::Defined,
        ControlState::Implemented => AssuranceLevel::Implemented,
        ControlState::Enforced => AssuranceLevel::Enforced,
        ControlState::Tested => AssuranceLevel::Tested,
        ControlState::Observed => AssuranceLevel::Observed,
        ControlState::Assured => AssuranceLevel::Assured,
        _ => AssuranceLevel::Unknown,
    }
}

#[must_use]
pub fn derive_state(
    applicability: Applicability,
    evidence: &[Evidence],
    prior: Option<ControlState>,
) -> ControlState {
    if applicability == Applicability::NotApplicable {
        return ControlState::NotApplicable;
    }
    let level = derive_level(evidence);
    if let Some(prior_state) = prior {
        if state_rung(prior_state) > level {
            return ControlState::Regressed;
        }
    }
    match level {
        AssuranceLevel::Unknown => match prior {
            None => ControlState::Unknown,
            Some(_) => ControlState::Gap,
        },
        other => level_to_state(other),
    }
}

fn criticality_weight(criticality: Criticality) -> u8 {
    match criticality {
        Criticality::Routine => 0,
        Criticality::Important => 1,
        Criticality::Critical => 2,
    }
}

fn protection_weight(need: &ProtectionNeed) -> u8 {
    match need.max_level() {
        ProtectionLevel::Normal => 0,
        ProtectionLevel::High => 1,
        ProtectionLevel::VeryHigh => 2,
    }
}

fn deficiency_depth(state: ControlState) -> u8 {
    match state {
        ControlState::Regressed => 2,
        ControlState::Gap => 1,
        _ => 0,
    }
}

#[must_use]
pub fn gap_severity(
    state: ControlState,
    criticality: Criticality,
    need: &ProtectionNeed,
) -> Option<GapSeverity> {
    if !state.is_deficiency() {
        return None;
    }
    let score = criticality_weight(criticality) + protection_weight(need) + deficiency_depth(state);
    Some(match score {
        0 => GapSeverity::Low,
        1..=2 => GapSeverity::Medium,
        3..=4 => GapSeverity::High,
        _ => GapSeverity::Critical,
    })
}

impl GermanControl {
    #[must_use]
    pub fn resolve(&self, prior: Option<ControlState>) -> ResolvedControl {
        let level = derive_level(&self.evidence);
        let state = derive_state(self.applicability, &self.evidence, prior);
        let severity = gap_severity(state, self.criticality, &self.protection_need);
        ResolvedControl {
            control: self.clone(),
            state,
            level,
            severity,
        }
    }
}

fn ev(kind: EvidenceKind, source: &str, detail: &str) -> Evidence {
    Evidence {
        kind,
        source: source.to_string(),
        detail: detail.to_string(),
        recorded_at: 0,
    }
}

fn need(elevated: &[(ProtectionDimension, ProtectionLevel)]) -> ProtectionNeed {
    ProtectionNeed {
        elevated: elevated.to_vec(),
    }
}

#[must_use]
pub fn catalog() -> Vec<GermanControl> {
    vec![
        GermanControl {
            id: "HRECON-LEDGER-INTEGRITY".to_string(),
            framework: "Offline Core".to_string(),
            framework_version: "2026-10-02".to_string(),
            module: "ledger".to_string(),
            requirement: "Evidence claims are chained, verified, and refused on tamper.".to_string(),
            profile: Profile::Core,
            applicability: Applicability::Applicable,
            applicability_reason: "Every deployment relies on the local evidence ledger.".to_string(),
            protection_need: need(&[(ProtectionDimension::Integrity, ProtectionLevel::High)]),
            criticality: Criticality::Critical,
            evidence: vec![
                ev(EvidenceKind::Definition, "src/assurance.rs", "Ledger integrity control mapped."),
                ev(EvidenceKind::Implementation, "src/ledger.rs", "Hash chaining and chain verification."),
                ev(EvidenceKind::Enforcement, "src/ledger.rs", "Broken chains are refused on load/write."),
                ev(EvidenceKind::Test, "src/ledger.rs::tampered_file_fails_load", "Tamper fails closed."),
            ],
        },
        GermanControl {
            id: "HRECON-ATTACK-INTEROP".to_string(),
            framework: "Offline Core".to_string(),
            framework_version: "2026-10-02".to_string(),
            module: "attack-export".to_string(),
            requirement: "ATT&CK/STIX/Navigator export occurs only for verified, explicitly bound claims.".to_string(),
            profile: Profile::Core,
            applicability: Applicability::Applicable,
            applicability_reason: "The crate ships ATT&CK-facing exports.".to_string(),
            protection_need: need(&[(ProtectionDimension::Integrity, ProtectionLevel::High)]),
            criticality: Criticality::Important,
            evidence: vec![
                ev(EvidenceKind::Definition, "src/assurance.rs", "Interop gate mapped to export surfaces."),
                ev(EvidenceKind::Implementation, "src/navigator.rs", "Navigator and coverage layers emit admitted entries only."),
                ev(EvidenceKind::Enforcement, "src/ledger.rs", "Binding table controls admission."),
                ev(EvidenceKind::Test, "src/navigator.rs::catalog_only_claim_is_absent", "Catalog presence alone never scores."),
            ],
        },
        GermanControl {
            id: "HRECON-CONFIDENCE".to_string(),
            framework: "Core Controls".to_string(),
            framework_version: "2026-10-02".to_string(),
            module: "confidence".to_string(),
            requirement: "Cross-source corroboration strengthens confidence without fabricating verification from weak sources.".to_string(),
            profile: Profile::Development,
            applicability: Applicability::Applicable,
            applicability_reason: "Confidence scoring underpins the reconstructed core.".to_string(),
            protection_need: need(&[(ProtectionDimension::Integrity, ProtectionLevel::High)]),
            criticality: Criticality::Important,
            evidence: vec![
                ev(EvidenceKind::Definition, "src/assurance.rs", "Confidence control mapped to the corroboration model."),
                ev(EvidenceKind::Implementation, "src/confidence.rs", "Effective confidence and classification logic."),
                ev(EvidenceKind::Test, "src/confidence.rs::weak_sources_cannot_compound_into_verified", "Weak-source escalation defect locked by test."),
            ],
        },
        GermanControl {
            id: "HRECON-CLOUD".to_string(),
            framework: "Cloud Controls".to_string(),
            framework_version: "2026-10-02".to_string(),
            module: "cloud".to_string(),
            requirement: "Cloud shared-responsibility controls are assessed only for hosted deployments.".to_string(),
            profile: Profile::Cloud,
            applicability: Applicability::NotApplicable,
            applicability_reason: "The reconstructed crate does not implement a hosted control plane in-tree.".to_string(),
            protection_need: ProtectionNeed::default(),
            criticality: Criticality::Routine,
            evidence: vec![ev(EvidenceKind::Definition, "src/assurance.rs", "Cloud profile exists but is out of scope by default.")],
        },
    ]
}

#[must_use]
pub fn resolve_catalog() -> Vec<ResolvedControl> {
    catalog()
        .into_iter()
        .map(|control| control.resolve(None))
        .collect()
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct AssuranceSummary {
    pub total: usize,
    pub not_applicable: usize,
    pub deficiencies: usize,
    pub tested_or_higher: usize,
    pub observed_or_higher: usize,
    pub assured: usize,
    pub critical_findings: usize,
    pub high_findings: usize,
    pub highest_open_severity: Option<GapSeverity>,
}

#[must_use]
pub fn summarise(resolved: &[ResolvedControl]) -> AssuranceSummary {
    let mut summary = AssuranceSummary {
        total: resolved.len(),
        ..AssuranceSummary::default()
    };
    for control in resolved {
        if control.state == ControlState::NotApplicable {
            summary.not_applicable += 1;
        }
        if control.state.is_deficiency() {
            summary.deficiencies += 1;
        }
        if control.level >= AssuranceLevel::Tested && control.state != ControlState::NotApplicable {
            summary.tested_or_higher += 1;
        }
        if control.level >= AssuranceLevel::Observed && control.state != ControlState::NotApplicable
        {
            summary.observed_or_higher += 1;
        }
        if control.level == AssuranceLevel::Assured && control.state == ControlState::Assured {
            summary.assured += 1;
        }
        if let Some(severity) = control.severity {
            match severity {
                GapSeverity::Critical => summary.critical_findings += 1,
                GapSeverity::High => summary.high_findings += 1,
                GapSeverity::Low | GapSeverity::Medium => {}
            }
            summary.highest_open_severity = Some(match summary.highest_open_severity {
                Some(previous) => previous.max(severity),
                None => severity,
            });
        }
    }
    summary
}

#[must_use]
pub fn findings(resolved: &[ResolvedControl]) -> Vec<GapFinding> {
    let mut out: Vec<GapFinding> = resolved
        .iter()
        .filter_map(|control| {
            gap_severity(
                control.state,
                control.control.criticality,
                &control.control.protection_need,
            )
            .map(|severity| GapFinding {
                control_id: control.control.id.clone(),
                module: control.control.module.clone(),
                state: control.state,
                severity,
                criticality: control.control.criticality,
                high_protection_need: control.control.protection_need.drives_high_assurance(),
            })
        })
        .collect();
    out.sort_by(|left, right| {
        right
            .severity
            .cmp(&left.severity)
            .then_with(|| right.criticality.cmp(&left.criticality))
            .then_with(|| left.control_id.cmp(&right.control_id))
    });
    out
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct VerifyVerdict {
    pub ok: bool,
    pub regressions: Vec<GapFinding>,
    pub blocking: Vec<GapFinding>,
    pub warnings: Vec<GapFinding>,
    pub summary: AssuranceSummary,
}

#[must_use]
pub fn verify(resolved: &[ResolvedControl]) -> VerifyVerdict {
    let mut verdict = VerifyVerdict {
        summary: summarise(resolved),
        ..VerifyVerdict::default()
    };
    for finding in findings(resolved) {
        let regressed = finding.state == ControlState::Regressed;
        let blocking = finding.severity >= GapSeverity::High;
        if regressed {
            verdict.regressions.push(finding.clone());
        }
        if blocking {
            verdict.blocking.push(finding);
        } else if !regressed {
            verdict.warnings.push(finding);
        }
    }
    verdict.ok = verdict.regressions.is_empty() && verdict.blocking.is_empty();
    verdict
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum RecoveryPoint {
    LastCommit,
    PreviousArtifact,
    NotApplicable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ContinuityState {
    Untested,
    Tested,
    Observed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ObservedRecovery {
    pub recovery_secs: u64,
    pub data_loss: String,
    pub source: String,
    pub recorded_at: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ContinuityObjective {
    pub capability: &'static str,
    pub name: &'static str,
    pub control_id: &'static str,
    pub criticality: Criticality,
    pub faults: &'static [&'static str],
    pub mtpd_secs: Option<u64>,
    pub rto_secs: Option<u64>,
    pub rpo: RecoveryPoint,
    pub degraded_mode: &'static str,
    pub fallback: &'static str,
    pub recovery_procedure: &'static str,
    pub recovery_tests: &'static [&'static str],
    pub observed: Option<ObservedRecovery>,
}

impl ContinuityObjective {
    #[must_use]
    pub fn state(&self) -> ContinuityState {
        if self.observed.is_some() {
            ContinuityState::Observed
        } else if self.recovery_tests.is_empty() {
            ContinuityState::Untested
        } else {
            ContinuityState::Tested
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ContinuityAssessment {
    pub objective: ContinuityObjective,
    pub state: ContinuityState,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct ContinuitySummary {
    pub total: usize,
    pub untested: usize,
    pub tested: usize,
    pub observed: usize,
    pub untested_capabilities: Vec<&'static str>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceEntryKind {
    Directory,
    File,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceEntry {
    pub path: PathBuf,
    pub kind: SourceEntryKind,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SourceDocument {
    pub path: String,
    pub body: String,
}

pub trait SourceTree {
    /// Lists the direct children of `dir`.
    ///
    /// # Errors
    ///
    /// Returns any backend-specific directory-enumeration failure.
    fn entries(&self, dir: &Path) -> io::Result<Vec<SourceEntry>>;

    /// Reads a UTF-8 source file into memory.
    ///
    /// # Errors
    ///
    /// Returns any backend-specific file-read or UTF-8 decoding failure.
    fn read_to_string(&self, path: &Path) -> io::Result<String>;
}

#[derive(Debug, Default, Clone, Copy)]
pub struct FsSourceTree;

impl SourceTree for FsSourceTree {
    fn entries(&self, dir: &Path) -> io::Result<Vec<SourceEntry>> {
        let mut entries = Vec::new();
        for entry in std::fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();
            let kind = if entry.file_type()?.is_dir() {
                SourceEntryKind::Directory
            } else {
                SourceEntryKind::File
            };
            entries.push(SourceEntry { path, kind });
        }
        entries.sort_by(|left, right| left.path.cmp(&right.path));
        Ok(entries)
    }

    fn read_to_string(&self, path: &Path) -> io::Result<String> {
        std::fs::read_to_string(path)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MissingRecoveryTest {
    pub capability: &'static str,
    pub test_name: &'static str,
}

/// Collects Rust source files from the supplied roots using the provided source-tree adapter.
///
/// # Errors
///
/// Returns any directory-listing or file-read error surfaced by the supplied `SourceTree`.
pub fn collect_rust_sources<T: SourceTree>(
    tree: &T,
    roots: &[&Path],
) -> io::Result<Vec<SourceDocument>> {
    let mut documents = Vec::new();
    for root in roots {
        collect_rust_sources_from(tree, root, &mut documents)?;
    }
    documents.sort_by(|left, right| left.path.cmp(&right.path));
    Ok(documents)
}

fn collect_rust_sources_from<T: SourceTree>(
    tree: &T,
    root: &Path,
    documents: &mut Vec<SourceDocument>,
) -> io::Result<()> {
    for entry in tree.entries(root)? {
        match entry.kind {
            SourceEntryKind::Directory => {
                collect_rust_sources_from(tree, &entry.path, documents)?;
            }
            SourceEntryKind::File if entry.path.extension().is_some_and(|ext| ext == "rs") => {
                documents.push(SourceDocument {
                    path: entry.path.display().to_string(),
                    body: tree.read_to_string(&entry.path)?,
                });
            }
            SourceEntryKind::File => {}
        }
    }
    Ok(())
}

#[must_use]
pub fn missing_recovery_tests(
    objectives: &[ContinuityObjective],
    documents: &[SourceDocument],
) -> Vec<MissingRecoveryTest> {
    objectives
        .iter()
        .flat_map(|objective| {
            objective.recovery_tests.iter().filter_map(|name| {
                let needle = format!("fn {name}(");
                if documents
                    .iter()
                    .any(|document| document.body.contains(&needle))
                {
                    None
                } else {
                    Some(MissingRecoveryTest {
                        capability: objective.capability,
                        test_name: name,
                    })
                }
            })
        })
        .collect()
}

#[must_use]
pub fn objectives() -> Vec<ContinuityObjective> {
    vec![
        ContinuityObjective {
            capability: "ledger_store",
            name: "Ledger persistence and verification",
            control_id: "HRECON-LEDGER-INTEGRITY",
            criticality: Criticality::Critical,
            faults: &["tampered artifact", "broken chain", "partial write"],
            mtpd_secs: Some(60),
            rto_secs: Some(10),
            rpo: RecoveryPoint::LastCommit,
            degraded_mode: "Broken or tampered ledgers fail closed instead of emitting a false green state.",
            fallback: "Regenerate the ledger from the current verified claims.",
            recovery_procedure: "Reload and re-seal from the last intact chain tip.",
            recovery_tests: &["tampered_file_fails_load"],
            observed: None,
        },
        ContinuityObjective {
            capability: "attack_exports",
            name: "Navigator and STIX exports",
            control_id: "HRECON-ATTACK-INTEROP",
            criticality: Criticality::Important,
            faults: &["stale export contract", "unsupported ATT&CK claim"],
            mtpd_secs: None,
            rto_secs: None,
            rpo: RecoveryPoint::PreviousArtifact,
            degraded_mode: "Unbound techniques stay absent rather than being inferred.",
            fallback: "Re-run export from the verified ledger after fixing the binding or coverage input.",
            recovery_procedure: "Regenerate artifacts from the current ledger and coverage sets.",
            recovery_tests: &[
                "bound_entry_exports_a_well_formed_indicator",
                "coverage_layer_emits_covered_and_gap_techniques",
            ],
            observed: None,
        },
    ]
}

#[must_use]
pub fn assess() -> Vec<ContinuityAssessment> {
    let mut out: Vec<ContinuityAssessment> = objectives()
        .into_iter()
        .map(|objective| ContinuityAssessment {
            state: objective.state(),
            objective,
        })
        .collect();
    out.sort_by(|left, right| {
        left.state
            .cmp(&right.state)
            .then_with(|| right.objective.criticality.cmp(&left.objective.criticality))
            .then_with(|| left.objective.capability.cmp(right.objective.capability))
    });
    out
}

#[must_use]
pub fn summarise_continuity(assessed: &[ContinuityAssessment]) -> ContinuitySummary {
    let mut summary = ContinuitySummary {
        total: assessed.len(),
        ..ContinuitySummary::default()
    };
    for item in assessed {
        match item.state {
            ContinuityState::Untested => {
                summary.untested += 1;
                summary
                    .untested_capabilities
                    .push(item.objective.capability);
            }
            ContinuityState::Tested => summary.tested += 1,
            ContinuityState::Observed => summary.observed += 1,
        }
    }
    summary
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::io;
    use std::path::{Path, PathBuf};

    use super::*;

    fn e(kind: EvidenceKind, at: u64) -> Evidence {
        Evidence {
            kind,
            source: "test".to_string(),
            detail: String::new(),
            recorded_at: at,
        }
    }

    fn ladder_to(top: EvidenceKind) -> Vec<Evidence> {
        let order = [
            EvidenceKind::Definition,
            EvidenceKind::Implementation,
            EvidenceKind::Enforcement,
            EvidenceKind::Test,
            EvidenceKind::RuntimeObservation,
            EvidenceKind::ExternalAssurance,
        ];
        let mut out = Vec::new();
        for kind in order {
            out.push(e(kind, 1));
            if kind == top {
                break;
            }
        }
        out
    }

    fn need_at(level: ProtectionLevel) -> ProtectionNeed {
        if level == ProtectionLevel::Normal {
            ProtectionNeed::default()
        } else {
            ProtectionNeed {
                elevated: vec![(ProtectionDimension::Integrity, level)],
            }
        }
    }

    fn syn(
        id: &str,
        applicability: Applicability,
        criticality: Criticality,
        need: ProtectionNeed,
        evidence: Vec<Evidence>,
    ) -> GermanControl {
        GermanControl {
            id: id.to_string(),
            framework: "test".to_string(),
            framework_version: "test".to_string(),
            module: "TST.0".to_string(),
            requirement: "synthetic".to_string(),
            profile: Profile::Core,
            applicability,
            applicability_reason: "synthetic".to_string(),
            protection_need: need,
            criticality,
            evidence,
        }
    }

    #[derive(Default)]
    struct FakeSourceTree {
        entries: BTreeMap<String, Vec<SourceEntry>>,
        files: BTreeMap<String, String>,
    }

    impl FakeSourceTree {
        fn with_dir(mut self, path: &str, entries: Vec<SourceEntry>) -> Self {
            self.entries.insert(path.to_string(), entries);
            self
        }

        fn with_file(mut self, path: &str, body: &str) -> Self {
            self.files.insert(path.to_string(), body.to_string());
            self
        }
    }

    impl SourceTree for FakeSourceTree {
        fn entries(&self, dir: &Path) -> io::Result<Vec<SourceEntry>> {
            Ok(self
                .entries
                .get(&dir.display().to_string())
                .cloned()
                .unwrap_or_default())
        }

        fn read_to_string(&self, path: &Path) -> io::Result<String> {
            self.files
                .get(&path.display().to_string())
                .cloned()
                .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "missing fake file"))
        }
    }

    #[test]
    fn ladder_is_contiguous_and_runtime_assurance_are_not_synthesised() {
        assert_eq!(derive_level(&[]), AssuranceLevel::Unknown);
        let broken = vec![e(EvidenceKind::Definition, 1), e(EvidenceKind::Test, 1)];
        assert_eq!(derive_level(&broken), AssuranceLevel::Defined);
        assert_eq!(
            derive_level(&ladder_to(EvidenceKind::Test)),
            AssuranceLevel::Tested
        );
        assert_eq!(
            derive_level(&ladder_to(EvidenceKind::RuntimeObservation)),
            AssuranceLevel::Observed
        );
        assert_eq!(
            derive_level(&[e(EvidenceKind::ExternalAssurance, 1)]),
            AssuranceLevel::Unknown
        );
    }

    #[test]
    fn state_derivation_handles_not_applicable_gap_and_regression() {
        assert_eq!(
            derive_state(Applicability::Applicable, &[], None),
            ControlState::Unknown
        );
        assert_eq!(
            derive_state(Applicability::Applicable, &[], Some(ControlState::Unknown)),
            ControlState::Gap
        );
        assert_eq!(
            derive_state(
                Applicability::Applicable,
                &[e(EvidenceKind::Definition, 1)],
                Some(ControlState::Tested)
            ),
            ControlState::Regressed
        );
        assert_eq!(
            derive_state(
                Applicability::NotApplicable,
                &ladder_to(EvidenceKind::ExternalAssurance),
                None
            ),
            ControlState::NotApplicable
        );
    }

    #[test]
    fn severity_is_monotone_and_met_controls_have_none() {
        assert_eq!(
            gap_severity(
                ControlState::Defined,
                Criticality::Critical,
                &need_at(ProtectionLevel::VeryHigh)
            ),
            None
        );
        let low = gap_severity(
            ControlState::Unknown,
            Criticality::Routine,
            &ProtectionNeed::default(),
        )
        .unwrap();
        let high = gap_severity(
            ControlState::Gap,
            Criticality::Important,
            &need_at(ProtectionLevel::High),
        )
        .unwrap();
        let critical = gap_severity(
            ControlState::Regressed,
            Criticality::Critical,
            &need_at(ProtectionLevel::VeryHigh),
        )
        .unwrap();
        assert!(low <= high && high <= critical);
        assert_eq!(critical, GapSeverity::Critical);
    }

    #[test]
    fn catalog_is_honest_and_verifies_cleanly() {
        let controls = catalog();
        assert!(controls.len() >= 4);
        for control in &controls {
            assert!(
                control
                    .evidence
                    .iter()
                    .any(|item| item.kind == EvidenceKind::Definition)
            );
            let resolved = control.resolve(None);
            assert!(resolved.level < AssuranceLevel::Observed || control.id == "HRECON-CLOUD");
            if control.applicability != Applicability::Applicable {
                assert!(!control.applicability_reason.trim().is_empty());
            }
        }
        let resolved = resolve_catalog();
        let summary = summarise(&resolved);
        assert_eq!(summary.total, resolved.len());
        assert!(verify(&resolved).ok);
    }

    #[test]
    fn regressions_fail_verification_and_low_first_gaps_only_warn() {
        let regressed = syn(
            "TST-REG",
            Applicability::Applicable,
            Criticality::Routine,
            ProtectionNeed::default(),
            vec![],
        )
        .resolve(Some(ControlState::Defined));
        let verdict = verify(&[regressed]);
        assert!(!verdict.ok);
        assert_eq!(verdict.regressions.len(), 1);

        let warned = syn(
            "TST-LOW",
            Applicability::Applicable,
            Criticality::Routine,
            ProtectionNeed::default(),
            vec![],
        )
        .resolve(None);
        let verdict = verify(&[warned]);
        assert!(verdict.ok);
        assert_eq!(verdict.warnings.len(), 1);
    }

    #[test]
    fn profile_parsing_and_short_names_round_trip() {
        assert_eq!(Profile::parse("core"), Some(Profile::Core));
        assert_eq!(Profile::parse("HRECON-CLOUD"), Some(Profile::Cloud));
        let names = Profile::short_names();
        assert_eq!(names.len(), Profile::all().len());
        for (profile, name) in Profile::all().iter().zip(names.iter()) {
            assert_eq!(Profile::parse(name), Some(*profile));
        }
    }

    #[test]
    fn continuity_state_is_derived_and_summary_counts_named_gaps() {
        let assessed = assess();
        assert!(
            assessed
                .iter()
                .all(|item| item.state == ContinuityState::Tested)
        );
        let summary = summarise_continuity(&assessed);
        assert_eq!(summary.total, assessed.len());
        assert_eq!(summary.tested, assessed.len());
        assert_eq!(summary.untested, 0);
        let mut observed = objectives();
        observed[0].observed = Some(ObservedRecovery {
            recovery_secs: 4,
            data_loss: "none".to_string(),
            source: "incident-42".to_string(),
            recorded_at: 1,
        });
        assert_eq!(observed[0].state(), ContinuityState::Observed);
    }

    #[test]
    fn collect_rust_sources_walks_directories_and_filters_extensions() {
        let tree = FakeSourceTree::default()
            .with_dir(
                "src",
                vec![
                    SourceEntry {
                        path: PathBuf::from("src/lib.rs"),
                        kind: SourceEntryKind::File,
                    },
                    SourceEntry {
                        path: PathBuf::from("src/nested"),
                        kind: SourceEntryKind::Directory,
                    },
                    SourceEntry {
                        path: PathBuf::from("src/notes.txt"),
                        kind: SourceEntryKind::File,
                    },
                ],
            )
            .with_dir(
                "src/nested",
                vec![SourceEntry {
                    path: PathBuf::from("src/nested/mod.rs"),
                    kind: SourceEntryKind::File,
                }],
            )
            .with_file("src/lib.rs", "fn top_level() {}")
            .with_file("src/nested/mod.rs", "fn nested() {}");
        let documents = collect_rust_sources(&tree, &[Path::new("src")]).unwrap();
        assert_eq!(
            documents,
            vec![
                SourceDocument {
                    path: "src/lib.rs".to_string(),
                    body: "fn top_level() {}".to_string(),
                },
                SourceDocument {
                    path: "src/nested/mod.rs".to_string(),
                    body: "fn nested() {}".to_string(),
                },
            ]
        );
    }

    #[test]
    fn missing_recovery_tests_report_named_gaps() {
        let docs = vec![SourceDocument {
            path: "src/ledger.rs".to_string(),
            body: "fn tampered_file_fails_load() {}".to_string(),
        }];
        let missing = missing_recovery_tests(&objectives(), &docs);
        assert_eq!(
            missing,
            vec![
                MissingRecoveryTest {
                    capability: "attack_exports",
                    test_name: "bound_entry_exports_a_well_formed_indicator",
                },
                MissingRecoveryTest {
                    capability: "attack_exports",
                    test_name: "coverage_layer_emits_covered_and_gap_techniques",
                },
            ]
        );
    }

    #[test]
    fn continuity_test_names_exist_in_current_sources() {
        let tree = FsSourceTree;
        let documents =
            collect_rust_sources(&tree, &[Path::new("src"), Path::new("tests")]).unwrap();
        assert!(missing_recovery_tests(&objectives(), &documents).is_empty());
    }
}
