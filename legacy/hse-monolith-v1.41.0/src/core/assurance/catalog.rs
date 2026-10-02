//! The built-in HSE assurance control catalogue: the canonical mapping of BSI /
//! IT-Grundschutz building blocks onto real HSE capabilities.
//!
//! Honesty contract for this unit: every control is seeded ONLY with evidence
//! that is a verifiable static fact about this repository —
//! - [`Definition`](super::EvidenceKind::Definition): the mapping itself,
//! - [`Implementation`](super::EvidenceKind::Implementation): a real production
//!   path that exists in the tree (cited),
//! - [`Enforcement`](super::EvidenceKind::Enforcement): the CI gate / repo policy
//!   that actually runs it,
//! - [`Test`](super::EvidenceKind::Test): a real test/ratchet name that exercises it.
//!
//! No control is seeded with `RuntimeObservation` (A5) or `ExternalAssurance`
//! (A6): those require actual runtime capture and independent audit, which the
//! wiring / assurance-import units attach later. So the catalogue tops out at
//! `A4 Tested`, and never reports a green it has not earned.

use super::model::{
    Applicability, Evidence, EvidenceKind, Profile, ProtectionDimension as Dim,
    ProtectionLevel as Lvl, ProtectionNeed,
};
use super::{Criticality, GermanControl};

/// `recorded_at` for catalogue-seeded static evidence: `0` marks a **catalogue
/// baseline** fact (the mapping / a cited repo artifact), distinct from a real
/// runtime-observation timestamp, which is always non-zero.
const BASELINE: u64 = 0;

/// Build one static evidence record. `source`/`detail` are compile-time-known
/// non-empty, so the record is always valid.
fn ev(kind: EvidenceKind, source: &str, detail: &str) -> Evidence {
    Evidence {
        kind,
        source: source.to_string(),
        detail: detail.to_string(),
        recorded_at: BASELINE,
    }
}

/// A protection need from a list of elevated dimensions.
fn need(elevated: &[(Dim, Lvl)]) -> ProtectionNeed {
    ProtectionNeed {
        elevated: elevated.to_vec(),
    }
}

/// The authoritative built-in control catalogue. Deterministic and offline — no
/// network, no clock; it is the same on every host so tests can pin it.
#[must_use]
pub fn catalog() -> Vec<GermanControl> {
    vec![
        // ── OPS.1.1.5 Logging ────────────────────────────────────────────────
        GermanControl {
            id: "HSE-OPS-1.1.5-LOG".to_string(),
            framework: "IT-Grundschutz".to_string(),
            framework_version: "Compendium 2023".to_string(),
            module: "OPS.1.1.5".to_string(),
            requirement: "Security-relevant events are logged with the fields needed to \
                          reconstruct what happened."
                .to_string(),
            profile: Profile::Core,
            applicability: Applicability::Applicable,
            applicability_reason: "Every HSE deployment records scan/provider events.".to_string(),
            protection_need: need(&[(Dim::Traceability, Lvl::High), (Dim::Integrity, Lvl::High)]),
            criticality: Criticality::Important,
            evidence: vec![
                ev(
                    EvidenceKind::Definition,
                    "src/core/assurance/catalog.rs",
                    "OPS.1.1.5 mapped to the HSE event bus + telemetry.",
                ),
                ev(
                    EvidenceKind::Implementation,
                    "src/core/event/mod.rs",
                    "Event bus emits structured scan/provider/module events.",
                ),
            ],
        },
        // ── DER.1 Detection of security-relevant events ──────────────────────
        GermanControl {
            id: "HSE-DER-1-DETECT".to_string(),
            framework: "IT-Grundschutz".to_string(),
            framework_version: "Compendium 2023".to_string(),
            module: "DER.1".to_string(),
            requirement: "Security-relevant events are detected from the collected telemetry."
                .to_string(),
            profile: Profile::Intelligence,
            applicability: Applicability::Applicable,
            applicability_reason: "The correlator evaluates deterministic detection rules over \
                                   collected entities/evidence."
                .to_string(),
            protection_need: need(&[(Dim::Integrity, Lvl::High)]),
            criticality: Criticality::Important,
            evidence: vec![
                ev(
                    EvidenceKind::Definition,
                    "src/core/assurance/catalog.rs",
                    "DER.1 mapped to the deterministic correlator (AU-rules).",
                ),
                ev(
                    EvidenceKind::Implementation,
                    "src/core/correlator/mod.rs",
                    "122 deterministic correlation rules over the entity graph.",
                ),
            ],
        },
        // ── CON.8 Software Development ───────────────────────────────────────
        GermanControl {
            id: "HSE-CON-8-DEV".to_string(),
            framework: "IT-Grundschutz".to_string(),
            framework_version: "Compendium 2023".to_string(),
            module: "CON.8".to_string(),
            requirement: "Software is developed under a defined, enforced process with \
                          reproducible checks."
                .to_string(),
            profile: Profile::Development,
            applicability: Applicability::Applicable,
            applicability_reason: "HSE is developed under a gated, falsification-first process."
                .to_string(),
            protection_need: need(&[(Dim::Integrity, Lvl::High)]),
            criticality: Criticality::Critical,
            evidence: vec![
                ev(
                    EvidenceKind::Definition,
                    "RULE.md",
                    "Falsification-first, no-fabrication development doctrine.",
                ),
                ev(
                    EvidenceKind::Implementation,
                    "scripts/gate.sh",
                    "One gate runs fmt, clippy -D warnings, tests, doc coverage, hse-core, wasm-ui.",
                ),
                ev(
                    EvidenceKind::Enforcement,
                    ".github/workflows/ci.yml",
                    "CI runs the gate on every PR; repo policy prohibits red merges.",
                ),
                ev(
                    EvidenceKind::Test,
                    "tests/architecture.rs",
                    "~99 architecture ratchets assert the invariants hold.",
                ),
            ],
        },
        // ── OPS.1.1.6 Software Testing and Release ───────────────────────────
        GermanControl {
            id: "HSE-OPS-1.1.6-TEST".to_string(),
            framework: "IT-Grundschutz".to_string(),
            framework_version: "Compendium 2023".to_string(),
            module: "OPS.1.1.6".to_string(),
            requirement: "Changes are tested and gated before release.".to_string(),
            profile: Profile::Development,
            applicability: Applicability::Applicable,
            applicability_reason: "Every change passes the full gate before merge.".to_string(),
            protection_need: need(&[(Dim::Integrity, Lvl::High)]),
            criticality: Criticality::Critical,
            evidence: vec![
                ev(
                    EvidenceKind::Definition,
                    "src/core/assurance/catalog.rs",
                    "OPS.1.1.6 mapped to the CI test/release gate.",
                ),
                ev(
                    EvidenceKind::Implementation,
                    "scripts/gate.sh",
                    "The release gate: lib + architecture + smoke + doctests + hse-core + wasm-ui.",
                ),
                ev(
                    EvidenceKind::Enforcement,
                    ".github/workflows/ci.yml",
                    "MSRV, aarch64 cross-build, wasm drift and the gate are required checks.",
                ),
                ev(
                    EvidenceKind::Test,
                    "tests/architecture.rs",
                    "Regression ratchets are falsified on the defect before landing.",
                ),
            ],
        },
        // ── APP.1.4 Mobile Applications (Android/Termux no-root) ──────────────
        GermanControl {
            id: "HSE-APP-1.4-MOBILE".to_string(),
            framework: "IT-Grundschutz".to_string(),
            framework_version: "Compendium 2023".to_string(),
            module: "APP.1.4".to_string(),
            requirement: "The mobile application runs with least privilege and no privilege \
                          escalation."
                .to_string(),
            profile: Profile::Android,
            applicability: Applicability::Applicable,
            applicability_reason: "HSE runs in the no-root Termux userland.".to_string(),
            protection_need: need(&[
                (Dim::Confidentiality, Lvl::High),
                (Dim::Integrity, Lvl::High),
            ]),
            criticality: Criticality::Important,
            evidence: vec![
                ev(
                    EvidenceKind::Definition,
                    "CLAUDE.md",
                    "No-root Termux-aarch64 userland is a standing platform contract.",
                ),
                ev(
                    EvidenceKind::Implementation,
                    "install.sh",
                    "Termux install path uses pkg with no sudo; single userland binary.",
                ),
                ev(
                    EvidenceKind::Enforcement,
                    ".github/workflows/ci.yml",
                    "The no-privilege-escalation ratchet runs in the gate on every PR.",
                ),
                ev(
                    EvidenceKind::Test,
                    "tests/architecture.rs::the_binary_never_escalates_privilege",
                    "Asserts the binary never spawns sudo/su/doas/pkexec.",
                ),
            ],
        },
        // ── APP.3.1 Web Applications and Web Services ────────────────────────
        GermanControl {
            id: "HSE-APP-3.1-WEB".to_string(),
            framework: "IT-Grundschutz".to_string(),
            framework_version: "Compendium 2023".to_string(),
            module: "APP.3.1".to_string(),
            requirement: "The web application/service binds safely and authenticates non-local \
                          access."
                .to_string(),
            profile: Profile::Web,
            applicability: Applicability::Applicable,
            applicability_reason: "HSE ships an embedded web UI + HTTP API.".to_string(),
            protection_need: need(&[
                (Dim::Confidentiality, Lvl::High),
                (Dim::Authenticity, Lvl::High),
            ]),
            criticality: Criticality::Important,
            evidence: vec![
                ev(
                    EvidenceKind::Definition,
                    "src/core/assurance/catalog.rs",
                    "APP.3.1 mapped to the loopback-default embedded UI/API.",
                ),
                ev(
                    EvidenceKind::Implementation,
                    "src/api",
                    "HTTP API + embedded SPA; binds 127.0.0.1 by default.",
                ),
            ],
        },
        // ── APP.4.3 Relational Databases ─────────────────────────────────────
        GermanControl {
            id: "HSE-APP-4.3-DB".to_string(),
            framework: "IT-Grundschutz".to_string(),
            framework_version: "Compendium 2023".to_string(),
            module: "APP.4.3".to_string(),
            requirement: "The relational store persists durably and survives interruption."
                .to_string(),
            profile: Profile::Storage,
            applicability: Applicability::Applicable,
            applicability_reason: "HSE persists scans/entities/relations in SQLite (WAL)."
                .to_string(),
            protection_need: need(&[(Dim::Integrity, Lvl::High), (Dim::Availability, Lvl::High)]),
            criticality: Criticality::Critical,
            evidence: vec![
                ev(
                    EvidenceKind::Definition,
                    "src/core/assurance/catalog.rs",
                    "APP.4.3 mapped to the SQLite/WAL storage layer.",
                ),
                ev(
                    EvidenceKind::Implementation,
                    "src/storage",
                    "SQLite-backed canonical store for scans/entities/relations.",
                ),
            ],
        },
        // ── BSI 200-3 Risk analysis ──────────────────────────────────────────
        GermanControl {
            id: "HSE-200-3-RISK".to_string(),
            framework: "BSI 200-3".to_string(),
            framework_version: "1.0".to_string(),
            module: "BSI-200-3".to_string(),
            requirement: "Risk is analysed from evidence-backed factors with preserved provenance."
                .to_string(),
            profile: Profile::Core,
            applicability: Applicability::Applicable,
            applicability_reason: "Risk prioritisation applies across the platform.".to_string(),
            protection_need: need(&[(Dim::Integrity, Lvl::High)]),
            criticality: Criticality::Important,
            // Defined only — the evidence-backed risk engine is a later unit, so
            // this control honestly sits at A1 Defined, not a synthesised green.
            evidence: vec![ev(
                EvidenceKind::Definition,
                "src/core/assurance/catalog.rs",
                "BSI 200-3 risk model mapped; engine implementation pending its own unit.",
            )],
        },
        // ── BSI 200-4 Business Continuity Management ──────────────────────────
        GermanControl {
            id: "HSE-200-4-BCM".to_string(),
            framework: "BSI 200-4".to_string(),
            framework_version: "1.0".to_string(),
            module: "BSI-200-4".to_string(),
            requirement: "Recovery is an executable, tested capability with observed RTO/RPO."
                .to_string(),
            profile: Profile::Core,
            applicability: Applicability::Applicable,
            applicability_reason: "HSE must recover from process death, restart and disk-full."
                .to_string(),
            protection_need: need(&[(Dim::Availability, Lvl::High)]),
            criticality: Criticality::Critical,
            // A4 Tested: the store's recovery behaviour is implemented (WAL +
            // atomic transactions + an on-disk growth cap), enforced (the
            // fault-injection tests run in the gate and CI on every commit) and
            // tested (SQLITE_FULL and crash-mid-write are injected and recovery
            // time / recovery point are asserted). NOT A5: no production runtime
            // observation of a real recovery is recorded, so Observed is not claimed.
            evidence: vec![
                ev(
                    EvidenceKind::Definition,
                    "src/core/assurance/catalog.rs",
                    "BSI 200-4 continuity model mapped: process death, restart and \
                     disk-full are the in-scope faults; RTO/RPO are the measures.",
                ),
                ev(
                    EvidenceKind::Implementation,
                    "src/storage/mod.rs",
                    "SQLite WAL store (synchronous=NORMAL) with atomic multi-statement \
                     transactions that roll back whole on SQLITE_FULL/BUSY, plus an \
                     HSE_SQLITE_MAX_PAGES growth cap (Store::apply_page_cap) that fails \
                     loud instead of filling the device.",
                ),
                ev(
                    EvidenceKind::Enforcement,
                    "scripts/gate.sh + .github/workflows/ci.yml",
                    "The storage fault-injection tests run under `cargo test --all` in \
                     the gate and in CI on every commit; a recovery regression is red.",
                ),
                ev(
                    EvidenceKind::Test,
                    "src/storage/tests.rs",
                    "writes_fail_loudly_at_the_page_cap_keep_committed_data_and_recover_when_raised \
                     (SQLITE_FULL: loud error, committed data intact, integrity ok, \
                     writes resume once the cap is raised) and \
                     a_crash_mid_write_recovers_to_the_last_commit_on_reopen (RPO = last \
                     commit, uncommitted transaction discarded whole, RTO bounded).",
                ),
            ],
        },
        // ── C5 (cloud only) — demonstrates NOT_APPLICABLE on a local profile ──
        GermanControl {
            id: "HSE-C5-CLOUD".to_string(),
            framework: "BSI C5".to_string(),
            framework_version: "2020".to_string(),
            module: "C5".to_string(),
            requirement: "Cloud shared-responsibility controls (host isolation, platform logs, \
                          backups, deletion) are assured for a cloud-hosted deployment."
                .to_string(),
            profile: Profile::Cloud,
            // Not applicable on the default local/Termux profile — and this is
            // NOT a failure: it must not dock overall maturity.
            applicability: Applicability::NotApplicable,
            applicability_reason: "Default deployment is local Termux/Android with no cloud \
                                   hosting provider; C5 applies only to a cloud-hosted profile."
                .to_string(),
            protection_need: ProtectionNeed::default(),
            criticality: Criticality::Routine,
            evidence: vec![ev(
                EvidenceKind::Definition,
                "src/core/assurance/catalog.rs",
                "C5 mapped as conditional on a cloud deployment profile.",
            )],
        },
    ]
}
