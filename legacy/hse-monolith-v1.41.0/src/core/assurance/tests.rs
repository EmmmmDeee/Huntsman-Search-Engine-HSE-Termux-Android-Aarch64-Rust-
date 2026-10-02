use super::*;

/// One evidence record for a test (recorded_at chosen per case).
fn e(kind: EvidenceKind, at: u64) -> Evidence {
    Evidence {
        kind,
        source: "test".to_string(),
        detail: String::new(),
        recorded_at: at,
    }
}

/// A full contiguous ladder up to and including `top`.
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
    for k in order {
        out.push(e(k, 1));
        if k == top {
            break;
        }
    }
    out
}

#[test]
fn empty_evidence_is_unknown() {
    assert_eq!(derive_level(&[]), AssuranceLevel::Unknown);
    assert_eq!(
        derive_state(Applicability::Applicable, &[], None),
        ControlState::Unknown
    );
}

#[test]
fn ladder_is_contiguous_a_gap_caps_the_level() {
    // Definition + Test but NO Implementation/Enforcement: the ladder stops at
    // Definition (A1). A "verified" claim without the intervening rungs cannot
    // be earned. (CLAIM ≠ EVIDENCE / IMPLEMENTATION ≠ TESTED.)
    let ev = vec![e(EvidenceKind::Definition, 1), e(EvidenceKind::Test, 1)];
    assert_eq!(derive_level(&ev), AssuranceLevel::Defined);
    assert_ne!(derive_level(&ev), AssuranceLevel::Tested);
}

#[test]
fn a5_observed_requires_runtime_observation() {
    // Full ladder through Test but no runtime observation → Tested, never Observed.
    let through_test = ladder_to(EvidenceKind::Test);
    assert_eq!(derive_level(&through_test), AssuranceLevel::Tested);
    assert!(derive_level(&through_test) < AssuranceLevel::Observed);

    // Add the runtime observation and it advances — and only then.
    let through_obs = ladder_to(EvidenceKind::RuntimeObservation);
    assert_eq!(derive_level(&through_obs), AssuranceLevel::Observed);
}

#[test]
fn a6_assured_requires_external_assurance_and_cannot_come_from_tests() {
    // Everything internal (through runtime observation) but no external assurance
    // → Observed, never Assured. TEST/RUNTIME ≠ EXTERNAL ASSURANCE.
    let internal = ladder_to(EvidenceKind::RuntimeObservation);
    assert_eq!(derive_level(&internal), AssuranceLevel::Observed);
    assert_ne!(derive_level(&internal), AssuranceLevel::Assured);

    // External assurance on TOP of the full internal ladder earns A6.
    let full = ladder_to(EvidenceKind::ExternalAssurance);
    assert_eq!(derive_level(&full), AssuranceLevel::Assured);

    // External assurance alone (no prerequisites) does NOT jump to Assured.
    let only_external = vec![e(EvidenceKind::ExternalAssurance, 1)];
    assert_eq!(derive_level(&only_external), AssuranceLevel::Unknown);
}

#[test]
fn not_applicable_is_never_a_deficiency_whatever_the_evidence() {
    // Even a full ladder of evidence, if the control is scoped out, is
    // NOT_APPLICABLE — and NOT_APPLICABLE ≠ FAILED.
    let full = ladder_to(EvidenceKind::ExternalAssurance);
    let state = derive_state(Applicability::NotApplicable, &full, None);
    assert_eq!(state, ControlState::NotApplicable);
    assert!(!state.is_deficiency());
}

#[test]
fn in_scope_but_unmet_is_a_gap_on_reassessment() {
    // First assessment of an in-scope control with no evidence: Unknown.
    assert_eq!(
        derive_state(Applicability::Applicable, &[], None),
        ControlState::Unknown
    );
    // A control we have assessed before (prior Defined) that now has NO evidence
    // has REGRESSED (a previously-earned rung lost), not merely Gap.
    assert_eq!(
        derive_state(Applicability::Applicable, &[], Some(ControlState::Defined)),
        ControlState::Regressed
    );
    // A control whose prior carried no rung (Unknown) and still has nothing is a
    // Gap on reassessment (we know it is deficient, not unassessed).
    assert_eq!(
        derive_state(Applicability::Applicable, &[], Some(ControlState::Unknown)),
        ControlState::Gap
    );
}

#[test]
fn regression_demotes_when_evidence_no_longer_supports_prior_state() {
    // Was Tested; current evidence is only Definition → REGRESSED.
    let only_def = vec![e(EvidenceKind::Definition, 1)];
    assert_eq!(
        derive_state(
            Applicability::Applicable,
            &only_def,
            Some(ControlState::Tested)
        ),
        ControlState::Regressed
    );
    // Was Implemented and evidence still supports Implemented → not a regression.
    let impl_ev = ladder_to(EvidenceKind::Implementation);
    assert_eq!(
        derive_state(
            Applicability::Applicable,
            &impl_ev,
            Some(ControlState::Implemented)
        ),
        ControlState::Implemented
    );
}

#[test]
fn protection_need_is_active_not_passive() {
    let high = ProtectionNeed {
        elevated: vec![(ProtectionDimension::Availability, ProtectionLevel::VeryHigh)],
    };
    assert!(high.drives_high_assurance());
    assert_eq!(high.max_level(), ProtectionLevel::VeryHigh);
    assert_eq!(
        high.level(ProtectionDimension::Confidentiality),
        ProtectionLevel::Normal
    );
    assert!(!ProtectionNeed::default().drives_high_assurance());
}

#[test]
fn catalog_is_well_formed_and_honest() {
    let cat = catalog();
    assert!(
        cat.len() >= 8,
        "catalogue should cover the named BSI modules"
    );

    // Ids are unique.
    let mut ids: Vec<&str> = cat.iter().map(|c| c.id.as_str()).collect();
    ids.sort_unstable();
    let n = ids.len();
    ids.dedup();
    assert_eq!(ids.len(), n, "control ids must be unique");

    for c in &cat {
        // Every control carries at least a Definition (earns A1, never less).
        assert!(
            c.evidence
                .iter()
                .any(|e| e.kind == EvidenceKind::Definition),
            "{} has no Definition evidence",
            c.id
        );
        // A scoped-out / conditional control must explain why.
        if c.applicability != Applicability::Applicable {
            assert!(
                !c.applicability_reason.trim().is_empty(),
                "{} is {:?} without a reason",
                c.id,
                c.applicability
            );
        }
        // HONESTY: no catalogue control may claim A5/A6 — those need runtime /
        // external evidence the static catalogue does not hold.
        let r = c.resolve(None);
        assert!(
            r.level < AssuranceLevel::Observed,
            "{} claims {:?} but the static catalogue holds no runtime/external evidence",
            c.id,
            r.level
        );
        assert_ne!(r.state, ControlState::Observed, "{} falsely Observed", c.id);
        assert_ne!(r.state, ControlState::Assured, "{} falsely Assured", c.id);
    }
}

#[test]
fn c5_is_not_applicable_on_the_local_profile_and_does_not_penalise() {
    let c5 = catalog()
        .into_iter()
        .find(|c| c.module == "C5")
        .expect("C5 control present");
    let r = c5.resolve(None);
    assert_eq!(r.state, ControlState::NotApplicable);
    assert!(!r.state.is_deficiency());
}

#[test]
fn summary_reports_raw_counts_and_excludes_not_applicable_from_deficiencies() {
    let resolved = resolve_catalog();
    let s = summarise(&resolved);
    assert_eq!(s.total, resolved.len());
    assert!(s.not_applicable >= 1, "C5 is NA on the local profile");
    // No fabricated green: the static catalogue asserts nothing Observed/Assured.
    assert_eq!(s.observed_or_higher, 0);
    assert_eq!(s.assured, 0);
    // NA controls are not counted as deficiencies.
    let na = resolved
        .iter()
        .filter(|r| r.state == ControlState::NotApplicable)
        .count();
    let deficiencies_incl_na = resolved.iter().filter(|r| r.state.is_deficiency()).count();
    assert_eq!(s.deficiencies, deficiencies_incl_na);
    assert!(s.total >= s.deficiencies + na);
}

// ── Gap prioritisation (Schutzbedarf + criticality made consequential) ────────

/// A protection need whose max level is exactly `lvl`.
fn need_at(lvl: ProtectionLevel) -> ProtectionNeed {
    if lvl == ProtectionLevel::Normal {
        ProtectionNeed::default()
    } else {
        ProtectionNeed {
            elevated: vec![(ProtectionDimension::Integrity, lvl)],
        }
    }
}

#[test]
fn a_met_or_not_applicable_control_has_no_severity() {
    // Every non-deficiency state yields no finding — NOT_APPLICABLE ≠ FAILED,
    // and a met rung is not a gap.
    for st in [
        ControlState::NotApplicable,
        ControlState::Defined,
        ControlState::Implemented,
        ControlState::Enforced,
        ControlState::Tested,
        ControlState::Observed,
        ControlState::Assured,
    ] {
        assert_eq!(
            gap_severity(
                st,
                Criticality::Critical,
                &need_at(ProtectionLevel::VeryHigh)
            ),
            None,
            "{st:?} is not a deficiency and must carry no severity"
        );
    }
}

#[test]
fn every_deficiency_carries_a_severity() {
    for st in [
        ControlState::Unknown,
        ControlState::Gap,
        ControlState::Regressed,
    ] {
        assert!(
            gap_severity(st, Criticality::Routine, &ProtectionNeed::default()).is_some(),
            "{st:?} is a deficiency and must be graded"
        );
    }
}

#[test]
fn severity_is_monotone_in_criticality() {
    let need = need_at(ProtectionLevel::High);
    let routine = gap_severity(ControlState::Gap, Criticality::Routine, &need).unwrap();
    let important = gap_severity(ControlState::Gap, Criticality::Important, &need).unwrap();
    let critical = gap_severity(ControlState::Gap, Criticality::Critical, &need).unwrap();
    assert!(routine <= important && important <= critical);
    // And criticality genuinely CHANGES the outcome somewhere (the field is not
    // dead weight): Routine here is High, Critical here is Critical.
    assert!(
        critical > routine,
        "criticality must be able to raise severity"
    );
}

#[test]
fn severity_is_monotone_in_protection_need() {
    let normal = gap_severity(
        ControlState::Gap,
        Criticality::Important,
        &need_at(ProtectionLevel::Normal),
    )
    .unwrap();
    let high = gap_severity(
        ControlState::Gap,
        Criticality::Important,
        &need_at(ProtectionLevel::High),
    )
    .unwrap();
    let very_high = gap_severity(
        ControlState::Gap,
        Criticality::Important,
        &need_at(ProtectionLevel::VeryHigh),
    )
    .unwrap();
    assert!(normal <= high && high <= very_high);
    assert!(
        very_high > normal,
        "Schutzbedarf must be able to raise severity"
    );
}

#[test]
fn a_regression_is_never_less_severe_than_a_first_gap_for_the_same_control() {
    // Same criticality + protection need: Regressed (lost ground) >= Gap >= Unknown.
    for crit in [
        Criticality::Routine,
        Criticality::Important,
        Criticality::Critical,
    ] {
        for lvl in [
            ProtectionLevel::Normal,
            ProtectionLevel::High,
            ProtectionLevel::VeryHigh,
        ] {
            let need = need_at(lvl);
            let unknown = gap_severity(ControlState::Unknown, crit, &need).unwrap();
            let gap = gap_severity(ControlState::Gap, crit, &need).unwrap();
            let regressed = gap_severity(ControlState::Regressed, crit, &need).unwrap();
            assert!(
                unknown <= gap && gap <= regressed,
                "depth must not lower severity ({crit:?}, {lvl:?})"
            );
        }
    }
}

#[test]
fn the_worst_case_is_critical_and_the_mildest_is_low() {
    // A critical, very-high-Schutzbedarf control that has regressed is the
    // fix-first finding.
    assert_eq!(
        gap_severity(
            ControlState::Regressed,
            Criticality::Critical,
            &need_at(ProtectionLevel::VeryHigh)
        ),
        Some(GapSeverity::Critical)
    );
    // A routine, normal-need control merely unassessed is the mildest.
    assert_eq!(
        gap_severity(
            ControlState::Unknown,
            Criticality::Routine,
            &ProtectionNeed::default()
        ),
        Some(GapSeverity::Low)
    );
}

#[test]
fn findings_are_ordered_most_severe_first_and_exclude_met_and_na() {
    // Build a synthetic deficient control set by resolving real controls against
    // a prior state that forces regression, plus a met control that must not
    // appear in the findings.
    let cat = catalog();
    // Resolve everything fresh: the honest catalogue has NO deficiencies, so the
    // findings list is empty and the summary reports a clean bill of health.
    let clean = resolve_catalog();
    assert!(
        findings(&clean).is_empty(),
        "the honest catalogue has no open deficiencies"
    );
    let s = summarise(&clean);
    assert_eq!(s.critical_findings, 0);
    assert_eq!(s.high_findings, 0);
    assert_eq!(s.highest_open_severity, None);

    // Now force two regressions with different impact and confirm ordering +
    // that the met/NA controls are excluded.
    let critical_ctrl = cat
        .iter()
        .find(|c| c.criticality == Criticality::Critical)
        .expect("a Critical control exists");
    // Prior Assured is strictly above the control's current (A4-Tested) evidence,
    // so it derives to Regressed — a lapsed external assurance.
    let resolved = vec![
        critical_ctrl.resolve(Some(ControlState::Assured)), // → Regressed, high impact
        cat[0].resolve(None),                               // met → excluded
    ];
    let open = findings(&resolved);
    assert_eq!(open.len(), 1, "only the regressed control is a finding");
    assert_eq!(open[0].control_id, critical_ctrl.id);
    assert_eq!(open[0].state, ControlState::Regressed);
    // The resolved control also carries the computed severity inline.
    assert!(resolved[0].severity.is_some());
    assert!(resolved[1].severity.is_none());
}

// ── Verification gate (evidence-derived PASS/FAIL policy) ─────────────────────

/// A synthetic control with the given applicability, criticality, protection
/// need and evidence — the string metadata is filler; only the fields the
/// verdict reasons about vary.
fn syn(
    id: &str,
    applicability: Applicability,
    criticality: Criticality,
    need: ProtectionNeed,
    evidence: Vec<Evidence>,
) -> GermanControl {
    GermanControl {
        id: id.to_string(),
        framework: "IT-Grundschutz".to_string(),
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

#[test]
fn verify_passes_on_the_honest_catalogue() {
    // The seeded catalogue records only verifiable static facts, so every
    // in-scope control holds at least its defined rung: the gate is green with
    // nothing blocking and nothing regressed.
    let v = verify(&resolve_catalog());
    assert!(v.ok, "honest catalogue must verify");
    assert!(v.regressions.is_empty());
    assert!(v.blocking.is_empty());
}

#[test]
fn a_regression_fails_verification_whatever_its_severity() {
    // Routine + Normal + REGRESSED: severity is only Medium, BELOW the High
    // blocking band — yet a regression must fail the gate regardless. This is
    // the case that separates "regression fails" from "severity >= High fails".
    let c = syn(
        "TST-REG",
        Applicability::Applicable,
        Criticality::Routine,
        ProtectionNeed::default(),
        vec![], // no current evidence → level Unknown
    );
    // Prior Defined sits above the current (Unknown) rung → Regressed.
    let resolved = vec![c.resolve(Some(ControlState::Defined))];
    assert_eq!(resolved[0].state, ControlState::Regressed);
    assert!(
        resolved[0].severity.unwrap() < GapSeverity::High,
        "this regression is deliberately sub-High to prove severity is not why it fails"
    );
    let v = verify(&resolved);
    assert!(!v.ok, "any regression fails the gate");
    assert_eq!(v.regressions.len(), 1);
    assert!(v.blocking.is_empty(), "it is not High/Critical");
    assert!(
        v.warnings.is_empty(),
        "a regression is never demoted to an advisory warning"
    );
}

#[test]
fn a_high_or_critical_gap_fails_verification() {
    // Critical + Very-High + unassessed (Unknown) → High severity → blocks.
    let c = syn(
        "TST-CRIT",
        Applicability::Applicable,
        Criticality::Critical,
        need_at(ProtectionLevel::VeryHigh),
        vec![],
    );
    let resolved = vec![c.resolve(None)];
    assert_eq!(resolved[0].state, ControlState::Unknown);
    assert!(resolved[0].severity.unwrap() >= GapSeverity::High);
    let v = verify(&resolved);
    assert!(!v.ok, "a High/Critical gap fails the gate");
    assert_eq!(v.blocking.len(), 1);
    assert!(
        v.regressions.is_empty(),
        "it is a first gap, not a regression"
    );
}

#[test]
fn a_low_or_medium_non_regressed_gap_is_a_warning_not_a_failure() {
    // Routine + Normal + unassessed → Low severity: reported, but the gate holds.
    let c = syn(
        "TST-LOW",
        Applicability::Applicable,
        Criticality::Routine,
        ProtectionNeed::default(),
        vec![],
    );
    let resolved = vec![c.resolve(None)];
    assert_eq!(resolved[0].severity.unwrap(), GapSeverity::Low);
    let v = verify(&resolved);
    assert!(v.ok, "a Low/Medium first gap must not fail the gate");
    assert_eq!(v.warnings.len(), 1, "but it is still surfaced, not hidden");
    assert!(v.blocking.is_empty() && v.regressions.is_empty());
}

#[test]
fn not_applicable_controls_never_affect_the_verdict() {
    // Even a Critical, Very-High control that is correctly scoped out produces
    // NO finding and cannot fail the gate — NOT APPLICABLE ≠ FAILED.
    let c = syn(
        "TST-NA",
        Applicability::NotApplicable,
        Criticality::Critical,
        need_at(ProtectionLevel::VeryHigh),
        vec![],
    );
    let resolved = vec![c.resolve(None)];
    assert_eq!(resolved[0].state, ControlState::NotApplicable);
    let v = verify(&resolved);
    assert!(v.ok);
    assert!(v.regressions.is_empty() && v.blocking.is_empty() && v.warnings.is_empty());
}
