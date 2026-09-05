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
