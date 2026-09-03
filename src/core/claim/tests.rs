//! Acceptance tests for the assertion layer.
//!
//! Each test in the first block pins ONE named invariant from the operational
//! contract and is named for it, so a change that breaks the doctrine has to
//! delete a test that states, in words, why it must not.

use super::*;

fn observed(provider: &str) -> Support {
    Support::For(Provenance::Observed(SourceLineage::provider(provider)))
}

fn observed_corpus(provider: &str, corpus: &str) -> Support {
    Support::For(Provenance::Observed(SourceLineage::corpus(
        provider, corpus,
    )))
}

fn identity_claim() -> Claim {
    Claim::new(
        "c1",
        ClaimKind::IdentityLink {
            left_uid: "uid-a".into(),
            right_uid: "uid-b".into(),
        },
    )
}

// ── The named invariants ────────────────────────────────────────────────────

#[test]
fn entity_claim_evidence_inference_are_not_interchangeable() {
    // An INFERENCE may support a claim but is never a witness to it: a
    // conclusion derived from the graph cannot corroborate the graph. Without
    // this, one observation plus two derivation rules reads as three sources.
    let mut c = identity_claim();
    let t = PromotionThresholds::default();
    c.add_support(observed("asic_director"), t);
    c.add_support(
        Support::For(Provenance::Inferred {
            rule_id: "AU-108".into(),
        }),
        t,
    );
    c.add_support(
        Support::For(Provenance::Inferred {
            rule_id: "AU-061".into(),
        }),
        t,
    );
    assert_eq!(
        c.independent_lineages(),
        1,
        "two inferences over one observation are still one witness"
    );
    assert_eq!(c.state, ClaimState::Supported);
    assert!(!c.state.is_actionable(), "one witness is not actionable");
}

#[test]
fn source_count_is_not_source_independence() {
    // Three providers reselling ONE breach corpus are one witness. Counting
    // provider names would call this corroboration and promote the claim.
    let mut c = identity_claim();
    let t = PromotionThresholds::default();
    for p in ["see_know", "dehashed", "comb_search"] {
        c.add_support(observed_corpus(p, "linkedin-2021"), t);
    }
    assert_eq!(c.support.len(), 3, "three records were observed");
    assert_eq!(
        c.independent_lineages(),
        1,
        "but they trace to one corpus, so one witness"
    );
    assert_eq!(c.state, ClaimState::Supported);

    // A genuinely separate corpus is a second witness and does corroborate.
    c.add_support(observed_corpus("asic_director", "ASIC-companies-2024Q1"), t);
    assert_eq!(c.independent_lineages(), 2);
    assert_eq!(c.state, ClaimState::Corroborated);
}

#[test]
fn the_same_filing_mirrored_twice_is_one_witness_but_two_jurisdictions_are_two() {
    let t = PromotionThresholds::default();
    // Same corpus, mirrored by two providers, no jurisdiction on either.
    let mut mirrored = identity_claim();
    mirrored.add_support(observed_corpus("a", "reg-2020"), t);
    mirrored.add_support(observed_corpus("b", "reg-2020"), t);
    assert_eq!(mirrored.independent_lineages(), 1);

    // The same register filed in two jurisdictions really is two filings.
    let mut cross = identity_claim();
    cross.add_support(
        Support::For(Provenance::Observed(
            SourceLineage::corpus("a", "reg-2020").in_jurisdiction("AU"),
        )),
        t,
    );
    cross.add_support(
        Support::For(Provenance::Observed(
            SourceLineage::corpus("b", "reg-2020").in_jurisdiction("SG"),
        )),
        t,
    );
    assert_eq!(cross.independent_lineages(), 2);
}

#[test]
fn identifier_match_is_not_entity_identity() {
    // A matching identifier produces a CLAIM to be corroborated, never a merge.
    // The claim starts hypothesised: proposing it is not evidence for it.
    let c = identity_claim();
    assert!(matches!(c.kind, ClaimKind::IdentityLink { .. }));
    assert_eq!(c.state, ClaimState::Hypothesised);
    assert!(
        !c.state.is_actionable(),
        "a bare identifier match must never be assertable as identity"
    );
    assert!(
        c.may_expand(),
        "but it IS eligible for expansion — that is how it gets corroborated"
    );
}

#[test]
fn absence_of_easy_evidence_is_not_absence_of_a_nexus() {
    // Every lookup either was never attempted or failed. The claim must stay
    // hypothesised — NOT refuted, and not silently "clean".
    let mut c = identity_claim();
    let t = PromotionThresholds::default();
    c.add_support(
        Support::Unattempted {
            provider: "oathnet".into(),
            reason: "no credential configured".into(),
        },
        t,
    );
    c.add_support(
        Support::Failed {
            provider: "see_know".into(),
            reason: "HTTP 429 rate limited".into(),
        },
        t,
    );
    c.add_support(
        Support::Failed {
            provider: "asic_director".into(),
            reason: "transport reset mid-body".into(),
        },
        t,
    );
    assert_eq!(
        c.state,
        ClaimState::Hypothesised,
        "a search that never answered is not a finding of absence"
    );
    assert_eq!(c.independent_lineages(), 0);
    assert_ne!(c.state, ClaimState::Refuted);
    assert_eq!(
        c.unresolved_gaps(),
        vec!["oathnet", "see_know", "asic_director"],
        "the gaps are surfaced so an incomplete search is never read as exhaustive"
    );
    assert!(c.may_expand(), "and the claim stays eligible for expansion");
}

#[test]
fn hard_target_is_not_a_lower_standard() {
    // The promotion bar is identical at every difficulty; only the BUDGET moves.
    let routine = PromotionThresholds::for_difficulty(TargetDifficulty::Routine);
    let sparse = PromotionThresholds::for_difficulty(TargetDifficulty::Sparse);
    let adversarial = PromotionThresholds::for_difficulty(TargetDifficulty::Adversarial);
    assert_eq!(routine, sparse);
    assert_eq!(sparse, adversarial);
    assert_eq!(adversarial, PromotionThresholds::default());

    // Effort, by contrast, must rise with difficulty — a hard target earns MORE
    // recursion, never a cheaper conclusion.
    let b_routine = ExpansionBudget::for_difficulty(100, 4, TargetDifficulty::Routine);
    let b_hard = ExpansionBudget::for_difficulty(100, 4, TargetDifficulty::Adversarial);
    assert!(
        b_hard.remaining > b_routine.remaining,
        "a hard target must get a larger budget, not a lower bar"
    );

    // And the same evidence yields the same state regardless of difficulty.
    let mut easy = identity_claim();
    let mut hard = identity_claim();
    easy.add_support(observed("p1"), routine);
    hard.add_support(observed("p1"), adversarial);
    assert_eq!(easy.state, hard.state);
    assert_eq!(hard.state, ClaimState::Supported);
}

#[test]
fn explore_aggressively_but_promote_conservatively() {
    // Eligibility is broad; conclusion is narrow. A claim with nothing but a
    // failed lookup is still expandable, and still not actionable.
    let mut c = identity_claim();
    let t = PromotionThresholds::default();
    c.add_support(
        Support::Failed {
            provider: "x".into(),
            reason: "timeout".into(),
        },
        t,
    );
    assert!(c.may_expand());
    assert!(!c.state.is_actionable());

    // Two independent witnesses corroborate but still do not "establish":
    // establishment needs evidence that discriminates it from its rivals.
    c.add_support(observed_corpus("p1", "corpus-1"), t);
    c.add_support(observed_corpus("p2", "corpus-2"), t);
    assert_eq!(c.state, ClaimState::Corroborated);
    assert!(c.state.is_actionable());

    c.add_discriminator(
        Provenance::Observed(SourceLineage::corpus("p3", "corpus-3")),
        t,
    );
    assert_eq!(c.state, ClaimState::Established);
}

#[test]
fn every_node_is_eligible_for_expansion_but_not_every_node_must_be_expanded() {
    // may_expand answers ELIGIBILITY only, and admits states a scheduler would
    // rank last: hypothesised, contested, corroborated alike.
    let t = PromotionThresholds::default();
    for state in [
        ClaimState::Hypothesised,
        ClaimState::Supported,
        ClaimState::Corroborated,
        ClaimState::Established,
        ClaimState::Contested,
    ] {
        let mut c = identity_claim();
        c.state = state;
        assert!(c.may_expand(), "{state:?} must remain eligible");
    }
    // Only terminal states are closed.
    for state in [ClaimState::Refuted, ClaimState::Withdrawn] {
        let mut c = identity_claim();
        c.state = state;
        assert!(!c.may_expand(), "{state:?} is terminal");
    }
    let _ = t;
}

#[test]
fn expand_broadly_is_not_conclude_broadly() {
    // The two gates are genuinely different predicates: everything expandable
    // is not thereby assertable.
    let mut c = identity_claim();
    c.add_support(observed("only-one"), PromotionThresholds::default());
    assert!(c.may_expand(), "expansion is broad");
    assert!(
        !c.state.is_actionable(),
        "conclusion is narrow — one witness concludes nothing"
    );
}

// ── Contradiction preservation ──────────────────────────────────────────────

#[test]
fn conflicting_values_are_preserved_not_overwritten() {
    let mut c = Claim::new(
        "dob",
        ClaimKind::Attribute {
            entity_uid: "uid-a".into(),
            aspect: "dob".into(),
        },
    );
    let t = PromotionThresholds::default();
    c.add_support(observed_corpus("p1", "corpus-1"), t);
    c.add_support(observed_corpus("p2", "corpus-2"), t);
    assert_eq!(c.state, ClaimState::Corroborated);

    let mut conflict = Contradiction::new(
        "dob",
        ("1974-03-02", SourceLineage::corpus("p1", "corpus-1")),
        ("1974-08-19", SourceLineage::corpus("p2", "corpus-2")),
    );
    conflict.add_discriminator("passport MRZ or a birth-register extract");
    c.add_contradiction(conflict, t);

    assert_eq!(
        c.state,
        ClaimState::Contested,
        "a conflict contests the claim even though both sides are corroborated"
    );
    assert!(
        !c.state.is_actionable(),
        "contested is not assertable as fact"
    );
    // BOTH values survive — nothing was collapsed to a winner.
    let vals: Vec<&String> = c.contradictions[0].values.keys().collect();
    assert_eq!(vals, vec!["1974-03-02", "1974-08-19"]);
    assert_eq!(c.contradictions[0].discriminators.len(), 1);
}

#[test]
fn weight_of_numbers_never_resolves_a_contradiction() {
    let mut conflict = Contradiction::new(
        "address",
        ("10 Alpha St", SourceLineage::corpus("p1", "c1")),
        ("22 Beta Rd", SourceLineage::corpus("p2", "c2")),
    );
    for p in ["p3", "p4", "p5"] {
        conflict.add_assertion("10 Alpha St", SourceLineage::corpus(p, p));
    }
    assert!(
        conflict.is_unresolved(),
        "4-to-1 is still a contradiction, not a resolution"
    );

    // Only an explicit, discriminating resolution closes it — and only to a
    // value some source actually asserted.
    assert!(conflict.resolve_to("99 Invented Ave").is_err());
    assert!(conflict.is_unresolved());
    conflict.resolve_to("10 Alpha St").expect("asserted value");
    assert!(!conflict.is_unresolved());
    assert_eq!(
        conflict.values.len(),
        2,
        "the historical disagreement is retained after resolution"
    );
}

#[test]
fn a_resolved_contradiction_stops_contesting_the_claim() {
    let mut c = identity_claim();
    let t = PromotionThresholds::default();
    c.add_support(observed_corpus("p1", "c1"), t);
    c.add_support(observed_corpus("p2", "c2"), t);
    let conflict = Contradiction::new(
        "dob",
        ("a", SourceLineage::corpus("p1", "c1")),
        ("b", SourceLineage::corpus("p2", "c2")),
    );
    c.add_contradiction(conflict, t);
    assert_eq!(c.state, ClaimState::Contested);

    c.contradictions[0].resolve_to("a").expect("asserted");
    c.recompute_state(t);
    assert_eq!(c.state, ClaimState::Corroborated);
}

// ── Claim-state transitions ─────────────────────────────────────────────────

#[test]
fn opposing_observation_contests_rather_than_refutes_when_support_exists() {
    let mut c = identity_claim();
    let t = PromotionThresholds::default();
    c.add_support(observed_corpus("p1", "c1"), t);
    c.add_support(
        Support::Against(Provenance::Observed(SourceLineage::corpus("p2", "c2"))),
        t,
    );
    assert_eq!(
        c.state,
        ClaimState::Contested,
        "evidence both ways is a conflict to preserve, not a refutation"
    );
}

#[test]
fn opposing_observation_with_no_support_refutes() {
    let mut c = identity_claim();
    let t = PromotionThresholds::default();
    c.add_support(
        Support::Against(Provenance::Observed(SourceLineage::corpus("p2", "c2"))),
        t,
    );
    assert_eq!(c.state, ClaimState::Refuted);
    assert!(!c.may_expand(), "refuted is terminal");
}

#[test]
fn withdrawal_is_terminal_and_survives_recompute() {
    let mut c = identity_claim();
    let t = PromotionThresholds::default();
    c.add_support(observed_corpus("p1", "c1"), t);
    c.add_support(observed_corpus("p2", "c2"), t);
    assert_eq!(c.state, ClaimState::Corroborated);
    c.withdraw();
    c.recompute_state(t);
    assert_eq!(
        c.state,
        ClaimState::Withdrawn,
        "a retracted source cannot be re-scored back into belief"
    );
}

#[test]
fn state_is_independent_of_the_order_evidence_arrived() {
    let t = PromotionThresholds::default();
    let supports = [
        observed_corpus("p1", "c1"),
        observed_corpus("p2", "c2"),
        Support::Failed {
            provider: "p3".into(),
            reason: "timeout".into(),
        },
    ];
    let mut forward = identity_claim();
    for s in supports.iter().cloned() {
        forward.add_support(s, t);
    }
    let mut reverse = identity_claim();
    for s in supports.iter().rev().cloned() {
        reverse.add_support(s, t);
    }
    assert_eq!(forward.state, reverse.state);
    assert_eq!(
        forward.independent_lineages(),
        reverse.independent_lineages()
    );
}

// ── Temporal validity ───────────────────────────────────────────────────────

#[test]
fn a_bounded_historical_claim_is_not_false_it_is_bounded() {
    let v = Validity {
        from: Some(1_000),
        until: Some(2_000),
    };
    assert!(v.holds_at(1_500));
    assert!(!v.holds_at(2_500), "outside the period it does not hold");
    assert!(!v.holds_at(500));

    // An unknown period holds — the evidence simply does not bound it, and
    // inventing a bound would be a fabricated finding.
    let unknown = Validity::default();
    assert!(unknown.holds_at(0) && unknown.holds_at(u64::MAX));
}

#[test]
fn concurrent_and_sequential_tenure_are_different_claims() {
    let a = Validity {
        from: Some(100),
        until: Some(200),
    };
    let overlapping = Validity {
        from: Some(150),
        until: Some(250),
    };
    let sequential = Validity {
        from: Some(200),
        until: Some(300),
    };
    assert!(
        a.overlaps(&overlapping),
        "both directors at the same time is a materially different claim"
    );
    assert!(
        !a.overlaps(&sequential),
        "abutting periods do not overlap — one ends as the other begins"
    );
    assert!(
        a.overlaps(&Validity::default()),
        "an unbounded period overlaps"
    );
}

// ── Competing hypotheses ────────────────────────────────────────────────────

#[test]
fn a_hypothesis_set_stays_open_while_rivals_survive() {
    let h = CompetingHypotheses::new(
        "who controls ACME Pty Ltd?",
        vec!["h-subject".into(), "h-namesake".into(), "h-nominee".into()],
    );
    let mut states = BTreeMap::new();
    states.insert("h-subject".to_string(), ClaimState::Corroborated);
    states.insert("h-namesake".to_string(), ClaimState::Supported);
    states.insert("h-nominee".to_string(), ClaimState::Hypothesised);
    assert!(h.is_open(&states), "three live alternatives: still open");

    states.insert("h-namesake".to_string(), ClaimState::Refuted);
    states.insert("h-nominee".to_string(), ClaimState::Refuted);
    assert!(!h.is_open(&states), "one survivor: closed");
}

#[test]
fn premature_closure_is_refused_when_rivals_were_merely_never_investigated() {
    // One alternative is corroborated; the others are untouched (hypothesised).
    // That is NOT a conclusion — it is an unfinished investigation.
    let h = CompetingHypotheses::new("q", vec!["a".into(), "b".into(), "c".into()]);
    let t = PromotionThresholds::default();
    let mut claims = BTreeMap::new();
    let mut a = Claim::new(
        "a",
        ClaimKind::Attribute {
            entity_uid: "u".into(),
            aspect: "x".into(),
        },
    );
    a.add_support(observed_corpus("p1", "c1"), t);
    a.add_support(observed_corpus("p2", "c2"), t);
    claims.insert("a".to_string(), a);
    claims.insert(
        "b".to_string(),
        Claim::new(
            "b",
            ClaimKind::Attribute {
                entity_uid: "u".into(),
                aspect: "x".into(),
            },
        ),
    );
    claims.insert(
        "c".to_string(),
        Claim::new(
            "c",
            ClaimKind::Attribute {
                entity_uid: "u".into(),
                aspect: "x".into(),
            },
        ),
    );
    assert_eq!(
        h.concluded(&claims),
        None,
        "two uninvestigated rivals still stand — concluding here is premature closure"
    );

    // Refute the rivals on evidence, and give the survivor a discriminator.
    for id in ["b", "c"] {
        let claim = claims.get_mut(id).expect("present");
        claim.add_support(
            Support::Against(Provenance::Observed(SourceLineage::corpus(id, id))),
            t,
        );
        assert_eq!(claim.state, ClaimState::Refuted);
    }
    assert_eq!(
        h.concluded(&claims),
        None,
        "a lone survivor without discriminating evidence is still not a conclusion"
    );

    claims
        .get_mut("a")
        .expect("present")
        .add_discriminator(Provenance::Observed(SourceLineage::corpus("p3", "c3")), t);
    assert_eq!(h.concluded(&claims), Some("a"));
}

// ── Budget ──────────────────────────────────────────────────────────────────

#[test]
fn exhausting_the_budget_stops_expansion_without_settling_anything() {
    let mut b = ExpansionBudget::for_difficulty(2, 3, TargetDifficulty::Routine);
    assert!(b.spend());
    assert!(b.spend());
    assert!(!b.spend(), "exhausted");

    // The claim it was expanding is untouched by the budget running out.
    let mut c = identity_claim();
    c.add_support(
        Support::Unattempted {
            provider: "p".into(),
            reason: "expansion budget exhausted".into(),
        },
        PromotionThresholds::default(),
    );
    assert_eq!(
        c.state,
        ClaimState::Hypothesised,
        "running out of budget is not a finding about the world"
    );
}

#[test]
fn budget_scales_super_linearly_with_difficulty() {
    let base = 50;
    let r = ExpansionBudget::for_difficulty(base, 4, TargetDifficulty::Routine).remaining;
    let s = ExpansionBudget::for_difficulty(base, 4, TargetDifficulty::Sparse).remaining;
    let a = ExpansionBudget::for_difficulty(base, 4, TargetDifficulty::Adversarial).remaining;
    assert_eq!((r, s, a), (50, 100, 200));
    assert!(
        a - s > s - r,
        "the hardest tier gains the most, not the least"
    );
}

// ── Serialisation stability ─────────────────────────────────────────────────

#[test]
fn a_claim_round_trips_and_serialises_deterministically() {
    let mut c = identity_claim();
    let t = PromotionThresholds::default();
    c.add_support(observed_corpus("p1", "c1"), t);
    c.add_contradiction(
        Contradiction::new(
            "dob",
            ("x", SourceLineage::corpus("p1", "c1")),
            ("y", SourceLineage::corpus("p2", "c2")),
        ),
        t,
    );
    let json = serde_json::to_string(&c).expect("serialise");
    let back: Claim = serde_json::from_str(&json).expect("deserialise");
    assert_eq!(back, c);
    assert_eq!(
        serde_json::to_string(&back).expect("re-serialise"),
        json,
        "identical claims must produce byte-identical JSON (hashable evidence chains)"
    );
    assert!(
        json.contains("\"state\":\"contested\""),
        "the wire spelling is the stable snake_case form: {json}"
    );
}
