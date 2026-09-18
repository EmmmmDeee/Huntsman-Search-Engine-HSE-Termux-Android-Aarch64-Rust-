use super::{Ahpra, build_practitioner_entities, parse_ahpra_html};
use crate::core::confidence;
use crate::core::{
    entity::EntityKind,
    module::{Module, ModuleCost},
    scan::{Target, TargetKind},
};

#[test]
fn build_practitioner_entities_emits_every_parsed_row_not_just_20() {
    // Full-fidelity: a common-surname register search (Smith/Nguyen/Lee) returns
    // many practitioners; every parsed row must become a Person entity (the HTML
    // body is already size-bounded upstream). Fail-before: capped at 20.
    let rows: Vec<(String, String, String)> = (0..25)
        .map(|i| {
            (
                format!("Jane Smith {i:02}"),
                "Medical Practitioner".to_string(),
                format!("MED{i:07}"),
            )
        })
        .collect();
    // Gated on the seed, the realistic FullName path: every row here genuinely
    // shares the seed's tokens, so the relevance gate must keep all 25 — it
    // suppresses strangers, never the subject's own common-surname cohort.
    let out = build_practitioner_entities(&rows, Some("Jane Smith"), "s");
    assert_eq!(
        out.len(),
        25,
        "every parsed practitioner must be emitted, not capped at 20"
    );
    assert!(out.iter().all(|e| e.kind == EntityKind::Person));
    assert!(out.iter().any(|e| e.value == "Jane Smith 24"));
}

#[test]
fn metadata() {
    let m = Ahpra;
    assert_eq!(m.name(), "ahpra");
    assert_eq!(m.priority(), 86);
    assert!(!m.description().is_empty());
    assert_eq!(m.cost(), ModuleCost::Free);
    assert!(m.accepts(&Target::new(TargetKind::FullName, "Jane Smith")));
    assert!(m.accepts(&Target::new(TargetKind::Organisation, "Acme Clinic")));
    assert!(!m.accepts(&Target::new(TargetKind::Email, "x@y.com")));
    assert!(m.max_timeout_ms() > 3000);
    assert!(!m.attack_techniques().is_empty());
}

#[test]
fn parse_ahpra_html_extracts_rows() {
    let html = r#"<table><tr><th>Name</th><th>Profession</th><th>Registration</th></tr>
<tr><td>Jane Smith</td><td>Medical Practitioner</td><td>MED0001234</td></tr>
<tr><td>Bob Jones</td><td>Nurse</td><td>NMW0005678</td></tr>
</table>"#;
    let rows = parse_ahpra_html(html);
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0].0, "Jane Smith");
    assert_eq!(rows[0].1, "Medical Practitioner");
    assert_eq!(rows[1].0, "Bob Jones");
}

// ── REQ-AHPRA-001: a register row is a name match, not a practitioner ID ────

#[test]
fn a_row_whose_name_is_not_the_seed_is_never_emitted() {
    // AHPRA's search is fuzzy and the FullName leg queries a surname field, so
    // the table can carry practitioners who are not the subject at all. Before
    // this, every parsed row became a Person at HIGH_PLUS — a stranger's real
    // health registration minted as the subject's.
    let rows = vec![
        (
            "Jane Smith".to_string(),
            "Medical Practitioner".to_string(),
            "MED0001234".to_string(),
        ),
        (
            "Robert Nguyen".to_string(),
            "Nurse".to_string(),
            "NMW0009999".to_string(),
        ),
    ];
    let out = build_practitioner_entities(&rows, Some("Jane Smith"), "s");
    assert_eq!(out.len(), 1, "only the seed's own name may be emitted");
    assert_eq!(out[0].value, "Jane Smith");
}

#[test]
fn an_organisation_search_is_not_gated_on_the_seed_name() {
    // An Organisation seed returns that clinic's practitioners; their names are
    // supposed to differ from the clinic's, so the name gate must not run.
    let rows = vec![(
        "Jane Smith".to_string(),
        "Medical Practitioner".to_string(),
        "MED0001234".to_string(),
    )];
    let out = build_practitioner_entities(&rows, None, "s");
    assert_eq!(out.len(), 1, "an org search keeps its practitioners");
}

#[test]
fn a_name_only_row_sits_at_the_au_register_anchor_and_says_it_is_unverified() {
    let rows = vec![(
        "Jane Smith".to_string(),
        "Medical Practitioner".to_string(),
        "MED0001234".to_string(),
    )];
    let out = build_practitioner_entities(&rows, Some("Jane Smith"), "s");
    let p = &out[0];
    assert!(
        (p.confidence - confidence::MEDIUM_PLUS).abs() < 1e-9,
        "a single-source name hit belongs at the AU-register anchor, got {}",
        p.confidence
    );
    assert!(
        p.has_tag("needs-identity-verification"),
        "a name-only register hit must say the identity is unproven"
    );
    assert!(
        p.evidence.iter().any(|ev| ev
            .attributes
            .get("caution")
            .is_some_and(|c| c.contains("Name-only match"))),
        "and carry the caution naming what would settle it"
    );
}

#[test]
fn two_practitioners_sharing_a_name_are_marked_as_a_proven_collision() {
    // The register returning the SAME name twice is positive proof the name does
    // not identify one person. The entity value IS the name, so the engine's
    // merge fuses these two rows into one Person carrying both registration
    // numbers — a composite practitioner who does not exist. It must describe
    // its own ambiguity rather than read as one confident registration.
    let rows = vec![
        (
            "Jane Smith".to_string(),
            "Medical Practitioner".to_string(),
            "MED0001234".to_string(),
        ),
        (
            "Jane Smith".to_string(),
            "Nurse".to_string(),
            "NMW0005678".to_string(),
        ),
    ];
    let out = build_practitioner_entities(&rows, Some("Jane Smith"), "s");
    assert_eq!(out.len(), 2);
    for p in &out {
        assert!(
            p.confidence < confidence::MEDIUM_PLUS,
            "a provably multi-holder name must score BELOW a single hit, got {}",
            p.confidence
        );
        assert!(p.has_tag("ambiguous-name"));
        assert!(
            p.evidence.iter().any(|ev| ev
                .attributes
                .get("caution")
                .is_some_and(|c| c.contains("MORE THAN ONE"))),
            "the evidence must state that the name has multiple holders"
        );
    }
}
