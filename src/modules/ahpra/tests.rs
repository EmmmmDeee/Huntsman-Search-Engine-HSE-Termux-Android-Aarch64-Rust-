use super::{Ahpra, build_practitioner_entities, parse_ahpra_html};
use crate::core::{
    module::{Module, ModuleCost},
    scan::{Target, TargetKind},
};

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

/// Regression guard for `PROBLEM_TREE` T2.26: the AHPRA search endpoint has no
/// page-size/limit query param, so a common-name search can return more than
/// the 20-row emit cap — the register is the national list for ALL registered
/// health practitioners, so this is an ordinary, not adversarial, case.
/// `total_matches` must always carry the TRUE row count, not the shown count,
/// so an operator can tell a capped result from a complete one.
#[test]
fn build_practitioner_entities_records_the_true_total_above_the_cap() {
    let practitioners: Vec<(String, String, String)> = (0..25)
        .map(|i| {
            (
                format!("Practitioner {i}"),
                "Nurse".to_string(),
                format!("NMW{i:07}"),
            )
        })
        .collect();
    let entities = build_practitioner_entities(&practitioners, "scan-1");
    assert_eq!(entities.len(), 20, "the emit cap is still enforced");
    for e in &entities {
        let total = e.evidence[0]
            .attributes
            .get("total_matches")
            .expect("every emitted practitioner must carry total_matches");
        assert_eq!(
            total, "25",
            "total_matches must be the TRUE row count, not the 20-row cap"
        );
    }
}

#[test]
fn build_practitioner_entities_under_the_cap_reports_its_own_count() {
    let practitioners = vec![(
        "Jane Smith".to_string(),
        "Nurse".to_string(),
        "N1".to_string(),
    )];
    let entities = build_practitioner_entities(&practitioners, "scan-1");
    assert_eq!(entities.len(), 1);
    assert_eq!(
        entities[0].evidence[0].attributes.get("total_matches"),
        Some(&"1".to_string())
    );
}
