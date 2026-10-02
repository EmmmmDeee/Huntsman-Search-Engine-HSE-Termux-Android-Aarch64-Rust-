use super::{Ahpra, build_practitioner_entities, parse_ahpra_html};
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
    let out = build_practitioner_entities(&rows, "s");
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
