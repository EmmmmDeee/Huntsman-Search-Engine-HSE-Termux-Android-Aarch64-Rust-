use crate::core::{
    module::{Module, ModuleCost},
    scan::{Target, TargetKind},
};
use super::{Ahpra, parse_ahpra_html};

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
