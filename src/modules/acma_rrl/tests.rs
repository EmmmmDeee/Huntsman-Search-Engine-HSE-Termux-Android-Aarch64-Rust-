use super::{AcmaRrl, extract_abn_from_html, parse_acma_html};
use crate::core::{
    module::{Module, ModuleCost},
    scan::{Target, TargetKind},
};

#[test]
fn metadata() {
    let m = AcmaRrl;
    assert_eq!(m.name(), "acma_rrl");
    assert_eq!(m.priority(), 48);
    assert!(!m.description().is_empty());
    assert_eq!(m.cost(), ModuleCost::Free);
    assert!(m.accepts(&Target::new(TargetKind::Organisation, "Acme Corp")));
    assert!(m.accepts(&Target::new(TargetKind::AbnAcn, "12345678901")));
    assert!(m.accepts(&Target::new(TargetKind::Coordinates, "-33.8688,151.2093")));
    assert!(!m.accepts(&Target::new(TargetKind::Email, "x@y.com")));
    assert!(m.max_timeout_ms() > 3000);
    let techs = m.attack_techniques();
    assert!(techs.contains(&"T1591.001"));
    assert!(techs.contains(&"T1591.002"));
}

#[test]
fn parse_acma_html_extracts_rows() {
    let html = r#"<table><tr><th>Licensee</th><th>Licence No</th><th>Service</th></tr>
<tr><td>ABC Radio Pty Ltd</td><td>L12345</td><td>Broadcasting</td></tr>
</table>"#;
    let rows = parse_acma_html(html);
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].0, "ABC Radio Pty Ltd");
    assert_eq!(rows[0].1, "L12345");
}

#[test]
fn extract_abn_returns_none_for_missing() {
    assert!(extract_abn_from_html("<html>no abn here</html>").is_none());
}
