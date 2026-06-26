use super::*;

#[test]
fn parse_financial_adviser() {
    let html = r#"
        <table>
          <tr><td>Thompson, Sarah Jane</td></tr>
          <tr><td>Financial Adviser</td></tr>
          <tr><td>Surry Hills NSW 2010</td></tr>
        </table>
    "#;

    let entities = parse_fsr_html(html, "Sarah Thompson", "test-scan");
    assert!(
        entities.iter().any(|e| e.kind == EntityKind::Person),
        "expected a Person entity for a financial adviser"
    );
    let person = entities
        .iter()
        .find(|e| e.kind == EntityKind::Person)
        .unwrap();
    assert!(person.has_tag("asic-fsr:financial-adviser"));
    assert!(person.has_tag("asic-fsr"));
    assert!(person.has_tag("country:AU"));
}

#[test]
fn parse_afs_licensee_organisation() {
    let html = r#"
        <div>
          <p>Greenfield Capital Partners Pty Ltd</p>
          <p>Australian Financial Services Licensee</p>
          <p>Melbourne VIC 3000</p>
        </div>
    "#;

    let entities = parse_fsr_html(html, "Greenfield Capital Partners", "test-scan");
    let org = entities.iter().find(|e| e.kind == EntityKind::Organisation);
    assert!(
        org.is_some(),
        "expected an Organisation entity for AFS licensee"
    );
    let o = org.unwrap();
    assert!(
        o.has_tag("asic-fsr:afs-licensee"),
        "should be tagged as AFS licensee"
    );
}

#[test]
fn parse_address_from_fsr_result() {
    let html = r#"
        <p>Wilson, Mark Anthony</p>
        <p>Credit Representative</p>
        <p>Parramatta NSW 2150</p>
    "#;

    let entities = parse_fsr_html(html, "Mark Wilson", "test-scan");
    let addr = entities.iter().find(|e| e.kind == EntityKind::Address);
    assert!(addr.is_some(), "expected an Address entity from FSR result");
    let a = addr.unwrap();
    assert!(
        a.value.contains("NSW"),
        "address should contain state abbreviation: {}",
        a.value
    );
    assert!(a.has_tag("au-state:NSW"));
}

#[test]
fn no_false_positive_on_unrelated_content() {
    let html = r#"<p>No matching results were found in the professional registers.</p>"#;
    let entities = parse_fsr_html(html, "John Smith", "test-scan");
    assert!(
        entities.is_empty(),
        "should not emit entities when no FSR records are present"
    );
}

#[test]
fn deduplication_across_repeated_fsr_results() {
    let html = r#"
        <p>Roberts, Emma Louise</p>
        <p>Financial Adviser</p>
        <p>Brisbane QLD 4000</p>
        <p>Roberts, Emma Louise</p>
        <p>Financial Adviser</p>
        <p>Brisbane QLD 4000</p>
    "#;
    let entities = parse_fsr_html(html, "Emma Roberts", "test-scan");
    let persons: Vec<_> = entities
        .iter()
        .filter(|e| e.kind == EntityKind::Person)
        .collect();
    assert_eq!(
        persons.len(),
        1,
        "duplicate FSR records should be deduplicated"
    );
}
