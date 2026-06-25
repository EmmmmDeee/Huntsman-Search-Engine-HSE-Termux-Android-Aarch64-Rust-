use super::*;

#[test]
fn parse_current_bankruptcy() {
    // Simulated AFSA NPII HTML containing a current bankruptcy record.
    let html = r#"
        <table>
          <tr><td>John William Smith</td></tr>
          <tr><td>Bankruptcy</td></tr>
          <tr><td>Current</td></tr>
          <tr><td>Parramatta, NSW 2150</td></tr>
        </table>
    "#;

    let entities = parse_npii_html(html, "John Smith", "test-scan");
    // At least a Person should be emitted.
    assert!(
        entities.iter().any(|e| e.kind == EntityKind::Person),
        "expected a Person entity for a name-matching NPII record"
    );
    let person = entities
        .iter()
        .find(|e| e.kind == EntityKind::Person)
        .unwrap();
    assert!(
        person.has_tag("insolvency:bankruptcy"),
        "person should be tagged with administration type"
    );
    assert!(
        person.has_tag("insolvency:current"),
        "person should be tagged with current status"
    );
    assert!(person.has_tag("afsa-npii"));
    assert!(person.has_tag("country:AU"));
}

#[test]
fn parse_debt_agreement_former() {
    let html = r#"
        <div>
          <p>Jane Elizabeth Brown</p>
          <p>Debt Agreement</p>
          <p>Completed</p>
          <p>Sunshine, VIC 3020</p>
        </div>
    "#;

    let entities = parse_npii_html(html, "Jane Brown", "test-scan");
    let person = entities.iter().find(|e| e.kind == EntityKind::Person);
    assert!(person.is_some(), "expected a Person entity");
    let p = person.unwrap();
    assert!(p.has_tag("insolvency:debt-agreement"));
    assert!(p.has_tag("insolvency:former"));
}

#[test]
fn parse_address_locality() {
    let html = r#"
        <p>Robert James Taylor</p>
        <p>Bankruptcy</p>
        <p>Current</p>
        <p>Southport QLD 4215</p>
    "#;

    let entities = parse_npii_html(html, "Robert Taylor", "test-scan");
    let addr = entities.iter().find(|e| e.kind == EntityKind::Address);
    assert!(addr.is_some(), "expected an Address entity");
    let a = addr.unwrap();
    assert!(
        a.value.contains("QLD"),
        "address should contain the state: {}",
        a.value
    );
    assert!(a.has_tag("au-state:QLD"));
}

#[test]
fn no_false_positive_on_unrelated_content() {
    let html = r#"<p>General content page, no insolvency records found.</p>"#;
    let entities = parse_npii_html(html, "John Smith", "test-scan");
    assert!(
        entities.is_empty(),
        "should not emit entities from a page with no NPII records"
    );
}

#[test]
fn deduplication_across_repeated_records() {
    // Same record appearing twice (e.g. pagination overlap).
    let html = r#"
        <p>Mary Anne Williams</p>
        <p>Bankruptcy</p>
        <p>Current</p>
        <p>Hobart, TAS 7000</p>
        <p>Mary Anne Williams</p>
        <p>Bankruptcy</p>
        <p>Current</p>
        <p>Hobart, TAS 7000</p>
    "#;
    let entities = parse_npii_html(html, "Mary Williams", "test-scan");
    let persons: Vec<_> = entities
        .iter()
        .filter(|e| e.kind == EntityKind::Person)
        .collect();
    assert_eq!(persons.len(), 1, "duplicate records should be deduplicated");
}
