use super::*;

#[test]
fn parse_financial_services_ban() {
    let html = r#"
        <table>
          <tr><td>ANDERSON, MICHAEL JAMES</td></tr>
          <tr><td>Banned from providing financial services</td></tr>
          <tr><td>Permanently</td></tr>
          <tr><td>01/06/2021</td><td>N/A</td></tr>
        </table>
    "#;

    let entities = parse_banned_html(html, "Michael Anderson", "test-scan");
    assert!(
        entities.iter().any(|e| e.kind == EntityKind::Person),
        "expected a Person entity for a name-matching banned register record"
    );
    let person = entities
        .iter()
        .find(|e| e.kind == EntityKind::Person)
        .unwrap();
    assert!(
        person.has_tag("asic:banned-financial"),
        "person should be tagged with ban type"
    );
    assert!(
        person.has_tag("asic:permanent"),
        "permanently banned person should be tagged asic:permanent"
    );
    assert!(person.has_tag("asic-banned"));
    assert!(person.has_tag("country:AU"));
}

#[test]
fn parse_disqualified_director() {
    let html = r#"
        <div>
          <p>NGUYEN, LISA THI</p>
          <p>Disqualified from managing corporations</p>
          <p>15/03/2023</p>
          <p>14/03/2028</p>
        </div>
    "#;

    let entities = parse_banned_html(html, "Lisa Nguyen", "test-scan");
    let person = entities.iter().find(|e| e.kind == EntityKind::Person);
    assert!(
        person.is_some(),
        "expected a Person entity for disqualified director"
    );
    let p = person.unwrap();
    assert!(
        p.has_tag("asic:disqualified"),
        "should be tagged as disqualified"
    );
    assert!(
        p.has_tag("asic:temporary"),
        "time-limited disqualification should be tagged temporary"
    );
}

#[test]
fn parse_credit_activities_ban() {
    let html = r#"
        <p>O'BRIEN, PATRICK SEAN</p>
        <p>Banned from engaging in credit activities</p>
        <p>01/09/2022</p>
        <p>N/A</p>
        <p>Permanently</p>
    "#;

    let entities = parse_banned_html(html, "Patrick O'Brien", "test-scan");
    let person = entities.iter().find(|e| e.kind == EntityKind::Person);
    assert!(person.is_some(), "expected a Person entity for credit ban");
    let p = person.unwrap();
    assert!(
        p.has_tag("asic:banned-credit"),
        "should be tagged as banned-credit"
    );
}

#[test]
fn no_false_positive_on_empty_page() {
    let html = r#"<p>No results found. Please refine your search.</p>"#;
    let entities = parse_banned_html(html, "John Smith", "test-scan");
    assert!(
        entities.is_empty(),
        "should not emit entities when no banned records are found"
    );
}

#[test]
fn deduplication_prevents_duplicate_persons() {
    let html = r#"
        <p>CHEN, DAVID WILLIAM</p>
        <p>Banned from providing financial services</p>
        <p>Permanently</p>
        <p>CHEN, DAVID WILLIAM</p>
        <p>Banned from providing financial services</p>
        <p>Permanently</p>
    "#;
    let entities = parse_banned_html(html, "David Chen", "test-scan");
    let persons: Vec<_> = entities
        .iter()
        .filter(|e| e.kind == EntityKind::Person)
        .collect();
    assert_eq!(persons.len(), 1, "duplicate records should be deduplicated");
}
