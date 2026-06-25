use super::*;

#[test]
fn parse_individual_tax_agent() {
    let html = r#"
        <table>
          <tr><td>John Michael Roberts</td></tr>
          <tr><td>Tax Agent</td></tr>
          <tr><td>Registered</td></tr>
          <tr><td>Brisbane, QLD 4000</td></tr>
          <tr><td>26 004 765 432</td></tr>
        </table>
    "#;
    let entities = parse_tpb_html(html, "John Roberts", "test-scan");
    let person = entities.iter().find(|e| e.kind == EntityKind::Person);
    assert!(
        person.is_some(),
        "should emit a Person entity for individual tax agent"
    );
    let p = person.unwrap();
    assert!(p.has_tag("tpb:tax-agent"), "should be tagged as tax agent");
    assert!(
        p.has_tag("tpb:current"),
        "should be tagged as current/registered"
    );
    assert!(p.has_tag("tpb-registered"));
    assert!(p.has_tag("country:AU"));
}

#[test]
fn parse_company_tax_agent() {
    let html = r#"
        <p>Smith &amp; Jones Accounting Pty Ltd</p>
        <p>Tax Agent</p>
        <p>Registered</p>
        <p>Melbourne, VIC 3000</p>
    "#;
    let entities = parse_tpb_html(html, "Smith Jones Accounting", "test-scan");
    let org = entities.iter().find(|e| e.kind == EntityKind::Organisation);
    assert!(
        org.is_some(),
        "should emit Organisation entity for company name"
    );
    let o = org.unwrap();
    assert!(o.has_tag("tpb:tax-agent"));
    assert!(o.value.contains("Pty Ltd"));
}

#[test]
fn parse_bas_agent() {
    let html = r#"
        <div>
          <span>Sarah Louise Chen</span>
          <span>BAS Agent</span>
          <span>Registered</span>
          <span>Perth WA 6000</span>
        </div>
    "#;
    let entities = parse_tpb_html(html, "Sarah Chen", "test-scan");
    let person = entities.iter().find(|e| e.kind == EntityKind::Person);
    assert!(person.is_some());
    assert!(person.unwrap().has_tag("tpb:bas-agent"));
}

#[test]
fn parse_address_and_abn() {
    let html = r#"
        <p>David Anthony Wilson</p>
        <p>Tax Agent</p>
        <p>Registered</p>
        <p>Hobart, TAS 7000</p>
        <p>26 004 765 432</p>
    "#;
    let entities = parse_tpb_html(html, "David Wilson", "test-scan");

    let addr = entities.iter().find(|e| e.kind == EntityKind::Address);
    assert!(addr.is_some(), "should emit Address entity");
    let a = addr.unwrap();
    assert!(
        a.value.contains("TAS"),
        "address should include state: {}",
        a.value
    );
    assert!(a.has_tag("au-state:TAS"));

    let abn = entities.iter().find(|e| e.kind == EntityKind::AbnAcn);
    assert!(abn.is_some(), "should emit ABN entity when 11 digits found");
}

#[test]
fn suspended_agent_tagged_correctly() {
    let html = r#"
        <p>Emma Louise Clark</p>
        <p>Tax Agent</p>
        <p>Suspended</p>
        <p>Sydney NSW 2000</p>
    "#;
    let entities = parse_tpb_html(html, "Emma Clark", "test-scan");
    let person = entities.iter().find(|e| e.kind == EntityKind::Person);
    assert!(person.is_some());
    assert!(person.unwrap().has_tag("tpb:suspended"));
}

#[test]
fn is_company_name_detection() {
    assert!(is_company_name("Acme Accounting Pty Ltd"));
    assert!(is_company_name("Smith & Jones Partners"));
    assert!(is_company_name("First Class Tax Services"));
    assert!(!is_company_name("John Michael Smith"));
    assert!(!is_company_name("Sarah Jane Brown"));
}

#[test]
fn no_false_positive_empty_page() {
    let html = "<html><body><p>No results found for your search.</p></body></html>";
    let entities = parse_tpb_html(html, "Nobody Here", "test-scan");
    assert!(
        entities.is_empty(),
        "should not emit entities from empty result page"
    );
}
