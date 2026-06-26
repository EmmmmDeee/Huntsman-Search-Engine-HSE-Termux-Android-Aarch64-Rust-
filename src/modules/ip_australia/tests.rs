use super::*;

#[test]
fn parse_registered_trademark_owner() {
    let html = r#"
        <table>
          <tr><th>Trade Mark</th><th>Owner</th><th>Status</th></tr>
          <tr>
            <td>BLUESTONE CAPITAL</td>
            <td>Bluestone Capital Management Pty Ltd</td>
            <td>Registered</td>
          </tr>
        </table>
        <div class="owner">Bluestone Capital Management Pty Ltd</div>
        <div class="address">North Sydney NSW 2060</div>
    "#;

    let entities = parse_trademark_html(html, "Bluestone Capital", "test-scan");
    assert!(
        entities.iter().any(|e| e.kind == EntityKind::Organisation),
        "expected an Organisation entity for a trademark owner"
    );
    let org = entities
        .iter()
        .find(|e| e.kind == EntityKind::Organisation)
        .unwrap();
    assert!(org.has_tag("trademark"));
    assert!(org.has_tag("ip-australia"));
    assert!(org.has_tag("country:AU"));
}

#[test]
fn parse_trademark_status_registered() {
    let html = r#"
        <div>
          <span>applicant</span>
          <p>Horizon Solar Group Pty Ltd</p>
          <p>Registered</p>
          <p>Adelaide SA 5000</p>
        </div>
    "#;

    let entities = parse_trademark_html(html, "Horizon Solar Group", "test-scan");
    let org = entities.iter().find(|e| e.kind == EntityKind::Organisation);
    assert!(org.is_some(), "expected an Organisation entity");
    let o = org.unwrap();
    assert!(
        o.has_tag("trademark-status:registered"),
        "registered trademark should have registered status tag"
    );
}

#[test]
fn parse_address_from_trademark_result() {
    let html = r#"
        <p>Owner:</p>
        <p>Pacific Ventures Holdings Pty Ltd</p>
        <p>Pending</p>
        <p>Melbourne VIC 3000</p>
    "#;

    let entities = parse_trademark_html(html, "Pacific Ventures", "test-scan");
    let addr = entities.iter().find(|e| e.kind == EntityKind::Address);
    assert!(
        addr.is_some(),
        "expected an Address entity from trademark result"
    );
    let a = addr.unwrap();
    assert!(
        a.value.contains("VIC"),
        "address should contain state abbreviation: {}",
        a.value
    );
    assert!(a.has_tag("au-state:VIC"));
}

#[test]
fn no_false_positive_on_no_results_page() {
    let html = r#"<p>Your search returned no results. Try a different search term.</p>"#;
    let entities = parse_trademark_html(html, "Example Corp", "test-scan");
    assert!(
        entities.is_empty(),
        "should not emit entities when no trademark records are found"
    );
}

#[test]
fn deduplication_across_identical_trademark_results() {
    let html = r#"
        <div>owner</div>
        <p>Sunburst Holdings Pty Ltd</p>
        <p>Registered</p>
        <div>owner</div>
        <p>Sunburst Holdings Pty Ltd</p>
        <p>Registered</p>
    "#;
    let entities = parse_trademark_html(html, "Sunburst Holdings", "test-scan");
    let orgs: Vec<_> = entities
        .iter()
        .filter(|e| e.kind == EntityKind::Organisation)
        .collect();
    assert_eq!(
        orgs.len(),
        1,
        "duplicate trademark entries should be deduplicated"
    );
}
