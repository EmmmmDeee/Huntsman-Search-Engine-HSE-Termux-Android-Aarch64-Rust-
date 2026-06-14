use super::*;

#[test]
fn accepts_org_and_fullname() {
    let m = OpenCorporates;
    assert!(m.accepts(&Target::new(TargetKind::Organisation, "Atlassian")));
    assert!(m.accepts(&Target::new(TargetKind::FullName, "John Smith")));
    assert!(!m.accepts(&Target::new(TargetKind::Email, "x@y.com")));
}

#[test]
fn module_metadata() {
    assert_eq!(OpenCorporates.name(), "opencorporates");
    // Government / public-records band (see priority() doc).
    assert_eq!(OpenCorporates.priority(), 116);
    assert_eq!(OpenCorporates.max_timeout_ms(), 10_000);
}

#[test]
fn parse_response() {
    let raw = r#"{
        "results": {
            "companies": [{
                "company": {
                    "name": "ATLASSIAN PTY LTD",
                    "company_number": "111222333",
                    "jurisdiction_code": "au",
                    "incorporation_date": "2002-01-01",
                    "company_type": "Australian Proprietary Company",
                    "current_status": "Active",
                    "registered_address_in_full": "Level 6, 341 George Street, Sydney NSW 2000",
                    "opencorporates_url": "https://opencorporates.com/companies/au/111222333"
                }
            }],
            "total_count": 1
        }
    }"#;
    let r: OcResp = serde_json::from_str(raw).unwrap();
    let results = r.results.unwrap();
    let co = results.companies[0].company.as_ref().unwrap();
    assert_eq!(co.name.as_deref(), Some("ATLASSIAN PTY LTD"));
    assert_eq!(co.jurisdiction_code.as_deref(), Some("au"));
}

fn company(json: &str) -> OcCompany {
    serde_json::from_str(json).unwrap()
}

fn org_attr<'a>(e: &'a Entity, k: &str) -> Option<&'a str> {
    e.evidence[0].attributes.get(k).map(String::as_str)
}

#[test]
fn au_company_yields_org_address_and_company_number() {
    let co = company(
        r#"{
            "name":"ATLASSIAN PTY LTD","company_number":"111222333",
            "jurisdiction_code":"au","incorporation_date":"2002-01-01",
            "current_status":"Active",
            "registered_address_in_full":"Level 6, 341 George Street, Sydney NSW 2000",
            "opencorporates_url":"https://opencorporates.com/companies/au/111222333"
        }"#,
    );
    let ents = build_company_entities(&co, 7, "s");
    // Org + Address + optional Coordinates (Sydney matches city_coords) + AbnAcn.
    assert!(
        ents.len() >= 3,
        "expected at least 3 entities, got {}",
        ents.len()
    );

    let org = &ents[0];
    assert_eq!(org.kind, EntityKind::Organisation);
    assert!(org.has_tag("opencorporates") && org.has_tag("country:AU") && org.has_tag("active"));
    assert_eq!(org_attr(org, "company_number"), Some("111222333"));
    assert_eq!(org_attr(org, "status"), Some("Active"));
    assert_eq!(org_attr(org, "total_matches"), Some("7"));

    assert!(ents.iter().any(|e| e.kind == EntityKind::Address
        && e.has_tag("registered-address")
        && e.has_tag("validated")));

    assert!(ents.iter().any(|e| e.kind == EntityKind::AbnAcn
        && e.has_tag("company-number")
        && e.value == "111222333"));
}

#[test]
fn non_au_company_omits_company_number_entity() {
    // A non-AU jurisdiction → no AbnAcn entity, no country:AU / no active tag.
    let co = company(
        r#"{"name":"Globex Inc","company_number":"C-99","jurisdiction_code":"us",
            "current_status":"Dissolved",
            "registered_address_in_full":"1 Market St, San Francisco"}"#,
    );
    let ents = build_company_entities(&co, 1, "s");
    // Org + Address (+ optional Coordinates if city matches) — no AU company-number.
    assert!(
        ents.len() >= 2,
        "expected at least 2 entities, got {}",
        ents.len()
    );
    assert!(!ents[0].has_tag("country:AU") && !ents[0].has_tag("active"));
    assert!(ents.iter().all(|e| e.kind != EntityKind::AbnAcn));
}

#[test]
fn short_address_and_missing_number_drop_optional_entities() {
    let co = company(
        r#"{"name":"Tiny Co","jurisdiction_code":"au","registered_address_in_full":"NSW"}"#,
    );
    let ents = build_company_entities(&co, 1, "s");
    // Address too short (< MIN_ADDRESS_LEN) and no company_number → org only.
    assert_eq!(ents.len(), 1);
    assert_eq!(ents[0].kind, EntityKind::Organisation);
}

#[test]
fn whitespace_address_does_not_create_blank_entity() {
    // A whitespace-only registered address must not become an Address entity.
    let co = company(
        r#"{"name":"Acme","jurisdiction_code":"au","registered_address_in_full":"        "}"#,
    );
    let ents = build_company_entities(&co, 1, "s");
    assert!(ents.iter().all(|e| e.kind != EntityKind::Address));
}

#[test]
fn blank_name_yields_nothing() {
    assert!(build_company_entities(&company(r#"{"name":"   "}"#), 1, "s").is_empty());
    assert!(build_company_entities(&company("{}"), 1, "s").is_empty());
}
