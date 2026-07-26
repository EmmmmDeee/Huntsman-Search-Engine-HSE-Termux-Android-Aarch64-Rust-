use super::*;

#[test]
fn accepts_org_and_fullname() {
    let m = OpenCorporates;
    assert!(m.accepts(&Target::new(TargetKind::Organisation, "Atlassian")));
    assert!(m.accepts(&Target::new(TargetKind::FullName, "John Smith")));
    assert!(!m.accepts(&Target::new(TargetKind::Email, "x@y.com")));
}

#[test]
fn abn_acn_search_is_restricted_to_australia() {
    // An ABN/ACN is Australian by construction — it could never appear in a
    // non-AU registry, so restricting the search saves quota.
    let url = build_search_url(TargetKind::AbnAcn, "51824753556");
    assert!(url.contains("/v0.4/companies/search"));
    assert!(url.contains("jurisdiction_code=au"));
}

#[test]
fn organisation_search_is_global() {
    // No jurisdiction signal in a bare company name — search all ~140
    // jurisdictions OpenCorporates indexes, not just AU.
    let url = build_search_url(TargetKind::Organisation, "Globex Inc");
    assert!(url.contains("/v0.4/companies/search"));
    assert!(!url.contains("jurisdiction_code"));
}

#[test]
fn full_name_search_uses_officer_endpoint_and_is_global() {
    let url = build_search_url(TargetKind::FullName, "Jane Roe");
    assert!(url.contains("/v0.4/officers/search"));
    assert!(!url.contains("jurisdiction_code"));
}

#[test]
fn should_report_key_status_covers_401_403_429_but_not_404_or_success() {
    assert!(should_report_key_status(401));
    assert!(should_report_key_status(403));
    assert!(should_report_key_status(429));
    assert!(!should_report_key_status(404));
    assert!(!should_report_key_status(200));
}

#[test]
fn module_metadata() {
    assert_eq!(OpenCorporates.name(), "opencorporates");
    // Government / public-records band (see priority() doc).
    assert_eq!(OpenCorporates.priority(), 116);
    assert_eq!(OpenCorporates.max_timeout_ms(), 10_000);
    // Key-gated since OpenCorporates withdrew its keyless public tier (2023);
    // a `Free` classification silently swallowed the 401 on every scan.
    assert!(matches!(
        OpenCorporates.cost(),
        crate::core::module::ModuleCost::KeyGated
    ));
}

#[tokio::test]
async fn missing_key_yields_a_clean_needs_key_skip_not_a_silent_empty() {
    // Regression: the keyless public tier is gone (every anonymous request
    // 401s), so an unconfigured scan must surface `Error::MissingKey` — which
    // dispatch renders as a "needs API key" skip with the signup hint — NOT
    // the `Ok(empty)` the pre-fix `key_opt` + 401-swallow path produced on
    // every scan, hiding the fact a key is required.
    let (bus, _rx) = tokio::sync::broadcast::channel(8);
    let ctx = ModuleContext {
        scan_id: "t".into(),
        bus,
        http: crate::util::http::build_client(),
        keys: std::collections::HashMap::new(),
        cancel: crate::core::cancel::CancelHandle::new(),
    };
    let err = OpenCorporates
        .process(&Target::new(TargetKind::Organisation, "Atlassian"), &ctx)
        .await
        .expect_err("an unconfigured key must be a MissingKey skip, not a silent empty result");
    assert!(
        matches!(err, crate::core::error::Error::MissingKey(ref k) if k == KEY_ENV),
        "must name the OpenCorporates key env so the operator sees the signup hint: {err:?}"
    );
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
    let r: OcResp = serde_json::from_str(raw).expect("should succeed");
    let results = r.results.expect("should succeed");
    let co = results.companies[0].company.as_ref().expect("should succeed");
    assert_eq!(co.name.as_deref(), Some("ATLASSIAN PTY LTD"));
    assert_eq!(co.jurisdiction_code.as_deref(), Some("au"));
}

fn company(json: &str) -> OcCompany {
    serde_json::from_str(json).expect("should succeed")
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
    // Org + Address + optional Coordinates (Sydney matches city_coords) + Url + AbnAcn.
    assert!(
        ents.len() >= 4,
        "expected at least 4 entities, got {}",
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

    assert!(ents.iter().any(|e| e.kind == EntityKind::Url
        && e.has_tag("profile-url")
        && e.value == "https://opencorporates.com/companies/au/111222333"));

    assert!(ents.iter().any(|e| e.kind == EntityKind::AbnAcn
        && e.has_tag("company-number")
        && e.value == "111222333"));
}

#[test]
fn au_company_opencorporates_url_becomes_pivotable_url_entity() {
    // The company's own OpenCorporates profile URL must be emitted as a
    // pivotable `Url` entity, not just stashed as Organisation evidence.
    let co = company(
        r#"{
            "name":"ATLASSIAN PTY LTD","company_number":"111222333",
            "jurisdiction_code":"au",
            "opencorporates_url":"https://opencorporates.com/companies/au/111222333"
        }"#,
    );
    let ents = build_company_entities(&co, 1, "s");
    let url_ent = ents
        .iter()
        .find(|e| e.kind == EntityKind::Url)
        .expect("opencorporates_url must yield a Url entity");
    assert_eq!(
        url_ent.value,
        "https://opencorporates.com/companies/au/111222333"
    );
    assert!(url_ent.has_tag("opencorporates") && url_ent.has_tag("profile-url"));
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

fn officer(json: &str) -> OcOfficer {
    serde_json::from_str(json).expect("should succeed")
}

#[test]
fn officer_au_with_company_emits_org_acn_and_person() {
    // The officer-search path mirrors the company path but was entirely untested.
    let o = officer(
        r#"{"name":"Jane Roe","position":"director","company":{"name":"Acme Pty Ltd","company_number":"123456789","jurisdiction_code":"au","current_status":"Active"}}"#,
    );
    let ents = build_officer_entities(&o, 9, "s");
    let org = ents
        .iter()
        .find(|e| e.kind == EntityKind::Organisation)
        .expect("company → Organisation");
    assert_eq!(org.value, "Acme Pty Ltd");
    assert!(org.has_tag("country:AU") && org.has_tag("active"));
    // AU + non-empty company_number → AbnAcn.
    assert!(
        ents.iter()
            .any(|e| e.kind == EntityKind::AbnAcn && e.value == "123456789")
    );
    // Multi-word officer name → Person.
    assert!(
        ents.iter()
            .any(|e| e.kind == EntityKind::Person && e.value == "Jane Roe")
    );
}

#[test]
fn officer_non_au_jurisdiction_emits_no_company_number() {
    let o = officer(
        r#"{"name":"John Smith","company":{"name":"Globex Inc","company_number":"C12345","jurisdiction_code":"us"}}"#,
    );
    let ents = build_officer_entities(&o, 1, "s");
    assert!(
        ents.iter().all(|e| e.kind != EntityKind::AbnAcn),
        "a non-AU company number must not become an AbnAcn"
    );
    // Org still emitted (no country:AU tag), Person still emitted.
    assert!(ents.iter().any(|e| e.kind == EntityKind::Organisation));
    assert!(ents.iter().any(|e| e.kind == EntityKind::Person));
}

#[test]
fn officer_single_token_name_yields_no_person() {
    // A mononym (no space) is not minted as a Person (avoids a junk identity).
    let o = officer(
        r#"{"name":"madonna","company":{"name":"Acme","jurisdiction_code":"au","company_number":""}}"#,
    );
    let ents = build_officer_entities(&o, 1, "s");
    assert!(ents.iter().all(|e| e.kind != EntityKind::Person));
    // Empty company_number → no AbnAcn even for AU.
    assert!(ents.iter().all(|e| e.kind != EntityKind::AbnAcn));
}
