use super::*;

fn resp(json: &str) -> RdapResponse {
    serde_json::from_str(json).expect("fixture should parse")
}

fn attr<'a>(e: &'a Entity, k: &str) -> Option<&'a str> {
    e.evidence.first()?.attributes.get(k).map(String::as_str)
}

fn find<'a>(ents: &'a [Entity], kind: &EntityKind, value: &str) -> Option<&'a Entity> {
    ents.iter().find(|e| e.kind == *kind && e.value == value)
}

// ── Module metadata ─────────────────────────────────────────────────────────

#[test]
fn module_metadata_is_coherent() {
    let m = AuRdap;
    assert_eq!(m.name(), "au_rdap");
    assert_eq!(m.category(), ModuleCategory::DnsRecon);
    assert!(m.accepts(&Target::new(TargetKind::Domain, "example.com.au")));
    assert!(!m.accepts(&Target::new(TargetKind::Email, "a@b.com")));
    assert!(!m.accepts(&Target::new(TargetKind::Url, "https://example.com.au")));
    for k in [
        EntityKind::Organisation,
        EntityKind::AbnAcn,
        EntityKind::Email,
        EntityKind::Domain,
    ] {
        assert!(
            m.produces().contains(&k),
            "produces() must declare {k:?}, which build_entities actually emits"
        );
    }
}

#[test]
fn priority_runs_before_the_generic_domain_registration_modules() {
    // whois = 32, rdap_domain = 31 in this crate: au_rdap discloses registrant
    // identity via auData_eligibility that neither can see, so it must be
    // dispatched first for a .au domain (engine sorts highest-priority-first).
    assert!(AuRdap.priority() > 32);
}

// ── query_domain ─────────────────────────────────────────────────────────────

#[test]
fn query_domain_reduces_subdomains_to_registrable_base() {
    assert_eq!(
        query_domain(&Target::new(TargetKind::Domain, "shop.example.com.au")).as_deref(),
        Some("example.com.au")
    );
    assert_eq!(
        query_domain(&Target::new(TargetKind::Domain, "example.com.au")).as_deref(),
        Some("example.com.au")
    );
}

#[test]
fn query_domain_empty_value_yields_none() {
    assert_eq!(query_domain(&Target::new(TargetKind::Domain, "   ")), None);
}

// ── The .au short-circuit (no network reached) ──────────────────────────────

#[tokio::test]
async fn non_au_domain_is_skipped_without_a_request() {
    let m = AuRdap;
    let (bus, _rx) = tokio::sync::broadcast::channel(1);
    let ctx = ModuleContext {
        scan_id: "scan-test".into(),
        bus,
        http: reqwest::Client::new(),
        keys: std::collections::HashMap::new(),
        cancel: crate::core::cancel::CancelHandle::new(),
    };
    // If this reached the network it would hang/error in a sandboxed test run;
    // since it must short-circuit before any request, it returns instantly.
    let target = Target::new(TargetKind::Domain, "example.com");
    let result = m.process(&target, &ctx).await.unwrap();
    assert!(result.entities.is_empty());
}

// ── auData_eligibility projection ───────────────────────────────────────────

#[test]
fn registrant_name_becomes_organisation() {
    let body =
        resp(r#"{"auData_eligibility":[{"name":"registrant name","value":"Example Pty Ltd"}]}"#);
    let ents = build_entities(&body, "example.com.au", "s");
    let e = find(&ents, &EntityKind::Organisation, "Example Pty Ltd").expect("registrant org");
    assert!(e.has_tag("au_rdap") && e.has_tag("registrant"));
    assert_eq!(e.confidence, confidence::HIGH_PLUSPLUS);
    assert_eq!(attr(e, "eligibility_field"), Some("registrant name"));
}

#[test]
fn eligibility_id_with_valid_abn_checksum_becomes_abn_acn() {
    // The ATO worked example — a real checksum-valid ABN (see
    // `crate::util::abn::is_valid_abn`'s doctest).
    let body =
        resp(r#"{"auData_eligibility":[{"name":"eligibility id","value":"51 824 753 556"}]}"#);
    let ents = build_entities(&body, "example.com.au", "s");
    let e = find(&ents, &EntityKind::AbnAcn, "51824753556").expect("ABN entity, digits-only");
    assert_eq!(e.confidence, confidence::VERY_HIGH);
    assert!(e.has_tag("abn"));
    // Must NOT also appear as a generic eligibility Other() node.
    assert!(
        !ents
            .iter()
            .any(|e| matches!(&e.kind, EntityKind::Other(k) if k == ELIGIBILITY_KIND))
    );
}

#[test]
fn eligibility_id_that_fails_the_abn_checksum_falls_back_to_generic_metadata() {
    // 11 digits (the source module's ONLY test), but the checksum does not
    // hold — this crate validates the real ATO mod-89 check, unlike the
    // source module's length-only `as_abn`. See module docs.
    let body = resp(r#"{"auData_eligibility":[{"name":"eligibility id","value":"51824753557"}]}"#);
    let ents = build_entities(&body, "example.com.au", "s");
    assert!(
        !ents.iter().any(|e| e.kind == EntityKind::AbnAcn),
        "a checksum-invalid 11-digit value must not be minted as an AbnAcn"
    );
    let e = find(
        &ents,
        &EntityKind::Other(ELIGIBILITY_KIND.to_string()),
        "51824753557",
    )
    .expect("falls back to the generic eligibility node");
    assert_eq!(e.confidence, confidence::MEDIUM_HIGH);
}

#[test]
fn eligibility_id_non_numeric_trademark_number_becomes_generic_metadata() {
    // A trademark-holder eligibility often carries a trademark number rather
    // than an ABN — real registry data, not an ABN.
    let body = resp(r#"{"auData_eligibility":[{"name":"eligibility id","value":"TM 788234"}]}"#);
    let ents = build_entities(&body, "example.com.au", "s");
    assert!(!ents.iter().any(|e| e.kind == EntityKind::AbnAcn));
    let e = find(
        &ents,
        &EntityKind::Other(ELIGIBILITY_KIND.to_string()),
        "TM 788234",
    )
    .expect("trademark number surfaces as generic eligibility metadata");
    assert_eq!(attr(e, "eligibility_field"), Some("eligibility id"));
}

#[test]
fn eligibility_type_and_name_become_generic_metadata_with_field_attribute() {
    let body = resp(
        r#"{"auData_eligibility":[
            {"name":"eligibility type","value":"Trademark Owner"},
            {"name":"eligibility name","value":"EXAMPLE"}
        ]}"#,
    );
    let ents = build_entities(&body, "example.com.au", "s");
    let ty = find(
        &ents,
        &EntityKind::Other(ELIGIBILITY_KIND.to_string()),
        "Trademark Owner",
    )
    .expect("eligibility type");
    assert_eq!(attr(ty, "eligibility_field"), Some("eligibility type"));
    let name = find(
        &ents,
        &EntityKind::Other(ELIGIBILITY_KIND.to_string()),
        "EXAMPLE",
    )
    .expect("eligibility name");
    assert_eq!(attr(name, "eligibility_field"), Some("eligibility name"));
}

#[test]
fn eligibility_field_name_matching_is_case_insensitive() {
    let body =
        resp(r#"{"auData_eligibility":[{"name":"Registrant Name","value":"Mixed Case Pty Ltd"}]}"#);
    let ents = build_entities(&body, "example.com.au", "s");
    assert!(find(&ents, &EntityKind::Organisation, "Mixed Case Pty Ltd").is_some());
}

#[test]
fn unrecognised_eligibility_field_names_are_ignored() {
    let body = resp(r#"{"auData_eligibility":[{"name":"something else","value":"whatever"}]}"#);
    assert!(build_entities(&body, "example.com.au", "s").is_empty());
}

#[test]
fn blank_or_missing_eligibility_values_are_skipped() {
    let body = resp(
        r#"{"auData_eligibility":[
            {"name":"registrant name","value":"   "},
            {"name":"registrant name"}
        ]}"#,
    );
    assert!(build_entities(&body, "example.com.au", "s").is_empty());
}

// ── Registrar + abuse contact ───────────────────────────────────────────────

const REGISTRAR_WITH_ABUSE_JSON: &str = r#"{
  "entities":[{
    "roles":["registrar"],
    "vcardArray":["vcard",[["version",{},"text","4.0"],["fn",{},"text","Example Registrar Pty Ltd"]]],
    "entities":[{
        "roles":["abuse"],
        "vcardArray":["vcard",[["email",{},"text","abuse@registrar.example"]]]
    }]
  }]
}"#;

#[test]
fn registrar_org_extracted_from_vcard_fn() {
    let body = resp(REGISTRAR_WITH_ABUSE_JSON);
    let ents = build_entities(&body, "example.com.au", "s");
    let e = find(
        &ents,
        &EntityKind::Organisation,
        "Example Registrar Pty Ltd",
    )
    .expect("registrar org");
    assert!(e.has_tag("au_rdap") && e.has_tag("registrar"));
    assert_eq!(e.confidence, confidence::HIGH_PLUS);
}

#[test]
fn abuse_email_extracted_from_nested_vcard() {
    let body = resp(REGISTRAR_WITH_ABUSE_JSON);
    let ents = build_entities(&body, "example.com.au", "s");
    let e = find(&ents, &EntityKind::Email, "abuse@registrar.example").expect("abuse email");
    assert!(e.has_tag("au_rdap") && e.has_tag("abuse-contact"));
    assert_eq!(e.confidence, confidence::HIGH);
}

#[test]
fn non_registrar_role_does_not_yield_an_organisation() {
    let body = resp(
        r#"{"entities":[{
            "roles":["technical"],
            "vcardArray":["vcard",[["fn",{},"text","Some Tech Contact"]]]
        }]}"#,
    );
    let ents = build_entities(&body, "example.com.au", "s");
    assert!(!ents.iter().any(|e| e.kind == EntityKind::Organisation));
}

#[test]
fn non_abuse_role_child_does_not_yield_an_email() {
    let body = resp(
        r#"{"entities":[{
            "roles":["registrar"],
            "vcardArray":["vcard",[["fn",{},"text","Example Registrar"]]],
            "entities":[{
                "roles":["technical"],
                "vcardArray":["vcard",[["email",{},"text","tech@registrar.example"]]]
            }]
        }]}"#,
    );
    let ents = build_entities(&body, "example.com.au", "s");
    assert!(!ents.iter().any(|e| e.kind == EntityKind::Email));
}

#[test]
fn registrar_entity_with_no_own_vcard_skips_its_abuse_child_too() {
    // The preserved source quirk (see module docs): the outer entity's own
    // `vcardArray` gates whether its nested children are inspected AT ALL, even
    // though the nested "abuse" child here carries a perfectly good vCard of
    // its own. This pins that behaviour so a future change to it is a visible,
    // deliberate decision rather than a silent regression.
    let body = resp(
        r#"{"entities":[{
            "roles":["registrar"],
            "entities":[{
                "roles":["abuse"],
                "vcardArray":["vcard",[["email",{},"text","abuse@registrar.example"]]]
            }]
        }]}"#,
    );
    let ents = build_entities(&body, "example.com.au", "s");
    assert!(
        ents.is_empty(),
        "the outer entity has no vCard, so its abuse child must not be reached either: {ents:?}"
    );
}

// ── Nameservers ──────────────────────────────────────────────────────────────

#[test]
fn nameservers_become_domain_entities() {
    let body = resp(
        r#"{"nameservers":[{"ldhName":"ns1.example.com.au"},{"ldhName":"ns2.example.com.au"}]}"#,
    );
    let ents = build_entities(&body, "example.com.au", "s");
    let a = find(&ents, &EntityKind::Domain, "ns1.example.com.au").expect("ns1");
    assert!(a.has_tag("au_rdap") && a.has_tag("nameserver"));
    assert_eq!(a.confidence, confidence::VERY_HIGH);
    assert!(find(&ents, &EntityKind::Domain, "ns2.example.com.au").is_some());
}

#[test]
fn blank_nameserver_name_is_skipped() {
    let body = resp(r#"{"nameservers":[{"ldhName":"   "},{"ldhName":"ns1.example.com.au"}]}"#);
    let ents = build_entities(&body, "example.com.au", "s");
    assert_eq!(ents.len(), 1);
    assert_eq!(ents[0].value, "ns1.example.com.au");
}

#[test]
fn duplicate_nameserver_entries_are_deduplicated() {
    let body = resp(
        r#"{"nameservers":[{"ldhName":"ns1.example.com.au"},{"ldhName":"ns1.example.com.au"}]}"#,
    );
    let ents = build_entities(&body, "example.com.au", "s");
    assert_eq!(ents.len(), 1, "a repeated nameserver must not double-count");
}

#[test]
fn nameserver_count_is_capped() {
    let list = (0..(MAX_NAMESERVERS + 10))
        .map(|i| format!(r#"{{"ldhName":"ns{i}.example.com.au"}}"#))
        .collect::<Vec<_>>()
        .join(",");
    let body = resp(&format!(r#"{{"nameservers":[{list}]}}"#));
    let ents = build_entities(&body, "example.com.au", "s");
    assert_eq!(ents.len(), MAX_NAMESERVERS);
}

// ── Empty / whole-response projection ───────────────────────────────────────

#[test]
fn empty_response_yields_nothing() {
    let body = resp("{}");
    assert!(build_entities(&body, "example.com.au", "s").is_empty());
}

#[test]
fn full_response_projects_every_category_and_stays_deterministic() {
    let body = resp(
        r#"{
            "auData_eligibility":[
                {"name":"registrant name","value":"Example Pty Ltd"},
                {"name":"eligibility type","value":"Trademark Owner"},
                {"name":"eligibility id","value":"51 824 753 556"}
            ],
            "entities":[{
                "roles":["registrar"],
                "vcardArray":["vcard",[["fn",{},"text","Example Registrar Pty Ltd"]]],
                "entities":[{
                    "roles":["abuse"],
                    "vcardArray":["vcard",[["email",{},"text","abuse@registrar.example"]]]
                }]
            }],
            "nameservers":[{"ldhName":"ns1.example.com.au"},{"ldhName":"ns2.example.com.au"}]
        }"#,
    );

    let a = build_entities(&body, "example.com.au", "s");
    let b = build_entities(&body, "example.com.au", "s");
    assert_eq!(
        a.iter()
            .map(|e| (e.kind.clone(), e.value.clone()))
            .collect::<Vec<_>>(),
        b.iter()
            .map(|e| (e.kind.clone(), e.value.clone()))
            .collect::<Vec<_>>(),
        "identical input must yield an identical projection"
    );

    assert!(find(&a, &EntityKind::Organisation, "Example Pty Ltd").is_some());
    assert!(find(&a, &EntityKind::Organisation, "Example Registrar Pty Ltd").is_some());
    assert!(find(&a, &EntityKind::AbnAcn, "51824753556").is_some());
    assert!(
        find(
            &a,
            &EntityKind::Other(ELIGIBILITY_KIND.to_string()),
            "Trademark Owner"
        )
        .is_some()
    );
    assert!(find(&a, &EntityKind::Email, "abuse@registrar.example").is_some());
    assert!(find(&a, &EntityKind::Domain, "ns1.example.com.au").is_some());
    assert!(find(&a, &EntityKind::Domain, "ns2.example.com.au").is_some());
    // Two distinct Organisation entities (registrant vs registrar) survive —
    // they must not collide even though both are `Organisation`.
    assert_eq!(
        a.iter()
            .filter(|e| e.kind == EntityKind::Organisation)
            .count(),
        2
    );
}
