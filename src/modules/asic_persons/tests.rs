use super::*;

/// Real Banned & Disqualified Persons record shape.
const BANNED: &str = r##"{
  "BD_PER_NAME":"ABBOTT, BILL","BD_PER_TYPE":"Banned Securities",
  "BD_PER_START_DT":"29/03/1994","BD_PER_END_DT":"29/03/1999",
  "BD_PER_DOC_NUM":"#004289112","BD_PER_ADD_LOCAL":"TEMPLESTOWE LOWER",
  "BD_PER_ADD_STATE":"VIC","BD_PER_ADD_PCODE":"3107","BD_PER_COMMENTS":"No comment made"}"##;

/// Financial Advisers record shape (no disciplinary action).
const ADVISER: &str = r#"{
  "ADV_NAME":"CITIZEN, JANE","ADV_ROLE":"Authorised Representative",
  "OVERALL_REGISTRATION_STATUS":"Current","ADV_NUMBER":"123456",
  "LICENCE_NAME":"Acme Financial Pty Ltd","LICENCE_NUMBER":"234567",
  "ADV_ABN":"12 345 678 901","LICENCE_ABN":"98765432109",
  "ADV_ADD_LOCAL":"SYDNEY","ADV_ADD_STATE":"NSW","ADV_ADD_PCODE":"2000",
  "ADV_DA_TYPE":"","ADV_DA_DESCRIPTION":""}"#;

fn rec(json: &str) -> Map<String, Value> {
    serde_json::from_str(json).unwrap()
}

#[test]
fn banned_emits_adverse_person_and_address() {
    let mut r = ModuleResult::new();
    emit_banned(&rec(BANNED), "scan", &mut r);
    let e = &r.entities;

    let p = e
        .iter()
        .find(|x| x.kind == EntityKind::Person)
        .expect("person");
    assert_eq!(p.value, "Bill Abbott"); // reordered + title-cased
    assert!(p.has_tag("asic-banned") && p.has_tag("regulatory-action"));
    assert!(p.evidence.iter().any(|ev| ev
        .attributes
        .get("ban_type")
        .is_some_and(|v| v == "Banned Securities")));
    // Registered address pivot.
    assert!(e.iter().any(|x| x.kind == EntityKind::Address
        && x.value.eq_ignore_ascii_case("TEMPLESTOWE LOWER VIC 3107")));
}

#[test]
fn adviser_emits_person_licensee_abns_and_address() {
    let mut r = ModuleResult::new();
    emit_adviser(&rec(ADVISER), "scan", &mut r);
    let e = &r.entities;

    let p = e
        .iter()
        .find(|x| x.kind == EntityKind::Person)
        .expect("person");
    assert_eq!(p.value, "Jane Citizen");
    assert!(p.has_tag("asic-financial-adviser"));
    assert!(!p.has_tag("disciplinary-action")); // no DA in this record

    // Licensee employer → Organisation pivot.
    assert!(e.iter().any(|x| x.kind == EntityKind::Organisation
        && x.value == "Acme Financial Pty Ltd"
        && x.has_tag("afs-licensee")));
    // Both ABNs (adviser + licensee) as AbnAcn pivots.
    let abns: Vec<String> = e
        .iter()
        .filter(|x| x.kind == EntityKind::AbnAcn)
        .map(|x| x.value.chars().filter(char::is_ascii_digit).collect())
        .collect();
    assert!(abns.contains(&"12345678901".to_string()));
    assert!(abns.contains(&"98765432109".to_string()));
    // Registered address — now tagged with its AU jurisdiction and inline-geocoded
    // so it reaches the AU geo correlators like every other AU register module.
    let addr = e
        .iter()
        .find(|x| x.kind == EntityKind::Address && x.value.eq_ignore_ascii_case("SYDNEY NSW 2000"))
        .expect("registered address");
    assert!(
        addr.has_tag("au-state:NSW") && addr.has_tag("country:AU"),
        "register address must carry its AU jurisdiction"
    );
    assert!(
        e.iter()
            .any(|x| x.kind == EntityKind::Coordinates && x.has_tag("au-state:NSW")),
        "the register address must inline-geocode to an AU Coordinates anchor"
    );
}

#[test]
fn adviser_with_disciplinary_action_is_flagged() {
    let mut m = rec(ADVISER);
    m.insert("ADV_DA_TYPE".into(), Value::String("Banning Order".into()));
    m.insert(
        "ADV_DA_DESCRIPTION".into(),
        Value::String("Banned for 3 years".into()),
    );
    let mut r = ModuleResult::new();
    emit_adviser(&m, "scan", &mut r);
    let p = r
        .entities
        .iter()
        .find(|x| x.kind == EntityKind::Person)
        .unwrap();
    assert!(p.has_tag("regulatory-action") && p.has_tag("disciplinary-action"));
    assert!(p.evidence.iter().any(|ev| ev.attributes.contains_key("disciplinary_action")));
}

// Real-shaped adviser record with a corporate controller chain and a distinct
// authorised-rep firm — modelled on the live data.gov.au dataset (e.g. an
// adviser under a wealth-group licensee controlled by a major bank, appointed
// through the group's own AR company with its own ABN).
const ADVISER_LINKED: &str = r#"{
  "ADV_NAME":"POPOV, MARSEL","ADV_ROLE":"Authorised Representative",
  "OVERALL_REGISTRATION_STATUS":"Current",
  "LICENCE_NAME":"VIRIDIAN ADVISORY PTY LTD","LICENCE_NUMBER":"34605438042",
  "LICENCE_CONTROLLED_BY":"NATIONAL AUSTRALIA BANK LIMITED [Date Ceased: 21/08/2023] ~ MLC WEALTH LIMITED",
  "REP_APPOINTED_BY":"VIRIDIAN FINANCIAL GROUP LTD","REP_APPOINTED_NUM":"000315094",
  "REP_APPOINTED_ABN":"67 605 994 741"}"#;

#[test]
fn adviser_emits_licensee_controllers_and_distinct_appointer() {
    let mut r = ModuleResult::new();
    emit_adviser(&rec(ADVISER_LINKED), "scan", &mut r);
    let e = &r.entities;

    let orgs: Vec<&Entity> = e.iter().filter(|x| x.kind == EntityKind::Organisation).collect();
    let org_named = |name: &str| orgs.iter().find(|o| o.value == name).copied();

    // The AFS licensee itself.
    assert!(org_named("VIRIDIAN ADVISORY PTY LTD").unwrap().has_tag("afs-licensee"));

    // Both controllers of the licensee, one current, one ceased.
    let nab = org_named("NATIONAL AUSTRALIA BANK LIMITED").expect("current-then-ceased controller");
    assert!(nab.has_tag("afs-licensee-controller") && nab.has_tag("ceased"));
    assert!(nab.evidence[0]
        .attributes
        .get("date_ceased")
        .is_some_and(|d| d == "21/08/2023"));
    let mlc = org_named("MLC WEALTH LIMITED").expect("second controller");
    assert!(mlc.has_tag("afs-licensee-controller") && !mlc.has_tag("ceased"));

    // The distinct corporate authorised-rep firm (differs from person + licensee).
    let appointer = org_named("VIRIDIAN FINANCIAL GROUP LTD").expect("appointing firm");
    assert!(appointer.has_tag("authorised-rep-firm"));
    assert!(appointer.evidence[0]
        .attributes
        .get("authorised_rep_no")
        .is_some_and(|n| n == "000315094"));

    // The appointing firm's ABN is emitted alongside the adviser/licensee ABNs.
    let abns: Vec<String> = e
        .iter()
        .filter(|x| x.kind == EntityKind::AbnAcn)
        .map(|x| x.value.chars().filter(char::is_ascii_digit).collect())
        .collect();
    assert!(abns.contains(&"67605994741".to_string()), "rep_appointer ABN");
}

#[test]
fn self_appointment_and_licensee_appointer_are_not_separate_firms() {
    // REP_APPOINTED_BY == the adviser (self-appointment) → no appointer Org.
    let mut m = rec(ADVISER);
    m.insert("REP_APPOINTED_BY".into(), Value::String("CITIZEN, JANE".into()));
    let mut r = ModuleResult::new();
    emit_adviser(&m, "scan", &mut r);
    assert!(
        !r.entities.iter().any(|x| x.has_tag("authorised-rep-firm")),
        "a self-appointment must not surface as an appointing firm"
    );

    // REP_APPOINTED_BY == the licensee → no separate appointer Org (already
    // captured as the afs-licensee).
    let mut m2 = rec(ADVISER);
    m2.insert(
        "REP_APPOINTED_BY".into(),
        Value::String("Acme Financial Pty Ltd".into()),
    );
    let mut r2 = ModuleResult::new();
    emit_adviser(&m2, "scan", &mut r2);
    assert!(
        !r2.entities.iter().any(|x| x.has_tag("authorised-rep-firm")),
        "an appointer equal to the licensee must not be duplicated as a firm"
    );
}

#[test]
fn individual_controller_is_typed_as_person_not_org() {
    // A small firm's controlling principal is a natural person, not a company —
    // it must surface as a Person (humanised), never an Organisation, so it
    // feeds person-oriented correlators correctly.
    let mut m = rec(ADVISER);
    m.insert(
        "LICENCE_CONTROLLED_BY".into(),
        Value::String("MELISSA  GOODIN".into()),
    );
    let mut r = ModuleResult::new();
    emit_adviser(&m, "scan", &mut r);

    let controller = r
        .entities
        .iter()
        .find(|x| x.has_tag("afs-licensee-controller"))
        .expect("controller entity");
    assert_eq!(controller.kind, EntityKind::Person);
    assert_eq!(controller.value, "Melissa Goodin"); // humanised, whitespace collapsed
    assert!(
        !r.entities
            .iter()
            .any(|x| x.kind == EntityKind::Organisation && x.has_tag("afs-licensee-controller")),
        "an individual controller must not be an Organisation"
    );
}

#[test]
fn parse_controllers_splits_and_strips_ceased_markers() {
    let parsed = parse_controllers(
        "NATIONAL AUSTRALIA BANK LIMITED [Date Ceased: 21/08/2023] ~ MLC WEALTH LIMITED [Date Ceased: 20/05/2021]",
    );
    assert_eq!(parsed.len(), 2);
    assert_eq!(parsed[0].0, "NATIONAL AUSTRALIA BANK LIMITED");
    assert_eq!(parsed[0].1.as_deref(), Some("21/08/2023"));
    assert_eq!(parsed[1].0, "MLC WEALTH LIMITED");
    assert_eq!(parsed[1].1.as_deref(), Some("20/05/2021"));

    // A single current controller with no marker.
    let one = parse_controllers("SOME PARENT PTY LTD");
    assert_eq!(one, vec![("SOME PARENT PTY LTD".to_string(), None)]);

    // Blank / too-short fragments are dropped.
    assert!(parse_controllers("  ~  ~ AB").is_empty());
}

/// Credit Representative record (mortgage/finance broker).
const CREDIT: &str = r#"{
  "CRED_REP_NAME":"SMITH, JOHN ANDREW","CRED_REP_NUM":"563552","CRED_LIC_NUM":"385487",
  "CRED_REP_ABN_ACN":"12345678901","CRED_REP_START_DT":"30/10/2024",
  "CRED_REP_LOCALITY":"BERWICK","CRED_REP_STATE":"VIC","CRED_REP_PCODE":"3806","CRED_REP_EDRS":"AFCA"}"#;

#[test]
fn credit_rep_emits_person_abn_and_address() {
    let mut r = ModuleResult::new();
    emit_credit_rep(&rec(CREDIT), "scan", &mut r);
    let e = &r.entities;
    let p = e
        .iter()
        .find(|x| x.kind == EntityKind::Person)
        .expect("person");
    assert_eq!(p.value, "John Andrew Smith");
    assert!(p.has_tag("asic-credit-rep"));
    assert!(p.evidence.iter().any(|ev| ev
        .attributes
        .get("credit_licence_no")
        .is_some_and(|v| v == "385487")));
    assert!(e.iter().any(|x| x.kind == EntityKind::AbnAcn
        && x.value.chars().filter(char::is_ascii_digit).collect::<String>() == "12345678901"));
    assert!(e.iter().any(|x| x.kind == EntityKind::Address
        && x.value.eq_ignore_ascii_case("BERWICK VIC 3806")));
}

#[test]
fn name_matching_is_order_independent_and_token_complete() {
    let tokens = name_tokens("Bill Abbott");
    assert_eq!(tokens, vec!["bill".to_string(), "abbott".to_string()]);
    assert!(record_name_matches(&rec(BANNED), "BD_PER_NAME", &tokens));
    // A different person must not match.
    let other = name_tokens("John Smith");
    assert!(!record_name_matches(&rec(BANNED), "BD_PER_NAME", &other));
    // Single-token names are too ambiguous (filtered upstream).
    assert_eq!(name_tokens("Madonna").len(), 1);
}

#[test]
fn humanise_name_reorders_and_titlecases() {
    assert_eq!(humanise_name("ABBOTT, BILL"), "Bill Abbott");
    assert_eq!(humanise_name("CITIZEN, JANE MARY"), "Jane Mary Citizen");
    assert_eq!(humanise_name("Jane Citizen"), "Jane Citizen");
}

#[tokio::test]
async fn single_token_name_makes_no_request() {
    // One token → returns before any network I/O (offline in CI).
    let (bus, _rx) = tokio::sync::broadcast::channel(1);
    let ctx = ModuleContext {
        scan_id: "t".into(),
        bus,
        http: reqwest::Client::new(),
        keys: std::collections::HashMap::new(),
        cancel: crate::core::cancel::CancelHandle::new(),
    };
    let r = AsicPersons
        .process(&Target::new(TargetKind::FullName, "Madonna"), &ctx)
        .await
        .expect("single-token name is a clean no-op");
    assert!(r.entities.is_empty());
}

#[test]
fn is_free_keyless_corporate_module() {
    let m = AsicPersons;
    assert!(matches!(m.cost(), crate::core::module::ModuleCost::Free));
    assert_eq!(m.category(), ModuleCategory::Corporate);
    assert!(!m.attack_techniques().is_empty());
    assert!(m.accepts(&Target::new(TargetKind::FullName, "Jane Citizen")));
    assert!(!m.accepts(&Target::new(TargetKind::Email, "a@b.com")));
}

/// Live end-to-end proof against the REAL ASIC open dataset — no mock. Ignored
/// by default (network); run with
/// `cargo test -p huntsman-search-engine asic_persons_live -- --ignored --nocapture`.
#[tokio::test]
#[ignore = "hits the live data.gov.au ASIC datastore; run manually"]
async fn asic_persons_live_finds_a_banned_person() {
    let (bus, _rx) = tokio::sync::broadcast::channel(1);
    let ctx = ModuleContext {
        scan_id: "live".into(),
        bus,
        http: reqwest::Client::new(),
        keys: std::collections::HashMap::new(),
        cancel: crate::core::cancel::CancelHandle::new(),
    };
    // A long-standing public entry in the Banned & Disqualified register.
    let r = AsicPersons
        .process(&Target::new(TargetKind::FullName, "Bill Abbott"), &ctx)
        .await
        .expect("live ASIC query must not error");
    eprintln!("asic_persons live (Bill Abbott): {} entities", r.entities.len());
    for e in &r.entities {
        eprintln!("  {:?} {} {:?}", e.kind, e.value, e.tags);
    }
    assert!(
        r.entities
            .iter()
            .any(|e| e.kind == EntityKind::Person && e.has_tag("asic-banned")),
        "expected the banned-person finding from the live register"
    );
}
