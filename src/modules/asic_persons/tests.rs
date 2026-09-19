use super::*;

/// Real Banned & Disqualified Persons record shape.
const BANNED: &str = r##"{
  "BD_PER_NAME":"ABBOTT, BILL","BD_PER_TYPE":"Banned Securities",
  "BD_PER_START_DT":"29/03/1994","BD_PER_END_DT":"29/03/1999",
  "BD_PER_DOC_NUM":"#004289112","BD_PER_ADD_LOCAL":"TEMPLESTOWE LOWER",
  "BD_PER_ADD_STATE":"VIC","BD_PER_ADD_PCODE":"3107","BD_PER_COMMENTS":"No comment made"}"##;

/// Financial Advisers record shape (no disciplinary action). The ABNs are
/// real checksum-valid numbers (ATO worked examples), not mere 11-digit
/// placeholders — `is_valid_abn` rejects a digit run that merely has the
/// right length, so a placeholder like the old "12 345 678 901" would now
/// fail validation and silently vanish from every assertion below.
const ADVISER: &str = r#"{
  "ADV_NAME":"CITIZEN, JANE","ADV_ROLE":"Authorised Representative",
  "OVERALL_REGISTRATION_STATUS":"Current","ADV_NUMBER":"123456",
  "LICENCE_NAME":"Acme Financial Pty Ltd","LICENCE_NUMBER":"234567",
  "ADV_ABN":"51 824 753 556","LICENCE_ABN":"53004085616",
  "ADV_ADD_LOCAL":"SYDNEY","ADV_ADD_STATE":"NSW","ADV_ADD_PCODE":"2000",
  "ADV_DA_TYPE":"","ADV_DA_DESCRIPTION":""}"#;

fn rec(json: &str) -> Map<String, Value> {
    serde_json::from_str(json).expect("should succeed")
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
    assert!(abns.contains(&"51824753556".to_string()));
    assert!(abns.contains(&"53004085616".to_string()));
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
fn two_registers_geocoding_to_the_same_point_dedup_to_one_coordinates_entity() {
    // Regression: `city_coords` is a many-to-one phrase lookup, so two
    // differently-worded registered addresses (one banned-persons record, one
    // financial-adviser record — the same shared `push_address` helper, no
    // gate of any kind) both naming Sydney independently resolved to the
    // identical centroid. `process()`'s live CKAN fetch isn't independently
    // testable here, so this calls the same pure `emit_banned`/`emit_adviser`
    // functions `process()` calls, into ONE shared `ModuleResult` (mirroring
    // its 3 loops sharing one `result`), followed by the same
    // `dedup_merge_entities` call `process()` now makes before returning.
    let banned = rec(r#"{"BD_PER_NAME":"ABBOTT, BILL","BD_PER_TYPE":"Banned Securities",
        "BD_PER_ADD_LOCAL":"SYDNEY","BD_PER_ADD_STATE":"NSW","BD_PER_ADD_PCODE":"2000"}"#);
    let adviser = rec(r#"{"ADV_NAME":"CITIZEN, JANE","ADV_ROLE":"Authorised Representative",
        "OVERALL_REGISTRATION_STATUS":"Current","ADV_ADD_LOCAL":"Sydney CBD","ADV_ADD_STATE":"NSW"}"#);
    let mut r = ModuleResult::new();
    emit_banned(&banned, "scan", &mut r);
    emit_adviser(&adviser, "scan", &mut r);
    let raw_coords = r
        .entities
        .iter()
        .filter(|e| e.kind == EntityKind::Coordinates)
        .count();
    assert_eq!(
        raw_coords, 2,
        "sanity: two differently-worded Sydney addresses must both resolve via city_coords, or this fixture doesn't exercise the bug"
    );
    crate::core::entity::dedup_merge_entities(&mut r.entities);
    let coords = r
        .entities
        .iter()
        .filter(|e| e.kind == EntityKind::Coordinates)
        .count();
    assert_eq!(
        coords, 1,
        "two registers' addresses resolving to the same point must dedup to one Coordinates entity: {:?}",
        r.entities
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
        .expect("should succeed");
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
    assert!(org_named("VIRIDIAN ADVISORY PTY LTD").expect("should succeed").has_tag("afs-licensee"));

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

/// Credit Representative record (mortgage/finance broker). `CRED_REP_ABN_ACN`
/// is a real checksum-valid ACN (the ASIC worked example embedded in ABN
/// "53 004 085 616"), exercising the 9-digit ACN branch rather than only ever
/// the 11-digit ABN branch.
const CREDIT: &str = r#"{
  "CRED_REP_NAME":"SMITH, JOHN ANDREW","CRED_REP_NUM":"563552","CRED_LIC_NUM":"385487",
  "CRED_REP_ABN_ACN":"004085616","CRED_REP_START_DT":"30/10/2024",
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
        && x.value.chars().filter(char::is_ascii_digit).collect::<String>() == "004085616"));
    assert!(e.iter().any(|x| x.kind == EntityKind::Address
        && x.value.eq_ignore_ascii_case("BERWICK VIC 3806")));
}

#[test]
fn checksum_invalid_abn_or_acn_is_not_emitted_as_a_pivot() {
    // "11111111111"/"111111111" have the right digit *count* (11 / 9) but fail
    // the ATO mod-89 / ASIC check-digit checksum (util::abn::is_valid_abn /
    // is_valid_acn) — ASIC's own export can carry a data-entry typo, and a
    // mere digit count must not be trusted as a real ABN/ACN pivot.
    let mut adv = rec(ADVISER);
    adv.insert("ADV_ABN".into(), Value::String("11111111111".into()));
    let mut r = ModuleResult::new();
    emit_adviser(&adv, "scan", &mut r);
    assert!(
        !r.entities.iter().any(|x| x.kind == EntityKind::AbnAcn
            && x.value.chars().filter(char::is_ascii_digit).collect::<String>() == "11111111111"),
        "a checksum-invalid ABN must not be emitted as a pivot"
    );
    // The licensee's genuinely valid ABN is unaffected.
    assert!(r.entities.iter().any(|x| x.kind == EntityKind::AbnAcn
        && x.value.chars().filter(char::is_ascii_digit).collect::<String>() == "53004085616"));

    let mut cred = rec(CREDIT);
    cred.insert("CRED_REP_ABN_ACN".into(), Value::String("111111111".into()));
    let mut r2 = ModuleResult::new();
    emit_credit_rep(&cred, "scan", &mut r2);
    assert!(
        !r2.entities.iter().any(|x| x.kind == EntityKind::AbnAcn),
        "a checksum-invalid ACN must not be emitted as a pivot"
    );
}

#[test]
fn name_matching_is_order_independent_and_token_complete() {
    let tokens = name_tokens("Bill Abbott");
    assert_eq!(tokens, vec!["bill".to_string(), "abbott".to_string()]);
    assert!(record_name_matches(&rec(BANNED), "BD_PER_NAME", "Bill Abbott"));
    // A different person must not match.
    assert!(!record_name_matches(&rec(BANNED), "BD_PER_NAME", "John Smith"));
    // Single-token names are too ambiguous (filtered upstream).
    assert_eq!(name_tokens("Madonna").len(), 1);
}

#[test]
fn name_matching_is_whole_word_not_substring() {
    // Regression: a raw `.contains()` token check let a short query token land
    // as a SUBSTRING of an unrelated name — "al" inside "Alexandra", "green"
    // inside "Greenwood" — attributing a completely different real person's
    // ban/licensee/disciplinary record to the queried name.
    let greenwood = rec(r##"{"BD_PER_NAME":"GREENWOOD, ALEXANDRA"}"##);
    assert!(
        !record_name_matches(&greenwood, "BD_PER_NAME", "Al Green"),
        "\"al\"/\"green\" must not match as substrings of \"Alexandra\"/\"Greenwood\""
    );
    // The whole-word counterpart must still match.
    assert!(record_name_matches(&greenwood, "BD_PER_NAME", "Alexandra Greenwood"));
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

// ── REQ-ASICPERSONS-001: a name match is not an identification ──────────────
//
// All three registers are selected by `record_name_matches` alone: the CKAN
// query is full-text and the predicate only requires the row to share the
// seed's whole-word tokens, order-independent. None of the three datasets
// publishes a date of birth. So for a seed like "John Smith" a DIFFERENT real
// John Smith's ban, disqualification or disciplinary action matched, and was
// emitted carrying `asic-banned` / `regulatory-action` with nothing marking it
// as unverified — a reputationally severe finding about a real person, fused
// onto the subject.
//
// The contract is the one every sibling name-matched register already keeps
// (`sanctions_ofac`, `openarch`, `austlii`, `trove_au`, `europeana`, `ahmia`):
// the `needs-identity-verification` tag plus an explicit evidence `caution`.
// Deliberately NOT `tags::CANDIDATE`, which this codebase reserves for a known
// non-match / off-region / synthetic value and which caps confidence — the
// register hit is real, it is the IDENTIFICATION that is unproven.

#[test]
fn every_emitted_entity_carries_the_name_only_identity_contract() {
    // The whole result set, not just the Person: the registered Address is a
    // stranger's home locality on a namesake match, and the licensee
    // Organisation / AbnAcn are that stranger's employer.
    let mut r = ModuleResult::new();
    emit_banned(&rec(BANNED), "scan", &mut r);
    emit_adviser(&rec(ADVISER), "scan", &mut r);
    super::flag_name_only_match(&mut r);

    assert!(
        !r.entities.is_empty(),
        "fixtures must produce entities or this test is vacuous"
    );
    for e in &r.entities {
        assert!(
            e.has_tag("needs-identity-verification"),
            "{:?} {} was matched by name alone and must say so",
            e.kind,
            e.value
        );
    }
}

#[test]
fn the_adverse_finding_and_the_address_both_carry_an_identity_caution() {
    let mut r = ModuleResult::new();
    emit_banned(&rec(BANNED), "scan", &mut r);

    let person = r
        .entities
        .iter()
        .find(|x| x.kind == EntityKind::Person)
        .expect("person");
    assert!(
        person
            .evidence
            .iter()
            .any(|ev| ev.attributes.get("caution").is_some_and(|c| c
                .contains("Name-only match"))),
        "a ban attributed by name alone must carry the identity caution"
    );

    let addr = r
        .entities
        .iter()
        .find(|x| x.kind == EntityKind::Address)
        .expect("address");
    assert!(
        addr.evidence
            .iter()
            .any(|ev| ev.attributes.get("caution").is_some_and(|c| c
                .contains("Name-only match"))),
        "the register address is a stranger's locality on a namesake match — \
         it must carry the caution too"
    );
}

#[test]
fn the_contract_is_not_the_candidate_quarantine() {
    // `tags::CANDIDATE` is enforced (held out of exports, timeline, correlator,
    // exposure) and caps confidence at 0.25. An ASIC register hit is a REAL
    // register row, so quarantining it would discard a true finding; only the
    // identification is unproven. Locking the distinction so a future change
    // doesn't "upgrade" this to the quarantine and silently drop AU register
    // findings out of every shareable view.
    let mut r = ModuleResult::new();
    emit_banned(&rec(BANNED), "scan", &mut r);
    super::flag_name_only_match(&mut r);

    for e in &r.entities {
        assert!(
            !e.has_tag(crate::core::tags::CANDIDATE),
            "{} must stay in the confirmed view, flagged — not quarantined",
            e.value
        );
    }
}
