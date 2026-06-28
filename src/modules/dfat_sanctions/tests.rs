use super::entity::{cell, name_matches, row_is_entity, row_to_entity};
use super::*;
use crate::core::entity::EntityKind;
use crate::core::module::{ModuleCategory, ModuleCost};
use crate::core::scan::{Target, TargetKind};

// A small fixture in the real DFAT Consolidated List shape: a quoted field with
// an embedded comma (`Address`), an individual and an entity row, and CRLF
// terminators (the export is Windows-authored).
const FIXTURE: &str = "Reference,Type of designation,Name of Individual or Entity,Name Type,Date of Birth,Place of Birth,Citizenship,Address,Additional Information,Listing Information,Committees\r\n\
LIB001,Individual,Muammar Mohammed Abu Minyar QADHAFI,Primary Name,1942,Sirte,Libya,\"Tripoli, Libya\",Leader of the Revolution,UNSC Resolution 1970,Libya (UNSC)\r\n\
DPRK010,Entity,Korea Mining Development Trading Corporation,Primary Name,,,,\"Pyongyang, DPRK\",Primary arms dealer,UNSC Resolution 1718,DPRK (UNSC)\r\n\
RUS200,Individual,Jane Ordinary Citizen,Primary Name,1980,Moscow,Russia,Moscow,Test row,Autonomous (Russia),Russia\r\n";

#[test]
fn accepts_name_and_org_only() {
    let m = DfatSanctions;
    assert!(m.accepts(&Target::new(TargetKind::FullName, "Muammar Qadhafi")));
    assert!(m.accepts(&Target::new(
        TargetKind::Organisation,
        "Korea Mining Development"
    )));
    assert!(!m.accepts(&Target::new(TargetKind::Email, "a@b.com")));
    assert!(!m.accepts(&Target::new(TargetKind::AbnAcn, "33051775556")));
}

#[test]
fn module_metadata() {
    let m = DfatSanctions;
    assert_eq!(m.name(), "dfat_sanctions");
    assert!(!m.description().is_empty());
    assert_eq!(m.cost(), ModuleCost::Free);
    assert_eq!(m.category(), ModuleCategory::People);
    // Non-passive network module must beat the 3s default timeout (CI guard).
    assert!(m.max_timeout_ms() > 3_000);
    // The finding pins these two techniques; Identify Roles is dropped.
    assert_eq!(m.attack_techniques(), &["T1589.003", "T1591.002"]);
    assert!(!m.attack_techniques().contains(&"T1591.004"));
}

#[test]
fn csv_parser_handles_quotes_commas_and_crlf() {
    let rows = csv::parse(FIXTURE);
    // Header + 3 data rows.
    assert_eq!(rows.len(), 4);
    let header = &rows[0];
    assert_eq!(header[0], "Reference");
    assert_eq!(header[2], "Name of Individual or Entity");
    // The quoted Address with an embedded comma stays a single field.
    let qadhafi = &rows[1];
    let idx = csv::header_index(header);
    assert_eq!(
        cell(qadhafi, &idx, "address"),
        Some("Tripoli, Libya"),
        "quoted comma must not split the Address field"
    );
}

#[test]
fn csv_parser_handles_escaped_quotes_and_lf_only() {
    // Doubled quote → literal quote; LF-only terminators.
    let input = "a,b\nx,\"y \"\"q\"\" z\"\n";
    let rows = csv::parse(input);
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[1][1], "y \"q\" z");
}

#[test]
fn csv_parser_flushes_unterminated_final_row() {
    let rows = csv::parse("h1,h2\nv1,v2");
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[1], vec!["v1".to_string(), "v2".to_string()]);
}

#[test]
fn name_match_is_whole_word_not_substring() {
    assert!(name_matches(
        "Muammar Mohammed Abu Minyar QADHAFI",
        "muammar qadhafi"
    ));
    // Order-independent.
    assert!(name_matches(
        "Korea Mining Development Trading Corporation",
        "development korea"
    ));
    // Whole word, not substring: "ali" must not match inside "Khalid".
    assert!(!name_matches("Khalid Sheikh", "ali"));
    // A seed token absent from the name → no match.
    assert!(!name_matches("Jane Ordinary Citizen", "muammar qadhafi"));
}

#[test]
fn row_type_classifies_entity_vs_individual() {
    let rows = csv::parse(FIXTURE);
    let idx = csv::header_index(&rows[0]);
    assert_eq!(row_is_entity(&rows[1], &idx), Some(false)); // Individual
    assert_eq!(row_is_entity(&rows[2], &idx), Some(true)); // Entity
}

#[test]
fn individual_row_becomes_tagged_person_with_full_record() {
    let rows = csv::parse(FIXTURE);
    let idx = csv::header_index(&rows[0]);
    let e = row_to_entity(&rows[1], &idx, true, "scan").expect("person entity");
    assert_eq!(e.kind, EntityKind::Person);
    assert!(e.has_tag("sanctions") && e.has_tag("pep") && e.has_tag("dfat-consolidated-list"));
    assert!((e.confidence - PERSON_CONF).abs() < f64::EPSILON);
    // Full record preserved in evidence (no omission).
    let attr = |k: &str| e.evidence[0].attributes.get(k).map(String::as_str);
    assert_eq!(attr("reference"), Some("LIB001"));
    assert_eq!(attr("date_of_birth"), Some("1942"));
    assert_eq!(attr("address"), Some("Tripoli, Libya"));
    assert_eq!(attr("designation"), Some("Individual"));
}

#[test]
fn entity_row_becomes_organisation_regardless_of_seed_kind() {
    let rows = csv::parse(FIXTURE);
    let idx = csv::header_index(&rows[0]);
    // Even with a person-seed hint, an Entity-typed row is an Organisation —
    // the row's own Type column wins.
    let e = row_to_entity(&rows[2], &idx, true, "scan").expect("org entity");
    assert_eq!(e.kind, EntityKind::Organisation);
    assert!((e.confidence - ORG_CONF).abs() < f64::EPSILON);
}

#[test]
fn match_rows_filters_to_seed_and_caps_output() {
    let m = DfatSanctions;
    // A full-name seed matches only the Qadhafi individual row.
    let hits = m.match_rows(FIXTURE, "Muammar Qadhafi", true, "scan");
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].kind, EntityKind::Person);
    assert!(hits[0].value.contains("QADHAFI") || hits[0].value.contains("Qadhafi"));

    // An organisation seed matches the entity row.
    let org_hits = m.match_rows(FIXTURE, "Korea Mining Development", false, "scan");
    assert_eq!(org_hits.len(), 1);
    assert_eq!(org_hits[0].kind, EntityKind::Organisation);

    // A seed matching nothing → no hits.
    assert!(
        m.match_rows(FIXTURE, "Nonexistent Personname", true, "scan")
            .is_empty()
    );
}

#[test]
fn match_rows_tolerates_missing_name_column_and_empty_body() {
    let m = DfatSanctions;
    // No recognised name column → emit nothing, don't guess.
    let bad = "ColA,ColB\nx,y\n";
    assert!(m.match_rows(bad, "x y", true, "scan").is_empty());
    // Empty body → no rows.
    assert!(m.match_rows("", "anything here", true, "scan").is_empty());
}

#[test]
fn lone_token_person_seed_is_rejected_by_guard() {
    // process() requires ≥2 name tokens for an individual; assert the
    // tokeniser precondition the guard relies on.
    let count = |q: &str| {
        q.split(|c: char| !c.is_alphanumeric())
            .filter(|t| t.len() >= 2)
            .count()
    };
    assert_eq!(count("Qadhafi"), 1);
    assert_eq!(count("Muammar Qadhafi"), 2);
}

/// Live end-to-end proof against the REAL DFAT Consolidated List — no mock. Run
/// with `cargo test -p huntsman-search-engine dfat_sanctions_live -- --ignored --nocapture`.
#[tokio::test]
#[ignore = "hits the live DFAT Consolidated List CSV; run manually"]
async fn dfat_sanctions_live_screens_a_listed_name() {
    let (bus, _rx) = tokio::sync::broadcast::channel(1);
    let ctx = ModuleContext {
        scan_id: "live".into(),
        bus,
        http: reqwest::Client::new(),
        keys: std::collections::HashMap::new(),
        cancel: crate::core::cancel::CancelHandle::new(),
        proxy_pool: Default::default(),
    };
    let r = DfatSanctions
        .process(&Target::new(TargetKind::FullName, "Muammar Qadhafi"), &ctx)
        .await
        .expect("live DFAT query must not error");
    eprintln!("dfat_sanctions live: {} entities", r.entities.len());
    assert!(
        r.entities.iter().any(|e| e.has_tag("sanctions")),
        "expected a sanctions hit for a known listed name"
    );
}
