use super::{OpenSanctions, entity_builders::build_entities, types::MatchResp};
use crate::core::{
    entity::EntityKind,
    module::{Module, ModuleCost},
    scan::{Target, TargetKind},
};

// ── Module surface ──────────────────────────────────────────────────
#[test]
fn accepts_full_name_with_at_least_two_tokens_only() {
    let m = OpenSanctions;
    assert!(m.accepts(&Target::new(TargetKind::FullName, "Jordan Avery")));
    assert!(!m.accepts(&Target::new(TargetKind::FullName, "Jordan")));
    assert!(!m.accepts(&Target::new(TargetKind::Email, "jordanavery@gmail.com")));
}

#[test]
fn consumes_declares_full_name_explicitly() {
    // accepts() value-gates on token count, so the default probe-based
    // consumes() would silently omit FullName from the dispatch index —
    // the same fix au_people needed for the identical gate shape.
    assert_eq!(OpenSanctions.consumes(), vec![TargetKind::FullName]);
}

#[test]
fn cost_is_key_gated() {
    assert!(matches!(OpenSanctions.cost(), ModuleCost::KeyGated));
}

#[test]
fn module_metadata() {
    assert_eq!(OpenSanctions.name(), "opensanctions");
    assert_eq!(OpenSanctions.priority(), 115);
    assert_eq!(OpenSanctions.max_timeout_ms(), 10_000);
    assert!(!OpenSanctions.description().is_empty());
    assert_eq!(OpenSanctions.produces(), &[EntityKind::Person]);
}

#[test]
fn attack_techniques_match_the_people_default_and_are_catalogued() {
    use crate::core::attack;
    let t = OpenSanctions.attack_techniques();
    for id in ["T1589.003", "T1591.004"] {
        assert!(t.contains(&id), "opensanctions must claim {id}, got {t:?}");
        assert!(attack::technique(id).is_some(), "{id} must be catalogued");
    }
    assert_eq!(t.len(), 2, "no unjustified extra techniques");
}

/// A real `/match` response shape (field names/nesting verified against
/// OpenSanctions' own live OpenAPI spec and matching-API quickstart
/// tutorial, 2026-07) built from their own published example — a real,
/// publicly-designated sanctioned individual, exactly the kind of subject a
/// sanctions database exists to describe (not the operator's own synthetic
/// test identity).
const REAL_MATCH_RESPONSE: &str = r#"{
    "responses": {
        "q": {
            "status": 200,
            "results": [{
                "id": "NK-aU5ybkbRFJucf8YMwsJvDw",
                "caption": "Alexander Vyacheslavovich ZAKHAROV",
                "schema": "Person",
                "properties": {
                    "lastName": ["ZAKHAROV", "Zakharov", "Zacharov"],
                    "position": ["Owner of LLC CST"],
                    "country": ["ru"],
                    "birthDate": ["1965-09-21"],
                    "firstName": ["Aleksandr", "Alexander"],
                    "topics": ["corp.disqual", "sanction", "debarment"],
                    "programId": ["EU-UKR", "US-RUSHAR"]
                },
                "datasets": ["ua_nsdc_sanctions", "us_ofac_sdn", "eu_fsf"],
                "score": 0.92,
                "match": true
            }],
            "total": {"value": 1, "relation": "eq"}
        }
    },
    "limit": 5
}"#;

#[test]
fn parse_match_response_matches_the_real_api_schema() {
    // Red/green anchor: this must deserialise into real (non-empty) values.
    let r: MatchResp = serde_json::from_str(REAL_MATCH_RESPONSE).unwrap();
    let results = &r.responses.q.results;
    assert_eq!(results.len(), 1);
    let m = &results[0];
    assert_eq!(m.id, "NK-aU5ybkbRFJucf8YMwsJvDw");
    assert_eq!(
        m.caption.as_deref(),
        Some("Alexander Vyacheslavovich ZAKHAROV")
    );
    assert_eq!(m.is_match, Some(true));
    assert!((m.score.unwrap() - 0.92).abs() < 0.001);
    assert_eq!(
        m.properties.topics,
        vec!["corp.disqual", "sanction", "debarment"]
    );
    assert_eq!(m.properties.position, vec!["Owner of LLC CST"]);
    assert_eq!(
        m.datasets,
        vec!["ua_nsdc_sanctions", "us_ofac_sdn", "eu_fsf"]
    );
}

// ── Core: entity building against the real schema ────────────────────
fn matches(json: &str) -> Vec<crate::core::entity::Entity> {
    let r: MatchResp = serde_json::from_str(json).unwrap();
    build_entities("Aleksandr Zacharov", &r.responses.q, "s")
}

#[test]
fn definitive_match_carries_sanction_and_debarment_tags_and_evidence() {
    let es = matches(REAL_MATCH_RESPONSE);
    assert_eq!(es.len(), 1);
    let e = &es[0];
    assert_eq!(e.kind, EntityKind::Person);
    assert_eq!(e.value, "Alexander Vyacheslavovich ZAKHAROV");
    assert!((e.confidence - 0.60).abs() < 1e-9);
    assert!(e.has_tag(crate::core::tags::SANCTIONED));
    assert!(e.has_tag(crate::core::tags::DEBARRED));
    assert!(
        !e.has_tag(crate::core::tags::PEP),
        "no role.pep topic present"
    );
    assert!(
        e.has_tag("high-confidence-match"),
        "0.92 clears the 0.90 bar"
    );

    let ev = &e.evidence[0];
    assert_eq!(
        ev.attributes.get("opensanctions_id").map(String::as_str),
        Some("NK-aU5ybkbRFJucf8YMwsJvDw")
    );
    assert_eq!(
        ev.attributes.get("match_score").map(String::as_str),
        Some("0.92")
    );
    assert_eq!(
        ev.attributes.get("position").map(String::as_str),
        Some("Owner of LLC CST")
    );
    assert_eq!(
        ev.attributes.get("birth_date").map(String::as_str),
        Some("1965-09-21")
    );
    assert_eq!(
        ev.attributes.get("program_id").map(String::as_str),
        Some("EU-UKR, US-RUSHAR")
    );
    assert_eq!(
        ev.attributes.get("datasets").map(String::as_str),
        Some("ua_nsdc_sanctions, us_ofac_sdn, eu_fsf")
    );
}

#[test]
fn pep_topic_without_sanction_tags_pep_only() {
    let es = matches(
        r#"{"responses":{"q":{"results":[{
            "id":"NK-pep1",
            "caption":"Jordan Avery",
            "properties":{"topics":["role.pep"], "position":["Minister for Regional Development"]},
            "datasets":["xx_peps"],
            "score":0.81,
            "match":true
        }]}}}"#,
    );
    assert_eq!(es.len(), 1);
    assert!(es[0].has_tag(crate::core::tags::PEP));
    assert!(!es[0].has_tag(crate::core::tags::SANCTIONED));
    assert!(!es[0].has_tag(crate::core::tags::DEBARRED));
    assert!(
        !es[0].has_tag("high-confidence-match"),
        "0.81 is below the 0.90 bar"
    );
}

#[test]
fn au_dfat_dataset_gets_the_au_sanctions_tag() {
    let es = matches(
        r#"{"responses":{"q":{"results":[{
            "id":"NK-au1",
            "caption":"Jordan Avery",
            "properties":{"topics":["sanction"]},
            "datasets":["au_dfat_sanctions", "un_sc_sanctions"],
            "score":0.95,
            "match":true
        }]}}}"#,
    );
    assert_eq!(es.len(), 1);
    assert!(es[0].has_tag("au-sanctions"));
}

#[test]
fn non_definitive_candidates_are_not_escalated() {
    // A fuzzy near-miss (match: false, or the field simply absent) must NOT
    // become a sanctions/PEP claim about a real person — false positives are
    // worse than missing coverage.
    let es = matches(
        r#"{"responses":{"q":{"results":[
            {"id":"NK-a","caption":"Someone Else","properties":{"topics":["sanction"]},"score":0.55,"match":false},
            {"id":"NK-b","caption":"Another Person","properties":{"topics":["sanction"]},"score":0.72}
        ]}}}"#,
    );
    assert!(es.is_empty());
}

#[test]
fn no_results_yields_no_entities() {
    let es = matches(r#"{"responses":{"q":{"results":[]}}}"#);
    assert!(es.is_empty());
}

#[test]
fn missing_caption_falls_back_to_the_queried_name() {
    let es = matches(
        r#"{"responses":{"q":{"results":[{
            "id":"NK-nocap",
            "properties":{"topics":["sanction"]},
            "score":0.9,
            "match":true
        }]}}}"#,
    );
    assert_eq!(es[0].value, "Aleksandr Zacharov");
}
