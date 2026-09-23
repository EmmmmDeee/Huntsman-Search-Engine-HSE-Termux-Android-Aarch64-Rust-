use serde_json::Value;

use crate::core::{
    confidence,
    entity::EntityKind,
    module::{ModuleCategory, ModuleCost, ModuleResult},
    scan::{Target, TargetKind},
};

use super::{
    HANDLE_PROPS, MAX_CANDIDATES, PERSON_PRIMARY, SEARCH_LIMIT, Wikidata,
    builder::{candidate_entity, primary_entities},
    claims::{claim_entity_ids, claim_p625, claim_strings, claim_time, en_text},
    classify::{classify, name_matches_query, seed_kind},
    declare_search_truncation,
    types::{SearchHit, SearchResp},
    urls::{entities_url, search_url},
};
use crate::core::module::Module;

fn torvalds_entity() -> Value {
    serde_json::json!({
        "labels": {"en": {"value": "Linus Torvalds"}},
        "descriptions": {"en": {"value": "Finnish software engineer (born 1969)"}},
        "claims": {
            "P31":   [{"mainsnak": {"datavalue": {"value": {"entity-type": "item", "id": "Q5"}}}}],
            "P856":  [{"mainsnak": {"datavalue": {"value": "https://torvalds-family.blogspot.com"}}}],
            "P2037": [{"mainsnak": {"datavalue": {"value": "torvalds"}}}],
            "P6634": [{"mainsnak": {"datavalue": {"value": "linustorvalds"}}}]
        }
    })
}

#[test]
fn accepts_fullname_and_org_only() {
    let m = Wikidata;
    assert!(m.accepts(&Target::new(TargetKind::FullName, "Linus Torvalds")));
    assert!(m.accepts(&Target::new(TargetKind::Organisation, "Mozilla Foundation")));
    assert!(!m.accepts(&Target::new(TargetKind::Email, "a@b.com")));
    assert!(!m.accepts(&Target::new(TargetKind::Domain, "example.com")));
}

#[test]
fn module_metadata() {
    let m = Wikidata;
    assert_eq!(m.name(), "wikidata");
    assert!(!m.description().is_empty());
    assert_eq!(m.cost(), ModuleCost::Free);
    assert_eq!(m.category(), ModuleCategory::People);
    assert!(m.max_timeout_ms() > 3_000);
}

#[test]
fn classify_uses_p31_human() {
    let person = torvalds_entity();
    assert_eq!(classify(&person, TargetKind::FullName), EntityKind::Person);
    // Non-human P31 → Organisation even for a FullName seed.
    let org = serde_json::json!({"claims": {"P31": [{"mainsnak": {"datavalue": {"value": {"id": "Q43229"}}}}]}});
    assert_eq!(
        classify(&org, TargetKind::FullName),
        EntityKind::Organisation
    );
    // No P31 → fall back to the seed kind.
    let bare = serde_json::json!({"claims": {}});
    assert_eq!(
        classify(&bare, TargetKind::Organisation),
        EntityKind::Organisation
    );
    assert_eq!(classify(&bare, TargetKind::FullName), EntityKind::Person);
}

#[test]
fn primary_fans_out_person_website_and_handles() {
    let body = torvalds_entity();
    let ents = primary_entities("Q34253", "Linus Torvalds", &body, TargetKind::FullName, "s");

    let person = ents
        .iter()
        .find(|e| e.kind == EntityKind::Person)
        .expect("a Person head entity");
    assert_eq!(person.value, "Linus Torvalds");
    assert!(person.tags.iter().any(|t| t == "Q34253"));
    assert!((person.confidence - PERSON_PRIMARY).abs() < f64::EPSILON);

    // Official website → Domain (host extracted).
    let dom = ents
        .iter()
        .find(|e| e.kind == EntityKind::Domain)
        .expect("a Domain from P856");
    assert_eq!(dom.value, "torvalds-family.blogspot.com");

    // Social handles → Usernames, tagged by platform.
    let unames: Vec<&str> = ents
        .iter()
        .filter(|e| e.kind == EntityKind::Username)
        .map(|e| e.value.as_str())
        .collect();
    assert!(unames.contains(&"torvalds")); // github
    assert!(unames.contains(&"linustorvalds")); // linkedin
    let gh = ents
        .iter()
        .find(|e| e.kind == EntityKind::Username && e.value == "torvalds")
        .expect("should succeed");
    assert!(gh.tags.iter().any(|t| t == "github"));
}

#[test]
fn primary_emits_commons_image_url_for_p18() {
    // P18 image claim → a normalized Url tagged image/avatar pointing at the
    // official Commons Special:FilePath endpoint, ending in an image
    // extension so exif_geo will mine its metadata during expansion.
    let body = serde_json::json!({
        "labels": {"en": {"value": "Jane Doe"}},
        "claims": {
            "P18": [{"mainsnak": {"datavalue": {"value": "Jane Doe portrait.jpg"}}}]
        }
    });
    let ents = primary_entities("Q1", "Jane Doe", &body, TargetKind::FullName, "s");
    let img = ents
        .iter()
        .find(|e| e.kind == EntityKind::Url)
        .expect("a Url image entity from P18");
    assert_eq!(
        img.value,
        "https://commons.wikimedia.org/wiki/Special:FilePath/Jane_Doe_portrait.jpg"
    );
    assert!(img.tags.iter().any(|t| t == "image"));
    assert!(img.tags.iter().any(|t| t == "avatar"));
    assert!(
        img.value.to_lowercase().ends_with(".jpg"),
        "must end in an image extension so exif_geo accepts it"
    );
    // No P18 → no image url.
    let none = serde_json::json!({"labels": {"en": {"value": "No Pic"}}, "claims": {}});
    let ents2 = primary_entities("Q2", "No Pic", &none, TargetKind::FullName, "s");
    assert!(ents2.iter().all(|e| e.kind != EntityKind::Url));
}

#[test]
fn name_match_gate_is_whole_word() {
    assert!(name_matches_query("Linus Torvalds", "linus torvalds"));
    assert!(name_matches_query(
        "Australian Red Cross",
        "red cross australian"
    ));
    assert!(!name_matches_query("Mildred Smith", "red")); // not substring of Mildred
    assert!(!name_matches_query("Linus Torvalds", "linus pauling")); // missing token
}

#[test]
fn candidate_is_sub_floor_with_description_evidence() {
    let hit = SearchHit {
        id: "Q123".into(),
        label: Some("John Smith".into()),
        description: Some("English cricketer".into()),
    };
    let e = candidate_entity(&hit, TargetKind::FullName, "s");
    assert_eq!(e.kind, EntityKind::Person);
    assert!(e.confidence < confidence::MEDIUM);
    assert!(e.tags.iter().any(|t| t == "name-candidate"));
    assert!(e.tags.iter().any(|t| t == "Q123"));
    assert!(
        e.evidence[0]
            .attributes
            .iter()
            .any(|(k, v)| k == "description" && v == "English cricketer")
    );
}

#[test]
fn search_url_and_entities_url_shapes() {
    let s = search_url("Linus Torvalds");
    assert!(s.contains("action=wbsearchentities"));
    assert!(s.contains("search=Linus+Torvalds"));
    assert!(s.contains("type=item"));
    let e = entities_url("Q34253");
    assert!(e.contains("action=wbgetentities"));
    assert!(e.contains("ids=Q34253"));
    assert!(e.contains("props=claims%7Clabels%7Cdescriptions"));
}

#[test]
fn every_handle_is_emitted_no_cap() {
    // A subject with handle history: two distinct, curated handles on EVERY
    // known platform — 2 × HANDLE_PROPS.len() total, well over the old
    // MAX_HANDLES = 12. Each is a Wikidata-sourced identity statement AND a
    // username-search pivot, so every one must surface; dropping the tail hid
    // real accounts by property order.
    let mut claims = serde_json::Map::new();
    for (pid, platform) in HANDLE_PROPS {
        claims.insert(
            (*pid).to_string(),
            serde_json::json!([
                {"mainsnak": {"datavalue": {"value": format!("{platform}_primary")}}},
                {"mainsnak": {"datavalue": {"value": format!("{platform}_old")}}}
            ]),
        );
    }
    let body = serde_json::json!({"claims": Value::Object(claims)});
    let ents = primary_entities("Q1", "X", &body, TargetKind::Organisation, "s");
    let handles: Vec<&str> = ents
        .iter()
        .filter(|e| e.kind == EntityKind::Username)
        .map(|e| e.value.as_str())
        .collect();
    let expected = HANDLE_PROPS.len() * 2;
    assert_eq!(
        handles.len(),
        expected,
        "every distinct handle emitted, not capped at 12: got {}",
        handles.len()
    );
    // Spot-check both the first and the last platform's handles survive — the
    // cap dropped exactly the trailing platforms.
    for (_, platform) in HANDLE_PROPS {
        for suffix in ["primary", "old"] {
            let want = format!("{platform}_{suffix}");
            assert!(
                handles.contains(&want.as_str()),
                "missing handle {want} (a trailing-platform handle the cap would drop)"
            );
        }
    }
}

#[test]
fn person_with_position_held_is_flagged_pep() {
    // P39 "position held" → the FATF politically-exposed-person signal: the head
    // Person gains the `pep` / `politically-exposed` tags and the position Q-IDs
    // are preserved as evidence for an investigator to resolve and verify.
    // (Q3066207 = member of the Australian House of Representatives.)
    let body = serde_json::json!({
        "labels": {"en": {"value": "Jane Politician"}},
        "claims": {
            "P31": [{"mainsnak": {"datavalue": {"value": {"id": "Q5"}}}}],
            "P39": [
                {"mainsnak": {"datavalue": {"value": {"id": "Q3066207"}}}},
                {"mainsnak": {"datavalue": {"value": {"id": "Q486839"}}}}
            ]
        }
    });
    let ents = primary_entities("Q1", "Jane Politician", &body, TargetKind::FullName, "s");
    let head = ents
        .iter()
        .find(|e| e.kind == EntityKind::Person)
        .expect("a Person head entity");
    assert!(
        head.tags.iter().any(|t| t == "pep"),
        "tags: {:?}",
        head.tags
    );
    assert!(head.tags.iter().any(|t| t == "politically-exposed"));
    assert_eq!(
        head.evidence[0]
            .attributes
            .get("position_held_qids")
            .map(String::as_str),
        Some("Q3066207,Q486839")
    );
}

#[test]
fn politician_occupation_is_flagged_pep_even_without_position() {
    // P106 occupation == Q82955 (politician) with NO P39 position still flags the
    // person PEP — covers a politician between terms or a Wikidata stub. No P39 ⇒
    // no `position_held_qids` attribute, but the pep tags are present.
    let body = serde_json::json!({
        "labels": {"en": {"value": "Sam Member"}},
        "claims": {
            "P31": [{"mainsnak": {"datavalue": {"value": {"id": "Q5"}}}}],
            "P106": [{"mainsnak": {"datavalue": {"value": {"id": "Q82955"}}}}]
        }
    });
    let ents = primary_entities("Q3", "Sam Member", &body, TargetKind::FullName, "s");
    let head = ents
        .iter()
        .find(|e| e.kind == EntityKind::Person)
        .expect("a Person head entity");
    assert!(
        head.tags.iter().any(|t| t == "pep"),
        "tags: {:?}",
        head.tags
    );
    assert!(head.tags.iter().any(|t| t == "politically-exposed"));
    assert!(
        !head.evidence[0]
            .attributes
            .contains_key("position_held_qids")
    );
}

#[test]
fn person_without_position_held_is_not_pep() {
    let body = serde_json::json!({
        "labels": {"en": {"value": "Jane Citizen"}},
        "claims": {"P31": [{"mainsnak": {"datavalue": {"value": {"id": "Q5"}}}}]}
    });
    let ents = primary_entities("Q2", "Jane Citizen", &body, TargetKind::FullName, "s");
    let head = ents
        .iter()
        .find(|e| e.kind == EntityKind::Person)
        .expect("a Person head entity");
    assert!(!head.tags.iter().any(|t| t == "pep"));
    assert!(
        !head.evidence[0]
            .attributes
            .contains_key("position_held_qids")
    );
}

#[test]
fn claim_p625_extracts_valid_lat_lon_in_order() {
    // Brisbane — a real, in-range, non-Null-Island fix. Tuple order is (lat, lon).
    let entity = serde_json::json!({
        "claims": {
            "P625": [{"mainsnak": {"datavalue": {"value": {
                "latitude": -27.4766,
                "longitude": 153.0166
            }}}}]
        }
    });
    assert_eq!(claim_p625(&entity), Some((-27.4766, 153.0166)));
}

#[test]
fn claim_p625_none_when_property_absent() {
    let entity = serde_json::json!({"claims": {}});
    assert_eq!(claim_p625(&entity), None);
}

#[test]
fn claim_p625_none_when_value_malformed() {
    // Missing the `longitude` member → walk fails, None.
    let entity = serde_json::json!({
        "claims": {
            "P625": [{"mainsnak": {"datavalue": {"value": {"latitude": -27.4766}}}}]
        }
    });
    assert_eq!(claim_p625(&entity), None);
    // Null-Island (0,0) is rejected by is_valid_coords even though well-formed.
    let null_island = serde_json::json!({
        "claims": {
            "P625": [{"mainsnak": {"datavalue": {"value": {"latitude": 0.0, "longitude": 0.0}}}}]
        }
    });
    assert_eq!(claim_p625(&null_island), None);
}

#[test]
fn claim_strings_collects_in_order_and_empty_when_missing() {
    let entity = serde_json::json!({
        "claims": {
            "P856": [
                {"mainsnak": {"datavalue": {"value": "https://a.example"}}},
                {"mainsnak": {"datavalue": {"value": "https://b.example"}}}
            ]
        }
    });
    assert_eq!(
        claim_strings(&entity, "P856"),
        vec![
            "https://a.example".to_string(),
            "https://b.example".to_string()
        ]
    );
    // Property not present → empty Vec.
    assert!(claim_strings(&entity, "P2037").is_empty());
}

#[test]
fn claim_entity_ids_collects_ids_and_empty_when_missing() {
    let entity = serde_json::json!({
        "claims": {
            "P31": [
                {"mainsnak": {"datavalue": {"value": {"entity-type": "item", "id": "Q5"}}}},
                {"mainsnak": {"datavalue": {"value": {"entity-type": "item", "id": "Q42"}}}}
            ]
        }
    });
    assert_eq!(
        claim_entity_ids(&entity, "P31"),
        vec!["Q5".to_string(), "Q42".to_string()]
    );
    assert!(claim_entity_ids(&entity, "P279").is_empty());
}

#[test]
fn en_text_reads_section_en_value() {
    let entity = serde_json::json!({
        "labels": {"en": {"value": "Linus Torvalds"}},
        "descriptions": {"en": {"value": "Finnish software engineer"}}
    });
    assert_eq!(
        en_text(&entity, "labels").as_deref(),
        Some("Linus Torvalds")
    );
    assert_eq!(
        en_text(&entity, "descriptions").as_deref(),
        Some("Finnish software engineer")
    );
    // Missing section → None.
    assert_eq!(en_text(&entity, "aliases"), None);
}

#[test]
fn seed_kind_maps_every_target_kind() {
    // Organisation is the only seed that maps to Organisation; all else → Person.
    assert_eq!(
        seed_kind(TargetKind::Organisation),
        EntityKind::Organisation
    );
    assert_eq!(seed_kind(TargetKind::FullName), EntityKind::Person);
    assert_eq!(seed_kind(TargetKind::Email), EntityKind::Person);
    assert_eq!(seed_kind(TargetKind::Domain), EntityKind::Person);
    assert_eq!(seed_kind(TargetKind::Username), EntityKind::Person);
    assert_eq!(seed_kind(TargetKind::IpAddress), EntityKind::Person);
}

#[test]
fn a_mediawiki_error_envelope_on_search_is_a_hard_error_not_no_match() {
    // wbsearchentities returns errors (maxlag, backend failure, bad params) as
    // HTTP 200 with an `error` object and an empty `search`. Modelling `error`
    // and gating on it stops that decoding as a clean "no matching item".
    let body = r#"{"error":{"code":"maxlag","info":"Waiting for a replica DB server"}}"#;
    let resp: SearchResp = serde_json::from_str(body).expect("envelope parses");
    assert!(
        resp.search.is_empty(),
        "the error envelope carries no search hits"
    );
    assert!(
        crate::util::mediawiki::MwError::check(&resp.error, "wikidata").is_err(),
        "a wbsearchentities error envelope must surface as an error, not an empty match set"
    );
}

#[test]
fn a_normal_search_response_has_no_error_envelope() {
    let body = r#"{"search":[{"id":"Q34253","label":"Linus Torvalds"}]}"#;
    let resp: SearchResp = serde_json::from_str(body).expect("parses");
    assert_eq!(resp.search.len(), 1);
    assert!(
        crate::util::mediawiki::MwError::check(&resp.error, "wikidata").is_ok(),
        "a normal search response passes the gate"
    );
}

/// The module's own promise (module doc, `mod.rs`):
///
/// > up to `MAX_CANDIDATES` further same-name items are surfaced as
/// > low-confidence candidates … that stay **below the expansion floor so a
/// > namesake can't pivot**.
///
/// `candidate_entity_is_sub_floor_and_named` above asserts that on the entity
/// **in isolation**, which is where the promise is true and where it does not
/// matter. Two Wikidata items that are namesakes share a label by definition —
/// that is what makes them namesakes — and an entity valued on a name derives
/// its uid from that name, so the primary and the candidate are ONE entity as
/// far as the engine is concerned. `Entity::absorb` takes
/// `f64::max(confidence)`, so the deliberate demotion is erased by the very
/// thing it was written to protect against.
#[test]
fn a_namesake_candidate_does_not_smuggle_the_primary_s_confidence() {
    let primary = primary_entities(
        "Q1",
        "John Smith",
        &serde_json::json!({
            "labels": {"en": {"value": "John Smith"}},
            "claims": {"P31": [{"mainsnak": {"datavalue": {"value": {"entity-type": "item", "id": "Q5"}}}}]}
        }),
        TargetKind::FullName,
        "s",
    );
    let candidate = candidate_entity(
        &SearchHit {
            id: "Q2".into(),
            label: Some("John Smith".into()),
            description: Some("a different, unrelated John Smith".into()),
        },
        TargetKind::FullName,
        "s",
    );

    // Precondition, asserted rather than assumed: these really are one entity
    // to the engine. If this ever stops holding the test below is vacuous.
    let head = primary.first().expect("a primary must be built");
    assert_eq!(
        head.uid, candidate.uid,
        "two same-label Wikidata items must share a uid — otherwise this \
         regression cannot occur and this test proves nothing"
    );

    let mut all = primary;
    all.push(candidate);
    // The page-level judgement `process` makes, at its pure seam.
    super::builder::mark_shared_labels(
        &mut all,
        TargetKind::FullName,
        &["John Smith", "John Smith"],
    );
    crate::core::entity::dedup_merge_entities(&mut all);

    let merged = all
        .iter()
        .find(|e| e.value == "John Smith" && e.kind == EntityKind::Person)
        .expect("the fused person must survive");
    assert!(
        merged.confidence < confidence::MEDIUM,
        "a name two Wikidata items hold does not identify one person, so the \
         fused entity must stay below the expansion floor and must not pivot; \
         got {} with tags {:?}",
        merged.confidence,
        merged.tags
    );
}

#[test]
fn a_single_wikidata_match_still_pivots_at_full_confidence() {
    // CONTROL — passes on the baseline AND the fix. One item, no namesake: the
    // primary keeps its full confidence and its fan-out.
    let primary = primary_entities(
        "Q1",
        "Linus Torvalds",
        &torvalds_entity(),
        TargetKind::FullName,
        "s",
    );
    let head = primary.first().expect("a primary must be built");
    assert!((head.confidence - PERSON_PRIMARY).abs() < f64::EPSILON);
    assert!(head.tags.iter().any(|t| t == "exact-name-match"));
    assert!(!head.tags.iter().any(|t| t == "ambiguous-name"));
}

#[test]
fn an_ambiguous_primary_does_not_leave_its_handles_pivot_eligible() {
    // The fan-out read from the primary item alone — its website, its GitHub
    // handle — rests on the same unresolved name. Demoting the Person while
    // leaving those at HANDLE_CONF/DOMAIN_CONF would move the defect rather
    // than remove it: the handle would still pivot, still attributed to a
    // subject who may be the OTHER holder of the name.
    let mut all = primary_entities(
        "Q1",
        "Linus Torvalds",
        &torvalds_entity(),
        TargetKind::FullName,
        "s",
    );
    let fan_out = all.len();
    assert!(
        fan_out > 1,
        "the fixture must produce a claims fan-out, or this test is vacuous"
    );
    all.push(candidate_entity(
        &SearchHit {
            id: "Q2".into(),
            label: Some("Linus Torvalds".into()),
            description: Some("a different person with the same name".into()),
        },
        TargetKind::FullName,
        "s",
    ));
    super::builder::mark_shared_labels(
        &mut all,
        TargetKind::FullName,
        &["Linus Torvalds", "Linus Torvalds"],
    );

    for e in &all {
        assert!(
            e.confidence < confidence::MEDIUM,
            "{:?} entity {:?} still pivots at {} on an unresolved name",
            e.kind,
            e.value,
            e.confidence
        );
        assert!(
            e.tags.iter().any(|t| t == "ambiguous-name"),
            "{:?} entity {:?} escaped the ambiguity marking",
            e.kind,
            e.value
        );
    }
}

#[test]
fn a_differently_labelled_candidate_leaves_the_primary_alone() {
    // CONTROL and boundary: a candidate whose label merely CONTAINS the seed
    // tokens ("Linus Torvalds Jr") is a different value, gets a different uid,
    // never fuses, and so erases nothing. The primary keeps full confidence.
    let mut all = primary_entities(
        "Q1",
        "Linus Torvalds",
        &torvalds_entity(),
        TargetKind::FullName,
        "s",
    );
    all.push(candidate_entity(
        &SearchHit {
            id: "Q2".into(),
            label: Some("Linus Torvalds Jr".into()),
            description: None,
        },
        TargetKind::FullName,
        "s",
    ));
    super::builder::mark_shared_labels(
        &mut all,
        TargetKind::FullName,
        &["Linus Torvalds", "Linus Torvalds Jr"],
    );

    let head = all.first().expect("primary");
    assert!((head.confidence - PERSON_PRIMARY).abs() < f64::EPSILON);
    assert!(!head.tags.iter().any(|t| t == "ambiguous-name"));
    // …and the genuinely distinct candidate keeps its own sub-floor demotion,
    // which was never at risk because it never fused.
    let cand = all
        .iter()
        .find(|e| e.value == "Linus Torvalds Jr")
        .expect("candidate");
    assert!(cand.confidence < confidence::MEDIUM);
    assert!(!cand.tags.iter().any(|t| t == "ambiguous-name"));
}

// ── REQ-WIKIDATA-002: Wikidata's own statement rank ──────────────────────────

/// One statement, with an explicit rank, in the shape the live API sends.
fn ranked(pid: &str, rows: &[(&str, Value)]) -> Value {
    let statements: Vec<Value> = rows
        .iter()
        .map(|(rank, value)| {
            serde_json::json!({
                "rank": rank,
                "mainsnak": { "snaktype": "value", "datavalue": { "value": value } }
            })
        })
        .collect();
    serde_json::json!({ "claims": { pid: statements } })
}

#[test]
fn a_deprecated_statement_is_never_read_back_as_current_fact() {
    // `deprecated` is Wikidata's own marker for a statement it knows to be
    // wrong or superseded — kept visible on purpose, for provenance. Minting it
    // as a current value republishes an error the source has already retracted.
    //
    // All four readers ignored `rank` entirely, so every deprecated statement
    // was surfaced exactly like a live one.
    let site = ranked(
        "P856",
        &[
            (
                "deprecated",
                Value::String("https://old-and-wrong.example".into()),
            ),
            ("normal", Value::String("https://current.example".into())),
        ],
    );
    assert_eq!(
        claim_strings(&site, "P856"),
        vec!["https://current.example".to_string()],
        "a deprecated website must not be surfaced"
    );

    let occ = ranked(
        "P106",
        &[
            ("deprecated", serde_json::json!({"id": "Q_WRONG"})),
            ("normal", serde_json::json!({"id": "Q82594"})),
        ],
    );
    assert_eq!(claim_entity_ids(&occ, "P106"), vec!["Q82594".to_string()]);

    let dob = ranked(
        "P569",
        &[
            (
                "deprecated",
                serde_json::json!({"time": "+1950-01-01T00:00:00Z"}),
            ),
            (
                "normal",
                serde_json::json!({"time": "+1969-12-28T00:00:00Z"}),
            ),
        ],
    );
    assert_eq!(claim_time(&dob, "P569"), Some("1969-12-28".to_string()));

    let coords = ranked(
        "P625",
        &[
            (
                "deprecated",
                serde_json::json!({"latitude": 1.0, "longitude": 1.0}),
            ),
            (
                "normal",
                serde_json::json!({"latitude": -27.4679, "longitude": 153.0281}),
            ),
        ],
    );
    let (lat, lon) = claim_p625(&coords).expect("the live statement must still resolve");
    assert!(
        (lat - -27.4679).abs() < 1e-9 && (lon - 153.0281).abs() < 1e-9,
        "the deprecated coordinate won: got {lat},{lon}"
    );
}

#[test]
fn a_single_valued_read_takes_the_preferred_statement_not_array_index_zero() {
    // `preferred` is how an item says "when you need ONE value, use this" —
    // exactly the case a superseded coordinate or date creates. The readers
    // indexed `claims/<pid>/0`, i.e. whichever statement serialised first, so a
    // stale value placed ahead of the current one won outright.
    let coords = ranked(
        "P625",
        &[
            // Deliberately FIRST in the array, as a superseded value often is.
            (
                "normal",
                serde_json::json!({"latitude": 51.5074, "longitude": -0.1278}),
            ),
            (
                "preferred",
                serde_json::json!({"latitude": -27.4679, "longitude": 153.0281}),
            ),
        ],
    );
    let (lat, lon) = claim_p625(&coords).expect("a coordinate must resolve");
    assert!(
        (lat - -27.4679).abs() < 1e-9 && (lon - 153.0281).abs() < 1e-9,
        "index 0 won over the preferred statement: got {lat},{lon}"
    );

    let dob = ranked(
        "P569",
        &[
            (
                "normal",
                serde_json::json!({"time": "+1900-01-01T00:00:00Z"}),
            ),
            (
                "preferred",
                serde_json::json!({"time": "+1969-12-28T00:00:00Z"}),
            ),
        ],
    );
    assert_eq!(claim_time(&dob, "P569"), Some("1969-12-28".to_string()));
}

#[test]
fn a_multi_valued_read_keeps_every_live_statement_including_the_preferred_one() {
    // The control that keeps the fix from over-correcting. P31/P106/P27 are
    // genuinely multi-valued — a person really does hold several occupations —
    // so narrowing to the preferred statement would DISCARD true values.
    // Only `deprecated` is dropped here; `preferred` and `normal` both survive.
    let occ = ranked(
        "P106",
        &[
            ("preferred", serde_json::json!({"id": "Q82594"})),
            ("normal", serde_json::json!({"id": "Q5482740"})),
            ("deprecated", serde_json::json!({"id": "Q_RETRACTED"})),
        ],
    );
    assert_eq!(
        claim_entity_ids(&occ, "P106"),
        vec!["Q82594".to_string(), "Q5482740".to_string()],
        "both live occupations must survive; only the deprecated one is dropped"
    );
}

#[test]
fn a_statement_carrying_no_rank_is_read_as_ordinary_not_discarded() {
    // The live API always sets `rank`, so this only arises for a trimmed body or
    // a fixture. The safe reading of a missing rank is "ordinary" — discarding
    // it would turn a partial response into silent data loss, and would break
    // every fixture in this file that predates REQ-WIKIDATA-002.
    let bare = serde_json::json!({
        "claims": { "P856": [
            { "mainsnak": { "datavalue": { "value": "https://no-rank.example" } } }
        ]}
    });
    assert_eq!(
        claim_strings(&bare, "P856"),
        vec!["https://no-rank.example".to_string()]
    );
}

#[test]
fn an_item_whose_only_classification_is_deprecated_falls_back_it_is_never_guessed() {
    // The boundary the rank filter moves in `classify`. P31 drives entity KIND,
    // so dropping a deprecated statement there changes which entity is minted,
    // not merely its content — this pins that the change is the module's own
    // defined "I don't know" answer and not a misclassification.
    //
    // An item whose sole `instance of` is one Wikidata marks wrong must not be
    // classified from it; `classify` falls back to the seed's kind.
    let only_deprecated = ranked("P31", &[("deprecated", serde_json::json!({"id": "Q5"}))]);
    assert_eq!(
        classify(&only_deprecated, TargetKind::Organisation),
        EntityKind::Organisation,
        "a deprecated `instance of` must not classify the item; the seed decides"
    );

    // Control: a live Q5 still classifies as a Person, deprecated sibling or not.
    let live_human = ranked(
        "P31",
        &[
            ("deprecated", serde_json::json!({"id": "Q43229"})),
            ("normal", serde_json::json!({"id": "Q5"})),
        ],
    );
    assert_eq!(
        classify(&live_human, TargetKind::Organisation),
        EntityKind::Person
    );
}

// ── what the coverage layer is told ─────────────────────────────────────────

#[test]
fn a_full_search_page_is_partial_even_with_no_matching_label() {
    // FAILS before the fix: a full page of fuzzy hits none of which carried
    // the name returned `ModuleResult::new()` — a clean "no such item" — while
    // the API held more hits beyond the page.
    let mut out = ModuleResult::new();
    declare_search_truncation(&mut out, SEARCH_LIMIT, 0);
    let why = out.truncation.expect("a full page is not the whole answer");
    assert!(why.contains(&format!("limit={SEARCH_LIMIT}")), "{why}");
    assert!(why.contains("did not report how many"), "{why}");
}

#[test]
fn more_matches_than_the_candidate_cap_are_declared_with_their_count() {
    let mut out = ModuleResult::new();
    declare_search_truncation(&mut out, SEARCH_LIMIT - 1, MAX_CANDIDATES + 2);
    let why = out.truncation.expect("the candidate cap cut the answer");
    assert!(
        why.starts_with(&format!("{MAX_CANDIDATES} of {}", MAX_CANDIDATES + 2)),
        "{why}"
    );
}

#[test]
fn a_short_page_within_the_cap_declares_nothing() {
    // The control: a short page is everything the API holds, so an empty or
    // capped-within-limit answer IS the answer.
    for (returned, matched) in [(0, 0), (3, 0), (SEARCH_LIMIT - 1, MAX_CANDIDATES)] {
        let mut out = ModuleResult::new();
        declare_search_truncation(&mut out, returned, matched);
        assert!(
            out.truncation.is_none(),
            "{returned}/{matched}: {:?}",
            out.truncation
        );
    }
}

#[test]
fn the_page_is_requested_at_the_size_it_is_measured_against() {
    assert!(search_url("x").ends_with(&format!("&limit={SEARCH_LIMIT}")));
}

/// REQ-WIKIDATA-003. An "Ian Thorpe" scan's label search also returned the
/// swimming centre named after him. Untyped, it fell back to the seed's kind
/// (Person), was tagged `exact-name-match`, and its P625 — emitted at HIGH —
/// became the subject's best location fix at 0.97.
#[test]
fn a_place_named_after_a_person_seed_is_neither_the_person_nor_their_location() {
    let venue = serde_json::json!({"claims": {
        "P625": [{"mainsnak": {"datavalue": {"value": {"latitude": -33.8774, "longitude": 151.199}}}}]
    }});
    // Untyped but located → not a person, whatever the seed.
    assert_eq!(
        classify(&venue, TargetKind::FullName),
        EntityKind::Organisation
    );

    let ents = primary_entities(
        "Q16892619",
        "Ian Thorpe Aquatic and Fitness Centre",
        &venue,
        TargetKind::FullName,
        "s",
    );
    let head = &ents[0];
    assert_eq!(head.kind, EntityKind::Organisation);
    assert!(
        !head.has_tag("exact-name-match"),
        "a venue is not an exact match of a person seed"
    );
    assert!(
        !ents.iter().any(|e| e.kind == EntityKind::Coordinates),
        "the venue's location must not be emitted as a geo fix for a person scan"
    );

    // Control: an organisation seed's own site keeps its coordinate and match.
    let ents = primary_entities("Q1", "Acme", &venue, TargetKind::Organisation, "s");
    assert!(ents[0].has_tag("exact-name-match"));
    assert!(ents.iter().any(|e| e.kind == EntityKind::Coordinates));
}
