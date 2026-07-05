use serde_json::Value;

use crate::core::{
    entity::EntityKind,
    module::{ModuleCategory, ModuleCost},
    scan::{Target, TargetKind},
};

use super::{
    HANDLE_PROPS, PERSON_PRIMARY, Wikidata,
    builder::{candidate_entity, primary_entities},
    claims::{claim_entity_ids, claim_p625, claim_strings, en_text},
    classify::{classify, name_matches_query, seed_kind},
    types::SearchHit,
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
        .unwrap();
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
    assert!(e.confidence < 0.50);
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
