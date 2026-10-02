use super::*;

/// A REAL Wikidata SPARQL `wikibase:around` response, fetched live (2026-07-22)
/// for `Point(151.2153 -33.8568)` (Sydney Opera House), checked in verbatim.
const GOLDEN: &str = include_str!("testdata/opera_house.json");

#[test]
fn parse_wkt_point_swaps_lon_first_order() {
    // Wikidata emits `Point(<lon> <lat>)`; HSE wants `(lat, lon)`.
    let (lat, lon) = parse_wkt_point("Point(151.214897 -33.857058)").expect("valid point");
    assert!((lat - -33.857058).abs() < 1e-9, "lat came from 2nd field");
    assert!((lon - 151.214897).abs() < 1e-9, "lon came from 1st field");

    // Malformed literals yield None rather than a bogus coordinate.
    assert!(parse_wkt_point("Point(151.2)").is_none(), "one component");
    assert!(parse_wkt_point("Point(1 2 3)").is_none(), "three components");
    assert!(parse_wkt_point("POLYGON((0 0))").is_none(), "not a point");
    assert!(parse_wkt_point("Point(a b)").is_none(), "non-numeric");
}

#[test]
fn qid_from_uri_extracts_entity_id() {
    assert_eq!(
        qid_from_uri("http://www.wikidata.org/entity/Q45178"),
        Some("Q45178")
    );
    assert_eq!(qid_from_uri("Q2154104"), Some("Q2154104"));
    assert!(qid_from_uri("http://www.wikidata.org/entity/P625").is_none());
    assert!(qid_from_uri("http://www.wikidata.org/entity/Q").is_none());
    assert!(qid_from_uri("http://example.com/notaqid").is_none());
}

#[test]
fn build_entities_maps_a_real_sparql_response() {
    let resp: SparqlResp = serde_json::from_str(GOLDEN).expect("golden fixture parses");
    let bindings = &resp.results.bindings;
    assert!(bindings.len() >= 5, "fixture has several nearby entities");

    let ents = build_entities("-33.8568,151.2153", bindings, "scan");
    assert_eq!(
        ents.len(),
        bindings.len(),
        "each binding with location+QID yields one Coordinates entity"
    );

    // The Opera House itself (Q45178) must be present, as a Coordinates entity
    // tagged for GEOINT + Wikidata + AU state, carrying the label, QID tag, and a
    // stable entity URL.
    let opera = ents
        .iter()
        .find(|e| e.has_tag("wikidata:Q45178"))
        .expect("Sydney Opera House (Q45178) present");
    assert_eq!(opera.kind, EntityKind::Coordinates);
    assert!(opera.has_tag("wikidata") && opera.has_tag("geoint") && opera.has_tag("nearby-place"));
    // WKT was `Point(151.214897 -33.857058)` — the entity must carry lat,lon
    // (NOT lon,lat): a negative latitude near -33.857.
    assert!(
        opera.value.starts_with("-33.857"),
        "place carries its OWN coords in lat,lon order, got {}",
        opera.value
    );
    assert!(
        opera
            .evidence
            .iter()
            .any(|ev| ev.attributes.get("label").map(String::as_str) == Some("Sydney Opera House")),
        "English label present"
    );
    assert!(
        opera
            .evidence
            .iter()
            .filter_map(|ev| ev.attributes.get("url"))
            .any(|v| v.contains("Q45178")),
        "stable entity URL present"
    );
    // Sydney is in NSW — the AU-state tagger must have fired.
    assert!(
        opera
            .tags
            .iter()
            .any(|t| t.contains("au-state:NSW") || t == "country:AU"),
        "AU state tagged: {:?}",
        opera.tags
    );
}

#[test]
fn empty_or_malformed_response_yields_nothing() {
    let ents = build_entities("0,0", &[], "scan");
    assert!(ents.is_empty());

    // A binding missing its location is skipped, not panicked on.
    let locationless = vec![Binding {
        place: Some(Cell {
            value: "http://www.wikidata.org/entity/Q1".into(),
        }),
        place_label: Some(Cell {
            value: "No Coords".into(),
        }),
        location: None,
        dist: Some(Cell {
            value: "0.5".into(),
        }),
    }];
    assert!(build_entities("0,0", &locationless, "scan").is_empty());

    // A binding whose QID slot is really a property (P…) is skipped.
    let propertyish = vec![Binding {
        place: Some(Cell {
            value: "http://www.wikidata.org/entity/P625".into(),
        }),
        place_label: None,
        location: Some(Cell {
            value: "Point(151.2 -33.8)".into(),
        }),
        dist: None,
    }];
    assert!(build_entities("0,0", &propertyish, "scan").is_empty());
}

#[test]
fn unlabelled_entity_falls_back_to_qid_summary() {
    // The label service echoes the QID when an item has no English label; that
    // must be treated as unlabelled (no `label` attr, QID-only summary).
    let bindings = vec![Binding {
        place: Some(Cell {
            value: "http://www.wikidata.org/entity/Q999999".into(),
        }),
        place_label: Some(Cell {
            value: "Q999999".into(),
        }),
        location: Some(Cell {
            value: "Point(151.2 -33.8)".into(),
        }),
        dist: Some(Cell {
            value: "0.5".into(),
        }),
    }];
    let ents = build_entities("-33.8,151.2", &bindings, "scan");
    assert_eq!(ents.len(), 1);
    let e = &ents[0];
    assert!(
        e.evidence
            .iter()
            .all(|ev| !ev.attributes.contains_key("label")),
        "QID-as-label is not surfaced as a real label"
    );
    // Distance (km) is surfaced as metres.
    assert!(
        e.evidence
            .iter()
            .any(|ev| ev.attributes.get("distance_m").map(String::as_str) == Some("500")),
        "0.5 km surfaced as 500 m"
    );
}

#[test]
fn module_metadata_is_free_geo_coordinate_consumer() {
    let m = WikidataGeo;
    assert_eq!(m.name(), "wikidata_geo");
    assert!(matches!(m.cost(), ModuleCost::Free));
    assert!(matches!(m.category(), ModuleCategory::Geo));
    assert!(m.accepts(&Target::new(TargetKind::Coordinates, "-33.85,151.21")));
    assert!(!m.accepts(&Target::new(TargetKind::Email, "a@b.com")));
    assert!(m.produces().contains(&EntityKind::Coordinates));
}
