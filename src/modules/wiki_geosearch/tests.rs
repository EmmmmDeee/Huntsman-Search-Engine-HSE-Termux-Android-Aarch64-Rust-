use super::*;

/// A REAL Wikipedia GeoSearch response, fetched live (2026-07-22) for
/// `gscoord=-33.8568|151.2153` (Sydney Opera House), checked in verbatim.
const GOLDEN: &str = include_str!("testdata/opera_house.json");

#[test]
fn build_entities_maps_a_real_geosearch_response() {
    let resp: GeoResp = serde_json::from_str(GOLDEN).expect("golden fixture parses");
    let places = resp.query.map(|q| q.geosearch).unwrap_or_default();
    assert!(places.len() >= 5, "fixture has several nearby places");

    let ents = build_entities("-33.8568,151.2153", &places, "scan");
    assert_eq!(
        ents.len(),
        places.len(),
        "each place with coords+title yields one Coordinates entity"
    );

    // The Opera House itself must be present, as a Coordinates entity tagged for
    // GEOINT + Wikipedia + AU state, with the title + a stable article URL.
    let opera = ents
        .iter()
        .find(|e| {
            e.evidence.iter().any(|ev| {
                ev.attributes.get("title").map(String::as_str) == Some("Sydney Opera House")
            })
        })
        .expect("Sydney Opera House present");
    assert_eq!(opera.kind, EntityKind::Coordinates);
    assert!(opera.has_tag("wikipedia") && opera.has_tag("geoint") && opera.has_tag("nearby-place"));
    assert!(
        opera.value.starts_with("-33.856"),
        "place carries its OWN coords, got {}",
        opera.value
    );
    assert!(
        opera
            .evidence
            .iter()
            .filter_map(|ev| ev.attributes.get("url"))
            .any(|v| v.contains("curid=28222")),
        "stable page-id article URL present"
    );
    // Sydney is in NSW — the AU-state tagger must have fired.
    assert!(
        opera.tags.iter().any(|t| t.contains("au-state:NSW") || t == "country:AU"),
        "AU state tagged: {:?}",
        opera.tags
    );
}

#[test]
fn empty_or_placeless_response_yields_nothing() {
    let ents = build_entities("0,0", &[], "scan");
    assert!(ents.is_empty());
    // A place missing coords is skipped rather than panicking.
    let placeless = vec![GeoPlace {
        pageid: Some(1),
        title: Some("No Coords".into()),
        lat: None,
        lon: None,
        dist: Some(5.0),
    }];
    assert!(build_entities("0,0", &placeless, "scan").is_empty());
}

#[test]
fn invalid_coordinates_are_skipped_not_emitted() {
    // Regression guard: the GeoSearch API returns raw floats with no
    // validation of its own. A null-island row (lat=lon=0, a common
    // upstream-bug default) or an out-of-range row must not become a
    // Coordinates entity — only presence of a value was checked before,
    // never validity.
    let places = vec![
        GeoPlace {
            pageid: Some(1),
            title: Some("Null Island Glitch".into()),
            lat: Some(0.0),
            lon: Some(0.0),
            dist: Some(10.0),
        },
        GeoPlace {
            pageid: Some(2),
            title: Some("Out Of Range".into()),
            lat: Some(200.0),
            lon: Some(-999.0),
            dist: Some(20.0),
        },
        GeoPlace {
            pageid: Some(3),
            title: Some("Sydney Opera House".into()),
            lat: Some(-33.8568),
            lon: Some(151.2153),
            dist: Some(0.0),
        },
    ];
    let ents = build_entities("-33.8568,151.2153", &places, "scan");
    assert_eq!(
        ents.len(),
        1,
        "only the one place with valid coords should be emitted, got {ents:?}"
    );
    assert!(
        ents[0]
            .evidence
            .iter()
            .any(|ev| ev.attributes.get("title").map(String::as_str)
                == Some("Sydney Opera House")),
        "the surviving entity must be the valid place, not a null-island/out-of-range one"
    );
}

#[test]
fn module_metadata_is_free_geo_coordinate_consumer() {
    let m = WikiGeoSearch;
    assert_eq!(m.name(), "wiki_geosearch");
    assert!(matches!(m.cost(), ModuleCost::Free));
    assert!(matches!(m.category(), ModuleCategory::Geo));
    assert!(m.accepts(&Target::new(TargetKind::Coordinates, "-33.85,151.21")));
    assert!(!m.accepts(&Target::new(TargetKind::Email, "a@b.com")));
    assert!(m.produces().contains(&EntityKind::Coordinates));
}
