//! Tests for the precision authority (`core::place::grain`), REQ-GEOLABEL-001.
//!
//! The fixtures are the shapes scan 7258fc07 actually stored: the Sydney and
//! Brisbane gazetteer centroids with every record the scan piled onto them,
//! the "Ian Thorpe, North Carolina" street fragments, the pool POI, and the
//! register postcode points.

use super::grain::{
    COORDINATE_TARGET_MODULES, FIX_GRAIN_TAG_PREFIX, best_precision_radius_m,
    geocode_grain_radius_m, is_annotator_row,
};
use super::{FixBasis, FixGrain, FixPrecision, StandsFor, assess};
use crate::core::entity::{Entity, EntityKind, Evidence};

fn coord(value: &str) -> Entity {
    Entity::new(EntityKind::Coordinates, value, 0.7, "s1")
}

fn ev(source: &str, summary: &str, attrs: &[(&str, &str)]) -> Evidence {
    attrs
        .iter()
        .fold(Evidence::new(source, summary), |e, (k, v)| {
            e.with_attr(*k, *v)
        })
}

/// Every record scan 7258fc07 stored on the Sydney centroid, flags as the
/// legacy rows had them (no `is_annotation` on the annotators — the shapes a
/// stored or recalled scan still carries).
fn sydney_7258fc07() -> Entity {
    let mut e = coord("-33.868800,151.209300");
    e.raw_value = "-33.8688,151.2093".to_string();
    for engine in ["duckduckgo", "brave", "mojeek"] {
        e.add_evidence(ev(
            "search_engines",
            &format!("[{engine}] Geocoded from search address: Sydney, Australia"),
            &[
                ("method", "known-city-lookup"),
                ("address", "Sydney, Australia"),
            ],
        ));
    }
    e.add_evidence(ev(
        "search_engines",
        "[bing] Coordinates from recycled search",
        &[("recycle_query", "\"Ian Thorpe\"")],
    ));
    e.add_evidence(ev(
        "overpass",
        "Overpass: 24 infrastructure node(s) within 500m",
        &[("node_count", "24")],
    ));
    e.add_evidence(ev(
        "overpass",
        "Infrastructure breakdown: camera=12",
        &[("categories", "camera=12, cell=12")],
    ));
    e.add_evidence(ev(
        "au_geo",
        "ASGS roll-up",
        &[("au_suburb", "Sydney"), ("au_postcode", "2000")],
    ));
    for phase in ["sunrise", "sunset", "solar_noon"] {
        e.add_evidence(ev("sunrise_sunset", phase, &[("phase", phase)]));
    }
    e.add_evidence(ev(hse_core::RECALL_SOURCE, "recalled", &[]));
    e.add_evidence(ev(
        "geo_normalize",
        "Geospatial enrichment",
        &[("lat", "-33.868800")],
    ));
    e
}

/// REQ-GEOLABEL-001 (P2/P3): the Sydney centroid is a city centroid — every
/// annotator on it (Overpass aggregates, ASGS, solar phases, recall, the
/// enrichment) is skipped, and the gazetteer names what it stands for.
#[test]
fn sydney_centroid_7258fc07_is_the_city_it_stands_for() {
    let p = assess(&sydney_7258fc07());
    assert_eq!(p.grain, FixGrain::Locality, "{p:?}");
    assert_eq!(p.basis, FixBasis::Centroid);
    assert!(p.positive_coarse && p.is_area());
    assert_eq!(
        p.stands_for,
        Some(StandsFor::Gazetteer {
            name: "Sydney".to_string(),
            state: Some("NSW".to_string()),
        })
    );
}

/// REQ-GEOLABEL-001 (P3/P6): the operator's own example coordinate,
/// `-27.4698,153.0251`, is the tabulated Brisbane centroid. The record that
/// put it there is `address_to_coords_pass` carrying a Bardon street
/// address's `geocode` source onto the city centroid (a legacy row with no
/// `place_type`), plus a parcel and an ASGS roll-up looked up BY the point. It
/// grades as the city, never as a 40 m rooftop on "123 Adelaide St" or the
/// parcel containing it.
#[test]
fn brisbane_centroid_is_not_a_street() {
    let mut e = coord("-27.469800,153.025100");
    e.add_evidence(ev(
        "geocode",
        "Inline geocode of address '390, Simpsons Road, Bardon' → -27.4698,153.0251",
        &[
            ("addr_entity_uid", "a1"),
            (
                "addr_value",
                "390, Simpsons Road, Bardon West, Bardon, Brisbane",
            ),
        ],
    ));
    e.add_evidence(ev(
        "qld_cadastre",
        "QLD DCDB cadastral parcel",
        &[("lotplan", "49SP314954"), ("locality", "Brisbane City")],
    ));
    e.add_evidence(ev(
        "au_geo",
        "ASGS roll-up",
        &[("au_suburb", "Brisbane City"), ("au_postcode", "4000")],
    ));
    let p = assess(&e);
    assert_eq!(p.grain, FixGrain::Locality, "{p:?}");
    assert!(
        p.radius_m >= 5_000.0,
        "a city centroid is not a rooftop: {p:?}"
    );
    assert!(p.is_area());
    assert_eq!(
        p.stands_for,
        Some(StandsFor::Gazetteer {
            name: "Brisbane".to_string(),
            state: Some("QLD".to_string()),
        })
    );

    // The operator TYPING the centroid is still the centroid: an operator
    // seed is not a measurement, so the coincidence stands.
    let mut seed = coord("-27.4698,153.0251");
    seed.add_evidence(Evidence::new("seed", "Scan seed"));
    let p = assess(&seed);
    assert_eq!(p.grain, FixGrain::Locality, "{p:?}");
    assert!(p.is_area());

    // Contrast: a MEASURED fix on the same value keeps its measurement — the
    // exemption lifts both the coincidence and the coarser sibling account.
    e.add_evidence(ev("exif_geo", "EXIF GPS", &[("gps_accuracy_m", "8")]));
    let p = assess(&e);
    assert_eq!(p.grain, FixGrain::Point, "{p:?}");
    assert_eq!(p.basis, FixBasis::Measured);
    assert!(!p.is_area());
    assert_eq!(p.stands_for, None);
}

/// REQ-GEOLABEL-001: an Address's source carried onto a centroid by
/// `address_to_coords_pass` (`addr_entity_uid`) is that centroid, whatever the
/// source's class — off every table, so only the row rule can decide it.
#[test]
fn a_carried_address_record_is_a_centroid_even_off_the_tables() {
    let mut e = coord("-27.4801,152.9912");
    assert!(!crate::util::city_coords::is_gazetteer_centroid(
        -27.4801, 152.9912
    ));
    e.add_evidence(ev(
        "qld_cadastre",
        "Inline geocode of address 'Toowong, Queensland'",
        &[("addr_entity_uid", "a2"), ("lotplan", "1RP1")],
    ));
    let p = assess(&e);
    assert_eq!(p.grain, FixGrain::Locality, "{p:?}");
    assert_eq!(p.basis, FixBasis::Centroid);
    assert!(p.is_area());

    // The pass's declared grain is read when present: a postcode centroid is
    // suburb grain.
    let mut pc = coord("-27.4801,152.9912");
    pc.add_evidence(ev(
        "abn_lookup",
        "Inline geocode",
        &[("addr_entity_uid", "a3"), ("place_type", "postcode")],
    ));
    assert_eq!(assess(&pc).grain, FixGrain::Suburb);
}

/// REQ-GEOLABEL-001: a register's postcode-grain record is a postcode
/// centroid and says which postcode.
#[test]
fn a_register_postcode_point_is_a_postcode_centroid() {
    let mut e = coord("-20.0041,145.9004");
    e.add_evidence(ev(
        "qld_unclaimed",
        "QLD unclaimed monies postcode",
        &[("postcode", "4820")],
    ));
    let p = assess(&e);
    assert_eq!(p.grain, FixGrain::Suburb, "{p:?}");
    assert!(p.is_area());
    assert_eq!(
        p.stands_for,
        Some(StandsFor::Postcode {
            code: "4820".to_string(),
            state: Some("QLD".to_string()),
        })
    );
}

/// REQ-GEOLABEL-001 (P4): a forward geocode is no finer than its input.
/// "Ian Thorpe, North Carolina" names a state; Photon's ambiguous street hit
/// "Thorpe-Abbotts Lane" is a surname fragment of a road, so only the state
/// stands. A numbered street address answered at house grain keeps it.
#[test]
fn a_forward_geocode_is_capped_at_its_input() {
    let mut nc = coord("35.102800,-77.102600");
    nc.add_evidence(ev(
        "photon",
        "Photon geocoded \"Ian Thorpe, North Carolina\"",
        &[
            ("input_address", "Ian Thorpe, North Carolina"),
            ("place_name", "Thorpe-Abbotts Lane"),
            ("place_type", "street"),
            ("osm_key", "highway"),
            ("ambiguity_detected", "true"),
        ],
    ));
    let p = assess(&nc);
    assert!(p.grain >= FixGrain::Region, "{p:?}");
    assert!(p.is_area());
    assert_eq!(p.basis, FixBasis::ForwardGeocode);
    assert_eq!(
        p.stands_for,
        Some(StandsFor::Input("Ian Thorpe, North Carolina".to_string()))
    );

    let mut house = coord("-27.482111,152.998765");
    house.add_evidence(ev(
        "geocode",
        "Geocoded \"12 Smith St, Toowong QLD 4066\"",
        &[
            ("input_address", "12 Smith St, Toowong QLD 4066"),
            ("place_type", "house"),
        ],
    ));
    let p = assess(&house);
    assert_eq!(p.grain, FixGrain::Point, "{p:?}");
    assert!(!p.is_area());

    // The same house-grain answer to a city-only question is the city.
    let mut city_only = coord("-27.482111,152.998765");
    city_only.add_evidence(ev(
        "geocode",
        "Geocoded \"Toowong\"",
        &[("input_address", "Toowong"), ("place_type", "house")],
    ));
    let p = assess(&city_only);
    assert_eq!(p.grain, FixGrain::Locality, "{p:?}");
    assert!(p.is_area());
}

/// REQ-GEOLABEL-001 (P4): a Photon `house` hit under a non-address `osm_key`
/// is a point of interest — a mapped feature at the input's administrative
/// grain, never a street address.
#[test]
fn a_photon_house_poi_is_a_mapped_feature() {
    let mut e = coord("-33.877400,151.198900");
    e.add_evidence(ev(
        "photon",
        "Photon geocoded \"Ian Thorpe Aquatic Centre in Ultimo, New South Wales\"",
        &[
            (
                "input_address",
                "Ian Thorpe Aquatic Centre in Ultimo, New South Wales",
            ),
            ("place_name", "Ian Thorpe Aquatic Centre"),
            ("place_type", "house"),
            ("osm_key", "leisure"),
            ("osm_value", "sports_centre"),
        ],
    ));
    let p = assess(&e);
    assert_eq!(p.basis, FixBasis::MappedFeature, "{p:?}");
    assert!(p.grain >= FixGrain::Suburb, "{p:?}");
    assert!(p.is_area());
}

/// REQ-GEOLABEL-001: a GeoNames feature code grades the hit — a populated
/// place is a town, a first-order division a state, and a headland is not a
/// point.
#[test]
fn an_open_meteo_feature_code_grades_the_hit() {
    let graded = |code: &str| {
        let mut e = coord("-21.950000,148.680000");
        e.add_evidence(ev(
            "open_meteo_geo",
            "Geocoded",
            &[("feature_code", code), ("place_name", "X")],
        ));
        assess(&e)
    };
    assert_eq!(graded("PPLA").grain, FixGrain::Locality);
    assert_eq!(graded("MT").grain, FixGrain::Locality);
    assert_eq!(graded("ADM1").grain, FixGrain::Region);
    assert_eq!(graded("PCLI").grain, FixGrain::Country);
    assert!(graded("MT").is_area());
}

/// REQ-GEOLABEL-001 (P2): annotators never set precision — only annotations
/// on a point off the tables is an Unknown point, never positive evidence of
/// an area (so the admission stamp cannot demote it).
#[test]
fn annotators_never_set_precision() {
    let mut e = coord("-27.480100,152.991200");
    e.add_evidence(ev("au_geo", "ASGS", &[("au_suburb", "Toowong")]));
    e.add_evidence(ev("sunrise_sunset", "sunrise", &[]));
    e.add_evidence(ev("geo_normalize", "Geospatial enrichment", &[]));
    e.add_evidence(ev(hse_core::RECALL_SOURCE, "recalled", &[]));
    e.add_evidence(ev("multipath_corroboration", "promotion", &[]));
    e.add_evidence(ev("some_new_module", "a flagged annotation", &[]).as_annotation());
    e.add_evidence(ev("wigle", "Wi-Fi density", &[("density", "sparse")]));
    let p = assess(&e);
    assert_eq!(p.basis, FixBasis::Unknown, "{p:?}");
    assert!(!p.positive_coarse);
    assert!(!p.is_area());
    for r in &e.evidence {
        assert!(is_annotator_row(r), "{r:?}");
    }
    // The seed is never an annotator, though its source is enrichment-only.
    assert!(!is_annotator_row(&Evidence::new("seed", "Scan seed")));
}

/// REQ-GEOLABEL-001 (P12): an unclassified source is graded at the unknown
/// default but is never positive evidence of an area.
#[test]
fn an_unclassified_emitter_is_not_demoted() {
    let mut e = coord("-27.480100,152.991200");
    e.add_evidence(ev("some_new_module", "a point", &[]));
    let p = assess(&e);
    assert_eq!(p.basis, FixBasis::Unknown);
    assert!(!p.positive_coarse && !p.is_area(), "{p:?}");
}

/// REQ-GEOLABEL-001: the coarsest originating account wins, and the answer
/// does not depend on the order the records were merged in.
#[test]
fn coarsest_wins_and_is_order_independent() {
    let rows = [
        ev("ip_geo", "IP geolocation", &[]),
        ev(
            "photon",
            "Photon match",
            &[("place_type", "street"), ("osm_key", "highway")],
        ),
        ev("social_location", "profile location", &[]),
    ];
    let build = |order: &[usize]| {
        let mut e = coord("-27.480100,152.991200");
        for &i in order {
            e.add_evidence(rows[i].clone());
        }
        assess(&e)
    };
    let reference = build(&[0, 1, 2]);
    assert_eq!(reference.grain, FixGrain::Locality, "{reference:?}");
    for order in [[0, 2, 1], [1, 0, 2], [1, 2, 0], [2, 0, 1], [2, 1, 0]] {
        assert_eq!(build(&order), reference, "order {order:?}");
    }
}

/// REQ-GEOLABEL-001: adding an originating record never makes a point finer
/// (outside the measurement exemption) — over a deterministic sweep of
/// generated record sets.
#[test]
fn adding_a_record_never_sharpens_the_point() {
    let pool: Vec<Evidence> = vec![
        ev("geocode", "g", &[("place_type", "house")]),
        ev("geocode", "g", &[("place_type", "city")]),
        ev("photon", "p", &[("place_type", "street")]),
        ev("abn_lookup", "registry", &[]),
        ev("social_location", "bio", &[]),
        ev("phone_area_geo", "prefix", &[]),
        ev("search_engines", "s", &[("method", "known-city-lookup")]),
        ev("open_meteo_geo", "o", &[("feature_code", "PPL")]),
        ev(
            "geocode",
            "g",
            &[("input_address", "Queensland"), ("place_type", "house")],
        ),
        ev("au_geo", "annotation", &[("au_suburb", "X")]),
    ];
    // A fixed linear-congruential walk: reproducible, no RNG dependency.
    let mut state: u64 = 0x5eed;
    let mut next = || {
        state = state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        usize::try_from(state >> 33).unwrap_or(0)
    };
    for _ in 0..300 {
        let n = 1 + next() % 5;
        let picks: Vec<usize> = (0..n).map(|_| next() % pool.len()).collect();
        let mut all = coord("-27.480100,152.991200");
        for &i in &picks {
            all.add_evidence(pool[i].clone());
        }
        let whole = assess(&all);
        for &i in &picks {
            let mut one = coord("-27.480100,152.991200");
            one.add_evidence(pool[i].clone());
            let single = assess(&one);
            if single.basis != FixBasis::Unknown {
                assert!(
                    whole.radius_m >= single.radius_m,
                    "{picks:?}: the set graded {} m, finer than record {i}'s {} m",
                    whole.radius_m,
                    single.radius_m
                );
            }
        }
    }
}

/// REQ-GEOLABEL-001 (P10): a value's own printed decimals cap its precision —
/// a redacted one-decimal value is at least a locality, whatever claims it.
#[test]
fn quantisation_floor_caps_a_one_decimal_value() {
    let mut e = coord("-33.9,151.2");
    e.add_evidence(ev("exif_geo", "EXIF GPS", &[("gps_accuracy_m", "5")]));
    let p = assess(&e);
    assert!(p.radius_m >= 5_500.0, "{p:?}");
    assert!(p.grain >= FixGrain::Locality);
    // Trailing zeros are not precision.
    let mut padded = coord("-33.900000,151.200000");
    padded.add_evidence(ev("exif_geo", "EXIF GPS", &[("gps_accuracy_m", "5")]));
    assert_eq!(assess(&padded).grain, p.grain);
    // A device's own decimals are not floored.
    let mut gps = coord("-27.4801234,152.9912345");
    gps.tag("accuracy:8m");
    gps.add_evidence(ev("signal_radar", "GNSS fix", &[]));
    assert_eq!(assess(&gps).grain, FixGrain::Point);
}

/// REQ-GEOLABEL-001: the legacy signatures of the paths that minted city
/// centroids before `coarse` existed, and the stamped `fix-grain:` tag, are
/// floors.
#[test]
fn legacy_signatures_and_stamps_are_floors() {
    let mut recycled = coord("-27.4801,152.9912");
    recycled.tag(crate::core::tags::RECYCLED);
    recycled.tag(crate::core::tags::ADDR_DERIVED);
    assert!(assess(&recycled).is_area());
    assert_eq!(assess(&recycled).grain, FixGrain::Locality);

    let mut searched = coord("-27.4801,152.9912");
    searched.tag(crate::core::tags::SEARCH_GEOCODED);
    assert!(assess(&searched).is_area());

    let mut stamped = coord("-27.4801,152.9912");
    stamped.add_evidence(ev("geocode", "g", &[("place_type", "house")]));
    stamped.tag(format!("{FIX_GRAIN_TAG_PREFIX}region"));
    let p = assess(&stamped);
    assert_eq!(p.grain, FixGrain::Region, "{p:?}");
    assert!(p.is_area());
}

/// The ladder: every rung's floor lands on that rung, its ceiling admits it,
/// and the tag vocabulary round-trips.
#[test]
fn the_grain_ladder_is_consistent() {
    for g in FixGrain::ALL {
        assert_eq!(FixGrain::from_radius_m(g.floor_m()), g, "{g:?}");
        if let Some(c) = g.ceiling_m() {
            assert_eq!(FixGrain::from_radius_m(c), g);
            assert_eq!(FixGrain::from_radius_m(c.next_up()), g.coarser());
        }
        assert_eq!(FixGrain::parse(g.as_str()), Some(g));
        assert_eq!(g.tag(), format!("{FIX_GRAIN_TAG_PREFIX}{}", g.as_str()));
    }
    assert_eq!(FixGrain::from_radius_m(f64::NAN), FixGrain::Country);
}

/// The grain table only ever coarsens past the geocode class default, and
/// street types now read as a street, not a rooftop (REQ-GEOLABEL-007).
#[test]
fn the_geocoder_grain_table_only_coarsens() {
    for t in [
        "country",
        "state",
        "county",
        "city",
        "administrative",
        "postcode",
        "suburb",
        "street",
        "road",
    ] {
        assert!(geocode_grain_radius_m(t).expect(t) > 40.0, "{t}");
    }
    assert_eq!(
        FixGrain::from_radius_m(geocode_grain_radius_m("street").unwrap()),
        FixGrain::Street
    );
    for t in ["house", "building", "amenity", ""] {
        assert!(geocode_grain_radius_m(t).is_none(), "{t}");
    }
}

/// REQ-GEOLABEL-007 (R3): the correlator's fusion radius is coarsen-only
/// against the grain authority. The Brisbane centroid carried under `geocode`
/// read 40 m before; a precise geocode off the tables keeps its class radius.
#[test]
fn the_fusion_radius_honours_the_grain_authority() {
    let mut bris = coord("-27.4698,153.0251");
    bris.add_evidence(ev(
        "geocode",
        "Inline geocode of address '390, Simpsons Road, Bardon'",
        &[("addr_entity_uid", "a1")],
    ));
    let r = best_precision_radius_m(&bris).expect("geocode anchors");
    assert!(
        r >= 8_000.0,
        "the Brisbane centroid is a city, not a rooftop: {r} m"
    );

    let mut house = coord("-27.482111,152.998765");
    house.add_evidence(ev("geocode", "g", &[("place_type", "house")]));
    let r = best_precision_radius_m(&house).expect("geocode anchors");
    assert!((r - 40.0).abs() < f64::EPSILON, "{r}");

    // No anchoring source: unchanged, `None`.
    let mut ip = coord("-27.482111,152.998765");
    ip.add_evidence(ev("ip_geo", "IP", &[]));
    assert_eq!(best_precision_radius_m(&ip), None);
}

/// REQ-GEOLABEL-001: the role table is complete — every registered module that
/// can be served a `Coordinates` target is listed (a new one cannot silently
/// count as an originator of the point it was asked about), and every listed
/// name is such a module (no stale rows).
#[test]
fn every_coordinate_target_module_has_a_role() {
    let serving: std::collections::BTreeSet<&str> = crate::modules::registry()
        .iter()
        .filter(|m| {
            m.consumes()
                .contains(&crate::core::scan::TargetKind::Coordinates)
        })
        .map(|m| m.name())
        .collect();
    let listed: std::collections::BTreeSet<&str> =
        COORDINATE_TARGET_MODULES.iter().map(|(n, _)| *n).collect();
    assert!(!serving.is_empty(), "vacuity guard");
    assert_eq!(
        serving, listed,
        "core::place::grain::COORDINATE_TARGET_MODULES must list exactly the \
         modules that accept a Coordinates target"
    );
    let names: Vec<&str> = COORDINATE_TARGET_MODULES.iter().map(|(n, _)| *n).collect();
    let mut sorted = names.clone();
    sorted.sort_unstable();
    assert_eq!(names, sorted, "the table is kept sorted by name");
}

/// The precision is a pure function of the entity: the same entity grades the
/// same twice.
#[test]
fn assess_is_deterministic() {
    let a: FixPrecision = assess(&sydney_7258fc07());
    let b: FixPrecision = assess(&sydney_7258fc07());
    assert_eq!(a, b);
}
