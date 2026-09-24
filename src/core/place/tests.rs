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
    assert!(crate::util::city_coords::tabulated_centroid_at(-27.4801, 152.9912).is_none());
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

// ── The nearest-place label (REQ-GEOLABEL-002..004) ───────────────────────

use super::label::{
    FixKind, LabelBasis, PlaceContext, PlaceLabel, bearing_8, describe, describe_fused,
    distance_display_m, radius_display_m,
};

/// A measured fix good to a doorway, off every gazetteer table, at six
/// significant decimals (so the quantisation floor does not coarsen it).
const GPS: (f64, f64) = (-27.481234, 153.012345);

fn gps_fix() -> Entity {
    let mut e = coord(&format!("{:.6},{:.6}", GPS.0, GPS.1));
    e.add_evidence(ev("signal_radar", "GNSS fix", &[("accuracy_m", "8")]));
    e
}

/// A point `metres` due north of `GPS` (1 m of latitude ≈ 1/111 320 °).
fn north_of_gps(metres: f64) -> (f64, f64) {
    (GPS.0 + metres / 111_320.0, GPS.1)
}

/// The `Address` a reverse leg stores for a lookup OF `at`: `source` is
/// `geocode` (Nominatim) or `photon`, `attrs` its structured parts.
fn reverse_address(value: &str, source: &str, at: (f64, f64), attrs: &[(&str, &str)]) -> Entity {
    let mut a = Entity::new(EntityKind::Address, value, 0.7, "s1");
    a.tag("reverse-geocoded");
    a.tag("nearest-address");
    let mut r = ev(
        source,
        &format!("Reverse geocode for {},{}", at.0, at.1),
        &[
            ("latitude", &at.0.to_string()),
            ("longitude", &at.1.to_string()),
        ],
    )
    .with_inferred(true);
    for (k, v) in attrs {
        r = r.with_attr(*k, *v);
    }
    a.add_evidence(r);
    a
}

/// A Nominatim reverse answer at a matched object `metres` north of the fix,
/// ranked `rank`, with the POI name every such answer at zoom 18 carries.
fn nominatim_at(metres: f64, rank: &str, road: &str, suburb: &str) -> Entity {
    let (mlat, mlon) = north_of_gps(metres);
    let (mlat, mlon) = (format!("{mlat:.6}"), format!("{mlon:.6}"));
    reverse_address(
        &format!("12 {road}, {suburb}, Queensland, 4066, Australia"),
        "geocode",
        GPS,
        &[
            ("house_number", "12"),
            ("road", road),
            ("street", &format!("12 {road}")),
            ("suburb", suburb),
            ("city", "Brisbane"),
            ("state", "Queensland"),
            ("postcode", "4066"),
            ("country", "Australia"),
            ("country_code", "AU"),
            ("nearest_feature", "Kazan Dining"),
            ("display_name", "Kazan Dining, 12, Smith Street, Toowong"),
            ("matched_lat", &mlat),
            ("matched_lon", &mlon),
            ("place_rank", rank),
        ],
    )
}

fn label_of(e: &Entity, scan: &[Entity]) -> PlaceLabel {
    describe(e, &PlaceContext::for_scan(scan, "s1")).expect("the point has a label")
}

/// P1 on every label: its grain is never finer than the fix's, and its
/// structured radius never smaller.
fn assert_honest(l: &PlaceLabel, e: &Entity) {
    let fix = assess(e);
    assert_eq!(l.fix_grain, fix.grain, "{l:?}");
    assert!(
        l.label_grain >= l.fix_grain,
        "label finer than the fix: {l:?}"
    );
    // A point with no radius (a country signal) shows none; any other shows
    // a whole number never smaller than its own.
    if fix.radius_m.is_finite() {
        let shown = l.to_json()["fix_radius_m"].as_u64().expect("an integer");
        assert!(shown as f64 >= fix.radius_m.floor(), "{l:?} vs {fix:?}");
    } else {
        assert!(l.to_json()["fix_radius_m"].is_null(), "{l:?}");
    }
}

/// REQ-GEOLABEL-002 (P3/P6): the 7258fc07 Sydney centroid is labelled as the
/// city it stands for — even when this scan holds a reverse geocode of that
/// exact point naming the restaurant and the street that contain the centroid.
#[test]
fn the_sydney_centroid_is_labelled_the_city_never_the_street_containing_it() {
    let e = sydney_7258fc07();
    let kazan = reverse_address(
        "25 Martin Place, Sydney, New South Wales, 2000, Australia",
        "geocode",
        (-33.8688, 151.2093),
        &[
            ("house_number", "25"),
            ("road", "Martin Place"),
            ("suburb", "Sydney"),
            ("nearest_feature", "Kazan Dining"),
            ("matched_lat", "-33.868800"),
            ("matched_lon", "151.209300"),
            ("place_rank", "30"),
        ],
    );
    let nina = reverse_address(
        "Nina Armando, Sydney",
        "photon",
        (-33.8688, 151.2093),
        &[("place_name", "Nina Armando"), ("road", "Martin Place")],
    );
    let l = label_of(&e, &[e.clone(), kazan, nina]);
    assert_eq!(
        l.text,
        "Sydney, NSW (city centroid — not a street location)"
    );
    assert_eq!(l.basis, LabelBasis::Centroid);
    for leak in ["Kazan", "25", "Martin", "Nina", "2000"] {
        assert!(!l.text.contains(leak), "{leak} leaked into {l:?}");
    }
    assert_honest(&l, &e);
}

/// REQ-GEOLABEL-002: the operator's own example. `-27.4698,153.0251 → 123
/// Adelaide St…` is the tabulated Brisbane centroid; it renders as the city,
/// never a street, a parcel, or the ASGS area that contains the centroid.
#[test]
fn the_operators_brisbane_example_renders_as_the_city_centroid() {
    let mut e = coord("-27.469800,153.025100");
    e.add_evidence(ev(
        "geocode",
        "Inline geocode of address '390, Simpsons Road, Bardon' → -27.4698,153.0251",
        &[
            ("addr_entity_uid", "a1"),
            ("addr_value", "390, Simpsons Road, Bardon"),
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
    let adelaide = reverse_address(
        "123 Adelaide Street, Brisbane City",
        "geocode",
        (-27.4698, 153.0251),
        &[
            ("house_number", "123"),
            ("road", "Adelaide Street"),
            ("matched_lat", "-27.469900"),
            ("matched_lon", "153.025100"),
            ("place_rank", "30"),
        ],
    );
    let l = label_of(&e, &[e.clone(), adelaide]);
    assert_eq!(
        l.text,
        "Brisbane, QLD (city centroid — not a street location)"
    );
    for leak in [
        "Adelaide",
        "123",
        "4000",
        "Brisbane City",
        "49SP",
        "Simpsons",
    ] {
        assert!(!l.text.contains(leak), "{leak} leaked into {l:?}");
    }
    assert_eq!(l.label_grain, FixGrain::Locality);
    assert_honest(&l, &e);
}

/// REQ-GEOLABEL-002 (P6): a postcode centroid names its postcode.
#[test]
fn a_postcode_centroid_names_its_postcode_area() {
    let mut e = coord("-20.0041,145.9004");
    e.add_evidence(ev(
        "qld_unclaimed",
        "QLD unclaimed monies postcode",
        &[("postcode", "4820")],
    ));
    let l = label_of(&e, &[]);
    assert_eq!(l.text, "Postcode 4820 area, QLD (postcode centroid, ±4 km)");
    assert_eq!(l.label_grain, FixGrain::Suburb);
    assert_honest(&l, &e);
}

/// REQ-GEOLABEL-002 (P5): a measured fix good to a doorway, reverse-geocoded
/// by this scan, is labelled from the structured parts of that answer — the
/// house number only for an address-point object within the fix's error bar,
/// and never the POI or display name.
#[test]
fn a_measured_fix_takes_this_scans_reverse_observation_within_its_error_bar() {
    let fix = gps_fix();
    let near = nominatim_at(30.0, "30", "Smith Street", "Toowong");
    let l = label_of(&fix, &[fix.clone(), near]);
    assert_eq!(
        l.text,
        "≈ 12 Smith Street, Toowong QLD 4066 (nearest address, ~30 m from the fix; fix ±8 m)"
    );
    assert_eq!(l.basis, LabelBasis::NearestAddress);
    assert_eq!(l.label_grain, FixGrain::Point);
    assert_eq!(l.to_json()["offset_m"], 30);
    assert!(!l.text.contains("Kazan"), "{l:?}");
    assert_honest(&l, &fix);

    // A street object (rank 26): the road, never a house number.
    let street = nominatim_at(30.0, "26", "Smith Street", "Toowong");
    let l = label_of(&fix, &[fix.clone(), street]);
    assert!(
        l.text.starts_with("≈ Smith Street, Toowong QLD 4066"),
        "{l:?}"
    );
    assert_eq!(l.label_grain, FixGrain::Street);

    // 400 m away: beyond max(3r, 150 m) — the suburb, no street.
    let far = nominatim_at(400.0, "30", "Smith Street", "Toowong");
    let l = label_of(&fix, &[fix.clone(), far]);
    assert!(
        l.text
            .starts_with("Toowong QLD 4066 (nearest address, ~400 m"),
        "{l:?}"
    );
    assert_eq!(l.label_grain, FixGrain::Suburb);

    // Over 2 km away: only the locality stands.
    let very_far = nominatim_at(2_500.0, "30", "Smith Street", "Toowong");
    let l = label_of(&fix, &[fix.clone(), very_far]);
    assert!(
        l.text.starts_with("Brisbane, QLD (nearest address, ~2 km"),
        "{l:?}"
    );
    assert_eq!(l.label_grain, FixGrain::Locality);
}

/// REQ-GEOLABEL-002 (P5): providers that disagree coarsen the label, a merge
/// splice (`"a; b"`) names nothing, and an answer that never recorded where
/// its object lies names no street.
#[test]
fn disagreement_splices_and_unrecorded_offsets_coarsen_the_nearest_address() {
    let fix = gps_fix();
    let nominatim = nominatim_at(20.0, "30", "Smith Street", "Toowong");
    let (plat, plon) = north_of_gps(25.0);
    let photon_other_road = reverse_address(
        "14 Jones Road, Toowong",
        "photon",
        GPS,
        &[
            ("house_number", "14"),
            ("road", "Jones Road"),
            ("suburb", "Toowong"),
            ("matched_lat", &format!("{plat:.6}")),
            ("matched_lon", &format!("{plon:.6}")),
        ],
    );
    let l = label_of(&fix, &[fix.clone(), nominatim.clone(), photon_other_road]);
    assert!(
        l.text.starts_with("Toowong QLD 4066"),
        "road conflict → suburb: {l:?}"
    );
    let photon_other_suburb = reverse_address(
        "Smith Street, Auchenflower",
        "photon",
        GPS,
        &[("road", "Smith Street"), ("suburb", "Auchenflower")],
    );
    let l = label_of(&fix, &[fix.clone(), nominatim, photon_other_suburb]);
    assert!(
        l.text.starts_with("Brisbane, QLD"),
        "suburb conflict → locality: {l:?}"
    );

    let spliced = nominatim_at(20.0, "30", "Smith Street; Jones Road", "Toowong");
    let l = label_of(&fix, &[fix.clone(), spliced]);
    assert!(
        !l.text.contains("Smith") && !l.text.contains("Jones"),
        "{l:?}"
    );

    let legacy = reverse_address(
        "12 Smith Street, Toowong",
        "geocode",
        GPS,
        &[
            ("street", "12 Smith Street"),
            ("suburb", "Toowong"),
            ("state", "Queensland"),
            ("postcode", "4066"),
            ("country_code", "AU"),
        ],
    );
    let l = label_of(&fix, &[fix.clone(), legacy]);
    assert_eq!(
        l.text,
        "Toowong QLD 4066 (nearest address, offset unrecorded; fix ±8 m)"
    );
}

/// REQ-GEOLABEL-002: only THIS scan's own, confirmed observation of the exact
/// point is read — never another scan's recalled row, a quarantined answer,
/// an answer for a neighbouring point, or one for a fix that is not measured.
#[test]
fn only_this_scans_confirmed_observation_of_the_exact_point_is_read() {
    let fix = gps_fix();
    let mut other_scan = nominatim_at(20.0, "30", "Smith Street", "Toowong");
    other_scan.evidence[0].scan_id = "s0".to_string();
    let l = label_of(&fix, &[fix.clone(), other_scan]);
    assert_ne!(l.basis, LabelBasis::NearestAddress, "{l:?}");

    let mut quarantined = nominatim_at(20.0, "30", "Smith Street", "Toowong");
    quarantined.tag(crate::core::tags::CANDIDATE);
    let l = label_of(&fix, &[fix.clone(), quarantined]);
    assert_ne!(l.basis, LabelBasis::NearestAddress, "{l:?}");

    let mut neighbour = nominatim_at(20.0, "30", "Smith Street", "Toowong");
    neighbour.evidence[0]
        .attributes
        .insert("latitude".into(), format!("{}", GPS.0 + 0.00001));
    let l = label_of(&fix, &[fix.clone(), neighbour]);
    assert_ne!(l.basis, LabelBasis::NearestAddress, "{l:?}");

    // A value from a snippet (unclassified provenance) is not measured.
    let mut snippet = coord(&format!("{:.6},{:.6}", GPS.0, GPS.1));
    snippet.add_evidence(ev("some_module", "a page printed it", &[]));
    let obs = nominatim_at(20.0, "30", "Smith Street", "Toowong");
    let l = label_of(&snippet, &[snippet.clone(), obs]);
    assert_ne!(l.basis, LabelBasis::NearestAddress, "{l:?}");
    assert!(!l.text.contains("Smith"), "{l:?}");
    assert_honest(&l, &snippet);
}

/// REQ-GEOLABEL-002 (P9): a point that IS a mapped feature is labelled with
/// its own stored name, worded so it cannot read as anyone's address.
#[test]
fn a_mapped_feature_labels_itself_as_a_mapped_place() {
    let mut e = coord("-33.868000,151.209700");
    e.tag("nearby-place");
    e.add_evidence(ev(
        "wiki_geosearch",
        "Wikipedia place 'The Australia Hotel' near -33.8688,151.2093",
        &[("title", "The Australia Hotel"), ("distance_m", "90")],
    ));
    let l = label_of(&e, &[]);
    assert!(
        l.text
            .starts_with("The Australia Hotel — mapped place, Sydney, NSW"),
        "{l:?}"
    );
    assert!(l.text.contains("not an address of the subject"), "{l:?}");
    assert_eq!(l.basis, LabelBasis::MappedFeature);
    assert_honest(&l, &e);

    // A Wikidata item is a mapped feature too, though its records are written
    // under the corpus's name.
    let mut w = coord("-33.856700,151.215300");
    w.add_evidence(ev(
        "wikidata",
        "Wikidata place 'Sydney Opera House' (Q45178)",
        &[("qid", "Q45178"), ("label", "Sydney Opera House")],
    ));
    assert_eq!(assess(&w).basis, FixBasis::MappedFeature);
    assert!(
        label_of(&w, &[])
            .text
            .starts_with("Sydney Opera House — mapped place")
    );

    // An OSM infrastructure node is prefixed as infrastructure.
    let mut cam = coord("-33.867900,151.208800");
    cam.tag("infra:camera");
    cam.add_evidence(ev(
        "overpass",
        "OSM camera node/1 near X",
        &[("category", "camera")],
    ));
    let l = label_of(&cam, &[]);
    assert!(
        l.text
            .starts_with("infrastructure: OSM camera — mapped place"),
        "{l:?}"
    );
}

/// REQ-GEOLABEL-002 (P4): a forward geocode is labelled from its own stored
/// answer at the grain its input supports — a numbered address keeps its
/// street, a surname-fragment street hit for a state-only input keeps only
/// the country its record names, and a point of interest never lends its name.
#[test]
fn a_forward_geocode_labels_itself_at_its_input_grain() {
    let mut house = coord("-27.482111,152.998765");
    house.add_evidence(ev(
        "geocode",
        "Geocoded \"12 Smith St, Toowong QLD 4066\"",
        &[
            ("input_address", "12 Smith St, Toowong QLD 4066"),
            ("place_type", "house"),
            ("house_number", "12"),
            ("road", "Smith Street"),
            ("street", "12 Smith Street"),
            ("suburb", "Toowong"),
            ("city", "Brisbane"),
            ("state", "Queensland"),
            ("postcode", "4066"),
            ("country_code", "AU"),
        ],
    ));
    let l = label_of(&house, &[]);
    assert_eq!(
        l.text,
        "12 Smith Street, Toowong QLD 4066 (forward geocode; point-level, ±40 m)"
    );
    assert_eq!(l.basis, LabelBasis::ForwardGeocode);
    assert_honest(&l, &house);

    let mut nc = coord("35.102800,-77.102600");
    nc.add_evidence(ev(
        "photon",
        "Photon geocoded \"Ian Thorpe, North Carolina\"",
        &[
            ("input_address", "Ian Thorpe, North Carolina"),
            ("place_name", "Thorpe-Abbotts Lane"),
            ("place_type", "street"),
            ("osm_key", "highway"),
            ("country_code", "US"),
            ("ambiguity_detected", "true"),
        ],
    ));
    let l = label_of(&nc, &[]);
    assert!(l.text.starts_with("United States"), "{l:?}");
    assert!(!l.text.contains("Thorpe"), "{l:?}");
    assert_honest(&l, &nc);

    let mut poi = coord("-33.877400,151.198900");
    poi.add_evidence(ev(
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
            ("country_code", "AU"),
        ],
    ));
    let l = label_of(&poi, &[]);
    assert!(
        !l.text.contains("Aquatic") && !l.text.contains("Thorpe"),
        "{l:?}"
    );
    assert!(l.label_grain >= FixGrain::Suburb, "{l:?}");
    assert_honest(&l, &poi);
}

/// REQ-GEOLABEL-002 (P7): the ASGS area of a point is read only at the grain
/// the fix supports, and never on a centroid.
#[test]
fn a_statistical_area_is_read_only_at_the_grain_it_supports() {
    let mut phone = coord("-27.481234,153.012345");
    phone.add_evidence(ev("social_location", "bio says Toowong", &[]));
    phone.add_evidence(ev(
        "au_geo",
        "ASGS roll-up",
        &[
            ("au_suburb", "Toowong"),
            ("au_postcode", "4066"),
            ("au_lga", "Brisbane"),
        ],
    ));
    // Social is 5 km: the suburb, but not the postcode (≤ 1.5 km only).
    let l = label_of(&phone, &[]);
    assert_eq!(l.text, "Toowong QLD (statistical-area lookup; fix ±5 km)");
    assert_eq!(l.basis, LabelBasis::StatisticalArea);
    assert_honest(&l, &phone);
}

/// REQ-GEOLABEL-002 (P10): a redacted export's one-decimal values label at a
/// locality at best — no street, no house number, no mapped feature's name.
#[test]
fn redacted_values_never_label_finer_than_a_locality() {
    let fix = gps_fix();
    let obs = nominatim_at(20.0, "30", "Smith Street", "Toowong");
    let mut feature = coord("-33.868000,151.209700");
    feature.add_evidence(ev(
        "wiki_geosearch",
        "Wikipedia place 'The Australia Hotel'",
        &[("title", "The Australia Hotel")],
    ));
    let mut all = vec![fix, obs, feature];
    crate::util::redact::redact_entities(&mut all);
    let ctx = PlaceContext::for_scan(&all, "s1");
    for e in all.iter().filter(|e| e.kind == EntityKind::Coordinates) {
        let l = describe(e, &ctx).expect("a redacted point still has a place");
        assert!(l.label_grain >= FixGrain::Locality, "{l:?}");
        for leak in ["Smith", "12 ", "4066", "Australia Hotel", "≈"] {
            assert!(!l.text.contains(leak), "{leak} leaked: {l:?}");
        }
        assert_honest(&l, e);
    }
}

/// REQ-GEOLABEL-002 (P8): a fused fix is offline, locality at best, never a
/// street or a point of interest, and says it is fused. The 7258fc07 headline
/// was the Ian Thorpe Aquatic Centre's position ±1.3 km.
#[test]
fn a_fused_fix_is_a_locality_and_says_so() {
    let l = describe_fused(-33.8774, 151.1989, 1.3, FixKind::Synergy).expect("Sydney");
    assert_eq!(l.text, "Sydney, NSW (fused fix ±2 km)");
    assert_eq!(l.basis, LabelBasis::Fused);
    assert!(l.label_grain >= FixGrain::Locality);
    // Wider than a locality: the state.
    let wide = describe_fused(-27.47, 153.02, 60.0, FixKind::Synergy).expect("QLD");
    assert_eq!(wide.text, "Queensland, Australia (fused fix ±60 km)");
    assert!(
        describe_fused(0.0, -140.0, 1.0, FixKind::Synergy).is_none(),
        "open ocean"
    );
    assert!(
        describe_fused(95.0, 0.0, 1.0, FixKind::Synergy).is_none(),
        "invalid"
    );
}

/// REQ-GEOLABEL-002 (P13): the offline gazetteer words distance and an
/// 8-point bearing only when they exceed the fix's own radius, names Vietnam's
/// centrally-run cities, and says "remote" for an outback point.
#[test]
fn the_offline_gazetteer_words_distance_bearing_and_remoteness() {
    let at = |lat: f64, lon: f64, radius_km: f64| {
        describe_fused(lat, lon, radius_km, FixKind::Synergy)
            .expect("placed")
            .text
    };
    // ~16 km north-east of Toowoomba, from a fix good to 1 km.
    let t = at(-27.45, 152.07, 0.5);
    assert!(
        t.starts_with("~15 km NE of Toowoomba, QLD") || t.contains("of "),
        "{t}"
    );
    assert!(t.contains(" of "), "{t}");
    // The same point from a 30 km fix: an offset inside the radius is not worded.
    assert!(!at(-27.45, 152.07, 25.0).contains(" of "));
    assert!(at(-23.0, 135.5, 1.0).starts_with("remote NT — nearest centre"));
    assert_eq!(
        at(21.0285, 105.8542, 1.0),
        "Hà Nội, Vietnam (fused fix ±1 km)"
    );
    assert!(at(10.80, 106.66, 1.0).contains("TP. Hồ Chí Minh, Vietnam"));
    // Vientiane is not "near Hà Nội" — the country box says VN, the anchors don't.
    assert!(!at(17.97, 102.63, 1.0).contains("Hà Nội"));
    assert!(
        at(40.75, -73.99, 1.0).contains("of New York"),
        "{}",
        at(40.75, -73.99, 1.0)
    );
}

/// REQ-GEOLABEL-003 (P13): rounding tables — radius UP to one significant
/// figure, distances to fixed buckets, bearings from integer sectors, no
/// `-0` anywhere.
#[test]
fn rounding_and_bearing_tables() {
    assert_eq!(radius_display_m(55.66), 60);
    assert_eq!(radius_display_m(1_300.0), 2_000);
    assert_eq!(radius_display_m(8_000.0), 8_000);
    assert_eq!(radius_display_m(FixGrain::Locality.floor_m()), 5_000);
    assert_eq!(radius_display_m(0.0), 0);
    assert_eq!(radius_display_m(-3.0), 0);
    assert_eq!(distance_display_m(34.0), 30);
    assert_eq!(distance_display_m(430.0), 450);
    assert_eq!(distance_display_m(2_600.0), 3_000);
    assert_eq!(distance_display_m(16_000.0), 15_000);
    assert_eq!(distance_display_m(-0.0), 0);
    assert_eq!(bearing_8(0.0, 0.0, 1.0, 0.0), "N");
    assert_eq!(bearing_8(0.0, 0.0, 0.0, 1.0), "E");
    assert_eq!(bearing_8(0.0, 0.0, -1.0, -1.0), "SW");
    assert_eq!(bearing_8(0.0, 0.0, 1.0, 1.0), "NE");
    assert_eq!(
        bearing_8(0.0, 179.9, 0.0, -179.9),
        "E",
        "across the antimeridian"
    );
}

/// REQ-GEOLABEL-003: a label depends on the records, never their order — the
/// entity's evidence permuted, and the scan's entities permuted, give the
/// same label byte for byte.
#[test]
fn labels_are_independent_of_record_and_entity_order() {
    let fix = gps_fix();
    let a = nominatim_at(20.0, "30", "Smith Street", "Toowong");
    let (plat, plon) = north_of_gps(40.0);
    let b = reverse_address(
        "12 Smith Street, Toowong",
        "photon",
        GPS,
        &[
            ("house_number", "12"),
            ("road", "Smith Street"),
            ("suburb", "Toowong"),
            ("matched_lat", &format!("{plat:.6}")),
            ("matched_lon", &format!("{plon:.6}")),
        ],
    );
    let want = label_of(&fix, &[fix.clone(), a.clone(), b.clone()]);
    let got = label_of(&fix, &[b, fix.clone(), a]);
    assert_eq!(want, got);

    let mut e = sydney_7258fc07();
    let want = label_of(&e, &[]);
    e.evidence.reverse();
    assert_eq!(want, label_of(&e, &[]));
}

/// REQ-GEOLABEL-003: two answers the same leg gave for the same point — same
/// provider, same offset, same summary, different house numbers, stored on two
/// `Address` entities — are told apart by the answer itself, so the label is
/// the same whichever order the store returns them in. Before the content
/// tie-break the first-listed answer won.
#[test]
fn a_tie_between_two_answers_is_broken_by_the_answer_not_the_order() {
    let fix = gps_fix();
    let (mlat, mlon) = north_of_gps(20.0);
    let (mlat, mlon) = (format!("{mlat:.6}"), format!("{mlon:.6}"));
    let answer = |n: &str| {
        reverse_address(
            &format!("{n} Smith Street, Toowong, Queensland, 4066, Australia"),
            "geocode",
            GPS,
            &[
                ("house_number", n),
                ("road", "Smith Street"),
                ("suburb", "Toowong"),
                ("state", "Queensland"),
                ("postcode", "4066"),
                ("country_code", "AU"),
                ("matched_lat", &mlat),
                ("matched_lon", &mlon),
                ("place_rank", "30"),
            ],
        )
    };
    let (twelve, fourteen) = (answer("12"), answer("14"));
    let a = label_of(&fix, &[fix.clone(), fourteen.clone(), twelve.clone()]);
    let b = label_of(&fix, &[fix.clone(), twelve, fourteen]);
    assert_eq!(a, b);
    assert!(a.text.starts_with("≈ 12 Smith Street"), "{}", a.text);
}

/// REQ-GEOLABEL-002: only coordinates are labelled; the radar sweep's `0,0`
/// sentinel is not a place.
#[test]
fn only_real_coordinates_are_labelled() {
    let ctx = PlaceContext::default();
    let email = Entity::new(EntityKind::Email, "a@b.test", 0.9, "s1");
    assert!(describe(&email, &ctx).is_none());
    let sentinel = coord(crate::core::scan::RADAR_SENTINEL_COORD_NORMALISED);
    assert!(describe(&sentinel, &ctx).is_none());
    assert!(describe(&coord("not,a-point"), &ctx).is_none());
}

// ── Review round 1 ────────────────────────────────────────────────────────

/// REQ-GEOLABEL-009: a country-grain signal is labelled as the COUNTRY. A
/// `+64` phone prefix puts its point on Wellington's row, a `.au` email
/// domain on Sydney's, `+61` at the continent's centre; each names a country
/// and nothing finer, and was labelled as the city (or a "remote NT" state
/// phrase) at locality grain.
#[test]
fn a_country_signal_is_labelled_the_country_never_a_city() {
    let phone = |value: &str, cc: &str, country: &str| {
        let mut e = coord(value);
        for t in ["geoint", "phone-prefix", "coarse"] {
            e.tag(t);
        }
        e.tag(format!("country:{cc}"));
        e.add_evidence(ev(
            "geo_intel",
            &format!("Phone prefix -> {country} for +000"),
            &[
                ("country", country),
                ("country_code", cc),
                ("method", "e164-prefix"),
            ],
        ));
        e
    };
    let nz = phone("-41.2865,174.7762", "NZ", "New Zealand");
    let au = phone("-25.2744,133.7751", "AU", "Australia");
    let mut email = coord("-33.8688,151.2093");
    for t in ["geoint", "coarse", "cctld-inferred"] {
        email.tag(t);
    }
    email.add_evidence(ev(
        "email_locale",
        "Email domain ccTLD .au indicates Australia",
        &[("cctld", "au"), ("locale", "en-au")],
    ));
    for (e, country, never) in [
        (&nz, "New Zealand", "Wellington"),
        (&au, "Australia", "Alice Springs"),
        (&email, "Australia", "Sydney"),
    ] {
        let p = assess(e);
        assert_eq!(p.grain, FixGrain::Country, "{p:?}");
        let l = label_of(e, std::slice::from_ref(e));
        assert_eq!(l.label_grain, FixGrain::Country, "{l:?}");
        assert!(l.text.starts_with(country), "{l:?}");
        assert!(
            !l.text.contains(never),
            "{never} is finer than the fix: {l:?}"
        );
        assert_honest(&l, e);
    }
    // The record alone (a copy whose tags were not carried) is the country.
    let mut untagged = nz.clone();
    untagged
        .tags
        .retain(|t| t != "phone-prefix" && t != "coarse");
    assert_eq!(assess(&untagged).grain, FixGrain::Country);
    // A re-imported copy keeps its tags but not its attributes: the tag alone
    // still reads as the country.
    let mut bare = coord("-41.2865,174.7762");
    bare.tag("phone-prefix");
    bare.add_evidence(ev("geo_intel", "Phone prefix -> New Zealand for +000", &[]));
    assert_eq!(assess(&bare).grain, FixGrain::Country);
    // A fine measurement on the same value is not demoted by the tag.
    let mut gps = coord("-41.286512,174.776234");
    gps.tag("phone-prefix");
    gps.add_evidence(ev("signal_radar", "GNSS fix", &[("accuracy_m", "8")]));
    assert_eq!(assess(&gps).grain, FixGrain::Point);
}

/// REQ-GEOLABEL-011: a positive radius never shows as zero. The operator's
/// seed typed to six decimals is good to its quantisation (~0.06 m); the
/// whole-metre step rounded it to `0`, a fix claiming no error at all.
#[test]
fn a_sub_metre_radius_shows_as_one_metre_never_zero() {
    assert_eq!(radius_display_m(0.0557), 1);
    assert_eq!(radius_display_m(0.3), 1);
    assert_eq!(radius_display_m(1.0), 1);
    assert_eq!(radius_display_m(1.2), 2);
    let mut seed = coord("-27.470123,153.021456");
    seed.add_evidence(ev("seed", "Operator seed", &[]));
    let l = label_of(&seed, std::slice::from_ref(&seed));
    assert_eq!(l.to_json()["fix_radius_m"], 1, "{l:?}");
    assert!(!l.text.contains("±0 m"), "{l:?}");
}

/// REQ-GEOLABEL-012: a value CUT below the gazetteer's 4-decimal key (a
/// redacted export) is never read as the table row it happens to land on. A
/// geocoded Parramatta address redacted to `-33.8,151.0` sits exactly on the
/// REGIONS row "21", and an inner-west Melbourne fix redacted to
/// `-37.8,144.9` on the Footscray anchor.
#[test]
fn a_redacted_value_is_not_the_table_row_it_lands_on() {
    // `-37.8,144.9` is also exactly the Footscray anchor: a suburb name for a
    // locality-grade fix would undo the redaction (REQ-GEOLABEL-030).
    for (value, never) in [
        ("-33.8,151.0", "Postcode 21xx"),
        ("-37.8,144.9", "city centroid"),
        ("-37.8,144.9", "Footscray"),
    ] {
        let mut e = coord("-33.815678,151.003456");
        e.add_evidence(ev(
            "geocode",
            "Geocoded \"12 Church St, Parramatta NSW 2150\"",
            &[
                ("input_address", "12 Church St, Parramatta NSW 2150"),
                ("place_type", "house"),
            ],
        ));
        e.value = value.to_string();
        e.raw_value = value.to_string();
        let p = assess(&e);
        assert_eq!(p.stands_for, None, "{value}: {p:?}");
        assert_eq!(p.grain, FixGrain::Locality, "{value}: {p:?}");
        let l = label_of(&e, std::slice::from_ref(&e));
        assert!(!l.text.contains(never), "{value}: {l:?}");
        assert!(!l.text.contains("region-level"), "{value}: {l:?}");
        assert_honest(&l, &e);
    }
    // Control: the SAME row minted at full width is still recognised.
    let region = coord("-33.800000,151.000000");
    assert!(
        assess(&region).stands_for.is_some(),
        "{:?}",
        assess(&region)
    );
}

/// REQ-GEOLABEL-013: two redactions of identical precision grade alike. The
/// redactor always prints one decimal, so `-28.0,153.0` is one decimal like
/// `-27.9,153.0`; reading its printed `0` as no digit graded it a region
/// (±56 km) beside a locality (±6 km).
#[test]
fn redactions_of_equal_precision_grade_alike() {
    let graded = |v: &str| {
        let mut e = coord("-27.960000,153.040000");
        e.value = v.to_string();
        e.raw_value = v.to_string();
        let p = assess(&e);
        (p.grain, p.radius_m)
    };
    assert_eq!(graded("-28.0,153.0"), graded("-27.9,153.0"));
    assert_eq!(graded("-28.0,153.0").0, FixGrain::Locality);
    // Trailing zeros of a WIDER value are still not precision.
    let mut padded = coord("-33.900000,151.200000");
    padded.add_evidence(ev("exif_geo", "EXIF GPS", &[("gps_accuracy_m", "5")]));
    assert!(assess(&padded).radius_m >= 5_500.0);
}

/// REQ-GEOLABEL-015: a scan's own reverse observation is read even when a
/// recalled prior scan made the identical one. Recall pre-loads the prior
/// Address (its rows still name the prior scan), the live leg re-observes the
/// same point with the same summary, and the two rows merge; the merged row
/// must name the scan that is building it, or the new scan's label skips its
/// own observation as another scan's.
#[test]
fn a_recalled_observation_re_made_live_is_this_scans() {
    let fix = gps_fix();
    // What `recall_prior_entities` hands the new scan: the prior scan's
    // Address, re-stamped to the new scan, its evidence rows untouched.
    let mut recalled = nominatim_at(20.0, "30", "Smith Street", "Toowong");
    recalled.evidence[0].scan_id = "s0".to_string();
    recalled.scan_id = "s1".to_string();
    // The new scan's live reverse leg: the identical record, this scan's.
    let live = nominatim_at(20.0, "30", "Smith Street", "Toowong");
    for (mut held, incoming) in [(recalled.clone(), live.clone()), (live, recalled)] {
        held.merge(incoming);
        assert_eq!(held.evidence.len(), 1, "one record");
        let l = label_of(&fix, &[fix.clone(), held]);
        assert_eq!(l.basis, LabelBasis::NearestAddress, "{l:?}");
        assert!(l.text.contains("Smith Street"), "{l:?}");
    }
    // Not re-observed: the recalled row alone is still the prior scan's.
    let mut stale = nominatim_at(20.0, "30", "Smith Street", "Toowong");
    stale.evidence[0].scan_id = "s0".to_string();
    stale.scan_id = "s1".to_string();
    let l = label_of(&fix, &[fix.clone(), stale]);
    assert_ne!(l.basis, LabelBasis::NearestAddress, "{l:?}");
}

/// REQ-GEOLABEL-016: one point, one grain stamp — the coarsest — however the
/// store's tag union combined them.
#[test]
fn a_point_keeps_one_grain_stamp_the_coarsest() {
    use super::grain::collapse_fix_grain_tags;
    let mut tags: Vec<String> = ["coarse", "fix-grain:locality", "geoint", "fix-grain:region"]
        .map(String::from)
        .to_vec();
    collapse_fix_grain_tags(&mut tags);
    assert_eq!(tags, ["coarse", "fix-grain:region", "geoint"]);
    collapse_fix_grain_tags(&mut tags);
    assert_eq!(tags, ["coarse", "fix-grain:region", "geoint"], "idempotent");
    let mut none: Vec<String> = vec!["coarse".into()];
    collapse_fix_grain_tags(&mut none);
    assert_eq!(none, ["coarse"]);
}

/// The point `address_to_coords_pass` carries from an Address that names
/// `city` onto the city's tabulated centroid — the shape a Sydney ABN address
/// or a Wellington register address takes (`addr_entity_uid`, `place_type`).
fn city_address_centroid(value: &str, source: &str, city: &str) -> Entity {
    let mut e = coord(value);
    e.tag("addr-derived");
    e.add_evidence(ev(
        source,
        &format!("Inline geocode of address '{city}'"),
        &[("addr_entity_uid", "a1"), ("place_type", "city")],
    ));
    e
}

/// A `.au` email's ccTLD point, as `email_locale` mints it (Sydney's row).
fn au_email_point() -> Entity {
    let mut e = coord("-33.8688,151.2093");
    for t in ["geoint", "coarse", "cctld-inferred"] {
        e.tag(t);
    }
    e.add_evidence(ev(
        "email_locale",
        "Email domain ccTLD .au indicates Australia",
        &[("cctld", "au"), ("locale", "en-au")],
    ));
    e
}

/// A `+64` number's dialling-prefix point, as `geo_intel` mints it
/// (Wellington's row).
fn nz_prefix_point() -> Entity {
    let mut e = coord("-41.2865,174.7762");
    for t in ["geoint", "phone-prefix", "coarse", "country:NZ"] {
        e.tag(t);
    }
    e.add_evidence(ev(
        "geo_intel",
        "Phone prefix -> New Zealand for +6444990000",
        &[
            ("country", "New Zealand"),
            ("country_code", "NZ"),
            ("method", "e164-prefix"),
        ],
    ));
    e
}

/// REQ-GEOLABEL-019: a country signal never erases a real finding of the
/// city its stand-in sits on. `email_locale` puts a `.au` domain on Sydney's
/// row and `geo_intel` puts `+64` on Wellington's; a Sydney ABN address or a
/// `+64 4` landline's area code resolves through `city_coords` to the very
/// same value, the two merge, and the coarsest-wins rule let the signal
/// grade the merged point "Australia" / "New Zealand". The finding is the
/// reading of the point; merging the signal in changes nothing about it.
#[test]
fn a_country_signal_never_erases_a_city_finding_on_its_stand_in() {
    let sydney = city_address_centroid("-33.868800,151.209300", "abn_lookup", "Sydney NSW");
    let wellington = city_address_centroid("-41.286500,174.776200", "asic_director", "Wellington");
    // `phone_geo`'s area-code point: a Provider account of its own (100 km).
    let mut area_code = coord("-41.2865,174.7762");
    for t in ["addr-derived", "geoint", "phone-area-code", "country:NZ"] {
        area_code.tag(t);
    }
    area_code.add_evidence(ev(
        "phone_area_geo",
        "Phone area code 4 → Wellington, New Zealand",
        &[
            ("area_code", "4"),
            ("country", "New Zealand"),
            ("country_code", "NZ"),
        ],
    ));
    for (finding, signal, city) in [
        (&sydney, au_email_point(), Some("Sydney")),
        (&wellington, nz_prefix_point(), Some("Wellington")),
        (&area_code, nz_prefix_point(), None),
    ] {
        assert_eq!(finding.uid, signal.uid, "the stand-in IS the city's row");
        let alone = assess(finding);
        for (mut held, incoming) in [
            (finding.clone(), signal.clone()),
            (signal.clone(), finding.clone()),
        ] {
            held.merge(incoming);
            let p = assess(&held);
            assert_eq!(p, alone, "the signal changed the finding: {p:?}");
            assert_ne!(p.grain, FixGrain::Country, "{p:?}");
            let l = label_of(&held, std::slice::from_ref(&held));
            if let Some(city) = city {
                assert!(l.text.starts_with(city), "{l:?}");
                assert!(l.text.contains("city centroid"), "{l:?}");
            }
            assert!(!l.text.contains("country-level"), "{l:?}");
            assert_honest(&l, &held);
        }
    }
    // Control: the signal alone is still the country, with no disc.
    for signal in [au_email_point(), nz_prefix_point()] {
        let p = assess(&signal);
        assert_eq!(p.grain, FixGrain::Country, "{p:?}");
        assert_eq!(p.basis, FixBasis::CountrySignal, "{p:?}");
        assert_eq!(p.stands_for, None, "{p:?}");
    }
    // The signal's own CSV copy explains nothing, so it does not set the
    // signal aside: `geo_intel`'s record without its `method` is still read
    // through its tag, and so is `email_locale`'s beside it.
    let mut bare = coord("-41.2865,174.7762");
    bare.tag("phone-prefix");
    bare.add_evidence(ev("geo_intel", "Phone prefix -> New Zealand for +000", &[]));
    bare.add_evidence(ev("email_locale", "Email domain ccTLD .nz", &[]));
    assert_eq!(assess(&bare).grain, FixGrain::Country);
}

/// REQ-GEOLABEL-024: a city finding from an UNCLASSIFIED source is not erased
/// by a country signal either. REQ-GEOLABEL-019 let only a classified account
/// set the signal aside, and skipped the gazetteer coincidence whenever a
/// signal was read — so a GitLab profile's "Sydney" (`profile_kit`), a
/// NumVerify line's "Wellington, New Zealand" or an ASIC register's Sydney
/// address, each minted through `city_coords` onto the very row the `.au` /
/// `+64` stand-in sits on, merged with the signal and read "Australia" /
/// "New Zealand (country-level signal)". Alone, each reads as its city.
#[test]
fn an_unclassified_city_finding_is_never_erased_by_a_country_signal() {
    let row = |place: &str| {
        let (lat, lon) = crate::util::city_coords::city_coords(place).expect("tabulated");
        format!("{lat:.4},{lon:.4}")
    };
    let finding = |place: &str, source: &str, attrs: &[(&str, &str)], tags: &[&str]| {
        let mut e = coord(&row(place));
        for t in tags {
            e.tag(*t);
        }
        e.add_evidence(ev(source, &format!("{source}: {place}"), attrs));
        e
    };
    let gitlab = finding(
        "Sydney",
        "gitlab_user",
        &[("source_field", "location")],
        &["addr-derived", "geoint", "gitlab"],
    );
    let numverify = finding(
        "Wellington, New Zealand",
        "numverify",
        &[
            ("carrier", "Spark"),
            ("line_type", "landline"),
            ("country_code", "NZ"),
        ],
        &["numverify", "addr-derived", "geoint", "phone-region"],
    );
    let asic = finding(
        "Level 5, 10 Smith St, Sydney NSW 2000",
        "asic_persons",
        &[("source_address", "Level 5, 10 Smith St, Sydney NSW 2000")],
        &["au", "asic", "addr-derived", "geoint", "country:AU"],
    );
    for (finding, signal, city) in [
        (&gitlab, au_email_point(), "Sydney"),
        (&numverify, nz_prefix_point(), "Wellington"),
        (&asic, au_email_point(), "Sydney"),
    ] {
        assert_eq!(finding.uid, signal.uid, "the stand-in IS the city's row");
        let alone = assess(finding);
        assert_ne!(alone.grain, FixGrain::Country, "{alone:?}");
        let alone_label = label_of(finding, std::slice::from_ref(finding));
        assert!(alone_label.text.starts_with(city), "{alone_label:?}");
        for (mut held, incoming) in [
            (finding.clone(), signal.clone()),
            (signal.clone(), finding.clone()),
        ] {
            held.merge(incoming);
            let p = assess(&held);
            assert_eq!(p, alone, "the signal changed the finding: {p:?}");
            let l = label_of(&held, std::slice::from_ref(&held));
            assert!(l.text.starts_with(city), "{l:?}");
            assert!(!l.text.contains("country-level"), "{l:?}");
            assert_honest(&l, &held);
        }
    }
}

/// REQ-GEOLABEL-025: a country signal is named in its own words, never as the
/// one country its stand-in happens to sit in. `+1` is "United States/Canada"
/// (a Toronto number read "United States"), and `email_locale`'s name
/// patterns name regions ("ivan.shevchenko" → "Eastern Europe
/// (Ukraine/Russia/Serbia)" read "Russia (approx.)" off the Moscow stand-in;
/// "jose.…" → "Iberia/Latin America" read "Portugal (approx.)").
#[test]
fn a_country_signal_is_named_in_its_own_words() {
    let mut nanp = coord("39.8283,-98.5795");
    for t in ["geoint", "phone-prefix", "coarse", "country:US"] {
        nanp.tag(t);
    }
    nanp.add_evidence(ev(
        "geo_intel",
        "Phone prefix -> United States/Canada for +14165550100",
        &[
            ("country", "United States/Canada"),
            ("country_code", "US"),
            ("method", "e164-prefix"),
        ],
    ));
    let pattern = |value: &str, locale: &str, region: &str| {
        let mut e = coord(value);
        for t in ["geoint", "coarse", "locale-inferred"] {
            e.tag(t);
        }
        e.add_evidence(ev(
            "email_locale",
            &format!("Email local part matches {locale} naming pattern"),
            &[
                ("locale", locale),
                ("pattern", "surname_suffix"),
                ("region", region),
            ],
        ));
        e
    };
    let slavic = pattern(
        "55.7512,37.6184",
        "ru",
        "Eastern Europe (Ukraine/Russia/Serbia)",
    );
    let iberian = pattern("38.7168,-9.1421", "pt", "Iberia/Latin America");
    for (e, named, never) in [
        (&nanp, "United States/Canada", "United States ("),
        (
            &slavic,
            "Eastern Europe (Ukraine/Russia/Serbia)",
            "Russia (",
        ),
        (&iberian, "Iberia/Latin America", "Portugal"),
    ] {
        let l = label_of(e, std::slice::from_ref(e));
        assert_eq!(l.fix_grain, FixGrain::Country, "{l:?}");
        assert!(l.text.starts_with(named), "{l:?}");
        assert!(!l.text.contains(never), "{l:?}");
        assert!(l.text.contains("country-level signal"), "{l:?}");
        assert_honest(&l, e);
    }
    // Two signals on one stand-in are both named, in a fixed order.
    let mut ru = slavic.clone();
    ru.add_evidence(ev(
        "email_locale",
        "Email domain ccTLD .ru indicates Russia",
        &[("cctld", "ru"), ("locale", "ru"), ("country", "Russia")],
    ));
    let mut reversed = ru.clone();
    reversed.evidence.reverse();
    let (a, b) = (label_of(&ru, &[]), label_of(&reversed, &[]));
    assert_eq!(a, b);
    assert!(
        a.text
            .starts_with("Eastern Europe (Ukraine/Russia/Serbia) or Russia"),
        "{a:?}"
    );
    // A signal whose records name nothing (a CSV copy) falls back to the box.
    let mut bare = coord("55.7512,37.6184");
    bare.tag("locale-inferred");
    bare.add_evidence(ev("email_locale", "Email local part matches", &[]));
    let l = label_of(&bare, &[]);
    assert_eq!(l.fix_grain, FixGrain::Country, "{l:?}");
    assert!(l.text.contains("(approx.)"), "{l:?}");
}

/// REQ-GEOLABEL-026: a country signal never reaches the correlator as a
/// position. A record from an ANCHORING source that is no account of the
/// point — a legacy `wigle` density annotation written before the
/// annotation flag existed — explains nothing on the `.au` stand-in, so the
/// point graded as the country with an unbounded radius, passed the
/// person-anchor gate on `wigle`, and `best_precision_radius_m` handed that
/// infinity to the best-location rung: report.json wrote `radius_km: null`,
/// the debug bundle "± 0.0 km" and the CLI dossier "± inf km". The point is
/// now kept out of every footprint, and no radius the correlator reads is
/// ever infinite.
#[test]
fn a_country_signal_is_never_a_best_location_candidate() {
    let mut point = au_email_point();
    point.add_evidence(ev(
        "wigle",
        "WiGLE: 12 networks within 500 m",
        &[("density", "12")],
    ));
    point.confidence = 0.6;
    assert_eq!(assess(&point).basis, FixBasis::CountrySignal);
    assert!(super::grain::claims_no_position(&point));
    assert_eq!(best_precision_radius_m(&point), None);
    assert!(crate::core::correlator::is_infrastructure_geo(&point));
    assert!(
        crate::core::correlator::best_au_location_estimate(std::slice::from_ref(&point)).is_none()
    );
    // The reviewers' path: `breach_timezone` mints its UTC+10 zone onto the
    // same Sydney row and is listed as an anchoring source — but it is an
    // enrichment-only derivation, so its record is neither an account of the
    // point nor a corroborating source. The merged point stays the country,
    // and no anchoring source carries it past the gate (this held before the
    // fix too; the `wigle` row above is the path that did not).
    let mut zone = au_email_point();
    zone.confidence = 0.6;
    zone.add_evidence(ev(
        "breach_timezone",
        "Breach activity clusters at UTC+10",
        &[("utc_offset", "10")],
    ));
    assert_eq!(assess(&zone).basis, FixBasis::CountrySignal);
    assert_eq!(best_precision_radius_m(&zone), None);
    assert!(crate::core::correlator::is_infrastructure_geo(&zone));
    // Controls: a real city finding on the same row is a position again.
    let mut sydney = point.clone();
    sydney.add_evidence(ev(
        "abn_lookup",
        "Inline geocode of address 'Sydney NSW'",
        &[("addr_entity_uid", "a1"), ("place_type", "city")],
    ));
    assert!(!super::grain::claims_no_position(&sydney));
    assert!(!crate::core::correlator::is_infrastructure_geo(&sydney));
    assert!(
        best_precision_radius_m(&sydney).is_some_and(f64::is_finite),
        "{sydney:?}"
    );
    // The shared radius formatter never prints a missing radius as zero.
    assert_eq!(super::fix_radius_km_text(Some(8.0)), "± 8.0 km");
    assert_eq!(super::fix_radius_km_text(None), "(no radius)");
    assert_eq!(
        super::fix_radius_km_text(Some(f64::INFINITY)),
        "(no radius)"
    );
}

/// REQ-GEOLABEL-020: a country signal claims no disc. Its point is a stand-in
/// (Sydney for `.au`, Wellington for `+64`), and "±300 km" around it left
/// Melbourne, Brisbane and Perth — or Auckland — outside the circle the label
/// stated. The label names the country with no `±`, the JSON radius is null
/// and the CSV cell is empty.
#[test]
fn a_country_signal_claims_no_disc() {
    for e in [au_email_point(), nz_prefix_point()] {
        let p = assess(&e);
        assert!(p.radius_m.is_infinite(), "{p:?}");
        assert_eq!(super::fix_radius_ceil_m(&e), None);
        let l = label_of(&e, std::slice::from_ref(&e));
        assert!(!l.text.contains('±'), "{l:?}");
        assert!(l.text.contains("country-level signal"), "{l:?}");
        assert!(l.to_json()["fix_radius_m"].is_null(), "{l:?}");
        assert!(l.detail().contains("no radius"), "{}", l.detail());
        assert!(!l.detail().contains('±'), "{}", l.detail());
        assert_honest(&l, &e);
    }
    // Every other point still shows its radius.
    let l = label_of(&gps_fix(), &[gps_fix()]);
    assert!(l.text.contains('±') || l.detail().contains('±'), "{l:?}");
}

/// REQ-GEOLABEL-021: a value CUT below the table key stays cut after
/// `Entity::new` normalises it. HSE's CSV importer rebuilds a redacted
/// `-33.8,151.0` into value `-33.800000,151.000000` and keeps the printed
/// form only in `raw_value`; the gate read `value` alone, so the re-imported
/// Parramatta point was the REGIONS row "21" again, and an inner-west
/// Melbourne point the Footscray anchor. And the precision floor took
/// `min(value, raw_value)`, so the normalisation's stripped zeros graded
/// `-28.0,153.0` a region beside `-27.9,153.2` at a locality.
#[test]
fn a_normalised_redaction_keeps_its_printed_width() {
    for (printed, never) in [
        ("-33.8,151.0", "Postcode 21xx"),
        ("-37.8,144.9", "city centroid"),
    ] {
        let e = coord(printed);
        assert_ne!(e.value, printed, "Entity::new normalises the value");
        let p = assess(&e);
        assert_eq!(p.stands_for, None, "{printed}: {p:?}");
        assert_eq!(p.grain, FixGrain::Locality, "{printed}: {p:?}");
        let l = label_of(&e, std::slice::from_ref(&e));
        assert!(!l.text.contains(never), "{printed}: {l:?}");
        assert!(!l.text.contains("region-level"), "{printed}: {l:?}");
    }
    let graded = |v: &str| {
        let p = assess(&coord(v));
        (p.grain, p.radius_m)
    };
    assert_eq!(graded("-28.0,153.0"), graded("-27.9,153.2"));
    assert_eq!(graded("-28.0,153.0").0, FixGrain::Locality);
    // Control: a row a module PRINTED at the key's width is still the row.
    assert!(assess(&coord("-33.8000,151.0000")).stands_for.is_some());
    assert!(assess(&coord("-33.868800,151.209300")).stands_for.is_some());
    // A raw value printed wider than the six decimals kept never grades the
    // point finer than the value it is.
    let mut wide = coord("-27.481234,153.012345");
    wide.raw_value = "-27.48123456,153.01234567".to_string();
    wide.add_evidence(ev("signal_radar", "GNSS fix", &[("accuracy_m", "0.01")]));
    assert!(assess(&wide).radius_m >= 0.05, "{:?}", assess(&wide));
}

/// REQ-GEOLABEL-022: an UNNUMBERED street naming is held to the street it
/// names. A street-type word also ends real locality names ("Kelvin Grove",
/// a Brisbane suburb) and a leading one starts given names ("Kiệt Nguyễn"),
/// so the widened street vocabulary read them as streets and lifted the cap
/// to Street — a geocoder's hit on "Kelvin Grove Road" or on any "Nguyễn …"
/// street then graded Street. A hit that is not the named street is a
/// fragment; a hit that is keeps the street cap.
#[test]
fn an_unnumbered_street_naming_is_held_to_the_street_it_names() {
    let geocoded = |source: &str, input: &str, attrs: &[(&str, &str)]| {
        let mut e = coord("-27.451234,153.012345");
        let mut all = vec![("input_address", input)];
        all.extend_from_slice(attrs);
        e.add_evidence(ev(source, &format!("Geocoded \"{input}\""), &all));
        assess(&e)
    };
    for (source, input, attrs) in [
        (
            "photon",
            "Kelvin Grove, QLD",
            &[
                ("place_type", "street"),
                ("osm_key", "highway"),
                ("place_name", "Kelvin Grove Road"),
            ][..],
        ),
        (
            "geocode",
            "Kelvin Grove, QLD",
            &[("place_type", "road"), ("road", "Kelvin Grove Road")][..],
        ),
        (
            "geocode",
            "Kiệt Nguyễn, Hà Nội",
            &[("place_type", "residential"), ("road", "Nguyễn Trãi")][..],
        ),
    ] {
        let p = geocoded(source, input, attrs);
        assert!(p.grain >= FixGrain::Locality, "{input} {attrs:?}: {p:?}");
        assert!(p.is_area(), "{input}: {p:?}");
    }
    // Controls: the named street itself, however the geocoder spells it.
    for (source, input, attrs) in [
        (
            "photon",
            "Smith St, Toowong QLD",
            &[
                ("place_type", "street"),
                ("osm_key", "highway"),
                ("place_name", "Smith Street"),
            ][..],
        ),
        (
            "geocode",
            "Oak Grove, Toowong QLD",
            &[("place_type", "road"), ("road", "Oak Grove")][..],
        ),
        (
            "geocode",
            "Đường Láng, Hà Nội",
            &[("place_type", "road"), ("road", "Đường Láng")][..],
        ),
    ] {
        let p = geocoded(source, input, attrs);
        assert_eq!(p.grain, FixGrain::Street, "{input}: {p:?}");
    }
    // A numbered street is not held to the hit's road name.
    let p = geocoded(
        "geocode",
        "12 Smith St, Toowong QLD 4066",
        &[("place_type", "house"), ("road", "Smith Street West")],
    );
    assert_eq!(p.grain, FixGrain::Point, "{p:?}");
}

// ── Final review, correction round 1 ──────────────────────────────────────

/// REQ-GEOLABEL-029: a cell tower's Mobile Country Code centroid is a
/// COUNTRY signal. With no OpenCelliD key, `cell_intel` places each tower at
/// its MCC's country centroid — MCC 530's is exactly Wellington's `CITIES`
/// row, MCC 505's the continent's centre, the very stand-ins `+64` and `+61`
/// use. It was graded a 30 km MEASURED fix (`cell_intel` measures, in
/// `COORDINATE_TARGET_MODULES`), so every NZ tower read "Wellington (city
/// centroid — not a street location)" and every AU tower "remote NT —
/// nearest centre Alice Springs", and the point stayed a person-anchor
/// candidate. It explained the value, too, so a `+64` point merged onto it
/// read as Wellington city.
#[test]
fn a_cell_tower_mcc_centroid_is_the_country_never_its_stand_in_city() {
    use crate::modules::cell_intel::mcc_centroid_point;
    for (mcc, value, country, never) in [
        ("530", "-41.286500,174.776200", "New Zealand", "Wellington"),
        ("505", "-25.274400,133.775100", "Australia", "Alice Springs"),
    ] {
        let point = mcc_centroid_point(mcc, "1", "tower-1", "s1").expect("a tabulated MCC");
        assert_eq!(point.value, value, "the stand-in this test is about");
        let p = assess(&point);
        assert_eq!(p.basis, FixBasis::CountrySignal, "{mcc}: {p:?}");
        assert_eq!(p.grain, FixGrain::Country, "{mcc}: {p:?}");
        assert_eq!(p.stands_for, None, "{mcc}: {p:?}");
        let l = label_of(&point, std::slice::from_ref(&point));
        assert!(l.text.starts_with(country), "{mcc}: {l:?}");
        assert!(!l.text.contains(never), "{mcc}: {l:?}");
        assert!(!l.text.contains("city centroid"), "{mcc}: {l:?}");
        assert_honest(&l, &point);
        assert!(super::grain::claims_no_position(&point), "{mcc}");
        assert_eq!(best_precision_radius_m(&point), None, "{mcc}");

        // A CSV copy keeps the tags and loses the attributes: still the
        // country.
        let mut bare = coord(value);
        bare.tags.clone_from(&point.tags);
        bare.add_evidence(ev(
            "cell_intel",
            &format!("Cell tower MCC {mcc} -> (country centroid)"),
            &[],
        ));
        assert_eq!(assess(&bare).basis, FixBasis::CountrySignal, "{mcc}");
    }
    // Merged with `+64`'s stand-in (the same value), neither explains it:
    // the point is New Zealand, not Wellington city.
    let mut merged = nz_prefix_point();
    let tower = mcc_centroid_point("530", "1", "tower-1", "s1").expect("NZ");
    merged.tags.extend(tower.tags.iter().cloned());
    merged.evidence.extend(tower.evidence.iter().cloned());
    let l = label_of(&merged, std::slice::from_ref(&merged));
    assert_eq!(l.fix_grain, FixGrain::Country, "{l:?}");
    assert!(!l.text.contains("Wellington"), "{l:?}");
    // Control: a tower OpenCelliD located is a measurement, as before.
    let mut located = coord("-41.290112,174.781234");
    located.add_evidence(ev(
        "opencellid",
        "Cell tower LTE 530-1-2-3 -> -41.290112,174.781234",
        &[("range_m", "800"), ("source", "OpenCelliD")],
    ));
    let p = assess(&located);
    assert_eq!(p.basis, FixBasis::Measured, "{p:?}");
    assert!(!super::grain::claims_no_position(&located));
}

/// REQ-GEOLABEL-036: a country signal whose records lost their words (a CSV
/// re-import keeps tags, never attributes) is named by its emitter's
/// `country:` tags before any box. The box answers the FIRST matching
/// country, so a Belgian MCC point read "France (approx.)", a Croatian one
/// "Italy (approx.)", a Ukrainian one "Russia (approx.)", and a Toronto
/// `+1 416` point "United States (approx.)" — the REQ-GEOLABEL-025 mislabel
/// back on the CSV path — while the point's own tag named the right one.
#[test]
fn a_csv_copy_of_a_country_signal_is_named_by_its_own_country_tags() {
    use crate::modules::cell_intel::mcc_centroid_point;
    // A live point through the offline enrichment, then its CSV copy: the
    // tags as stored, one attribute-less record per original.
    let csv_copy = |mut live: Entity| {
        crate::core::engine::enrich_geospatial(&mut live);
        let mut bare = coord(&live.value);
        bare.tags.clone_from(&live.tags);
        for r in &live.evidence {
            bare.add_evidence(ev(&r.source, &r.summary, &[]));
        }
        assert_eq!(assess(&bare).basis, FixBasis::CountrySignal, "{bare:?}");
        bare
    };
    for (mcc, country, never) in [
        ("206", "Belgium", "France"),
        ("219", "Croatia", "Italy"),
        ("255", "Ukraine", "Russia"),
        ("268", "Portugal", "Spain"),
    ] {
        let live = mcc_centroid_point(mcc, "1", "tower-1", "s1").expect("a tabulated MCC");
        let bare = csv_copy(live);
        let l = label_of(&bare, std::slice::from_ref(&bare));
        assert!(l.text.starts_with(country), "MCC {mcc}: {l:?}");
        assert!(!l.text.contains(never), "MCC {mcc}: {l:?}");
        assert!(!l.text.contains("(approx.)"), "MCC {mcc}: {l:?}");
        assert_honest(&l, &bare);
    }
    // `+1`: the prefix's own tags name both countries it covers.
    let mut nanp = coord("39.8283,-98.5795");
    for t in [
        "geoint",
        "phone-prefix",
        "coarse",
        "country:US",
        "country:CA",
    ] {
        nanp.tag(t);
    }
    nanp.add_evidence(ev(
        "geo_intel",
        "Phone prefix -> United States/Canada for +14165550100",
        &[
            ("country", "United States/Canada"),
            ("country_code", "US"),
            ("method", "e164-prefix"),
        ],
    ));
    let bare = csv_copy(nanp);
    let l = label_of(&bare, std::slice::from_ref(&bare));
    assert!(l.text.starts_with("Canada or United States"), "{l:?}");
    assert_honest(&l, &bare);
    // Control: a tag the box itself would write says nothing the box does
    // not — a `.pt` email's Lisbon stand-in is boxed in Spain, and its copy
    // reads as the approximation it is, never a sure "Spain".
    let mut pt = coord("38.7168,-9.1421");
    for t in ["geoint", "coarse", "cctld-inferred"] {
        pt.tag(t);
    }
    pt.add_evidence(ev(
        "email_locale",
        "Email domain ccTLD .pt indicates Portugal",
        &[("cctld", "pt"), ("locale", "pt"), ("country", "Portugal")],
    ));
    let bare = csv_copy(pt);
    assert!(bare.has_tag("country:ES"), "fixture: {:?}", bare.tags);
    let l = label_of(&bare, std::slice::from_ref(&bare));
    assert!(l.text.starts_with("Spain (approx.)"), "{l:?}");
}

/// REQ-GEOLABEL-030: a fix coarser than a suburb is never named after a
/// capital's suburb. The offline gazetteer named a point after its nearest
/// curated anchor and stamped the label locality grain whatever the anchor
/// was, and the anchors include metro suburbs — so a redacted `-37.8,144.9`
/// (on the Footscray anchor) read "Footscray, VIC (locality-level fix, ±6
/// km)", and any unclassified ±30 km point by the Bondi anchor "Bondi, NSW".
/// Both name the capital now; a suburb-grade fix still gets the suburb.
#[test]
fn a_coarse_fix_is_never_named_after_a_capital_suburb() {
    let mut redacted = coord("-37.812345,144.901234");
    redacted.value = "-37.8,144.9".to_string();
    redacted.raw_value = "-37.8,144.9".to_string();
    let l = label_of(&redacted, std::slice::from_ref(&redacted));
    assert_eq!(l.fix_grain, FixGrain::Locality, "{l:?}");
    assert!(l.text.contains("Melbourne, VIC"), "{l:?}");
    assert!(!l.text.contains("Footscray"), "{l:?}");
    assert_honest(&l, &redacted);

    let mut bondi = coord("-33.891612,151.276789");
    bondi.add_evidence(ev("some_profile", "Location: somewhere", &[]));
    let l = label_of(&bondi, std::slice::from_ref(&bondi));
    assert_eq!(l.fix_grain, FixGrain::Locality, "{l:?}");
    assert!(l.text.contains("Sydney, NSW"), "{l:?}");
    assert!(!l.text.contains("Bondi"), "{l:?}");
    assert_honest(&l, &bondi);

    // Control: a suburb-grade measurement by the same anchor keeps the suburb.
    let mut fine = coord("-33.891612,151.276789");
    fine.add_evidence(ev(
        "some_wifi_locator",
        "Wi-Fi fix",
        &[("accuracy_m", "2000")],
    ));
    let l = label_of(&fine, std::slice::from_ref(&fine));
    assert_eq!(l.fix_grain, FixGrain::Suburb, "{l:?}");
    assert!(l.text.starts_with("Bondi, NSW"), "{l:?}");
}
