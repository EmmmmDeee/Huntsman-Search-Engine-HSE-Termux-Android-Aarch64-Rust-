use super::*;

/// Assert two floats agree within `eps`.
fn near(a: f64, b: f64, eps: f64, what: &str) {
    assert!(
        (a - b).abs() <= eps,
        "{what}: {a} vs {b} (Δ {})",
        (a - b).abs()
    );
}

// ───────────────────────────── decimal ─────────────────────────────────────

#[test]
fn decimal_comma_and_space() {
    for s in [
        "-27.4766,153.0166",
        "-27.4766, 153.0166",
        "-27.4766 153.0166",
    ] {
        let p = parse(s).expect("should succeed");
        near(p.lat, -27.4766, 1e-9, "lat");
        near(p.lon, 153.0166, 1e-9, "lon");
        assert_eq!(p.format, CoordFormat::Decimal);
    }
}

#[test]
fn decimal_zero_and_signs() {
    assert!(parse("0,0").is_some()); // Null Island kept at the parse boundary
    let p = parse("+12.5, -34.25").expect("should succeed");
    near(p.lat, 12.5, 1e-9, "lat");
    near(p.lon, -34.25, 1e-9, "lon");
}

#[test]
fn decimal_rejects_non_pairs_and_out_of_range() {
    for s in ["42", "1,2,3", "91,0", "0,181", "-90.1,0", "abc,def", ""] {
        assert!(parse(s).is_none(), "should reject {s:?}");
    }
    // Boundaries are inclusive.
    assert!(parse("90,180").is_some());
    assert!(parse("-90,-180").is_some());
}

// ───────────────────────────── geo: URI ────────────────────────────────────

#[test]
fn geo_uri_basic_params_and_altitude() {
    let p = parse("geo:-27.4766,153.0166").expect("should succeed");
    near(p.lat, -27.4766, 1e-9, "lat");
    assert_eq!(p.format, CoordFormat::GeoUri);
    // Uncertainty / CRS parameters and an altitude field are ignored.
    assert!(parse("geo:-27.4766,153.0166;u=35").is_some());
    assert!(parse("geo:-27.4766,153.0166,12.0;crs=wgs84").is_some());
    // Case-insensitive scheme.
    assert!(parse("GEO:1,2").is_some());
    assert!(parse("Geo:1,2").is_some());
}

#[test]
fn geo_uri_rejects_malformed() {
    for s in [
        "geo:",
        "geo:1",
        "geo:1,2,3,4",
        "geo:abc,def",
        "geo:200,0",
        "geo:1,2,",             // empty altitude
        "geo:1,2,not-a-number", // non-numeric altitude
    ] {
        assert!(parse(s).is_none(), "should reject {s:?}");
    }
    // A numeric altitude is accepted and ignored.
    assert!(parse("geo:1,2,12.5").is_some());
}

// ───────────────────────────── DMS / DDM / DD+hemisphere ────────────────────

#[test]
fn dms_suffix_hemisphere() {
    // Brisbane City Hall, suffix N/S/E/W with ASCII glyphs.
    let p = parse("27°28'35.8\"S 153°00'59.8\"E").expect("should succeed");
    near(p.lat, -27.476611, 1e-5, "lat");
    near(p.lon, 153.016611, 1e-5, "lon");
    assert_eq!(p.format, CoordFormat::Dms);
}

#[test]
fn dms_unicode_glyph_variants() {
    // Prime ′, double-prime ″, masculine-ordinal º, right-quote ’.
    let a = parse("27º28′35.8″S 153º00′59.8″E").expect("should succeed");
    near(a.lat, -27.476611, 1e-5, "lat");
    near(a.lon, 153.016611, 1e-5, "lon");
    let b = parse("27°28’35.8”S, 153°00’59.8”E").expect("should succeed");
    near(b.lat, -27.476611, 1e-5, "lat");
}

#[test]
fn ddm_degrees_decimal_minutes() {
    let p = parse("27 28.6 S, 153 01.0 E").expect("should succeed");
    near(p.lat, -(27.0 + 28.6 / 60.0), 1e-9, "lat");
    near(p.lon, 153.0 + 1.0 / 60.0, 1e-9, "lon");
    assert_eq!(p.format, CoordFormat::Ddm);
}

#[test]
fn dd_with_hemisphere_spaced() {
    // Whitespace between the value and the hemisphere letter must still suffix.
    let p = parse("27.4766 S 153.0166 E").expect("should succeed");
    near(p.lat, -27.4766, 1e-9, "lat");
    near(p.lon, 153.0166, 1e-9, "lon");
}

#[test]
fn hemisphere_letters_reorder_axes() {
    // Longitude written first; E/W vs N/S pins the axis regardless of order.
    let p = parse("153.0166E, 27.4766S").expect("should succeed");
    near(p.lat, -27.4766, 1e-9, "lat");
    near(p.lon, 153.0166, 1e-9, "lon");
}

#[test]
fn prefix_hemisphere() {
    let p = parse("N33 E151").expect("should succeed");
    near(p.lat, 33.0, 1e-9, "lat");
    near(p.lon, 151.0, 1e-9, "lon");
    let q = parse("S33.5 W151.25").expect("should succeed");
    near(q.lat, -33.5, 1e-9, "lat");
    near(q.lon, -151.25, 1e-9, "lon");
}

#[test]
fn dms_halved_no_delimiter() {
    // Glyph DMS with neither comma nor hemisphere: the six numbers split 3/3.
    let p = parse("33°52'12\" 151°12'36\"").expect("should succeed");
    near(p.lat, 33.0 + 52.0 / 60.0 + 12.0 / 3600.0, 1e-9, "lat");
    near(p.lon, 151.0 + 12.0 / 60.0 + 36.0 / 3600.0, 1e-9, "lon");
}

#[test]
fn dms_rejects_bad_minutes_seconds() {
    // Minutes/seconds ≥ 60 are not a valid sexagesimal coordinate.
    assert!(parse("27°60'00\"S 153°00'00\"E").is_none());
    assert!(parse("27°00'60\"S 153°00'00\"E").is_none());
}

// ───────────────────────────── Maidenhead ──────────────────────────────────

#[test]
fn maidenhead_hand_computed_corners() {
    // Centre of the south-west-most subsquare and the north-east-most one,
    // computed by hand from the grid definition.
    let sw = parse("AA00aa").expect("should succeed");
    near(sw.lat, -90.0 + 1.0 / 48.0, 1e-9, "sw lat");
    near(sw.lon, -180.0 + 1.0 / 24.0, 1e-9, "sw lon");
    assert_eq!(sw.format, CoordFormat::Maidenhead);
    let ne = parse("RR99xx").expect("should succeed");
    near(ne.lat, 89.9791667, 1e-6, "ne lat");
    near(ne.lon, 179.9583333, 1e-6, "ne lon");
}

#[test]
fn maidenhead_known_point_in_australia() {
    // QG62kn sits in SE Queensland; QG62 is the coarser 4-char square.
    let p = parse("QG62kn").expect("should succeed");
    near(p.lat, -27.4375, 1e-4, "lat");
    near(p.lon, 152.875, 1e-4, "lon");
    assert!(crate::util::geo::is_in_australia(p.lat, p.lon));
    let coarse = parse("QG62").expect("should succeed");
    near(coarse.lat, -27.5, 1e-9, "coarse lat");
    near(coarse.lon, 153.0, 1e-9, "coarse lon");
}

#[test]
fn maidenhead_rejects_bad_shapes() {
    for s in ["QG6", "QG62k", "ZZ00aa", "QGAAaa", "QG62zz", "1234"] {
        assert!(parse(s).is_none(), "should reject {s:?}");
    }
}

// ───────────────────────────── Plus Codes (OLC) ────────────────────────────

#[test]
fn plus_code_hand_computed_pairs() {
    // All-zero-index pairs land at the SW corner cell centre.
    let sw = parse("22222222+22").expect("should succeed");
    near(sw.lat, -90.0 + 0.0000625, 1e-9, "sw lat");
    near(sw.lon, -180.0 + 0.0000625, 1e-9, "sw lon");
    assert_eq!(sw.format, CoordFormat::PlusCode);
    // First latitude digit = 'C' (index 8) → +8·20° = +160°.
    let lat_set = parse("C2222222+22").expect("should succeed");
    near(lat_set.lat, 70.0000625, 1e-9, "lat");
    near(lat_set.lon, -179.9999375, 1e-9, "lon");
    // First longitude digit = 'C' → +160° in longitude.
    let lon_set = parse("2C222222+22").expect("should succeed");
    near(lon_set.lat, -89.9999375, 1e-9, "lat");
    near(lon_set.lon, -19.9999375, 1e-9, "lon");
}

#[test]
fn plus_code_reference_vector() {
    // Google's documented example: encode(47.365590, 8.524997) == "8FVC9G8F+6X".
    // Decoding it must land within the code's cell of that point.
    let p = parse("8FVC9G8F+6X").expect("should succeed");
    near(p.lat, 47.365590, 1e-4, "lat");
    near(p.lon, 8.524997, 1e-4, "lon");
    assert_eq!(p.format, CoordFormat::PlusCode);
}

#[test]
fn plus_code_rejects_short_padded_and_misplaced() {
    for s in [
        "9G8F+6X",      // short code (separator not at position 8)
        "8FVC0000+",    // padded with '0'
        "8FVC9G8F",     // no separator
        "8FVC9G8F+",    // nothing after the separator
        "8FVC9G8F+6X+", // a second, stray separator
        "++++++++++",   // junk
    ] {
        assert!(parse(s).is_none(), "should reject {s:?}");
    }
}

// ───────────────────────────── classification / hygiene ────────────────────

#[test]
fn self_evident_is_only_the_marker_bearing_formats() {
    // Decimal and Maidenhead are handle/measurement-ambiguous → not auto-detected.
    for f in [CoordFormat::Decimal, CoordFormat::Maidenhead] {
        assert!(!f.is_self_evident(), "{f:?} must not be self-evident");
    }
    for f in [
        CoordFormat::Dms,
        CoordFormat::Ddm,
        CoordFormat::GeoUri,
        CoordFormat::PlusCode,
    ] {
        assert!(f.is_self_evident(), "{f:?} should be self-evident");
    }
}

#[test]
fn rejects_non_coordinates() {
    // Things the unified-scan classifier checks around the coordinate arm must
    // not parse as coordinates.
    for s in [
        "john_doe",
        "example.com",
        "user@example.com",
        "192.168.0.1",
        "AS13335",
        "hello world",
        "the quick brown fox",
    ] {
        assert!(parse(s).is_none(), "should not be a coordinate: {s:?}");
    }
}

mod prop {
    use super::super::*;
    use proptest::prelude::*;

    proptest! {
        /// Totality: `parse` never panics on arbitrary input.
        #[test]
        fn parse_is_total(s in ".{0,64}") {
            let _ = parse(&s);
        }

        /// Any in-range decimal pair round-trips through `parse`.
        #[test]
        fn decimal_round_trips(lat in -90.0f64..=90.0, lon in -180.0f64..=180.0) {
            let s = format!("{lat:.6},{lon:.6}");
            let p = parse(&s).expect("a formatted in-range pair must parse");
            prop_assert!((p.lat - lat).abs() < 1e-5);
            prop_assert!((p.lon - lon).abs() < 1e-5);
        }

        /// Every successful parse is finite and in range, whatever the input.
        #[test]
        fn parsed_values_are_always_in_range(s in "[-+0-9.,°'\" NSEWnsew]{0,32}") {
            if let Some(p) = parse(&s) {
                prop_assert!(p.lat.is_finite() && (-90.0..=90.0).contains(&p.lat));
                prop_assert!(p.lon.is_finite() && (-180.0..=180.0).contains(&p.lon));
            }
        }
    }
}
