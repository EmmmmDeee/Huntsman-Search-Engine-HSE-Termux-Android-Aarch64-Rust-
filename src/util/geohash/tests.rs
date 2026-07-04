use super::*;

#[test]
fn geohash_sydney_opera_house() {
    // Famous coords: -33.8568° S, 151.2153° E → r3gx2f7 prefix
    let h = geohash(-33.8568, 151.2153, 7);
    assert!(h.starts_with("r3gx2"), "got {h}");
    assert_eq!(h.len(), 7);
}

#[test]
fn geohash_invalid_coords_returns_empty() {
    assert!(geohash(91.0, 0.0, 7).is_empty());
    assert!(geohash(0.0, 200.0, 7).is_empty());
}

#[test]
fn parse_coords_handles_typical_format() {
    assert_eq!(
        parse_coords("-33.8568,151.2153"),
        Some((-33.8568, 151.2153))
    );
    assert_eq!(parse_coords("38.83, -104.82"), Some((38.83, -104.82)));
}

#[test]
fn parse_coords_rejects_invalid() {
    assert!(parse_coords("not-coords").is_none());
    assert!(parse_coords("91,0").is_none());
    assert!(parse_coords("0,181").is_none());
}

#[test]
fn timezone_australia_specific() {
    assert_eq!(timezone_for(-33.86, 151.21), "Australia/Sydney");
    assert_eq!(timezone_for(-31.95, 115.86), "Australia/Perth");
    assert_eq!(timezone_for(-34.93, 138.60), "Australia/Adelaide");
}

#[test]
fn timezone_us_specific() {
    assert_eq!(timezone_for(40.71, -74.00), "America/New_York");
    assert_eq!(timezone_for(37.77, -122.41), "America/Los_Angeles");
}

#[test]
fn parse_address_aus_full() {
    let a = parse_address("Sydney, NSW, Australia");
    assert_eq!(a.city.as_deref(), Some("Sydney"));
    assert_eq!(a.state.as_deref(), Some("NSW"));
    assert_eq!(a.country.as_deref(), Some("Australia"));
    assert_eq!(a.iso_country.as_deref(), Some("AU"));
}

#[test]
fn parse_address_with_street() {
    let a = parse_address("10 Smith St, Melbourne, VIC, Australia");
    assert_eq!(a.street.as_deref(), Some("10 Smith St"));
    assert_eq!(a.city.as_deref(), Some("Melbourne"));
    assert_eq!(a.state.as_deref(), Some("VIC"));
    assert_eq!(a.iso_country.as_deref(), Some("AU"));
}

#[test]
fn parse_address_state_only() {
    let a = parse_address("SA, VIC");
    // First-classified-state wins
    assert_eq!(a.state.as_deref(), Some("SA"));
    // Country inferred from AU state code
    assert_eq!(a.iso_country.as_deref(), Some("AU"));
}

#[test]
fn parse_address_postal_code() {
    let a = parse_address("Brisbane, QLD 4000");
    assert_eq!(a.city.as_deref(), Some("Brisbane"));
    assert_eq!(a.state.as_deref(), Some("QLD"));
    assert_eq!(a.postal_code.as_deref(), Some("4000"));
}

#[test]
fn parse_address_handles_spelled_out_multiword_states() {
    // Regression: au_state_norm defines multi-word arms ("new south
    // wales", "western australia", …) but the state loop only ever passed
    // single whitespace-split tokens, so a spelled-out state silently
    // failed to parse while its abbreviation succeeded. Both must work.
    let a = parse_address("Sydney, New South Wales, Australia");
    assert_eq!(a.city.as_deref(), Some("Sydney"));
    assert_eq!(a.state.as_deref(), Some("NSW"));
    assert_eq!(a.country.as_deref(), Some("Australia"));

    // Multi-word state alone still infers the AU country, and is not
    // misread as the city.
    let b = parse_address("Perth, Western Australia");
    assert_eq!(b.state.as_deref(), Some("WA"));
    assert_eq!(b.city.as_deref(), Some("Perth"));
    assert_eq!(b.iso_country.as_deref(), Some("AU"));

    // Abbreviation and combined "STATE postcode" forms are unchanged.
    assert_eq!(
        parse_address("Brisbane, QLD 4000").state.as_deref(),
        Some("QLD")
    );
}

#[test]
fn parse_address_does_not_mistake_street_number_for_postal() {
    // Regression: a multi-digit street number is the LEADING token of a
    // street part, not a postcode — it must not be captured as postal_code.
    let a = parse_address("1234 Smith St, Sydney, NSW");
    assert_eq!(a.street.as_deref(), Some("1234 Smith St"));
    assert_eq!(a.postal_code, None);
    assert_eq!(a.state.as_deref(), Some("NSW"));

    // A trailing postcode is still captured even alongside a long street no.
    let b = parse_address("4000 George St, Brisbane, QLD 4000");
    assert_eq!(b.street.as_deref(), Some("4000 George St"));
    assert_eq!(b.postal_code.as_deref(), Some("4000")); // from "QLD 4000", not the street
    assert_eq!(b.state.as_deref(), Some("QLD"));
}

#[test]
fn haversine_known_distance_sydney_to_melbourne() {
    // SYD (-33.87,151.21) → MEL (-37.81,144.96) is ~714 km great-circle.
    let d = haversine_km(-33.87, 151.21, -37.81, 144.96);
    assert!((d - 714.0).abs() < 15.0, "got {d} km");
    // Identical points → zero distance, no NaN.
    assert_eq!(haversine_km(10.0, 20.0, 10.0, 20.0), 0.0);
}

#[test]
fn haversine_antipodal_pairs_are_finite_not_nan() {
    // Regression: at a near-antipodal pair the haversine `a` term can round ~1 ULP
    // above 1.0 (e.g. (-87.5, 0, 87.5, 180) → a = 1.0000000000000002), and the old
    // unclamped `(1.0 - a).sqrt()` was `sqrt(<0) = NaN`. The random metric test
    // above never lands on the antipodal locus, so scan it explicitly: (lat, lon)
    // and (-lat, lon+180) are exact antipodes, π·R ≈ 20015 km apart, never NaN.
    let half_circ = std::f64::consts::PI * 6371.0;
    for i in -90..=90 {
        let lat = f64::from(i);
        for lon in [0.0, 86.58, -120.0, 45.5, 179.9] {
            let d = haversine_km(lat, lon, -lat, lon + 180.0);
            assert!(
                d.is_finite(),
                "antipodal ({lat},{lon}) produced non-finite {d}"
            );
            assert!(
                (d - half_circ).abs() < 1.0,
                "antipodal distance {d} should be ~{half_circ} km"
            );
        }
    }
}

/// Metric invariants of `haversine_km`, proved over a randomised sample of
/// valid coordinates (seeded LCG — deterministic, no `rand` dependency). The
/// geo-cluster correlators treat this as a distance, so it must stay a proper
/// metric: finite, non-negative, symmetric, identity-zero, and bounded by
/// half the Earth's circumference. Guards against a future edit (e.g. swapping
/// back to the `acos` form, or transposing a term) silently breaking it.
#[test]
fn haversine_is_a_bounded_symmetric_metric() {
    // Half-circumference upper bound: π·R, plus a hair for float slack.
    let max_km = std::f64::consts::PI * 6371.0 + 1e-6;
    let mut state: u64 = 0x5DEECE66D;
    let mut next = || {
        state = state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1);
        // Top 53 bits → [0, 1).
        (state >> 11) as f64 / (1u64 << 53) as f64
    };
    for _ in 0..50_000 {
        let lat1 = next() * 180.0 - 90.0;
        let lon1 = next() * 360.0 - 180.0;
        let lat2 = next() * 180.0 - 90.0;
        let lon2 = next() * 360.0 - 180.0;
        let d = haversine_km(lat1, lon1, lat2, lon2);
        assert!(d.is_finite() && d >= 0.0, "non-metric distance {d}");
        assert!(d <= max_km, "distance {d} exceeds half-circumference");
        // Symmetric: swapping the endpoints is byte-identical (the formula is
        // symmetric, so this is exact, not approximate).
        assert_eq!(d, haversine_km(lat2, lon2, lat1, lon1), "asymmetric");
        // Identity: a point is zero distance from itself.
        assert_eq!(haversine_km(lat1, lon1, lat1, lon1), 0.0);
    }
}

#[test]
fn reverse_country_iso_aliases_us_subregions() {
    assert_eq!(reverse_country_iso(-33.87, 151.21), Some("AU")); // Sydney
    assert_eq!(reverse_country_iso(61.0, -150.0), Some("US")); // Alaska → US
    assert_eq!(reverse_country_iso(21.3, -157.8), Some("US")); // Hawaii → US
    assert_eq!(reverse_country_iso(0.0, -30.0), None); // mid-Atlantic
}

#[test]
fn reverse_country_iso_resolves_boxes_contained_in_larger_neighbours() {
    // Regression: SG, HK and TW each sit geographically INSIDE a larger box
    // declared earlier (SG ⊂ both the ID and MY boxes; HK and TW ⊂ the CN box).
    // Because the first box to match in declaration order wins, those three were
    // shadowed and could never be returned — defined-but-dead entries that
    // misreported Singapore as Indonesia and Hong Kong / Taiwan as China. Each
    // specific box must precede EVERY box that contains it (mirroring KR/JP,
    // already placed before CN for the same reason). Unlike LU/UA — whose boxes
    // cover neighbours' actual territory and so stay shadowed by design — these
    // three boxes enclose no other country, so the fix is pure and regression-free.
    assert_eq!(reverse_country_iso(1.3521, 103.8198), Some("SG")); // Singapore
    assert_eq!(reverse_country_iso(22.3193, 114.1694), Some("HK")); // Hong Kong
    assert_eq!(reverse_country_iso(25.0330, 121.5654), Some("TW")); // Taipei
    // The containing nations remain correct outside the small contained boxes:
    // Beijing still resolves to CN (HK/TW inserted before CN do not cover it),
    // and Jakarta still resolves to ID (SG inserted before ID does not cover it).
    assert_eq!(reverse_country_iso(39.9042, 116.4074), Some("CN")); // Beijing
    assert_eq!(reverse_country_iso(-6.2088, 106.8456), Some("ID")); // Jakarta
}

#[test]
fn reverse_country_iso_pt_be_stay_shadowed_by_container_by_design() {
    // PT ⊂ ES and BE ⊂ FR/NL, so — exactly like LU/UA — these stay shadowed by
    // DESIGN: the earlier-declared container wins and a precise result needs the
    // None→HTTP fallback (declaring them first would mis-tag the container's own
    // border cities, per the box comments). This pins the ACCEPTED coarse-box
    // behaviour so a naive "fix" that reorders regresses HERE and forces a read of
    // the comments rather than silently mis-attributing Spanish/French/Dutch cities.
    assert_eq!(reverse_country_iso(38.72, -9.14), Some("ES")); // Lisbon → ES (shadowed)
    assert_eq!(reverse_country_iso(50.85, 4.35), Some("FR")); // Brussels → FR (shadowed)
    assert_eq!(reverse_country_iso(51.22, 4.40), Some("NL")); // Antwerp → NL (shadowed)
    // The containers still resolve their OWN cities correctly (not swallowed).
    assert_eq!(reverse_country_iso(40.42, -3.70), Some("ES")); // Madrid
    assert_eq!(reverse_country_iso(48.85, 2.35), Some("FR")); // Paris
    assert_eq!(reverse_country_iso(52.37, 4.90), Some("NL")); // Amsterdam
}

// ── Property tests (proptest) ──────────────────────────────────────────────
mod prop {
    use proptest::prelude::*;

    use super::{geohash, parse_coords};

    proptest! {
        /// `geohash` is **total**: any `f64` lat/lon (incl. NaN/inf/out-of-range)
        /// and any precision yields a result without panicking. In-range inputs
        /// produce a string of the clamped precision (1..=12) drawn only from the
        /// base-32 geohash alphabet; out-of-range (or non-finite) yields "".
        #[test]
        fn geohash_is_total_and_well_formed(
            lat in proptest::num::f64::ANY,
            lon in proptest::num::f64::ANY,
            prec in 0u8..20,
        ) {
            let h = geohash(lat, lon, prec);
            if (-90.0..=90.0).contains(&lat) && (-180.0..=180.0).contains(&lon) {
                prop_assert_eq!(h.len(), prec.clamp(1, 12) as usize);
                prop_assert!(
                    h.bytes().all(|b| b"0123456789bcdefghjkmnpqrstuvwxyz".contains(&b)),
                    "non-base32 char in {h:?}"
                );
            } else {
                prop_assert!(h.is_empty(), "out-of-range/non-finite must yield empty, got {h:?}");
            }
        }

        /// `parse_coords` round-trips a formatted valid coordinate pair (within
        /// f64 formatting tolerance) and rejects out-of-range pairs.
        #[test]
        fn parse_coords_round_trips_valid(lat in -90.0f64..=90.0, lon in -180.0f64..=180.0) {
            let s = format!("{lat},{lon}");
            let (rlat, rlon) = parse_coords(&s).expect("valid pair must parse");
            prop_assert!((rlat - lat).abs() < 1e-9);
            prop_assert!((rlon - lon).abs() < 1e-9);
        }

        /// `parse_coords` never panics on arbitrary text and only ever returns
        /// in-range pairs.
        #[test]
        fn parse_coords_is_total_and_bounded(s in ".{0,40}") {
            if let Some((lat, lon)) = parse_coords(&s) {
                prop_assert!((-90.0..=90.0).contains(&lat));
                prop_assert!((-180.0..=180.0).contains(&lon));
            }
        }
    }
}
