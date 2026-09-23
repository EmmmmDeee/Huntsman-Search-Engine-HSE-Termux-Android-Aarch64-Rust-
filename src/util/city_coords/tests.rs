use super::*;

    #[test]
    fn au_capitals_resolve() {
        assert!(city_coords("Brisbane, QLD").is_some());
        assert!(city_coords("Sydney NSW").is_some());
        assert!(city_coords("Darwin").is_some());
    }

    #[test]
    fn regional_au_resolves() {
        assert!(city_coords("Lockyer Valley").is_some());
        assert!(city_coords("Gatton, QLD").is_some());
        assert!(city_coords("Newcastle NSW").is_some());
    }

    #[test]
    fn international_resolves() {
        assert!(city_coords("Philadelphia").is_some());
        assert!(city_coords("Auckland").is_some());
        assert!(city_coords("London").is_some());
    }

    #[test]
    fn no_match_returns_none() {
        assert!(city_coords("Clobberville").is_none());
    }

    #[test]
    fn bare_postcode_resolves() {
        // Capital-city postcodes resolve via the fallback table.
        let (lat, lon) = city_coords("4000").expect("should succeed");
        assert!((lat - -27.4698).abs() < 0.01);
        assert!((lon - 153.0251).abs() < 0.01);
        assert!(city_coords("3000").is_some());
        assert!(city_coords("2000").is_some());
    }

    #[test]
    fn unknown_postcode_returns_none() {
        // "0100" is below the NT 08xx span and in no assigned AU range, so it has
        // no offline fix at all — neither the exact gazetteer nor the region/
        // capital fallback resolves it.
        assert!(city_coords("0100").is_none());
        assert!(postcode_coords("0100").is_none());
        // 9999 is the top of the QLD 9xxx large-volume-receiver range: NOT in the
        // exact gazetteer (postcode_coords stays None), but a real assigned
        // postcode that now resolves to the Brisbane region via the capital
        // fallback rather than vanishing from the geo footprint.
        assert!(postcode_coords("9999").is_none());
        assert!(city_coords("9999").is_some());
    }

    #[test]
    fn region_geocoder_covers_the_whole_au_postcode_space() {
        use crate::util::geohash::haversine_km;
        // The QLD family postcodes that aren't in the exact table still resolve to
        // their region — and to the RIGHT region relative to the subject's fix
        // near Woodford QLD (-26.82, 152.81).
        let (subj_lat, subj_lon) = (-26.815_f64, 152.814_f64);
        let near = |pc: &str| {
            let (la, lo) = au_postcode_region(pc).expect("AU postcode resolves to a region");
            haversine_km(la, lo, subj_lat, subj_lon)
        };
        // Sunshine Coast / Brisbane / Ipswich family → within ~150 km of subject.
        assert!(near("4518") < 150.0, "Beerwah (45xx) is in the subject's area");
        assert!(near("4169") < 150.0, "East Brisbane (41xx) is in the subject's area");
        assert!(near("4311") < 150.0, "Lower Lockyer (43xx) is in the subject's area");
        // Far North QLD and interstate are correctly far.
        assert!(near("4870") > 800.0, "Cairns (48xx) is far from the subject");
        assert!(near("2076") > 700.0, "Sydney (20xx) is interstate / far");

        // Every state prefix resolves; malformed input does not.
        for pc in ["2000", "3000", "5000", "6000", "7000", "0800"] {
            assert!(au_postcode_region(pc).is_some(), "{pc} resolves");
        }
        assert!(au_postcode_region("12").is_none());
        assert!(au_postcode_region("abcd").is_none());

        // The non-geographic large-volume-receiver / PO-box ranges and the sparse
        // state tails used to return None (no offline fix at all); the capital
        // fallback now resolves them so the WHOLE assigned AU postcode space
        // geocodes offline. Each lands in the right state's capital region.
        let near_capital = |pc: &str, clat: f64, clon: f64| {
            let (la, lo) = au_postcode_region(pc).expect("LVR / tail postcode resolves");
            haversine_km(la, lo, clat, clon) < 60.0
        };
        assert!(near_capital("1234", -33.87, 151.21), "NSW 1xxx → Sydney");
        assert!(near_capital("8000", -37.81, 144.96), "VIC 8xxx → Melbourne");
        assert!(near_capital("9000", -27.47, 153.03), "QLD 9xxx → Brisbane");
        assert!(near_capital("3777", -37.81, 144.96), "VIC 37xx alpine/fringe → Melbourne");
        assert!(near_capital("7112", -42.88, 147.33), "TAS 71xx → Hobart");
        // A leading digit in no AU range still yields nothing (no false fix).
        assert!(au_postcode_region("0000").is_none());
    }

    #[test]
    fn postcode_in_address_string_also_resolves() {
        // When city_coords is called with "Brisbane, QLD 4000" the city name
        // matches before postcode fallback even fires.
        assert!(city_coords("Brisbane, QLD 4000").is_some());
    }

    #[test]
    fn embedded_postcode_resolves_when_suburb_is_untabulated() {
        use crate::util::geohash::haversine_km;
        // Maleny is NOT in CITIES, but its postcode 4552 IS in the exact table.
        // A full address string must still earn the suburb centroid offline.
        let (lat, lon) = city_coords("12 Smith St, Maleny QLD 4552")
            .expect("a postcode-bearing AU address resolves offline");
        // ~Maleny / Sunshine Coast hinterland (4552 centroid).
        assert!(haversine_km(lat, lon, -26.729, 152.7554) < 5.0);
    }

    #[test]
    fn trailing_street_number_is_not_mistaken_for_the_postcode() {
        // A 4-digit STREET number leads, the postcode trails. The last valid
        // token (4217 = Gold Coast) must win over the first (4000 = Brisbane).
        // Suburb deliberately untabulated so the postcode path is exercised.
        use crate::util::geohash::haversine_km;
        let (lat, lon) = city_coords("4000 Pacific Hwy, Tugun-Vista QLD 4217")
            .expect("address with a leading 4-digit street number still resolves");
        // Gold Coast region (42xx ≈ -28.01,153.40), NOT Brisbane (40xx ≈ -27.47).
        assert!(
            haversine_km(lat, lon, -28.01, 153.40) < haversine_km(lat, lon, -27.47, 153.03),
            "resolved to the trailing postcode 4217 (Gold Coast), not the street number 4000"
        );
    }

    #[test]
    fn embedded_long_tail_postcode_falls_back_to_region() {
        // A NSW north-coast suburb absent from CITIES and from the exact postcode
        // table still resolves to its REGION centroid via the leading two digits,
        // so it never silently drops out of the geo footprint.
        let (lat, _lon) = city_coords("3 Ocean Ave, Smalltown NSW 2470")
            .expect("an untabulated AU address still resolves at region grain");
        // 24xx → NSW north coast band (negative latitude, well south of the equator).
        assert!(lat < 0.0, "an AU region centroid is in the southern hemisphere");
    }

    #[test]
    fn non_au_address_with_no_postcode_still_none() {
        // No AU postcode, no tabulated city → still a clean miss (no false fix).
        assert!(city_coords("221B Baker Street, Clobberville").is_none());
    }

    #[test]
    fn consolidated_gazetteer_widens_exact_postcode_coverage() {
        use crate::util::geohash::haversine_km;
        // 7250 (Launceston) was NOT in the old 22-entry city_coords table, so it
        // used to resolve only to the coarse 72xx region centroid (~70 km away).
        // After delegating to the shared ground-truth gazetteer it resolves to
        // the EXACT Launceston centroid — proving the wider table is now in use.
        let (lat, lon) = postcode_coords("7250").expect("7250 is in the shared gazetteer");
        assert!(
            haversine_km(lat, lon, -41.4388, 147.1347) < 2.0,
            "7250 resolves to exact Launceston, not the region centroid"
        );
        // And it is meaningfully tighter than the region fallback for 72xx.
        let (rlat, rlon) = au_postcode_region("7250").expect("should succeed");
        assert!(
            haversine_km(lat, lon, -41.4388, 147.1347)
                < haversine_km(rlat, rlon, -41.4388, 147.1347),
            "exact centroid beats the region centroid for a tabulated postcode"
        );
    }

    /// Inside the Australian mainland+Tasmania bounding box.
    fn in_australia(lat: f64, lon: f64) -> bool {
        (-44.0..=-10.0).contains(&lat) && (112.0..=154.0).contains(&lon)
    }

    /// The nine real address→coordinate derivations captured in a production scan
    /// (Huntsman debug bundle, scan `90b936dc…`, target "Matthew Diegmann"): US
    /// breach-record addresses the geo pass turned into `coordinates` entities.
    /// SEVEN of the nine resolved to *Australian* region centroids because a
    /// 4-digit US STREET NUMBER was misread as an Australian postcode — e.g.
    /// "Glendale AZ" → South Australia, "Jefferson City MO" → Sydney, "Bronx NY" →
    /// Melbourne. The two that resolved correctly (Miami, Las Vegas) matched a US
    /// city name in `CITIES` before the postcode fallback. These are the verbatim
    /// inputs, replayed through the real function as the regression oracle.
    const REAL_US_BREACH_ADDRESSES: &[&str] = &[
        "5528 North 73rd Avenue, Glendale, AZ, 85303, US",
        "1019 Winston Dr, Jefferson City, MO, 65101, US",
        "3425 North Moorings Way, Miami, FL, 10007, US",
        "3025 Arden Ridge Dr., Suwanee, GA, 30024, US",
        "9025 W. 84th St N, Valley Center, KS, 67147, US",
        "4530 Donald Creek Ave, Las Vegas, NV, 89141, US",
        "7512 somerset blvd, Paramount, CA, 90723, US",
        "3145 Rochambeau Ave, Bronx, NY, 10467, US",
        "3809 Slalom Dr, Billings, MT, 59102, US",
    ];

    #[test]
    fn real_us_breach_addresses_never_geocode_to_australia() {
        for addr in REAL_US_BREACH_ADDRESSES {
            if let Some((lat, lon)) = city_coords(addr) {
                assert!(
                    !in_australia(lat, lon),
                    "US address {addr:?} resolved to Australian coords ({lat},{lon})"
                );
            }
        }
    }

    #[test]
    fn tabulated_us_cities_still_resolve_to_the_us() {
        // The two captures that resolved correctly matched a US city name in
        // CITIES before the postcode fallback — that path must keep working, and
        // land in the northern hemisphere (positive latitude), never in AU.
        let (lat, _) = city_coords("3425 North Moorings Way, Miami, FL, 10007, US")
            .expect("Miami is tabulated in CITIES");
        assert!(lat > 0.0, "Miami resolves to the US, not the southern hemisphere");
        let (lat, _) = city_coords("4530 Donald Creek Ave, Las Vegas, NV, 89141, US")
            .expect("Las Vegas is tabulated in CITIES");
        assert!(lat > 0.0, "Las Vegas resolves to the US, not the southern hemisphere");
    }

    #[test]
    fn untabulated_us_suburbs_earn_no_coordinate() {
        // The seven untabulated US suburbs used to manufacture an AU region fix
        // from their leading 4-digit street number. Now each cleanly misses
        // rather than fabricating a false Australian location.
        for addr in [
            "5528 North 73rd Avenue, Glendale, AZ, 85303, US",
            "1019 Winston Dr, Jefferson City, MO, 65101, US",
            "3025 Arden Ridge Dr., Suwanee, GA, 30024, US",
            "9025 W. 84th St N, Valley Center, KS, 67147, US",
            "7512 somerset blvd, Paramount, CA, 90723, US",
            "3145 Rochambeau Ave, Bronx, NY, 10467, US",
            "3809 Slalom Dr, Billings, MT, 59102, US",
        ] {
            assert!(
                city_coords(addr).is_none(),
                "untabulated US address {addr:?} must not fabricate a coordinate"
            );
        }
    }

    #[test]
    fn us_zip_plus_four_addon_is_not_read_as_an_au_postcode() {
        // Real captured US ZIP+4 addresses (debug bundle, scan 90b936dc…, entity
        // [21]): the trailing 4-digit run is the +4 add-on of a 5-digit US ZIP, NOT
        // an AU postcode. Previously "…, NV, 89436-9322" → final run "9322" → QLD
        // region (Brisbane). It must now earn no Australian coordinate.
        assert!(
            city_coords("6509 Angels Orchard Dr, Sparks, NV, 89436-9322").is_none(),
            "ZIP+4 add-on 9322 must not resolve to the QLD region"
        );
        assert!(city_coords("697 Echo Drive, Gates Mills, OH, 44040-9606").is_none());
        assert!(city_coords("13382 Kootenay Drive, Santa Ana, CA, 92705-2038").is_none());
        // Positive control: a genuine AU address (postcode after the state, no
        // "#####-" prefix) still resolves to its trailing postcode.
        use crate::util::geohash::haversine_km;
        let (lat, lon) = city_coords("4000 Gold Coast Hwy, Mermaid Beach QLD 4217")
            .expect("a trailing AU postcode still resolves");
        assert!(
            haversine_km(lat, lon, -28.01, 153.40) < haversine_km(lat, lon, -27.47, 153.03),
            "resolved to the trailing AU postcode 4217 (Gold Coast)"
        );
    }

    #[test]
    fn leading_street_number_is_not_read_as_postcode_without_a_country_tag() {
        // Prove the final-run anchoring fixes the root cause independently of the
        // non-AU country guard: with the country stripped, the leading 4-digit
        // street number still must not resolve as an AU postcode.
        assert!(
            city_coords("5528 North 73rd Avenue, Glendale, 85303").is_none(),
            "leading street number 5528 must not read as an SA postcode"
        );
        assert!(
            city_coords("9025 W. 84th St N, Valley Center, 67147").is_none(),
            "leading street number 9025 must not read as a QLD postcode"
        );
    }

    #[test]
    fn au_address_still_resolves_with_the_non_au_guard_in_place() {
        use crate::util::geohash::haversine_km;
        // Untabulated AU suburb, postcode trailing, explicit AU country suffix —
        // must still earn its coordinate. The guard lists only non-AU nations, so
        // "Australia" never gates a genuine AU address.
        let (lat, lon) = city_coords("9 Coral St, Maleny QLD 4552, Australia")
            .expect("a trailing AU postcode resolves even with a country suffix");
        assert!(haversine_km(lat, lon, -26.729, 152.7554) < 5.0);
    }

    #[test]
    fn non_au_country_guard_blocks_a_foreign_four_digit_postcode() {
        // A NZ postcode is 4 digits and 4310 falls in an AU range — without the
        // guard it would borrow an Australian fix. The explicit nation name blocks
        // it; a tabulated NZ city still resolves via CITIES (which runs first).
        assert!(city_coords("10 Queen St, Smalltown, New Zealand 4310").is_none());
        assert!(city_coords("Auckland, New Zealand").is_some());
    }

    #[test]
    fn non_au_country_detector_does_not_gate_new_south_wales() {
        // "wales" inside "New South Wales" must NOT read as a non-AU signal.
        assert!(!mentions_non_au_country(
            "100 george st, sydney, new south wales 2000"
        ));
        assert!(mentions_non_au_country("100 main st, glendale, az, 85303, us"));
        assert!(mentions_non_au_country(
            "10 queen st, smalltown, new zealand 4310"
        ));
    }

    #[test]
    fn au_address_never_resolves_to_a_foreign_homonym() {
        use crate::util::geo::is_in_australia;
        // liverpool/portland/wellington are tabulated ONLY with their overseas
        // coordinates; an AU address naming the state + postcode must resolve in
        // Australia (via the postcode fallback), not to the foreign homonym.
        for a in [
            "Liverpool, NSW 2170",
            "Portland, VIC 3305",
            "Wellington, NSW 2820",
        ] {
            let p = city_coords(a).unwrap_or_else(|| panic!("{a} should resolve"));
            assert!(is_in_australia(p.0, p.1), "{a} -> {p:?} (expected AU)");
        }
        assert_eq!(city_coords("Liverpool, NSW 2170"), city_coords("2170"));
    }

    #[test]
    fn bare_nz_city_with_a_four_digit_postcode_stays_in_new_zealand() {
        use crate::util::geo::is_in_australia;
        // NZ postcodes are 4 digits and overlap AU numeric ranges (6011 falls in
        // the WA range, 1010 in NSW, 8011 in VIC). A bare "City NNNN" with NO
        // country word and NO explicit AU state token must keep its correct
        // tabulated NZ coordinate — an in-range AU postcode ALONE is not proof of
        // Australia. Regression: keying `names_au_locality` on the postcode alone
        // suppressed the NZ homonym and redirected these to AU (WA/NSW/VIC).
        for (a, want) in [
            ("Wellington 6011", (-41.2865, 174.7762)),
            ("Auckland 1010", (-36.8485, 174.7633)),
            ("Christchurch 8011", (-43.5321, 172.6362)),
        ] {
            let p = city_coords(a).unwrap_or_else(|| panic!("{a} should resolve"));
            assert!(!is_in_australia(p.0, p.1), "{a} -> {p:?} (must stay in NZ)");
            assert_eq!(p, want, "{a} must resolve to its tabulated NZ coordinate");
        }
    }

    #[test]
    fn foreign_address_with_an_ambiguous_state_code_is_unchanged() {
        use crate::util::geo::is_in_australia;
        // WA = Washington State here, not Western Australia: no AU postcode, no
        // "australia" — the foreign homonym must still win.
        let p = city_coords("Seattle, WA 98101").expect("seattle resolves");
        assert!(!is_in_australia(p.0, p.1), "Seattle must stay in the US: {p:?}");
        assert!(city_coords("London, UK").is_some());
    }

    #[test]
    fn tabulated_au_city_still_wins_over_the_postcode_fallback() {
        // A genuine AU tabulated row must not be gated out by the AU-place check.
        assert_eq!(city_coords("Newcastle, NSW 2300"), Some((-32.9283, 151.7817)));
    }

    #[test]
    fn is_tabulated_au_city_matches_exact_multi_word_names_only() {
        assert!(is_tabulated_au_city("gold coast"));
        assert!(is_tabulated_au_city("brisbane"));
        // Exact-match, case-sensitive by design — callers lowercase first, same
        // as every other lookup in this module.
        assert!(!is_tabulated_au_city("Gold Coast"));
        // Tabulated, but not Australian — CITIES also carries representative
        // overseas cities for the free-text city_coords() lookup.
        assert!(!is_tabulated_au_city("new york"));
        // An arbitrary phrase, and a superset of a real name, must not match.
        assert!(!is_tabulated_au_city("smith gold coast"));
        assert!(!is_tabulated_au_city("nowhere special"));
    }

    #[test]
    fn is_tabulated_au_city_recognises_port_macquarie() {
        // Discovered mid-merge (2026-08-26): a concurrent session's own OD-18
        // fix (correlator::rules::geo::profile::extract_ratemyagent_suburb)
        // names "Port Macquarie" as one of four target markets the defect
        // must resolve, and its own provenance notes explicitly recorded this
        // gap and deliberately deferred it as a separate gazetteer-coverage
        // question. Closed here instead: a genuinely major NSW mid-north-coast
        // town (~90k population) is a two-line, zero-risk addition. Added
        // alongside the other NSW regional entries.
        assert!(is_tabulated_au_city("port macquarie"));
    }

// ── REQ-SHODAN-002: the gazetteer's contract at its boundary ─────────────────

#[test]
fn a_bare_country_name_never_resolves_but_the_address_it_belongs_to_does() {
    // CITIES is a gazetteer of CITIES. Two modules held geocoding legs that
    // passed a bare country name into it and could therefore never fire: a
    // silent `None` is indistinguishable from "no such place", so the dead leg
    // survived review twice and was worked around in test fixtures rather than
    // fixed (`shodan`, `oathnet_pro`).
    //
    // This pins the boundary the callers must respect. It is not a claim that a
    // country-shaped row could never be added — it is a claim that adding one
    // would be a DELIBERATE change to what this table means, which this test
    // makes you confront rather than discover in production.
    const COUNTRIES: &[&str] = &[
        // Countries whose centroid a provider's `country` field might name.
        "Australia",
        "United States",
        "United Kingdom",
        "Germany",
        "France",
        "Japan",
        "China",
        "India",
        "Canada",
        "Brazil",
        "Vietnam",
        // City-states, where the country/city distinction is thinnest and the
        // temptation to rely on a hit is strongest.
        "Singapore",
        "Monaco",
        "Hong Kong",
        "Luxembourg",
    ];
    let resolved: Vec<&str> = COUNTRIES
        .iter()
        .copied()
        .filter(|c| city_coords(c).is_some())
        .collect();
    assert!(
        resolved.is_empty(),
        "a bare country name resolved through the CITY gazetteer: {resolved:?} — \
         if this row was added on purpose, update the callers that rely on the \
         miss (see REQ-SHODAN-002) before relaxing this test"
    );

    // The converse, and the reason the rule is workable: the same country
    // composed with the city the caller already had DOES resolve. A caller with
    // both fields must pass the composed string, not one field of it.
    for (composed, why) in [
        ("Brisbane, Australia", "AU capital"),
        ("Manchester, United Kingdom", "non-AU, foreign-place gate active"),
        ("Chicago, United States", "non-AU, multi-word country"),
    ] {
        assert!(
            city_coords(composed).is_some(),
            "{composed} ({why}) must resolve — otherwise the rule this test \
             teaches has no workable alternative"
        );
    }
}

    /// REQ-GEO-017: every value `city_coords` can return — a tabulated name, a
    /// tabulated postcode, a leading-digit region — is recognised at the
    /// 4-decimal grain callers format it with; a point off the tables is not.
    #[test]
    fn every_city_coords_answer_is_a_gazetteer_centroid() {
        for addr in [
            "Sydney NSW",
            "Brisbane, QLD",
            "Auckland",
            "4552",
            "4999",
            "12 Smith St, Maleny QLD 4552",
        ] {
            let (lat, lon) = city_coords(addr).expect(addr);
            let shown: Vec<f64> = format!("{lat:.4},{lon:.4}")
                .split(',')
                .map(|p| p.parse().unwrap())
                .collect();
            assert!(is_gazetteer_centroid(shown[0], shown[1]), "{addr}");
        }
        assert!(!is_gazetteer_centroid(-27.4801, 152.9912));
        assert!(!is_gazetteer_centroid(-33.869844, 151.208285));
    }

    /// REQ-GEOLABEL-001: the one centroid authority says WHICH place a value
    /// stands for. The operator's example `-27.4698,153.0251` is both the
    /// `brisbane` row and postcode 4000's centroid; the coarser reading, the
    /// city, is kept, in the AU anchor's spelling.
    #[test]
    fn tabulated_centroid_at_names_what_a_centroid_stands_for() {
        assert_eq!(
            tabulated_centroid_at(-27.4698, 153.0251),
            Some(TabulatedCentroid::City {
                name: "Brisbane".to_string(),
                state: Some("QLD"),
            })
        );
        // A CITIES row with no anchor is title-cased, its state from the box.
        assert_eq!(
            tabulated_centroid_at(-27.4833, 152.9833),
            Some(TabulatedCentroid::City {
                name: "Toowong".to_string(),
                state: Some("QLD"),
            })
        );
        // A postcode centroid that is no city row or anchor (Mansfield).
        let (lat, lon) = postcode_coords("4122").expect("Mansfield is tabulated");
        assert!(matches!(
            tabulated_centroid_at(lat, lon),
            Some(TabulatedCentroid::Postcode { ref code, state: Some("QLD") }) if code == "4122"
        ));
        // Maleny's postcode centroid is also its anchor: the city reading wins.
        let (lat, lon) = postcode_coords("4552").expect("Maleny is tabulated");
        assert!(matches!(
            tabulated_centroid_at(lat, lon),
            Some(TabulatedCentroid::City { ref name, .. }) if name == "Maleny"
        ));
        // A leading-digit region centroid.
        let (lat, lon) = au_postcode_region("4820").expect("the 48 region");
        assert_eq!(
            tabulated_centroid_at(lat, lon),
            Some(TabulatedCentroid::PostcodeRegion {
                prefix: "48",
                state: Some("QLD"),
            })
        );
        // Off every table.
        assert_eq!(tabulated_centroid_at(-27.4801, 152.9912), None);
        assert!(TabulatedCentroid::PostcodeRegion { prefix: "40", state: None }.rank()
            > TabulatedCentroid::City { name: String::new(), state: None }.rank());
    }

    /// `is_gazetteer_centroid` is `tabulated_centroid_at` as a predicate — and
    /// the curated AU locality anchors are centroids too.
    #[test]
    fn the_gazetteer_predicate_is_the_lookup() {
        for (lat, lon) in [(-27.4698, 153.0251), (-28.8136, 153.2773), (-27.4801, 152.9912)] {
            assert_eq!(
                is_gazetteer_centroid(lat, lon),
                tabulated_centroid_at(lat, lon).is_some()
            );
        }
        // Lismore's anchor value is in no CITIES or postcode row: only the
        // anchor table makes it a centroid.
        assert_eq!(
            tabulated_centroid_at(-28.8136, 153.2773),
            Some(TabulatedCentroid::City {
                name: "Lismore".to_string(),
                state: Some("NSW"),
            })
        );
    }
