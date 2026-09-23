use super::*;
    use crate::core::entity::Evidence;

    fn au_coord(value: &str, conf: f64, source: &str, state: &str) -> Entity {
        let mut e = Entity::new(EntityKind::Coordinates, value, conf, "s");
        e.tag(format!("au-state:{state}"));
        e.tag("country:AU");
        e.add_evidence(Evidence::new(source, "geo sighting"));
        e
    }

    #[test]
    fn fires_on_two_orthogonal_classes() {
        // A registry address and a photo GPS, both in NSW, converge.
        let ents = vec![
            au_coord("-33.8688,151.2093", 0.80, "abn_lookup", "NSW"),
            au_coord("-33.8700,151.2100", 0.70, "exif_geo", "NSW"),
        ];
        let out = rule_au_059_cross_seed_geo_synergy(&RuleContext::new(&ents), "s", 0);
        assert_eq!(out.len(), 1, "two orthogonal classes must fire AU-059");
        assert!(out[0].description.contains("state=NSW"));
    }

    #[test]
    fn agreeing_coarse_sightings_never_synthesise_a_precision_neither_had() {
        // A search-snippet geocode (~15 km grain) and a self-reported social bio
        // (~5 km grain) that both name the same city resolve a few hundred
        // metres apart. The median distance between them is a few hundred
        // metres — and reporting THAT as the fix's radius turns two city-grain
        // guesses agreeing into a street-level claim, which then leaves the tool
        // as `best_location` in report.json and as the dossier's geo line.
        let ents = vec![
            au_coord("-33.8688,151.2093", 0.70, "search_engines", "NSW"),
            au_coord("-33.8724,151.2093", 0.70, "social_location", "NSW"),
        ];
        let fix = au059_synergy_fix(&ents).expect("two orthogonal classes fuse");
        let spread_km = crate::util::geometry::median_distance_km(
            (fix.lat, fix.lon),
            &[(-33.8688, 151.2093), (-33.8724, 151.2093)],
        );
        assert!(
            spread_km < 1.0,
            "fixture precondition: the sightings agree closely ({spread_km} km)"
        );
        let finest_km = precision_radius_m(GeoSourceClass::Social) / 1000.0;
        assert!(
            fix.radius_km >= finest_km - 1e-9,
            "agreement corroborates the AREA; it cannot report {} km when the \
             tightest contributing source was only good to {finest_km} km",
            fix.radius_km
        );
        // The prose and the field are one and the same, so the description
        // cannot report the pre-floor number either.
        assert!(
            fix.description().contains(&format!("{:.1} km", fix.radius_km)),
            "{}",
            fix.description()
        );
    }

    #[test]
    fn a_genuine_disagreement_still_widens_the_radius_beyond_the_floor() {
        // The floor raises a too-tight radius; it must never CAP a legitimately
        // wide one. Two sightings ~8 km apart are further apart than the finest
        // contributing precision, so the spread still governs.
        let ents = vec![
            au_coord("-33.8688,151.2093", 0.70, "exif_geo", "NSW"),
            au_coord("-33.9400,151.2093", 0.70, "geocode", "NSW"),
        ];
        let fix = au059_synergy_fix(&ents).expect("two orthogonal classes fuse");
        let finest_km = precision_radius_m(GeoSourceClass::PhotoGps) / 1000.0;
        assert!(
            fix.radius_km > finest_km,
            "a real disagreement of several km must not be reported as {} km",
            fix.radius_km
        );
        assert!(
            fix.radius_km > 1.0,
            "the spread governs when it exceeds the floor: {}",
            fix.radius_km
        );
    }

    #[test]
    fn a_registered_or_inferred_place_is_never_the_subjects_own_position() {
        // INFRASTRUCTURE LOCATION != HUMAN LOCATION, REGISTERED LOCATION !=
        // PHYSICAL PRESENCE. Only a sighting of the subject's own device counts
        // as observing them; every other class names a real place that can be
        // right about the address and wrong about the person.
        for class in [
            GeoSourceClass::DeviceGps,
            GeoSourceClass::PhotoGps,
            GeoSourceClass::WifiSensor,
        ] {
            assert!(class_locates_subject_directly(class), "{class:?}");
        }
        for class in [
            GeoSourceClass::Geocode,
            GeoSourceClass::Registry,
            GeoSourceClass::Directory,
            GeoSourceClass::Enrichment,
            GeoSourceClass::Social,
            GeoSourceClass::Search,
            GeoSourceClass::NetworkIp,
            GeoSourceClass::Phone,
            GeoSourceClass::Other,
        ] {
            assert!(
                !class_locates_subject_directly(class),
                "{class:?} names a place associated with the subject, not the subject"
            );
        }
        // It is orthogonal to precision: a registered office is known to ~500 m
        // and still is not the subject; a Wi-Fi survey is coarser at ~75 m and
        // is. Collapsing the two turns a filing agent's PO box into a residence.
        assert!(
            precision_radius_m(GeoSourceClass::Registry)
                < precision_radius_m(GeoSourceClass::WifiSensor) * 10.0
        );
        assert!(!class_locates_subject_directly(GeoSourceClass::Registry));
        assert!(class_locates_subject_directly(GeoSourceClass::WifiSensor));
    }

    #[test]
    fn a_fix_built_only_from_records_is_marked_as_an_associated_location() {
        // A registry office and a search snippet: two orthogonal classes, so
        // AU-059 fires — and nothing in it observed the subject.
        let records = vec![
            au_coord("-33.8688,151.2093", 0.80, "abn_lookup", "NSW"),
            au_coord("-33.8700,151.2100", 0.70, "search_engines", "NSW"),
        ];
        let fix = au059_synergy_fix(&records).expect("two orthogonal classes fuse");
        assert!(
            !fix.locates_subject_directly,
            "a registered office and a search snippet locate records, not a person"
        );
        assert!(
            !best_au_location_estimate(&records)
                .expect("a headline estimate exists")
                .locates_subject_directly,
            "the headline estimate must carry the same verdict as the fix behind it"
        );

        // One photo GPS among them and the fix DID observe the subject's device.
        let sighted = vec![
            au_coord("-33.8688,151.2093", 0.80, "abn_lookup", "NSW"),
            au_coord("-33.8700,151.2100", 0.70, "exif_geo", "NSW"),
        ];
        let fix = au059_synergy_fix(&sighted).expect("two orthogonal classes fuse");
        assert!(fix.locates_subject_directly);
        assert!(
            best_au_location_estimate(&sighted)
                .expect("a headline estimate exists")
                .locates_subject_directly
        );
    }

    #[test]
    fn does_not_fire_on_single_class() {
        // Two registry sources are the SAME class — no orthogonal synergy.
        let ents = vec![
            au_coord("-33.8688,151.2093", 0.80, "abn_lookup", "NSW"),
            au_coord("-33.8700,151.2100", 0.75, "acnc_charities", "NSW"),
        ];
        let out = rule_au_059_cross_seed_geo_synergy(&RuleContext::new(&ents), "s", 0);
        assert!(out.is_empty(), "same source class must not assert synergy");
    }

    #[test]
    fn three_classes_is_high_severity() {
        let ents = vec![
            au_coord("-37.8136,144.9631", 0.80, "abn_lookup", "VIC"),
            au_coord("-37.8140,144.9640", 0.70, "exif_geo", "VIC"),
            au_coord("-37.8150,144.9650", 0.65, "wigle", "VIC"),
        ];
        let out = rule_au_059_cross_seed_geo_synergy(&RuleContext::new(&ents), "s", 0);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].severity, Severity::High);
    }

    #[test]
    fn excludes_non_australian_coordinates() {
        // One AU registry point + one London photo GPS: only 1 AU class remains.
        let mut london = Entity::new(EntityKind::Coordinates, "51.5074,-0.1278", 0.80, "s");
        london.add_evidence(Evidence::new("exif_geo", "geo sighting"));
        let ents = vec![
            au_coord("-33.8688,151.2093", 0.80, "abn_lookup", "NSW"),
            london,
        ];
        let out = rule_au_059_cross_seed_geo_synergy(&RuleContext::new(&ents), "s", 0);
        assert!(
            out.is_empty(),
            "non-AU coordinate must not contribute a class"
        );
    }

    #[test]
    fn source_class_mapping_is_orthogonal() {
        assert_eq!(geo_source_class("exif_geo"), GeoSourceClass::PhotoGps);
        assert_eq!(geo_source_class("abn_lookup"), GeoSourceClass::Registry);
        assert_eq!(geo_source_class("asic_director"), GeoSourceClass::Registry);
        assert_eq!(geo_source_class("au_unclaimed"), GeoSourceClass::Directory);
        assert_eq!(geo_source_class("phone_area_geo"), GeoSourceClass::Phone);
        assert_eq!(geo_source_class("unknown_src"), GeoSourceClass::Other);
    }

    #[test]
    fn au_state_majority_picks_dominant() {
        let ents = [
            au_coord("-33.8688,151.2093", 0.8, "abn_lookup", "NSW"),
            au_coord("-33.8700,151.2100", 0.7, "exif_geo", "NSW"),
            au_coord("-37.8136,144.9631", 0.7, "wigle", "VIC"),
        ];
        let parsed: Vec<(&Entity, (f64, f64))> = ents
            .iter()
            .filter_map(|e| crate::util::geohash::parse_coords(&e.value).map(|ll| (e, ll)))
            .collect();
        assert_eq!(au_state_majority(&parsed), Some("NSW"));
    }

    // ── is_australian_coord ───────────────────────────────────────────────────

    #[test]
    fn is_australian_coord_accepts_via_tag_or_bounding_box() {
        // country:AU tag → AU regardless of the passed lat/lon.
        let mut tagged = Entity::new(EntityKind::Coordinates, "0,0", 0.6, "s");
        tagged.tag("country:AU");
        assert!(is_australian_coord(&tagged, (51.5, -0.12)));

        // au-state: tag → AU.
        let mut state = Entity::new(EntityKind::Coordinates, "0,0", 0.6, "s");
        state.tag("au-state:NSW");
        assert!(is_australian_coord(&state, (51.5, -0.12)));

        // No tag, but the coordinate lands inside Australia (Sydney).
        let untagged = Entity::new(EntityKind::Coordinates, "-33.8688,151.2093", 0.6, "s");
        assert!(is_australian_coord(&untagged, (-33.8688, 151.2093)));
    }

    #[test]
    fn is_australian_coord_rejects_untagged_offshore_fix() {
        // No AU tag and the coordinate is in London → not Australian.
        let e = Entity::new(EntityKind::Coordinates, "51.5074,-0.1278", 0.6, "s");
        assert!(!is_australian_coord(&e, (51.5074, -0.1278)));
    }

    // ── is_infrastructure_geo ─────────────────────────────────────────────────

    #[test]
    fn is_infrastructure_geo_flags_hosting_and_poi_and_unanchored() {
        // hosting-tagged CDN/cloud edge.
        let mut hosting = Entity::new(EntityKind::Coordinates, "0,0", 0.6, "s");
        hosting.add_evidence(Evidence::new("wigle", "x")); // anchored, but…
        hosting.tag("hosting"); // …the hosting tag still vetoes it
        assert!(is_infrastructure_geo(&hosting));

        // infra: map-feature tag (Overpass POI).
        let mut poi = Entity::new(EntityKind::Coordinates, "0,0", 0.6, "s");
        poi.tag("infra:camera");
        assert!(is_infrastructure_geo(&poi));

        // No person-anchoring corroborating source → infrastructure geo.
        let mut ipgeo = Entity::new(EntityKind::Coordinates, "0,0", 0.6, "s");
        ipgeo.add_evidence(Evidence::new("ipinfo", "ip-geo")); // not in the anchor list
        assert!(is_infrastructure_geo(&ipgeo));
    }

    #[test]
    fn is_infrastructure_geo_false_for_person_anchored_fix() {
        // A WiGLE sighting is person-anchoring, and there's no hosting/infra tag.
        let mut e = Entity::new(EntityKind::Coordinates, "-33.87,151.21", 0.6, "s");
        e.add_evidence(Evidence::new("wigle", "wifi sighting"));
        assert!(!is_infrastructure_geo(&e));
    }

    #[test]
    fn is_infrastructure_geo_flags_radar_sentinel_even_when_seed_anchored() {
        // `hse radar` seeds its sweep with the sentinel Coordinates target
        // (0,0), minted with the same `seed, subject` tags — and a
        // person-anchoring evidence source — a real operator-provided anchor
        // carries. Without the sentinel check it sails past every other gate
        // here and gets fused into AU-057's weighted median as a full subject
        // sighting (observed live: dragged a real Brisbane fix out to the
        // Indian Ocean via UID f428eed0...).
        let mut sentinel = Entity::new(
            crate::core::entity::EntityKind::Coordinates,
            crate::core::scan::RADAR_SENTINEL_COORD_RAW,
            1.0,
            "s",
        );
        sentinel.add_evidence(Evidence::new("wigle", "seed anchor"));
        sentinel.tag("seed");
        sentinel.tag("subject");
        assert!(is_infrastructure_geo(&sentinel));
    }

    #[test]
    fn best_au_location_estimate_rung2_is_order_independent_on_a_confidence_tie() {
        // Two equal-confidence AU person-anchored coordinates (Brisbane QLD vs
        // Melbourne VIC), single-source so the rung-1 synergy gate stays closed and
        // rung 2 (most-confident single coordinate) runs. On a c_effective tie
        // `max_by` returns whichever coord iterated LAST, so before the UID
        // tie-break the winning estimate — a user-facing dossier/export headline —
        // flipped with the HashMap-snapshot order of the entity slice.
        let bris = au_coord("-27.4698,153.0251", 0.70, "geocode", "QLD");
        let melb = au_coord("-37.8136,144.9631", 0.70, "geocode", "VIC");
        let fwd = best_au_location_estimate(&[bris.clone(), melb.clone()])
            .expect("rung-2 coordinate estimate");
        let rev =
            best_au_location_estimate(&[melb, bris]).expect("rung-2 coordinate estimate");
        assert_eq!(fwd.basis, "confirmed coordinate");
        assert_eq!(
            (fwd.lat, fwd.lon, fwd.state, fwd.uids),
            (rev.lat, rev.lon, rev.state, rev.uids),
            "the rung-2 coordinate winner must be order-independent on a confidence tie"
        );
    }

    /// Sightings in two different cities must never be averaged into a fix
    /// between them.
    ///
    /// Perth and Sydney are ~3,290 km apart. Before the coherence gate, an
    /// `abn_lookup` hit in one and an `exif_geo` hit in the other satisfied the
    /// "≥2 orthogonal classes" test, and their weighted geometric median landed
    /// in the Nullarbor — reported at up to 0.97 confidence. The radius was
    /// honest about the spread, but the point itself was a place nobody had
    /// been seen.
    #[test]
    fn does_not_fuse_sightings_from_different_cities() {
        let ents = vec![
            au_coord("-31.9523,115.8613", 0.80, "abn_lookup", "WA"),
            au_coord("-33.8688,151.2093", 0.70, "exif_geo", "NSW"),
        ];
        let fix = au059_synergy_fix(&ents);
        if let Some(f) = &fix {
            // Whatever survives must be one real city, never the midpoint.
            assert!(
                f.radius_km < 100.0,
                "a fused fix must not span cities, got radius {} km at {},{}",
                f.radius_km,
                f.lat,
                f.lon
            );
            assert!(
                f.lon < 125.0 || f.lon > 140.0,
                "fix at lon {} sits between Perth and Sydney — the Nullarbor \
                 midpoint this gate exists to prevent",
                f.lon
            );
        }
        // Each city contributes a single class, so neither group can satisfy
        // the ≥2-orthogonal-class synergy gate on its own.
        assert!(
            fix.is_none(),
            "two single-class city groups must not assert cross-class synergy"
        );
    }

    /// The dominant group is chosen by orthogonal-class agreement, so a
    /// well-corroborated cluster wins over a distant lone sighting — and the
    /// outlier must not drag the fused point toward itself.
    #[test]
    fn fuses_the_best_supported_group_and_ignores_a_distant_outlier() {
        let ents = vec![
            au_coord("-33.8688,151.2093", 0.80, "abn_lookup", "NSW"),
            au_coord("-33.8700,151.2100", 0.75, "exif_geo", "NSW"),
            au_coord("-33.8710,151.2110", 0.70, "wigle", "NSW"),
            // A lone Perth sighting 3,290 km west.
            au_coord("-31.9523,115.8613", 0.85, "au_unclaimed", "WA"),
        ];
        let f = au059_synergy_fix(&ents).expect("the Sydney cluster must still fire");
        assert!(
            (f.lat - -33.87).abs() < 0.5 && (f.lon - 151.21).abs() < 0.5,
            "expected the Sydney cluster, got {},{}",
            f.lat,
            f.lon
        );
        assert!(f.radius_km < 50.0, "radius {} km", f.radius_km);
        assert_eq!(f.state, "NSW");
    }

    /// Two coherent groups that tie on class-count, summed confidence, AND size
    /// must resolve to the SAME group regardless of the input slice's order.
    /// Before the content-based (min-UID) tie-break, `max_by` kept the *last*
    /// maximal group, so feeding the same entities in a different order — which
    /// the HashMap-ordered live pass does relative to the ordered finalise pass —
    /// flipped the chosen city and produced a different AU-059 fix for one set.
    #[test]
    fn dominant_group_choice_is_order_independent_on_a_full_tie() {
        let sydney = || {
            vec![
                au_coord("-33.8688,151.2093", 0.80, "abn_lookup", "NSW"),
                au_coord("-33.8700,151.2100", 0.70, "exif_geo", "NSW"),
            ]
        };
        let melbourne = || {
            vec![
                au_coord("-37.8136,144.9631", 0.80, "abn_lookup", "VIC"),
                au_coord("-37.8140,144.9640", 0.70, "exif_geo", "VIC"),
            ]
        };
        // Both groups: 2 classes, summed confidence 1.50, size 2 — a full tie.
        let mut forward = sydney();
        forward.extend(melbourne());
        let mut reversed = melbourne();
        reversed.extend(sydney());

        let a = au059_synergy_fix(&forward).expect("a tied group must still fuse");
        let b = au059_synergy_fix(&reversed).expect("a tied group must still fuse");
        assert_eq!(
            (a.lat.to_bits(), a.lon.to_bits(), a.state),
            (b.lat.to_bits(), b.lon.to_bits(), b.state),
            "the chosen group must not depend on input order"
        );
    }

    /// Adding evidence must never ERASE a finding. A lone coordinate that carries
    /// several distinct anchoring classes forms a 1-point group with a high
    /// class-count; ranking class-count first once let it outrank a genuine
    /// 2-point cluster, after which the ≥2-point fusion gate discarded it and the
    /// whole synergy fix vanished. The valid Sydney cluster must still fire.
    #[test]
    fn a_high_class_singleton_does_not_suppress_a_valid_cluster() {
        // A single Perth coordinate merged from three distinct anchoring classes
        // (DeviceGps + WifiSensor + PhotoGps) — class-count 3, but only 1 point.
        let mut lone_perth = au_coord("-31.9523,115.8613", 0.95, "device_sensors", "WA");
        lone_perth.add_evidence(Evidence::new("wifi_intel", "geo sighting"));
        lone_perth.add_evidence(Evidence::new("exif_geo", "geo sighting"));

        let ents = vec![
            lone_perth,
            // A genuine 2-point, 2-class Sydney cluster that fires on its own.
            au_coord("-33.8688,151.2093", 0.80, "abn_lookup", "NSW"),
            au_coord("-33.8700,151.2100", 0.70, "exif_geo", "NSW"),
        ];
        let f = au059_synergy_fix(&ents)
            .expect("the 2-point Sydney cluster must fire despite the high-class singleton");
        assert_eq!(f.state, "NSW", "the fused fix must be the Sydney cluster");
        assert!(
            (f.lat - -33.87).abs() < 0.5 && (f.lon - 151.21).abs() < 0.5,
            "expected the Sydney cluster, got {},{}",
            f.lat,
            f.lon
        );
    }

    /// A live handset GNSS fix is the most precise person-location signal the
    /// product has. The person-anchor gate is an allowlist, and omitting
    /// `signal_radar`/`device_sensors` made `is_infrastructure_geo` classify a
    /// 20 m lock on the subject's own phone as infrastructure — excluding it
    /// from every rule that answers "where is this person".
    #[test]
    fn device_gps_is_person_anchoring_not_infrastructure() {
        for src in ["signal_radar", "device_sensors", "wifi_intel"] {
            assert!(
                is_anchoring_geo_source(src),
                "{src} locates the subject's own device"
            );
            let e = au_coord("-27.4698,153.0251", 0.90, src, "QLD");
            assert!(
                !is_infrastructure_geo(&e),
                "{src} must not be treated as infrastructure"
            );
        }
        assert_eq!(geo_source_class("signal_radar"), GeoSourceClass::DeviceGps);
        assert_eq!(geo_source_class("device_sensors"), GeoSourceClass::DeviceGps);
        assert_eq!(geo_source_class("wifi_intel"), GeoSourceClass::WifiSensor);
        // Finest in the precision table — finer than photo EXIF.
        assert!(
            precision_radius_m(GeoSourceClass::DeviceGps)
                < precision_radius_m(GeoSourceClass::PhotoGps)
        );
    }

    /// A handset fix must now reach the headline estimate, and it should win
    /// over a coarse registry address at the same location.
    #[test]
    fn device_gps_reaches_the_headline_location_estimate() {
        let ents = vec![au_coord("-27.4698,153.0251", 0.90, "signal_radar", "QLD")];
        let est = best_au_location_estimate(&ents)
            .expect("a handset GNSS fix must produce a location estimate");
        assert!((est.lat - -27.4698).abs() < 0.001, "got {}", est.lat);
        assert_eq!(est.state, Some("QLD"));
    }

    fn coord_at(value: &str, conf: f64, source: &str) -> Entity {
        let mut e = Entity::new(EntityKind::Coordinates, value, conf, "s");
        e.add_evidence(Evidence::new(source, "geo sighting"));
        e
    }

    /// A WHOIS-registrant address (a company's filing address, not the
    /// subject's home) must not drive the postcode-grain rung the way a real
    /// breach/register address does. `is_infrastructure_geo` exists exactly
    /// to stop a registrant/hosting location from voting the subject's
    /// physical position (its own doc comment names the postcode/address
    /// rollup rules as consumers), but the postcode rungs (3 & 4) below only
    /// filtered on entity kind, never on this guard.
    #[test]
    fn best_location_does_not_use_a_whois_registrant_address_as_the_postcode_grain() {
        let mut registrant = Entity::new(
            EntityKind::Address,
            "123 Corporate Ave, Melbourne, VIC, 3000",
            crate::core::confidence::MEDIUM_PLUS,
            "s",
        );
        registrant.tag(crate::core::tags::REGISTRANT);
        let est = best_au_location_estimate(&[registrant]);
        assert!(
            est.is_none(),
            "a WHOIS-registrant address must not produce a location estimate: {est:?}"
        );
    }

    /// A subject outside Australia must still get a headline location.
    ///
    /// Rung 2 used to be filtered through `is_australian_coord`, so a person in
    /// London with a photo-GPS fix produced no estimate at all — the JSON
    /// export wrote `null` and the dossier printed nothing. The AU enrichments
    /// are simply absent; the fix itself is jurisdiction-neutral.
    #[test]
    fn non_australian_subject_gets_a_location_estimate() {
        // Westminster, London.
        let ents = vec![coord_at("51.5007,-0.1246", 0.85, "exif_geo")];
        let est = best_au_location_estimate(&ents)
            .expect("a London photo-GPS fix must produce an estimate");
        assert!((est.lat - 51.5007).abs() < 0.001, "got {}", est.lat);
        assert!((est.lon - -0.1246).abs() < 0.001, "got {}", est.lon);
        assert_eq!(est.state, None, "there is no AU state for a London fix");
        assert_eq!(est.locality, None, "AU gazetteer must not name a UK place");
        assert_eq!(est.basis, "confirmed coordinate");
    }

    /// Australian subjects keep their state and locality enrichment.
    #[test]
    fn australian_subject_still_gets_state_enrichment() {
        let ents = vec![coord_at("-27.4698,153.0251", 0.85, "exif_geo")];
        let est = best_au_location_estimate(&ents).expect("Brisbane fix");
        assert_eq!(est.state, Some("QLD"));
    }

    /// The precision radius must come from the measurement, not a flat
    /// constant. Only the device-sensor modules stamp `accuracy:{n}m`, so the
    /// fallback was taken almost always and a 20 m EXIF fix reported "± 2 km".
    #[test]
    fn radius_reflects_source_precision_not_a_flat_default() {
        let photo = best_au_location_estimate(&[coord_at("-27.4698,153.0251", 0.85, "exif_geo")])
            .expect("photo fix");
        let social =
            best_au_location_estimate(&[coord_at("-27.4698,153.0251", 0.85, "social_location")])
                .expect("social fix");
        assert!(
            photo.radius_km < social.radius_km,
            "a photo GPS fix ({} km) must be reported tighter than a \
             self-reported social location ({} km)",
            photo.radius_km,
            social.radius_km
        );
        assert!(photo.radius_km < 0.1, "EXIF GPS is ~20 m, got {} km", photo.radius_km);
    }

    // ------------------------------------------- geocoder match grain -----

    fn geocoded_coord(value: &str, place_type: Option<&str>) -> Entity {
        let mut e = Entity::new(EntityKind::Coordinates, value, 0.80, "s");
        e.tag("country:AU");
        let mut ev = Evidence::new("geocode", "Geocoded \"…\" → …");
        if let Some(pt) = place_type {
            ev = ev.with_attr("place_type", pt);
        }
        e.add_evidence(ev);
        e
    }

    /// `geocode` and `photon` both already RECORD what the geocoder actually
    /// matched — Nominatim's and Photon's own `type` field, written to the
    /// `place_type` evidence attribute on the very Coordinates entity the
    /// fusion weighs. Nothing reads it. `best_precision_radius_m` maps the
    /// SOURCE NAME to `GeoSourceClass::Geocode` and hands back a flat 40 m,
    /// whether the geocoder pinpointed a house number or shrugged and returned
    /// a state centroid.
    ///
    /// At 40 m the fusion multiplier is `sqrt(1000/40)` = **5.0×**; a state
    /// centroid honestly deserves well under 1×. A vague address string thus
    /// pulls the fused location harder than a registry hit that really is
    /// known to 500 m.
    #[test]
    fn a_state_centroid_is_not_weighed_as_a_rooftop_fix() {
        let coarse = geocoded_coord("-33.8688,151.2093", Some("state"));
        let radius = best_precision_radius_m(&coarse).expect("an anchoring source");
        assert!(
            radius > precision_radius_m(GeoSourceClass::Registry),
            "a geocoder that matched only a STATE must be treated as coarser \
             than a registry address known to {} m; got {radius} m",
            precision_radius_m(GeoSourceClass::Registry)
        );
        assert!(
            precision_weight_multiplier(radius) < 1.0,
            "a state centroid must pull SOFTER than the 1 km reference, not \
             5x harder; got {}x",
            precision_weight_multiplier(radius)
        );
    }

    #[test]
    fn a_city_grain_match_is_coarser_than_the_class_default() {
        let city = geocoded_coord("-33.8688,151.2093", Some("city"));
        let radius = best_precision_radius_m(&city).expect("an anchoring source");
        assert!(
            radius > precision_radius_m(GeoSourceClass::Geocode),
            "a city-grain match must be coarser than the geocode class default"
        );
    }

    #[test]
    fn a_house_grain_match_keeps_the_class_default() {
        // CONTROL — passes on the baseline AND the fix. A precise match is
        // exactly what the class radius already describes, and the guard must
        // never SHARPEN a source beyond it: inventing precision is the one
        // direction this change must not move in.
        let house = geocoded_coord("-33.8688,151.2093", Some("house"));
        let radius = best_precision_radius_m(&house).expect("an anchoring source");
        assert!(
            (radius - precision_radius_m(GeoSourceClass::Geocode)).abs() < f64::EPSILON,
            "a rooftop match keeps the class radius; got {radius} m"
        );
    }

    #[test]
    fn an_unrecorded_or_unknown_grain_keeps_the_class_default() {
        // CONTROL — fail-safe. A provider that sends no `type`, or one this
        // table does not know, must behave exactly as before rather than being
        // guessed at in either direction.
        for pt in [None, Some("some_new_osm_type"), Some("")] {
            let e = geocoded_coord("-33.8688,151.2093", pt);
            let radius = best_precision_radius_m(&e).expect("an anchoring source");
            assert!(
                (radius - precision_radius_m(GeoSourceClass::Geocode)).abs() < f64::EPSILON,
                "unknown grain {pt:?} must fall back to the class radius; got {radius} m"
            );
        }
    }

    #[test]
    fn a_coarse_geocode_never_degrades_a_precise_sibling_source() {
        // CONTROL and the boundary that matters: `best_precision_radius_m`
        // takes the MINIMUM across an entity's sources precisely because "a
        // coarser corroborating source confirms the same point without
        // degrading the known precision". Coarsening the geocode leg must not
        // leak into a GPS leg on the same entity.
        let mut e = geocoded_coord("-33.8688,151.2093", Some("state"));
        e.add_evidence(Evidence::new("exif_geo", "EXIF GPS"));
        let radius = best_precision_radius_m(&e).expect("an anchoring source");
        assert!(
            (radius - precision_radius_m(GeoSourceClass::PhotoGps)).abs() < f64::EPSILON,
            "the photo GPS fix still sets the entity's precision; got {radius} m"
        );
    }

    #[test]
    fn the_grain_table_can_only_ever_coarsen() {
        // The safety property the whole change rests on, asserted rather than
        // left to a `debug_assert!` that release builds drop. Sharpening would
        // let a geocoder's own self-report override the class anchor and
        // annihilate genuinely precise sightings via the inverse-sqrt weight —
        // the one direction this must never move in.
        let class_default = precision_radius_m(GeoSourceClass::Geocode);
        let mut recognised = 0usize;
        for pt in [
            "country",
            "state",
            "province",
            "region",
            "state_district",
            "county",
            "district",
            "city",
            "municipality",
            "postcode",
            "postal_code",
            "town",
            "island",
            "borough",
            "suburb",
            "village",
            "quarter",
            "neighbourhood",
            "hamlet",
            "locality",
        ] {
            let r = geocode_grain_radius_m(pt)
                .unwrap_or_else(|| panic!("{pt} must be recognised by the grain table"));
            assert!(
                r > class_default,
                "{pt} maps to {r} m, which is FINER than the {class_default} m class \
                 default — the table may only coarsen"
            );
            recognised += 1;
        }
        assert!(recognised >= 20, "vacuity guard: the table shrank to {recognised} entries");

        // Grains at least as precise as the class default are deliberately not
        // in the table at all: there is nothing to correct.
        for pt in ["house", "building", "street", "road", "amenity", ""] {
            assert!(
                geocode_grain_radius_m(pt).is_none(),
                "{pt} is not coarser than the class default and must not be listed"
            );
        }
    }

    #[test]
    fn the_grain_ordering_follows_real_geography() {
        // A country is coarser than a state is coarser than a city is coarser
        // than a suburb. Getting this inverted would weight the vaguest answer
        // hardest, which is the defect wearing a different hat.
        let r = |pt: &str| geocode_grain_radius_m(pt).expect("recognised");
        assert!(r("country") > r("state"));
        assert!(r("state") > r("county"));
        assert!(r("county") > r("city"));
        assert!(r("city") > r("town"));
        assert!(r("town") > r("suburb"));
    }

    #[test]
    fn the_coarsest_geocoder_answer_on_an_entity_wins() {
        // Two geocoding answers on one coordinate: one resolved a street, the
        // other only a state. The state answer is still a state centroid, so
        // the geocode leg is weighed at the coarser of the two.
        let mut e = geocoded_coord("-33.8688,151.2093", Some("street"));
        e.add_evidence(
            Evidence::new("photon", "Photon match").with_attr("place_type", "state"),
        );
        let radius = best_precision_radius_m(&e).expect("an anchoring source");
        assert!(
            radius >= geocode_grain_radius_m("state").expect("recognised"),
            "the coarsest geocoder answer must set the geocode leg; got {radius} m"
        );
    }

    /// REQ-GEO-009: one search-snippet mention of "Sydney, Australia",
    /// geocoded twice — `search_engines`' inline city lookup and the geocode
    /// module's pivot on the same Address — is one mention, one class. Scan
    /// 7258fc07's headline 0.97 fix rested on exactly this {Geocode, Search}.
    #[test]
    fn a_geocoder_leg_inherits_the_class_of_the_address_it_geocoded() {
        let mut addr = Entity::new(EntityKind::Address, "Sydney, Australia", 0.65, "s");
        addr.tag("country:AU");
        addr.add_evidence(Evidence::new("search_engines", "Address near example.com"));

        let mut a = Entity::new(EntityKind::Coordinates, "-33.8688,151.2093", 0.72, "s");
        a.tag("country:AU");
        a.tag("au-state:NSW");
        a.add_evidence(
            Evidence::new(
                "search_engines",
                "Geocoded from search address: Sydney, Australia",
            )
            .with_attr("source_address", "Sydney, Australia"),
        );

        let mut b = Entity::new(EntityKind::Coordinates, "-33.8698,151.2083", 0.55, "s");
        b.tag("country:AU");
        b.tag("au-state:NSW");
        b.add_evidence(
            Evidence::new("geocode", "Geocoded \"Sydney, Australia\"")
                .with_attr("input_address", "Sydney, Australia")
                .with_attr("place_type", "city"),
        );

        let ents = vec![addr.clone(), a.clone(), b.clone()];
        assert!(
            au059_synergy_fix(&ents).is_none(),
            "a geocode of a search-snippet address is the snippet's datum, not an orthogonal class"
        );
        assert!(
            rule_au_059_cross_seed_geo_synergy(&RuleContext::new(&ents), "s", 0).is_empty()
        );
        assert_eq!(
            au_location_corroboration(&ents).map(|c| c.independent_classes),
            Some(1),
            "best_geo_class must read the geocoder leg's lineage too"
        );

        // Control 1: the geocoded Address came from a registry, so the leg is
        // Registry — a genuinely independent method beside the snippet.
        let mut reg = addr.clone();
        reg.evidence.clear();
        reg.add_evidence(Evidence::new("abn_lookup", "ABR registered address"));
        let fix = au059_synergy_fix(&[reg, a.clone(), b.clone()])
            .expect("a registry address geocoded + a search sighting are two classes");
        assert_eq!(fix.class_names.len(), 2);
        assert!(
            !fix.class_names
                .iter()
                .any(|c| c.eq_ignore_ascii_case("geocode")),
            "{:?}",
            fix.class_names
        );

        // Control 2: no resolvable Address in the slice (an operator seed): the
        // leg keeps its own Geocode class.
        assert!(
            au059_synergy_fix(&[a, b]).is_some(),
            "an untraceable geocoder input stays an independent Geocode leg"
        );
    }
