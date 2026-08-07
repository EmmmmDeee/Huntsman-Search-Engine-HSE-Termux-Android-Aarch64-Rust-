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
        assert_eq!(geo_source_class("au_people"), GeoSourceClass::Directory);
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
            au_coord("-31.9523,115.8613", 0.85, "au_electoral", "WA"),
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

    #[test]
    fn distinct_geo_sources_counts_only_the_sources_that_located_the_entity() {
        // One camera's GPS fix, on an entity a breach corpus also happens to
        // corroborate. `hibp` corroborates the ENTITY but never located it, so
        // the geo multi-source gate must see ONE source, not two.
        //
        // Before the anchoring filter this returned 2, and AU-052/AU-053's
        // `>= 2` gate then reported a High "tight fix on a residence/base" off
        // a single device's own track — exactly what that gate's doc says it
        // exists to prevent.
        let mut e = au_coord("-33.8688,151.2093", 0.80, "exif_geo", "NSW");
        e.add_evidence(Evidence::new("hibp", "breach record"));

        assert_eq!(
            e.corroborating_sources().len(),
            2,
            "both sources corroborate the entity — this is what the unfiltered \
             count used to see"
        );

        let parsed = vec![(&e, (-33.8688_f64, 151.2093_f64))];
        assert_eq!(
            distinct_geo_sources(&parsed),
            1,
            "only `exif_geo` is an anchoring geo source; `hibp` located nothing"
        );

        // And the anchoring source alone still counts, so the filter cannot
        // zero out a legitimate entity.
        let only_geo = au_coord("-33.8688,151.2093", 0.80, "exif_geo", "NSW");
        let parsed_one = vec![(&only_geo, (-33.8688_f64, 151.2093_f64))];
        assert_eq!(distinct_geo_sources(&parsed_one), 1);
    }
