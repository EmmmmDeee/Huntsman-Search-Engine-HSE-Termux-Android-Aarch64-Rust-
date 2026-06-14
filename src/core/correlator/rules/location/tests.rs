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
        let out = rule_au_059_cross_seed_geo_synergy(&ents, "s", 0);
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
        let out = rule_au_059_cross_seed_geo_synergy(&ents, "s", 0);
        assert!(out.is_empty(), "same source class must not assert synergy");
    }

    #[test]
    fn three_classes_is_high_severity() {
        let ents = vec![
            au_coord("-37.8136,144.9631", 0.80, "abn_lookup", "VIC"),
            au_coord("-37.8140,144.9640", 0.70, "exif_geo", "VIC"),
            au_coord("-37.8150,144.9650", 0.65, "wigle", "VIC"),
        ];
        let out = rule_au_059_cross_seed_geo_synergy(&ents, "s", 0);
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
        let out = rule_au_059_cross_seed_geo_synergy(&ents, "s", 0);
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
