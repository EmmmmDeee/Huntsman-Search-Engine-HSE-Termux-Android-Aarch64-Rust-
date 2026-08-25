use super::*;

    #[test]
    fn histogram_us_eastern() {
        // Activity at UTC hours 13-23 = 08:00-18:00 at UTC-5 (US Eastern)
        let hours: Vec<u32> = vec![13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23];
        let tz = infer_timezone(&hours).expect("should succeed");
        assert_eq!(tz.utc_offset, -5);
        assert!(tz.region.contains("Eastern"));
    }

    #[test]
    fn too_few_timestamps_returns_none() {
        let hours = vec![10, 11, 12];
        assert!(infer_timezone(&hours).is_none());
    }

    #[test]
    fn uniform_distribution_returns_none() {
        // Activity evenly spread = no timezone signal
        let hours: Vec<u32> = (0..24).collect();
        assert!(infer_timezone(&hours).is_none());
    }

    #[test]
    fn offset_to_region_coverage() {
        assert!(offset_to_region(10).contains("Australia"));
        assert!(offset_to_region(0).contains("UK"));
        assert!(offset_to_region(-5).contains("Eastern"));
    }

    #[test]
    fn offset_to_region_recognises_utc_plus_11_as_australia_eastern() {
        // AEDT (Australian eastern DAYLIGHT time, UTC+11) — infer_timezone can
        // legitimately resolve to +11 in summer, and tag_timezone_jurisdiction
        // already treats 10 and 11 identically as AU-eastern evidence.
        // offset_to_region used to fall through to "Unknown timezone region"
        // for +11, so an AEDT-clustered subject got tagged country:AU with an
        // unreadable Address value AND no Coordinates entity at all, since
        // city_coords can't resolve "Unknown timezone region" to any city.
        assert_eq!(offset_to_region(11), offset_to_region(10));
        assert!(offset_to_region(11).contains("Australia"));
    }

    #[test]
    fn histogram_australia_eastern_daylight_offset_11() {
        // Activity at UTC hours 21,22,23,0..10 = the full 08:00-22:00 local
        // window at UTC+11 (AEDT) — the wraparound analogue of
        // histogram_us_eastern above. A shorter, non-full-width cluster here
        // ties across several adjacent offsets (an 11-hour run has 3 hours of
        // slack against the 14-hour window, so offsets -12..-10 and 11..12
        // all match it fully, and first-wins on ties picks -12) — using the
        // complete 14-hour window makes offset 11 the unique, un-tied winner.
        let hours: Vec<u32> = vec![21, 22, 23, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
        let tz = infer_timezone(&hours).expect("should succeed");
        assert_eq!(tz.utc_offset, 11);
        assert!(tz.region.contains("Australia"));
    }

    #[tokio::test]
    async fn module_metadata() {
        let m = BreachTimezone;
        assert!(m.is_passive());
        assert!(m.accepts(&Target::new(TargetKind::Email, "x@y.com")));
        assert!(!m.accepts(&Target::new(TargetKind::Domain, "y.com")));
    }

    #[test]
    fn offset_to_region_europe_and_asia_pacific() {
        assert!(offset_to_region(1).contains("Europe"));
        assert!(offset_to_region(10).contains("Australia"));
        assert!(offset_to_region(9).contains("Japan"));
        assert!(offset_to_region(8).contains("China"));
    }

    #[test]
    fn utc_plus_8_gets_no_australian_jurisdiction_tag() {
        // UTC+8 is dominated by China/Singapore/Malaysia/Taiwan; Perth (WA) is a
        // tiny minority a bare hour-offset cannot single out. The old
        // `8 if region.contains("Perth")` guard was a tautology (the region
        // string ALWAYS contains "Perth"), so every UTC+8 subject was falsely
        // stamped country:AU / au-state:WA. It must not be.
        let mut e = Entity::new(EntityKind::Address, offset_to_region(8), 0.5, "scan");
        tag_timezone_jurisdiction(&mut e, 8, offset_to_region(8));
        assert!(!e.has_tag("country:AU"), "UTC+8 must not be tagged country:AU");
        assert!(!e.has_tag("au-state:WA"), "UTC+8 must not be tagged au-state:WA");
    }

    #[test]
    fn utc_plus_9_gets_no_australian_jurisdiction_tag() {
        // The old `9 if region.contains("Darwin")` arm was dead (region(9) is
        // Japan/Korea) AND wrong (Darwin is UTC+9:30). No AU claim for UTC+9.
        let mut e = Entity::new(EntityKind::Address, offset_to_region(9), 0.5, "scan");
        tag_timezone_jurisdiction(&mut e, 9, offset_to_region(9));
        assert!(!e.has_tag("country:AU"), "UTC+9 must not be tagged country:AU");
        assert!(!e.has_tag("au-state:NT"), "UTC+9 must not be tagged au-state:NT");
    }

    #[test]
    fn utc_plus_10_still_tags_australia_eastern() {
        let mut e = Entity::new(EntityKind::Address, offset_to_region(10), 0.5, "scan");
        tag_timezone_jurisdiction(&mut e, 10, offset_to_region(10));
        assert!(e.has_tag("country:AU"), "UTC+10 must remain country:AU");
    }

    #[test]
    fn utc_plus_11_still_tags_australia_eastern() {
        let mut e = Entity::new(EntityKind::Address, offset_to_region(11), 0.5, "scan");
        tag_timezone_jurisdiction(&mut e, 11, offset_to_region(11));
        assert!(
            e.has_tag("country:AU"),
            "UTC+11 (AEDT) must tag country:AU, same as UTC+10 (AEST)"
        );
    }

    #[test]
    fn coordinates_entity_carries_the_same_jurisdiction_tag_as_the_address_entity() {
        // Regression: entities_for_inference used to build the Coordinates
        // entity without ever calling tag_timezone_jurisdiction on it, so a
        // subject whose timezone resolved to an AU offset got an Address
        // entity tagged country:AU but a sibling Coordinates entity with no
        // jurisdiction tag at all — even though AU-056's coord_state() reads
        // au-state:/country: tags off Coordinates entities specifically.
        let tz = TimezoneInference {
            utc_offset: 10,
            region: offset_to_region(10),
            confidence: 0.5,
            concentration: 0.9,
        };
        let entities = entities_for_inference(&tz, 10, "scan");
        let addr = entities
            .iter()
            .find(|e| e.kind == EntityKind::Address)
            .expect("Address entity must be present");
        let coords = entities
            .iter()
            .find(|e| e.kind == EntityKind::Coordinates)
            .expect("Coordinates entity must be present for a resolvable AU region");
        assert!(addr.has_tag("country:AU"));
        assert!(
            coords.has_tag("country:AU"),
            "Coordinates entity must carry the same jurisdiction tag as the Address entity"
        );
    }

    #[test]
    fn utc_plus_12_still_tags_new_zealand() {
        let mut e = Entity::new(EntityKind::Address, offset_to_region(12), 0.5, "scan");
        tag_timezone_jurisdiction(&mut e, 12, offset_to_region(12));
        assert!(e.has_tag("country:NZ"), "UTC+12 must remain country:NZ");
    }

    #[test]
    fn extract_hours_from_value_parses_embedded_timestamps() {
        // Unix timestamp 1618308000 = 2021-04-13 10:00:00 UTC → hour 10
        let hours = extract_hours_from_value("event:1618308000:end");
        assert!(
            hours.contains(&10),
            "should extract UTC hour 10 from embedded timestamp: {hours:?}"
        );
    }

    #[test]
    fn module_metadata_shape() {
        let m = BreachTimezone;
        assert_eq!(m.name(), "breach_timezone");
        assert!(!m.description().is_empty());
        assert_eq!(m.priority(), 7);
        assert!(m.produces().contains(&EntityKind::Address));
    }
