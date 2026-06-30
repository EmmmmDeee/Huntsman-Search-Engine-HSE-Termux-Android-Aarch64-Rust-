use super::*;
    use crate::core::module::ModuleCost;

    fn attrs(pairs: &[(&str, &str)]) -> HashMap<String, Value> {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_string(), Value::String((*v).to_string())))
            .collect()
    }

    #[test]
    fn accepts_coordinates_only() {
        let m = QldCadastre;
        assert!(m.accepts(&Target::new(TargetKind::Coordinates, "-27.47,153.02")));
        assert!(!m.accepts(&Target::new(TargetKind::Address, "Brisbane")));
        assert!(!m.accepts(&Target::new(TargetKind::MacAddress, "aa:bb:cc:dd:ee:ff")));
    }

    #[test]
    fn module_metadata() {
        let m = QldCadastre;
        assert_eq!(m.name(), "qld_cadastre");
        assert_eq!(m.priority(), 18);
        assert!(matches!(m.cost(), ModuleCost::Free));
        assert_eq!(m.category(), ModuleCategory::Geo);
        assert!(m.produces().contains(&EntityKind::Coordinates));
        assert!(m.produces().contains(&EntityKind::Address));
        // Geo category yields a non-empty ATT&CK Reconnaissance mapping (guarded
        // in tests/architecture.rs); confirm the default propagates here too.
        assert!(!m.attack_techniques().is_empty());
    }

    #[test]
    fn build_query_url_targets_layer_4_point_in_qld() {
        let url = build_query_url(-27.4766, 153.0166);
        assert!(url.contains("spatial-gis.information.qld.gov.au"));
        assert!(url.contains("/LandParcelPropertyFramework/MapServer/4/query"));
        assert!(url.contains("geometryType=esriGeometryPoint"));
        assert!(url.contains("inSR=4326"));
        // ArcGIS point geometry is x,y = lon,lat (not lat,lon).
        assert!(url.contains("geometry=153.016600,-27.476600"));
        assert!(url.contains("f=json"));
    }

    #[test]
    fn build_entities_emits_coordinates_and_address_with_parcel_evidence() {
        let a = attrs(&[
            ("lot", "12"),
            ("plan", "RP123456"),
            ("lotplan", "12RP123456"),
            ("locality", "NUNDAH"),
            ("shire_name", "BRISBANE CITY"),
            ("tenure", "Freehold"),
            ("parcel_typ", "Lot Type Parcel"),
        ]);
        let out = build_entities("-27.4766,153.0166", &a, "s");
        assert_eq!(out.len(), 2);

        let coords = &out[0];
        assert_eq!(coords.kind, EntityKind::Coordinates);
        assert!(coords.has_tag("qld_cadastre"));
        assert!(coords.has_tag("au-state:QLD"));
        assert!(coords.has_tag("lotplan:12RP123456"));
        let ev = &coords.evidence[0];
        assert_eq!(
            ev.attributes.get("lotplan").map(String::as_str),
            Some("12RP123456")
        );
        assert_eq!(
            ev.attributes.get("local_authority").map(String::as_str),
            Some("BRISBANE CITY")
        );
        assert_eq!(
            ev.attributes.get("tenure").map(String::as_str),
            Some("Freehold")
        );

        let addr = &out[1];
        assert_eq!(addr.kind, EntityKind::Address);
        assert_eq!(addr.value, "NUNDAH, Queensland");
        assert!(addr.has_tag("cadastre-derived"));
        assert!(addr.has_tag("lotplan:12RP123456"));
    }

    #[test]
    fn build_entities_derives_lotplan_from_lot_and_plan() {
        let a = attrs(&[
            ("lot", "5"),
            ("plan", "SP181800"),
            ("locality", "TENERIFFE"),
        ]);
        let out = build_entities("-27.45,153.04", &a, "s");
        assert!(out[0].has_tag("lotplan:5SP181800"));
    }

    #[test]
    fn build_all_features_emits_every_parcel_deduping_the_shared_coordinate() {
        // Two intersecting parcels at one query point (a boundary / strata hit):
        // every parcel must surface, not just the first (the no-omission policy).
        let f1 = Feature {
            attributes: attrs(&[("lotplan", "12RP123456"), ("locality", "NUNDAH")]),
        };
        let f2 = Feature {
            attributes: attrs(&[("lotplan", "13RP123456"), ("locality", "NUNDAH")]),
        };
        let out = build_all_features("-27.4766,153.0166", &[f1, f2], "s");
        // BOTH parcels' lot/plans must survive (carried as `lotplan:` tags on the
        // per-parcel entities; the engine's value-merge later unions them). The
        // previous `.next()`-only path dropped the second parcel entirely.
        assert!(
            out.iter().any(|e| e.has_tag("lotplan:12RP123456")),
            "first parcel must be emitted"
        );
        assert!(
            out.iter().any(|e| e.has_tag("lotplan:13RP123456")),
            "second parcel must be emitted (previously dropped)"
        );
    }

    #[test]
    fn build_entities_empty_when_no_parcel_or_locality() {
        let a = attrs(&[("tenure", "Freehold")]);
        assert!(build_entities("-27.45,153.04", &a, "s").is_empty());
    }

    #[test]
    fn attr_handles_strings_numbers_blanks_and_nulls() {
        let mut a: HashMap<String, Value> = HashMap::new();
        a.insert("s".into(), Value::String("  hi  ".into()));
        a.insert("n".into(), Value::from(42));
        a.insert("blank".into(), Value::String("   ".into()));
        a.insert("nul".into(), Value::Null);
        assert_eq!(attr(&a, "s").as_deref(), Some("hi"));
        assert_eq!(attr(&a, "n").as_deref(), Some("42"));
        assert_eq!(attr(&a, "blank"), None);
        assert_eq!(attr(&a, "nul"), None);
        assert_eq!(attr(&a, "missing"), None);
    }

    #[test]
    fn parse_response_extracts_attributes() {
        let raw = r#"{"features":[{"attributes":{"lot":"12","plan":"RP123456",
            "lotplan":"12RP123456","locality":"NUNDAH"}}],"exceededTransferLimit":false}"#;
        let r: QueryResp = serde_json::from_str(raw).unwrap();
        assert_eq!(r.features.len(), 1);
        assert_eq!(
            r.features[0].attributes.get("lotplan"),
            Some(&Value::String("12RP123456".into()))
        );
    }
