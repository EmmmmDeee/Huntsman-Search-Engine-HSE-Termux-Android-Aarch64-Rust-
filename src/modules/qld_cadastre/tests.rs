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
    fn max_timeout_covers_a_429_retry_path() {
        // Regression guard: a 429 used to degrade straight to a silent
        // Ok(empty) with no retry at all. `process` now sleeps a real
        // Retry-After (clamped to 5s max, see the retry_after_secs call
        // there) and retries once — the budget must comfortably cover two
        // requests plus that sleep, not just the original single call.
        let max_retry_after_sleep_secs = 5;
        assert!(
            QldCadastre.max_timeout_ms() > max_retry_after_sleep_secs * 1000,
            "budget {} leaves no headroom for a real request plus the {}s retry sleep",
            QldCadastre.max_timeout_ms(),
            max_retry_after_sleep_secs
        );
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
        let out = build_all_features("-27.4766,153.0166", &[f1, f2], false, "s");
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
    fn build_all_features_signals_truncation_when_over_max_features() {
        // Regression: a strata/stacked-cadastre point intersecting more than
        // MAX_FEATURES=8 polygons must not read as an exhaustive parcel list —
        // the primary Coordinates entity must be tagged `truncated` with the
        // true total.
        let features: Vec<Feature> = (0..9)
            .map(|i| Feature {
                attributes: attrs(&[
                    ("lotplan", &format!("{i}RP123456")),
                    ("locality", "NUNDAH"),
                ]),
            })
            .collect();
        let out = build_all_features("-27.4766,153.0166", &features, false, "s");
        let seed = out
            .iter()
            .find(|e| e.kind == EntityKind::Coordinates)
            .expect("primary Coordinates entity");
        assert!(seed.has_tag("truncated"), "seed must be tagged 'truncated'");
        let ev = seed.evidence.last().unwrap();
        assert_eq!(
            ev.attributes.get("total_features").map(String::as_str),
            Some("9"),
            "total_features must reflect all intersecting features, not just the capped 8"
        );
        assert_eq!(
            ev.attributes.get("features_capped").map(String::as_str),
            Some("true")
        );
    }

    #[test]
    fn build_all_features_under_cap_is_not_flagged() {
        let f1 = Feature {
            attributes: attrs(&[("lotplan", "12RP123456"), ("locality", "NUNDAH")]),
        };
        let out = build_all_features("-27.4766,153.0166", &[f1], false, "s");
        let seed = out
            .iter()
            .find(|e| e.kind == EntityKind::Coordinates)
            .expect("primary Coordinates entity");
        assert!(!seed.has_tag("truncated"), "must not flag when under cap");
    }

    #[test]
    fn build_all_features_signals_arcgis_exceeded_transfer_limit_even_under_client_cap() {
        // ArcGIS's own server-side maxRecordCount can truncate BEFORE this
        // module ever sees the surplus, even when the returned feature count
        // is itself below MAX_FEATURES — a distinct truncation source from the
        // client-side .take(MAX_FEATURES) cap.
        let f1 = Feature {
            attributes: attrs(&[("lotplan", "12RP123456"), ("locality", "NUNDAH")]),
        };
        let out = build_all_features("-27.4766,153.0166", &[f1], true, "s");
        let seed = out
            .iter()
            .find(|e| e.kind == EntityKind::Coordinates)
            .expect("primary Coordinates entity");
        assert!(seed.has_tag("truncated"));
        assert_eq!(
            seed.evidence
                .last()
                .unwrap()
                .attributes
                .get("arcgis_exceeded_transfer_limit")
                .map(String::as_str),
            Some("true")
        );
        // The client-side cap was NOT hit (1 feature <= MAX_FEATURES), so this
        // flag must be absent even though the seed is still truncated.
        assert!(
            !seed
                .evidence
                .last()
                .unwrap()
                .attributes
                .contains_key("features_capped")
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
        assert!(!r.exceeded_transfer_limit);
    }

    #[test]
    fn parse_response_reads_exceeded_transfer_limit_true() {
        let raw = r#"{"features":[],"exceededTransferLimit":true}"#;
        let r: QueryResp = serde_json::from_str(raw).unwrap();
        assert!(r.exceeded_transfer_limit);
    }

    #[test]
    fn parse_response_defaults_exceeded_transfer_limit_when_absent() {
        let raw = r#"{"features":[]}"#;
        let r: QueryResp = serde_json::from_str(raw).unwrap();
        assert!(!r.exceeded_transfer_limit);
    }
