use super::*;

    #[test]
    fn build_entity_emits_region_with_carrier_evidence() {
        let r = NvResp {
            valid: true,
            country_code: Some("AU".into()),
            country_name: Some("Australia".into()),
            location: Some("Queensland".into()),
            carrier: Some("Telstra".into()),
            line_type: Some("mobile".into()),
            international_format: Some("+61400000000".into()),
        };
        let e = build_entity(&r, "scan").unwrap();
        assert_eq!(e.kind, EntityKind::Address);
        assert_eq!(e.value, "Queensland, Australia");
        assert!(
            e.has_tag("phone-region") && e.has_tag("carrier-known") && e.has_tag("line:mobile")
        );
        let attr = |k: &str| e.evidence[0].attributes.get(k).cloned().unwrap_or_default();
        assert_eq!(attr("carrier"), "Telstra");
        assert_eq!(attr("line_type"), "mobile");
        assert_eq!(attr("country_code"), "AU");
    }

    #[test]
    fn invalid_number_yields_nothing() {
        let r = NvResp {
            valid: false,
            ..Default::default()
        };
        assert!(build_entity(&r, "scan").is_none());
    }

    #[test]
    fn country_only_still_geolocates() {
        let r = NvResp {
            valid: true,
            country_name: Some("Australia".into()),
            ..Default::default()
        };
        assert_eq!(build_entity(&r, "scan").unwrap().value, "Australia");
    }

    #[test]
    fn metadata_is_keygated_phone() {
        let m = NumVerify;
        assert_eq!(m.cost(), ModuleCost::KeyGated);
        assert_eq!(m.category(), ModuleCategory::Phone);
        assert!(m.accepts(&Target::new(TargetKind::Phone, "+61400000000")));
        assert!(!m.accepts(&Target::new(TargetKind::Email, "a@b.com")));
    }

    #[test]
    fn module_metadata_full() {
        let m = NumVerify;
        assert_eq!(m.name(), "numverify");
        assert!(!m.description().is_empty());
        assert_eq!(m.max_timeout_ms(), 8_000);
        assert!(!m.attack_techniques().is_empty());
        assert!(m.produces().contains(&EntityKind::Address));
    }

    #[test]
    fn build_entity_line_type_tag() {
        for lt in ["mobile", "landline", "voip"] {
            let r = NvResp {
                valid: true,
                country_name: Some("Australia".into()),
                location: Some("Queensland".into()),
                line_type: Some(lt.to_string()),
                ..Default::default()
            };
            let e = build_entity(&r, "s").unwrap();
            assert!(e.has_tag(&format!("line:{lt}")), "missing line:{lt} tag");
        }
    }
