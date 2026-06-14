use super::*;

    #[test]
    fn classify_apple_phone_mac_returns_vendor_and_class() {
        let info = classify_mac("3C:07:54:AB:CD:EF").unwrap();
        assert_eq!(info.vendor, "Apple");
        assert_eq!(info.class, DeviceClass::Phone);
    }

    #[test]
    fn classify_apple_airtag() {
        let info = classify_mac("F8:B6:E9:00:11:22").unwrap();
        assert_eq!(info.vendor, "Apple AirTag");
        assert_eq!(info.class, DeviceClass::Beacon);
    }

    #[test]
    fn classify_tesla_vehicle() {
        let info = classify_mac("4C:FC:AA:11:22:33").unwrap();
        assert_eq!(info.vendor, "Tesla");
        assert_eq!(info.class, DeviceClass::Vehicle);
    }

    #[test]
    fn classify_tesla_dc4427_now_reachable() {
        // Regression: this OUI was mis-entered as a 7-char "DC44271", which could
        // never equal classify_mac's 6-hex extract, so a Tesla on the DC:44:27
        // prefix classified as Unregistered. The corrected "DC4427" resolves.
        let info = classify_mac("DC:44:27:AA:BB:CC").unwrap();
        assert_eq!(info.vendor, "Tesla");
        assert_eq!(info.class, DeviceClass::Vehicle);
    }

    #[test]
    fn classify_hikvision_camera() {
        let info = classify_mac("4C-71-DD-AB-CD-EF").unwrap();
        assert_eq!(info.vendor, "Hikvision");
        assert_eq!(info.class, DeviceClass::Camera);
    }

    #[test]
    fn classify_no_separator_format() {
        let info = classify_mac("e0cb1dabcdef").unwrap();
        assert_eq!(info.vendor, "Apple AirPods");
        assert_eq!(info.class, DeviceClass::Headphones);
    }

    #[test]
    fn classify_lowercase_input() {
        let info = classify_mac("3c:5a:b4:00:11:22").unwrap();
        assert_eq!(info.vendor, "Google Pixel");
    }

    #[test]
    fn classify_unknown_oui_returns_unregistered() {
        let info = classify_mac("00:11:22:33:44:55").unwrap();
        assert_eq!(info.vendor, "Unknown");
        assert_eq!(info.class, DeviceClass::Unregistered);
    }

    #[test]
    fn classify_short_input_returns_none() {
        assert!(classify_mac("AA:BB").is_none());
        assert!(classify_mac("").is_none());
    }

    #[test]
    fn classify_non_hex_input_returns_none() {
        assert!(classify_mac("not-a-mac").is_none());
    }

    #[test]
    fn device_class_as_str_round_trips() {
        for c in [
            DeviceClass::Phone,
            DeviceClass::Wearable,
            DeviceClass::Headphones,
            DeviceClass::Tv,
            DeviceClass::Camera,
            DeviceClass::Vehicle,
            DeviceClass::IotHub,
            DeviceClass::GameConsole,
            DeviceClass::Router,
            DeviceClass::Printer,
            DeviceClass::Beacon,
            DeviceClass::Unknown,
            DeviceClass::Unregistered,
        ] {
            // Just assert the discriminant has a non-empty label.
            assert!(!c.as_str().is_empty());
        }
    }

    #[test]
    fn classify_handles_six_char_prefix_only() {
        // Trailing chars beyond the 6-hex OUI must not affect lookup.
        let a = classify_mac("3C0754000000").unwrap();
        let b = classify_mac("3C:07:54:FF:FF:FF").unwrap();
        assert_eq!(a.vendor, b.vendor);
        assert_eq!(a.class, b.class);
    }

    #[test]
    fn oui_table_prefixes_are_well_formed() {
        // Every OUI is 24 bits — exactly 6 hex digits. `classify_mac` extracts
        // the first 6 hex chars of the input and uppercases them, then
        // `lookup_prefix` compares for *equality*, so any table prefix that
        // isn't exactly 6 uppercase-hex chars can never equal an extracted
        // prefix: it's unreachable dead data. This guard turns that silent
        // mis-entry into a test failure (it caught a 7-char "DC44271" Tesla
        // typo that classified no MAC at all).
        for &(p, vendor, _) in OUI_TABLE {
            assert_eq!(
                p.len(),
                6,
                "OUI prefix {p:?} ({vendor}) must be exactly 6 hex chars"
            );
            assert!(
                p.bytes()
                    .all(|b| b.is_ascii_digit() || (b'A'..=b'F').contains(&b)),
                "OUI prefix {p:?} ({vendor}) must be uppercase hex — \
                 lowercase/non-hex can't match classify_mac's normalised input"
            );
        }
    }

    #[test]
    fn table_has_no_obvious_duplicates_per_prefix() {
        // Defensive: a single prefix should have one canonical entry
        // (later entries shadow earlier ones in `lookup_prefix`).
        // Allow shadowing but flag suspiciously high counts.
        for &(p, _, _) in OUI_TABLE {
            let count = OUI_TABLE.iter().filter(|(q, _, _)| *q == p).count();
            assert!(
                count <= 2,
                "OUI prefix {p} appears {count} times — drop the duplicates",
            );
        }
    }
