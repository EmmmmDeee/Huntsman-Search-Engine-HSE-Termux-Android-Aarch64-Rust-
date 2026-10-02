//! OUI parsing and lookup rebuilt from the monolith's `util::oui`.

use crate::oui_ieee as ieee;

pub use crate::oui_ieee::registry_len;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceClass {
    Phone,
    Wearable,
    Headphones,
    Tablet,
    Laptop,
    Tv,
    Camera,
    Vehicle,
    IotHub,
    GameConsole,
    Router,
    Printer,
    Beacon,
    Randomized,
    Unknown,
    Unregistered,
}

impl DeviceClass {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Phone => "phone",
            Self::Wearable => "wearable",
            Self::Headphones => "headphones",
            Self::Tablet => "tablet",
            Self::Laptop => "laptop",
            Self::Tv => "tv",
            Self::Camera => "camera",
            Self::Vehicle => "vehicle",
            Self::IotHub => "iot_hub",
            Self::GameConsole => "game_console",
            Self::Router => "router",
            Self::Printer => "printer",
            Self::Beacon => "beacon",
            Self::Randomized => "randomized",
            Self::Unknown => "unknown",
            Self::Unregistered => "unregistered",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OuiInfo {
    pub vendor: &'static str,
    pub class: DeviceClass,
}

#[must_use]
pub fn is_locally_administered(mac: &str) -> Option<bool> {
    let hex: String = mac
        .chars()
        .filter(char::is_ascii_hexdigit)
        .take(2)
        .collect();
    if hex.len() != 2 {
        return None;
    }
    let first = u8::from_str_radix(&hex, 16).ok()?;
    Some(first & 0x02 != 0)
}

#[must_use]
pub fn is_multicast(mac: &str) -> Option<bool> {
    let hex: String = mac
        .chars()
        .filter(char::is_ascii_hexdigit)
        .take(2)
        .collect();
    if hex.len() != 2 {
        return None;
    }
    let first = u8::from_str_radix(&hex, 16).ok()?;
    Some(first & 0x01 != 0)
}

#[must_use]
pub fn classify_mac(mac: &str) -> Option<OuiInfo> {
    let hex: String = mac
        .chars()
        .filter(char::is_ascii_hexdigit)
        .take(6)
        .collect();
    if hex.len() != 6 {
        return None;
    }
    let first = u8::from_str_radix(&hex[0..2], 16).ok()?;
    if first & 0x02 != 0 {
        return Some(OuiInfo {
            vendor: "Randomized (private)",
            class: DeviceClass::Randomized,
        });
    }
    Some(lookup_prefix(&hex.to_ascii_uppercase()))
}

pub(crate) fn lookup_prefix(prefix: &str) -> OuiInfo {
    for &(table_prefix, vendor, class) in OUI_TABLE {
        if table_prefix == prefix {
            return OuiInfo { vendor, class };
        }
    }
    if let Ok(parsed) = u32::from_str_radix(prefix, 16) {
        if let Some(vendor) = ieee::vendor_for(parsed) {
            return OuiInfo {
                vendor,
                class: DeviceClass::Unknown,
            };
        }
    }
    OuiInfo {
        vendor: "Unknown",
        class: DeviceClass::Unregistered,
    }
}

#[rustfmt::skip]
const OUI_TABLE: &[(&str, &str, DeviceClass)] = &[
    ("3C0754", "Apple", DeviceClass::Phone),
    ("ACBC32", "Apple", DeviceClass::Phone),
    ("DCA904", "Apple", DeviceClass::Phone),
    ("F0DBE2", "Apple", DeviceClass::Phone),
    ("88665A", "Apple", DeviceClass::Phone),
    ("A4C361", "Apple", DeviceClass::Phone),
    ("DC2B61", "Apple", DeviceClass::Phone),
    ("E0AC8B", "Apple", DeviceClass::Phone),
    ("F0DCE2", "Apple", DeviceClass::Phone),
    ("F40F24", "Apple", DeviceClass::Phone),
    ("F49F54", "Apple", DeviceClass::Phone),
    ("E0CB1D", "Apple AirPods", DeviceClass::Headphones),
    ("64B0A6", "Apple AirPods", DeviceClass::Headphones),
    ("B8C75D", "Apple Beats", DeviceClass::Headphones),
    ("70DEE2", "Apple Watch", DeviceClass::Wearable),
    ("A4D1D2", "Apple Watch", DeviceClass::Wearable),
    ("0C74C2", "Apple TV", DeviceClass::Tv),
    ("60FACD", "Apple TV", DeviceClass::Tv),
    ("A8667F", "Apple MacBook", DeviceClass::Laptop),
    ("F0B479", "Apple MacBook", DeviceClass::Laptop),
    ("002566", "Samsung", DeviceClass::Phone),
    ("002738", "Samsung", DeviceClass::Phone),
    ("0CB319", "Samsung", DeviceClass::Phone),
    ("28987B", "Samsung", DeviceClass::Phone),
    ("382DD1", "Samsung", DeviceClass::Phone),
    ("5C0A5B", "Samsung", DeviceClass::Phone),
    ("90F1AA", "Samsung", DeviceClass::Phone),
    ("D052A8", "Samsung", DeviceClass::Phone),
    ("E89F80", "Samsung", DeviceClass::Phone),
    ("F87B7A", "Samsung", DeviceClass::Phone),
    ("002491", "Samsung TV", DeviceClass::Tv),
    ("089DF4", "Samsung TV", DeviceClass::Tv),
    ("88366C", "Samsung TV", DeviceClass::Tv),
    ("48137B", "Samsung Galaxy Watch", DeviceClass::Wearable),
    ("5439DF", "Samsung Galaxy Buds", DeviceClass::Headphones),
    ("3C5AB4", "Google Pixel", DeviceClass::Phone),
    ("D461DA", "Google Pixel", DeviceClass::Phone),
    ("F4F5D8", "Google", DeviceClass::IotHub),
    ("40A36B", "Google Nest", DeviceClass::IotHub),
    ("64166C", "Google Chromecast", DeviceClass::Tv),
    ("F4F5E8", "Google Chromecast", DeviceClass::Tv),
    ("D8E1CC", "Google Home", DeviceClass::IotHub),
    ("18B430", "Google Home", DeviceClass::IotHub),
    ("4CFCAA", "Tesla", DeviceClass::Vehicle),
    ("984FEE", "Tesla", DeviceClass::Vehicle),
    ("CC51B3", "Tesla", DeviceClass::Vehicle),
    ("DC4427", "Tesla", DeviceClass::Vehicle),
    ("4C71DD", "Hikvision", DeviceClass::Camera),
    ("584C19", "Hikvision", DeviceClass::Camera),
    ("BC9B5E", "Hikvision", DeviceClass::Camera),
    ("C0511C", "Hikvision", DeviceClass::Camera),
    ("3CEF8C", "Hikvision", DeviceClass::Camera),
    ("000B7C", "Dahua", DeviceClass::Camera),
    ("3C1B20", "Dahua", DeviceClass::Camera),
    ("00408C", "Axis Comms", DeviceClass::Camera),
    ("00408D", "Axis Comms", DeviceClass::Camera),
    ("ACCC8E", "Axis Comms", DeviceClass::Camera),
    ("B8A44F", "Axis Comms", DeviceClass::Camera),
    ("000E58", "Sonos", DeviceClass::IotHub),
    ("5CAAFD", "Sonos", DeviceClass::IotHub),
    ("B8E937", "Sonos", DeviceClass::IotHub),
    ("78282A", "Bose", DeviceClass::Headphones),
    ("E40B09", "Bose", DeviceClass::Headphones),
    ("00C04F", "Sony", DeviceClass::Tv),
    ("18594D", "Xiaomi", DeviceClass::Phone),
    ("286C07", "Xiaomi", DeviceClass::Phone),
    ("8CBEBE", "Xiaomi", DeviceClass::Phone),
    ("AC2DA9", "Xiaomi", DeviceClass::Phone),
    ("00E0FC", "Huawei", DeviceClass::Phone),
    ("80FB06", "Huawei", DeviceClass::Phone),
    ("0C37DC", "Huawei", DeviceClass::Phone),
    ("2C5BB8", "OnePlus", DeviceClass::Phone),
    ("48D343", "OnePlus", DeviceClass::Phone),
    ("001E45", "Nintendo", DeviceClass::GameConsole),
    ("E84ECE", "Nintendo Switch", DeviceClass::GameConsole),
    ("0050C2", "Sony PlayStation", DeviceClass::GameConsole),
    ("FCDBB3", "Sony PlayStation", DeviceClass::GameConsole),
    ("000D3A", "Microsoft Xbox", DeviceClass::GameConsole),
    ("7C1E52", "Microsoft Xbox", DeviceClass::GameConsole),
    ("00FC8B", "Amazon Echo", DeviceClass::IotHub),
    ("44650D", "Amazon Echo", DeviceClass::IotHub),
    ("F0D2F1", "Amazon Echo", DeviceClass::IotHub),
    ("AC63BE", "Amazon Echo", DeviceClass::IotHub),
    ("38F73D", "Amazon Echo", DeviceClass::IotHub),
    ("FCA667", "Amazon Ring", DeviceClass::Camera),
    ("000F4A", "Amazon Kindle", DeviceClass::Tablet),
    ("2C300A", "Wyze", DeviceClass::Camera),
    ("0C5101", "ASUS", DeviceClass::Router),
    ("2C56DC", "ASUS", DeviceClass::Router),
    ("FC8FC4", "ASUS", DeviceClass::Router),
    ("00904C", "Netgear", DeviceClass::Router),
    ("204E7F", "Netgear", DeviceClass::Router),
    ("9C3DCF", "Netgear", DeviceClass::Router),
    ("AC9E17", "Netgear", DeviceClass::Router),
    ("002584", "TP-Link", DeviceClass::Router),
    ("0C808A", "TP-Link", DeviceClass::Router),
    ("344293", "TP-Link", DeviceClass::Router),
    ("D8074D", "TP-Link", DeviceClass::Router),
    ("18A6F7", "TP-Link", DeviceClass::Router),
    ("D03972", "Estimote Beacon", DeviceClass::Beacon),
    ("E1F4B8", "Estimote Beacon", DeviceClass::Beacon),
    ("DC0C5C", "Kontakt Beacon", DeviceClass::Beacon),
    ("D8BC38", "Radius Networks", DeviceClass::Beacon),
    ("3CD92B", "HP", DeviceClass::Printer),
    ("9C8E99", "HP", DeviceClass::Printer),
    ("001E33", "Brother", DeviceClass::Printer),
    ("003C6E", "Canon", DeviceClass::Printer),
    ("EC2EB8", "Tile", DeviceClass::Beacon),
    ("DCEFCA", "Tile", DeviceClass::Beacon),
    ("F8B6E9", "Apple AirTag", DeviceClass::Beacon),
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_curated_examples() {
        assert_eq!(classify_mac("3C:07:54:AB:CD:EF").unwrap().vendor, "Apple");
        assert_eq!(
            classify_mac("F8:B6:E9:00:11:22").unwrap().class,
            DeviceClass::Beacon
        );
        assert_eq!(
            classify_mac("4C:FC:AA:11:22:33").unwrap().class,
            DeviceClass::Vehicle
        );
        assert_eq!(classify_mac("DC:44:27:AA:BB:CC").unwrap().vendor, "Tesla");
        assert_eq!(
            classify_mac("4C-71-DD-AB-CD-EF").unwrap().vendor,
            "Hikvision"
        );
        assert_eq!(
            classify_mac("e0cb1dabcdef").unwrap().class,
            DeviceClass::Headphones
        );
        assert_eq!(
            classify_mac("3c:5a:b4:00:11:22").unwrap().vendor,
            "Google Pixel"
        );
    }

    #[test]
    fn registry_tier_names_uncurated_real_ouis() {
        let info = classify_mac("00:11:22:33:44:55").unwrap();
        assert_ne!(info.vendor, "Unknown");
        assert_eq!(info.class, DeviceClass::Unknown);
    }

    #[test]
    fn unknown_and_malformed_inputs_are_distinguished() {
        let info = classify_mac("10:10:10:33:44:55").unwrap();
        assert_eq!(info.vendor, "Unknown");
        assert_eq!(info.class, DeviceClass::Unregistered);
        assert!(classify_mac("AA:BB").is_none());
        assert!(classify_mac("not-a-mac").is_none());
    }

    #[test]
    fn randomised_and_multicast_bits_are_read_directly() {
        for mac in [
            "02:00:00:00:00:01",
            "06:11:22:33:44:55",
            "DA:A1:19:AB:CD:EF",
        ] {
            let info = classify_mac(mac).unwrap();
            assert_eq!(info.class, DeviceClass::Randomized);
            assert_eq!(info.vendor, "Randomized (private)");
        }
        assert_eq!(is_locally_administered("3C:07:54:AB:CD:EF"), Some(false));
        assert_eq!(is_multicast("01:00:5e:00:00:fb"), Some(true));
        assert_eq!(is_multicast("3c:5a:b4:11:22:33"), Some(false));
        assert_eq!(is_multicast("zz"), None);
    }

    #[test]
    fn table_prefixes_are_well_formed() {
        for &(prefix, _, _) in OUI_TABLE {
            assert_eq!(prefix.len(), 6);
            assert!(
                prefix
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'A'..=b'F').contains(&b))
            );
        }
    }
}
