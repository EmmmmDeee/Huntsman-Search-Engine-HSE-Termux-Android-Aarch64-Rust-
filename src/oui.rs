//! OUI parsing and lookup. The manufacturer is always the IEEE MA-L registry's assignee
//! (`oui_ieee`); the curated table below adds only a device class, and only for prefixes the
//! registry assigns to the brand the row expects, which a test checks against the registry.

use crate::oui_ieee as ieee;

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
    /// The IEEE MA-L assignee, or a placeholder where there is none: see [`Self::manufacturer`].
    pub vendor: &'static str,
    pub class: DeviceClass,
}

/// The assignee the MA-L registry gives a block the IEEE Registration Authority sub-assigns
/// (MA-M, MA-S, IAB): its real holder is not in the MA-L registry.
const IEEE_RA: &str = "IEEE Registration Authority";

impl OuiInfo {
    /// The manufacturer the IEEE MA-L registry names for the address: `None` for a randomised
    /// address, an unregistered prefix, or a block the IEEE Registration Authority sub-assigns.
    #[must_use]
    pub fn manufacturer(&self) -> Option<&'static str> {
        match self.class {
            DeviceClass::Randomized | DeviceClass::Unregistered => None,
            _ => (self.vendor != IEEE_RA).then_some(self.vendor),
        }
    }
}

/// The six octets of a MAC address written as 12 hex digits, bare or separated by `:`, `-` or
/// `.`. Anything else, such as text that merely contains hex letters, is not an address.
fn octets(mac: &str) -> Option<[u8; 6]> {
    let digits = mac
        .bytes()
        .filter(|byte| !matches!(byte, b':' | b'-' | b'.'))
        .collect::<Vec<u8>>();
    if digits.len() != 12 || !digits.iter().all(u8::is_ascii_hexdigit) {
        return None;
    }
    let mut out = [0u8; 6];
    for (octet, pair) in out.iter_mut().zip(digits.chunks(2)) {
        *octet = u8::from_str_radix(std::str::from_utf8(pair).ok()?, 16).ok()?;
    }
    Some(out)
}

/// Whether the address is locally administered (randomised): the U/L bit of its first octet.
#[must_use]
pub fn is_locally_administered(mac: &str) -> Option<bool> {
    octets(mac).map(|octets| octets[0] & 0x02 != 0)
}

/// Whether the address is a group (multicast or broadcast) address: the I/G bit of its first
/// octet.
#[must_use]
pub fn is_multicast(mac: &str) -> Option<bool> {
    octets(mac).map(|octets| octets[0] & 0x01 != 0)
}

#[must_use]
pub fn classify_mac(mac: &str) -> Option<OuiInfo> {
    let octets = octets(mac)?;
    if octets[0] & 0x02 != 0 {
        return Some(OuiInfo {
            vendor: "Randomized (private)",
            class: DeviceClass::Randomized,
        });
    }
    Some(lookup_oui([octets[0], octets[1], octets[2]]))
}

/// An OUI as the registry keys it.
fn registry_key(oui: [u8; 3]) -> u32 {
    u32::from_be_bytes([0, oui[0], oui[1], oui[2]])
}

fn lookup_oui(oui: [u8; 3]) -> OuiInfo {
    match ieee::vendor_for(registry_key(oui)) {
        Some(vendor) => OuiInfo {
            vendor,
            class: OUI_TABLE
                .iter()
                .find(|row| row.0 == oui)
                .map_or(DeviceClass::Unknown, |row| row.2),
        },
        None => OuiInfo {
            vendor: "Unknown",
            class: DeviceClass::Unregistered,
        },
    }
}

/// Device classes for prefixes the registry assigns to the brand named, which is the assignee the
/// row expects: `every_curated_row_is_assigned_to_its_brand` holds each row to the registry.
#[rustfmt::skip]
const OUI_TABLE: &[([u8; 3], &str, DeviceClass)] = &[
    ([0x3C, 0x07, 0x54], "Apple", DeviceClass::Phone),
    ([0xAC, 0xBC, 0x32], "Apple", DeviceClass::Phone),
    ([0xDC, 0xA9, 0x04], "Apple", DeviceClass::Phone),
    ([0xF0, 0xDB, 0xE2], "Apple", DeviceClass::Phone),
    ([0x88, 0x66, 0x5A], "Apple", DeviceClass::Phone),
    ([0xA4, 0xC3, 0x61], "Apple", DeviceClass::Phone),
    ([0xDC, 0x2B, 0x61], "Apple", DeviceClass::Phone),
    ([0xF0, 0xDC, 0xE2], "Apple", DeviceClass::Phone),
    ([0xF4, 0x0F, 0x24], "Apple", DeviceClass::Phone),
    ([0x64, 0xB0, 0xA6], "Apple AirPods", DeviceClass::Headphones),
    ([0xB8, 0xC7, 0x5D], "Apple Beats", DeviceClass::Headphones),
    ([0x70, 0xDE, 0xE2], "Apple Watch", DeviceClass::Wearable),
    ([0xA4, 0xD1, 0xD2], "Apple Watch", DeviceClass::Wearable),
    ([0x0C, 0x74, 0xC2], "Apple TV", DeviceClass::Tv),
    ([0x60, 0xFA, 0xCD], "Apple TV", DeviceClass::Tv),
    ([0xA8, 0x66, 0x7F], "Apple MacBook", DeviceClass::Laptop),
    ([0xF0, 0xB4, 0x79], "Apple MacBook", DeviceClass::Laptop),
    ([0x00, 0x25, 0x66], "Samsung", DeviceClass::Phone),
    ([0x0C, 0xB3, 0x19], "Samsung", DeviceClass::Phone),
    ([0x28, 0x98, 0x7B], "Samsung", DeviceClass::Phone),
    ([0x38, 0x2D, 0xD1], "Samsung", DeviceClass::Phone),
    ([0x5C, 0x0A, 0x5B], "Samsung", DeviceClass::Phone),
    ([0x90, 0xF1, 0xAA], "Samsung", DeviceClass::Phone),
    ([0x00, 0x24, 0x91], "Samsung TV", DeviceClass::Tv),
    ([0x3C, 0x5A, 0xB4], "Google Pixel", DeviceClass::Phone),
    ([0xF4, 0xF5, 0xD8], "Google", DeviceClass::IotHub),
    ([0xF4, 0xF5, 0xE8], "Google Chromecast", DeviceClass::Tv),
    ([0x18, 0xB4, 0x30], "Nest Labs", DeviceClass::IotHub),
    ([0x4C, 0xFC, 0xAA], "Tesla", DeviceClass::Vehicle),
    ([0xBC, 0x9B, 0x5E], "Hikvision", DeviceClass::Camera),
    ([0x00, 0x40, 0x8C], "Axis Comms", DeviceClass::Camera),
    ([0xAC, 0xCC, 0x8E], "Axis Comms", DeviceClass::Camera),
    ([0xB8, 0xA4, 0x4F], "Axis Comms", DeviceClass::Camera),
    ([0x00, 0x0E, 0x58], "Sonos", DeviceClass::IotHub),
    ([0x5C, 0xAA, 0xFD], "Sonos", DeviceClass::IotHub),
    ([0xB8, 0xE9, 0x37], "Sonos", DeviceClass::IotHub),
    ([0x28, 0x6C, 0x07], "Xiaomi", DeviceClass::Phone),
    ([0x8C, 0xBE, 0xBE], "Xiaomi", DeviceClass::Phone),
    ([0x00, 0xE0, 0xFC], "Huawei", DeviceClass::Phone),
    ([0x80, 0xFB, 0x06], "Huawei", DeviceClass::Phone),
    ([0x0C, 0x37, 0xDC], "Huawei", DeviceClass::Phone),
    ([0x2C, 0x5B, 0xB8], "OPPO", DeviceClass::Phone),
    ([0xE8, 0x4E, 0xCE], "Nintendo Switch", DeviceClass::GameConsole),
    ([0x00, 0x0D, 0x3A], "Microsoft Xbox", DeviceClass::GameConsole),
    ([0x7C, 0x1E, 0x52], "Microsoft Xbox", DeviceClass::GameConsole),
    ([0x00, 0xFC, 0x8B], "Amazon Echo", DeviceClass::IotHub),
    ([0x44, 0x65, 0x0D], "Amazon Echo", DeviceClass::IotHub),
    ([0xF0, 0xD2, 0xF1], "Amazon Echo", DeviceClass::IotHub),
    ([0xAC, 0x63, 0xBE], "Amazon Echo", DeviceClass::IotHub),
    ([0x38, 0xF7, 0x3D], "Amazon Echo", DeviceClass::IotHub),
    ([0xFC, 0xA6, 0x67], "Amazon Ring", DeviceClass::Camera),
    ([0x2C, 0x56, 0xDC], "ASUS", DeviceClass::Router),
    ([0x20, 0x4E, 0x7F], "Netgear", DeviceClass::Router),
    ([0x9C, 0x3D, 0xCF], "Netgear", DeviceClass::Router),
    ([0x18, 0xA6, 0xF7], "TP-Link", DeviceClass::Router),
    ([0x3C, 0xD9, 0x2B], "Hewlett Packard", DeviceClass::Printer),
    ([0x9C, 0x8E, 0x99], "Hewlett Packard", DeviceClass::Printer),
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_manufacturer_is_the_registry_assignee_and_the_table_adds_a_class() {
        let apple = classify_mac("3C:07:54:AB:CD:EF").unwrap();
        assert_eq!(apple.vendor, "Apple, Inc.");
        assert_eq!(apple.class, DeviceClass::Phone);
        assert_eq!(
            classify_mac("4C:FC:AA:11:22:33").unwrap().class,
            DeviceClass::Vehicle
        );
        let hikvision = classify_mac("BC-9B-5E-AB-CD-EF").unwrap();
        assert!(
            hikvision.vendor.contains("Hikvision"),
            "{}",
            hikvision.vendor
        );
        assert_eq!(hikvision.class, DeviceClass::Camera);
        assert_eq!(
            classify_mac("64b0a6abcdef").unwrap().class,
            DeviceClass::Headphones
        );
        assert_eq!(
            classify_mac("3c:5a:b4:00:11:22").unwrap().vendor,
            "Google, Inc."
        );
        // A prefix the old table gave to Apple belongs to Samsung in the registry.
        assert!(
            classify_mac("F4:9F:54:00:11:22")
                .unwrap()
                .vendor
                .starts_with("Samsung"),
        );
    }

    #[test]
    fn every_curated_row_is_assigned_to_its_brand() {
        let token = |text: &str| {
            text.chars()
                .filter(char::is_ascii_alphanumeric)
                .collect::<String>()
                .to_ascii_lowercase()
        };
        let mut seen = std::collections::BTreeSet::new();
        for &(oui, brand, _) in OUI_TABLE {
            let prefix = registry_key(oui);
            assert!(seen.insert(oui), "{prefix:06X} is listed twice");
            assert_eq!(
                oui[0] & 0x03,
                0,
                "{prefix:06X} is not a universal unicast OUI"
            );
            let assignee = ieee::vendor_for(prefix)
                .unwrap_or_else(|| panic!("{prefix:06X} is not an IEEE MA-L assignment"));
            assert_ne!(assignee, IEEE_RA, "{prefix:06X}");
            let first = token(brand.split_whitespace().next().unwrap_or_default());
            assert!(
                !first.is_empty() && token(assignee).contains(&first),
                "{prefix:06X}: the table expects {brand:?}, the registry names {assignee:?}"
            );
        }
    }

    #[test]
    fn registry_tier_names_uncurated_real_ouis() {
        let info = classify_mac("00:11:22:33:44:55").unwrap();
        assert_ne!(info.vendor, "Unknown");
        assert_eq!(info.class, DeviceClass::Unknown);
        assert_eq!(info.manufacturer(), Some(info.vendor));
    }

    #[test]
    fn unknown_and_malformed_inputs_are_distinguished() {
        let info = classify_mac("10:10:10:33:44:55").unwrap();
        assert_eq!(info.vendor, "Unknown");
        assert_eq!(info.class, DeviceClass::Unregistered);
        assert_eq!(info.manufacturer(), None);
        for malformed in [
            "AA:BB",
            "not-a-mac",
            "Cafe Babe",
            "deadbeef",
            "3C",
            "3C:07:54:AB:CD:EF:01",
        ] {
            assert!(classify_mac(malformed).is_none(), "{malformed}");
            assert!(is_locally_administered(malformed).is_none(), "{malformed}");
            assert!(is_multicast(malformed).is_none(), "{malformed}");
        }
    }

    #[test]
    fn a_registration_authority_block_names_no_manufacturer() {
        let info = classify_mac("00:50:C2:00:11:22").unwrap();
        assert_eq!(info.vendor, IEEE_RA);
        assert_eq!(info.manufacturer(), None);
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
            assert_eq!(info.manufacturer(), None);
        }
        assert_eq!(is_locally_administered("3C:07:54:AB:CD:EF"), Some(false));
        assert_eq!(is_multicast("01:00:5e:00:00:fb"), Some(true));
        assert_eq!(is_multicast("3c:5a:b4:11:22:33"), Some(false));
        assert_eq!(is_multicast("zz"), None);
    }
}
