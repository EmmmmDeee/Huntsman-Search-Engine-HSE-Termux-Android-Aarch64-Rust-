//! IEEE OUI (Organisationally Unique Identifier) classifier for
//! consumer device fingerprinting.
//!
//! The first 24 bits of a MAC address (the OUI) identify the
//! manufacturer. WireTapper, AntennaWizard, and similar OSINT tools
//! use this to label otherwise anonymous BSSID/Bluetooth-beacon
//! observations as "Apple AirPods", "Tesla Model 3", "Hikvision
//! IP-camera", etc.
//!
//! The full IEEE registry is ~7 MB and includes ~36,000 prefixes,
//! the bulk of which are enterprise network gear of no OSINT
//! interest. HSE embeds a curated subset (~120 entries) focused on
//! consumer devices most commonly surfaced by WiGLE Bluetooth +
//! WiFi observations — phones, wearables, IoT, vehicles, cameras,
//! TVs. The classifier returns both the vendor and a coarse device
//! type so callers can tag entities at the right semantic level.

/// Coarse device categories surfaced from OUI classification.
/// `Unknown` covers OUIs we recognise as a vendor but can't bucket
/// into a device type; `Unregistered` is for prefixes not in our
/// curated set at all.
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
    /// A locally-administered (randomized / private) address — NOT a
    /// manufacturer-assigned identity. Modern phones (iOS 8+, Android 10+),
    /// AirTags/SmartTags, and other privacy-hardened devices rotate these
    /// (often every ~15 min), so the address is ephemeral and its OUI bytes are
    /// randomly generated. Callers must not attribute it to a vendor or treat it
    /// as a persistent device identifier for colocation / tracking.
    Randomized,
    Unknown,
    Unregistered,
}

impl DeviceClass {
    pub fn as_str(self) -> &'static str {
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

/// Result of classifying an OUI prefix.
#[derive(Debug, Clone, Copy)]
pub struct OuiInfo {
    pub vendor: &'static str,
    pub class: DeviceClass,
}

/// True if `mac` is a **locally-administered** address — the U/L bit (bit 1 of
/// the first octet, mask `0x02`) is set. These are randomized / private
/// addresses that modern phones (iOS 8+, Android 10+), AirTags/SmartTags, and
/// other privacy-hardened devices rotate (often every ~15 min), NOT a
/// manufacturer-assigned identity: the first three bytes are randomly generated,
/// so an OUI lookup on them is meaningless and treating the address as a
/// persistent device identifier (for colocation / tracking) would outrun the
/// evidence. Universally-administered (real IEEE OUI) addresses return
/// `Some(false)`. Returns `None` when `mac` has no parseable first octet.
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

/// True when `mac`'s I/G (individual/group) bit is set — a MULTICAST or
/// broadcast group address rather than one individual interface.
///
/// The low bit of the first octet. `01:00:5e:…` (IPv4 multicast),
/// `33:33:…` (IPv6 multicast) and `ff:ff:ff:ff:ff:ff` (broadcast) all set it.
/// Orthogonal to [`is_locally_administered`], which reads the *adjacent* U/L
/// bit (0x02): an address can be group-addressed and universally administered
/// at once, so a caller that wants "one real, individual device" must test
/// BOTH. Returns `None` when `mac` has no parseable first octet.
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

/// Look up the OUI for a MAC address and return vendor + device
/// class. Accepts any common MAC formatting (`AA:BB:CC:DD:EE:FF`,
/// `aa-bb-cc-dd-ee-ff`, `aabbccddeeff`). Returns `None` only if the
/// string can't be parsed as a MAC at all.
///
/// A locally-administered (randomized / private) address — see
/// [`is_locally_administered`] — is reported as
/// `OuiInfo { vendor: "Randomized (private)", class: Randomized }` WITHOUT an
/// OUI lookup: its prefix bytes are randomly generated, so attributing it to a
/// vendor would fabricate an identity, and its rotation makes it useless as a
/// persistent device key. This keeps a privacy address from posing as a real
/// device.
///
/// Unrecognised (but genuine) OUIs return `OuiInfo { vendor: "Unknown", class:
/// Unregistered }` so callers can still surface the prefix as
/// evidence even when our curated set doesn't know it.
pub fn classify_mac(mac: &str) -> Option<OuiInfo> {
    let hex: String = mac
        .chars()
        .filter(char::is_ascii_hexdigit)
        .take(6)
        .collect();
    if hex.len() != 6 {
        return None;
    }
    // Randomized / private address: the U/L bit is set, so the prefix carries no
    // real OUI. Surface it as Randomized instead of a meaningless table lookup.
    let first = u8::from_str_radix(&hex[0..2], 16).ok()?;
    if first & 0x02 != 0 {
        return Some(OuiInfo {
            vendor: "Randomized (private)",
            class: DeviceClass::Randomized,
        });
    }
    let prefix = hex.to_uppercase();
    Some(lookup_prefix(&prefix))
}

/// Internal lookup — pulls the const tables. Public for tests; not
/// otherwise re-exported.
pub(crate) fn lookup_prefix(prefix_6hex: &str) -> OuiInfo {
    for &(p, vendor, class) in OUI_TABLE {
        if p == prefix_6hex {
            return OuiInfo { vendor, class };
        }
    }
    OuiInfo {
        vendor: "Unknown",
        class: DeviceClass::Unregistered,
    }
}

/// Curated OUI table — sourced from IEEE registry, filtered to
/// consumer-device prefixes that recur in WiGLE Bluetooth/WiFi
/// observations. Format: `(6-hex prefix UPPERCASE, vendor name,
/// device class)`.
///
/// Entries lean toward vendors whose products dominate the
/// passive-RF survey corpus on consumer hardware. Enterprise
/// switch/router vendors (Cisco, Juniper, Arista, etc.) are
/// included only when their consumer products surface — the bulk
/// of their OUIs are uninteresting for OSINT.
#[rustfmt::skip]
const OUI_TABLE: &[(&str, &str, DeviceClass)] = &[
    // ── Apple — phones, wearables, headphones, laptops, tablets, TVs ──
    ("3C0754", "Apple",         DeviceClass::Phone),
    ("ACBC32", "Apple",         DeviceClass::Phone),
    ("DCA904", "Apple",         DeviceClass::Phone),
    ("F0DBE2", "Apple",         DeviceClass::Phone),
    ("88665A", "Apple",         DeviceClass::Phone),
    ("9C8E99", "Apple",         DeviceClass::Phone),
    ("A4C361", "Apple",         DeviceClass::Phone),
    ("DC2B61", "Apple",         DeviceClass::Phone),
    ("E0AC8B", "Apple",         DeviceClass::Phone),
    ("F0DCE2", "Apple",         DeviceClass::Phone),
    ("F40F24", "Apple",         DeviceClass::Phone),
    ("F49F54", "Apple",         DeviceClass::Phone),
    // Apple AirPods / Beats — Bluetooth-only OUIs
    ("E0CB1D", "Apple AirPods", DeviceClass::Headphones),
    ("64B0A6", "Apple AirPods", DeviceClass::Headphones),
    ("B8C75D", "Apple Beats",   DeviceClass::Headphones),
    // Apple Watch
    ("70DEE2", "Apple Watch",   DeviceClass::Wearable),
    ("A4D1D2", "Apple Watch",   DeviceClass::Wearable),
    // Apple TV
    ("0C74C2", "Apple TV",      DeviceClass::Tv),
    ("60FACD", "Apple TV",      DeviceClass::Tv),
    // MacBook
    ("A8667F", "Apple MacBook", DeviceClass::Laptop),
    ("F0B479", "Apple MacBook", DeviceClass::Laptop),

    // ── Samsung — phones, TVs, wearables, IoT ──
    ("002566", "Samsung",            DeviceClass::Phone),
    ("002738", "Samsung",            DeviceClass::Phone),
    ("0CB319", "Samsung",            DeviceClass::Phone),
    ("28987B", "Samsung",            DeviceClass::Phone),
    ("382DD1", "Samsung",            DeviceClass::Phone),
    ("5C0A5B", "Samsung",            DeviceClass::Phone),
    ("90F1AA", "Samsung",            DeviceClass::Phone),
    ("D052A8", "Samsung",            DeviceClass::Phone),
    ("E89F80", "Samsung",            DeviceClass::Phone),
    ("F87B7A", "Samsung",            DeviceClass::Phone),
    ("002491", "Samsung TV",         DeviceClass::Tv),
    ("089DF4", "Samsung TV",         DeviceClass::Tv),
    ("88366C", "Samsung TV",         DeviceClass::Tv),
    ("48137B", "Samsung Galaxy Watch", DeviceClass::Wearable),
    ("5439DF", "Samsung Galaxy Buds",  DeviceClass::Headphones),

    // ── Google — Pixel phones, Nest, Chromecast, Home ──
    ("3C5AB4", "Google Pixel",   DeviceClass::Phone),
    ("D461DA", "Google Pixel",   DeviceClass::Phone),
    ("F4F5D8", "Google",         DeviceClass::IotHub),
    ("40A36B", "Google Nest",    DeviceClass::IotHub),
    ("64166C", "Google Chromecast", DeviceClass::Tv),
    ("F4F5E8", "Google Chromecast", DeviceClass::Tv),
    ("D8E1CC", "Google Home",    DeviceClass::IotHub),
    ("18B430", "Google Home",    DeviceClass::IotHub),

    // ── Tesla ──
    ("4CFCAA", "Tesla",          DeviceClass::Vehicle),
    ("984FEE", "Tesla",          DeviceClass::Vehicle),
    ("CC51B3", "Tesla",          DeviceClass::Vehicle),
    ("DC4427", "Tesla",          DeviceClass::Vehicle),

    // ── Hikvision / Dahua / Axis — IP cameras ──
    ("4C71DD", "Hikvision",      DeviceClass::Camera),
    ("584C19", "Hikvision",      DeviceClass::Camera),
    ("BC9B5E", "Hikvision",      DeviceClass::Camera),
    ("C0511C", "Hikvision",      DeviceClass::Camera),
    ("3CEF8C", "Hikvision",      DeviceClass::Camera),
    ("000B7C", "Dahua",          DeviceClass::Camera),
    ("3C1B20", "Dahua",          DeviceClass::Camera),
    ("00408C", "Axis Comms",     DeviceClass::Camera),
    ("00408D", "Axis Comms",     DeviceClass::Camera),
    ("ACCC8E", "Axis Comms",     DeviceClass::Camera),
    ("B8A44F", "Axis Comms",     DeviceClass::Camera),

    // ── Sonos / Bose / Sony Audio — speakers, headphones ──
    ("000E58", "Sonos",          DeviceClass::IotHub),
    ("5CAAFD", "Sonos",          DeviceClass::IotHub),
    ("B8E937", "Sonos",          DeviceClass::IotHub),
    ("78282A", "Bose",           DeviceClass::Headphones),
    ("E40B09", "Bose",           DeviceClass::Headphones),
    ("00C04F", "Sony",           DeviceClass::Tv),

    // ── Xiaomi / Huawei / OnePlus ──
    ("18594D", "Xiaomi",         DeviceClass::Phone),
    ("286C07", "Xiaomi",         DeviceClass::Phone),
    ("8CBEBE", "Xiaomi",         DeviceClass::Phone),
    ("AC2DA9", "Xiaomi",         DeviceClass::Phone),
    ("00E0FC", "Huawei",         DeviceClass::Phone),
    ("80FB06", "Huawei",         DeviceClass::Phone),
    ("0C37DC", "Huawei",         DeviceClass::Phone),
    ("2C5BB8", "OnePlus",        DeviceClass::Phone),
    ("48D343", "OnePlus",        DeviceClass::Phone),

    // ── Game consoles ──
    ("001E45", "Nintendo",       DeviceClass::GameConsole),
    ("E84ECE", "Nintendo Switch", DeviceClass::GameConsole),
    ("0050C2", "Sony PlayStation", DeviceClass::GameConsole),
    ("FCDBB3", "Sony PlayStation", DeviceClass::GameConsole),
    ("000D3A", "Microsoft Xbox", DeviceClass::GameConsole),
    ("7C1E52", "Microsoft Xbox", DeviceClass::GameConsole),

    // ── Smart-home: Amazon Echo, Ring, Wyze, etc. ──
    ("00FC8B", "Amazon Echo",    DeviceClass::IotHub),
    ("44650D", "Amazon Echo",    DeviceClass::IotHub),
    ("F0D2F1", "Amazon Echo",    DeviceClass::IotHub),
    ("AC63BE", "Amazon Echo",    DeviceClass::IotHub),
    ("38F73D", "Amazon Echo",    DeviceClass::IotHub),
    ("FCA667", "Amazon Ring",    DeviceClass::Camera),
    ("000F4A", "Amazon Kindle",  DeviceClass::Tablet),
    ("2C300A", "Wyze",           DeviceClass::Camera),

    // ── Routers (consumer wireless) ──
    ("0C5101", "ASUS",           DeviceClass::Router),
    ("2C56DC", "ASUS",           DeviceClass::Router),
    ("FC8FC4", "ASUS",           DeviceClass::Router),
    ("00904C", "Netgear",        DeviceClass::Router),
    ("204E7F", "Netgear",        DeviceClass::Router),
    ("9C3DCF", "Netgear",        DeviceClass::Router),
    ("AC9E17", "Netgear",        DeviceClass::Router),
    ("002584", "TP-Link",        DeviceClass::Router),
    ("0C808A", "TP-Link",        DeviceClass::Router),
    ("344293", "TP-Link",        DeviceClass::Router),
    ("D8074D", "TP-Link",        DeviceClass::Router),
    ("18A6F7", "TP-Link",        DeviceClass::Router),

    // ── Beacons / iBeacon / Eddystone hardware ──
    ("D03972", "Estimote Beacon", DeviceClass::Beacon),
    ("E1F4B8", "Estimote Beacon", DeviceClass::Beacon),
    ("DC0C5C", "Kontakt Beacon",  DeviceClass::Beacon),
    ("D8BC38", "Radius Networks", DeviceClass::Beacon),

    // ── Printers (HP / Brother / Canon) ──
    ("3CD92B", "HP",             DeviceClass::Printer),
    ("9C8E99", "HP",             DeviceClass::Printer), // shared OUI, biased phone above; printer fallback
    ("001E33", "Brother",        DeviceClass::Printer),
    ("003C6E", "Canon",          DeviceClass::Printer),

    // ── Tile / Apple AirTag-class trackers ──
    ("EC2EB8", "Tile",           DeviceClass::Beacon),
    ("DCEFCA", "Tile",           DeviceClass::Beacon),
    ("F8B6E9", "Apple AirTag",   DeviceClass::Beacon),
];

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
