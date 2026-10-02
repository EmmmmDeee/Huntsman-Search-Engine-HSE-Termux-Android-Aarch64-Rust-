//! RF helpers rebuilt from the monolith's `util::wifi`, `util::cell`, and
//! `core::rf`.

use std::borrow::Cow;
use std::fmt::Display;

use serde::{Deserialize, Serialize};

use super::oui;
use crate::geo::is_valid_coords;
use crate::timefmt::days_from_civil;

pub const GENERIC_SSID_BRANDS: &[&str] = &[
    "android", "dlink", "eduroam", "galaxy", "hidden", "iphone", "linksys", "netgear", "optimum",
    "optus", "spectrum", "telstra", "tp-link", "tplink", "unnamed", "unknown", "vodafone",
    "xfinity",
];

pub const GENERIC_SSID_WORDS: &[&str] = &[
    "admin", "asus", "att", "config", "cox", "default", "free", "guest", "nbn", "open", "pixel",
    "public", "setup", "test",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RadioKind {
    Wifi,
    Ble,
    BtClassic,
    Cellular,
}

impl RadioKind {
    #[must_use]
    pub const fn as_db_str(self) -> &'static str {
        match self {
            Self::Wifi => "wifi",
            Self::Ble => "ble",
            Self::BtClassic => "bt",
            Self::Cellular => "cell",
        }
    }

    #[must_use]
    pub fn from_db_str(value: &str) -> Self {
        match value {
            "ble" => Self::Ble,
            "bt" => Self::BtClassic,
            "cell" => Self::Cellular,
            _ => Self::Wifi,
        }
    }

    #[must_use]
    pub const fn has_hardware_address(self) -> bool {
        !matches!(self, Self::Cellular)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RfSource {
    WigleKml,
    WigleApi,
    BluetoothRadar,
    WifiRadar,
}

impl RfSource {
    #[must_use]
    pub const fn as_db_str(self) -> &'static str {
        match self {
            Self::WigleKml => "wigle-kml",
            Self::WigleApi => "wigle-api",
            Self::BluetoothRadar => "bt-radar",
            Self::WifiRadar => "wifi-radar",
        }
    }

    #[must_use]
    pub fn from_db_str(value: &str) -> Self {
        match value {
            "wigle-api" => Self::WigleApi,
            "bt-radar" => Self::BluetoothRadar,
            "wifi-radar" => Self::WifiRadar,
            _ => Self::WigleKml,
        }
    }

    #[must_use]
    pub const fn is_local_sensor(self) -> bool {
        matches!(self, Self::BluetoothRadar | Self::WifiRadar)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AddressKind {
    Fixed,
    Randomised,
    NotAnAddress,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RfSighting {
    pub network_id: String,
    pub radio: RadioKind,
    pub source: RfSource,
    pub device_class: Option<String>,
    pub name: Option<String>,
    pub encryption: Option<String>,
    pub observed_at: Option<String>,
    pub observed_epoch: Option<i64>,
    pub signal_dbm: Option<f64>,
    pub accuracy_m: Option<f64>,
    pub latitude: Option<f64>,
    pub longitude: Option<f64>,
    pub raw_type: Option<String>,
}

impl RfSighting {
    #[must_use]
    pub fn new(network_id: &str, radio: RadioKind, source: RfSource) -> Self {
        Self {
            network_id: canonical_network_id(network_id),
            radio,
            source,
            device_class: None,
            name: None,
            encryption: None,
            observed_at: None,
            observed_epoch: None,
            signal_dbm: None,
            accuracy_m: None,
            latitude: None,
            longitude: None,
            raw_type: None,
        }
    }

    #[must_use]
    pub fn address_kind(&self) -> AddressKind {
        if !self.radio.has_hardware_address() {
            return AddressKind::NotAnAddress;
        }
        match oui::is_locally_administered(&self.network_id) {
            Some(true) => AddressKind::Randomised,
            Some(false) => AddressKind::Fixed,
            None => AddressKind::NotAnAddress,
        }
    }

    #[must_use]
    pub fn oui(&self) -> Option<String> {
        if !is_mac(&self.network_id) {
            return None;
        }
        Some(
            self.network_id
                .replace(':', "")
                .get(..6)?
                .to_ascii_uppercase(),
        )
    }

    #[must_use]
    pub fn has_usable_position(&self) -> bool {
        match (self.latitude, self.longitude) {
            (Some(lat), Some(lon)) => is_valid_coords(lat, lon),
            _ => false,
        }
    }
}

#[must_use]
pub fn band(freq_mhz: Option<i64>) -> Option<&'static str> {
    match freq_mhz? {
        2400..=2500 => Some("2.4GHz"),
        4900..=5900 => Some("5GHz"),
        5925..=7125 => Some("6GHz"),
        _ => None,
    }
}

#[must_use]
pub fn is_generic_ssid(ssid: &str) -> bool {
    let lower = ssid.to_ascii_lowercase();
    if GENERIC_SSID_BRANDS
        .iter()
        .any(|brand| lower.contains(brand))
    {
        return true;
    }
    ssid_tokens(&lower).any(|token| GENERIC_SSID_WORDS.contains(&token))
}

#[must_use]
pub fn tower_id(
    mcc: impl Display,
    mnc: impl Display,
    lac: impl Display,
    cid: impl Display,
) -> String {
    format!("{mcc}-{mnc}-{lac}-{cid}")
}

#[must_use]
pub fn mcc_mnc_str(value: &Option<serde_json::Value>) -> Cow<'_, str> {
    match value {
        Some(serde_json::Value::String(s)) => Cow::Borrowed(s),
        Some(serde_json::Value::Number(n)) => Cow::Owned(n.to_string()),
        _ => Cow::Borrowed(""),
    }
}

#[must_use]
pub fn resolve_lac(lac: Option<i64>, tac: Option<i64>) -> i64 {
    lac.or(tac).unwrap_or(0)
}

#[must_use]
pub fn is_mac(value: &str) -> bool {
    let mut count = 0usize;
    for part in value.split(':') {
        if part.len() != 2 || !part.bytes().all(|b| b.is_ascii_hexdigit()) {
            return false;
        }
        count += 1;
    }
    count == 6
}

#[must_use]
pub fn canonical_network_id(raw: &str) -> String {
    let trimmed = raw.trim();
    if is_mac(trimmed) {
        trimmed.to_ascii_lowercase()
    } else {
        trimmed.to_string()
    }
}

#[must_use]
pub fn classify_wigle_type(raw: &str) -> (RadioKind, Option<String>) {
    let trimmed = raw.trim();
    let (head, tail) = trimmed.split_once(':').unwrap_or((trimmed, ""));
    let class = tail
        .split(';')
        .next()
        .map(str::trim)
        .filter(|value| {
            !value.is_empty()
                && !value.eq_ignore_ascii_case("null")
                && !value.eq_ignore_ascii_case("uncategorized")
        })
        .map(str::to_string);
    let head = head.trim().to_ascii_uppercase();
    let radio = if head.starts_with("WIFI") || head == "W" {
        RadioKind::Wifi
    } else if head.starts_with("BLE") {
        RadioKind::Ble
    } else if head.starts_with("BT") {
        RadioKind::BtClassic
    } else {
        RadioKind::Cellular
    };
    match radio {
        RadioKind::Ble | RadioKind::BtClassic => (radio, class),
        _ => (radio, None),
    }
}

#[must_use]
pub fn parse_iso8601_epoch(value: &str) -> Option<i64> {
    let bytes = value.as_bytes();
    if bytes.len() < 19
        || bytes[4] != b'-'
        || bytes[7] != b'-'
        || (bytes[10] != b'T' && bytes[10] != b' ')
    {
        return None;
    }
    let num = |from: usize, to: usize| value.get(from..to)?.parse::<i64>().ok();
    let (year, month, day) = (num(0, 4)?, num(5, 7)?, num(8, 10)?);
    let (hour, minute, second) = (num(11, 13)?, num(14, 16)?, num(17, 19)?);
    if !(1900..=2100).contains(&year)
        || !(1..=12).contains(&month)
        || !(1..=31).contains(&day)
        || hour > 23
        || minute > 59
        || second > 60
    {
        return None;
    }

    let mut epoch = days_from_civil(
        i32::try_from(year).ok()?,
        u32::try_from(month).ok()?,
        u32::try_from(day).ok()?,
    ) * 86_400
        + hour * 3600
        + minute * 60
        + second;
    let rest = &value[19..];
    let tz = rest.trim_start_matches(|c: char| c == '.' || c.is_ascii_digit());
    if !tz.is_empty() && tz != "Z" && tz != "z" {
        let sign = match tz.as_bytes()[0] {
            b'+' => -1,
            b'-' => 1,
            _ => return None,
        };
        let digits: String = tz[1..].chars().filter(char::is_ascii_digit).collect();
        if digits.len() != 4 {
            return None;
        }
        let offset_hour = digits.get(..2)?.parse::<i64>().ok()?;
        let offset_minute = digits.get(2..4)?.parse::<i64>().ok()?;
        if offset_hour > 23 || offset_minute > 59 {
            return None;
        }
        epoch += sign * (offset_hour * 3600 + offset_minute * 60);
    }
    Some(epoch)
}

fn ssid_tokens(lower: &str) -> impl Iterator<Item = &str> {
    lower
        .split(|c: char| !c.is_alphanumeric())
        .flat_map(|part| {
            let mut tokens = Vec::new();
            let mut start = 0usize;
            let mut prev: Option<char> = None;
            for (index, ch) in part.char_indices() {
                if let Some(prev_char) = prev {
                    if prev_char.is_ascii_digit() != ch.is_ascii_digit() {
                        tokens.push(&part[start..index]);
                        start = index;
                    }
                }
                prev = Some(ch);
            }
            if start < part.len() {
                tokens.push(&part[start..]);
            }
            tokens
        })
        .filter(|token| !token.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    const HW1: &str = "3C:5A:B4:11:22:33";
    const RND: &str = "36:32:62:36:31:33";

    #[test]
    fn generic_ssid_detection_uses_substrings_for_brands_and_tokens_for_words() {
        for ssid in [
            "linksys",
            "xfinitywifi",
            "NETGEAR-Guest",
            "Telstra-Home-123",
            "Free Public WiFi",
        ] {
            assert!(is_generic_ssid(ssid), "{ssid}");
        }
        for ssid in [
            "Freeman-Family",
            "Seattle-Cafe",
            "Testa-Household",
            "Openshaw-House",
            "Hancox-Home",
            "Attwood-Residence",
            "Nbnalla-House",
            "Smith-WiFi",
            "Johnson WLAN",
        ] {
            assert!(!is_generic_ssid(ssid), "{ssid}");
        }
    }

    #[test]
    fn band_and_cell_helpers_are_single_sourced() {
        assert_eq!(band(Some(2412)), Some("2.4GHz"));
        assert_eq!(band(Some(5180)), Some("5GHz"));
        assert_eq!(band(Some(5955)), Some("6GHz"));
        assert_eq!(band(Some(1234)), None);
        assert_eq!(tower_id("505", "1", 12345, 67890), "505-1-12345-67890");
        assert_eq!(tower_id(505, 1, 12345, 67890), "505-1-12345-67890");
        assert_eq!(
            mcc_mnc_str(&Some(serde_json::json!("505"))),
            Cow::Borrowed("505")
        );
        assert_eq!(mcc_mnc_str(&Some(serde_json::json!(310))).as_ref(), "310");
        assert_eq!(
            mcc_mnc_str(&Some(serde_json::json!(true))),
            Cow::Borrowed("")
        );
        assert_eq!(resolve_lac(Some(100), Some(200)), 100);
        assert_eq!(resolve_lac(None, Some(200)), 200);
        assert_eq!(resolve_lac(None, None), 0);
    }

    #[test]
    fn wigle_types_network_ids_and_address_kind_are_normalised() {
        assert_eq!(classify_wigle_type("WIFI"), (RadioKind::Wifi, None));
        assert_eq!(classify_wigle_type("LTE"), (RadioKind::Cellular, None));
        assert_eq!(
            classify_wigle_type("BLEAttributes: Watch;10"),
            (RadioKind::Ble, Some("Watch".to_string()))
        );
        assert_eq!(
            classify_wigle_type("BTAttributes: Display/Speaker;10"),
            (RadioKind::BtClassic, Some("Display/Speaker".to_string()))
        );
        assert_eq!(
            classify_wigle_type("BLEAttributes: Uncategorized;10"),
            (RadioKind::Ble, None)
        );

        assert!(is_mac("00:1a:2b:3c:4d:5e"));
        assert!(!is_mac("00:1a:2b:3c:4d"));
        assert_eq!(
            canonical_network_id("  00:1A:2B:3C:4D:5E  "),
            "00:1a:2b:3c:4d:5e"
        );
        assert_eq!(canonical_network_id("50501_28693_ABC"), "50501_28693_ABC");

        let fixed = RfSighting::new(HW1, RadioKind::Wifi, RfSource::WigleKml);
        let random = RfSighting::new(RND, RadioKind::Wifi, RfSource::WigleKml);
        let cell = RfSighting::new(
            "50501_28693_147572482",
            RadioKind::Cellular,
            RfSource::WigleKml,
        );
        assert_eq!(fixed.address_kind(), AddressKind::Fixed);
        assert_eq!(random.address_kind(), AddressKind::Randomised);
        assert_eq!(cell.address_kind(), AddressKind::NotAnAddress);
        assert_eq!(fixed.oui().as_deref(), Some("3C5AB4"));
        assert_eq!(cell.oui(), None);
    }

    #[test]
    fn positions_and_timestamps_are_defensive() {
        let mut sighting = RfSighting::new(HW1, RadioKind::Wifi, RfSource::WigleKml);
        assert!(!sighting.has_usable_position());
        sighting.latitude = Some(0.0);
        sighting.longitude = Some(0.0);
        assert!(!sighting.has_usable_position());
        sighting.latitude = Some(91.0);
        sighting.longitude = Some(10.0);
        assert!(!sighting.has_usable_position());
        sighting.latitude = Some(-26.814_468);
        sighting.longitude = Some(153.086_472);
        assert!(sighting.has_usable_position());

        assert_eq!(parse_iso8601_epoch("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(
            parse_iso8601_epoch("2000-01-01T00:00:00Z"),
            Some(946_684_800)
        );
        assert_eq!(
            parse_iso8601_epoch("2000-01-01T00:00:00"),
            Some(946_684_800)
        );
        assert_eq!(
            parse_iso8601_epoch("2000-01-01T00:00:00-07:00"),
            Some(946_684_800 + 7 * 3600)
        );
        assert_eq!(
            parse_iso8601_epoch("2000-01-01T00:00:00+05:30"),
            Some(946_684_800 - (5 * 3600 + 1800))
        );
        assert_eq!(
            parse_iso8601_epoch("2000-01-01T00:00:00.000-07:00"),
            Some(946_684_800 + 7 * 3600)
        );
        assert_eq!(
            parse_iso8601_epoch("2000-01-01T00:00:00-0700"),
            Some(946_684_800 + 7 * 3600)
        );
        for bad in [
            "",
            "not a date",
            "2026-08-21",
            "2026/08/21T00:00:00Z",
            "2026-13-01T00:00:00Z",
            "2026-08-32T00:00:00Z",
            "2026-08-21T24:00:00Z",
            "2026-08-21T00:60:00Z",
            "2026-08-21T00:00:00~07:00",
            "2026-08-21T00:00:00-7:00",
            "2026-08-21T00:00:00-25:00",
            "0001-01-01T00:00:00Z",
            "1899-12-31T23:59:59Z",
            "2101-01-01T00:00:00Z",
            "9999-12-31T23:59:59Z",
        ] {
            assert_eq!(parse_iso8601_epoch(bad), None, "{bad}");
        }
    }

    #[test]
    fn enums_round_trip_through_db_strings() {
        for radio in [
            RadioKind::Wifi,
            RadioKind::Ble,
            RadioKind::BtClassic,
            RadioKind::Cellular,
        ] {
            assert_eq!(RadioKind::from_db_str(radio.as_db_str()), radio);
        }
        for source in [
            RfSource::WigleKml,
            RfSource::WigleApi,
            RfSource::BluetoothRadar,
            RfSource::WifiRadar,
        ] {
            assert_eq!(RfSource::from_db_str(source.as_db_str()), source);
        }
        assert!(RfSource::BluetoothRadar.is_local_sensor());
        assert!(!RfSource::WigleApi.is_local_sensor());
        assert!(RadioKind::Wifi.has_hardware_address());
        assert!(!RadioKind::Cellular.has_hardware_address());
    }
}
