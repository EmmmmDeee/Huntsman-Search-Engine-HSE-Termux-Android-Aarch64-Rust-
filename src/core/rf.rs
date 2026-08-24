//! The RF *sighting* — one radio hearing one device at one place and time.
//!
//! ## Why this exists alongside the entity graph
//!
//! A wardriving capture or a radar sweep flattens into the generic graph as
//! independent `MacAddress` / `Ssid` / `Coordinates` entities, which is right for
//! correlation and wrong for everything else: it dissolves the *sighting*. Once
//! flattened, the graph can say "this BSSID exists" and "this position exists"
//! but not "this BSSID was heard at −53 dBm from that position at 17:18" — so
//! the two questions an RF survey is actually run to answer both become
//! unanswerable:
//!
//!   * **How did this device's signal change as the operator moved?** — the
//!     multilateration input, and the difference between a bearing and a fix.
//!   * **Which distinct places was it heard from?** — the input to
//!     [`crate::core::radar_track`]'s "is the same device following me?".
//!
//! [`crate::core::radar_track`] today reconstructs sweeps by reading entities
//! back through `observation_from_entity`, which recovers the MAC, a name and
//! the bonded flag — everything the flattening preserved — and cannot recover
//! signal, position or sighting time, because those were never stored per
//! sighting. This module is the record that keeps them.
//!
//! This mirrors the `stealer_rows` precedent exactly: persisted **alongside**
//! the entity graph, not instead of it, because the flattening loses a pairing
//! the operator wants back.
//!
//! ## One table, both radios
//!
//! A WiGLE capture and a live Bluetooth sweep observe the same physical thing —
//! a radio emitting an address at a place — so they share one record and are
//! distinguished by [`RfSource`]. Keeping them apart would mean answering
//! "was this device near me before?" twice and reconciling the answers.
//!
//! Pure: no I/O, no storage, no clock. The only dependency is
//! [`crate::util::oui`], the same U/L-bit classifier `radar_track` uses.

use serde::{Deserialize, Serialize};

/// The radio family a sighting came from.
///
/// Cellular is carried because a capture contains it and dropping a row is a
/// silent loss, but it is deliberately distinct: a cellular `network_id` is an
/// `MCC_MNC_LAC_CID` tuple, not a hardware address, so none of the
/// address-derived reasoning below applies to it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RadioKind {
    Wifi,
    Ble,
    BtClassic,
    Cellular,
}

impl RadioKind {
    #[must_use]
    pub fn as_db_str(self) -> &'static str {
        match self {
            Self::Wifi => "wifi",
            Self::Ble => "ble",
            Self::BtClassic => "bt",
            Self::Cellular => "cell",
        }
    }

    #[must_use]
    pub fn from_db_str(s: &str) -> Self {
        match s {
            "ble" => Self::Ble,
            "bt" => Self::BtClassic,
            "cell" => Self::Cellular,
            _ => Self::Wifi,
        }
    }

    /// Whether a `network_id` of this family is a hardware address, and so
    /// carries an OUI and a U/L bit worth reading.
    #[must_use]
    pub fn has_hardware_address(self) -> bool {
        !matches!(self, Self::Cellular)
    }
}

/// Where a sighting came from. Provenance is not cosmetic: a WiGLE API answer is
/// somebody else's observation at an unknown time, while a local sweep is the
/// operator's own radio now, and a counter-surveillance question must not treat
/// the two as equal evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RfSource {
    /// A WiGLE KML export written by the capture device.
    WigleKml,
    /// The WiGLE API.
    WigleApi,
    /// A local Bluetooth sweep (`modules::signal_radar::bluetooth`).
    BluetoothRadar,
    /// A local Wi-Fi scan (`modules::signal_radar::wifi`).
    WifiRadar,
}

impl RfSource {
    #[must_use]
    pub fn as_db_str(self) -> &'static str {
        match self {
            Self::WigleKml => "wigle-kml",
            Self::WigleApi => "wigle-api",
            Self::BluetoothRadar => "bt-radar",
            Self::WifiRadar => "wifi-radar",
        }
    }

    #[must_use]
    pub fn from_db_str(s: &str) -> Self {
        match s {
            "wigle-api" => Self::WigleApi,
            "bt-radar" => Self::BluetoothRadar,
            "wifi-radar" => Self::WifiRadar,
            _ => Self::WigleKml,
        }
    }

    /// True when the operator's own radio made this observation, rather than it
    /// being reported by a third party.
    #[must_use]
    pub fn is_local_sensor(self) -> bool {
        matches!(self, Self::BluetoothRadar | Self::WifiRadar)
    }
}

/// Whether an address is followable across time.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AddressKind {
    /// A universally-administered (real hardware) address. The same value in two
    /// sightings is the same device.
    Fixed,
    /// A locally-administered privacy address. It rotates, so recurrence proves
    /// nothing and it must never be plotted as a followable pin (AU-122).
    Randomised,
    /// Not a hardware address at all (a cellular identifier).
    NotAnAddress,
}

/// One radio hearing one device, once.
///
/// Every field except `network_id`, `radio` and `source` is optional because a
/// real capture omits them individually: a hidden network has no name, a
/// GPS-less fix has no position, a Bluetooth sighting has no encryption. An
/// absent field is recorded as absent rather than defaulted, so a query can tell
/// "not observed" from "observed as zero".
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RfSighting {
    /// The device address, canonicalised by [`canonical_network_id`].
    pub network_id: String,
    pub radio: RadioKind,
    pub source: RfSource,
    /// Device class where the source reports one (`Watch`, `Handsfree`, …).
    pub device_class: Option<String>,
    /// SSID for Wi-Fi, friendly name for Bluetooth.
    pub name: Option<String>,
    pub encryption: Option<String>,
    /// The source's own timestamp, verbatim.
    pub observed_at: Option<String>,
    /// [`observed_at`](Self::observed_at) as Unix seconds, where it parsed.
    /// Stored beside the text because the text is not orderable: two ISO-8601
    /// stamps at different UTC offsets sort lexicographically in the wrong
    /// order, so a `MIN()` over mixed offsets would report the wrong
    /// first-seen.
    pub observed_epoch: Option<i64>,
    pub signal_dbm: Option<f64>,
    pub accuracy_m: Option<f64>,
    pub latitude: Option<f64>,
    pub longitude: Option<f64>,
    /// The source's own type string, kept verbatim so a later reader can
    /// re-derive a classification this version did not know how to make.
    pub raw_type: Option<String>,
}

impl RfSighting {
    /// Minimal sighting; callers set the optional fields they actually have.
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

    /// Classify the address from its bits, never from a vendor lookup — the
    /// U/L bit is present in every MAC, while a vendor table covers a fraction
    /// of allocations and would report most real hardware as unknown.
    #[must_use]
    pub fn address_kind(&self) -> AddressKind {
        if !self.radio.has_hardware_address() {
            return AddressKind::NotAnAddress;
        }
        match crate::util::oui::is_locally_administered(&self.network_id) {
            Some(true) => AddressKind::Randomised,
            Some(false) => AddressKind::Fixed,
            None => AddressKind::NotAnAddress,
        }
    }

    /// The 24-bit OUI as six uppercase hex digits, or `None` when the id is not
    /// a MAC. Worth storing even with no vendor name for it: a larger IEEE table
    /// can then be joined in later without re-reading a single capture.
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

    /// A position is usable only if it is in range and is not the null island —
    /// exactly `0,0` is what a receiver with no fix reports.
    #[must_use]
    pub fn has_usable_position(&self) -> bool {
        match (self.latitude, self.longitude) {
            (Some(lat), Some(lon)) => {
                (-90.0..=90.0).contains(&lat)
                    && (-180.0..=180.0).contains(&lon)
                    && !(lat == 0.0 && lon == 0.0)
            }
            _ => false,
        }
    }
}

/// True for a colon-separated six-octet MAC.
#[must_use]
pub fn is_mac(s: &str) -> bool {
    let mut octets = 0;
    for part in s.split(':') {
        if part.len() != 2 || !part.bytes().all(|b| b.is_ascii_hexdigit()) {
            return false;
        }
        octets += 1;
    }
    octets == 6
}

/// Fold an address to the one spelling the rest of the engine uses.
///
/// Identity is the value, and WiGLE writes BSSIDs uppercase while every other
/// producer writes them lowercase — without folding, one access point seen by a
/// capture and by the local radio would be two unrelated devices. Non-MAC ids
/// (cellular tuples) are left alone: their case is not known to be
/// insignificant.
#[must_use]
pub fn canonical_network_id(raw: &str) -> String {
    let t = raw.trim();
    if is_mac(t) {
        t.to_ascii_lowercase()
    } else {
        t.to_string()
    }
}

/// Split a WiGLE `Type:` value into its radio family and device class.
///
/// The field is not the flat token it appears to be. Wi-Fi is bare `WIFI`, but
/// Bluetooth arrives as `BLEAttributes: Watch;10` — a family, a device class and
/// a trailing counter. The class is genuine device attribution and, on real
/// captures where a curated OUI table resolves a fraction of a percent of
/// addresses, it is the better of the two attribution sources.
///
/// `Uncategorized` and `null` are the source declining to classify; both map to
/// `None` so "no class" is one value rather than three spellings of it.
#[must_use]
pub fn classify_wigle_type(raw: &str) -> (RadioKind, Option<String>) {
    let (head, tail) = raw.trim().split_once(':').unwrap_or((raw.trim(), ""));
    let head_u = head.trim().to_ascii_uppercase();
    let class = tail
        .split(';')
        .next()
        .map(str::trim)
        .filter(|c| {
            !c.is_empty()
                && !c.eq_ignore_ascii_case("null")
                && !c.eq_ignore_ascii_case("uncategorized")
        })
        .map(str::to_string);

    let radio = if head_u.starts_with("WIFI") || head_u == "W" {
        RadioKind::Wifi
    } else if head_u.starts_with("BLE") {
        RadioKind::Ble
    } else if head_u.starts_with("BT") {
        RadioKind::BtClassic
    } else {
        RadioKind::Cellular
    };
    // A device class is a Bluetooth concept; a Wi-Fi `Type` has no tail to read,
    // and a cellular one must not be attributed.
    match radio {
        RadioKind::Ble | RadioKind::BtClassic => (radio, class),
        _ => (radio, None),
    }
}

/// Parse `YYYY-MM-DDTHH:MM:SS[.fff][Z|±HH:MM]` to Unix seconds.
///
/// Hand-rolled rather than pulling in a date crate for one format: the repo
/// gates dependencies (`cargo deny` / `cargo machete`) and this is the only
/// timestamp shape the RF sources emit. Returns `None` on anything it does not
/// fully understand rather than guessing — a wrong epoch silently reorders a
/// device's history, which is worse than an absent one.
#[must_use]
pub fn parse_iso8601_epoch(s: &str) -> Option<i64> {
    let b = s.as_bytes();
    if b.len() < 19 || b[4] != b'-' || b[7] != b'-' || (b[10] != b'T' && b[10] != b' ') {
        return None;
    }
    let num = |from: usize, to: usize| s.get(from..to)?.parse::<i64>().ok();
    let (y, mo, d) = (num(0, 4)?, num(5, 7)?, num(8, 10)?);
    let (h, mi, sec) = (num(11, 13)?, num(14, 16)?, num(17, 19)?);
    if !(1..=12).contains(&mo) || !(1..=31).contains(&d) || h > 23 || mi > 59 || sec > 60 {
        return None;
    }

    // Days from the civil epoch (1970-01-01), Howard Hinnant's algorithm: exact
    // in integer arithmetic for the whole proleptic Gregorian calendar, so it
    // needs no leap-year special cases and no lookup table.
    let y_adj = if mo <= 2 { y - 1 } else { y };
    let era = if y_adj >= 0 { y_adj } else { y_adj - 399 } / 400;
    let yoe = y_adj - era * 400;
    let mp = (mo + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;

    let mut epoch = days * 86_400 + h * 3600 + mi * 60 + sec;

    // Offset: `Z`, or ±HH:MM / ±HHMM at the very end. A stamp with no offset is
    // read as UTC, which is what every producer here means by it.
    let rest = &s[19..];
    let tz = rest.trim_start_matches(|c: char| c == '.' || c.is_ascii_digit());
    if !tz.is_empty() && tz != "Z" && tz != "z" {
        let sign: i64 = match tz.as_bytes()[0] {
            b'+' => -1,
            b'-' => 1,
            _ => return None,
        };
        let digits: String = tz[1..].chars().filter(char::is_ascii_digit).collect();
        if digits.len() != 4 {
            return None;
        }
        let oh = digits.get(..2)?.parse::<i64>().ok()?;
        let om = digits.get(2..4)?.parse::<i64>().ok()?;
        if oh > 23 || om > 59 {
            return None;
        }
        epoch += sign * (oh * 3600 + om * 60);
    }
    Some(epoch)
}

#[cfg(test)]
mod tests {
    include!("rf_tests.rs");
}
