//! The network selector grammar: a BSSID, an SSID, a coordinate pair or a `cell:` site, parsed
//! and written back in one canonical form. **Pure.** Kept apart from `scan_route` so the `wigle`
//! collector depends only on this grammar, not on scan routing; `scan_route` re-exports it.

use crate::canonical::{canonical_coordinates, canonical_mac};

/// The longest SSID, in bytes (IEEE 802.11).
pub const MAX_SSID_BYTES: usize = 32;
/// Written before an SSID that would otherwise read as a BSSID or a coordinate pair.
pub const SSID_PREFIX: &str = "ssid:";
/// Written before a cell site's identity: `cell:MCC:MNC:AREA:CELL`, as `radar cells` reports it.
pub const CELL_PREFIX: &str = "cell:";
/// The largest cell identity a phone reports: a 5G NR cell's 36 bits.
pub const MAX_CELL_ID: u64 = (1 << 36) - 1;

/// What a network lookup searches for.
#[derive(Debug, Clone, PartialEq)]
pub enum NetworkSelector {
    /// A BSSID, lower case with `:` separators.
    Bssid(String),
    /// An exact SSID.
    Ssid(String),
    /// A point, rounded to six decimal places.
    Area { lat: f64, lon: f64 },
    /// A cell site: its country code (3 digits), network code (2 or 3 digits, as written, since
    /// `010` and `10` are different networks in some countries), location or tracking area, and
    /// cell identity.
    Cell {
        mcc: String,
        mnc: String,
        area: u32,
        cell: u64,
    },
}

impl NetworkSelector {
    /// `raw` as a selector: `ssid:NAME` is always an SSID; `cell:` is a cell site or nothing, so
    /// a mistyped one is refused rather than searched for as a network name; otherwise a BSSID
    /// (`:` or `-` separated), then a coordinate pair, then an SSID. `None` for an empty or
    /// over-long SSID, or one with control characters. **Pure.**
    #[must_use]
    pub fn parse(raw: &str) -> Option<Self> {
        let trimmed = raw.trim();
        if let Some(name) = trimmed.strip_prefix(SSID_PREFIX) {
            return ssid(name);
        }
        if trimmed
            .get(..CELL_PREFIX.len())
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case(CELL_PREFIX))
        {
            return cell(trimmed);
        }
        Self::parse_identifier(trimmed).or_else(|| ssid(trimmed))
    }

    /// `raw` as a BSSID, a `cell:` site or a coordinate pair, never an SSID: the selectors
    /// `scan` may infer without being told the kind. `0,0` is no position. **Pure.**
    #[must_use]
    pub fn parse_identifier(raw: &str) -> Option<Self> {
        if let Some(cell) = cell(raw.trim()) {
            return Some(cell);
        }
        if let Some(mac) = canonical_mac(raw) {
            return Some(Self::Bssid(mac));
        }
        let canonical = canonical_coordinates(raw.trim())?;
        let (lat, lon) = canonical.split_once(',')?;
        let (lat, lon) = (lat.parse::<f64>().ok()?, lon.parse::<f64>().ok()?);
        (lat != 0.0 || lon != 0.0).then_some(Self::Area { lat, lon })
    }

    /// The selector as one string that [`Self::parse`] reads back to the same selector. **Pure.**
    #[must_use]
    pub fn canonical(&self) -> String {
        match self {
            Self::Bssid(bssid) => bssid.clone(),
            Self::Area { lat, lon } => format!("{lat:.6},{lon:.6}"),
            Self::Cell {
                mcc,
                mnc,
                area,
                cell,
            } => format!("{CELL_PREFIX}{mcc}:{mnc}:{area}:{cell}"),
            Self::Ssid(name) => {
                if Self::parse(name).as_ref() == Some(self) {
                    name.clone()
                } else {
                    format!("{SSID_PREFIX}{name}")
                }
            }
        }
    }
}

/// `cell:MCC:MNC:AREA:CELL`, the prefix in any case: a three-digit country code other than
/// `000`, a two- or three-digit network code, and decimal area and cell numbers within what a
/// phone reports. **Pure.**
fn cell(raw: &str) -> Option<NetworkSelector> {
    let prefix = raw.get(..CELL_PREFIX.len())?;
    if !prefix.eq_ignore_ascii_case(CELL_PREFIX) {
        return None;
    }
    let digits = |part: &str| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit());
    let mut parts = raw[CELL_PREFIX.len()..].split(':');
    let (mcc, mnc, area, cell) = (parts.next()?, parts.next()?, parts.next()?, parts.next()?);
    if parts.next().is_some()
        || !(digits(mcc) && mcc.len() == 3 && mcc != "000")
        || !(digits(mnc) && (2..=3).contains(&mnc.len()))
        || !digits(area)
        || !digits(cell)
    {
        return None;
    }
    let cell = cell
        .parse::<u64>()
        .ok()
        .filter(|cell| *cell <= MAX_CELL_ID)?;
    Some(NetworkSelector::Cell {
        mcc: mcc.to_owned(),
        mnc: mnc.to_owned(),
        area: area.parse().ok()?,
        cell,
    })
}

fn ssid(name: &str) -> Option<NetworkSelector> {
    let name = name.trim();
    let ok =
        !name.is_empty() && name.len() <= MAX_SSID_BYTES && !name.chars().any(char::is_control);
    ok.then(|| NetworkSelector::Ssid(name.to_owned()))
}

/// The canonical network selector string for `raw`, or `None` when it is not one.
#[must_use]
pub fn network_selector(raw: &str) -> Option<String> {
    NetworkSelector::parse(raw).map(|selector| selector.canonical())
}
