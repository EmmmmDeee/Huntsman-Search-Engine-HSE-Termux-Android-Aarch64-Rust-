//! Universal coordinate parser — turn any human- or document-written location
//! string into a validated WGS84 latitude/longitude.
//!
//! A GEOINT tool ingests coordinates from wildly inconsistent sources: a CSV
//! column of signed decimals, a photo caption in degrees-minutes-seconds, a
//! ham-radio call log's Maidenhead locator, a Google-Maps "Plus Code", an
//! `geo:` URI from a vCard. The rest of the engine speaks exactly one dialect —
//! 6-decimal `"lat,lon"` — so this module is the single front door that accepts
//! every notation and normalises it to that one canonical form.
//!
//! Supported notations ([`CoordFormat`]):
//!
//! * **Decimal** — `-27.4766, 153.0166`, `-27.4766 153.0166` (comma *or*
//!   whitespace separated, signed).
//! * **DMS / DDM** — `27°28'35.8"S 153°00'59.8"E`, `27 28.6 S, 153 01.0 E`, with
//!   every common degree/minute/second glyph (`° º`, `' ′ ’ \``, `" ″ ”`) and
//!   the hemisphere letter in prefix *or* suffix position. The N/S/E/W letters
//!   also disambiguate axis order, so `153°E, 27°S` is read back as
//!   `lat -27, lon 153`.
//! * **`geo:` URI** (RFC 5870) — `geo:-27.4766,153.0166;u=35`.
//! * **Plus Code / Open Location Code** — `4RRH46RW+RH7` (full codes).
//! * **Maidenhead** grid locator — `QG62kn` (ham radio; 4/6/8 character).
//!
//! Every path funnels through [`LatLon::checked`], so a returned [`LatLon`] is
//! always finite and in range (`lat ∈ [-90, 90]`, `lon ∈ [-180, 180]`). The
//! entry point [`parse`] is **total**: it never panics on any input and returns
//! `None` when nothing parses (proven by a fuzz-style property test).
//!
//! Out of scope (a deliberate, documented boundary — these need an ellipsoidal
//! projection rather than the closed-form decode every notation here uses):
//! UTM and MGRS. The [`CoordFormat`] enum and [`parse`] dispatcher are arranged
//! so they can be added as additional arms without disturbing the rest.

/// The notation a coordinate string was recognised as. Returned alongside the
/// parsed value so callers can decide how much to trust an auto-detected match
/// (see [`CoordFormat::is_self_evident`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoordFormat {
    /// Signed decimal degrees.
    Decimal,
    /// Degrees, minutes, seconds.
    Dms,
    /// Degrees and decimal minutes.
    Ddm,
    /// RFC 5870 `geo:` URI.
    GeoUri,
    /// Open Location Code (Plus Code).
    PlusCode,
    /// Maidenhead grid locator.
    Maidenhead,
}

impl CoordFormat {
    /// Whether a bare string in this notation carries an *unambiguous marker* —
    /// a degree glyph, an N/S/E/W letter, the `geo:` scheme, or a Plus Code's
    /// `+` — that makes it safe for the unified-scan auto-detector to classify
    /// as a coordinate without false-positiving against ordinary handles.
    ///
    /// `Decimal` (a bare `"12 34"` is as likely a username or a measurement) and
    /// `Maidenhead` (`QG62kn` is indistinguishable from a handle) are **not**
    /// self-evident: they are accepted only when the operator has already
    /// declared the target a coordinate (`--kind coordinates`). Plain comma
    /// decimals are still auto-detected by the classifier's existing
    /// [`crate::util::geohash::parse_coords`] gate, unchanged.
    #[must_use]
    pub fn is_self_evident(self) -> bool {
        matches!(
            self,
            CoordFormat::Dms | CoordFormat::Ddm | CoordFormat::GeoUri | CoordFormat::PlusCode
        )
    }
}

/// A parsed WGS84 coordinate: decimal-degree latitude/longitude, guaranteed
/// finite and in range, tagged with the [`CoordFormat`] it came from.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct LatLon {
    /// Latitude in decimal degrees, `[-90, 90]`.
    pub lat: f64,
    /// Longitude in decimal degrees, `[-180, 180]`.
    pub lon: f64,
    /// The notation this value was recognised from.
    pub format: CoordFormat,
}

impl LatLon {
    /// The single validity gate every parse path funnels through: finite and in
    /// range, else `None`. (`0,0` is intentionally *kept* here — Null-Island
    /// filtering is an output-policy concern for provider responses
    /// [`crate::util::geo::is_valid_coords`], not an input-parsing one, matching
    /// the existing `geo`/`geohash` seed parsers.)
    fn checked(lat: f64, lon: f64, format: CoordFormat) -> Option<Self> {
        (lat.is_finite()
            && lon.is_finite()
            && (-90.0..=90.0).contains(&lat)
            && (-180.0..=180.0).contains(&lon))
        .then_some(Self { lat, lon, format })
    }
}

/// Parse any supported coordinate notation into a validated [`LatLon`].
///
/// Total and panic-free for arbitrary input. Returns `None` when no notation
/// matches or the value is out of range.
///
/// ```
/// use huntsman_search_engine::util::geo::coords::{parse, CoordFormat};
///
/// let p = parse("27°28'35.8\"S 153°00'59.8\"E").unwrap();
/// assert!((p.lat - -27.476611).abs() < 1e-5);
/// assert!((p.lon - 153.016611).abs() < 1e-5);
/// assert_eq!(p.format, CoordFormat::Dms);
///
/// assert!(parse("not a coordinate").is_none());
/// ```
#[must_use]
pub fn parse(input: &str) -> Option<LatLon> {
    let s = input.trim();
    // Bound the work an arbitrary string can trigger (the scanners are linear,
    // but this keeps the totality property cheap and the function constant-ish).
    if s.is_empty() || s.len() > 256 {
        return None;
    }
    // Order: most-distinctive markers first, the handle-shaped Maidenhead last,
    // so no notation can steal another's input.
    parse_geo_uri(s)
        .or_else(|| parse_plus_code(s))
        .or_else(|| parse_dms(s))
        .or_else(|| parse_decimal_pair(s))
        .or_else(|| parse_maidenhead(s))
}

// ───────────────────────────── geo: URI (RFC 5870) ─────────────────────────

/// `geo:<lat>,<lon>[,<alt>][;<params>]` — strip the scheme and any `;`
/// parameters / altitude, then read the decimal pair.
fn parse_geo_uri(s: &str) -> Option<LatLon> {
    let rest = match s.get(..4) {
        Some(p) if p.eq_ignore_ascii_case("geo:") => &s[4..],
        _ => return None,
    };
    let coords = rest.split(';').next()?; // drop ;u=, ;crs=, …
    let mut it = coords.split(',');
    let lat: f64 = it.next()?.trim().parse().ok()?;
    let lon: f64 = it.next()?.trim().parse().ok()?;
    // a third field (altitude) is allowed and ignored; more is malformed
    if it.next().is_some() && it.next().is_some() {
        return None;
    }
    LatLon::checked(lat, lon, CoordFormat::GeoUri)
}

// ───────────────────────────── decimal pair ────────────────────────────────

/// Bare signed decimals separated by a comma or whitespace: `"-27.47,153.02"`
/// or `"-27.47 153.02"`. Rejects anything that isn't exactly two finite numbers.
fn parse_decimal_pair(s: &str) -> Option<LatLon> {
    let (a, b) = split_pair(s)?;
    let lat: f64 = a.trim().parse().ok()?;
    let lon: f64 = b.trim().parse().ok()?;
    LatLon::checked(lat, lon, CoordFormat::Decimal)
}

/// Split into exactly two non-empty halves on a single comma, else on
/// whitespace. `None` if the shape isn't a clean pair.
fn split_pair(s: &str) -> Option<(&str, &str)> {
    if let Some((a, b)) = s.split_once(',') {
        return (!a.trim().is_empty() && !b.trim().is_empty() && !b.contains(','))
            .then_some((a, b));
    }
    let mut it = s.split_whitespace();
    let a = it.next()?;
    let b = it.next()?;
    it.next().is_none().then_some((a, b))
}

// ───────────────────────────── DMS / DDM / DD-with-hemisphere ───────────────

fn is_deg_mark(c: char) -> bool {
    matches!(c, '\u{00B0}' | '\u{00BA}') // ° º
}
fn is_min_mark(c: char) -> bool {
    matches!(c, '\'' | '\u{2032}' | '\u{2019}' | '`') // ' ′ ’ `
}
fn is_sec_mark(c: char) -> bool {
    matches!(c, '"' | '\u{2033}' | '\u{201D}') // " ″ ”
}
/// `(is_latitude, is_negative)` for an N/S/E/W hemisphere letter.
fn hemisphere(c: char) -> Option<(bool, bool)> {
    match c.to_ascii_uppercase() {
        'N' => Some((true, false)),
        'S' => Some((true, true)),
        'E' => Some((false, false)),
        'W' => Some((false, true)),
        _ => None,
    }
}

fn has_dms_marker(s: &str) -> bool {
    s.chars()
        .any(|c| is_deg_mark(c) || is_min_mark(c) || is_sec_mark(c) || hemisphere(c).is_some())
}

/// A character that may legitimately appear in a DMS/DDM coordinate string.
/// Guards the DMS path against junk that merely *contains* an N/S/E/W letter
/// (e.g. the `e` in `geo:` or arbitrary words), which would otherwise be read
/// as a hemisphere and let stray numbers through as a false coordinate.
fn is_dms_char(c: char) -> bool {
    c.is_ascii_digit()
        || c.is_whitespace()
        || matches!(c, '.' | '+' | '-' | ',')
        || is_deg_mark(c)
        || is_min_mark(c)
        || is_sec_mark(c)
        || hemisphere(c).is_some()
}

/// One side of a coordinate after splitting: its signed magnitude in degrees,
/// the axis its hemisphere letter pins it to (if any), and how deep the
/// notation went (for the [`CoordFormat`] tag).
struct Side {
    value: f64,
    axis_is_lat: Option<bool>,
    used_min: bool,
    used_sec: bool,
}

/// Parse DMS/DDM/DD that carries degree glyphs and/or hemisphere letters.
/// Returns `None` for input with no such marker (so a bare `"a b"`/`"a,b"`
/// decimal pair is left to [`parse_decimal_pair`]).
fn parse_dms(s: &str) -> Option<LatLon> {
    if !has_dms_marker(s) || !s.chars().all(is_dms_char) {
        return None;
    }

    // Split into the latitude side and longitude side. A comma is the strongest
    // delimiter; otherwise the hemisphere letters delimit; otherwise (glyphs but
    // no comma/hemisphere) the numeric tokens are halved.
    let (lhs, rhs) = if let Some((a, b)) = s.split_once(',') {
        (parse_side(a)?, parse_side(b)?)
    } else if let Some((a, b)) = split_on_hemisphere(s) {
        (parse_side(a)?, parse_side(b)?)
    } else {
        return parse_dms_halved(s);
    };

    combine(lhs, rhs)
}

/// Combine two parsed sides into a validated [`LatLon`], honouring N/S/E/W axis
/// assignment and rejecting contradictions (two latitudes, etc.).
fn combine(lhs: Side, rhs: Side) -> Option<LatLon> {
    let (lat_side, lon_side) = match (lhs.axis_is_lat, rhs.axis_is_lat) {
        // Both pinned: must be one lat and one lon.
        (Some(true), Some(false)) => (lhs, rhs),
        (Some(false), Some(true)) => (rhs, lhs),
        (Some(_), Some(_)) => return None, // two N/S or two E/W
        // One pinned: it claims its axis, the other takes the complement.
        (Some(true), None) => (lhs, rhs),
        (Some(false), None) => (rhs, lhs),
        (None, Some(true)) => (rhs, lhs),
        (None, Some(false)) => (lhs, rhs),
        // Neither pinned: latitude first, by convention.
        (None, None) => (lhs, rhs),
    };
    let format = if lat_side.used_sec || lon_side.used_sec {
        CoordFormat::Dms
    } else if lat_side.used_min || lon_side.used_min {
        CoordFormat::Ddm
    } else {
        CoordFormat::Dms // degrees-only but glyph/hemisphere-marked
    };
    LatLon::checked(lat_side.value, lon_side.value, format)
}

/// Split a hemisphere-delimited string (no comma) into two sides. Handles both
/// suffix (`33°S 151°E`) and prefix (`N33° E151°`) placement.
fn split_on_hemisphere(s: &str) -> Option<(&str, &str)> {
    let hemis: Vec<usize> = s
        .char_indices()
        .filter(|(_, c)| hemisphere(*c).is_some())
        .map(|(i, _)| i)
        .collect();
    let &first = hemis.first()?;
    // Suffix style if a digit/glyph (not whitespace) immediately precedes the
    // first hemisphere letter; otherwise treat it as a prefix.
    let preceded_by_value = s[..first].trim_end().chars().next_back().is_some_and(|c| {
        c.is_ascii_digit() || c == '.' || is_deg_mark(c) || is_min_mark(c) || is_sec_mark(c)
    });
    if preceded_by_value {
        // Cut just after the first hemisphere letter.
        let cut = first + s[first..].chars().next()?.len_utf8();
        Some((&s[..cut], &s[cut..]))
    } else if hemis.len() >= 2 {
        // Prefix style: the second letter begins the longitude side.
        let second = hemis[1];
        Some((&s[..second], &s[second..]))
    } else {
        None
    }
}

/// Parse one side: extract its (single) hemisphere letter and leading sign, then
/// read up to three numbers as degrees / minutes / seconds.
fn parse_side(s: &str) -> Option<Side> {
    let mut axis_is_lat = None;
    let mut hemi_neg = false;
    let mut core = String::with_capacity(s.len());
    for c in s.chars() {
        if let Some((is_lat, neg)) = hemisphere(c) {
            if axis_is_lat.is_some() {
                return None; // two hemisphere letters on one side
            }
            axis_is_lat = Some(is_lat);
            hemi_neg = neg;
        } else {
            core.push(c);
        }
    }
    let (magnitude, neg_sign, used_min, used_sec) = read_dms_numbers(&core)?;
    // A hemisphere letter and an explicit minus must not *both* claim the sign;
    // if a hemisphere is present it wins (a leading '-' with 'S' is degenerate).
    let value = if axis_is_lat.is_some() {
        if hemi_neg { -magnitude } else { magnitude }
    } else if neg_sign {
        -magnitude
    } else {
        magnitude
    };
    Some(Side {
        value,
        axis_is_lat,
        used_min,
        used_sec,
    })
}

/// Glyph-marked DMS with no comma and no hemisphere letters
/// (`33°52'12" 151°12'33"`): collect every numeric token across the whole
/// string and split them in half — first half latitude, second longitude.
fn parse_dms_halved(s: &str) -> Option<LatLon> {
    let tokens = scan_numbers(s);
    let n = tokens.len();
    if n < 2 || !n.is_multiple_of(2) {
        return None;
    }
    let (lat_v, lat_min, lat_sec) = fold_numbers(&tokens[..n / 2])?;
    let (lon_v, lon_min, lon_sec) = fold_numbers(&tokens[n / 2..])?;
    let lhs = Side {
        value: lat_v,
        axis_is_lat: None,
        used_min: lat_min,
        used_sec: lat_sec,
    };
    let rhs = Side {
        value: lon_v,
        axis_is_lat: None,
        used_min: lon_min,
        used_sec: lon_sec,
    };
    combine(lhs, rhs)
}

/// A scanned number plus the unit its trailing glyph declared (if any).
#[derive(Clone, Copy)]
struct NumTok {
    value: f64,
    /// `0` degrees, `1` minutes, `2` seconds, `None` = inferred by position.
    unit: Option<u8>,
}

/// Read one side's `core` (hemisphere already removed) into degrees, honouring
/// any leading sign and glyph-declared units. Returns
/// `(magnitude, is_negative, used_minutes, used_seconds)`.
fn read_dms_numbers(core: &str) -> Option<(f64, bool, bool, bool)> {
    let neg = core.trim_start().starts_with('-');
    let tokens = scan_numbers(core);
    if tokens.is_empty() {
        return None;
    }
    let (mag, used_min, used_sec) = fold_numbers(&tokens)?;
    Some((mag.abs(), neg, used_min, used_sec))
}

/// Scan a string into its numeric tokens, tagging each with the unit declared by
/// the glyph that follows it (° / ′ / ″). Stray characters are separators.
fn scan_numbers(s: &str) -> Vec<NumTok> {
    let chars: Vec<char> = s.chars().collect();
    let mut out = Vec::new();
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if c.is_ascii_digit() || c == '.' || ((c == '-' || c == '+') && starts_number(&chars, i)) {
            let start = i;
            if c == '-' || c == '+' {
                i += 1;
            }
            let mut seen_dot = false;
            while i < chars.len() && (chars[i].is_ascii_digit() || (chars[i] == '.' && !seen_dot)) {
                if chars[i] == '.' {
                    seen_dot = true;
                }
                i += 1;
            }
            let text: String = chars[start..i].iter().collect();
            let Ok(value) = text.parse::<f64>() else {
                continue;
            };
            // Look past spaces for a unit glyph.
            let mut j = i;
            while j < chars.len() && chars[j] == ' ' {
                j += 1;
            }
            let unit = chars.get(j).and_then(|&g| {
                if is_deg_mark(g) {
                    Some(0)
                } else if is_min_mark(g) {
                    Some(1)
                } else if is_sec_mark(g) {
                    Some(2)
                } else {
                    None
                }
            });
            if unit.is_some() {
                i = j + 1;
            }
            out.push(NumTok { value, unit });
        } else {
            i += 1;
        }
    }
    out
}

/// True if a `+`/`-` at `i` begins a number (a digit or dot follows it).
fn starts_number(chars: &[char], i: usize) -> bool {
    chars
        .get(i + 1)
        .is_some_and(|&n| n.is_ascii_digit() || n == '.')
}

/// Fold up to three tokens into one decimal-degree magnitude:
/// `deg + min/60 + sec/3600`. Glyph-declared units win; unmarked tokens fall
/// into the next free degree→minute→second slot. Returns
/// `(value, used_minutes, used_seconds)`.
fn fold_numbers(tokens: &[NumTok]) -> Option<(f64, bool, bool)> {
    let mut deg = None;
    let mut min = None;
    let mut sec = None;
    let mut next_ordinal = 0u8;
    for t in tokens {
        let unit = match t.unit {
            Some(u) => {
                next_ordinal = u + 1;
                u
            }
            None => {
                let u = next_ordinal;
                next_ordinal += 1;
                u
            }
        };
        let slot = match unit {
            0 => &mut deg,
            1 => &mut min,
            2 => &mut sec,
            _ => return None, // more than three components
        };
        if slot.is_some() {
            return None; // same unit twice
        }
        *slot = Some(t.value);
    }
    let d = deg?;
    // Minutes/seconds carry no independent sign; the degree term owns it.
    let m = min.unwrap_or(0.0);
    let sc = sec.unwrap_or(0.0);
    if !(0.0..60.0).contains(&m) || !(0.0..60.0).contains(&sc) {
        return None;
    }
    let value = d.abs() + m / 60.0 + sc / 3600.0;
    let value = if d.is_sign_negative() { -value } else { value };
    Some((value, min.is_some(), sec.is_some()))
}

// ───────────────────────────── Maidenhead grid locator ─────────────────────

/// Decode a 4/6/8-character Maidenhead locator to the **centre** of its cell.
/// Layout: field (2 letters `A`–`R`), square (2 digits), subsquare (2 letters
/// `a`–`x`), extended square (2 digits).
fn parse_maidenhead(s: &str) -> Option<LatLon> {
    let t = s.trim();
    let chars: Vec<char> = t.chars().collect();
    if !matches!(chars.len(), 4 | 6 | 8) {
        return None;
    }
    // longitude spans 360° (×2 of latitude's 180°) at every level.
    let mut lon = -180.0;
    let mut lat = -90.0;
    let mut lon_cell = 360.0;
    let mut lat_cell = 180.0;

    // Field: A–R (18 columns lon, 18 rows lat).
    let f0 = field_index(chars[0])?;
    let f1 = field_index(chars[1])?;
    lon_cell /= 18.0;
    lat_cell /= 18.0;
    lon += f64::from(f0) * lon_cell;
    lat += f64::from(f1) * lat_cell;

    // Square: 0–9.
    let s0 = digit_index(chars[2])?;
    let s1 = digit_index(chars[3])?;
    lon_cell /= 10.0;
    lat_cell /= 10.0;
    lon += f64::from(s0) * lon_cell;
    lat += f64::from(s1) * lat_cell;

    if chars.len() >= 6 {
        // Subsquare: a–x (24).
        let ss0 = subsquare_index(chars[4])?;
        let ss1 = subsquare_index(chars[5])?;
        lon_cell /= 24.0;
        lat_cell /= 24.0;
        lon += f64::from(ss0) * lon_cell;
        lat += f64::from(ss1) * lat_cell;
    }
    if chars.len() == 8 {
        // Extended square: 0–9.
        let e0 = digit_index(chars[6])?;
        let e1 = digit_index(chars[7])?;
        lon_cell /= 10.0;
        lat_cell /= 10.0;
        lon += f64::from(e0) * lon_cell;
        lat += f64::from(e1) * lat_cell;
    }

    // Centre of the final cell.
    LatLon::checked(
        lat + lat_cell / 2.0,
        lon + lon_cell / 2.0,
        CoordFormat::Maidenhead,
    )
}

fn field_index(c: char) -> Option<u32> {
    let u = c.to_ascii_uppercase();
    ('A'..='R').contains(&u).then(|| u as u32 - 'A' as u32)
}
fn digit_index(c: char) -> Option<u32> {
    c.to_digit(10)
}
fn subsquare_index(c: char) -> Option<u32> {
    let l = c.to_ascii_lowercase();
    ('a'..='x').contains(&l).then(|| l as u32 - 'a' as u32)
}

// ───────────────────────────── Open Location Code (Plus Codes) ─────────────

const OLC_ALPHABET: &[u8; 20] = b"23456789CFGHJMPQRVWX";
const OLC_SEPARATOR: char = '+';
const OLC_GRID_ROWS: f64 = 5.0;
const OLC_GRID_COLS: f64 = 4.0;

/// Index of an OLC digit in the base-20 alphabet (case-insensitive).
fn olc_index(c: char) -> Option<usize> {
    let u = c.to_ascii_uppercase() as u8;
    OLC_ALPHABET.iter().position(|&a| a == u)
}

/// Decode a **full** Open Location Code (Plus Code) to the centre of its cell.
///
/// Full codes carry the `+` separator after the eighth digit. The first ten
/// digits are latitude/longitude base-20 pairs at shrinking resolution; any
/// further digits refine within a 5×4 (lat×lon) grid. Short/padded codes
/// (those needing a reference location) are intentionally not accepted here —
/// they are not absolute coordinates.
fn parse_plus_code(s: &str) -> Option<LatLon> {
    let t = s.trim();
    let sep = t.find(OLC_SEPARATOR)?;
    // Separator must sit at position 8 for an absolute (full) code, and the code
    // must not be padded with '0'.
    if sep != 8 || t.contains('0') {
        return None;
    }
    let digits: Vec<char> = t.chars().filter(|&c| c != OLC_SEPARATOR).collect();
    // 8 digits before '+' plus ≥ 2 after = ≥ 10; cap the refinement we honour.
    if !(10..=15).contains(&digits.len()) {
        return None;
    }

    let mut lat = -90.0_f64;
    let mut lon = -180.0_f64;
    let mut lat_res = 20.0_f64;
    let mut lon_res = 20.0_f64;

    // Pair section: up to five (lat, lon) pairs = ten digits.
    let pair_len = digits.len().min(10);
    let mut i = 0;
    while i < pair_len {
        lat += olc_index(digits[i])? as f64 * lat_res;
        lon += olc_index(digits[i + 1])? as f64 * lon_res;
        if i + 2 < pair_len {
            lat_res /= 20.0;
            lon_res /= 20.0;
        }
        i += 2;
    }
    // The cell size at the end of the pair section is the last applied resolution.
    let mut lat_cell = lat_res;
    let mut lon_cell = lon_res;

    // Grid refinement section (digits 11+): each digit picks a row/col in a 5×4
    // grid, shrinking the cell by 5 (lat) and 4 (lon) each step.
    for &d in &digits[pair_len..] {
        lat_cell /= OLC_GRID_ROWS;
        lon_cell /= OLC_GRID_COLS;
        let v = olc_index(d)?;
        let row = (v as f64 / OLC_GRID_COLS).floor();
        let col = (v as f64 % OLC_GRID_COLS).floor();
        lat += row * lat_cell;
        lon += col * lon_cell;
    }

    LatLon::checked(
        lat + lat_cell / 2.0,
        lon + lon_cell / 2.0,
        CoordFormat::PlusCode,
    )
}

#[cfg(test)]
mod tests;
