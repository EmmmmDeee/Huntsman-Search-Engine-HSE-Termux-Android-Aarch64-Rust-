//! The envelope every Network Survey CSV export shares, and the bounded RFC4180 CSV parser
//! under it, for the offline radio survey importers (Bluetooth, Wi-Fi, LTE and NR). This layer
//! has no dependencies on cellular, Wi-Fi or Bluetooth collectors.
//!
//! It answers with a [`Refusal`], never a worded error: each importer words the reason under
//! its own label, so an NR export's fault is reported as an NR one.

use std::collections::BTreeMap;

pub const MAX_SURVEY_CSV_BYTES: u64 = 262_144;

/// Why an export was refused before its header was checked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Refusal {
    TooLarge,
    NotUtf8,
    DuplicateVersion,
    UnsupportedVersion,
    /// The CSV itself is malformed, for this reason.
    Csv(&'static str),
    NoHeader,
}

impl Refusal {
    /// The reason, for the importer to word under its own label.
    pub(crate) const fn reason(self) -> &'static str {
        match self {
            Self::TooLarge => "input exceeds 256 KiB",
            Self::NotUtf8 => "not UTF-8",
            Self::DuplicateVersion => "duplicate CSV version",
            Self::UnsupportedVersion => "missing or unsupported CSV version",
            Self::Csv(reason) => reason,
            Self::NoHeader => "missing header",
        }
    }
}

/// An export read as far as its records: the header row, and the rows after it.
pub(crate) struct Export {
    pub(crate) header: Vec<String>,
    pub(crate) rows: std::vec::IntoIter<Vec<String>>,
}

/// Read the envelope of an export that must be CSV version `version`: at most
/// [`MAX_SURVEY_CSV_BYTES`] of UTF-8, leading `#` comment lines of which exactly one is
/// `# CSV Version=<version>`, then CSV whose first row is the header.
pub(crate) fn read_export(bytes: &[u8], version: &str) -> Result<Export, Refusal> {
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MAX_SURVEY_CSV_BYTES {
        return Err(Refusal::TooLarge);
    }
    let text = std::str::from_utf8(bytes).map_err(|_| Refusal::NotUtf8)?;
    let mut offset = 0;
    let mut declared = None;
    for line in text.split_inclusive('\n') {
        let trimmed = line.trim_end_matches(['\r', '\n']);
        if !trimmed.starts_with('#') {
            break;
        }
        if let Some(value) = trimmed.strip_prefix("# CSV Version=") {
            if declared.replace(value.trim()).is_some() {
                return Err(Refusal::DuplicateVersion);
            }
        }
        offset += line.len();
    }
    if declared != Some(version) {
        return Err(Refusal::UnsupportedVersion);
    }
    let mut rows = csv_rows(&text[offset..]).map_err(Refusal::Csv)?.into_iter();
    let header = rows.next().ok_or(Refusal::NoHeader)?;
    Ok(Export { header, rows })
}

/// The column of each name in `expected`, when the header row is `expected` exactly.
pub(crate) fn exact_columns(
    header: &[String],
    expected: &[&'static str],
) -> Option<BTreeMap<&'static str, usize>> {
    (header.len() == expected.len()
        && header
            .iter()
            .zip(expected)
            .all(|(actual, name)| actual == name))
    .then(|| {
        expected
            .iter()
            .enumerate()
            .map(|(index, name)| (*name, index))
            .collect()
    })
}

/// A field whose text is present but is not a value its column allows. The importers refuse the
/// row that holds one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct InvalidField;

/// The text of the column `name` in `row`, or `""` when the export has no such column or the row
/// stops short of it. **Pure.**
pub(crate) fn column<'a>(
    row: &'a [String],
    columns: &BTreeMap<&str, usize>,
    name: &str,
) -> &'a str {
    columns
        .get(name)
        .and_then(|index| row.get(*index))
        .map_or("", String::as_str)
}

/// An optional whole number of at most `max`: `None` when `raw` is empty, refused unless it is
/// ASCII digits alone (no sign, space or point) that fit. **Pure.**
pub(crate) fn optional_number(raw: &str, max: u64) -> Result<Option<u64>, InvalidField> {
    if raw.is_empty() {
        return Ok(None);
    }
    if !raw.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(InvalidField);
    }
    raw.parse::<u64>()
        .ok()
        .filter(|value| *value <= max)
        .map(Some)
        .ok_or(InvalidField)
}

/// An optional finite measurement within `low..=high`: `None` when `raw` is empty. **Pure.**
pub(crate) fn optional_finite(raw: &str, low: f64, high: f64) -> Result<Option<f64>, InvalidField> {
    if raw.is_empty() {
        return Ok(None);
    }
    let value = raw.parse::<f64>().map_err(|_| InvalidField)?;
    (value.is_finite() && (low..=high).contains(&value))
        .then_some(Some(value))
        .ok_or(InvalidField)
}

/// The largest horizontal accuracy, in metres, a reported fix may claim: beyond 100 km the point
/// says nothing about where a radio was heard.
const MAX_FIX_ACCURACY_M: f64 = 100_000.0;

/// A row's reported fix: its latitude, longitude and horizontal accuracy in metres, kept only when
/// all three parse, the point is a real fix ([`crate::geohash::valid_fix`]: in range, and not the
/// 0°, 0° a device writes when it has none) and the accuracy is finite, positive and at most
/// 100 km. Otherwise none of the three is kept. Every Network Survey importer reads its location
/// here. **Pure.**
#[must_use]
pub(crate) fn reported_fix(
    latitude: &str,
    longitude: &str,
    accuracy: &str,
) -> (Option<f64>, Option<f64>, Option<f64>) {
    match (
        latitude.parse::<f64>().ok(),
        longitude.parse::<f64>().ok(),
        accuracy.parse::<f64>().ok(),
    ) {
        (Some(lat), Some(lon), Some(accuracy))
            if crate::geohash::valid_fix(lat, lon)
                && accuracy.is_finite()
                && accuracy > 0.0
                && accuracy <= MAX_FIX_ACCURACY_M =>
        {
            (Some(lat), Some(lon), Some(accuracy))
        }
        _ => (None, None, None),
    }
}

/// Optional text of at most `max_bytes`: `None` when `raw` is empty. **Pure.**
pub(crate) fn optional_text(raw: &str, max_bytes: usize) -> Result<Option<String>, InvalidField> {
    if raw.len() > max_bytes {
        return Err(InvalidField);
    }
    Ok((!raw.is_empty()).then(|| raw.to_owned()))
}

/// RFC4180-style records, including quoted commas, escaped quotes and newlines.
/// Input, field, row and column counts are all bounded.
///
/// # Errors
/// Why the input is not such CSV.
pub(crate) fn csv_rows(input: &str) -> Result<Vec<Vec<String>>, &'static str> {
    let mut chars = input.chars().peekable();
    let mut rows = Vec::new();
    let mut row = Vec::new();
    let mut field = String::new();
    let mut quoted = false;
    let mut closed = false;
    while let Some(ch) = chars.next() {
        if quoted {
            if ch == '"' {
                if chars.peek() == Some(&'"') {
                    chars.next();
                    field.push('"');
                } else {
                    quoted = false;
                    closed = true;
                }
            } else {
                field.push(ch);
            }
        } else {
            match ch {
                '"' if field.is_empty() && !closed => quoted = true,
                '"' => return Err("unexpected quote"),
                ',' => {
                    row.push(std::mem::take(&mut field));
                    closed = false;
                }
                '\n' => {
                    row.push(std::mem::take(&mut field));
                    rows.push(std::mem::take(&mut row));
                    closed = false;
                }
                '\r' if chars.peek() == Some(&'\n') => {
                    chars.next();
                    row.push(std::mem::take(&mut field));
                    rows.push(std::mem::take(&mut row));
                    closed = false;
                }
                '\r' => return Err("bare carriage return"),
                _ if closed => return Err("text after quoted field"),
                _ => field.push(ch),
            }
        }
        if field.len() > 4096 || row.len() > 32 || rows.len() > 4097 {
            return Err("CSV field or record limit exceeded");
        }
    }
    if quoted {
        return Err("unterminated quoted field");
    }
    if !field.is_empty() || !row.is_empty() || closed {
        row.push(field);
        rows.push(row);
    }
    Ok(rows)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A reported fix is all three fields or none: a point that is not a real fix (out of range,
    /// or the 0°, 0° a device writes without one) or an accuracy that is not finite, positive and
    /// at most 100 km keeps no location at all.
    #[test]
    fn a_reported_fix_is_a_real_point_with_a_bounded_accuracy_or_nothing() {
        let none = (None, None, None);
        assert_eq!(
            reported_fix("-27.4698", "153.0251", "22"),
            (Some(-27.4698), Some(153.0251), Some(22.0))
        );
        assert_eq!(
            reported_fix("-27.4698", "153.0251", "100000"),
            (Some(-27.4698), Some(153.0251), Some(100_000.0))
        );
        for (lat, lon, accuracy) in [
            ("0", "0", "22"),
            ("0.0", "-0.0", "5"),
            ("90.5", "0", "22"),
            ("-27.4698", "180.5", "22"),
            ("-27.4698", "153.0251", "0"),
            ("-27.4698", "153.0251", "-5"),
            ("-27.4698", "153.0251", "100000.5"),
            ("-27.4698", "153.0251", "NaN"),
            ("-27.4698", "153.0251", "inf"),
            ("-27.4698", "153.0251", ""),
            ("", "153.0251", "22"),
            ("NaN", "153.0251", "22"),
        ] {
            assert_eq!(
                reported_fix(lat, lon, accuracy),
                none,
                "{lat},{lon},{accuracy}"
            );
        }
    }

    /// The field readers every importer shares: an empty field is absent, and a present one is
    /// read exactly or refused, never coerced.
    #[test]
    fn a_number_is_digits_alone_within_its_bound() {
        assert_eq!(optional_number("", 9), Ok(None));
        assert_eq!(optional_number("0", 9), Ok(Some(0)));
        assert_eq!(optional_number("009", 9), Ok(Some(9)));
        assert_eq!(
            optional_number("18446744073709551615", u64::MAX),
            Ok(Some(u64::MAX))
        );
        for refused in [
            "10",
            "-1",
            "+1",
            " 1",
            "1 ",
            "1.0",
            "1e3",
            "0x1",
            "18446744073709551616",
        ] {
            assert_eq!(optional_number(refused, 9), Err(InvalidField), "{refused}");
        }
    }

    #[test]
    fn a_measurement_is_finite_and_within_its_range() {
        assert_eq!(optional_finite("", -1.0, 1.0), Ok(None));
        assert_eq!(optional_finite("-1", -1.0, 1.0), Ok(Some(-1.0)));
        assert_eq!(optional_finite("0.5", -1.0, 1.0), Ok(Some(0.5)));
        for refused in ["1.01", "-1.5", "NaN", "inf", "-inf", "x", " 0"] {
            assert_eq!(
                optional_finite(refused, -1.0, 1.0),
                Err(InvalidField),
                "{refused}"
            );
        }
    }

    #[test]
    fn text_is_absent_when_empty_and_refused_past_its_bound() {
        assert_eq!(optional_text("", 3), Ok(None));
        assert_eq!(optional_text("abc", 3), Ok(Some("abc".to_owned())));
        assert_eq!(optional_text("abcd", 3), Err(InvalidField));
        // The bound counts bytes, so a multi-byte character counts in full.
        assert_eq!(optional_text("\u{e9}\u{e9}", 3), Err(InvalidField));
    }

    #[test]
    fn a_missing_column_or_a_short_row_reads_as_empty() {
        let columns: BTreeMap<&str, usize> = [("a", 0), ("b", 1), ("c", 5)].into_iter().collect();
        let row = vec!["1".to_owned(), "two".to_owned()];
        assert_eq!(column(&row, &columns, "a"), "1");
        assert_eq!(column(&row, &columns, "b"), "two");
        assert_eq!(column(&row, &columns, "c"), "");
        assert_eq!(column(&row, &columns, "absent"), "");
    }
}
