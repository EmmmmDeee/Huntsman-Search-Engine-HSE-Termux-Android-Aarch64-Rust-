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
