//! Canonical bounded RFC4180 CSV parser shared by offline radio survey importers.
//! This layer has no dependencies on cellular, Wi-Fi or Bluetooth collectors.

use crate::error::Error;

pub const MAX_SURVEY_CSV_BYTES: u64 = 262_144;

// Preserve the historical LTE error wording for existing callers. Wi-Fi and
// Bluetooth adapters remap CSV parse errors to their own source-specific errors.
fn invalid(message: &str) -> Error {
    Error::Invalid(format!("Network Survey LTE CSV: {message}"))
}

/// RFC4180-style records, including quoted commas, escaped quotes and newlines.
/// Input, field, row and column counts are all bounded.
pub(crate) fn csv_rows(input: &str) -> Result<Vec<Vec<String>>, Error> {
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
                '"' => return Err(invalid("unexpected quote")),
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
                '\r' => return Err(invalid("bare carriage return")),
                _ if closed => return Err(invalid("text after quoted field")),
                _ => field.push(ch),
            }
        }
        if field.len() > 4096 || row.len() > 32 || rows.len() > 4097 {
            return Err(invalid("CSV field or record limit exceeded"));
        }
    }
    if quoted {
        return Err(invalid("unterminated quoted field"));
    }
    if !field.is_empty() || !row.is_empty() || closed {
        row.push(field);
        rows.push(row);
    }
    Ok(rows)
}
