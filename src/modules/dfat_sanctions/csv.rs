//! A minimal, allocation-conscious RFC 4180 CSV reader — just enough to parse
//! the DFAT Consolidated List export, with **no `csv` crate dependency** (the
//! project pins a deliberately small, Termux-viable dependency tree; see the
//! workspace conventions). It handles the three structural cases the DFAT export
//! actually uses:
//!
//!   * quoted fields (`"…"`) that may contain commas, CR/LF and `""` escapes,
//!   * bare fields,
//!   * CRLF *or* LF row terminators (the export is Windows-authored),
//!
//! and nothing more. It is pure and total: it never panics and never allocates
//! per-character beyond the field/row vectors it returns.

/// Parse a whole CSV document into rows of owned string fields. A row inside a
/// quoted field (an embedded newline) does not terminate the record — quotes are
/// tracked across line boundaries, so an `Address` cell spanning lines stays one
/// field. A trailing newline does not yield a spurious empty final row.
#[must_use]
pub(super) fn parse(input: &str) -> Vec<Vec<String>> {
    let mut rows: Vec<Vec<String>> = Vec::new();
    let mut row: Vec<String> = Vec::new();
    let mut field = String::new();
    let mut in_quotes = false;
    // `produced` tracks whether the current line has emitted any field/quote, so a
    // bare trailing newline doesn't append an empty record.
    let mut produced = false;

    let mut chars = input.chars().peekable();
    while let Some(c) = chars.next() {
        if in_quotes {
            match c {
                '"' => {
                    // A doubled quote inside a quoted field is a literal quote;
                    // a lone quote closes the field.
                    if chars.peek() == Some(&'"') {
                        field.push('"');
                        chars.next();
                    } else {
                        in_quotes = false;
                    }
                }
                other => field.push(other),
            }
            continue;
        }
        match c {
            '"' => {
                in_quotes = true;
                produced = true;
            }
            ',' => {
                row.push(std::mem::take(&mut field));
                produced = true;
            }
            '\r' => {
                // Swallow a following '\n' so CRLF is one terminator.
                if chars.peek() == Some(&'\n') {
                    chars.next();
                }
                if produced {
                    row.push(std::mem::take(&mut field));
                    rows.push(std::mem::take(&mut row));
                }
                produced = false;
            }
            '\n' => {
                if produced {
                    row.push(std::mem::take(&mut field));
                    rows.push(std::mem::take(&mut row));
                }
                produced = false;
            }
            other => {
                field.push(other);
                produced = true;
            }
        }
    }
    // Flush a final unterminated row (no trailing newline).
    if produced {
        row.push(field);
        rows.push(row);
    }
    rows
}

/// Index the header row: a map from each (trimmed, lower-cased) column name to
/// its position, so the entity transform reads columns by name and is immune to
/// column reordering in a future DFAT re-export.
#[must_use]
pub(super) fn header_index(header: &[String]) -> std::collections::HashMap<String, usize> {
    header
        .iter()
        .enumerate()
        .map(|(i, h)| (h.trim().to_ascii_lowercase(), i))
        .collect()
}
