//! Minimal RFC-4180-ish CSV row/field tokenizer, dependency-free. Sufficient
//! for the small in-memory buffers HSE parses with it — its own entity
//! exports and pasted-in DeHashed exports — so pulling in the `csv` crate
//! (already a dependency for [`crate::util::document_parse::csv_parse`]'s
//! file-backed reader) isn't worth it for a few KB of string already in hand.
//!
//! Handles double-quoted fields that may contain commas, embedded newlines,
//! and doubled `""`-escaped quotes; both CRLF and bare LF line endings are
//! accepted.

/// Split a full CSV document into rows of fields. A trailing row with no
/// final newline is still captured.
pub fn parse_rows(body: &str) -> Vec<Vec<String>> {
    let mut rows = Vec::new();
    let mut row: Vec<String> = Vec::new();
    let mut field = String::new();
    let mut in_quotes = false;
    let mut chars = body.chars().peekable();

    while let Some(c) = chars.next() {
        if in_quotes {
            if c == '"' {
                if chars.peek() == Some(&'"') {
                    field.push('"');
                    chars.next();
                } else {
                    in_quotes = false;
                }
            } else {
                field.push(c);
            }
        } else {
            match c {
                '"' => in_quotes = true,
                ',' => row.push(std::mem::take(&mut field)),
                '\r' => {}
                '\n' => {
                    row.push(std::mem::take(&mut field));
                    rows.push(std::mem::take(&mut row));
                }
                _ => field.push(c),
            }
        }
    }
    // Trailing field/row when the body has no final newline.
    if !field.is_empty() || !row.is_empty() {
        row.push(field);
        rows.push(row);
    }
    rows
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splits_plain_fields() {
        assert_eq!(parse_rows("a,b,c"), vec![vec!["a", "b", "c"]]);
    }

    #[test]
    fn handles_quoted_commas_and_escaped_quotes() {
        let rows = parse_rows("\"a,b\",\"say \"\"hi\"\"\"\n");
        assert_eq!(rows, vec![vec!["a,b", "say \"hi\""]]);
    }

    #[test]
    fn handles_embedded_newline_inside_quotes() {
        let rows = parse_rows("\"line1\nline2\",b\n");
        assert_eq!(rows, vec![vec!["line1\nline2", "b"]]);
    }

    #[test]
    fn handles_crlf_and_multiple_rows() {
        let rows = parse_rows("a,b\r\nc,d\r\n");
        assert_eq!(rows, vec![vec!["a", "b"], vec!["c", "d"]]);
    }

    #[test]
    fn captures_trailing_row_without_final_newline() {
        assert_eq!(parse_rows("a,b"), vec![vec!["a", "b"]]);
    }

    #[test]
    fn empty_body_yields_no_rows() {
        assert!(parse_rows("").is_empty());
    }
}
