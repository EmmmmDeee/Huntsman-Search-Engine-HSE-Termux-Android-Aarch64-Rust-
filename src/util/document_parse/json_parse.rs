//! JSON and JSONL parsing.

use super::{DocumentMetadata, DocumentResult, RawDocumentText};
use crate::util::document_parse::DocumentFormat;
use serde_json::Value;
use std::fs::File;
use std::path::Path;
use tracing::debug;

/// Parse JSON file into a flat text representation.
pub fn parse_json<P: AsRef<Path>>(json_path: P) -> DocumentResult<RawDocumentText> {
    let path = json_path.as_ref();
    let path_str = path.to_string_lossy().to_string();

    debug!("Parsing JSON: {}", path_str);

    let file = File::open(path)?;
    let value: Value = serde_json::from_reader(file)?;

    let text = flatten_json_to_text(&value);
    let character_count = text.len();

    Ok(RawDocumentText {
        text,
        source_format: DocumentFormat::Json,
        confidence: 0.50, // Structured, machine-readable JSON
        metadata: DocumentMetadata {
            source_file: Some(path_str),
            character_count,
            extraction_method: "json_parse".to_string(),
            ..Default::default()
        },
    })
}

/// Parse JSONL (one JSON object per line) file.
pub fn parse_jsonl<P: AsRef<Path>>(jsonl_path: P) -> DocumentResult<RawDocumentText> {
    let path = jsonl_path.as_ref();
    let path_str = path.to_string_lossy().to_string();

    debug!("Parsing JSONL: {}", path_str);

    let file = File::open(path)?;
    let reader = std::io::BufReader::new(file);
    use std::io::BufRead;

    let mut text = String::new();
    let mut parsed = 0usize;
    let mut skipped = 0usize;
    // The first line that would not parse, kept so a file that is not JSONL at
    // all can report WHY rather than just yielding nothing.
    let mut first_err: Option<serde_json::Error> = None;

    for line in reader.lines() {
        let line = line?;
        // A blank line is structure, not data — neither parsed nor a failure.
        if line.trim().is_empty() {
            continue;
        }
        match serde_json::from_str::<Value>(&line) {
            Ok(value) => {
                parsed += 1;
                text.push_str(&flatten_json_to_text(&value));
                text.push('\n');
            }
            Err(e) => {
                skipped += 1;
                first_err.get_or_insert(e);
            }
        }
    }

    // Nothing parsed, but there WAS content: this is not a JSONL file (a UTF-16
    // export, a truncated download, plain text under a .jsonl name). Silently
    // returning empty text made that indistinguishable from a genuinely empty
    // file — `hse ingest` exited 0 reporting "0 entities", and the operator read
    // it as "this document contained nothing". Its sibling `parse_json` above
    // propagates a parse failure with `?`; this now matches, and reports the
    // first real serde error rather than a generic message.
    if parsed == 0
        && let Some(e) = first_err
    {
        return Err(e.into());
    }
    // Some lines parsed and some did not: the result is PARTIAL. Say so — an
    // undisclosed partial parse is a quietly wrong answer.
    if skipped > 0 {
        tracing::warn!(
            file = %path_str,
            parsed,
            skipped,
            "JSONL: some lines could not be parsed and contributed nothing"
        );
    }

    let character_count = text.len();

    Ok(RawDocumentText {
        text,
        source_format: DocumentFormat::Jsonl,
        confidence: 0.50, // Structured JSONL
        metadata: DocumentMetadata {
            source_file: Some(path_str),
            character_count,
            // Reports what was actually READ, not the raw line count. The old
            // string said "(N lines)" using the total, so a file whose lines all
            // failed still claimed N lines of provenance.
            extraction_method: format!("jsonl_parse ({parsed} parsed, {skipped} unparseable)"),
            ..Default::default()
        },
    })
}

/// Flatten JSON to key: value text format (breadth-first traversal).
fn flatten_json_to_text(value: &Value) -> String {
    let mut text = String::new();

    match value {
        Value::Object(map) => {
            for (key, val) in map {
                text.push_str(key);
                text.push_str(": ");
                text.push_str(&flatten_json_to_text(val));
                text.push('\n');
            }
        }
        Value::Array(arr) => {
            for (idx, item) in arr.iter().enumerate() {
                text.push_str(&format!("[{idx}]: "));
                text.push_str(&flatten_json_to_text(item));
                text.push('\n');
            }
        }
        Value::String(s) => text.push_str(s),
        Value::Number(n) => text.push_str(&n.to_string()),
        Value::Bool(b) => text.push_str(&b.to_string()),
        Value::Null => text.push_str("null"),
    }

    text
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn json_parse_basic() {
        let mut file = NamedTempFile::new().expect("should succeed");
        let json = serde_json::json!({
            "name": "John Doe",
            "email": "john@example.com",
            "age": 30
        });
        writeln!(file, "{json}").expect("should succeed");
        file.flush().expect("should succeed");

        let result = parse_json(file.path()).expect("should succeed");
        assert!(result.text.contains("John Doe"));
        assert!(result.text.contains("john@example.com"));
    }

    #[test]
    fn jsonl_parse_basic() {
        let mut file = NamedTempFile::new().expect("should succeed");
        writeln!(file, r#"{{"name":"John","email":"john@example.com"}}"#).expect("should succeed");
        writeln!(file, r#"{{"name":"Jane","email":"jane@example.com"}}"#).expect("should succeed");
        file.flush().expect("should succeed");

        let result = parse_jsonl(file.path()).expect("should succeed");
        assert!(result.text.contains("John"));
        assert!(result.text.contains("Jane"));
    }

    /// A file whose lines are not JSON at all is a MALFUNCTION, not an empty
    /// document.
    ///
    /// Every line used to be dropped with `if let Ok(..)`, so a UTF-16 export, a
    /// truncated download, or plain text under a `.jsonl` name yielded empty text
    /// and `hse ingest` exited 0 reporting "0 entities" — indistinguishable from
    /// a genuinely empty file. The sibling `parse_json` propagates a parse
    /// failure; this must too.
    #[test]
    fn jsonl_that_parses_no_line_is_an_error_not_an_empty_document() {
        let mut file = NamedTempFile::new().expect("should succeed");
        writeln!(file, "this is not json").expect("should succeed");
        writeln!(file, "neither is this").expect("should succeed");
        file.flush().expect("should succeed");

        let err = parse_jsonl(file.path())
            .expect_err("a file with no parseable line must not report success");
        // The real serde error is carried, not a generic message.
        assert!(
            matches!(
                err,
                crate::util::document_parse::DocumentParseError::JsonError(_)
            ),
            "expected the underlying JSON error, got {err:?}"
        );
    }

    /// A partial parse must be disclosed in the provenance, not rounded up to a
    /// clean read. The old `extraction_method` printed the TOTAL line count, so a
    /// file whose lines mostly failed still claimed N lines of provenance.
    #[test]
    fn jsonl_reports_what_it_actually_parsed() {
        let mut file = NamedTempFile::new().expect("should succeed");
        writeln!(file, r#"{{"name":"John"}}"#).expect("should succeed");
        writeln!(file, "corrupt line, not json").expect("should succeed");
        writeln!(file).expect("should succeed"); // blank: structure, not a failure
        writeln!(file, r#"{{"name":"Jane"}}"#).expect("should succeed");
        file.flush().expect("should succeed");

        let got = parse_jsonl(file.path()).expect("two good lines still parse");
        assert!(got.text.contains("John") && got.text.contains("Jane"));
        assert_eq!(
            got.metadata.extraction_method, "jsonl_parse (2 parsed, 1 unparseable)",
            "provenance must state what was read and what was lost"
        );
    }

    /// A file of only blank lines is genuinely empty, not a malfunction — blank
    /// lines must not be counted as parse failures and turned into an error.
    #[test]
    fn jsonl_of_blank_lines_is_an_empty_success() {
        let mut file = NamedTempFile::new().expect("should succeed");
        writeln!(file).expect("should succeed");
        writeln!(file, "   ").expect("should succeed");
        file.flush().expect("should succeed");

        let got = parse_jsonl(file.path()).expect("blank lines are not a failure");
        assert!(got.text.is_empty());
        assert_eq!(
            got.metadata.extraction_method,
            "jsonl_parse (0 parsed, 0 unparseable)"
        );
    }
}
