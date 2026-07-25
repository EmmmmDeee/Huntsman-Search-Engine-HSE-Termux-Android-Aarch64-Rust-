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
    let mut line_count = 0;

    for line in reader.lines() {
        let line = line?;
        line_count += 1;

        if let Ok(value) = serde_json::from_str::<Value>(&line) {
            text.push_str(&flatten_json_to_text(&value));
            text.push('\n');
        }
    }

    let character_count = text.len();

    Ok(RawDocumentText {
        text,
        source_format: DocumentFormat::Jsonl,
        confidence: 0.50, // Structured JSONL
        metadata: DocumentMetadata {
            source_file: Some(path_str),
            character_count,
            extraction_method: format!("jsonl_parse ({} lines)", line_count),
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
                text.push_str(&format!("[{}]: ", idx));
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
        let mut file = NamedTempFile::new().unwrap();
        let json = serde_json::json!({
            "name": "John Doe",
            "email": "john@example.com",
            "age": 30
        });
        writeln!(file, "{}", json.to_string()).unwrap();
        file.flush().unwrap();

        let result = parse_json(file.path()).unwrap();
        assert!(result.text.contains("John Doe"));
        assert!(result.text.contains("john@example.com"));
    }

    #[test]
    fn jsonl_parse_basic() {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, r#"{{"name":"John","email":"john@example.com"}}"#).unwrap();
        writeln!(file, r#"{{"name":"Jane","email":"jane@example.com"}}"#).unwrap();
        file.flush().unwrap();

        let result = parse_jsonl(file.path()).unwrap();
        assert!(result.text.contains("John"));
        assert!(result.text.contains("Jane"));
    }
}
