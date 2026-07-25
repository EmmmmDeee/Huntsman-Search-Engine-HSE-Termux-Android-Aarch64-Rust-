//! CSV parsing and field extraction.

use super::{DocumentMetadata, DocumentResult, RawDocumentText};
use crate::util::document_parse::DocumentFormat;
use csv::Reader;
use std::fs::File;
use std::path::Path;
use tracing::debug;

/// Parse CSV file and extract all records as text and structured data.
pub fn parse_csv<P: AsRef<Path>>(csv_path: P) -> DocumentResult<CsvData> {
    let path = csv_path.as_ref();
    let path_str = path.to_string_lossy().to_string();

    debug!("Parsing CSV: {}", path_str);

    let file = File::open(path)?;
    let mut reader = Reader::from_reader(file);

    let headers = reader
        .headers()?
        .iter()
        .map(std::string::ToString::to_string)
        .collect::<Vec<_>>();

    let mut records = Vec::new();
    let mut raw_text = String::new();

    for result in reader.records() {
        let record = result?;
        let row: Vec<String> = record
            .iter()
            .map(std::string::ToString::to_string)
            .collect();
        records.push(row.clone());

        // Build raw text representation
        raw_text.push_str(&row.join(" | "));
        raw_text.push('\n');
    }

    let character_count = raw_text.len();

    Ok(CsvData {
        raw_text: RawDocumentText {
            text: raw_text,
            source_format: DocumentFormat::Csv,
            confidence: 0.50, // CSV is structured human-entered data
            metadata: DocumentMetadata {
                source_file: Some(path_str),
                character_count,
                extraction_method: "csv_parse".to_string(),
                ..Default::default()
            },
        },
        headers,
        records,
    })
}

/// Structured CSV data with headers and rows.
#[derive(Debug, Clone)]
pub struct CsvData {
    pub raw_text: RawDocumentText,
    pub headers: Vec<String>,
    pub records: Vec<Vec<String>>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn csv_parse_basic() {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, "name,email,phone").unwrap();
        writeln!(file, "John Doe,john@example.com,1234567890").unwrap();
        writeln!(file, "Jane Smith,jane@example.com,0987654321").unwrap();

        let csv_data = parse_csv(file.path()).unwrap();
        assert_eq!(csv_data.headers, vec!["name", "email", "phone"]);
        assert_eq!(csv_data.records.len(), 2);
        assert_eq!(csv_data.records[0][0], "John Doe");
    }

    #[test]
    fn csv_parse_nonexistent() {
        let result = parse_csv("/nonexistent/file.csv");
        assert!(result.is_err());
    }
}
