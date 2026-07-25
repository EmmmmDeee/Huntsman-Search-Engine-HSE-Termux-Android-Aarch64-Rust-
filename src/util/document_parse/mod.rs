//! Document ingestion: parse images, PDFs, CSV, JSON into extractable text & structured data.
//!
//! Supports OCR (via system tesseract or pure-Rust fallback), PDF text extraction,
//! CSV/JSON parsing, and image preprocessing. Gracefully degrades if OCR unavailable.

pub mod ocr;
pub mod pdf_parse;
pub mod csv_parse;
pub mod json_parse;
pub mod image_prep;

use std::path::Path;
use thiserror::Error;
use crate::util::entity_extractor::ExtractionError;

/// Supported document input formats.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DocumentFormat {
    Image,
    Pdf,
    Csv,
    Json,
    Jsonl,
    Text,
}

impl DocumentFormat {
    /// Detect format from file extension.
    pub fn from_path<P: AsRef<Path>>(path: P) -> Option<Self> {
        let path = path.as_ref();
        path.extension()
            .and_then(|ext| ext.to_str())
            .and_then(|ext| match ext.to_lowercase().as_str() {
                "jpg" | "jpeg" | "png" | "gif" | "bmp" | "webp" => Some(Self::Image),
                "pdf" => Some(Self::Pdf),
                "csv" => Some(Self::Csv),
                "json" => Some(Self::Json),
                "jsonl" | "ndjson" => Some(Self::Jsonl),
                "txt" | "text" => Some(Self::Text),
                _ => None,
            })
    }
}

/// Document parsing error.
#[derive(Error, Debug)]
pub enum DocumentParseError {
    #[error("OCR not available (tesseract missing); image processing disabled")]
    OcrUnavailable,
    #[error("PDF parsing error: {0}")]
    PdfError(String),
    #[error("CSV parsing error: {0}")]
    CsvError(#[from] csv::Error),
    #[error("JSON parsing error: {0}")]
    JsonError(#[from] serde_json::Error),
    #[error("Image error: {0}")]
    ImageError(#[from] image::error::ImageError),
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
    #[error("UTF-8 error: {0}")]
    Utf8Error(#[from] std::string::FromUtf8Error),
    #[error("Entity extraction error: {0}")]
    ExtractionError(String),
    #[error("Unsupported format: {0}")]
    UnsupportedFormat(String),
    #[error("File size limit exceeded: {0} MiB")]
    FileTooLarge(usize),
}

/// Result type for document parsing.
pub type DocumentResult<T> = Result<T, DocumentParseError>;

/// Extracted raw text from a document.
#[derive(Debug, Clone)]
pub struct RawDocumentText {
    pub text: String,
    pub source_format: DocumentFormat,
    pub confidence: f64, // Lower for OCR (0.25), higher for structured (0.50+)
    pub metadata: DocumentMetadata,
}

/// Document metadata (source, timestamps, etc.).
#[derive(Debug, Clone, Default)]
pub struct DocumentMetadata {
    pub source_file: Option<String>,
    pub page_count: Option<usize>,
    pub character_count: usize,
    pub language: Option<String>,
    pub extraction_method: String, // "ocr", "pdf_text_layer", "csv", "json", "text"
}

impl From<ExtractionError> for DocumentParseError {
    fn from(err: ExtractionError) -> Self {
        Self::ExtractionError(err.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_format_from_extension() {
        assert_eq!(DocumentFormat::from_path("photo.jpg"), Some(DocumentFormat::Image));
        assert_eq!(DocumentFormat::from_path("data.pdf"), Some(DocumentFormat::Pdf));
        assert_eq!(DocumentFormat::from_path("records.csv"), Some(DocumentFormat::Csv));
        assert_eq!(DocumentFormat::from_path("data.json"), Some(DocumentFormat::Json));
        assert_eq!(DocumentFormat::from_path("data.jsonl"), Some(DocumentFormat::Jsonl));
        assert_eq!(DocumentFormat::from_path("notes.txt"), Some(DocumentFormat::Text));
        assert_eq!(DocumentFormat::from_path("unknown.xyz"), None);
    }
}
