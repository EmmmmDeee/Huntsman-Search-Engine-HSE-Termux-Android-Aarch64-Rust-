//! Document ingestion: parse images, PDFs, CSV, JSON into extractable text & structured data.
//!
//! Supports OCR (via system tesseract or pure-Rust fallback), PDF text extraction,
//! CSV/JSON parsing, and image preprocessing. Gracefully degrades if OCR unavailable.

pub mod csv_parse;
pub mod image_geolocation;
pub mod image_prep;
pub mod image_reverse_search;
pub mod json_parse;
pub mod ocr;
pub mod pdf_parse;

use crate::util::entity_extractor::ExtractionError;
use std::path::Path;
use thiserror::Error;

/// Supported document input formats.
///
/// Phase 5 extensions: YAML, TOML, env files for configuration/secrets ingestion.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DocumentFormat {
    Image,
    Pdf,
    Csv,
    Json,
    Jsonl,
    Text,
    Yaml, // Phase 5: YAML config/data files
    Toml, // Phase 5: TOML config files
    Env,  // Phase 5: Environment variable files (.env, .env.local)
    Xml,  // Phase 5: XML data/config files
}

impl DocumentFormat {
    /// Detect format from file extension.
    /// Supports Phase 5 extended formats: YAML, TOML, env files, XML.
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
                "yaml" | "yml" => Some(Self::Yaml),
                "toml" => Some(Self::Toml),
                "env" => Some(Self::Env),
                "xml" => Some(Self::Xml),
                _ => None,
            })
            .or_else(|| {
                // Special handling for dotfiles (.env, .env.local, .env.example)
                let file_name = path.file_name()?.to_str()?;
                if file_name.starts_with(".env") {
                    Some(Self::Env)
                } else {
                    None
                }
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

impl RawDocumentText {
    /// Build a `RawDocumentText` from its extracted text and provenance — the
    /// shape every parser in this module was hand-assembling via a struct
    /// literal + `DocumentMetadata { .. ..Default::default() }`.
    /// `metadata.character_count` is always the extracted text's byte length
    /// across every parser, so it's computed here rather than passed in.
    /// `page_count` (only meaningful for [`DocumentFormat::Pdf`] today) and
    /// `language` (never set by any parser yet) stay their `Default` — attach
    /// a page count with [`Self::with_page_count`].
    pub fn new(
        text: String,
        source_format: DocumentFormat,
        confidence: f64,
        source_file: impl Into<String>,
        extraction_method: impl Into<String>,
    ) -> Self {
        let character_count = text.len();
        Self {
            text,
            source_format,
            confidence,
            metadata: DocumentMetadata {
                source_file: Some(source_file.into()),
                character_count,
                extraction_method: extraction_method.into(),
                ..Default::default()
            },
        }
    }

    /// Attach a page count (PDF-only today).
    #[must_use]
    pub fn with_page_count(mut self, page_count: usize) -> Self {
        self.metadata.page_count = Some(page_count);
        self
    }
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
        assert_eq!(
            DocumentFormat::from_path("photo.jpg"),
            Some(DocumentFormat::Image)
        );
        assert_eq!(
            DocumentFormat::from_path("data.pdf"),
            Some(DocumentFormat::Pdf)
        );
        assert_eq!(
            DocumentFormat::from_path("records.csv"),
            Some(DocumentFormat::Csv)
        );
        assert_eq!(
            DocumentFormat::from_path("data.json"),
            Some(DocumentFormat::Json)
        );
        assert_eq!(
            DocumentFormat::from_path("data.jsonl"),
            Some(DocumentFormat::Jsonl)
        );
        assert_eq!(
            DocumentFormat::from_path("notes.txt"),
            Some(DocumentFormat::Text)
        );
        // Phase 5: Extended format detection
        assert_eq!(
            DocumentFormat::from_path("config.yaml"),
            Some(DocumentFormat::Yaml)
        );
        assert_eq!(
            DocumentFormat::from_path("settings.yml"),
            Some(DocumentFormat::Yaml)
        );
        assert_eq!(
            DocumentFormat::from_path("app.toml"),
            Some(DocumentFormat::Toml)
        );
        assert_eq!(
            DocumentFormat::from_path("data.xml"),
            Some(DocumentFormat::Xml)
        );
        assert_eq!(DocumentFormat::from_path(".env"), Some(DocumentFormat::Env));
        assert_eq!(
            DocumentFormat::from_path(".env.local"),
            Some(DocumentFormat::Env)
        );
        assert_eq!(DocumentFormat::from_path("unknown.xyz"), None);
    }
}
