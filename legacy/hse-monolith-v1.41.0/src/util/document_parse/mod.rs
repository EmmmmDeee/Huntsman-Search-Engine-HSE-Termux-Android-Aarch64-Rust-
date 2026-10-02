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
    /// The binary genuinely is not there — the `which` probe failed, or the
    /// spawn returned `ErrorKind::NotFound`. Nothing else, because the message
    /// asserts "tesseract missing" and that must stay true wherever it is shown.
    #[error("OCR not available (tesseract missing); image processing disabled")]
    OcrUnavailable,
    /// Distinct from [`Self::OcrUnavailable`] on purpose: "tesseract is not
    /// installed" and "tesseract ran and would not finish" are different facts
    /// about the host, and an operator can act on them differently — install a
    /// package, versus feed a smaller image or raise the bound. Folding a hang
    /// into "unavailable" would report a capability the host actually has as
    /// missing.
    #[error("OCR timed out after {secs}s; tesseract did not finish")]
    OcrTimeout { secs: u64 },
    /// Tesseract ran to completion and reported failure. Also distinct from
    /// "missing": the binary is installed and working, it rejected this input.
    /// The exit code is carried rather than dropped — it is the only thing that
    /// distinguishes one refusal from another.
    #[error("OCR failed; tesseract exited with {}", match code {
        Some(c) => c.to_string(),
        None => "a signal".to_string(),
    })]
    OcrFailed { code: Option<i32> },
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
