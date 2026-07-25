//! PDF text extraction via pure-Rust PDF parser.

use super::{DocumentMetadata, DocumentParseError, DocumentResult, RawDocumentText};
use crate::util::document_parse::DocumentFormat;
use std::fs;
use std::path::Path;
use tracing::debug;

/// Extract text from a PDF file (basic validation).
/// Full PDF text extraction requires complex content stream parsing.
/// For MVP, we detect PDF validity and estimate page count from file structure.
pub fn parse_pdf<P: AsRef<Path>>(pdf_path: P) -> DocumentResult<RawDocumentText> {
    let path = pdf_path.as_ref();
    let path_str = path.to_string_lossy().to_string();

    debug!("Parsing PDF: {}", path_str);

    // Read file and validate PDF signature
    let data = fs::read(path)?;
    if data.len() < 8 || !data.starts_with(b"%PDF-") {
        return Err(DocumentParseError::PdfError(
            "Not a valid PDF file (missing %PDF- signature)".to_string(),
        ));
    }

    // Estimate page count by counting "/Type /Page" objects (heuristic)
    let text = String::from_utf8_lossy(&data);
    let page_count = text.matches("/Type/Page").count() + text.matches("/Type /Page").count();

    let message = if page_count > 0 {
        format!("PDF document with {} pages detected (full text extraction requires OCR or PDf text layer)", page_count)
    } else {
        "PDF document detected (page count unknown; full text extraction requires OCR or PDF text layer)".to_string()
    };

    let character_count = message.len();

    Ok(RawDocumentText {
        text: message,
        source_format: DocumentFormat::Pdf,
        confidence: 0.40, // PDF validation (text extraction lower confidence without full parser)
        metadata: DocumentMetadata {
            source_file: Some(path_str),
            page_count: if page_count > 0 { Some(page_count) } else { None },
            character_count,
            extraction_method: "pdf_signature_validation".to_string(),
            ..Default::default()
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pdf_parse_nonexistent_file() {
        let result = parse_pdf("/nonexistent/file.pdf");
        assert!(result.is_err());
    }
}
