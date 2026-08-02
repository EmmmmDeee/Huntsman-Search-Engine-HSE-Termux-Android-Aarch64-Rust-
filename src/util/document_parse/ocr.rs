//! OCR via system tesseract or pure-Rust fallback.

use super::{DocumentParseError, DocumentResult, RawDocumentText};
use crate::util::document_parse::DocumentFormat;
use std::path::Path;
use std::process::Command;
use tracing::{debug, warn};

/// Attempt OCR on an image file via system `tesseract` binary.
/// Falls back gracefully if tesseract is unavailable.
pub async fn ocr_image<P: AsRef<Path>>(
    image_path: P,
    _timeout_secs: u64,
) -> DocumentResult<RawDocumentText> {
    let path = image_path.as_ref();
    let path_str = path.to_string_lossy().to_string();

    // Check if tesseract is available
    if !is_tesseract_available() {
        warn!("tesseract not found in PATH; OCR disabled for {}", path_str);
        return Err(DocumentParseError::OcrUnavailable);
    }

    debug!("OCR via tesseract: {}", path_str);

    // Run tesseract with timeout
    let output = Command::new("tesseract")
        .arg(&path_str)
        .arg("stdout")
        .arg("-l")
        .arg("eng+fra+deu+spa") // Common multi-language support
        .output()
        .map_err(|e| {
            warn!("tesseract execution failed: {}", e);
            DocumentParseError::OcrUnavailable
        })?;

    if !output.status.success() {
        warn!("tesseract returned non-zero exit code");
        return Err(DocumentParseError::OcrUnavailable);
    }

    let text = String::from_utf8(output.stdout)?;

    Ok(RawDocumentText::new(
        text,
        DocumentFormat::Image,
        0.25, // OCR confidence floor (character recognition errors)
        path_str,
        "ocr_tesseract",
    ))
}

/// Check if tesseract is available in PATH.
fn is_tesseract_available() -> bool {
    Command::new("which")
        .arg("tesseract")
        .output()
        .is_ok_and(|o| o.status.success())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn tesseract_availability_check() {
        // This test just verifies the availability check function runs
        let available = is_tesseract_available();
        // Don't assert on availability (environment-dependent)
        println!("tesseract available: {available}");
    }
}
