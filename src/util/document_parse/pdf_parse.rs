//! PDF text extraction via pure-Rust PDF parser.

use super::{DocumentMetadata, DocumentParseError, DocumentResult, RawDocumentText};
use crate::util::document_parse::DocumentFormat;
use std::fs;
use std::path::Path;
use tracing::debug;

/// Count non-overlapping occurrences of `needle` in `haystack`. **Pure.**
fn count_subslices(haystack: &[u8], needle: &[u8]) -> usize {
    if needle.is_empty() || haystack.len() < needle.len() {
        return 0;
    }
    let mut n = 0;
    let mut i = 0;
    while i + needle.len() <= haystack.len() {
        if &haystack[i..i + needle.len()] == needle {
            n += 1;
            i += needle.len();
        } else {
            i += 1;
        }
    }
    n
}

/// Extract text from a PDF file (basic validation).
/// Full PDF text extraction requires complex content stream parsing.
/// For MVP, we detect PDF validity and estimate page count from file structure.
pub fn parse_pdf<P: AsRef<Path>>(pdf_path: P) -> DocumentResult<RawDocumentText> {
    parse_pdf_with_limit(pdf_path, super::MAX_DOCUMENT_BYTES)
}

/// [`parse_pdf`] with the size ceiling injected, so the refusal can be
/// exercised against a small fixture rather than a 64 MiB one.
pub(crate) fn parse_pdf_with_limit<P: AsRef<Path>>(
    pdf_path: P,
    limit: u64,
) -> DocumentResult<RawDocumentText> {
    let path = pdf_path.as_ref();
    let path_str = path.to_string_lossy().to_string();

    debug!("Parsing PDF: {}", path_str);

    // The ceiling is checked from the DIRECTORY ENTRY, before the read — a cap
    // applied after `fs::read` would have already made the allocation it exists
    // to prevent (REQ-DOCPARSE-002).
    super::size_within_limit(fs::metadata(path)?.len(), limit)?;

    // Read file and validate PDF signature
    let data = fs::read(path)?;
    if data.len() < 8 || !data.starts_with(b"%PDF-") {
        return Err(DocumentParseError::PdfError(
            "Not a valid PDF file (missing %PDF- signature)".to_string(),
        ));
    }

    // Estimate page count by counting "/Type /Page" objects (heuristic).
    //
    // Counted on the BYTES. This used to run `String::from_utf8_lossy(&data)`
    // first, which for a PDF — binary, mostly not valid UTF-8 — allocates a
    // second copy of the whole file, and a LARGER one: every invalid byte
    // becomes a three-byte U+FFFD. An entire extra pass and allocation over
    // untrusted input, to count two ASCII needles.
    //
    // The counts are identical: both needles are pure ASCII, lossy conversion
    // leaves valid ASCII bytes untouched, and U+FFFD cannot manufacture a match
    // that the bytes do not contain.
    let page_count = count_subslices(&data, b"/Type/Page") + count_subslices(&data, b"/Type /Page");

    let message = if page_count > 0 {
        format!(
            "PDF document with {page_count} pages detected (full text extraction requires OCR or PDf text layer)"
        )
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
            page_count: if page_count > 0 {
                Some(page_count)
            } else {
                None
            },
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

    /// REQ-DOCPARSE-002: the ceiling is enforced, and it is enforced BEFORE the
    /// read that it exists to prevent.
    #[test]
    fn a_file_over_the_ceiling_is_refused_and_names_its_size() {
        let dir = std::env::temp_dir().join("hse_pdf_cap_test");
        std::fs::create_dir_all(&dir).expect("temp dir");
        let path = dir.join("big.pdf");
        // A VALID PDF: the refusal must come from the size, not the signature,
        // or this test would pass for the wrong reason.
        let body = [b"%PDF-1.7\n".as_slice(), &vec![b'x'; 4096]].concat();
        std::fs::write(&path, &body).expect("write");

        // Sanity: under a generous limit it parses.
        assert!(
            super::parse_pdf_with_limit(&path, 1024 * 1024).is_ok(),
            "the fixture must be a parseable PDF, or the refusal below proves nothing"
        );

        match super::parse_pdf_with_limit(&path, 100) {
            Err(DocumentParseError::FileTooLarge(mib)) => {
                assert_eq!(
                    mib, 1,
                    "a 4 KiB file over a 100-byte cap rounds UP to 1 MiB"
                );
            }
            other => panic!("a file over the ceiling must be refused: {other:?}"),
        }
        let _ = std::fs::remove_file(&path);
    }

    /// The boundary, on the pure seam: `limit` bytes is allowed, one more is not.
    #[test]
    fn the_ceiling_is_inclusive_and_reports_whole_mib_rounded_up() {
        use super::super::size_within_limit;
        assert!(size_within_limit(0, 10).is_ok());
        assert!(
            size_within_limit(10, 10).is_ok(),
            "exactly at the limit is allowed"
        );
        assert!(size_within_limit(11, 10).is_err(), "one byte over is not");

        // Rounding UP: a file one byte over 1 MiB must not report "1 MiB", which
        // would name the ceiling as the file's own size.
        match size_within_limit(1024 * 1024 + 1, 1024 * 1024) {
            Err(DocumentParseError::FileTooLarge(mib)) => assert_eq!(mib, 2),
            other => panic!("expected FileTooLarge: {other:?}"),
        }
    }

    /// Counting on the bytes must agree with the lossy conversion it replaced —
    /// including on input that is NOT valid UTF-8, which is every real PDF.
    #[test]
    fn byte_counting_agrees_with_the_lossy_conversion_it_replaced() {
        let cases: Vec<Vec<u8>> = vec![
            b"%PDF-1.7 /Type/Page /Type /Page".to_vec(),
            // Invalid UTF-8 around and inside the region of interest.
            [
                b"%PDF-".as_slice(),
                &[0xff, 0xfe, 0x80],
                b"/Type/Page".as_slice(),
                &[0x81],
                b"/Type /Page".as_slice(),
            ]
            .concat(),
            [&[0xc3u8, 0x28][..], b"/Type/Page".as_slice()].concat(),
            b"no markers here".to_vec(),
            Vec::new(),
        ];
        let mut saw_a_match = false;
        for data in &cases {
            let lossy = String::from_utf8_lossy(data);
            let old = lossy.matches("/Type/Page").count() + lossy.matches("/Type /Page").count();
            let new = super::count_subslices(data, b"/Type/Page")
                + super::count_subslices(data, b"/Type /Page");
            assert_eq!(old, new, "disagreement on {data:?}");
            saw_a_match |= new > 0;
        }
        // Vacuity guard on the INPUT SET: agreeing on zero everywhere would be
        // no evidence at all.
        assert!(
            saw_a_match,
            "at least one case must actually contain a marker"
        );
    }

    /// The page-count call site must pass BOTH spellings of the marker.
    ///
    /// This exists because a mutation survived without it: dropping the spaced
    /// `/Type /Page` needle from the call site passed every other lock,
    /// including the one that verifies `count_subslices` itself. A helper's own
    /// tests cannot check its callers' arguments — the same gap REQ-ZOOMEYE-002
    /// found when a module passed a wrong cap to a shared guard.
    #[test]
    fn the_page_count_call_site_counts_both_spellings_of_the_marker() {
        let dir = std::env::temp_dir().join("hse_pdf_marker_test");
        std::fs::create_dir_all(&dir).expect("temp dir");

        let parse_count = |name: &str, body: &[u8]| -> String {
            let path = dir.join(name);
            std::fs::write(&path, body).expect("write");
            let out = super::parse_pdf(&path).expect("valid PDF").text;
            let _ = std::fs::remove_file(&path);
            out
        };

        // Unspaced only.
        assert!(
            parse_count("a.pdf", b"%PDF-1.7\n/Type/Page\n/Type/Page\n").contains("2 pages"),
            "the unspaced marker must be counted"
        );
        // SPACED only — the needle the mutation dropped. Without this case the
        // spaced spelling could go uncounted forever and every other test would
        // still pass.
        assert!(
            parse_count(
                "b.pdf",
                b"%PDF-1.7\n/Type /Page\n/Type /Page\n/Type /Page\n"
            )
            .contains("3 pages"),
            "the spaced marker must be counted at the call site too"
        );
        // Both, so the two counts are summed rather than one shadowing the other.
        assert!(
            parse_count("c.pdf", b"%PDF-1.7\n/Type/Page\n/Type /Page\n").contains("2 pages"),
            "both spellings must contribute to one total"
        );
    }
}
