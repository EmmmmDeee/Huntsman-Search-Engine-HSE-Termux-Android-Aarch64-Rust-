//! OCR via system tesseract or pure-Rust fallback.

use super::{DocumentMetadata, DocumentParseError, DocumentResult, RawDocumentText};
use crate::util::document_parse::DocumentFormat;
use std::path::Path;
use std::process::Output;
use std::time::Duration;
use tokio::process::Command;
use tracing::{debug, warn};

/// Run `cmd`, failing with [`DocumentParseError::OcrTimeout`] if it has not
/// finished within `timeout_secs`.
///
/// `kill_on_drop(true)` is load-bearing, not tidiness. Without it a timeout only
/// stops us *waiting* — the process keeps running, and on the declared target
/// (a phone) an abandoned tesseract burns CPU and battery for as long as it
/// likes, with nothing left holding a handle to stop it. Dropping the future
/// must actually kill the child.
///
/// A zero timeout is treated as "no bound", so a caller that has not thought
/// about it cannot accidentally make every OCR fail instantly.
async fn run_bounded(mut cmd: Command, timeout_secs: u64) -> DocumentResult<Output> {
    cmd.kill_on_drop(true);
    let run = cmd.output();
    let output = if timeout_secs == 0 {
        run.await
    } else {
        match tokio::time::timeout(Duration::from_secs(timeout_secs), run).await {
            Ok(res) => res,
            Err(_elapsed) => {
                warn!(timeout_secs, "tesseract exceeded its time budget; killed");
                return Err(DocumentParseError::OcrTimeout { secs: timeout_secs });
            }
        }
    };
    output.map_err(|e| {
        warn!("tesseract execution failed: {}", e);
        DocumentParseError::OcrUnavailable
    })
}

/// Attempt OCR on an image file via system `tesseract` binary.
/// Falls back gracefully if tesseract is unavailable.
///
/// `timeout_secs` is enforced. It previously was not: the parameter was bound as
/// `_timeout_secs` and discarded while the comment above the call claimed "run
/// tesseract with timeout", so the one caller (`hse ingest --file`, which passes
/// 60) believed it had a bound it did not have. A tesseract that never returned
/// hung the ingest indefinitely.
///
/// Both subprocess calls are `tokio::process`, not `std::process`. The old code
/// blocked the async worker across a fork+exec and the whole OCR run; on the
/// declared target that is roughly half the runtime's workers stalled on one
/// image.
pub async fn ocr_image<P: AsRef<Path>>(
    image_path: P,
    timeout_secs: u64,
) -> DocumentResult<RawDocumentText> {
    let path = image_path.as_ref();
    let path_str = path.to_string_lossy().to_string();

    // Check if tesseract is available
    if !is_tesseract_available().await {
        warn!("tesseract not found in PATH; OCR disabled for {}", path_str);
        return Err(DocumentParseError::OcrUnavailable);
    }

    debug!("OCR via tesseract: {}", path_str);

    let mut cmd = Command::new("tesseract");
    cmd.arg(&path_str)
        .arg("stdout")
        .arg("-l")
        .arg("eng+fra+deu+spa"); // Common multi-language support
    let output = run_bounded(cmd, timeout_secs).await?;

    if !output.status.success() {
        warn!("tesseract returned non-zero exit code");
        return Err(DocumentParseError::OcrUnavailable);
    }

    let text = String::from_utf8(output.stdout)?;
    let character_count = text.len();

    Ok(RawDocumentText {
        text,
        source_format: DocumentFormat::Image,
        confidence: 0.25, // OCR confidence floor (character recognition errors)
        metadata: DocumentMetadata {
            source_file: Some(path_str),
            extraction_method: "ocr_tesseract".to_string(),
            character_count,
            ..Default::default()
        },
    })
}

/// Check if tesseract is available in PATH.
///
/// Async for the same reason as the OCR run itself: this is a fork+exec, and
/// running it inline on the async worker blocks it. It is also the probe that
/// runs on *every* ingest, including the common case where tesseract is absent.
async fn is_tesseract_available() -> bool {
    Command::new("which")
        .arg("tesseract")
        .kill_on_drop(true)
        .output()
        .await
        .is_ok_and(|o| o.status.success())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn tesseract_availability_check() {
        // This test just verifies the availability check function runs
        let available = is_tesseract_available().await;
        // Don't assert on availability (environment-dependent)
        println!("tesseract available: {available}");
    }

    /// The timeout must actually bound the run, and must report a hang as a
    /// hang rather than as "tesseract is missing" — those are different facts
    /// about the host and an operator acts on them differently.
    ///
    /// Uses `sleep`, not tesseract, so this holds whether or not OCR is
    /// installed here.
    #[tokio::test]
    async fn a_command_that_overruns_is_reported_as_a_timeout() {
        let mut cmd = Command::new("sleep");
        cmd.arg("30");
        let err = run_bounded(cmd, 1)
            .await
            .expect_err("a 30s sleep must not finish within a 1s budget");
        assert!(
            matches!(err, DocumentParseError::OcrTimeout { secs: 1 }),
            "a hang must surface as OcrTimeout carrying the budget, not as \
             OcrUnavailable — got {err:?}"
        );
    }

    /// A command that finishes inside the budget must pass straight through.
    #[tokio::test]
    async fn a_command_within_budget_succeeds() {
        let out = run_bounded(Command::new("true"), 30)
            .await
            .expect("`true` must complete well inside a 30s budget");
        assert!(out.status.success());
    }

    /// Zero means "no bound" — a caller that never considered the timeout must
    /// not have every OCR fail instantly.
    #[tokio::test]
    async fn zero_timeout_means_unbounded_not_instant_failure() {
        let out = run_bounded(Command::new("true"), 0)
            .await
            .expect("a zero budget must mean unbounded, not immediate timeout");
        assert!(out.status.success());
    }
}
