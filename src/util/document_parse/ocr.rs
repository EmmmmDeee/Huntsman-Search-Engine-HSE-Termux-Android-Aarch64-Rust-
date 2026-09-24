//! OCR via the system `tesseract` binary. There is no fallback: an image
//! tesseract cannot read yields an error that says why, and the caller decides
//! what, if anything, it can still do without the text.

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
    let program = cmd.as_std().get_program().to_os_string();
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
        // Only a program that is nowhere to be found is `OcrUnavailable`: that
        // variant's message says tesseract is not installed, and that must
        // stay true wherever it is shown. One that is there and would not start
        // is `OcrStart`, with the cause: no permission to run it, too few
        // resources, or a missing script interpreter, which the kernel also
        // reports as "not found". Telling that operator to install tesseract
        // would be wrong.
        if e.kind() == std::io::ErrorKind::NotFound && !on_path(&program) {
            warn!("tesseract is not installed");
            DocumentParseError::OcrUnavailable
        } else {
            warn!("tesseract could not be started: {e}");
            DocumentParseError::OcrStart(e)
        }
    })
}

/// Whether `program` names a file that exists: itself when it is a path, else
/// a file of that name in a `PATH` directory. Pure Rust, so telling "not
/// installed" from "installed and would not start" needs no `which`, which
/// minimal systems do not ship.
fn on_path(program: &std::ffi::OsStr) -> bool {
    let named = Path::new(program);
    if named.components().count() > 1 {
        return named.is_file();
    }
    std::env::var_os("PATH")
        .is_some_and(|dirs| std::env::split_paths(&dirs).any(|dir| dir.join(program).is_file()))
}

/// How much of tesseract's stderr an [`DocumentParseError::OcrFailed`] keeps.
const STDERR_TAIL_CHARS: usize = 300;

/// The end of tesseract's stderr, where it says why it refused an image: on
/// one line, and at most [`STDERR_TAIL_CHARS`] characters.
fn stderr_tail(stderr: &[u8]) -> String {
    let line = String::from_utf8_lossy(stderr)
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    let skip = line.chars().count().saturating_sub(STDERR_TAIL_CHARS);
    line.chars().skip(skip).collect()
}

/// Attempt OCR on an image file via the system `tesseract` binary.
///
/// # Errors
///
/// [`DocumentParseError::OcrUnavailable`] when tesseract is not installed,
/// [`DocumentParseError::OcrStart`] when it is and could not be started,
/// [`DocumentParseError::OcrFailed`] when it ran and rejected the image (with
/// the end of its stderr), and [`DocumentParseError::OcrTimeout`] when it
/// overran `timeout_secs`.
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

    // No `which` probe first: spawning tesseract is the probe, and the spawn
    // error says whether it is missing (`run_bounded`).
    debug!("OCR via tesseract: {}", path_str);

    let mut cmd = Command::new("tesseract");
    cmd.arg(&path_str)
        .arg("stdout")
        .arg("-l")
        .arg("eng+fra+deu+spa"); // Common multi-language support
    let output = run_bounded(cmd, timeout_secs).await?;

    if !output.status.success() {
        // Tesseract is installed and ran; it rejected this input. Reporting
        // that as "tesseract missing" would send an operator to install a
        // package they already have.
        let code = output.status.code();
        let stderr = stderr_tail(&output.stderr);
        warn!(?code, %stderr, "tesseract returned a failure exit status");
        return Err(DocumentParseError::OcrFailed { code, stderr });
    }

    // Tesseract writes UTF-8; a stray invalid byte costs one character, not
    // the page.
    let text = String::from_utf8_lossy(&output.stdout).into_owned();
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

#[cfg(test)]
mod tests {
    use super::*;

    /// The timeout must actually bound the run, and must report a hang as a
    /// hang rather than as "tesseract is missing" — those are different facts
    /// about the host and an operator acts on them differently.
    ///
    /// Uses `sleep`, not tesseract, so this holds whether or not OCR is
    /// installed here.
    #[tokio::test]
    async fn a_command_that_overruns_is_reported_as_a_timeout() {
        let mut cmd = Command::new("sleep");
        cmd.arg("5");
        let err = run_bounded(cmd, 1)
            .await
            .expect_err("a 5s sleep must not finish within a 1s budget");
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

    /// Only an absent binary may be reported as "tesseract missing".
    ///
    /// `OcrUnavailable`'s message asserts that, so every other failure has to
    /// stay distinguishable: a spawn error carries its `io::Error`, and a
    /// process that ran and exited non-zero is not a spawn failure at all — it
    /// returns a completed `Output` the caller classifies as `OcrFailed`.
    /// Flattening those into "missing" would send an operator to install a
    /// package they already have.
    #[tokio::test]
    async fn only_an_absent_binary_is_reported_as_missing() {
        let err = run_bounded(Command::new("hse-no-such-binary-should-exist-xyz"), 30)
            .await
            .expect_err("a missing binary must fail");
        assert!(
            matches!(err, DocumentParseError::OcrUnavailable),
            "an absent binary is the one case that may claim 'missing' — got {err:?}"
        );

        let out = run_bounded(Command::new("false"), 30)
            .await
            .expect("`false` spawns fine; it merely exits non-zero");
        assert!(
            !out.status.success(),
            "the failing exit status must reach the caller intact, so it can be \
             reported as OcrFailed rather than as a missing binary"
        );
    }

    /// A program that is there and will not start is `OcrStart`, never "not
    /// installed": a script whose interpreter is missing (the kernel reports
    /// that as "not found" too), and a file without permission to run.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_program_that_is_there_but_will_not_start_is_not_reported_as_missing() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().expect("tempdir");
        let no_interpreter = dir.path().join("no-interpreter");
        std::fs::write(&no_interpreter, "#!/hse/no/such/interpreter\n").expect("script");
        std::fs::set_permissions(&no_interpreter, std::fs::Permissions::from_mode(0o755))
            .expect("chmod");
        let not_executable = dir.path().join("not-executable");
        std::fs::write(&not_executable, "#!/bin/sh\n").expect("script");
        std::fs::set_permissions(&not_executable, std::fs::Permissions::from_mode(0o644))
            .expect("chmod");
        for program in [&no_interpreter, &not_executable] {
            let err = run_bounded(Command::new(program), 30)
                .await
                .expect_err("must not start");
            assert!(
                matches!(err, DocumentParseError::OcrStart(_)),
                "{program:?}: {err:?}"
            );
        }
    }

    /// Tesseract's reason reaches the error, on one line and bounded.
    #[test]
    fn a_refusal_keeps_the_end_of_stderr_on_one_line() {
        assert_eq!(
            stderr_tail(b"Error in pixRead\n  image file could not be read\n"),
            "Error in pixRead image file could not be read"
        );
        let long = "x".repeat(STDERR_TAIL_CHARS + 50) + " END";
        let tail = stderr_tail(long.as_bytes());
        assert_eq!(tail.chars().count(), STDERR_TAIL_CHARS);
        assert!(tail.ends_with(" END"), "the end is what is kept: {tail}");
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
