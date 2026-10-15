//! Durable history of test-suite runs and a regression verdict between them.
//!
//! Each run is one JSON line, appended to a file, so a crash can lose at most
//! the line being written. Loading is strict: a malformed line is an error that
//! names its line number, never a silently skipped record. The verdict compares a
//! run against the one before it and reports a regression only on measured
//! evidence: a new failure, or a suite that ran fewer tests than before.

use std::fs::{File, Metadata, OpenOptions};
use std::io::{self, Write};
use std::path::Path;

use crate::fsio::{CHANGED_WHILE_OPENING, NOT_REGULAR_FILE, REFUSED_SYMLINK};

/// Upper bound on a history file, in bytes, for every read of it.
///
/// One record is a JSON line of roughly 150 bytes, so 16 MiB holds on the order
/// of a hundred thousand runs, far more than a regression store accumulates.
/// The cap keeps a hostile or runaway `--file` from exhausting memory on the
/// Termux/Android target: every external input in the crate is capped.
pub const MAX_HISTORY_BYTES: u64 = 16 * 1024 * 1024;

/// Read the whole history file through [`crate::fsio::read_bounded`].
/// `Ok(None)` means the file does not exist. A symlink, a non-file, or a file
/// over [`MAX_HISTORY_BYTES`] is an IO error.
fn read_history(path: &Path) -> Result<Option<Vec<u8>>, HistoryError> {
    match std::fs::symlink_metadata(path) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(HistoryError::Io(e)),
        Ok(_) => {}
    }
    crate::fsio::read_bounded(path, MAX_HISTORY_BYTES)
        .map(Some)
        .map_err(|e| HistoryError::Io(io::Error::other(e.to_string())))
}

fn refusal(path: &Path, reason: &str) -> HistoryError {
    HistoryError::Io(io::Error::other(format!("{}: {reason}", path.display())))
}

/// `lstat` the history before a write, matching `fsio`: a symlink is refused, since
/// writing through a planted link would land in whatever file it points at. `None`
/// when the path does not exist yet.
fn lstat_for_write(path: &Path) -> Result<Option<Metadata>, HistoryError> {
    match std::fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_symlink() => Err(refusal(path, REFUSED_SYMLINK)),
        Ok(meta) => Ok(Some(meta)),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(HistoryError::Io(e)),
    }
}

/// Open the history for an in-place write through a descriptor that is the file
/// `lstat` saw. The path is checked, opened with `options`, and the descriptor
/// compared with the check (same inode, regular file), so a link or a replacement
/// planted between the check and the open is refused rather than written through.
/// With `create`, a history that does not exist yet is created exclusively, which
/// never follows a link planted after the check.
fn open_checked(
    path: &Path,
    options: &mut OpenOptions,
    create: bool,
) -> Result<File, HistoryError> {
    let linked = lstat_for_write(path)?;
    if create && linked.is_none() {
        options.create_new(true);
    }
    let file = options.open(path)?;
    require_opened(path, linked.as_ref(), &file.metadata()?)?;
    Ok(file)
}

/// The descriptor half of [`open_checked`]: `opened` must be the inode `linked`
/// describes, when the path existed at the check, and a regular file.
fn require_opened(
    path: &Path,
    linked: Option<&Metadata>,
    opened: &Metadata,
) -> Result<(), HistoryError> {
    if linked.is_some_and(|linked| !crate::fsio::same_inode(linked, opened)) {
        return Err(refusal(path, CHANGED_WHILE_OPENING));
    }
    if !opened.is_file() {
        return Err(refusal(path, NOT_REGULAR_FILE));
    }
    Ok(())
}

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunRecord {
    pub commit: String,
    pub suite: String,
    pub passed: u64,
    pub failed: u64,
    pub recorded_at_unix: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// No earlier run in this suite to compare against.
    Baseline,
    /// Same or better: no new failures, no fewer tests.
    Held,
    /// A new failure, or fewer tests than the previous run.
    Regressed { reason: String },
}

#[derive(Debug, thiserror::Error)]
pub enum HistoryError {
    #[error("run history io: {0}")]
    Io(#[from] io::Error),
    #[error("run history line {line} is malformed: {reason}")]
    Malformed { line: usize, reason: String },
}

/// Append one run as a JSON line. Creates the file, and any missing parent
/// directories, if they do not exist.
///
/// The default path is `var/run_history.jsonl`, relative to the working
/// directory, so without creating the parent `run-history record` failed in any
/// directory without a `var/` — a Termux user's `$HOME`, say — with an IO error
/// and no record written. Creating it mirrors every other writer in the crate
/// (`fsio::write_atomic`, the session `store`).
///
/// Before writing, a torn tail left by a previously interrupted append — bytes
/// not ended by a newline, which are not a committed record — is truncated, so
/// the new record is never fused onto a partial line. This assumes a single
/// writer, which the regression store has (one CI step or one host).
pub fn append(path: &Path, record: &RunRecord) -> Result<(), HistoryError> {
    let mut line = serde_json::to_string(record).map_err(|e| HistoryError::Malformed {
        line: 0,
        reason: e.to_string(),
    })?;
    line.push('\n');
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        std::fs::create_dir_all(parent)?;
    }
    heal_torn_tail(path)?;
    let mut options = OpenOptions::new();
    options.append(true);
    let mut file = open_checked(path, &mut options, true)?;
    file.write_all(line.as_bytes())?;
    file.sync_data()?;
    Ok(())
}

/// Drop an unterminated trailing fragment so the file stays a clean sequence of
/// whole lines. A missing file, an empty file, or one already ending in a
/// newline needs no repair.
fn heal_torn_tail(path: &Path) -> Result<(), HistoryError> {
    let Some(bytes) = read_history(path)? else {
        return Ok(());
    };
    if bytes.is_empty() || bytes.last() == Some(&b'\n') {
        return Ok(());
    }
    let keep = bytes
        .iter()
        .rposition(|b| *b == b'\n')
        .map_or(0, |index| index + 1);
    let mut options = OpenOptions::new();
    options.write(true);
    let file = open_checked(path, &mut options, false)?;
    file.set_len(keep as u64)?;
    file.sync_data()?;
    Ok(())
}

/// Load every run in file order. Missing file means an empty history.
pub fn load(path: &Path) -> Result<Vec<RunRecord>, HistoryError> {
    // Read bytes, not lines: an append interrupted mid-write can leave a torn
    // final line, possibly splitting a multi-byte character, which a UTF-8
    // line reader would itself reject. A completed append always ends in '\n',
    // so a file that does not is missing its last line's terminator — that
    // final fragment is the torn write and is dropped, losing at most the line
    // being written, exactly as this module guarantees. A malformed line that
    // is *not* the unterminated tail is genuine corruption and still errors.
    let Some(bytes) = read_history(path)? else {
        return Ok(Vec::new());
    };
    if bytes.is_empty() {
        return Ok(Vec::new());
    }
    let complete = bytes.last() == Some(&b'\n');
    let mut segments: Vec<&[u8]> = bytes.split(|b| *b == b'\n').collect();
    if complete {
        segments.pop(); // the empty segment after the final terminator
    }
    let last = segments.len().saturating_sub(1);
    let mut out = Vec::new();
    for (index, segment) in segments.iter().enumerate() {
        if segment.iter().all(u8::is_ascii_whitespace) {
            continue;
        }
        let parsed = std::str::from_utf8(segment)
            .ok()
            .and_then(|text| serde_json::from_str::<RunRecord>(text.trim()).ok());
        match parsed {
            Some(record) => out.push(record),
            None if index == last && !complete => break,
            None => {
                let reason = match std::str::from_utf8(segment) {
                    Err(_) => "invalid UTF-8".to_string(),
                    Ok(text) => serde_json::from_str::<RunRecord>(text.trim())
                        .err()
                        .map_or_else(|| "unparseable".to_string(), |e| e.to_string()),
                };
                return Err(HistoryError::Malformed {
                    line: index + 1,
                    reason,
                });
            }
        }
    }
    Ok(out)
}

/// Compare `current` with the most recent earlier run of the same suite.
#[must_use]
pub fn verdict(history: &[RunRecord], current: &RunRecord) -> Verdict {
    let previous = history.iter().rev().find(|r| r.suite == current.suite);
    let Some(previous) = previous else {
        return Verdict::Baseline;
    };
    if current.failed > previous.failed {
        return Verdict::Regressed {
            reason: format!(
                "failures rose from {} to {}",
                previous.failed, current.failed
            ),
        };
    }
    if current.passed < previous.passed {
        return Verdict::Regressed {
            reason: format!(
                "passing tests fell from {} to {}",
                previous.passed, current.passed
            ),
        };
    }
    Verdict::Held
}

/// Sum the pass/fail counts across every `test result:` line in libtest output.
///
/// libtest prints one summary line per test binary, e.g.
/// `test result: ok. 12 passed; 0 failed; 1 ignored; 0 measured; 3 filtered out`.
/// A `cargo test --workspace` run prints many; this totals them. Returns `None`
/// when no summary line is present, so an empty or unrelated input is an error
/// at the call site rather than a silent zero.
#[must_use]
pub fn parse_libtest_summary(output: &str) -> Option<(u64, u64)> {
    let mut passed = 0u64;
    let mut failed = 0u64;
    let mut seen = false;
    for line in output.lines() {
        let Some(rest) = line.trim().strip_prefix("test result:") else {
            continue;
        };
        // rest looks like " ok. 12 passed; 0 failed; 1 ignored; ..."
        let mut line_passed = None;
        let mut line_failed = None;
        for field in rest.split(';') {
            let mut parts = field.split_whitespace();
            // The first field carries the "ok."/"FAILED." verdict before the count,
            // so scan for a <number> <label> pair rather than assuming position.
            let tokens: Vec<&str> = parts.by_ref().collect();
            for pair in tokens.windows(2) {
                if let Ok(n) = pair[0].parse::<u64>() {
                    match pair[1] {
                        "passed" => line_passed = Some(n),
                        "failed" => line_failed = Some(n),
                        _ => {}
                    }
                }
            }
        }
        if let (Some(p), Some(f)) = (line_passed, line_failed) {
            passed += p;
            failed += f;
            seen = true;
        }
    }
    seen.then_some((passed, failed))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(suite: &str, passed: u64, failed: u64) -> RunRecord {
        RunRecord {
            commit: "abc123".into(),
            suite: suite.into(),
            passed,
            failed,
            recorded_at_unix: 1,
        }
    }

    fn scratch(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("run-history-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir.join("runs.jsonl")
    }

    #[test]
    fn append_then_load_round_trips_in_order() {
        let path = scratch("roundtrip");
        append(&path, &run("unit", 10, 0)).unwrap();
        append(&path, &run("unit", 11, 0)).unwrap();
        let loaded = load(&path).unwrap();
        assert_eq!(loaded, vec![run("unit", 10, 0), run("unit", 11, 0)]);
    }

    #[test]
    fn missing_file_is_an_empty_history() {
        let path = scratch("missing");
        assert!(load(&path).unwrap().is_empty());
    }

    #[test]
    fn append_creates_missing_parent_directories() {
        // The default path is `var/run_history.jsonl`; outside a checkout that `var/` does not
        // exist, and append used to fail with an IO error and write nothing. It must create the
        // parent so `run-history record` works in any directory, as every other writer does.
        let base = std::env::temp_dir().join(format!("run-history-parents-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let path = base.join("var").join("run_history.jsonl");
        assert!(!path.parent().unwrap().exists());
        append(&path, &run("unit", 3, 0)).unwrap();
        assert_eq!(load(&path).unwrap(), vec![run("unit", 3, 0)]);
        let _ = std::fs::remove_dir_all(&base);
    }

    #[cfg(unix)]
    #[test]
    fn append_refuses_a_symlink_and_does_not_write_through_it() {
        // A history path that is a symlink must be refused, so an append cannot land in whatever
        // file the link points at. The refusal is enforced in append's read step (heal_torn_tail,
        // through fsio::read_bounded); open_checked guards the writes behind it as a second layer.
        let link = scratch("symlink");
        let target = link.with_file_name("target.jsonl");
        std::fs::write(&target, b"").unwrap();
        std::os::unix::fs::symlink(&target, &link).unwrap();
        match append(&link, &run("unit", 1, 0)) {
            Err(HistoryError::Io(e)) => assert!(e.to_string().contains("refusing symlink"), "{e}"),
            other => panic!("a symlink history path must be refused, got {other:?}"),
        }
        assert_eq!(
            std::fs::read(&target).unwrap(),
            b"",
            "the append followed the link and wrote through it"
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_descriptor_that_is_not_the_checked_inode_is_refused_before_a_write() {
        // The write path checks the history with lstat, opens it, then compares the descriptor
        // with the check. A swap between the two cannot be scheduled from a test, so the
        // comparison is given, by construction, the lstat result of the history and a descriptor
        // on another file: what a link or a replacement planted in that window produces.
        let path = scratch("descriptor");
        let planted = path.with_file_name("planted.jsonl");
        std::fs::write(&path, b"").unwrap();
        std::fs::write(&planted, b"").unwrap();
        let linked = std::fs::symlink_metadata(&path).unwrap();
        require_opened(&path, Some(&linked), &std::fs::metadata(&path).unwrap()).unwrap();
        require_opened(&path, None, &std::fs::metadata(&path).unwrap()).unwrap();
        match require_opened(&path, Some(&linked), &std::fs::metadata(&planted).unwrap()) {
            Err(HistoryError::Io(e)) => {
                let shown = e.to_string();
                assert!(
                    shown.contains("changed between the check and the open"),
                    "{shown}"
                );
                assert!(shown.contains(&path.display().to_string()), "{shown}");
            }
            other => panic!("a descriptor on another inode must be refused, got {other:?}"),
        }
        let dir = std::fs::metadata(path.parent().unwrap()).unwrap();
        match require_opened(&path, None, &dir) {
            Err(HistoryError::Io(e)) => {
                assert!(e.to_string().contains("not a regular file"), "{e}");
            }
            other => panic!("a descriptor on a directory must be refused, got {other:?}"),
        }
    }

    #[test]
    fn malformed_line_is_a_named_error_not_a_skip() {
        let path = scratch("malformed");
        append(&path, &run("unit", 1, 0)).unwrap();
        std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap()
            .write_all(b"{not json}\n")
            .unwrap();
        match load(&path) {
            Err(HistoryError::Malformed { line, .. }) => assert_eq!(line, 2),
            other => panic!("expected malformed at line 2, got {other:?}"),
        }
    }

    #[test]
    fn verdict_is_baseline_then_held_then_regressed() {
        let history = vec![run("unit", 10, 0)];
        assert_eq!(verdict(&[], &run("unit", 10, 0)), Verdict::Baseline);
        assert_eq!(verdict(&history, &run("unit", 10, 0)), Verdict::Held);
        assert_eq!(verdict(&history, &run("unit", 12, 0)), Verdict::Held);
        assert!(matches!(
            verdict(&history, &run("unit", 10, 1)),
            Verdict::Regressed { .. }
        ));
        assert!(matches!(
            verdict(&history, &run("unit", 9, 0)),
            Verdict::Regressed { .. }
        ));
    }

    #[test]
    fn verdict_compares_only_within_the_same_suite() {
        let history = vec![run("unit", 10, 0)];
        assert_eq!(
            verdict(&history, &run("integration", 1, 0)),
            Verdict::Baseline
        );
    }

    #[test]
    fn libtest_summary_sums_every_result_line() {
        let output = "\
running 2 tests
test a ... ok
test result: ok. 2 passed; 0 failed; 1 ignored; 0 measured; 3 filtered out; finished in 0.01s

running 3 tests
test result: FAILED. 1 passed; 2 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.02s
";
        assert_eq!(parse_libtest_summary(output), Some((3, 2)));
    }

    #[test]
    fn libtest_summary_is_none_without_a_result_line() {
        assert_eq!(parse_libtest_summary(""), None);
        assert_eq!(
            parse_libtest_summary("Compiling huntsman-recon\nFinished\n"),
            None
        );
    }

    #[test]
    fn libtest_summary_ignores_measured_and_filtered_counts() {
        let output = "test result: ok. 5 passed; 0 failed; 0 ignored; 7 measured; 9 filtered out";
        assert_eq!(parse_libtest_summary(output), Some((5, 0)));
    }

    #[test]
    fn a_torn_final_line_loses_only_itself_and_keeps_prior_records() {
        // Simulate an append interrupted mid-write: a complete record, then a
        // partial final line with no trailing newline.
        let path = scratch("torn");
        append(&path, &run("unit", 10, 0)).unwrap();
        let mut file = OpenOptions::new().append(true).open(&path).unwrap();
        file.write_all(b"{\"commit\":\"a").unwrap();
        drop(file);
        let loaded = load(&path).expect("a torn tail must not wedge the whole history");
        assert_eq!(loaded, vec![run("unit", 10, 0)]);
        // And recording continues to work: the torn tail does not block appends.
        append(&path, &run("unit", 11, 0)).unwrap();
        assert_eq!(load(&path).unwrap().last().unwrap().passed, 11);
    }

    #[test]
    fn interior_corruption_with_a_terminator_still_errors() {
        // A malformed line that DID get its newline is genuine corruption, not a
        // torn write, and must not be silently dropped.
        let path = scratch("interior");
        append(&path, &run("unit", 1, 0)).unwrap();
        let mut file = OpenOptions::new().append(true).open(&path).unwrap();
        file.write_all(b"{garbage}\n").unwrap();
        file.write_all(b"{\"commit\":\"c\",\"suite\":\"unit\",\"passed\":2,\"failed\":0,\"recorded_at_unix\":1}\n").unwrap();
        drop(file);
        assert!(matches!(
            load(&path),
            Err(HistoryError::Malformed { line: 2, .. })
        ));
    }

    #[test]
    fn a_history_over_the_cap_is_refused_on_load_and_append() {
        let path = scratch("oversize");
        let file = std::fs::File::create(&path).unwrap();
        file.set_len(MAX_HISTORY_BYTES + 1).unwrap();
        drop(file);
        assert!(matches!(load(&path), Err(HistoryError::Io(_))));
        assert!(matches!(
            append(&path, &run("unit", 1, 0)),
            Err(HistoryError::Io(_))
        ));
    }

    #[cfg(unix)]
    #[test]
    fn a_symlinked_history_is_refused_and_its_target_untouched() {
        let path = scratch("symlink");
        let victim = path.with_file_name("victim.txt");
        std::fs::write(&victim, b"keep me").unwrap();
        std::os::unix::fs::symlink(&victim, &path).unwrap();
        assert!(matches!(load(&path), Err(HistoryError::Io(_))));
        assert!(matches!(
            append(&path, &run("unit", 1, 0)),
            Err(HistoryError::Io(_))
        ));
        assert_eq!(std::fs::read(&victim).unwrap(), b"keep me");
    }
}

/// Command-line surface over the run history. Kept in this module so argument
/// parsing is unit-tested without the binary. The caller supplies the clock and
/// the commit so a test is deterministic and nothing here reads global state.
pub mod cli {
    use std::io::Write;
    use std::path::PathBuf;

    use super::{RunRecord, Verdict, append, load, verdict};
    use crate::exit::{EX_DATAERR, EX_IOERR, EX_USAGE};
    use crate::textnorm::escape_controls;

    pub const USAGE: &str = "usage: huntsman-recon run-history (record --suite NAME (--passed N --failed N | --from-stdin) [--commit SHA] [--file PATH] | show [--suite NAME] [--file PATH])";

    const DEFAULT_FILE: &str = "var/run_history.jsonl";

    /// Parsed `record` arguments, before any I/O.
    #[derive(Debug, PartialEq, Eq)]
    struct RecordArgs {
        suite: String,
        passed: u64,
        failed: u64,
        commit: String,
        file: PathBuf,
    }

    fn parse_record(args: &[String]) -> Result<RecordArgs, String> {
        let (mut suite, mut passed, mut failed, mut commit, mut file) =
            (None, None, None, None, None);
        let mut iter = args.iter();
        while let Some(flag) = iter.next() {
            let mut value = || match iter.next() {
                // A value beginning with "--" is the next flag, not this flag's
                // value: reject it rather than silently swallowing it.
                Some(next) if next.starts_with("--") => {
                    Err(format!("{flag} needs a value, got the flag {next:?}"))
                }
                Some(next) => Ok(next),
                None => Err(format!("{flag} needs a value")),
            };
            match flag.as_str() {
                "--suite" => suite = Some(value()?.clone()),
                "--passed" => {
                    passed = Some(
                        value()?
                            .parse::<u64>()
                            .map_err(|_| "--passed must be a number".to_string())?,
                    );
                }
                "--failed" => {
                    failed = Some(
                        value()?
                            .parse::<u64>()
                            .map_err(|_| "--failed must be a number".to_string())?,
                    );
                }
                "--commit" => commit = Some(value()?.clone()),
                "--file" => file = Some(PathBuf::from(value()?)),
                other => return Err(format!("unknown argument {other:?}")),
            }
        }
        Ok(RecordArgs {
            suite: suite.ok_or("record needs --suite")?,
            passed: passed.ok_or("record needs --passed")?,
            failed: failed.ok_or("record needs --failed")?,
            commit: commit.unwrap_or_else(|| "unknown".to_string()),
            file: file.unwrap_or_else(|| PathBuf::from(DEFAULT_FILE)),
        })
    }

    fn parse_show(args: &[String]) -> Result<(Option<String>, PathBuf), String> {
        let (mut suite, mut file) = (None, None);
        let mut iter = args.iter();
        while let Some(flag) = iter.next() {
            let mut value = || match iter.next() {
                Some(next) if next.starts_with("--") => {
                    Err(format!("{flag} needs a value, got the flag {next:?}"))
                }
                Some(next) => Ok(next),
                None => Err(format!("{flag} needs a value")),
            };
            match flag.as_str() {
                "--suite" => suite = Some(value()?.clone()),
                "--file" => file = Some(PathBuf::from(value()?)),
                other => return Err(format!("unknown argument {other:?}")),
            }
        }
        Ok((suite, file.unwrap_or_else(|| PathBuf::from(DEFAULT_FILE))))
    }

    /// Run the command. `now_unix` and the writers are injected so the whole
    /// surface is deterministic under test. Returns the process exit code.
    pub fn run(args: &[String], now_unix: u64, out: &mut dyn Write, err: &mut dyn Write) -> u8 {
        match args.first().map(String::as_str) {
            Some("record") => record(&args[1..], now_unix, out, err),
            Some("show") => show(&args[1..], out, err),
            Some("help") => {
                let _ = writeln!(out, "{USAGE}");
                0
            }
            _ => {
                let _ = writeln!(err, "{USAGE}");
                EX_USAGE
            }
        }
    }

    fn record(args: &[String], now_unix: u64, out: &mut dyn Write, err: &mut dyn Write) -> u8 {
        let parsed = match parse_record(args) {
            Ok(parsed) => parsed,
            Err(message) => {
                let _ = writeln!(err, "run-history: {message}\n{USAGE}");
                return EX_USAGE;
            }
        };
        let history = match load(&parsed.file) {
            Ok(history) => history,
            Err(error) => {
                let _ = writeln!(err, "run-history: {error}");
                return EX_IOERR;
            }
        };
        let record = RunRecord {
            commit: parsed.commit,
            suite: parsed.suite,
            passed: parsed.passed,
            failed: parsed.failed,
            recorded_at_unix: now_unix,
        };
        let verdict = verdict(&history, &record);
        if let Err(error) = append(&parsed.file, &record) {
            let _ = writeln!(err, "run-history: {error}");
            return EX_IOERR;
        }
        let _ = writeln!(
            out,
            "suite={} passed={} failed={} verdict={}",
            record.suite,
            record.passed,
            record.failed,
            describe(&verdict)
        );
        match verdict {
            Verdict::Regressed { .. } => EX_DATAERR,
            _ => 0,
        }
    }

    fn show(args: &[String], out: &mut dyn Write, err: &mut dyn Write) -> u8 {
        let (suite, file) = match parse_show(args) {
            Ok(parsed) => parsed,
            Err(message) => {
                let _ = writeln!(err, "run-history: {message}\n{USAGE}");
                return EX_USAGE;
            }
        };
        let history = match load(&file) {
            Ok(history) => history,
            Err(error) => {
                let _ = writeln!(err, "run-history: {error}");
                return EX_IOERR;
            }
        };
        for record in history
            .iter()
            .filter(|r| suite.as_deref().is_none_or(|s| s == r.suite))
        {
            // The commit and the suite are text from the history file, which anyone may have written.
            let _ = writeln!(
                out,
                "commit={} suite={} passed={} failed={} at={}",
                escape_controls(&record.commit),
                escape_controls(&record.suite),
                record.passed,
                record.failed,
                record.recorded_at_unix
            );
        }
        0
    }

    fn describe(verdict: &Verdict) -> String {
        match verdict {
            Verdict::Baseline => "baseline".to_string(),
            Verdict::Held => "held".to_string(),
            Verdict::Regressed { reason } => format!("regressed ({reason})"),
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::test_support::unexpected_controls;

        fn scratch(name: &str) -> PathBuf {
            let dir = std::env::temp_dir().join(format!("rh-cli-{name}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).unwrap();
            dir.join("runs.jsonl")
        }

        fn argv(parts: &[&str]) -> Vec<String> {
            parts.iter().map(|s| (*s).to_string()).collect()
        }

        #[test]
        fn show_cannot_be_driven_by_the_text_in_the_history_file() {
            // The file is read as written, and anyone may have written it.
            let file = scratch("hostile");
            let record = RunRecord {
                commit: "abc\u{1b}]0;x\u{7}\nforged".into(),
                suite: "unit\u{9b}2J\u{2028}".into(),
                passed: 1,
                failed: 0,
                recorded_at_unix: 5,
            };
            append(&file, &record).unwrap();
            let (mut o, mut e) = (Vec::new(), Vec::new());
            let code = run(
                &argv(&["show", "--file", file.to_str().unwrap()]),
                1,
                &mut o,
                &mut e,
            );
            assert_eq!(code, 0, "{}", String::from_utf8_lossy(&e));
            let shown = String::from_utf8(o).unwrap();
            assert_eq!(shown.lines().count(), 1, "{shown:?}");
            assert!(
                unexpected_controls(&shown, &['\n']).is_empty() && !shown.contains('\u{2028}'),
                "{shown:?}"
            );
            assert!(
                shown
                    .contains("commit=abc\\u{1b}]0;x\\u{7}\\nforged suite=unit\\u{9b}2J\\u{2028} ")
            );
        }

        #[test]
        fn record_reports_baseline_then_held_then_regressed_with_exit_codes() {
            let file = scratch("codes");
            let f = file.to_str().unwrap();
            let (mut o, mut e) = (Vec::new(), Vec::new());
            assert_eq!(
                run(
                    &argv(&[
                        "record", "--suite", "unit", "--passed", "10", "--failed", "0", "--file", f
                    ]),
                    1,
                    &mut o,
                    &mut e
                ),
                0
            );
            assert!(String::from_utf8(o).unwrap().contains("verdict=baseline"));

            let (mut o, mut e) = (Vec::new(), Vec::new());
            assert_eq!(
                run(
                    &argv(&[
                        "record", "--suite", "unit", "--passed", "10", "--failed", "0", "--file", f
                    ]),
                    2,
                    &mut o,
                    &mut e
                ),
                0
            );
            assert!(String::from_utf8(o).unwrap().contains("verdict=held"));

            let (mut o, mut e) = (Vec::new(), Vec::new());
            let code = run(
                &argv(&[
                    "record", "--suite", "unit", "--passed", "10", "--failed", "1", "--file", f,
                ]),
                3,
                &mut o,
                &mut e,
            );
            assert_eq!(code, EX_DATAERR);
            assert!(String::from_utf8(o).unwrap().contains("verdict=regressed"));
        }

        #[test]
        fn record_rejects_missing_flags_before_touching_the_file() {
            let file = scratch("usage");
            let f = file.to_str().unwrap();
            let (mut o, mut e) = (Vec::new(), Vec::new());
            let code = run(
                &argv(&["record", "--suite", "unit", "--file", f]),
                1,
                &mut o,
                &mut e,
            );
            assert_eq!(code, EX_USAGE);
            assert!(String::from_utf8(e).unwrap().contains("--passed"));
            assert!(!file.exists(), "no file should be created on a usage error");
        }

        #[test]
        fn show_filters_by_suite() {
            let file = scratch("show");
            let f = file.to_str().unwrap();
            let (mut o, mut e) = (Vec::new(), Vec::new());
            run(
                &argv(&[
                    "record", "--suite", "unit", "--passed", "5", "--failed", "0", "--file", f,
                ]),
                1,
                &mut o,
                &mut e,
            );
            run(
                &argv(&[
                    "record",
                    "--suite",
                    "integration",
                    "--passed",
                    "3",
                    "--failed",
                    "0",
                    "--file",
                    f,
                ]),
                2,
                &mut o,
                &mut e,
            );
            let (mut o, mut e) = (Vec::new(), Vec::new());
            run(
                &argv(&["show", "--suite", "unit", "--file", f]),
                0,
                &mut o,
                &mut e,
            );
            let text = String::from_utf8(o).unwrap();
            assert!(text.contains("suite=unit"));
            assert!(!text.contains("suite=integration"));
        }

        #[test]
        fn unknown_subcommand_is_a_usage_error() {
            let (mut o, mut e) = (Vec::new(), Vec::new());
            assert_eq!(run(&argv(&["frobnicate"]), 0, &mut o, &mut e), EX_USAGE);
        }

        #[test]
        fn a_value_flag_does_not_swallow_the_following_flag() {
            // `show --suite --file` must error, not let --suite eat --file and
            // then silently load the default file for a bogus suite.
            let err = parse_show(&argv(&["--suite", "--file"])).unwrap_err();
            assert!(err.contains("--suite needs a value"), "{err}");

            let err =
                parse_record(&argv(&["--suite", "unit", "--passed", "--failed"])).unwrap_err();
            assert!(err.contains("--passed needs a value"), "{err}");
        }

        #[test]
        fn show_rejecting_a_missing_value_does_not_run_silently() {
            let (mut o, mut e) = (Vec::new(), Vec::new());
            let code = run(&argv(&["show", "--suite", "--file"]), 0, &mut o, &mut e);
            assert_eq!(code, EX_USAGE);
            assert!(o.is_empty(), "nothing should print on a usage error");
        }
    }
}
