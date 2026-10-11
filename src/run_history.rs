//! Durable history of test-suite runs and a regression verdict between them.
//!
//! Each run is one JSON line, appended to a file, so a crash can lose at most
//! the line being written. Loading is strict: a malformed line is an error that
//! names its line number, never a silently skipped record. The verdict compares a
//! run against the one before it and reports a regression only on measured
//! evidence: a new failure, or a suite that ran fewer tests than before.

use std::fs::OpenOptions;
use std::io::{self, BufRead, BufReader, Write};
use std::path::Path;

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

/// Append one run as a JSON line. Creates the file if it does not exist.
pub fn append(path: &Path, record: &RunRecord) -> Result<(), HistoryError> {
    let mut line = serde_json::to_string(record).map_err(|e| HistoryError::Malformed {
        line: 0,
        reason: e.to_string(),
    })?;
    line.push('\n');
    let mut file = OpenOptions::new().create(true).append(true).open(path)?;
    file.write_all(line.as_bytes())?;
    file.sync_data()?;
    Ok(())
}

/// Load every run in file order. Missing file means an empty history.
pub fn load(path: &Path) -> Result<Vec<RunRecord>, HistoryError> {
    if !path.exists() {
        return Ok(Vec::new());
    }
    let reader = BufReader::new(std::fs::File::open(path)?);
    let mut out = Vec::new();
    for (index, line) in reader.lines().enumerate() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let record = serde_json::from_str(&line).map_err(|e| HistoryError::Malformed {
            line: index + 1,
            reason: e.to_string(),
        })?;
        out.push(record);
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
}

/// Command-line surface over the run history. Kept in this module so argument
/// parsing is unit-tested without the binary. The caller supplies the clock and
/// the commit so a test is deterministic and nothing here reads global state.
pub mod cli {
    use std::io::Write;
    use std::path::PathBuf;

    use super::{RunRecord, Verdict, append, load, verdict};

    pub const USAGE: &str = "usage: huntsman-recon run-history (record --suite NAME (--passed N --failed N | --from-stdin) [--commit SHA] [--file PATH] | show [--suite NAME] [--file PATH])";

    const EX_USAGE: u8 = 64;
    const EX_REGRESSION: u8 = 65;
    const EX_IO: u8 = 74;
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
            let mut value = || iter.next().ok_or_else(|| format!("{flag} needs a value"));
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
            let mut value = || iter.next().ok_or_else(|| format!("{flag} needs a value"));
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
                return EX_IO;
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
            return EX_IO;
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
            Verdict::Regressed { .. } => EX_REGRESSION,
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
                return EX_IO;
            }
        };
        for record in history
            .iter()
            .filter(|r| suite.as_deref().is_none_or(|s| s == r.suite))
        {
            let _ = writeln!(
                out,
                "commit={} suite={} passed={} failed={} at={}",
                record.commit, record.suite, record.passed, record.failed, record.recorded_at_unix
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
            assert_eq!(code, EX_REGRESSION);
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
    }
}
