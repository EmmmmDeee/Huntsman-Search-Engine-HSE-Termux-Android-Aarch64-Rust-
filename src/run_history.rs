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
}
