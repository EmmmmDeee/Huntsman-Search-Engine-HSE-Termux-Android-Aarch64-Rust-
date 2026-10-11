//! Process helpers the xtask commands share: the repository root, git output, and a command
//! that runs under a time limit and is killed when the limit passes. A gate run keeps each
//! step's output under `target/repair-gate/<run>/`, so a failure can be read again without
//! running the gate once more.

use std::collections::VecDeque;
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::error::{Error, Result};

/// Gate runs kept under `target/repair-gate/`. Older run directories are removed when a run starts.
const KEEP_RUNS: usize = 5;
/// Lines of a failing step's output printed to the terminal, counted from its end.
const TAIL_LINES: usize = 80;
/// Tells runs started by one process apart, even within one second.
static RUN_SEQUENCE: AtomicU64 = AtomicU64::new(0);

/// The repository root. This crate lives in `<root>/xtask`.
#[must_use]
pub fn repository_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .map_or_else(|| PathBuf::from("."), Path::to_path_buf)
}

/// The standard output of `git ARGS` in ROOT. A git failure is an error, never empty output.
pub fn git_stdout(root: &Path, args: &[&str]) -> Result<Vec<u8>> {
    let shown = format!("git {}", args.join(" "));
    let output = Command::new("git")
        .args(args)
        .current_dir(root)
        .output()
        .map_err(|source| Error::Command {
            shown: shown.clone(),
            reason: format!("could not start: {source}"),
        })?;
    if !output.status.success() {
        return Err(Error::Command {
            shown,
            reason: format!("exited with {}", output.status),
        });
    }
    Ok(output.stdout)
}

/// One gate run's record: a directory with `NN.log` for each step, numbered in the order the
/// steps ran, and `summary.txt`, which has one line per step: `NN`, the status, the seconds it
/// took, and the command.
pub struct RunRecord {
    dir: PathBuf,
    steps: usize,
}

impl RunRecord {
    /// A new run directory for MODE under ROOT's `target/repair-gate/`. Before it is created,
    /// the run directories beyond the newest `KEEP_RUNS - 1` are removed, so `KEEP_RUNS` remain.
    ///
    /// # Errors
    /// `Error::Io` when the directory cannot be created, or an old run cannot be removed.
    pub fn create(root: &Path, mode: &str) -> Result<Self> {
        let base = root.join("target").join("repair-gate");
        fs::create_dir_all(&base).map_err(|source| io_error(&base, source))?;
        prune(&base)?;
        let seconds = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |elapsed| elapsed.as_secs());
        let sequence = RUN_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let dir = base.join(format!(
            "{seconds:012}-{:07}-{sequence:04}-{mode}",
            std::process::id()
        ));
        fs::create_dir(&dir).map_err(|source| io_error(&dir, source))?;
        Ok(Self { dir, steps: 0 })
    }

    /// The directory holding this run's logs and summary.
    #[must_use]
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Opens the log for the next step. Returns the step's number, its path, and the file.
    fn next_log(&mut self) -> Result<(usize, PathBuf, File)> {
        self.steps += 1;
        let path = self.dir.join(format!("{:02}.log", self.steps));
        let file = File::create(&path).map_err(|source| io_error(&path, source))?;
        Ok((self.steps, path, file))
    }

    /// Appends the summary line for step INDEX.
    fn finish(&self, index: usize, status: &str, elapsed: Duration, shown: &str) -> Result<()> {
        let summary = self.dir.join("summary.txt");
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&summary)
            .map_err(|source| io_error(&summary, source))?;
        writeln!(
            file,
            "{index:02}\t{status}\t{:.1}\t{shown}",
            elapsed.as_secs_f64()
        )
        .map_err(|source| io_error(&summary, source))
    }
}

/// Runs PROGRAM with ARGS in ROOT. The command is printed first. Its output goes to the next log
/// in RECORD, and its outcome is one line in the record's summary. A run still going at LIMIT is
/// killed, and the step fails. A failing step prints the end of its log, so the failure can be
/// read without opening the file.
pub fn run_step(
    root: &Path,
    limit: Duration,
    record: &mut RunRecord,
    program: &str,
    args: &[&str],
) -> Result<()> {
    let shown = std::iter::once(program)
        .chain(args.iter().copied())
        .collect::<Vec<_>>()
        .join(" ");
    println!("xtask: RUN: {shown}");
    let (index, log, stdout) = record.next_log()?;
    let stderr = stdout
        .try_clone()
        .map_err(|source| io_error(&log, source))?;
    let started = Instant::now();
    let mut child = match Command::new(program)
        .args(args)
        .current_dir(root)
        .stdin(Stdio::null())
        .stdout(Stdio::from(stdout))
        .stderr(Stdio::from(stderr))
        .spawn()
    {
        Ok(child) => child,
        Err(source) => {
            record.finish(index, "NOT-STARTED", started.elapsed(), &shown)?;
            return Err(Error::Command {
                shown,
                reason: format!("could not start: {source}"),
            });
        }
    };
    let verdict = loop {
        match child.try_wait() {
            Ok(Some(status)) if status.success() => break Ok(()),
            Ok(Some(status)) => break Err(("FAIL", format!("exited with {status}"))),
            Ok(None) => {}
            Err(source) => break Err(("FAIL", format!("could not be waited for: {source}"))),
        }
        if started.elapsed() >= limit {
            let _ = child.kill();
            let _ = child.wait();
            break Err(("TIMEOUT", format!("timed out after {}s", limit.as_secs())));
        }
        std::thread::sleep(Duration::from_millis(100));
    };
    let elapsed = started.elapsed();
    match verdict {
        Ok(()) => {
            record.finish(index, "PASS", elapsed, &shown)?;
            Ok(())
        }
        Err((status, reason)) => {
            record.finish(index, status, elapsed, &shown)?;
            print_tail(&log)?;
            Err(Error::Command {
                shown,
                reason: format!("{reason}; output kept in {}", log.display()),
            })
        }
    }
}

/// Removes run directories under BASE, oldest first, until `KEEP_RUNS - 1` remain. Names begin
/// with a zero-padded timestamp, so sorting the names sorts the runs by age.
fn prune(base: &Path) -> Result<()> {
    let entries = fs::read_dir(base).map_err(|source| io_error(base, source))?;
    let mut runs = Vec::new();
    for entry in entries {
        let path = entry.map_err(|source| io_error(base, source))?.path();
        if path.is_dir() {
            runs.push(path);
        }
    }
    runs.sort();
    let excess = runs.len().saturating_sub(KEEP_RUNS - 1);
    for old in &runs[..excess] {
        fs::remove_dir_all(old).map_err(|source| io_error(old, source))?;
    }
    Ok(())
}

/// Prints the last `TAIL_LINES` lines of LOG to the terminal, under a heading that names the file.
fn print_tail(log: &Path) -> Result<()> {
    let lines = last_lines(log, TAIL_LINES)?;
    eprintln!("xtask: last {} lines of {}:", lines.len(), log.display());
    for line in lines {
        eprintln!("{line}");
    }
    Ok(())
}

/// The last COUNT lines of the file at PATH. Bytes that are not UTF-8 are shown with replacement
/// characters, so a log with stray bytes still prints.
fn last_lines(path: &Path, count: usize) -> Result<Vec<String>> {
    let file = File::open(path).map_err(|source| io_error(path, source))?;
    let mut lines: VecDeque<String> = VecDeque::with_capacity(count);
    for line in BufReader::new(file).split(b'\n') {
        let line = line.map_err(|source| io_error(path, source))?;
        if lines.len() == count {
            lines.pop_front();
        }
        lines.push_back(String::from_utf8_lossy(&line).into_owned());
    }
    Ok(lines.into())
}

fn io_error(path: &Path, source: std::io::Error) -> Error {
    Error::Io {
        path: path.to_path_buf(),
        source,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch_root(tag: &str) -> PathBuf {
        let root = std::env::temp_dir().join(format!("xtask-proc-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).expect("scratch root");
        root
    }

    #[test]
    fn last_lines_keeps_only_the_end_of_the_output() {
        let root = scratch_root("tail");
        let log = root.join("long.log");
        let text: String = (1..=100).map(|n| format!("line {n}\n")).collect();
        fs::write(&log, text).expect("write log");
        let lines = last_lines(&log, 3).expect("tail");
        assert_eq!(lines, ["line 98", "line 99", "line 100"]);
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn a_passing_step_keeps_its_output_and_records_pass() {
        let root = scratch_root("pass");
        let mut record = RunRecord::create(&root, "fast").expect("record");
        run_step(
            &root,
            Duration::from_secs(60),
            &mut record,
            "sh",
            &["-c", "echo hello"],
        )
        .expect("the step passes");
        let log = fs::read_to_string(record.dir().join("01.log")).expect("step log");
        assert_eq!(log, "hello\n");
        let summary = fs::read_to_string(record.dir().join("summary.txt")).expect("summary");
        assert!(summary.starts_with("01\tPASS\t"), "{summary}");
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn a_failing_step_keeps_its_output_and_names_the_log() {
        let root = scratch_root("fail");
        let mut record = RunRecord::create(&root, "fast").expect("record");
        let error = run_step(
            &root,
            Duration::from_secs(60),
            &mut record,
            "sh",
            &["-c", "echo before; exit 3"],
        )
        .expect_err("the step fails");
        let message = error.to_string();
        assert!(message.contains("exited with"), "{message}");
        assert!(message.contains("01.log"), "{message}");
        let summary = fs::read_to_string(record.dir().join("summary.txt")).expect("summary");
        assert!(summary.starts_with("01\tFAIL\t"), "{summary}");
        let log = fs::read_to_string(record.dir().join("01.log")).expect("step log");
        assert_eq!(log, "before\n");
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn only_the_newest_runs_are_kept() {
        let root = scratch_root("prune");
        for _ in 0..KEEP_RUNS + 2 {
            RunRecord::create(&root, "fast").expect("record");
        }
        let base = root.join("target").join("repair-gate");
        let kept = fs::read_dir(&base).expect("runs").count();
        assert_eq!(kept, KEEP_RUNS);
        let _ = fs::remove_dir_all(&root);
    }
}
