//! Process helpers the xtask commands share: the repository root, git output, and a command
//! that runs under a time limit and is killed when the limit passes. A gate run keeps each
//! step's output under `target/repair-gate/<run>/`, so a failure can be read again without
//! running the gate once more. Every step builds in a directory of the checkout's own
//! ([`checkout_target_dir`]), and a gate run holds the checkout's lock, so no two runs share a
//! build directory or a tree.

use std::collections::VecDeque;
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, ErrorKind, Write};
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
/// The lock file a gate run holds. It sits beside the run directories, which pruning skips
/// because it is a file, not a directory.
const LOCK_FILE: &str = "gate.lock";

/// The repository root. This crate lives in `<root>/xtask`.
///
/// `cargo run`, and so `cargo gate`, names the package it runs in `CARGO_MANIFEST_DIR`, and that
/// is the checkout to work on. The path compiled into the binary is only the fallback, for a
/// binary run directly: checkouts that share a target directory share one `xtask` binary, which
/// cargo does not rebuild for a checkout at another path, so its compiled path can name another
/// checkout. The steps it runs build in the checkout's own directory, whichever binary runs them.
#[must_use]
pub fn repository_root() -> PathBuf {
    let manifest = std::env::var_os("CARGO_MANIFEST_DIR")
        .filter(|dir| !dir.is_empty())
        .map_or_else(|| PathBuf::from(env!("CARGO_MANIFEST_DIR")), PathBuf::from);
    manifest
        .parent()
        .map_or_else(|| PathBuf::from("."), Path::to_path_buf)
}

/// Where the gate builds for the checkout at ROOT: its own `target/`, or, when `CARGO_TARGET_DIR`
/// (SHARED) names a directory, `checkouts/<name>-<cksum of its path>` inside it, the directory
/// `scripts/lifecycle.sh` builds the checkout in there. Cargo names a workspace crate's build
/// without its checkout's path and judges it fresh by file times, so in a directory several
/// checkouts share it would test one checkout's code for another. A directory the caller chose
/// is kept, as on Termux, where a checkout on shared storage cannot run what is built beside it.
#[must_use]
pub fn checkout_target_dir(root: &Path, shared: Option<&std::ffi::OsStr>) -> PathBuf {
    let Some(shared) = shared.filter(|dir| !dir.is_empty()) else {
        return root.join("target");
    };
    let root = root.canonicalize().unwrap_or_else(|_| root.to_path_buf());
    // Only characters cargo accepts in a library path: a `:` would break every build there.
    let name: String = root
        .file_name()
        .map_or_else(String::new, |name| name.to_string_lossy().into_owned())
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-') {
                c
            } else {
                '_'
            }
        })
        .collect();
    let path = root.as_os_str().to_string_lossy();
    let shared =
        std::env::current_dir().map_or_else(|_| PathBuf::from(shared), |cwd| cwd.join(shared));
    shared
        .join("checkouts")
        .join(format!("{name}-{}", cksum(path.as_bytes())))
}

/// POSIX `cksum` of BYTES (CRC-32 over the bytes and then their length), as `cksum` prints it.
fn cksum(bytes: &[u8]) -> u32 {
    fn update(crc: u32, byte: u8) -> u32 {
        let mut crc = crc ^ (u32::from(byte) << 24);
        for _ in 0..8 {
            crc = if crc & 0x8000_0000 == 0 {
                crc << 1
            } else {
                (crc << 1) ^ 0x04C1_1DB7
            };
        }
        crc
    }
    let mut crc = bytes.iter().fold(0, |crc, &byte| update(crc, byte));
    let mut length = bytes.len();
    while length > 0 {
        crc = update(crc, (length & 0xff) as u8);
        length >>= 8;
    }
    !crc
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

/// The lock a gate run holds on its checkout. Two runs in one checkout share the build directory
/// and the tree, so the later one would read the earlier one's writes as its own changes. The
/// lock file names its holder's process id. A holder that has exited leaves a stale lock, which
/// the next run takes over. A holder that is still running blocks the run.
pub struct GateLock {
    path: PathBuf,
    pid: String,
}

impl GateLock {
    /// Takes the gate lock of the checkout at ROOT.
    ///
    /// # Errors
    /// `Error::Refused` when a running process holds the lock, or the holder cannot be read.
    /// `Error::Io` when the lock file cannot be created.
    pub fn acquire(root: &Path) -> Result<Self> {
        let base = root.join("target").join("repair-gate");
        fs::create_dir_all(&base).map_err(|source| io_error(&base, source))?;
        let path = base.join(LOCK_FILE);
        if let Some(lock) = Self::create(&path)? {
            return Ok(lock);
        }
        let holder = fs::read_to_string(&path)
            .unwrap_or_default()
            .trim()
            .to_owned();
        let stale = holder
            .parse::<u32>()
            .is_ok_and(|pid| pid > 0 && !process_is_alive(pid));
        if !stale {
            return Err(held_by(&holder, &path));
        }
        fs::remove_file(&path).map_err(|source| io_error(&path, source))?;
        Self::create(&path)?.ok_or_else(|| {
            Error::Refused(format!(
                "another gate run took over {} at the same moment; run the gate again",
                path.display()
            ))
        })
    }

    /// Creates the lock file, holding this process's id. `None` when the file already exists.
    fn create(path: &Path) -> Result<Option<Self>> {
        let pid = std::process::id().to_string();
        match OpenOptions::new().write(true).create_new(true).open(path) {
            Ok(mut file) => {
                writeln!(file, "{pid}").map_err(|source| io_error(path, source))?;
                Ok(Some(Self {
                    path: path.to_path_buf(),
                    pid,
                }))
            }
            Err(source) if source.kind() == ErrorKind::AlreadyExists => Ok(None),
            Err(source) => Err(io_error(path, source)),
        }
    }
}

impl Drop for GateLock {
    fn drop(&mut self) {
        // The file goes only while it still names this run, so a lock taken over from this run
        // is left alone.
        if fs::read_to_string(&self.path).is_ok_and(|held| held.trim() == self.pid.as_str()) {
            let _ = fs::remove_file(&self.path);
        }
    }
}

/// The refusal for a checkout that a running gate run holds. HOLDER is the holder's process id,
/// empty when the lock file does not yet name one.
fn held_by(holder: &str, path: &Path) -> Error {
    let who = if holder.is_empty() {
        "a gate run that has not yet recorded its process id".to_owned()
    } else {
        format!("the gate run in process {holder}")
    };
    Error::Refused(format!(
        "{who} holds {}; wait for it to finish, or remove the file if no gate is running",
        path.display()
    ))
}

/// Whether process PID exists. `kill -0` sends no signal and only checks that the process is
/// there. A process owned by another user counts as gone, because kill refuses it. When the check
/// cannot run, the process counts as alive, so a lock is never taken over on a guess.
fn process_is_alive(pid: u32) -> bool {
    match Command::new("kill")
        .arg("-0")
        .arg(pid.to_string())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
    {
        Ok(status) => status.success(),
        Err(_) => true,
    }
}

/// Runs PROGRAM with ARGS in ROOT. The command is printed first. Its output goes to the next log
/// in RECORD, and its outcome is one line in the record's summary. A run still going at LIMIT is
/// killed, and the step fails. A failing step prints the end of its log, so the failure can be
/// read without opening the file.
///
/// Cargo builds in ROOT's own directory ([`checkout_target_dir`]), as both its target and its
/// build directory (cargo 1.91 and later keep compiled crates in the build directory, which a
/// user may also share): in a directory another checkout shares, cargo can reuse that checkout's
/// compiled crates as fresh, and the step would test its code instead of ROOT's.
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
    let builds = checkout_target_dir(root, std::env::var_os("CARGO_TARGET_DIR").as_deref());
    let (index, log, stdout) = record.next_log()?;
    let stderr = stdout
        .try_clone()
        .map_err(|source| io_error(&log, source))?;
    let started = Instant::now();
    let mut child = match Command::new(program)
        .args(args)
        .current_dir(root)
        .env("CARGO_TARGET_DIR", &builds)
        .env("CARGO_BUILD_BUILD_DIR", &builds)
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
    fn a_step_builds_in_the_checkouts_own_directory() {
        // Whatever target directory the gate was started with, a step's cargo builds in ROOT's.
        let root = scratch_root("target-dir");
        let mut record = RunRecord::create(&root, "fast").expect("record");
        run_step(
            &root,
            Duration::from_secs(60),
            &mut record,
            "sh",
            &[
                "-c",
                "printf '%s|%s' \"$CARGO_TARGET_DIR\" \"$CARGO_BUILD_BUILD_DIR\"",
            ],
        )
        .expect("the step passes");
        let log = fs::read_to_string(record.dir().join("01.log")).expect("step log");
        let builds = checkout_target_dir(&root, std::env::var_os("CARGO_TARGET_DIR").as_deref());
        assert_eq!(log, format!("{0}|{0}", builds.display()));
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn each_checkout_builds_in_a_directory_of_its_own() {
        let first = scratch_root("own-first");
        let second = scratch_root("own-second");
        // By default, in the checkout's own target/.
        assert_eq!(checkout_target_dir(&first, None), first.join("target"));
        assert_eq!(
            checkout_target_dir(&first, Some(std::ffi::OsStr::new(""))),
            first.join("target")
        );
        // In a directory the checkouts share, each in one of its own there, named as
        // scripts/lifecycle.sh names it, and the same for another spelling of the checkout.
        let shared = std::ffi::OsStr::new("/shared/cache");
        let own = checkout_target_dir(&first, Some(shared));
        let path = first.canonicalize().expect("checkout");
        let name = path.file_name().expect("name").to_string_lossy();
        let key = cksum(path.as_os_str().to_string_lossy().as_bytes());
        assert_eq!(
            own,
            Path::new("/shared/cache/checkouts").join(format!("{name}-{key}"))
        );
        assert_ne!(own, checkout_target_dir(&second, Some(shared)));
        fs::create_dir_all(first.join("xtask")).expect("xtask directory");
        assert_eq!(
            own,
            checkout_target_dir(&first.join("xtask").join(".."), Some(shared))
        );
        let _ = fs::remove_dir_all(&first);
        let _ = fs::remove_dir_all(&second);
    }

    #[test]
    fn a_checkout_name_keeps_only_characters_a_library_path_accepts() {
        let root = scratch_root("wt:fix one");
        let own = checkout_target_dir(&root, Some(std::ffi::OsStr::new("/shared")));
        let name = own
            .file_name()
            .expect("name")
            .to_string_lossy()
            .into_owned();
        assert!(name.starts_with("xtask-proc-wt_fix_one-"), "{name}");
        assert!(
            name.chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-')),
            "{name}"
        );
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn a_checkout_key_is_the_posix_cksum_of_its_path() {
        // As `printf '%s' PATH | cksum` prints it.
        assert_eq!(cksum(b""), 4_294_967_295);
        assert_eq!(cksum(b"x"), 12_738_659);
        assert_eq!(cksum(b"123456789"), 930_766_865);
        assert_eq!(
            cksum(b"/data/data/com.termux/files/home/Huntsman"),
            1_392_625_309
        );
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

    #[test]
    fn a_checkout_held_by_a_running_gate_refuses_a_second_run() {
        let root = scratch_root("lock-held");
        let _first = GateLock::acquire(&root).expect("the first run takes the lock");
        let error = GateLock::acquire(&root)
            .err()
            .expect("the second run is refused");
        let message = error.to_string();
        assert!(message.contains("holds"), "{message}");
        assert!(
            message.contains(&format!("process {}", std::process::id())),
            "{message}"
        );
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn dropping_the_lock_releases_the_checkout() {
        let root = scratch_root("lock-released");
        drop(GateLock::acquire(&root).expect("the first run takes the lock"));
        let _again = GateLock::acquire(&root).expect("a later run takes the lock");
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn a_lock_left_by_an_exited_process_is_taken_over() {
        let root = scratch_root("lock-stale");
        let base = root.join("target").join("repair-gate");
        fs::create_dir_all(&base).expect("run directory");
        let mut child = Command::new("sh")
            .args(["-c", "exit 0"])
            .spawn()
            .expect("a short-lived process");
        let pid = child.id();
        child.wait().expect("the process exits");
        fs::write(base.join(LOCK_FILE), format!("{pid}\n")).expect("a stale lock");
        let _lock = GateLock::acquire(&root).expect("the stale lock is taken over");
        let _ = fs::remove_dir_all(&root);
    }
}
