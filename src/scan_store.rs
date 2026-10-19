//! Saved scans: Spiderfoot's scan instances, kept on the device.
//!
//! Each scan is a directory under the store, named by its id: `scan.json` holds the scan's row
//! (target, options, status, times, counts), `results.json` everything it found (entities, source
//! outcomes, data elements, correlations, the lookup's report) and `log.jsonl` its log, one entry
//! per line. Rows and results are replaced atomically and durably through [`crate::fsio`], private
//! to the user, so a killed process leaves the old file or the new one and never half of either.
//!
//! A scan's status is one of Spiderfoot's: `CREATED`, `STARTING`, `RUNNING`, `ABORT-REQUESTED`,
//! `ABORTED`, `FINISHED`, `ERROR-FAILED`. A server that stops while a scan runs cannot finish it,
//! so [`ScanStore::recover`] marks every scan a previous process left active as `ABORTED`, with
//! a log entry saying why; Spiderfoot leaves such a scan `RUNNING` forever.

use std::fs::{self, OpenOptions};
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::correlator::{Correlation, rule_catalog};
use crate::entity::Entity;
use crate::recursion::PivotEdge;
use crate::sf_correlate::Finding;
pub use crate::sf_correlate::Risk;
use crate::sf_elements::DataElement;
use crate::sha256::{hex32, sha256};
use crate::source_outcome::SourceExecutionOutcome;
use crate::termination::TerminationReason;

/// The only format this build reads and writes.
pub const FORMAT_VERSION: u32 = 1;
/// The largest `scan.json`.
pub const MAX_ROW_BYTES: u64 = 256 * 1024;
/// The largest `results.json`: a lookup's entities are well under a megabyte, and the cap keeps a
/// runaway or hostile file from exhausting a phone's memory.
pub const MAX_RESULTS_BYTES: u64 = 64 * 1024 * 1024;
/// The largest `log.jsonl`; entries past it are dropped after one entry saying so.
pub const MAX_LOG_BYTES: u64 = 4 * 1024 * 1024;
/// The most scans one store lists.
pub const MAX_SCANS: usize = 4096;
/// The length of a scan id: lower-case hex.
pub const ID_LEN: usize = 16;

const ROW_FILE: &str = "scan.json";
const RESULTS_FILE: &str = "results.json";
const LOG_FILE: &str = "log.jsonl";

// Serializes appends across ScanStore instances in one process. No cross-process guarantee.
static LOG_APPEND_LOCK: Mutex<()> = Mutex::new(());

/// Why a store operation failed.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum StoreError {
    #[error("no scan {0}")]
    NotFound(String),
    #[error("{0}")]
    Invalid(String),
    #[error("scan store: {0}")]
    Io(String),
}

fn io_error(path: &Path, error: &std::io::Error) -> StoreError {
    StoreError::Io(format!("{}: {error}", path.display()))
}

fn fsio_error(error: &crate::error::Error) -> StoreError {
    StoreError::Io(error.to_string())
}

/// An optional scan artifact is absent only on `NotFound`, never on an I/O failure.
/// Pass the checked metadata result so the classification is independently testable.
fn optional_file_missing(
    path: &Path,
    metadata: std::io::Result<fs::Metadata>,
) -> Result<bool, StoreError> {
    match metadata {
        Ok(_) => Ok(false),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(true),
        Err(error) => Err(io_error(path, &error)),
    }
}

/// A scan's state, by Spiderfoot's names.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ScanStatus {
    #[serde(rename = "CREATED")]
    Created,
    #[serde(rename = "STARTING")]
    Starting,
    #[serde(rename = "RUNNING")]
    Running,
    #[serde(rename = "ABORT-REQUESTED")]
    AbortRequested,
    #[serde(rename = "ABORTED")]
    Aborted,
    #[serde(rename = "FINISHED")]
    Finished,
    #[serde(rename = "ERROR-FAILED")]
    ErrorFailed,
}

impl ScanStatus {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Created => "CREATED",
            Self::Starting => "STARTING",
            Self::Running => "RUNNING",
            Self::AbortRequested => "ABORT-REQUESTED",
            Self::Aborted => "ABORTED",
            Self::Finished => "FINISHED",
            Self::ErrorFailed => "ERROR-FAILED",
        }
    }

    /// Not finished one way or another: a scan in this state still has a worker, or had one.
    #[must_use]
    pub const fn is_active(self) -> bool {
        matches!(
            self,
            Self::Created | Self::Starting | Self::Running | Self::AbortRequested
        )
    }
}

/// What the operator asked for when starting the scan, as Spiderfoot's New Scan page offers it.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScanOptions {
    /// `all`, `footprint`, `investigate` or `passive`.
    pub usecase: String,
    /// Modules asked for by name; empty means every module the target's kind runs.
    #[serde(default)]
    pub modules: Vec<String>,
    /// Data types asked for; empty means every type.
    #[serde(default)]
    pub types: Vec<String>,
    /// How many hops past the target the scan follows what it finds, as Spiderfoot hands every
    /// event to the modules that take it: each email, username, domain, phone, IP address and
    /// BSSID a lookup finds is looked up in turn. 0 runs the target's own lookup only.
    #[serde(default)]
    pub depth: u32,
}

/// Correlation results per Spiderfoot risk level.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RiskCounts {
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub info: usize,
}

/// One scan's row: Spiderfoot's `tbl_scan_instance` plus the counts its scan list shows.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ScanRecord {
    pub format_version: u32,
    pub id: String,
    pub name: String,
    pub target: String,
    /// The target's Spiderfoot type, such as `INTERNET_NAME`.
    pub target_type: String,
    /// The lookup kind the target routed to, such as `domain`.
    pub kind: String,
    pub options: ScanOptions,
    pub status: ScanStatus,
    /// Unix milliseconds.
    pub created: u64,
    #[serde(default)]
    pub started: Option<u64>,
    #[serde(default)]
    pub ended: Option<u64>,
    #[serde(default)]
    pub elements: usize,
    #[serde(default)]
    pub unique: usize,
    #[serde(default)]
    pub correlations: RiskCounts,
    /// Sources that failed, and lookups that could not run.
    #[serde(default)]
    pub errors: usize,
    /// Every source that ran, by module name.
    #[serde(default)]
    pub modules_run: Vec<String>,
    /// The process running the scan, so [`ScanStore::recover`] leaves alone a scan another live
    /// process (a `scans run` beside `serve`) is still running.
    #[serde(default)]
    pub owner: Option<u32>,
}

/// One correlation on a saved scan, with the elements it is about: a row of Spiderfoot's
/// `tbl_scan_correlation_results`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ScanCorrelation {
    pub id: String,
    pub rule: String,
    /// The rule's name.
    #[serde(default)]
    pub name: String,
    /// The headline naming what this result found.
    pub title: String,
    pub risk: Risk,
    /// What the rule looks for.
    pub description: String,
    /// `huntsman` for Huntsman's own rules, `spiderfoot` for Spiderfoot's, else the rule's file.
    #[serde(default)]
    pub origin: String,
    /// The rule as written (Spiderfoot's `rule_logic`); empty for a built-in Huntsman rule.
    #[serde(default)]
    pub logic: String,
    pub elements: Vec<String>,
}

impl ScanCorrelation {
    /// A Huntsman correlator result as a scan correlation, naming the elements of its entities.
    #[must_use]
    pub fn from_rule(correlation: &Correlation, elements: &[DataElement]) -> Self {
        let ids: Vec<String> = correlation
            .entity_uids
            .iter()
            .filter_map(|uid| {
                elements
                    .iter()
                    .find(|element| element.entity.as_deref() == Some(uid.as_str()))
                    .map(|element| element.id.clone())
            })
            .collect();
        let mut key = correlation.rule_id.clone().into_bytes();
        for uid in &correlation.entity_uids {
            key.push(0);
            key.extend_from_slice(uid.as_bytes());
        }
        let name = correlation.rule_name.replace('_', " ");
        let description = rule_catalog()
            .into_iter()
            .find(|rule| rule.id == correlation.rule_id)
            .map_or_else(
                || correlation.description.clone(),
                |rule| rule.description.to_owned(),
            );
        Self {
            id: hex32(&sha256(&key))[..ID_LEN].to_owned(),
            rule: correlation.rule_id.clone(),
            title: format!("{name}: {}", correlation.description),
            name,
            risk: Risk::of(correlation.severity),
            description,
            origin: "huntsman".to_owned(),
            logic: String::new(),
            elements: ids,
        }
    }

    /// A Spiderfoot-rule result as a scan correlation.
    #[must_use]
    pub fn from_finding(finding: Finding) -> Self {
        Self {
            id: finding.id,
            rule: finding.rule,
            name: finding.name,
            title: finding.title,
            risk: finding.risk,
            description: finding.description,
            origin: finding.origin,
            logic: finding.logic,
            elements: finding.elements,
        }
    }
}

/// Everything a scan found, saved whole.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ScanResults {
    pub format_version: u32,
    pub scan_id: String,
    /// The report each lookup printed, in order.
    #[serde(default)]
    pub text: String,
    pub entities: Vec<Entity>,
    pub outcomes: Vec<SourceExecutionOutcome>,
    pub elements: Vec<DataElement>,
    pub correlations: Vec<ScanCorrelation>,
    /// Which lookup found which entity, generation by generation: the scan's discovery tree.
    #[serde(default)]
    pub lineage: Vec<PivotEdge>,
    /// Why the scan stopped following what it found.
    #[serde(default)]
    pub termination: Option<TerminationReason>,
}

/// A log entry's level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum LogLevel {
    Info,
    Warning,
    Error,
}

impl LogLevel {
    /// Its name as the log shows it: `INFO`, `WARNING` or `ERROR`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Info => "INFO",
            Self::Warning => "WARNING",
            Self::Error => "ERROR",
        }
    }
}

/// One line of a scan's log: Spiderfoot's Time, Component, Type and Event columns.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LogEntry {
    /// Unix milliseconds.
    pub time: u64,
    pub component: String,
    pub level: LogLevel,
    pub message: String,
}

/// Whether `id` is a scan id this store could have made. Every path below the store goes
/// through this, so an id can never name a path outside it.
#[must_use]
pub fn valid_id(id: &str) -> bool {
    id.len() == ID_LEN
        && id
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// A new scan id from the target, the time and a per-process sequence number.
#[must_use]
pub fn new_id(target: &str, now_nanos: u128, sequence: u64) -> String {
    let mut seed = target.as_bytes().to_vec();
    seed.extend_from_slice(&now_nanos.to_le_bytes());
    seed.extend_from_slice(&sequence.to_le_bytes());
    seed.extend_from_slice(&std::process::id().to_le_bytes());
    hex32(&sha256(&seed))[..ID_LEN].to_owned()
}

/// A directory of saved scans.
#[derive(Debug, Clone)]
pub struct ScanStore {
    dir: PathBuf,
}

impl ScanStore {
    /// Open the store at `dir`, creating it private to the user when it is missing.
    ///
    /// # Errors
    /// [`StoreError::Io`] when the directory cannot be created, is a symlink, or is not a
    /// directory.
    pub fn open(dir: &Path) -> Result<Self, StoreError> {
        if fs::symlink_metadata(dir).is_ok_and(|meta| meta.file_type().is_symlink()) {
            return Err(StoreError::Io(format!("{}: is a symlink", dir.display())));
        }
        fs::create_dir_all(dir).map_err(|error| io_error(dir, &error))?;
        private_dir(dir)?;
        if !dir.is_dir() {
            return Err(StoreError::Io(format!(
                "{}: not a directory",
                dir.display()
            )));
        }
        Ok(Self {
            dir: dir.to_path_buf(),
        })
    }

    #[must_use]
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    fn scan_dir(&self, id: &str) -> Result<PathBuf, StoreError> {
        if !valid_id(id) {
            return Err(StoreError::NotFound(id.to_owned()));
        }
        Ok(self.dir.join(id))
    }

    /// Distinguish an absent scan from a filesystem failure while checking its row.
    /// A nonregular row cannot establish that the scan is registered.
    fn require_row(&self, id: &str) -> Result<(), StoreError> {
        let path = self.scan_dir(id)?.join(ROW_FILE);
        match fs::symlink_metadata(&path) {
            Ok(meta) if meta.is_file() && !meta.file_type().is_symlink() => Ok(()),
            Ok(_) => Err(StoreError::Io(format!(
                "{}: not a regular scan row",
                path.display()
            ))),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                Err(StoreError::NotFound(id.to_owned()))
            }
            Err(error) => Err(io_error(&path, &error)),
        }
    }

    /// Save a new scan's row.
    ///
    /// # Errors
    /// [`StoreError::Invalid`] when a scan with that id exists; [`StoreError::Io`] on a write
    /// failure.
    pub fn create(&self, record: &ScanRecord) -> Result<(), StoreError> {
        let dir = self.scan_dir(&record.id)?;
        if fs::symlink_metadata(&dir).is_ok() {
            return Err(StoreError::Invalid(format!("scan {} exists", record.id)));
        }
        fs::create_dir(&dir).map_err(|error| io_error(&dir, &error))?;
        let created = private_dir(&dir).and_then(|()| self.write_row(record));
        if let Err(error) = created {
            // Only remove the directory if it remains empty. A concurrent writer's
            // files must never be removed by rollback, even if the first write failed.
            if let Err(cleanup) = fs::remove_dir(&dir) {
                return Err(StoreError::Io(format!(
                    "{error}; failed to remove incomplete scan directory {}: {cleanup}",
                    dir.display()
                )));
            }
            return Err(error);
        }
        Ok(())
    }

    /// Replace an existing scan's row without creating an unregistered scan.
    ///
    /// # Errors
    /// [`StoreError::NotFound`] when the scan has no persisted row; [`StoreError::Io`] for
    /// an unreadable or nonregular row, or a write failure.
    pub fn update(&self, record: &ScanRecord) -> Result<(), StoreError> {
        let path = self.scan_dir(&record.id)?.join(ROW_FILE);
        match fs::symlink_metadata(&path) {
            Ok(meta) if meta.is_file() && !meta.file_type().is_symlink() => {}
            Ok(_) => {
                return Err(StoreError::Io(format!(
                    "{}: not a regular scan row",
                    path.display()
                )));
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Err(StoreError::NotFound(record.id.clone()));
            }
            Err(error) => return Err(io_error(&path, &error)),
        }
        self.write_row(record)
    }

    /// Write an initial or replacement scan row; only `create` may use this before a row exists.
    fn write_row(&self, record: &ScanRecord) -> Result<(), StoreError> {
        let path = self.scan_dir(&record.id)?.join(ROW_FILE);
        let limit = usize::try_from(MAX_ROW_BYTES).unwrap_or(usize::MAX);
        let body = match crate::json::to_bounded_json(record, limit, true) {
            Ok(Ok(bytes)) => bytes,
            Ok(Err(required_bytes)) => {
                return Err(StoreError::Io(format!(
                    "{}: exceeds {MAX_ROW_BYTES} bytes (needs {required_bytes})",
                    path.display()
                )));
            }
            Err(error) => return Err(StoreError::Invalid(error.to_string())),
        };
        crate::fsio::write_atomic_private(&path, &body, MAX_ROW_BYTES).map_err(|e| fsio_error(&e))
    }

    /// One scan's row.
    ///
    /// # Errors
    /// [`StoreError::NotFound`] when there is no such scan; [`StoreError::Io`] when its row
    /// cannot be read or parsed.
    pub fn get(&self, id: &str) -> Result<ScanRecord, StoreError> {
        let path = self.scan_dir(id)?.join(ROW_FILE);
        self.require_row(id)?;
        let bytes = crate::fsio::read_bounded_replacing(&path, MAX_ROW_BYTES)
            .map_err(|e| fsio_error(&e))?;
        let record: ScanRecord = serde_json::from_slice(&bytes)
            .map_err(|error| StoreError::Io(format!("{}: {error}", path.display())))?;
        if record.format_version != FORMAT_VERSION || record.id != id {
            return Err(StoreError::Io(format!(
                "{}: format {} for scan {} is not this build's format {FORMAT_VERSION} for {id}",
                path.display(),
                record.format_version,
                record.id
            )));
        }
        Ok(record)
    }

    /// Every scan, newest first. A scan whose row cannot be read is listed as `ERROR-FAILED` with
    /// the reason as its name, so it can still be seen and deleted.
    ///
    /// # Errors
    /// [`StoreError::Io`] when the store cannot be listed or holds more than [`MAX_SCANS`].
    pub fn list(&self) -> Result<Vec<ScanRecord>, StoreError> {
        let mut records = Vec::new();
        for entry in fs::read_dir(&self.dir).map_err(|error| io_error(&self.dir, &error))? {
            let entry = entry.map_err(|error| io_error(&self.dir, &error))?;
            let Some(id) = entry.file_name().to_str().map(str::to_owned) else {
                continue;
            };
            if !valid_id(&id) || !entry.file_type().is_ok_and(|kind| kind.is_dir()) {
                continue;
            }
            if records.len() == MAX_SCANS {
                return Err(StoreError::Io(format!(
                    "{}: more than {MAX_SCANS} scans",
                    self.dir.display()
                )));
            }
            records.push(
                self.get(&id)
                    .unwrap_or_else(|error| unreadable(&id, &error)),
            );
        }
        records.sort_by(|a, b| b.created.cmp(&a.created).then_with(|| a.id.cmp(&b.id)));
        Ok(records)
    }

    /// Save what a scan found.
    ///
    /// # Errors
    /// [`StoreError::NotFound`] when the scan has no valid saved row; [`StoreError::Io`] on a
    /// write failure or results over [`MAX_RESULTS_BYTES`].
    pub fn save_results(&self, results: &ScanResults) -> Result<(), StoreError> {
        // The atomic writer creates parents; without this precondition, saving
        // an unregistered scan would create a directory with no scan.json.
        self.get(&results.scan_id)?;
        let path = self.scan_dir(&results.scan_id)?.join(RESULTS_FILE);
        let limit = usize::try_from(MAX_RESULTS_BYTES).unwrap_or(usize::MAX);
        let body = match crate::json::to_bounded_json(results, limit, false) {
            Ok(Ok(bytes)) => bytes,
            Ok(Err(required_bytes)) => {
                return Err(StoreError::Io(format!(
                    "{}: exceeds {MAX_RESULTS_BYTES} bytes (needs {required_bytes})",
                    path.display()
                )));
            }
            Err(error) => return Err(StoreError::Invalid(error.to_string())),
        };
        crate::fsio::write_atomic_private(&path, &body, MAX_RESULTS_BYTES)
            .map_err(|e| fsio_error(&e))
    }

    /// What a scan found, or `None` when it has saved nothing yet.
    ///
    /// # Errors
    /// [`StoreError::NotFound`] when there is no such scan; [`StoreError::Io`] when the results
    /// cannot be read or parsed.
    pub fn results(&self, id: &str) -> Result<Option<ScanResults>, StoreError> {
        let dir = self.scan_dir(id)?;
        self.require_row(id)?;
        let path = dir.join(RESULTS_FILE);
        if optional_file_missing(&path, fs::symlink_metadata(&path))? {
            return Ok(None);
        }
        let bytes = crate::fsio::read_bounded_replacing(&path, MAX_RESULTS_BYTES)
            .map_err(|e| fsio_error(&e))?;
        let results: ScanResults = serde_json::from_slice(&bytes)
            .map_err(|error| StoreError::Io(format!("{}: {error}", path.display())))?;
        if results.format_version != FORMAT_VERSION || results.scan_id != id {
            return Err(StoreError::Io(format!(
                "{}: not this build's results for scan {id}",
                path.display()
            )));
        }
        Ok(Some(results))
    }

    /// Append one entry to a scan's log. Past [`MAX_LOG_BYTES`] the entry is dropped, after a
    /// single entry saying the log is full.
    ///
    /// # Errors
    /// [`StoreError::NotFound`] for an id the store cannot hold; [`StoreError::Io`] on a write
    /// failure or a symlink in place of the log.
    pub fn append_log(&self, id: &str, entry: &LogEntry) -> Result<(), StoreError> {
        // The lock applies to every store instance in this process and covers
        // both the size decision and the append. Another process must still
        // coordinate separately: std has no portable cross-process append lock
        // on the project's Rust 1.87 baseline.
        let _guard = LOG_APPEND_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let path = self.scan_dir(id)?.join(LOG_FILE);
        let mut file = checked_open_for_append(&path)?;
        let size = file
            .metadata()
            .map_err(|error| io_error(&path, &error))?
            .len();

        let full = LogEntry {
            time: entry.time,
            component: "huntsman".into(),
            level: LogLevel::Warning,
            message: format!("log full at {MAX_LOG_BYTES} bytes; later entries are not kept"),
        };
        let mut full_line =
            serde_json::to_vec(&full).map_err(|error| StoreError::Invalid(error.to_string()))?;
        full_line.push(b'\n');

        // A very large log message must not allocate an unbounded encoded
        // string merely to be discarded. A single oversized entry consumes
        // only the log-full marker, if room is available.
        let limit = usize::try_from(MAX_LOG_BYTES).unwrap_or(usize::MAX);
        let mut line = crate::json::to_bounded_json(entry, limit, false)
            .map_err(|error| StoreError::Invalid(error.to_string()))?
            .ok();
        if let Some(bytes) = &mut line {
            bytes.push(b'\n');
        }

        let selected = if let Some(bytes) = line.as_ref().filter(|bytes| {
            size.saturating_add(bytes.len() as u64)
                .saturating_add(full_line.len() as u64)
                <= MAX_LOG_BYTES
        }) {
            bytes.as_slice()
        } else if size.saturating_add(full_line.len() as u64) <= MAX_LOG_BYTES
            && !log_is_full(&path)
        {
            full_line.as_slice()
        } else {
            return Ok(());
        };

        file.write_all(selected)
            .map_err(|error| io_error(&path, &error))
    }

    /// A scan's log, oldest first. A line that does not parse is kept as an `ERROR` entry
    /// naming the line, rather than dropped.
    ///
    /// # Errors
    /// [`StoreError::NotFound`] when there is no such scan; [`StoreError::Io`] when the log
    /// cannot be read.
    pub fn log(&self, id: &str) -> Result<Vec<LogEntry>, StoreError> {
        let dir = self.scan_dir(id)?;
        self.require_row(id)?;
        let path = dir.join(LOG_FILE);
        if optional_file_missing(&path, fs::symlink_metadata(&path))? {
            return Ok(Vec::new());
        }
        let bytes = crate::fsio::read_bounded(&path, MAX_LOG_BYTES).map_err(|e| fsio_error(&e))?;
        Ok(String::from_utf8_lossy(&bytes)
            .lines()
            .enumerate()
            .filter(|(_, line)| !line.trim().is_empty())
            .map(|(number, line)| {
                serde_json::from_str(line).unwrap_or_else(|error| LogEntry {
                    time: 0,
                    component: "huntsman".into(),
                    level: LogLevel::Error,
                    message: format!("log line {} does not parse: {error}", number + 1),
                })
            })
            .collect())
    }

    /// Delete a scan and everything it saved.
    ///
    /// # Errors
    /// [`StoreError::NotFound`] when there is no such scan; [`StoreError::Io`] when it cannot be
    /// removed.
    pub fn delete(&self, id: &str) -> Result<(), StoreError> {
        let dir = self.scan_dir(id)?;
        match fs::symlink_metadata(&dir) {
            Ok(meta) if meta.is_dir() => {
                fs::remove_dir_all(&dir).map_err(|error| io_error(&dir, &error))
            }
            Ok(_) => Err(StoreError::Io(format!(
                "{}: not a directory",
                dir.display()
            ))),
            Err(_) => Err(StoreError::NotFound(id.to_owned())),
        }
    }

    /// Mark every scan a previous process left active as `ABORTED`, ended at `now_ms`, with a
    /// log entry; returns how many. A scan whose owner is another process that is still running
    /// is left as it is. Run once when a server starts, before it runs any scan.
    ///
    /// # Errors
    /// [`StoreError::Io`] when the store cannot be listed or a row cannot be saved.
    pub fn recover(&self, now_ms: u64) -> Result<usize, StoreError> {
        let mut recovered = 0;
        for mut record in self.list()? {
            if !record.status.is_active()
                || self.get(&record.id).is_err()
                || record.owner.is_some_and(other_process_alive)
            {
                continue;
            }
            let was = record.status;
            record.status = ScanStatus::Aborted;
            record.ended = Some(now_ms);
            self.update(&record)?;
            self.append_log(
                &record.id,
                &LogEntry {
                    time: now_ms,
                    component: "huntsman".into(),
                    level: LogLevel::Warning,
                    message: format!(
                        "the server stopped while this scan was {}; marked ABORTED",
                        was.as_str()
                    ),
                },
            )?;
            recovered += 1;
        }
        Ok(recovered)
    }
}

/// Whether `pid` is a running process other than this one. Android shows another app's
/// processes to no one, so a reused pid there reads as gone; without `/proc` every owner does.
fn other_process_alive(pid: u32) -> bool {
    pid != std::process::id() && Path::new("/proc").join(pid.to_string()).exists()
}

/// Open an append descriptor only after confirming that the path is a regular
/// file and that its opened inode is the inode checked before the open.
/// Creation uses `create_new`, so an attacker cannot plant a symlink in the
/// missing-file window and have it followed.
fn checked_open_for_append(path: &Path) -> Result<std::fs::File, StoreError> {
    checked_open_for_append_with(path, || {})
}

fn checked_open_for_append_with(
    path: &Path,
    after_check: impl FnOnce(),
) -> Result<std::fs::File, StoreError> {
    let parent = path
        .parent()
        .ok_or_else(|| StoreError::Io(format!("{}: no parent", path.display())))?;
    let directory = fs::symlink_metadata(parent).map_err(|error| io_error(parent, &error))?;
    if directory.file_type().is_symlink() || !directory.is_dir() {
        return Err(StoreError::Io(format!(
            "{}: not a regular directory",
            parent.display()
        )));
    }

    let checked = match fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_symlink() || !meta.is_file() => {
            return Err(StoreError::Io(format!(
                "{}: not a regular file",
                path.display()
            )));
        }
        Ok(meta) => Some(meta),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => return Err(io_error(path, &error)),
    };
    after_check();

    let mut options = OpenOptions::new();
    options.append(true);
    if checked.is_none() {
        options.create_new(true);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let file = options.open(path).map_err(|error| io_error(path, &error))?;
    let opened = file.metadata().map_err(|error| io_error(path, &error))?;
    if !opened.is_file()
        || checked
            .as_ref()
            .is_some_and(|meta| !crate::fsio::same_inode(meta, &opened))
    {
        return Err(StoreError::Io(format!(
            "{}: file changed between check and open",
            path.display()
        )));
    }
    Ok(file)
}

fn log_is_full(path: &Path) -> bool {
    let Ok(bytes) = crate::fsio::read_bounded(path, MAX_LOG_BYTES) else {
        return false;
    };
    let marker = format!("log full at {MAX_LOG_BYTES} bytes; later entries are not kept");
    bytes.split(|byte| *byte == b'\n').any(|line| {
        serde_json::from_slice::<LogEntry>(line).is_ok_and(|entry| {
            entry.component == "huntsman"
                && entry.level == LogLevel::Warning
                && entry.message == marker
        })
    })
}

fn unreadable(id: &str, error: &StoreError) -> ScanRecord {
    ScanRecord {
        format_version: FORMAT_VERSION,
        id: id.to_owned(),
        name: format!("unreadable scan: {error}"),
        target: String::new(),
        target_type: String::new(),
        kind: String::new(),
        options: ScanOptions::default(),
        status: ScanStatus::ErrorFailed,
        created: 0,
        started: None,
        ended: None,
        elements: 0,
        unique: 0,
        correlations: RiskCounts::default(),
        errors: 1,
        modules_run: Vec::new(),
        owner: None,
    }
}

#[cfg(unix)]
fn private_dir(dir: &Path) -> Result<(), StoreError> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(dir, fs::Permissions::from_mode(0o700))
        .map_err(|error| io_error(dir, &error))
}

#[cfg(not(unix))]
fn private_dir(_dir: &Path) -> Result<(), StoreError> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("hse-scan-store-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        dir
    }

    fn record(id: &str, created: u64, status: ScanStatus) -> ScanRecord {
        ScanRecord {
            format_version: FORMAT_VERSION,
            id: id.to_owned(),
            name: "example".into(),
            target: "example.com".into(),
            target_type: "INTERNET_NAME".into(),
            kind: "domain".into(),
            options: ScanOptions {
                usecase: "all".into(),
                ..ScanOptions::default()
            },
            status,
            created,
            started: None,
            ended: None,
            elements: 0,
            unique: 0,
            correlations: RiskCounts::default(),
            errors: 0,
            modules_run: Vec::new(),
            owner: None,
        }
    }

    #[test]
    fn rows_round_trip_and_list_newest_first() {
        let dir = scratch("list");
        let store = ScanStore::open(&dir).unwrap();
        let older = record(&new_id("a", 1, 0), 1_000, ScanStatus::Finished);
        let newer = record(&new_id("b", 2, 1), 2_000, ScanStatus::Running);
        store.create(&older).unwrap();
        store.create(&newer).unwrap();
        assert_eq!(store.get(&older.id).unwrap(), older);
        let ids: Vec<String> = store.list().unwrap().into_iter().map(|r| r.id).collect();
        assert_eq!(ids, [newer.id.clone(), older.id.clone()]);
        assert!(matches!(store.create(&older), Err(StoreError::Invalid(_))));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn ids_outside_the_alphabet_never_reach_the_filesystem() {
        let dir = scratch("ids");
        let store = ScanStore::open(&dir).unwrap();
        for id in ["../etc", "ABCDEF0123456789", "0123", "0123456789abcdeg", ""] {
            assert!(!valid_id(id));
            assert_eq!(store.get(id), Err(StoreError::NotFound(id.to_owned())));
            assert_eq!(store.delete(id), Err(StoreError::NotFound(id.to_owned())));
        }
        assert!(valid_id(&new_id("x", 0, 0)));
        assert_ne!(new_id("x", 0, 0), new_id("x", 0, 1));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn optional_scan_files_distinguish_absence_from_metadata_errors() {
        let dir = scratch("optional-file-errors");
        let store = ScanStore::open(&dir).unwrap();
        let row = record(&new_id("optional-files", 305, 0), 305, ScanStatus::Created);
        store.create(&row).unwrap();

        let absent_path = dir.join(&row.id).join(RESULTS_FILE);
        assert_eq!(
            optional_file_missing(&absent_path, fs::symlink_metadata(&absent_path)),
            Ok(true)
        );
        assert_eq!(store.results(&row.id).unwrap(), None);
        assert!(store.log(&row.id).unwrap().is_empty());

        let io_failure = optional_file_missing(
            &absent_path,
            Err(std::io::Error::from(std::io::ErrorKind::PermissionDenied)),
        );
        assert!(
            matches!(io_failure, Err(StoreError::Io(_))),
            "metadata access failures must not masquerade as missing results or logs"
        );
        fs::write(&absent_path, b"present").unwrap();
        assert_eq!(
            optional_file_missing(&absent_path, fs::symlink_metadata(&absent_path)),
            Ok(false)
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn saving_results_cannot_create_a_scan_without_a_record() {
        let dir = scratch("results-no-row");
        let store = ScanStore::open(&dir).unwrap();
        let id = new_id("missing-row", 303, 0);
        let results = ScanResults {
            format_version: FORMAT_VERSION,
            scan_id: id.clone(),
            text: "orphaned".into(),
            entities: Vec::new(),
            outcomes: Vec::new(),
            elements: Vec::new(),
            correlations: Vec::new(),
            lineage: Vec::new(),
            termination: None,
        };
        assert_eq!(
            store.save_results(&results),
            Err(StoreError::NotFound(id.clone()))
        );
        assert!(
            !dir.join(&id).exists(),
            "results must not create a scan directory"
        );
        assert!(store.list().unwrap().is_empty());

        let row = record(&id, 303, ScanStatus::Finished);
        store.create(&row).unwrap();
        store.save_results(&results).unwrap();
        assert_eq!(store.results(&id).unwrap(), Some(results));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn results_and_log_are_saved_whole_and_deleted_with_the_scan() {
        let dir = scratch("results");
        let store = ScanStore::open(&dir).unwrap();
        let row = record(&new_id("c", 3, 0), 3_000, ScanStatus::Finished);
        store.create(&row).unwrap();
        assert_eq!(store.results(&row.id).unwrap(), None);
        let results = ScanResults {
            format_version: FORMAT_VERSION,
            scan_id: row.id.clone(),
            text: "report".into(),
            entities: Vec::new(),
            outcomes: Vec::new(),
            elements: Vec::new(),
            correlations: Vec::new(),
            lineage: Vec::new(),
            termination: None,
        };
        store.save_results(&results).unwrap();
        assert_eq!(store.results(&row.id).unwrap(), Some(results));
        let entry = LogEntry {
            time: 5,
            component: "crtsh".into(),
            level: LogLevel::Error,
            message: "timed out".into(),
        };
        store.append_log(&row.id, &entry).unwrap();
        store.append_log(&row.id, &entry).unwrap();
        assert_eq!(store.log(&row.id).unwrap(), [entry.clone(), entry]);
        store.delete(&row.id).unwrap();
        assert_eq!(
            store.get(&row.id),
            Err(StoreError::NotFound(row.id.clone()))
        );
        assert!(store.list().unwrap().is_empty());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_scan_left_active_by_a_dead_server_reads_aborted_after_recovery() {
        let dir = scratch("recover");
        let store = ScanStore::open(&dir).unwrap();
        let running = record(&new_id("r", 4, 0), 4_000, ScanStatus::Running);
        let done = record(&new_id("d", 5, 0), 5_000, ScanStatus::Finished);
        store.create(&running).unwrap();
        store.create(&done).unwrap();
        assert_eq!(store.recover(9_000).unwrap(), 1);
        let after = store.get(&running.id).unwrap();
        assert_eq!(after.status, ScanStatus::Aborted);
        assert_eq!(after.ended, Some(9_000));
        assert!(
            store.log(&running.id).unwrap()[0]
                .message
                .contains("RUNNING")
        );
        assert_eq!(store.get(&done.id).unwrap(), done);
        assert_eq!(store.recover(10_000).unwrap(), 0);
        let _ = fs::remove_dir_all(&dir);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn recovery_leaves_a_scan_another_live_process_is_running() {
        let dir = scratch("owner");
        let store = ScanStore::open(&dir).unwrap();
        let mut theirs = record(&new_id("t", 6, 0), 6_000, ScanStatus::Running);
        // The test runner's parent is alive for as long as this test runs.
        theirs.owner = Some(std::os::unix::process::parent_id());
        let mut ours = record(&new_id("o", 7, 0), 7_000, ScanStatus::Running);
        ours.owner = Some(std::process::id());
        store.create(&theirs).unwrap();
        store.create(&ours).unwrap();
        assert_eq!(store.recover(9_000).unwrap(), 1);
        assert_eq!(store.get(&theirs.id).unwrap().status, ScanStatus::Running);
        assert_eq!(store.get(&ours.id).unwrap().status, ScanStatus::Aborted);
        let _ = fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn a_non_directory_scan_path_is_io_failure_not_a_missing_scan() {
        let dir = scratch("scan-not-directory");
        let store = ScanStore::open(&dir).unwrap();
        let id = new_id("not-a-directory", 101, 0);
        fs::write(dir.join(&id), b"not a scan directory").unwrap();
        assert!(matches!(store.get(&id), Err(StoreError::Io(_))));
        assert!(matches!(store.results(&id), Err(StoreError::Io(_))));
        assert!(matches!(store.log(&id), Err(StoreError::Io(_))));

        let absent = new_id("absent", 102, 0);
        assert_eq!(
            store.get(&absent),
            Err(StoreError::NotFound(absent.clone()))
        );
        assert_eq!(
            store.results(&absent),
            Err(StoreError::NotFound(absent.clone()))
        );
        assert_eq!(
            store.log(&absent),
            Err(StoreError::NotFound(absent.clone()))
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_unreadable_row_is_listed_as_failed_instead_of_hidden() {
        let dir = scratch("corrupt");
        let store = ScanStore::open(&dir).unwrap();
        let id = new_id("bad", 6, 0);
        fs::create_dir(dir.join(&id)).unwrap();
        fs::write(dir.join(&id).join(ROW_FILE), b"{not json").unwrap();
        let listed = store.list().unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].status, ScanStatus::ErrorFailed);
        assert!(listed[0].name.starts_with("unreadable scan"));
        store.delete(&id).unwrap();
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn statuses_serialise_as_spiderfoots_names() {
        assert_eq!(
            serde_json::to_string(&ScanStatus::AbortRequested).unwrap(),
            "\"ABORT-REQUESTED\""
        );
        assert_eq!(
            serde_json::to_string(&ScanStatus::ErrorFailed).unwrap(),
            "\"ERROR-FAILED\""
        );
        assert!(ScanStatus::Starting.is_active());
        assert!(!ScanStatus::Aborted.is_active());
        assert_eq!(serde_json::to_string(&Risk::Info).unwrap(), "\"INFO\"");
    }

    #[cfg(unix)]
    #[test]
    fn the_store_and_its_files_are_private() {
        use std::os::unix::fs::PermissionsExt;
        let dir = scratch("modes");
        let store = ScanStore::open(&dir).unwrap();
        let row = record(&new_id("m", 7, 0), 7_000, ScanStatus::Created);
        store.create(&row).unwrap();
        store
            .append_log(
                &row.id,
                &LogEntry {
                    time: 1,
                    component: "c".into(),
                    level: LogLevel::Info,
                    message: "m".into(),
                },
            )
            .unwrap();
        let mode = |path: &Path| fs::metadata(path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&dir), 0o700);
        assert_eq!(mode(&dir.join(&row.id)), 0o700);
        assert_eq!(mode(&dir.join(&row.id).join(ROW_FILE)), 0o600);
        assert_eq!(mode(&dir.join(&row.id).join(LOG_FILE)), 0o600);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn failed_initial_row_write_leaves_no_phantom_scan_and_id_can_be_reused() {
        let dir = scratch("failed-create");
        let store = ScanStore::open(&dir).unwrap();
        let mut oversized = record(&new_id("too-large", 201, 0), 201, ScanStatus::Created);
        oversized.name = "x".repeat(usize::try_from(MAX_ROW_BYTES).unwrap());
        assert!(matches!(store.create(&oversized), Err(StoreError::Io(_))));
        assert!(
            !dir.join(&oversized.id).exists(),
            "a failed create must not leave a scan directory without a row"
        );
        assert!(store.list().unwrap().is_empty());

        let mut valid = oversized;
        valid.name = "retry".into();
        store.create(&valid).unwrap();
        assert_eq!(store.get(&valid.id).unwrap(), valid);
        assert_eq!(store.list().unwrap().len(), 1);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn update_refuses_missing_and_deleted_scan_rows_without_creating_directories() {
        let dir = scratch("update-missing-row");
        let store = ScanStore::open(&dir).unwrap();
        let row = record(&new_id("update-absent", 401, 0), 401, ScanStatus::Created);
        assert_eq!(
            store.update(&row),
            Err(StoreError::NotFound(row.id.clone()))
        );
        assert!(!dir.join(&row.id).exists());
        assert!(store.list().unwrap().is_empty());

        store.create(&row).unwrap();
        let mut finished = row.clone();
        finished.status = ScanStatus::Finished;
        store.update(&finished).unwrap();
        assert_eq!(store.get(&row.id).unwrap(), finished);

        store.delete(&row.id).unwrap();
        assert_eq!(
            store.update(&finished),
            Err(StoreError::NotFound(row.id.clone()))
        );
        assert!(!dir.join(&row.id).exists());
        assert!(store.list().unwrap().is_empty());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn oversized_row_update_never_replaces_previous_scan() {
        let dir = scratch("oversized-row");
        let store = ScanStore::open(&dir).unwrap();
        let original = record(&new_id("oversized", 100, 0), 100, ScanStatus::Finished);
        store.create(&original).unwrap();
        let before = fs::read(dir.join(&original.id).join(ROW_FILE)).unwrap();
        let mut larger = original.clone();
        larger.name = "x".repeat(usize::try_from(MAX_ROW_BYTES).unwrap());
        assert!(matches!(store.update(&larger), Err(StoreError::Io(_))));
        assert_eq!(store.get(&original.id).unwrap(), original);
        assert_eq!(
            fs::read(dir.join(&original.id).join(ROW_FILE)).unwrap(),
            before
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn append_refuses_symlink_swapped_between_check_and_open() {
        let dir = scratch("log-link-swap");
        fs::create_dir_all(&dir).unwrap();
        let log = dir.join(LOG_FILE);
        let unrelated = dir.join("unrelated.jsonl");
        fs::write(&log, b"old\n").unwrap();
        fs::write(&unrelated, b"protected\n").unwrap();
        let result = checked_open_for_append_with(&log, || {
            fs::remove_file(&log).unwrap();
            std::os::unix::fs::symlink(&unrelated, &log).unwrap();
        });
        assert!(matches!(result, Err(StoreError::Io(_))));
        assert_eq!(fs::read(&unrelated).unwrap(), b"protected\n");
        let _ = fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn append_refuses_existing_log_symlink_and_nonregular_file() {
        let dir = scratch("log-nonregular");
        fs::create_dir_all(&dir).unwrap();
        let log = dir.join(LOG_FILE);
        let unrelated = dir.join("unrelated");
        fs::write(&unrelated, b"unchanged").unwrap();
        std::os::unix::fs::symlink(&unrelated, &log).unwrap();
        assert!(checked_open_for_append(&log).is_err());
        fs::remove_file(&log).unwrap();
        fs::create_dir(&log).unwrap();
        assert!(checked_open_for_append(&log).is_err());
        assert_eq!(fs::read(&unrelated).unwrap(), b"unchanged");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn spoofed_log_full_message_does_not_suppress_real_marker() {
        let dir = scratch("marker-spoof");
        fs::create_dir_all(&dir).unwrap();
        let log = dir.join(LOG_FILE);
        let fake = LogEntry {
            time: 1,
            component: "source".into(),
            level: LogLevel::Info,
            message: format!("log full at {MAX_LOG_BYTES} bytes; later entries are not kept"),
        };
        fs::write(&log, serde_json::to_vec(&fake).unwrap()).unwrap();
        assert!(!log_is_full(&log));
        let genuine = LogEntry {
            component: "huntsman".into(),
            level: LogLevel::Warning,
            ..fake
        };
        fs::write(&log, serde_json::to_vec(&genuine).unwrap()).unwrap();
        assert!(log_is_full(&log));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn oversized_entry_writes_one_marker_and_never_overshoots_budget() {
        let dir = scratch("oversized-log-message");
        let store = ScanStore::open(&dir).unwrap();
        let record = record(&new_id("large-log", 31, 0), 31, ScanStatus::Running);
        store.create(&record).unwrap();
        let enormous = LogEntry {
            time: 31,
            component: "source".into(),
            level: LogLevel::Error,
            message: "x".repeat(usize::try_from(MAX_LOG_BYTES).unwrap()),
        };
        store.append_log(&record.id, &enormous).unwrap();
        store.append_log(&record.id, &enormous).unwrap();
        let log = store.log(&record.id).unwrap();
        assert_eq!(log.len(), 1);
        assert_eq!(log[0].level, LogLevel::Warning);
        assert!(log[0].message.starts_with("log full at"));
        assert!(
            fs::metadata(dir.join(&record.id).join(LOG_FILE))
                .unwrap()
                .len()
                <= MAX_LOG_BYTES
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn same_process_concurrent_log_writers_do_not_lose_entries() {
        let dir = scratch("concurrent-append");
        let store = ScanStore::open(&dir).unwrap();
        let row = record(&new_id("concurrent-log", 41, 0), 41, ScanStatus::Running);
        store.create(&row).unwrap();
        std::thread::scope(|scope| {
            for worker in 0..8 {
                let id = &row.id;
                let store = &store;
                scope.spawn(move || {
                    for number in 0..25 {
                        store
                            .append_log(
                                id,
                                &LogEntry {
                                    time: number,
                                    component: format!("worker-{worker}"),
                                    level: LogLevel::Info,
                                    message: format!("entry-{number}"),
                                },
                            )
                            .unwrap();
                    }
                });
            }
        });
        assert_eq!(store.log(&row.id).unwrap().len(), 200);
        assert!(
            fs::metadata(dir.join(&row.id).join(LOG_FILE))
                .unwrap()
                .len()
                <= MAX_LOG_BYTES
        );
        let _ = fs::remove_dir_all(&dir);
    }
}
