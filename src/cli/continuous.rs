//! Opt-in, bounded, always-on reconciliation of saved-scan evidence.
//!
//! Uses the existing `ScanService` and /analyze endpoint rather than creating another
//! canonicalisation or attribution model. Nothing runs until targets are configured.
use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::UNIX_EPOCH;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use huntsman_recon::clock;
use huntsman_recon::fsio::{read_bounded, write_atomic_private};
use huntsman_recon::scan_api::ScanApi;
use huntsman_recon::scan_service::{ScanRequest, plan};
use huntsman_recon::scan_store::{MAX_RESULTS_BYTES, ScanOptions, ScanRecord, ScanStatus};
use huntsman_recon::sha256::{hex32, sha256};

use super::scans::default_scan_dir;

const MAX_TARGETS: usize = 32;
const MAX_TARGET_CONFIG_BYTES: usize = 8192;
const MAX_ANALYSIS_BYTES: u64 = 4 * 1024 * 1024;
const TICK: Duration = Duration::from_secs(60);
const RETRY: u64 = 15 * 60 * 1000;

struct Config {
    targets: Vec<ScanRequest>,
    cadence_ms: u64,
    normalised_dir: PathBuf,
    normalise_all: bool,
}

fn config(targets: &str, minutes: &str, directory: PathBuf) -> Result<Config, String> {
    if targets.len() > MAX_TARGET_CONFIG_BYTES {
        return Err(format!(
            "HUNTSMAN_CONTINUOUS_TARGETS exceeds {MAX_TARGET_CONFIG_BYTES} bytes"
        ));
    }
    let minutes: u64 = minutes.parse().map_err(|_| {
        "HUNTSMAN_CONTINUOUS_INTERVAL_MINUTES must be an integer (60..=10080)".to_owned()
    })?;
    if !(60..=10_080).contains(&minutes) {
        return Err("HUNTSMAN_CONTINUOUS_INTERVAL_MINUTES must be 60..=10080".to_owned());
    }
    let mut unique = BTreeMap::new();
    let mut normalise_all = false;
    for raw in targets.split(['\n', ';']) {
        let target = raw.trim();
        if target.is_empty() {
            continue;
        }
        if target == "*" {
            normalise_all = true;
            continue;
        }
        let resolved =
            plan(target, None).map_err(|error| format!("invalid continuous target: {error}"))?;
        let kind = resolved.kind.command().to_owned();
        if kind == "people" {
            return Err("continuous people-name scans are disabled".to_owned());
        }
        unique
            .entry((kind.clone(), resolved.target.clone()))
            .or_insert_with(|| ScanRequest {
                target: resolved.target,
                name: None,
                kind: Some(kind),
                options: ScanOptions {
                    usecase: "passive".to_owned(),
                    ..ScanOptions::default()
                },
            });
        if unique.len() > MAX_TARGETS {
            return Err(format!(
                "at most {MAX_TARGETS} distinct continuous targets are supported"
            ));
        }
    }
    if unique.is_empty() && !normalise_all {
        return Err("HUNTSMAN_CONTINUOUS_TARGETS contains no valid targets".to_owned());
    }
    Ok(Config {
        targets: unique.into_values().collect(),
        cadence_ms: minutes * 60 * 1000,
        normalised_dir: directory,
        normalise_all,
    })
}

fn latest<'a>(records: &'a [ScanRecord], request: &ScanRequest) -> Option<&'a ScanRecord> {
    records
        .iter()
        .filter(|record| {
            record.target == request.target && request.kind.as_deref() == Some(record.kind.as_str())
        })
        .max_by_key(|record| (record.created, record.id.as_str()))
}

/// Do not reschedule a scan until a full cadence has elapsed after completion.
/// For historical records without an end time, retain the creation-time fallback.
fn due(record: Option<&ScanRecord>, now: u64, cadence_ms: u64) -> bool {
    record.is_none_or(|record| {
        let last_activity = record.ended.unwrap_or(record.created).max(record.created);
        !record.status.is_active() && now.saturating_sub(last_activity) >= cadence_ms
    })
}


// Stat-only change detector. This is bounded to one metadata query per selected
// latest scan each tick; metadata collisions remain a documented limitation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RevisionStamp {
    bytes: u64,
    modified_ns: u64,
}

fn revision_stamp(path: &Path) -> Result<RevisionStamp, String> {
    let meta = fs::symlink_metadata(path).map_err(|e| format!("{}: {e}", path.display()))?;
    if !meta.is_file() || meta.file_type().is_symlink() || meta.len() > MAX_RESULTS_BYTES {
        return Err(format!("{}: invalid saved-results file", path.display()));
    }
    let modified = meta.modified().map_err(|e| e.to_string())?
        .duration_since(UNIX_EPOCH).map_err(|e| e.to_string())?;
    let modified_ns = u64::try_from(modified.as_nanos())
        .map_err(|_| "saved-results timestamp overflow".to_owned())?;
    Ok(RevisionStamp { bytes: meta.len(), modified_ns })
}

fn results_path(api: &ScanApi, record: &ScanRecord) -> PathBuf {
    api.service().store().dir().join(&record.id).join("results.json")
}

fn normalised_path(record: &ScanRecord, directory: &Path) -> PathBuf {
    let key = format!("{}\0{}", record.kind, record.target);
    directory.join(format!("{}.json", &hex32(&sha256(key.as_bytes()))[..32]))
}

/// Preserve historical output, but remove it from the current slot before a
/// refused or revised analysis could otherwise continue to be presented as valid.
fn archive_current(path: &Path) -> Result<bool, String> {
    match fs::symlink_metadata(path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(e) => return Err(format!("{}: {e}", path.display())),
        Ok(meta) if !meta.is_file() || meta.file_type().is_symlink() =>
            return Err(format!("{}: invalid current report", path.display())),
        Ok(_) => {}
    }
    for offset in 0..32_u64 {
        let stale = path.with_extension(format!(
            "stale-{}.json", clock::unix_now_millis().saturating_add(offset)
        ));
        if fs::symlink_metadata(&stale).is_ok() {
            continue;
        }
        fs::rename(path, &stale).map_err(|e| format!("archive failed: {e}"))?;
        return Ok(true);
    }
    Err("stale archive collision".to_owned())
}

fn source_hash(path: &Path) -> Result<String, String> {
    let bytes = read_bounded(path, MAX_RESULTS_BYTES)
        .map_err(|error| format!("saved-results read failed: {error}"))?;
    Ok(hex32(&sha256(&bytes)))
}

fn needs_reconciliation(
    previous: Option<&(String, RevisionStamp)>,
    scan_id: &str,
    current: RevisionStamp,
    exists: bool,
) -> bool {
    !exists || previous.is_none_or(|(id, stamp)| id != scan_id || *stamp != current)
}

fn normalise_saved(
    api: &ScanApi,
    record: &ScanRecord,
    directory: &Path,
    expected: RevisionStamp,
) -> Result<bool, String> {
    if record.status != ScanStatus::Finished {
        return Err(format!("scan {} is not finished; refusing current analysis", record.id));
    }
    let source = results_path(api, record);
    let before = source_hash(&source)?;
    if revision_stamp(&source)? != expected {
        return Err(format!("scan {} results changed before analysis", record.id));
    }
    let response = api.handle("GET", &format!("/api/scans/{}/analyze", record.id), "");
    if response.status != 200 {
        return Err(format!(
            "scan {} analysis refused (HTTP {})",
            record.id, response.status
        ));
    }
    // Double-check exact source bytes, not just timestamps, against concurrent writes.
    if revision_stamp(&source)? != expected || source_hash(&source)? != before {
        return Err(format!(
            "scan {} results changed during analysis",
            record.id
        ));
    }
    let mut report: serde_json::Value = serde_json::from_slice(&response.body)
        .map_err(|error| format!("scan {} analysis JSON invalid: {error}", record.id))?;
    let object = report
        .as_object_mut()
        .ok_or_else(|| format!("scan {} analysis is not an object", record.id))?;
    object.insert(
        "source_revision".to_owned(),
        serde_json::json!({
            "scan_id": record.id,
            "results_sha256": before,
            "results_bytes": expected.bytes,
            "modified_unix_ns": expected.modified_ns,
        }),
    );
    let body = serde_json::to_vec(&report)
        .map_err(|error| format!("analysis serialization failed: {error}"))?;
    if body.len() as u64 > MAX_ANALYSIS_BYTES {
        return Err(format!(
            "scan {} analysis exceeds bounded output",
            record.id
        ));
    }
    write_atomic_private(
        &normalised_path(record, directory),
        &body,
        MAX_ANALYSIS_BYTES,
    )
    .map_err(|error| format!("normalisation write failed: {error}"))?;
    Ok(true)
}

fn cycle(
    api: &ScanApi,
    config: &Config,
    observed: &mut BTreeMap<PathBuf, (String, RevisionStamp)>,
    retry_after: &mut BTreeMap<String, u64>,
) -> Result<(), String> {
    let now = clock::unix_now_millis();
    let records = api
        .service()
        .store()
        .list()
        .map_err(|error| error.to_string())?;
    // ScanStore::list returns newest first. Keep one latest scan per canonical kind/target;
    // normalise-all does not schedule collection of arbitrary observed identities.
    let mut normalise = Vec::new();
    if config.normalise_all {
        let mut seen = BTreeSet::new();
        for record in &records {
            if seen.insert((record.kind.as_str(), record.target.as_str())) {
                normalise.push(record);
            }
        }
    }

    for request in &config.targets {
        let key = format!(
            "{}:{}",
            request.kind.as_deref().unwrap_or("auto"),
            request.target
        );
        let last = latest(&records, request);
        if !config.normalise_all {
            if let Some(record) = last {
                normalise.push(record);
            }
        }
        if due(last, now, config.cadence_ms)
            && retry_after.get(&key).is_none_or(|until| now >= *until)
        {
            match api.service().start_or_join(request) {
                Ok(record) => eprintln!("continuous: scan {} scheduled", record.id),
                Err(error) => {
                    eprintln!("continuous: scan schedule failed: {error}");
                    retry_after.insert(key, now.saturating_add(RETRY));
                }
            }
        }
    }
    for record in normalise {
        let analysis_key = format!("analysis:{}", record.id);
        let output = normalised_path(record, &config.normalised_dir);
        if record.status.is_active() {
            observed.remove(&output);
            if let Err(error) = archive_current(&output) {
                eprintln!("continuous: {error}");
            }
            continue;
        }
        let source = results_path(api, record);
        let stamp = match revision_stamp(&source) {
            Ok(stamp) => stamp,
            Err(error) => {
                if let Err(archive_error) = archive_current(&output) {
                    eprintln!("continuous: {archive_error}");
                }
                observed.remove(&output);
                eprintln!("continuous: {error}");
                continue;
            }
        };
        let current_is_regular = fs::symlink_metadata(&output)
            .is_ok_and(|meta| meta.is_file() && !meta.file_type().is_symlink());
        if !needs_reconciliation(observed.get(&output), &record.id, stamp, current_is_regular) {
            continue;
        }
        if let Err(error) = archive_current(&output) {
            eprintln!("continuous: {error}");
            continue;
        }
        observed.remove(&output);
        if retry_after
            .get(&analysis_key)
            .is_some_and(|until| now < *until)
        {
            continue;
        }
        match normalise_saved(api, record, &config.normalised_dir, stamp) {
            Ok(true) => {
                // Never mark a revision observed if it changed during analysis.
                match revision_stamp(&source) {
                    Ok(after) if after == stamp => {
                        observed.insert(output.clone(), (record.id.clone(), stamp));
                        retry_after.remove(&analysis_key);
                        eprintln!("continuous: normalised saved scan {}", record.id);
                    }
                    _ => {
                        if let Err(error) = archive_current(&output) {
                            eprintln!("continuous: {error}");
                        }
                        eprintln!("continuous: scan {} changed during analysis", record.id);
                    }
                }
            }
            Ok(false) => {}
            Err(error) => {
                eprintln!("continuous: {error}");
                retry_after.insert(analysis_key, now.saturating_add(RETRY));
            }
        }
    }
    Ok(())
}

/// Start the controller only when explicitly configured; it shares the server's
/// scan service, rate/worker admission and durable scan store.
pub(super) fn launch(scans: Option<&Arc<ScanApi>>) -> Result<(), String> {
    let Some(raw) = env::var_os("HUNTSMAN_CONTINUOUS_TARGETS") else {
        return Ok(());
    };
    let raw = raw
        .into_string()
        .map_err(|_| "continuous target list is not UTF-8")?;
    let Some(scans) = scans else {
        return Err("continuous normalisation requires an available scan store".to_owned());
    };
    let state = default_scan_dir()
        .and_then(|path| path.parent().map(std::path::Path::to_path_buf))
        .ok_or("continuous normalisation requires an absolute state directory")?;
    let minutes =
        env::var("HUNTSMAN_CONTINUOUS_INTERVAL_MINUTES").unwrap_or_else(|_| "1440".to_owned());
    let config = config(&raw, &minutes, state.join("normalised"))?;
    let api = Arc::clone(scans);
    eprintln!(
        "continuous: enabled with {} canonical targets, interval={} minutes, normalise_all={}",
        config.targets.len(),
        config.cadence_ms / 60_000,
        config.normalise_all
    );
    thread::Builder::new()
        .name("continuous-normalisation".to_owned())
        .spawn(move || {
            let mut observed = BTreeMap::new();
            let mut retry_after = BTreeMap::new();
            loop {
                if let Err(error) = cycle(&api, &config, &mut observed, &mut retry_after) {
                    eprintln!("continuous: {error}");
                }
                thread::sleep(TICK);
            }
        })
        .map_err(|error| format!("could not start continuous normalisation: {error}"))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        RevisionStamp, archive_current, config, due, needs_reconciliation, revision_stamp,
    };
    use huntsman_recon::scan_store::{RiskCounts, ScanOptions, ScanRecord, ScanStatus};
    use std::path::PathBuf;

    #[test]
    fn targets_are_canonical_and_deduplicated() {
        let configured = config(
            " Example.COM. ; example.com ; 1.1.1.1 ",
            "1440",
            PathBuf::from("/tmp/example"),
        )
        .expect("canonical targets");
        assert_eq!(configured.targets.len(), 2);
        assert!(configured.targets.iter().any(|r| r.target == "example.com"));
        assert!(
            configured
                .targets
                .iter()
                .all(|r| r.options.usecase == "passive")
        );
    }

    #[test]
    fn wildcard_enables_reconciliation_without_network_scan_targets() {
        let configured =
            config("*", "1440", PathBuf::from("/tmp/example")).expect("offline normalisation");
        assert!(configured.normalise_all);
        assert_eq!(configured.targets.len(), 0);
    }

    #[test]
    fn refuses_invalid_configuration() {
        assert!(config(" ", "1440", PathBuf::from("/tmp/x")).is_err());
        assert!(config("example.com", "0", PathBuf::from("/tmp/x")).is_err());
        assert!(config("example.com", "10081", PathBuf::from("/tmp/x")).is_err());
        assert!(config("example.com", "abc", PathBuf::from("/tmp/x")).is_err());
    }

    #[test]
    fn refuses_continuous_people_name_expansion() {
        let Err(error) = config("Jane Example", "1440", PathBuf::from("/tmp/x")) else {
            panic!("a continuous people-name scan must be rejected");
        };
        assert_eq!(error, "continuous people-name scans are disabled");
    }

    #[test]
    fn due_respects_active_and_recent_scans() {
        assert!(due(None, 1_000, 60_000));
        let mut record = ScanRecord {
            format_version: 1,
            id: "0123456789abcdef".into(),
            name: "example".into(),
            target: "example.com".into(),
            target_type: "INTERNET_NAME".into(),
            kind: "domain".into(),
            options: ScanOptions::default(),
            status: ScanStatus::Running,
            created: 100,
            started: None,
            ended: None,
            elements: 0,
            unique: 0,
            correlations: RiskCounts::default(),
            errors: 0,
            modules_run: Vec::new(),
            owner: None,
        };
        assert!(!due(Some(&record), 500_000, 60_000));
        record.status = ScanStatus::ErrorFailed;
        assert!(!due(Some(&record), 60_099, 60_000));
        assert!(due(Some(&record), 60_100, 60_000));
        // A scan longer than the interval must still get a full rest after finishing.
        record.ended = Some(120_000);
        assert!(!due(Some(&record), 120_000, 60_000));
        assert!(!due(Some(&record), 179_999, 60_000));
        assert!(due(Some(&record), 180_000, 60_000));
        // Finished and aborted scans obey the same completion-time boundary.
        record.status = ScanStatus::Finished;
        assert!(!due(Some(&record), 179_999, 60_000));
        record.status = ScanStatus::Aborted;
        assert!(due(Some(&record), 180_000, 60_000));
        // Clock regressions and malformed earlier end times never accelerate refresh.
        record.ended = Some(50);
        assert!(!due(Some(&record), 60_099, 60_000));
        assert!(due(Some(&record), 60_100, 60_000));
    }
    #[test]
    fn changed_evidence_and_restart_invalidate_cached_analysis() {
        let old = RevisionStamp {
            bytes: 10,
            modified_ns: 100,
        };
        let new = RevisionStamp {
            bytes: 11,
            modified_ns: 101,
        };
        let previous = ("scan-a".to_owned(), old);
        assert!(!needs_reconciliation(Some(&previous), "scan-a", old, true));
        assert!(needs_reconciliation(Some(&previous), "scan-a", new, true));
        assert!(needs_reconciliation(Some(&previous), "scan-a", old, false));
        assert!(needs_reconciliation(Some(&previous), "scan-b", old, true));
        assert!(needs_reconciliation(None, "scan-a", old, true));
    }

    #[test]
    fn stale_report_is_preserved_and_removed_from_current_slot() {
        let dir = std::env::temp_dir().join(format!(
            "hse-continuous-{}-{}",
            std::process::id(),
            huntsman_recon::clock::unix_now_millis()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let report = dir.join("canonical.json");
        std::fs::write(&report, b"historical").unwrap();
        assert!(archive_current(&report).unwrap());
        assert!(!report.exists());
        let files = std::fs::read_dir(&dir)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .collect::<Vec<_>>();
        assert_eq!(files.len(), 1);
        assert!(files[0].to_string_lossy().contains(".stale-"));
        assert_eq!(std::fs::read(&files[0]).unwrap(), b"historical");
        assert!(!archive_current(&report).unwrap());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn revision_stamp_detects_saved_results_replacement() {
        let dir = std::env::temp_dir().join(format!(
            "hse-continuous-revision-{}-{}",
            std::process::id(),
            huntsman_recon::clock::unix_now_millis()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("results.json");
        std::fs::write(&path, b"original").unwrap();
        let old = revision_stamp(&path).unwrap();
        std::fs::write(&path, b"updated-data").unwrap();
        assert_ne!(revision_stamp(&path).unwrap(), old);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
