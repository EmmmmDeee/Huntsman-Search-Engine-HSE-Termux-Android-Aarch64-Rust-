//! Opt-in, bounded, always-on reconciliation of saved-scan evidence.
//!
//! Uses the existing `ScanService` and /analyze endpoint rather than creating another
//! canonicalisation or attribution model. Nothing runs until targets are configured.
use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use huntsman_recon::fsio::{read_bounded, write_atomic_private};
use huntsman_recon::scan_api::ScanApi;
use huntsman_recon::scan_service::{ScanRequest, plan};
use huntsman_recon::scan_store::{ScanOptions, ScanRecord, ScanStore};
use huntsman_recon::sha256::{hex32, sha256};
use serde_json::{Value, json};

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

/// A new scan must not be scheduled over an active or recently attempted scan.
/// Failed attempts are evidence of failure, not permission to hammer the provider.
fn due(record: Option<&ScanRecord>, now: u64, cadence_ms: u64) -> bool {
    record.is_none_or(|record| {
        !record.status.is_active() && now.saturating_sub(record.created) >= cadence_ms
    })
}

fn millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |time| {
            u64::try_from(time.as_millis()).unwrap_or(u64::MAX)
        })
}

// Revision detection uses cheap file metadata, including the inode on Unix so atomic
// replacement is visible even when size and timestamp coincide. This is a change detector,
// not a content checksum: adversarial in-place changes that restore metadata may escape it.
fn file_stamp(path: &Path) -> Result<String, String> {
    let meta =
        fs::symlink_metadata(path).map_err(|error| format!("{}: {error}", path.display()))?;
    if !meta.is_file() || meta.file_type().is_symlink() {
        return Err(format!("{}: not a regular evidence file", path.display()));
    }
    let modified = meta
        .modified()
        .map_err(|error| format!("{}: {error}", path.display()))?
        .duration_since(UNIX_EPOCH)
        .map_err(|error| format!("{}: {error}", path.display()))?;
    #[cfg(unix)]
    let inode = {
        use std::os::unix::fs::MetadataExt;
        meta.ino()
    };
    #[cfg(not(unix))]
    let inode = 0_u64;
    Ok(format!(
        "{}:{}:{}:{inode}",
        meta.len(),
        modified.as_secs(),
        modified.subsec_nanos()
    ))
}

fn source_revision(store: &ScanStore, record: &ScanRecord) -> Result<String, String> {
    let directory = store.dir().join(&record.id);
    let row = file_stamp(&directory.join("scan.json"))?;
    let result_path = directory.join("results.json");
    let results = match fs::symlink_metadata(&result_path) {
        Ok(_) => file_stamp(&result_path)?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => "absent".to_owned(),
        Err(error) => return Err(format!("{}: {error}", result_path.display())),
    };
    let stamp = format!("v1:{row}:{results}");
    Ok(hex32(&sha256(stamp.as_bytes())))
}

fn normalised_path(record: &ScanRecord, directory: &Path) -> PathBuf {
    let key = format!("{}\0{}", record.kind, record.target);
    directory.join(format!("{}.json", &hex32(&sha256(key.as_bytes()))[..32]))
}

// Retain the most recent valid derived output outside the current-report slot.
// Never archive a stale marker over that historical evidence.
fn archive_previous(output: &Path) -> Result<(), String> {
    match fs::symlink_metadata(output) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(format!("{}: {error}", output.display())),
        Ok(meta) if !meta.is_file() || meta.file_type().is_symlink() => {
            return Err(format!("{}: not a regular report", output.display()));
        }
        Ok(_) => {}
    }
    let prior = read_bounded(output, MAX_ANALYSIS_BYTES)
        .map_err(|error| format!("cannot archive previous report: {error}"))?;
    let stale = serde_json::from_slice::<Value>(&prior)
        .ok()
        .and_then(|value| value["normalisation"]["state"].as_str().map(str::to_owned))
        .is_some_and(|state| state == "stale");
    if !stale {
        let previous = output.with_extension("previous.json");
        write_atomic_private(&previous, &prior, MAX_ANALYSIS_BYTES)
            .map_err(|error| format!("cannot preserve historical report: {error}"))?;
    }
    Ok(())
}

fn invalidate_saved(
    record: &ScanRecord,
    directory: &Path,
    revision: &str,
    reason: &str,
) -> Result<(), String> {
    let output = normalised_path(record, directory);
    archive_previous(&output)?;
    let marker = json!({
        "normalisation": {
            "state": "stale",
            "source_revision_hint": revision,
            "reason": reason,
            "scan_id": record.id,
            "canonical_kind": record.kind,
            "canonical_target": record.target,
            "checked_at_ms": millis(),
            "historical_report_suffix": ".previous.json"
        }
    });
    let body = serde_json::to_vec(&marker).map_err(|error| error.to_string())?;
    write_atomic_private(&output, &body, MAX_ANALYSIS_BYTES)
        .map_err(|error| format!("cannot invalidate stale report: {error}"))
}

fn normalise_saved(
    api: &ScanApi,
    record: &ScanRecord,
    directory: &Path,
    revision: &str,
) -> Result<bool, String> {
    if record.status.is_active() {
        return Ok(false);
    }
    let response = api.handle("GET", &format!("/api/scans/{}/analyze", record.id), "");
    if response.status != 200 {
        invalidate_saved(
            record,
            directory,
            revision,
            &format!("analysis_refused_http_{}", response.status),
        )?;
        return Err(format!(
            "scan {} analysis refused (HTTP {})",
            record.id, response.status
        ));
    }
    if response.body.len() as u64 > MAX_ANALYSIS_BYTES {
        invalidate_saved(record, directory, revision, "analysis_exceeds_output_limit")?;
        return Err(format!(
            "scan {} analysis exceeds bounded output",
            record.id
        ));
    }
    let after = match source_revision(api.service().store(), record) {
        Ok(revision) => revision,
        Err(error) => {
            invalidate_saved(record, directory, "unavailable", "evidence_unreadable_after_analysis")?;
            return Err(error);
        }
    };
    if revision != after {
        invalidate_saved(
            record,
            directory,
            &after,
            "evidence_changed_during_analysis",
        )?;
        return Err(format!(
            "scan {} evidence changed during analysis",
            record.id
        ));
    }
    let mut report: Value = match serde_json::from_slice(&response.body) {
        Ok(report) => report,
        Err(error) => {
            invalidate_saved(record, directory, revision, "malformed_analysis")?;
            return Err(format!("scan {} malformed analysis: {error}", record.id));
        }
    };
    let Some(root) = report.as_object_mut() else {
        invalidate_saved(record, directory, revision, "unexpected_analysis_shape")?;
        return Err(format!("scan {} analysis is not an object", record.id));
    };
    root.insert(
        "normalisation".to_owned(),
        json!({
            "state": "current",
            "source_revision_hint": revision,
            "checked_at_ms": millis(),
        }),
    );
    let body = serde_json::to_vec(&report).map_err(|error| error.to_string())?;
    if body.len() as u64 > MAX_ANALYSIS_BYTES {
        invalidate_saved(record, directory, revision, "normalised_output_too_large")?;
        return Err(format!(
            "scan {} normalised output exceeds limit",
            record.id
        ));
    }
    let output = normalised_path(record, directory);
    archive_previous(&output)?;
    write_atomic_private(&output, &body, MAX_ANALYSIS_BYTES)
        .map_err(|error| format!("normalisation write failed: {error}"))?;
    Ok(true)
}

fn cycle(
    api: &ScanApi,
    config: &Config,
    observed: &mut BTreeMap<String, String>,
    retry_after: &mut BTreeMap<String, u64>,
) -> Result<(), String> {
    let now = millis();
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
        if record.status.is_active() {
            continue;
        }
        let revision = match source_revision(api.service().store(), record) {
            Ok(revision) => revision,
            Err(error) => {
                eprintln!("continuous: cannot inspect scan {}: {error}", record.id);
                if let Err(invalidation) = invalidate_saved(
                    record,
                    &config.normalised_dir,
                    "unavailable",
                    "evidence_revision_unreadable",
                ) {
                    eprintln!("continuous: {invalidation}");
                }
                continue;
            }
        };
        let analysis_key = format!("analysis:{}", record.id);
        if observed.get(&record.id) != Some(&revision)
            && retry_after
                .get(&analysis_key)
                .is_none_or(|until| now >= *until)
        {
            match normalise_saved(api, record, &config.normalised_dir, &revision) {
                Ok(true) => {
                    observed.insert(record.id.clone(), revision);
                    retry_after.remove(&analysis_key);
                    eprintln!("continuous: normalised saved scan {}", record.id);
                }
                Ok(false) => {}
                Err(error) => {
                    eprintln!("continuous: {error}");
                    retry_after.insert(analysis_key, now.saturating_add(RETRY));
                }
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
        archive_previous, config, due, file_stamp, invalidate_saved, normalised_path,
        source_revision,
    };
    use huntsman_recon::scan_store::{RiskCounts, ScanOptions, ScanRecord, ScanStatus, ScanStore};
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
    fn atomic_evidence_changes_invalidate_revision_hint() {
        let directory = std::env::temp_dir().join(format!(
            "huntsman-continuous-revision-{}-{}",
            std::process::id(),
            super::millis()
        ));
        let store = ScanStore::open(&directory).expect("create temporary store");
        let record = ScanRecord {
            format_version: 1,
            id: "0123456789abcdef".into(),
            name: "test".into(),
            target: "example.com".into(),
            target_type: "INTERNET_NAME".into(),
            kind: "domain".into(),
            options: ScanOptions::default(),
            status: ScanStatus::Finished,
            created: 100,
            started: None,
            ended: Some(200),
            elements: 0,
            unique: 0,
            correlations: RiskCounts::default(),
            errors: 0,
            modules_run: Vec::new(),
            owner: None,
        };
        store.create(&record).expect("create scan");
        let first = source_revision(&store, &record).expect("initial revision");
        let results = directory.join(&record.id).join("results.json");
        std::fs::write(&results, b"{}").expect("write results");
        let second = source_revision(&store, &record).expect("new results revision");
        assert_ne!(first, second);
        std::fs::write(&results, b"{\"revision\":2}").expect("revise results");
        let third = source_revision(&store, &record).expect("replaced revision");
        assert_ne!(second, third);
        assert!(file_stamp(&results).is_ok());
        std::fs::remove_dir_all(&directory).expect("remove test store");
    }

    #[test]
    fn stale_marker_does_not_overwrite_historical_evidence() {
        let directory = std::env::temp_dir().join(format!(
            "huntsman-continuous-archive-{}-{}",
            std::process::id(),
            super::millis()
        ));
        std::fs::create_dir(&directory).expect("create archive directory");
        let output = directory.join("canonical.json");
        let original = br#"{"report":{"count":2}}"#;
        std::fs::write(&output, original).expect("write good report");
        archive_previous(&output).expect("save history");
        assert_eq!(
            std::fs::read(output.with_extension("previous.json")).unwrap(),
            original
        );
        std::fs::write(&output, br#"{"normalisation":{"state":"stale"}}"#)
            .expect("replace report with stale marker");
        archive_previous(&output).expect("keep historical version");
        assert_eq!(
            std::fs::read(output.with_extension("previous.json")).unwrap(),
            original
        );
        std::fs::remove_dir_all(&directory).expect("remove archive directory");
    }

    #[test]
    fn refused_evidence_is_marked_stale_and_previous_report_survives() {
        let directory = std::env::temp_dir().join(format!(
            "huntsman-continuous-stale-{}-{}",
            std::process::id(),
            super::millis()
        ));
        std::fs::create_dir(&directory).expect("create stale marker directory");
        let record = ScanRecord {
            format_version: 1,
            id: "0123456789abcdef".into(),
            name: "test".into(),
            target: "example.com".into(),
            target_type: "INTERNET_NAME".into(),
            kind: "domain".into(),
            options: ScanOptions::default(),
            status: ScanStatus::Finished,
            created: 100,
            started: None,
            ended: Some(200),
            elements: 0,
            unique: 0,
            correlations: RiskCounts::default(),
            errors: 0,
            modules_run: Vec::new(),
            owner: None,
        };
        let path = normalised_path(&record, &directory);
        let original = br#"{"report":{"confirmed":true}}"#;
        std::fs::write(&path, original).expect("write current report");
        invalidate_saved(&record, &directory, "new-revision", "false_positive")
            .expect("invalidate");
        let stale: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        assert_eq!(stale["normalisation"]["state"], "stale");
        assert_eq!(stale["normalisation"]["reason"], "false_positive");
        assert!(stale.get("report").is_none());
        assert_eq!(
            std::fs::read(path.with_extension("previous.json")).unwrap(),
            original
        );
        std::fs::remove_dir_all(&directory).expect("remove stale test directory");
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
    }
}
