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
use std::time::Duration;

use huntsman_recon::clock;
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

/// Retry identities remain distinct even when target text contains separators.
/// An analysis retry is tied to a persisted scan ID; collection retries only
/// apply to explicitly configured targets.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum RetryKey {
    Analysis(String),
    Collection {
        kind: Option<String>,
        target: String,
    },
}

impl RetryKey {
    fn collection(request: &ScanRequest) -> Self {
        Self::Collection {
            kind: request.kind.clone(),
            target: request.target.clone(),
        }
    }
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

// Revision detection uses cheap file metadata, including the inode on Unix so atomic
// replacement is visible even when size and timestamp coincide. This is a change detector,
// not a content checksum: adversarial in-place changes that restore metadata may escape it.
fn file_stamp(path: &Path) -> Result<String, String> {
    let meta =
        fs::symlink_metadata(path).map_err(|error| format!("{}: {error}", path.display()))?;
    if !meta.is_file() || meta.file_type().is_symlink() {
        return Err(format!("{}: not a regular evidence file", path.display()));
    }
    let (modified_secs, modified_nanos) = clock::unix_parts_of(
        meta.modified()
            .map_err(|error| format!("{}: {error}", path.display()))?,
    )
    .ok_or_else(|| {
        format!(
            "{}: modification time precedes the Unix epoch",
            path.display()
        )
    })?;
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
        modified_secs,
        modified_nanos
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
    let mut history: Value = serde_json::from_slice(&prior)
        .map_err(|error| format!("cannot read previous report JSON: {error}"))?;
    if history["normalisation"]["state"] == "stale" {
        return Ok(());
    }
    let Some(root) = history.as_object_mut() else {
        return Err("previous report must be a JSON object".to_owned());
    };
    let metadata = root.entry("normalisation").or_insert_with(|| json!({}));
    let Some(metadata) = metadata.as_object_mut() else {
        return Err("previous report normalisation metadata is invalid".to_owned());
    };
    metadata.insert("state".to_owned(), json!("historical"));
    metadata.insert("archived_at_ms".to_owned(), json!(clock::unix_now_millis()));
    let body = serde_json::to_vec(&history)
        .map_err(|error| format!("cannot serialize historical report: {error}"))?;
    let previous = output.with_extension("previous.json");
    write_atomic_private(&previous, &body, MAX_ANALYSIS_BYTES)
        .map_err(|error| format!("cannot preserve historical report: {error}"))?;
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
            "checked_at_ms": clock::unix_now_millis(),
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
            invalidate_saved(
                record,
                directory,
                "unavailable",
                "evidence_unreadable_after_analysis",
            )?;
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
            "checked_at_ms": clock::unix_now_millis(),
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

fn prune_tracking_state(
    records: &[ScanRecord],
    configured: &[ScanRequest],
    now: u64,
    observed: &mut BTreeMap<String, String>,
    retry_after: &mut BTreeMap<RetryKey, u64>,
) {
    let live_ids: BTreeSet<&str> = records.iter().map(|record| record.id.as_str()).collect();
    observed.retain(|id, _| live_ids.contains(id.as_str()));
    retry_after.retain(|key, until| {
        if *until <= now {
            return false;
        }
        match key {
            RetryKey::Analysis(scan_id) => live_ids.contains(scan_id.as_str()),
            RetryKey::Collection { kind, target } => configured.iter().any(|request| {
                request.kind.as_deref() == kind.as_deref()
                    && request.target.as_str() == target.as_str()
            }),
        }
    });
}

fn cycle(
    api: &ScanApi,
    config: &Config,
    observed: &mut BTreeMap<String, String>,
    retry_after: &mut BTreeMap<RetryKey, u64>,
) -> Result<(), String> {
    let now = clock::unix_now_millis();
    let records = api
        .service()
        .store()
        .list()
        .map_err(|error| error.to_string())?;
    prune_tracking_state(&records, &config.targets, now, observed, retry_after);
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
        let key = RetryKey::collection(request);
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
        let analysis_key = RetryKey::Analysis(record.id.clone());
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
        RetryKey, archive_previous, config, cycle, due, file_stamp, invalidate_saved,
        normalised_path, prune_tracking_state, source_revision,
    };
    use huntsman_recon::entity::{Entity, EntityKind, Evidence, EvidenceProvenance};
    use huntsman_recon::scan_api::ScanApi;
    use huntsman_recon::scan_service::{LookupOutput, ScanLookup, ScanRequest, ScanService};
    use huntsman_recon::scan_store::{RiskCounts, ScanOptions, ScanRecord, ScanStatus, ScanStore};
    use huntsman_recon::source_outcome::SourceExecutionOutcome;
    use std::collections::BTreeMap;
    use std::path::PathBuf;
    use std::sync::Arc;

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
            huntsman_recon::clock::unix_now_millis()
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
            owner_started: None,
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
            huntsman_recon::clock::unix_now_millis()
        ));
        std::fs::create_dir(&directory).expect("create archive directory");
        let output = directory.join("canonical.json");
        let original = br#"{"report":{"count":2}}"#;
        std::fs::write(&output, original).expect("write good report");
        archive_previous(&output).expect("save history");
        let archived: serde_json::Value =
            serde_json::from_slice(&std::fs::read(output.with_extension("previous.json")).unwrap())
                .unwrap();
        assert_eq!(archived["normalisation"]["state"], "historical");
        assert_eq!(archived["report"]["count"], 2);
        std::fs::write(&output, br#"{"normalisation":{"state":"stale"}}"#)
            .expect("replace report with stale marker");
        archive_previous(&output).expect("keep historical version");
        let archived: serde_json::Value =
            serde_json::from_slice(&std::fs::read(output.with_extension("previous.json")).unwrap())
                .unwrap();
        assert_eq!(archived["normalisation"]["state"], "historical");
        assert_eq!(archived["report"]["count"], 2);
        std::fs::remove_dir_all(&directory).expect("remove archive directory");
    }

    #[test]
    fn refused_evidence_is_marked_stale_and_previous_report_survives() {
        let directory = std::env::temp_dir().join(format!(
            "huntsman-continuous-stale-{}-{}",
            std::process::id(),
            huntsman_recon::clock::unix_now_millis()
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
            owner_started: None,
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
        let historical: serde_json::Value =
            serde_json::from_slice(&std::fs::read(path.with_extension("previous.json")).unwrap())
                .unwrap();
        assert_eq!(historical["normalisation"]["state"], "historical");
        assert_eq!(historical["report"]["confirmed"], true);
        std::fs::remove_dir_all(&directory).expect("remove stale test directory");
    }

    fn offline_scan_fixture(scans_dir: &std::path::Path) -> (ScanApi, ScanRecord) {
        let store = ScanStore::open(scans_dir).expect("scan store");
        let lookup: ScanLookup = Arc::new(|_, selector, _| {
            let evidence =
                Evidence::new(EvidenceProvenance::for_scan("internetdb", "test"), "ports")
                    .with_attr("ports", "443");
            Ok(LookupOutput {
                text: "offline fixture".to_owned(),
                entities: vec![
                    Entity::builder(EntityKind::IpAddress, selector, 0.9, "test")
                        .evidence(evidence)
                        .build(),
                ],
                outcomes: vec![SourceExecutionOutcome::success("internetdb", 1, 1)],
            })
        });
        let service = ScanService::new(store, lookup);
        let record = service
            .run(&ScanRequest {
                target: "1.1.1.1".to_owned(),
                options: ScanOptions {
                    usecase: "passive".to_owned(),
                    ..ScanOptions::default()
                },
                ..ScanRequest::default()
            })
            .expect("generate real saved scan fixture");
        assert_eq!(record.status, ScanStatus::Finished);
        (ScanApi::new(service, None), record)
    }

    #[test]
    fn wildcard_cycle_reconciles_false_positive_edits_without_network_collection() {
        let directory = std::env::temp_dir().join(format!(
            "huntsman-offline-fp-cycle-{}-{}",
            std::process::id(),
            huntsman_recon::clock::unix_now_millis()
        ));
        let scans_dir = directory.join("scans");
        let (api, record) = offline_scan_fixture(&scans_dir);
        let service = api.service();
        let configured =
            config("*", "1440", directory.join("normalised")).expect("offline-only mode");
        assert_eq!(configured.targets.len(), 0);

        let mut observed = BTreeMap::new();
        let mut retry_after = BTreeMap::new();
        let source_path = scans_dir.join(&record.id).join("results.json");
        let saved_evidence = std::fs::read(&source_path).expect("source bytes");
        cycle(&api, &configured, &mut observed, &mut retry_after).expect("first cycle");
        let report_path = normalised_path(&record, &configured.normalised_dir);
        let first: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&report_path).unwrap()).unwrap();
        assert_eq!(first["normalisation"]["state"], "current");
        assert_eq!(first["scan"]["id"], record.id);
        assert_eq!(std::fs::read(&source_path).unwrap(), saved_evidence);
        assert_eq!(observed.len(), 1);

        let mut results = service
            .store()
            .results(&record.id)
            .unwrap()
            .expect("saved results");
        let element = results
            .elements
            .iter_mut()
            .find(|element| element.entity.is_some() && element.kind != "ROOT")
            .expect("an evidence element to flag");
        element.fp = true;
        service
            .store()
            .save_results(&results)
            .expect("persist false positive");
        assert_eq!(
            api.handle("GET", &format!("/api/scans/{}/analyze", record.id), "")
                .status,
            409
        );
        cycle(&api, &configured, &mut observed, &mut retry_after).expect("flagged cycle");
        let stale: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&report_path).unwrap()).unwrap();
        assert_eq!(stale["normalisation"]["state"], "stale");
        assert_eq!(
            stale["normalisation"]["reason"],
            "analysis_refused_http_409"
        );
        assert!(stale.get("report").is_none());
        let previous: serde_json::Value = serde_json::from_slice(
            &std::fs::read(report_path.with_extension("previous.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(previous["normalisation"]["state"], "historical");
        assert_eq!(observed.len(), 1);
        assert_eq!(retry_after.len(), 1);
        assert!(
            service
                .store()
                .results(&record.id)
                .unwrap()
                .unwrap()
                .elements
                .iter()
                .any(|element| element.fp)
        );

        let mut results = service.store().results(&record.id).unwrap().unwrap();
        for element in &mut results.elements {
            element.fp = false;
        }
        service
            .store()
            .save_results(&results)
            .expect("remove false positive");
        // Emulate expiry of the documented 15-minute retry back-off without sleeping.
        retry_after.clear();
        cycle(&api, &configured, &mut observed, &mut retry_after).expect("recovered cycle");
        let recovered: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&report_path).unwrap()).unwrap();
        assert_eq!(recovered["normalisation"]["state"], "current");
        assert_eq!(recovered["scan"]["id"], record.id);

        // A restarted controller recomputes the latest saved scan without remote requests.
        let mut restarted_observed = BTreeMap::new();
        let mut restarted_retries = BTreeMap::new();
        cycle(
            &api,
            &configured,
            &mut restarted_observed,
            &mut restarted_retries,
        )
        .expect("process restart cycle");
        assert_eq!(restarted_observed.len(), 1);
        assert!(restarted_retries.is_empty());
        assert_eq!(service.store().list().unwrap().len(), 1);
        std::fs::remove_dir_all(&directory).expect("remove offline fixture");
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
            owner_started: None,
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
    fn deleted_scans_and_expired_backoffs_do_not_accumulate() {
        let record = ScanRecord {
            format_version: 1,
            id: "0123456789abcdef".into(),
            name: "example".into(),
            target: "example.com".into(),
            target_type: "INTERNET_NAME".into(),
            kind: "domain".into(),
            options: ScanOptions::default(),
            status: ScanStatus::ErrorFailed,
            created: 100,
            started: None,
            ended: None,
            elements: 0,
            unique: 0,
            correlations: RiskCounts::default(),
            errors: 0,
            modules_run: Vec::new(),
            owner: None,
            owner_started: None,
        };
        let mut observed = BTreeMap::from([
            ("0123456789abcdef".to_owned(), "rev1".to_owned()),
            ("deadbeefdeadbeef".to_owned(), "rev2".to_owned()),
        ]);
        let configured =
            config("example.com", "1440", PathBuf::from("/tmp/example")).expect("valid target");
        let collection_key = RetryKey::collection(&configured.targets[0]);
        let analysis_key = RetryKey::Analysis("0123456789abcdef".to_owned());
        let mut retry_after = BTreeMap::from([
            (analysis_key.clone(), 200),
            (RetryKey::Analysis("deadbeefdeadbeef".to_owned()), 200),
            (RetryKey::Analysis("expired".to_owned()), 99),
            (collection_key.clone(), 200),
            (
                RetryKey::Collection {
                    kind: Some("domain".to_owned()),
                    target: "removed.example.net".to_owned(),
                },
                200,
            ),
            (
                RetryKey::Collection {
                    kind: Some("domain".to_owned()),
                    target: "expired.example.net".to_owned(),
                },
                99,
            ),
        ]);
        let records = [record];
        prune_tracking_state(
            &records,
            &configured.targets,
            100,
            &mut observed,
            &mut retry_after,
        );
        assert_eq!(
            observed,
            BTreeMap::from([("0123456789abcdef".to_owned(), "rev1".to_owned())])
        );
        assert_eq!(retry_after.len(), 2);
        assert_eq!(retry_after.get(&analysis_key), Some(&200));
        assert_eq!(retry_after.get(&collection_key), Some(&200));
        // Repeated successful inventory reads must not change the stable state.
        let previous = (observed.clone(), retry_after.clone());
        prune_tracking_state(
            &records,
            &configured.targets,
            100,
            &mut observed,
            &mut retry_after,
        );
        assert_eq!(previous, (observed, retry_after));
    }
}
