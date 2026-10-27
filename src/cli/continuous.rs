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
use huntsman_recon::environment::{CONTINUOUS_INTERVAL_ENV, CONTINUOUS_TARGETS_ENV};
use huntsman_recon::fsio::{read_bounded, write_atomic_private};
use huntsman_recon::keys::Keys;
use huntsman_recon::scan_alert::{self, Policy};
use huntsman_recon::scan_api::ScanApi;
use huntsman_recon::scan_compare;
use huntsman_recon::scan_service::{ScanRequest, plan};
use huntsman_recon::scan_store::{
    MAX_RESULTS_BYTES, ScanOptions, ScanRecord, ScanStatus, ScanStore,
};
use huntsman_recon::sf_correlate::Risk;
use huntsman_recon::sha256::{hex32, sha256};
use serde_json::{Value, json};

use super::scans::default_scan_dir;

const MAX_TARGETS: usize = 32;
const MAX_TARGET_CONFIG_BYTES: usize = 8192;
const MAX_ANALYSIS_BYTES: u64 = 4 * 1024 * 1024;
const TICK: Duration = Duration::from_secs(60);
const RETRY: u64 = 15 * 60 * 1000;

/// What continuous normalisation runs with, from [`configure`].
pub(super) struct Config {
    targets: Vec<ScanRequest>,
    cadence_ms: u64,
    normalised_dir: PathBuf,
    normalise_all: bool,
}

impl Config {
    /// What the Settings page shows for this configuration: the cadence, every target with its
    /// kind, and whether every saved target is re-normalised too.
    fn summary(&self) -> String {
        let mut parts: Vec<String> = self
            .targets
            .iter()
            .map(|request| {
                format!(
                    "{} ({})",
                    request.target,
                    request.kind.as_deref().unwrap_or("auto")
                )
            })
            .collect();
        if self.normalise_all {
            parts.push("every saved target, re-normalised only".to_owned());
        }
        format!(
            "every {} minutes: {}",
            self.cadence_ms / 60_000,
            parts.join(", ")
        )
    }
}

/// The Global Settings entry's key and label for continuous normalisation.
pub(super) const SETTING_KEY: &str = "continuous";
pub(super) const SETTING_DESCRIPTION: &str = "continuous normalisation while serve runs";

/// The Global Settings value for `config`: its summary, or that it is off and how to turn it on.
pub(super) fn setting_value(config: Option<&Config>) -> String {
    config.map_or_else(
        || format!("off (set {CONTINUOUS_TARGETS_ENV} in ~/.huntsman.env or the environment)"),
        Config::summary,
    )
}

/// The configuration `keys` holds, read as every key is: [`CONTINUOUS_TARGETS_ENV`] and
/// [`CONTINUOUS_INTERVAL_ENV`] from `~/.huntsman.env`, then the process environment. `None` when
/// no targets are set, so the controller stays off; an error names the setting that is wrong.
pub(super) fn configure(keys: &Keys) -> Result<Option<Config>, String> {
    let Some((targets, minutes)) = settings(keys)? else {
        return Ok(None);
    };
    let state = default_scan_dir()
        .and_then(|path| path.parent().map(Path::to_path_buf))
        .ok_or("continuous normalisation requires an absolute state directory")?;
    config(&targets, &minutes, state.join("normalised")).map(Some)
}

/// The two settings as `keys` resolves them: the target list and the interval, `1440` when the
/// interval is unset. A target list the environment holds as something other than UTF-8 is an
/// error, not an unconfigured controller.
fn settings(keys: &Keys) -> Result<Option<(String, String)>, String> {
    let Some(targets) = keys.setting(CONTINUOUS_TARGETS_ENV) else {
        if env::var_os(CONTINUOUS_TARGETS_ENV).is_some_and(|raw| raw.into_string().is_err()) {
            return Err(format!("{CONTINUOUS_TARGETS_ENV} is not UTF-8"));
        }
        return Ok(None);
    };
    let minutes = keys
        .setting(CONTINUOUS_INTERVAL_ENV)
        .unwrap_or_else(|| "1440".to_owned());
    Ok(Some((targets, minutes)))
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
            "{CONTINUOUS_TARGETS_ENV} exceeds {MAX_TARGET_CONFIG_BYTES} bytes"
        ));
    }
    let minutes: u64 = minutes
        .parse()
        .map_err(|_| format!("{CONTINUOUS_INTERVAL_ENV} must be an integer (60..=10080)"))?;
    if !(60..=10_080).contains(&minutes) {
        return Err(format!("{CONTINUOUS_INTERVAL_ENV} must be 60..=10080"));
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
        return Err(format!(
            "{CONTINUOUS_TARGETS_ENV} contains no valid targets"
        ));
    }
    Ok(Config {
        targets: unique.into_values().collect(),
        cadence_ms: minutes * 60 * 1000,
        normalised_dir: directory,
        normalise_all,
    })
}

/// Whether `record` is a scan of the configured `request`: its target, by the same lookup.
fn scans(record: &ScanRecord, request: &ScanRequest) -> bool {
    record.target == request.target && request.kind.as_deref() == Some(record.kind.as_str())
}

fn latest<'a>(records: &'a [ScanRecord], request: &ScanRequest) -> Option<&'a ScanRecord> {
    records
        .iter()
        .filter(|record| scans(record, request))
        .max_by_key(|record| (record.created, record.id.as_str()))
}

/// For each configured target, whether its newest finished scan raises an alert over the
/// finished scan before it, decided once per newest scan with the default policy (a new HIGH
/// correlation) and kept in the alert history `scans alerts`, the scan API and the Web UI read.
/// The history is the record of what was decided, so a restarted controller does not decide
/// again. It reads only saved scans and requests nothing. Returns how many it recorded.
fn record_alerts(
    api: &ScanApi,
    records: &[ScanRecord],
    targets: &[ScanRequest],
    now: u64,
) -> Result<usize, String> {
    let store = api.service().store();
    let path = store.dir().join(scan_alert::HISTORY_FILE);
    let decided: BTreeSet<String> = scan_alert::read_history(&path)
        .map_err(|error| error.to_string())?
        .iter()
        .filter_map(|entry| entry["later"].as_str().map(str::to_owned))
        .collect();
    let policy = Policy {
        min_risk: Risk::High,
        new_values: false,
    };
    let mut recorded = 0;
    for request in targets {
        let mut finished: Vec<&ScanRecord> = records
            .iter()
            .filter(|record| scans(record, request) && record.status == ScanStatus::Finished)
            .collect();
        finished.sort_by_key(|record| (record.created, record.id.as_str()));
        let [.., earlier, later] = finished.as_slice() else {
            continue;
        };
        if decided.contains(&later.id) {
            continue;
        }
        let saved = |id: &str| store.results(id).map_err(|error| error.to_string());
        let (Some(base), Some(other)) = (saved(&earlier.id)?, saved(&later.id)?) else {
            continue;
        };
        let alert = scan_alert::assess(&scan_compare::compare(&base, &other), policy);
        let entry = scan_alert::history_entry(now, &earlier.id, &later.id, &alert);
        scan_alert::append_history(&path, &entry).map_err(|error| error.to_string())?;
        if alert.raised {
            eprintln!(
                "continuous: alert raised for scan {} over {}",
                later.id, earlier.id
            );
        }
        recorded += 1;
    }
    Ok(recorded)
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

// Hash saved bytes only when analysing a changed scan, not on each 60-second tick.
// A same-size, restored-mtime edit during analysis must not yield a current report.
fn results_digest(store: &ScanStore, record: &ScanRecord) -> Result<String, String> {
    let path = store.dir().join(&record.id).join("results.json");
    let bytes = read_bounded(&path, MAX_RESULTS_BYTES)
        .map_err(|error| format!("cannot hash saved results: {error}"))?;
    Ok(hex32(&sha256(&bytes)))
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

fn persist_normalised_report(
    record: &ScanRecord,
    directory: &Path,
    revision: &str,
    before_digest: &str,
    mut report: Value,
) -> Result<bool, String> {
    let Some(root) = report.as_object_mut() else {
        invalidate_saved(record, directory, revision, "unexpected_analysis_shape")?;
        return Err(format!("scan {} analysis is not an object", record.id));
    };
    root.insert(
        "normalisation".to_owned(),
        json!({
            "state": "current",
            "source_revision_hint": revision,
            "results_sha256": before_digest,
            "scan_id": record.id,
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

fn normalise_saved(
    api: &ScanApi,
    record: &ScanRecord,
    directory: &Path,
    revision: &str,
) -> Result<bool, String> {
    if record.status.is_active() {
        return Ok(false);
    }
    let before_digest = match results_digest(api.service().store(), record) {
        Ok(digest) => digest,
        Err(error) => {
            invalidate_saved(
                record,
                directory,
                revision,
                "results_unreadable_before_analysis",
            )?;
            return Err(error);
        }
    };
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
    match results_digest(api.service().store(), record) {
        Ok(after_digest) if after_digest == before_digest => {}
        Ok(_) => {
            invalidate_saved(
                record,
                directory,
                revision,
                "results_changed_during_analysis",
            )?;
            return Err(format!(
                "scan {} saved results changed during analysis",
                record.id
            ));
        }
        Err(error) => {
            invalidate_saved(
                record,
                directory,
                revision,
                "results_unreadable_after_analysis",
            )?;
            return Err(error);
        }
    }
    let report: Value = match serde_json::from_slice(&response.body) {
        Ok(report) => report,
        Err(error) => {
            invalidate_saved(record, directory, revision, "malformed_analysis")?;
            return Err(format!("scan {} malformed analysis: {error}", record.id));
        }
    };
    persist_normalised_report(record, directory, revision, &before_digest, report)
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
    if let Err(error) = record_alerts(api, &records, &config.targets, now) {
        eprintln!("continuous: alert decision not recorded: {error}");
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

/// Starts the controller [`configure`] described, if any; it shares the server's scan service,
/// rate/worker admission and durable scan store, so it needs the saved scans to be on.
pub(super) fn launch(config: Option<Config>, scans: Option<&Arc<ScanApi>>) -> Result<(), String> {
    let Some(config) = config else {
        return Ok(());
    };
    let Some(scans) = scans else {
        return Err("continuous normalisation requires an available scan store".to_owned());
    };
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
        normalised_path, prune_tracking_state, results_digest, setting_value, settings,
        source_revision,
    };
    use huntsman_recon::entity::{Entity, EntityKind, Evidence, EvidenceProvenance};
    use huntsman_recon::keys::Keys;
    use huntsman_recon::scan_api::ScanApi;
    use huntsman_recon::scan_service::{LookupOutput, ScanLookup, ScanRequest, ScanService};
    use huntsman_recon::scan_store::{RiskCounts, ScanOptions, ScanRecord, ScanStatus, ScanStore};
    use huntsman_recon::source_outcome::SourceExecutionOutcome;
    use std::collections::BTreeMap;
    use std::path::PathBuf;
    use std::sync::Arc;

    /// Both settings come from the keys file, as every key does, with the interval defaulted; a
    /// file without the target list leaves the controller off.
    #[test]
    fn settings_come_from_the_keys_file_with_the_interval_defaulted() {
        let keys = Keys::parse(
            "HUNTSMAN_CONTINUOUS_TARGETS=example.com;1.1.1.1\nHUNTSMAN_CONTINUOUS_INTERVAL_MINUTES=60\n",
        )
        .expect("keys");
        assert_eq!(
            settings(&keys).expect("read"),
            Some(("example.com;1.1.1.1".to_owned(), "60".to_owned()))
        );
        let keys = Keys::parse("HUNTSMAN_CONTINUOUS_TARGETS=*\n").expect("keys");
        assert_eq!(
            settings(&keys).expect("read"),
            Some(("*".to_owned(), "1440".to_owned()))
        );
        let keys = Keys::parse("HUNTSMAN_SHODAN_KEY=not-a-target-list-0123\n").expect("keys");
        assert_eq!(settings(&keys).expect("read"), None);
    }

    /// The Settings page reads what `serve` collects and how often, or how to turn it on.
    #[test]
    fn the_settings_page_reads_what_serve_collects_or_how_to_turn_it_on() {
        let configured = config("example.com;1.1.1.1;*", "60", PathBuf::from("/tmp/example"))
            .expect("configured");
        assert_eq!(
            setting_value(Some(&configured)),
            "every 60 minutes: example.com (domain), 1.1.1.1 (ip), every saved target, re-normalised only"
        );
        assert_eq!(
            setting_value(None),
            "off (set HUNTSMAN_CONTINUOUS_TARGETS in ~/.huntsman.env or the environment)"
        );
    }

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
    fn saved_results_digest_detects_same_size_in_place_changes() {
        let directory = std::env::temp_dir().join(format!(
            "huntsman-results-digest-{}-{}",
            std::process::id(),
            huntsman_recon::clock::unix_now_millis()
        ));
        let (api, record) = offline_scan_fixture(&directory);
        let source = directory.join(&record.id).join("results.json");
        let original = std::fs::read(&source).expect("saved scan results");
        assert_ne!(original, Vec::<u8>::new());
        let before = results_digest(api.service().store(), &record).expect("first digest");
        let mut altered = original.clone();
        altered[0] ^= 1;
        std::fs::write(&source, &altered).expect("same-size in-place edit");
        assert_eq!(original.len(), altered.len());
        let after = results_digest(api.service().store(), &record).expect("second digest");
        assert_ne!(before, after);
        std::fs::remove_dir_all(&directory).expect("remove fixture");
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
        assert_eq!(first["normalisation"]["scan_id"], record.id);
        assert_eq!(
            first["normalisation"]["results_sha256"],
            results_digest(service.store(), &record).expect("saved results digest")
        );
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

    /// A configured target's newest finished scan is decided once against the one before it and
    /// kept in the alert history; deciding again, as a restarted controller would, records nothing.
    #[test]
    fn a_configured_targets_new_scan_is_decided_once_into_the_alert_history() {
        use huntsman_recon::scan_alert;
        use huntsman_recon::scan_store::ScanCorrelation;
        use huntsman_recon::sf_correlate::Risk;
        let directory = std::env::temp_dir().join(format!(
            "huntsman-continuous-alert-{}-{}",
            std::process::id(),
            huntsman_recon::clock::unix_now_millis()
        ));
        let scans_dir = directory.join("scans");
        let (api, first) = offline_scan_fixture(&scans_dir);
        let configured = config("1.1.1.1", "60", directory.join("normalised")).expect("target");
        let store = api.service().store();
        let records = store.list().unwrap();
        assert_eq!(
            super::record_alerts(&api, &records, &configured.targets, 1).unwrap(),
            0,
            "one finished scan has nothing to be compared with"
        );

        let second = api
            .service()
            .run(&configured.targets[0])
            .expect("second scan");
        assert_eq!(second.status, ScanStatus::Finished);
        assert_eq!(
            second.kind, first.kind,
            "both scans are of the configured lookup"
        );
        let mut results = store.results(&second.id).unwrap().expect("saved results");
        results.correlations.push(ScanCorrelation {
            id: "fresh".into(),
            rule: "fresh_exposure".into(),
            name: "Fresh exposure".into(),
            title: "Port 443 newly exposed on 1.1.1.1".into(),
            risk: Risk::High,
            description: String::new(),
            origin: "huntsman".into(),
            logic: String::new(),
            elements: Vec::new(),
        });
        store.save_results(&results).expect("save correlation");

        let records = store.list().unwrap();
        assert_eq!(
            super::record_alerts(&api, &records, &configured.targets, 2).unwrap(),
            1
        );
        let history = scan_alert::read_history(&scans_dir.join(scan_alert::HISTORY_FILE)).unwrap();
        assert_eq!(history.len(), 1);
        assert_eq!(history[0]["earlier"], first.id.as_str());
        assert_eq!(history[0]["later"], second.id.as_str());
        assert_eq!(history[0]["raised"], true);
        assert_eq!(history[0]["reasons"][0]["rule"], "fresh_exposure");
        assert!(
            !history[0].to_string().contains("1.1.1.1"),
            "no target in the history"
        );

        assert_eq!(
            super::record_alerts(&api, &records, &configured.targets, 3).unwrap(),
            0,
            "a decided scan is not decided again"
        );
        assert_eq!(
            scan_alert::read_history(&scans_dir.join(scan_alert::HISTORY_FILE))
                .unwrap()
                .len(),
            1
        );
        std::fs::remove_dir_all(&directory).expect("remove fixture");
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
