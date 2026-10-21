//! Opt-in, bounded, always-on reconciliation of saved-scan evidence.
//!
//! Uses the existing `ScanService` and /analyze endpoint rather than creating another
//! canonicalisation or attribution model. Nothing runs until targets are configured.
use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::path::PathBuf;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use huntsman_recon::clock;
use huntsman_recon::fsio::write_atomic_private;
use huntsman_recon::scan_api::ScanApi;
use huntsman_recon::scan_service::{ScanRequest, plan};
use huntsman_recon::scan_store::{ScanOptions, ScanRecord};
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

/// A new scan must not be scheduled over an active or recently attempted scan.
/// Failed attempts are evidence of failure, not permission to hammer the provider.
fn due(record: Option<&ScanRecord>, now: u64, cadence_ms: u64) -> bool {
    record.is_none_or(|record| {
        !record.status.is_active() && now.saturating_sub(record.created) >= cadence_ms
    })
}

fn normalise_saved(
    api: &ScanApi,
    record: &ScanRecord,
    directory: &std::path::Path,
) -> Result<bool, String> {
    if record.status.is_active() {
        return Ok(false);
    }
    let response = api.handle("GET", &format!("/api/scans/{}/analyze", record.id), "");
    if response.status != 200 {
        // A refused or incomplete analysis must not overwrite an earlier good one.
        return Err(format!(
            "scan {} analysis refused (HTTP {})",
            record.id, response.status
        ));
    }
    if response.body.len() as u64 > MAX_ANALYSIS_BYTES {
        return Err(format!(
            "scan {} analysis exceeds bounded output",
            record.id
        ));
    }
    // Per-target latest, not per-run accumulation: canonical identity is the already-validated
    // scan target + kind. The scan ID remains in the report for provenance and audit.
    let key = format!("{}\0{}", record.kind, record.target);
    let output = directory.join(format!("{}.json", &hex32(&sha256(key.as_bytes()))[..32]));
    write_atomic_private(&output, &response.body, MAX_ANALYSIS_BYTES)
        .map_err(|error| format!("normalisation write failed: {error}"))?;
    Ok(true)
}

fn cycle(
    api: &ScanApi,
    config: &Config,
    observed: &mut BTreeSet<String>,
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
        if !record.status.is_active()
            && !observed.contains(&record.id)
            && retry_after
                .get(&analysis_key)
                .is_none_or(|until| now >= *until)
        {
            match normalise_saved(api, record, &config.normalised_dir) {
                Ok(true) => {
                    observed.insert(record.id.clone());
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
            let mut observed = BTreeSet::new();
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
    use super::{config, due};
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
    }
}
