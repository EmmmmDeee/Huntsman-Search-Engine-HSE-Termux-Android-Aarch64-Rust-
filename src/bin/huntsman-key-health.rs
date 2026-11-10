//! Pure-Rust, non-secret, continuously refreshed provider-key health register.
//!
//! This binary uses Huntsman's canonical key resolver, provider catalogue, optional
//! guarded provider probes and atomic private-file writer. It never rotates,
//! guesses, exports, serialises, or logs credential values. A configured key is
//! never represented as verified functional without a successful provider probe.

use std::env;
use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::thread;
use std::time::Duration;

use huntsman_recon::clock;
use huntsman_recon::fsio::{self, ExclusiveLock};
use huntsman_recon::http::{TransportConfig, UreqTransport};
use huntsman_recon::keys::Keys;
use huntsman_recon::provider_credentials::{self, ProbeState, ProviderProbeStatus, ProviderStatus};
use serde::Serialize;

const SCHEMA_VERSION: u8 = 1;
const MAX_REPORT_BYTES: u64 = 512 * 1024;
const DEFAULT_INTERVAL_SECS: u64 = 30 * 60;
const MIN_INTERVAL_SECS: u64 = 60;
const MAX_INTERVAL_SECS: u64 = 24 * 60 * 60;

#[derive(Debug)]
struct Options {
    output: PathBuf,
    probe: bool,
    watch: bool,
    interval_secs: u64,
}

#[derive(Serialize)]
struct Row {
    provider: &'static str,
    slots: Vec<Slot>,
    configured: bool,
    /// 'valid' is only used for an observed, successful authenticated provider probe.
    probe: &'static str,
    /// A configured key alone never implies a working key, subscription or source.
    authenticated_probe_success: bool,
    /// One of: authenticated_probe_success, not_configured, not_probed,
    /// unsupported, rejected, rate_limited, indeterminate, unavailable.
    health: &'static str,
    /// A source catalogue entry is not proof that the provider is invoked on a scan.
    runtime_use_verified: bool,
}

#[derive(Serialize)]
struct Slot {
    name: &'static str,
    configured: bool,
}

#[derive(Serialize)]
struct Report {
    schema_version: u8,
    observed_at_unix: u64,
    expected_refresh_interval_secs: u64,
    stale_after_unix: u64,
    status: &'static str,
    safety: &'static str,
    probe_requested: bool,
    key_resolution_warning_present: bool,
    provider_count: usize,
    configured_provider_count: usize,
    authenticated_probe_success_count: usize,
    providers_needing_attention: usize,
    unrecognised_slot_names: Vec<String>,
    providers: Vec<Row>,
}

fn row(status: ProviderStatus, probe: Option<ProbeState>) -> Row {
    let probe_name = probe.map_or("not_probed", ProbeState::as_str);
    let authenticated_probe_success = status.configured && probe == Some(ProbeState::Valid);
    let health = if !status.configured {
        "not_configured"
    } else if authenticated_probe_success {
        "authenticated_probe_success"
    } else {
        probe_name
    };
    Row {
        provider: status.name,
        slots: status
            .slots
            .into_iter()
            .map(|s| Slot {
                name: s.slot,
                configured: s.configured,
            })
            .collect(),
        configured: status.configured,
        probe: probe_name,
        authenticated_probe_success,
        health,
        runtime_use_verified: false,
    }
}

fn assemble(
    statuses: Vec<ProviderStatus>,
    probed: Option<Vec<ProviderProbeStatus>>,
    keys: &Keys,
    now: u64,
    key_resolution_warning_present: bool,
    interval_secs: u64,
) -> Report {
    let probe_requested = probed.is_some();
    let providers: Vec<Row> = match probed {
        Some(probes) => probes
            .into_iter()
            .map(|p| row(p.provider, Some(p.probe)))
            .collect(),
        None => statuses.into_iter().map(|s| row(s, None)).collect(),
    };
    Report {
        schema_version: SCHEMA_VERSION,
        observed_at_unix: now,
        expected_refresh_interval_secs: interval_secs,
        stale_after_unix: now.saturating_add(interval_secs).saturating_add(60),
        status: "provider_credential_health_not_credential_store",
        safety: "no_key_values; no_automatic_rotation; authenticated_probe_is_not_scan_use",
        probe_requested,
        key_resolution_warning_present,
        provider_count: providers.len(),
        configured_provider_count: providers.iter().filter(|p| p.configured).count(),
        authenticated_probe_success_count: providers
            .iter()
            .filter(|p| p.authenticated_probe_success)
            .count(),
        providers_needing_attention: providers
            .iter()
            .filter(|p| matches!(p.health, "rejected" | "rate_limited" | "unavailable"))
            .count(),
        unrecognised_slot_names: provider_credentials::unrecognised_slots(keys)
            .into_iter()
            .map(str::to_owned)
            .collect(),
        providers,
    }
}

fn refresh(probe_requested: bool, output: &Path, interval_secs: u64) -> Result<Report, String> {
    let home = env::var_os("HOME");
    let resolved = Keys::for_lookup(home.as_deref());
    let statuses = provider_credentials::status(&resolved.keys);
    // Live probes are opt-in: endpoints can consume requests or quota. They use
    // the already hardened guarded transport and existing provider probe contracts.
    let probed = probe_requested.then(|| {
        let transport = UreqTransport::new(&TransportConfig::default());
        provider_credentials::probe(&resolved.keys, &transport)
    });
    let report = assemble(
        statuses,
        probed,
        &resolved.keys,
        clock::unix_now(),
        resolved.warning.is_some(),
        interval_secs,
    );
    let bytes = serde_json::to_vec_pretty(&report)
        .map_err(|_| "health register JSON serialization failed".to_owned())?;
    let parent = output.parent().ok_or("health register has no parent directory")?;
    create_private_parent(parent)?;
    let _lock = ExclusiveLock::acquire(output, Duration::from_secs(2))
        .map_err(|_| "another health register writer is active or lock cannot be acquired".to_owned())?;
    fsio::write_atomic_private(output, &bytes, MAX_REPORT_BYTES)
        .map_err(|_| "atomic health register write failed; prior file preserved".to_owned())?;
    Ok(report)
}

fn create_private_parent(parent: &Path) -> Result<(), String> {
    if parent.as_os_str().is_empty() || !parent.is_absolute() {
        return Err("health register directory must be absolute".to_owned());
    }
    if let Ok(existing) = fs::symlink_metadata(parent) {
        if !existing.is_dir() || existing.file_type().is_symlink() {
            return Err("health register directory is not a real directory".to_owned());
        }
    } else {
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            let mut builder = fs::DirBuilder::new();
            builder.recursive(true).mode(0o700);
            builder.create(parent).map_err(|_| "cannot create private register directory")?;
        }
        #[cfg(not(unix))]
        fs::create_dir_all(parent).map_err(|_| "cannot create register directory")?;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let metadata = fs::symlink_metadata(parent).map_err(|_| "cannot stat register directory")?;
        if !metadata.is_dir() || metadata.permissions().mode() & 0o077 != 0 {
            return Err("health register parent is accessible by group or others".to_owned());
        }
    }
    Ok(())
}

fn parse_args(args: impl IntoIterator<Item = OsString>) -> Result<Option<Options>, String> {
    let mut output = None;
    let mut interval_secs = DEFAULT_INTERVAL_SECS;
    let mut watch = false;
    let mut probe = false;
    let mut values = args.into_iter();
    while let Some(raw) = values.next() {
        let token = raw
            .into_string()
            .map_err(|_| "arguments must be UTF-8".to_owned())?;
        match token.as_str() {
            "--help" | "-h" => return Ok(None),
            "--watch" if !watch => watch = true,
            "--probe" if !probe => probe = true,
            "--output" if output.is_none() => {
                let value = values
                    .next()
                    .ok_or("--output requires an absolute path")?;
                let path = PathBuf::from(value);
                if !path.is_absolute() {
                    return Err("--output must be an absolute path".to_owned());
                }
                output = Some(path);
            }
            "--interval-seconds" => {
                let value = values
                    .next()
                    .ok_or("--interval-seconds requires a number")?
                    .into_string()
                    .map_err(|_| "interval must be UTF-8".to_owned())?;
                interval_secs = value.parse::<u64>().map_err(|_| "invalid interval")?;
                if !(MIN_INTERVAL_SECS..=MAX_INTERVAL_SECS).contains(&interval_secs) {
                    return Err(format!("interval must be {MIN_INTERVAL_SECS}-{MAX_INTERVAL_SECS} seconds"));
                }
            }
            _ => return Err(format!("unrecognised argument: {token}")),
        }
    }
    let output = match output {
        Some(path) => path,
        None => {
            let home = env::var_os("HOME").ok_or("HOME is not set; pass --output")?;
            let home = PathBuf::from(home);
            if !home.is_absolute() {
                return Err("HOME must be absolute".to_owned());
            }
            home.join(".huntsman").join("api-key-health.json")
        }
    };
    Ok(Some(Options { output, probe, watch, interval_secs }))
}

fn run() -> Result<(), String> {
    let opts = match parse_args(env::args_os().skip(1))? {
        None => {
            println!("huntsman-key-health [--output /absolute/path.json] [--probe] [--watch] [--interval-seconds 1800]");
            println!("By default: one key-PRESENCE snapshot; --probe validates supported providers, potentially consuming quota; --watch refreshes while this process is alive.");
            return Ok(());
        }
        Some(opts) => opts,
    };
    loop {
        match refresh(opts.probe, &opts.output, opts.interval_secs) {
            Ok(report) => println!(
                "credential_health_updated={} providers={} configured={} authenticated_probe_success={} probe_requested={}",
                report.observed_at_unix,
                report.provider_count,
                report.configured_provider_count,
                report.authenticated_probe_success_count,
                report.probe_requested
            ),
            Err(error) => {
                eprintln!("credential health refresh failed: {error}");
                if !opts.watch {
                    return Err(error);
                }
            }
        }
        if !opts.watch {
            return Ok(());
        }
        thread::sleep(Duration::from_secs(opts.interval_secs));
    }
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("huntsman-key-health: {error}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_key_never_claims_functional() {
        let keys = Keys::default();
        let status = assemble(provider_credentials::status(&keys), None, &keys, 123, false, DEFAULT_INTERVAL_SECS);
        assert_eq!(status.authenticated_probe_success_count, 0);
        assert!(status.providers.iter().all(|p| !p.authenticated_probe_success));
    }

    #[test]
    fn configured_without_probe_is_not_a_success_or_runtime_use() {
        let slot = provider_credentials::PROVIDERS[0].slots[0];
        let secret = "do-not-expose-api-secret-for-test";
        let keys = Keys::parse(&format!("{slot}={secret}")).unwrap();
        let report = assemble(provider_credentials::status(&keys), None, &keys, 124, false, DEFAULT_INTERVAL_SECS);
        assert_eq!(report.authenticated_probe_success_count, 0);
        assert!(report.providers.iter().all(|p| !p.runtime_use_verified));
        assert!(!serde_json::to_string(&report).unwrap().contains(secret));
        assert!(report.providers.iter().any(|p| p.configured));
    }

    #[test]
    fn key_presence_and_probe_verdict_are_different_facts() {
        let slot = provider_credentials::PROVIDERS[0].slots[0];
        let keys = Keys::parse(&format!("{slot}=dummy-key")).unwrap();
        let status = provider_credentials::status(&keys);
        let configured = status.iter().find(|p| p.name == provider_credentials::PROVIDERS[0].name).unwrap().clone();
        let no_probe = row(configured.clone(), None);
        assert!(!no_probe.authenticated_probe_success);
        let rejection = row(configured.clone(), Some(ProbeState::Rejected));
        assert!(!rejection.authenticated_probe_success);
        let validation = row(configured, Some(ProbeState::Valid));
        assert!(validation.authenticated_probe_success);
        assert_eq!(validation.health, "authenticated_probe_success");
    }

    #[test]
    fn refresh_interval_cannot_be_abusive() {
        let args = [OsString::from("--interval-seconds"), OsString::from("1")];
        assert!(parse_args(args).is_err());
    }
}