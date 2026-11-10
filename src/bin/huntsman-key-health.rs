//! Native Rust credential-health register, not a credential generator or vault.
//! One report replaces the previous report atomically, while actual key files
//! and credentials remain untouched. Probes are opt-in and can spend quota.

use std::env;
use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::thread;
use std::time::Duration;

use huntsman_recon::clock;
use huntsman_recon::fsio;
use huntsman_recon::http::{TransportConfig, UreqTransport};
use huntsman_recon::keys::Keys;
use huntsman_recon::provider_credentials::{self, ProviderProbeStatus, ProviderStatus};
use serde::Serialize;

const MAX_REPORT_BYTES: u64 = 512 * 1024;
const DEFAULT_INTERVAL: u64 = 1800;

#[derive(Clone, Debug)]
struct Options {
    path: PathBuf,
    interval: u64,
    watch: bool,
    probe: bool,
}

#[derive(Serialize)]
struct Slot {
    name: &'static str,
    configured: bool,
}

#[derive(Serialize)]
struct ProviderRow {
    provider: &'static str,
    configured: bool,
    slots: Vec<Slot>,
    probe_response: &'static str,
    /// A shape-valid free response is not always proof of authentication.
    authentication_verified: bool,
    source_execution_verified: bool,
}

#[derive(Serialize)]
struct Report {
    schema_version: u32,
    observed_at_unix: u64,
    stale_after_unix: u64,
    expected_refresh_interval_seconds: u64,
    mode: &'static str,
    configured_provider_count: usize,
    valid_probe_response_count: usize,
    authentication_verified_count: usize,
    source_execution_verified_count: usize,
    warning_loading_credentials: bool,
    unrecognised_slot_names: Vec<String>,
    providers: Vec<ProviderRow>,
}

fn make_report(
    statuses: Vec<ProviderStatus>,
    probes: Option<Vec<ProviderProbeStatus>>,
    keys: &Keys,
    now: u64,
    interval: u64,
    warning: bool,
) -> Report {
    let providers: Vec<ProviderRow> = statuses
        .into_iter()
        .map(|provider| {
            let probe_response = probes
                .as_ref()
                .and_then(|list| list.iter().find(|p| p.provider.name == provider.name))
                .map_or("not_checked", |entry| entry.probe.as_str());
            ProviderRow {
                provider: provider.name,
                configured: provider.configured,
                slots: provider
                    .slots
                    .into_iter()
                    .map(|slot| Slot {
                        name: slot.slot,
                        configured: slot.configured,
                    })
                    .collect(),
                probe_response,
                authentication_verified: false,
                source_execution_verified: false,
            }
        })
        .collect();
    Report {
        schema_version: 1,
        observed_at_unix: now,
        stale_after_unix: now.saturating_add(interval).saturating_add(60),
        expected_refresh_interval_seconds: interval,
        mode: if probes.is_some() { "opt_in_probe" } else { "offline_presence" },
        configured_provider_count: providers.iter().filter(|p| p.configured).count(),
        valid_probe_response_count: providers
            .iter()
            .filter(|p| p.configured && p.probe_response == "valid")
            .count(),
        authentication_verified_count: 0,
        source_execution_verified_count: 0,
        warning_loading_credentials: warning,
        unrecognised_slot_names: provider_credentials::unrecognised_slots(keys)
            .iter()
            .map(|slot| (*slot).to_owned())
            .collect(),
        providers,
    }
}

fn private_parent(parent: &Path) -> Result<(), String> {
    if !parent.is_absolute() {
        return Err("report parent must be an absolute directory".into());
    }
    if !parent.exists() {
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(parent)
                .map_err(|_| "cannot create private report directory")?;
        }
        #[cfg(not(unix))]
        fs::create_dir_all(parent).map_err(|_| "cannot create report directory")?;
    }
    let meta = fs::symlink_metadata(parent).map_err(|_| "cannot inspect report directory")?;
    if !meta.is_dir() || meta.file_type().is_symlink() {
        return Err("report directory must not be a symlink".into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if meta.permissions().mode() & 0o077 != 0 {
            return Err("report directory is accessible to another user".into());
        }
    }
    Ok(())
}

fn refresh(opts: &Options) -> Result<Report, String> {
    let home = env::var_os("HOME");
    let resolved = Keys::for_lookup(home.as_deref());
    let statuses = provider_credentials::status(&resolved.keys);
    let probed = if opts.probe {
        let transport = UreqTransport::new(&TransportConfig::default());
        Some(provider_credentials::probe(&resolved.keys, &transport))
    } else {
        None
    };
    let report = make_report(
        statuses, probed, &resolved.keys, clock::unix_now(),
        opts.interval, resolved.warning.is_some(),
    );
    let bytes = serde_json::to_vec_pretty(&report)
        .map_err(|_| "cannot serialize credential status")?;
    let parent = opts.path.parent().ok_or("report path needs a parent")?;
    private_parent(parent)?;
    fsio::write_atomic_private_locked(&opts.path, &bytes, MAX_REPORT_BYTES)
        .map_err(|_| "private atomic report write failed; previous report remains")?;
    Ok(report)
}

fn parse(args: impl IntoIterator<Item = OsString>) -> Result<Option<Options>, String> {
    let mut output = None;
    let mut interval = DEFAULT_INTERVAL;
    let mut watch = false;
    let mut probe = false;
    let mut items = args.into_iter();
    while let Some(arg) = items.next() {
        let arg = arg.into_string().map_err(|_| "arguments must be valid UTF-8")?;
        match arg.as_str() {
            "-h" | "--help" => return Ok(None),
            "--watch" if !watch => watch = true,
            "--probe" if !probe => probe = true,
            "--interval-seconds" => {
                let value = items.next().ok_or("missing interval")?;
                interval = value
                    .into_string().map_err(|_| "invalid interval")?
                    .parse::<u64>().map_err(|_| "invalid interval")?;
                if !(60..=86_400).contains(&interval) {
                    return Err("interval must be between 60 and 86400 seconds".into());
                }
            }
            "--output" if output.is_none() => {
                let value = items.next().ok_or("missing output path")?;
                let path = PathBuf::from(value);
                if !path.is_absolute() {
                    return Err("output path must be absolute".into());
                }
                output = Some(path);
            }
            _ => return Err("unrecognised or duplicate option".into()),
        }
    }
    let path = match output {
        Some(path) => path,
        None => {
            let home = PathBuf::from(env::var_os("HOME").ok_or("HOME is unset")?);
            if !home.is_absolute() {
                return Err("HOME must be absolute".into());
            }
            home.join(".huntsman").join("api-key-health.json")
        }
    };
    Ok(Some(Options { path, interval, watch, probe }))
}

fn run() -> Result<(), String> {
    let Some(opts) = parse(env::args_os().skip(1))? else {
        println!("huntsman-key-health [--watch] [--probe] [--interval-seconds 1800] [--output /absolute/path.json]");
        return Ok(());
    };
    loop {
        match refresh(&opts) {
            Ok(report) => println!(
                "credential_health_updated={} configured={} valid_probe_responses={} auth_verified={} scan_use_verified={}",
                report.observed_at_unix, report.configured_provider_count,
                report.valid_probe_response_count,
                report.authentication_verified_count, report.source_execution_verified_count
            ),
            Err(err) if !opts.watch => return Err(err),
            Err(err) => eprintln!("credential_health_refresh_error={err}"),
        }
        if !opts.watch {
            return Ok(());
        }
        thread::sleep(Duration::from_secs(opts.interval));
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
    fn a_configured_key_without_a_verified_search_is_not_validated() {
        let key_value = "unique-private-fixture-secret";
        let slot = provider_credentials::PROVIDERS[0].slots[0];
        let keys = Keys::parse(&format!("{slot}={key_value}")).expect("valid fixture");
        let report = make_report(
            provider_credentials::status(&keys), None, &keys, 111, 1800, false
        );
        let json = serde_json::to_string(&report).expect("json");
        assert!(!json.contains(key_value));
        assert_eq!(report.authentication_verified_count, 0);
        assert_eq!(report.source_execution_verified_count, 0);
        assert_eq!(report.valid_probe_response_count, 0);
        assert!(report.configured_provider_count > 0);
        assert_eq!(report.stale_after_unix, 1971);
    }
    #[test]
    fn a_short_refresh_is_rejected() {
        assert!(parse([OsString::from("--interval-seconds"), OsString::from("1")]).is_err());
    }
    #[test]
    fn relative_output_is_rejected() {
        assert!(parse([OsString::from("--output"), OsString::from("health.json")]).is_err());
    }
}
