//! Rootless passive MITM Wi-Fi audit adapter.
//!
//! Separate opt-in baseline enrollment from observational assessment.
//! The user owns the trust decision: never silently trust the first AP seen.

use std::fs::OpenOptions;
use std::io::Write as _;
use std::path::Path;
use std::process::ExitCode;

use super::fail;
use huntsman_recon::exit::{EX_DATAERR, EX_NOINPUT, EX_UNAVAILABLE, EX_USAGE};
use huntsman_recon::fsio::read_bounded;
use huntsman_recon::mitm::{TrustedBaseline, assess};
use huntsman_recon::wifi_radar::{self, MAX_SCAN_BYTES, WifiScan};

pub(super) const MITM_HELP: &str = "\
mitm baseline SSID --file SCAN.json --output BASELINE.json --confirmed
mitm assess --baseline BASELINE.json [--file SCAN.json]

A passive Wi-Fi security audit. Requires independent confirmation of the
network's authorised BSSIDs and security BEFORE creating a baseline.
The --confirmed switch records operator confirmation; it cannot verify ownership.
Assessment reads Android's OS-cached Wi-Fi results via Termux:API unless --file
supplies a captured termux-wifi-scaninfo JSON array. Replay does NOT prove
freshness. JSON output separates findings from limitations. No root, API keys,
active probing, automatic disconnect, or OS network modification.

No result from this command establishes an active MITM. For suspicious Wi-Fi,
avoid joining unknown access points, compare BSSID/security with the trusted
router administration interface, and use cellular data until independently
verified. ARP/DNS/TLS and mobile-network MITM are outside this sensor's scope.";

const MAX_BASELINE_BYTES: u64 = 32 * 1024;

/// Parse key/value arguments without silently accepting repeated/unknown flags.
fn path_options(
    args: &[String],
    allow_confirm: bool,
) -> Result<(Option<&str>, Option<&str>, bool), String> {
    let mut file = None;
    let mut output = None;
    let mut confirmed = false;
    let mut words = args.iter();
    while let Some(word) = words.next() {
        match word.as_str() {
            "--file" if file.is_none() => {
                file = Some(
                    words
                        .next()
                        .filter(|s| !s.starts_with("--"))
                        .ok_or("missing --file path")?
                        .as_str(),
                );
            }
            "--output" if output.is_none() => {
                output = Some(
                    words
                        .next()
                        .filter(|s| !s.starts_with("--"))
                        .ok_or("missing --output path")?
                        .as_str(),
                );
            }
            "--confirmed" if allow_confirm && !confirmed => confirmed = true,
            _ => return Err(format!("unexpected or repeated option: {word}")),
        }
    }
    Ok((file, output, confirmed))
}

fn scan_from_file(path: &str) -> Result<WifiScan, String> {
    let raw = read_bounded(Path::new(path), MAX_SCAN_BYTES).map_err(|e| e.to_string())?;
    wifi_radar::parse_replay(&raw).map_err(|e| e.to_string())
}

pub(super) fn mitm_cmd(args: &[String]) -> ExitCode {
    match args.first().map(String::as_str) {
        Some("baseline") => baseline_cmd(&args[1..]),
        Some("assess") => assess_cmd(&args[1..]),
        _ => fail(EX_USAGE, MITM_HELP),
    }
}

fn baseline_cmd(args: &[String]) -> ExitCode {
    let Some(ssid) = args.first().filter(|s| !s.starts_with("--")) else {
        return fail(EX_USAGE, MITM_HELP);
    };
    let (Some(file), Some(output), true) = (match path_options(&args[1..], true) {
        Ok(options) => options,
        Err(message) => return fail(EX_USAGE, &message),
    }) else {
        return fail(
            EX_USAGE,
            "baseline requires --file, --output and --confirmed",
        );
    };
    let scan = match scan_from_file(file) {
        Ok(scan) => scan,
        Err(message) => return fail(EX_NOINPUT, &message),
    };
    let baseline = match TrustedBaseline::enroll(&scan, ssid) {
        Ok(baseline) => baseline,
        Err(message) => return fail(EX_DATAERR, &message),
    };
    let encoded = match serde_json::to_vec_pretty(&baseline) {
        Ok(encoded) => encoded,
        Err(error) => return fail(EX_DATAERR, &error.to_string()),
    };
    // Fail closed if a baseline already exists, including if the path is a symlink.
    // Retaining the original is more important than a silent "update."
    let mut out = match OpenOptions::new().write(true).create_new(true).open(output) {
        Ok(out) => out,
        Err(error) => return fail(EX_NOINPUT, &format!("cannot create new baseline: {error}")),
    };
    if let Err(error) = out.write_all(&encoded).and_then(|()| out.write_all(b"\n")) {
        let _ = std::fs::remove_file(output);
        return fail(EX_UNAVAILABLE, &format!("cannot write baseline: {error}"));
    }
    println!(
        "saved verified-by-operator baseline for {ssid:?} ({} BSSIDs)",
        baseline.anchors.len()
    );
    ExitCode::SUCCESS
}

fn assess_cmd(args: &[String]) -> ExitCode {
    let mut baseline_path = None;
    let mut file_path = None;
    let mut words = args.iter();
    while let Some(word) = words.next() {
        match word.as_str() {
            "--baseline" if baseline_path.is_none() => {
                baseline_path = words
                    .next()
                    .filter(|s| !s.starts_with("--"))
                    .map(String::as_str);
                if baseline_path.is_none() {
                    return fail(EX_USAGE, "missing --baseline path");
                }
            }
            "--file" if file_path.is_none() => {
                file_path = words
                    .next()
                    .filter(|s| !s.starts_with("--"))
                    .map(String::as_str);
                if file_path.is_none() {
                    return fail(EX_USAGE, "missing --file path");
                }
            }
            _ => return fail(EX_USAGE, MITM_HELP),
        }
    }
    let Some(baseline_path) = baseline_path else {
        return fail(EX_USAGE, MITM_HELP);
    };
    let bytes = match read_bounded(Path::new(baseline_path), MAX_BASELINE_BYTES) {
        Ok(bytes) => bytes,
        Err(error) => return fail(EX_NOINPUT, &error.to_string()),
    };
    let baseline: TrustedBaseline = match serde_json::from_slice(&bytes) {
        Ok(value) => value,
        Err(error) => return fail(EX_DATAERR, &format!("invalid baseline JSON: {error}")),
    };
    if let Err(error) = baseline.validate() {
        return fail(EX_DATAERR, &error);
    }
    let scan = match file_path {
        Some(path) => scan_from_file(path),
        None => super::radar::capture_wifi(),
    };
    let scan = match scan {
        Ok(scan) => scan,
        Err(message) => return fail(EX_UNAVAILABLE, &message),
    };
    let report = match assess(&scan, &baseline) {
        Ok(report) => report,
        Err(message) => return fail(EX_DATAERR, &message),
    };
    match serde_json::to_string_pretty(&report) {
        Ok(json) => {
            println!("{json}");
            ExitCode::SUCCESS
        }
        Err(error) => fail(EX_DATAERR, &error.to_string()),
    }
}
