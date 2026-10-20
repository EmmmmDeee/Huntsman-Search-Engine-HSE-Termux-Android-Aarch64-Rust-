//! Termux Wi-Fi observations: no root, no active radio scans, bounded JSON IO.

use std::io::Read as _;
use std::path::Path;
use std::process::{Command, ExitCode, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use super::fail;
use huntsman_recon::cell_radar;
use huntsman_recon::exit::{EX_DATAERR, EX_NOINPUT, EX_UNAVAILABLE, EX_USAGE};
use huntsman_recon::fsio::read_bounded;
use huntsman_recon::wifi_radar::{self, MAX_SCAN_BYTES};

const USAGE: &str = "usage: huntsman-recon radar wifi|cells [--json] [--file TERMUX_SCAN_JSON]";

fn uptime_secs() -> Option<f64> {
    let data = read_bounded(Path::new("/proc/uptime"), 128).ok()?;
    let first = std::str::from_utf8(&data).ok()?.split_whitespace().next()?;
    let seconds = first.parse::<f64>().ok()?;
    (seconds.is_finite() && seconds >= 0.0).then_some(seconds)
}

/// Collect real Android cached scan results. An independent reader drains the
/// pipe while the child runs, so a full stdout pipe cannot deadlock the child.
/// The watchdog bounds hanging plugin calls; oversized JSON is refused.
fn collect_termux_radio(command: &str) -> Result<Vec<u8>, String> {
    let mut child = Command::new(command)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| format!(
            "cannot launch {command} ({e}); install pkg termux-api and the matching Termux:API Android app, then grant the required permissions"
        ))?;
    let Some(stdout) = child.stdout.take() else {
        let _ = child.kill();
        let _ = child.wait();
        return Err("Termux Wi-Fi stdout unavailable".into());
    };
    let reader = thread::spawn(move || {
        let mut data = Vec::new();
        stdout
            .take(MAX_SCAN_BYTES + 1)
            .read_to_end(&mut data)
            .map(|_| data)
    });
    let started = Instant::now();
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Ok(status),
            Ok(None) if started.elapsed() < Duration::from_secs(15) => {
                thread::sleep(Duration::from_millis(50));
            }
            Ok(None) => {
                let _ = child.kill();
                let _ = child.wait();
                break Err("Termux Wi-Fi scan-result request timed out".to_owned());
            }
            Err(e) => {
                let _ = child.kill();
                let _ = child.wait();
                break Err(format!("Termux Wi-Fi scan-result request failed: {e}"));
            }
        }
    };
    let data = reader
        .join()
        .map_err(|_| "Termux Wi-Fi output reader failed".to_owned())?
        .map_err(|e| format!("cannot read Termux Wi-Fi output: {e}"))?;
    let status = status?;
    if !status.success() {
        return Err(format!(
            "{command} exited with {status}; check the matching Termux:API Android app, permissions and Android location services"
        ));
    }
    if usize::try_from(MAX_SCAN_BYTES).is_ok_and(|limit| data.len() > limit) {
        return Err("Termux Wi-Fi output exceeds 1 MiB".into());
    }
    Ok(data)
}

fn collect_termux_wifi() -> Result<Vec<u8>, String> {
    collect_termux_radio("termux-wifi-scaninfo")
}

/// The telephony API is rootless but may be restricted by Android's OS.
fn collect_termux_cells() -> Result<Vec<u8>, String> {
    collect_termux_radio("termux-telephony-cellinfo")
}

/// One OS-cached scan shared by the CLI and the mobile Web UI.
/// No root and no active scan. Missing Termux:API is an explicit error.
pub(super) fn capture_wifi() -> Result<wifi_radar::WifiScan, String> {
    let data = collect_termux_wifi()?;
    wifi_radar::parse_scan(&data, uptime_secs()).map_err(|e| e.to_string())
}

pub(super) fn radar_cmd(args: &[String]) -> ExitCode {
    if args.first().map(String::as_str) == Some("cells") {
        return cells_cmd(&args[1..]);
    }
    if args.first().map(String::as_str) != Some("wifi") {
        return fail(EX_USAGE, USAGE);
    }
    let mut json = false;
    let mut file = None;
    let mut rest = args[1..].iter();
    while let Some(arg) = rest.next() {
        match arg.as_str() {
            "--json" if !json => json = true,
            "--file" if file.is_none() => file = rest.next(),
            _ => return fail(EX_USAGE, USAGE),
        }
    }
    if args.iter().any(|arg| arg == "--file") && file.is_none() {
        return fail(EX_USAGE, USAGE);
    }
    let (raw, replay) = match file {
        Some(path) => match read_bounded(Path::new(path), MAX_SCAN_BYTES) {
            Ok(raw) => (raw, true),
            Err(e) => return fail(EX_NOINPUT, &e.to_string()),
        },
        None => match collect_termux_wifi() {
            Ok(raw) => (raw, false),
            Err(error) => return fail(EX_UNAVAILABLE, &error),
        },
    };
    // A replay file's boot-relative scan timestamps cannot be aged against
    // this host's /proc/uptime: file and host may not share the same boot.
    let result = if replay {
        wifi_radar::parse_replay(&raw)
    } else {
        wifi_radar::parse_scan(&raw, uptime_secs())
    };
    let parsed = match result {
        Ok(parsed) => parsed,
        Err(error) => return fail(EX_DATAERR, &error.to_string()),
    };
    if json {
        match serde_json::to_string_pretty(&parsed) {
            Ok(output) => println!("{output}"),
            Err(e) => return fail(EX_DATAERR, &e.to_string()),
        }
    } else {
        print!("{}", wifi_radar::render(&parsed));
    }
    // An empty OS cache or all-stale observations are not a clean zero and
    // cannot certify that nothing is present right now.
    if matches!(parsed.status, "inconclusive" | "stale_only") {
        ExitCode::from(EX_UNAVAILABLE)
    } else {
        ExitCode::SUCCESS
    }
}

fn cells_cmd(args: &[String]) -> ExitCode {
    let mut json = false;
    let mut file = None;
    let mut rest = args.iter();
    while let Some(arg) = rest.next() {
        match arg.as_str() {
            "--json" if !json => json = true,
            "--file" if file.is_none() => file = rest.next(),
            _ => return fail(EX_USAGE, USAGE),
        }
    }
    if args.iter().any(|arg| arg == "--file") && file.is_none() {
        return fail(EX_USAGE, USAGE);
    }
    let (raw, replay) = match file {
        Some(path) => match read_bounded(Path::new(path), cell_radar::MAX_CELL_SCAN_BYTES) {
            Ok(raw) => (raw, true),
            Err(error) => return fail(EX_NOINPUT, &error.to_string()),
        },
        None => match collect_termux_cells() {
            Ok(raw) => (raw, false),
            Err(error) => return fail(EX_UNAVAILABLE, &error),
        },
    };
    let parsed = match if replay {
        cell_radar::parse_replay(&raw)
    } else {
        cell_radar::parse_cells(&raw)
    } {
        Ok(parsed) => parsed,
        Err(error) => return fail(EX_DATAERR, &error.to_string()),
    };
    if json {
        match serde_json::to_string_pretty(&parsed) {
            Ok(output) => println!("{output}"),
            Err(error) => return fail(EX_DATAERR, &error.to_string()),
        }
    } else {
        print!("{}", cell_radar::render(&parsed));
    }
    if parsed.status == "inconclusive" {
        ExitCode::from(EX_UNAVAILABLE)
    } else {
        ExitCode::SUCCESS
    }
}
