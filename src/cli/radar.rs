//! Termux Wi-Fi observations: no root, no active radio scans, bounded JSON IO.

use std::io::Read as _;
use std::path::Path;
use std::process::{Command, ExitCode, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::{self, RecvTimeoutError};
use std::thread;
use std::time::{Duration, Instant};

use super::{fail, terminal_json_pretty};
use huntsman_recon::cell_radar;
use huntsman_recon::exit::{EX_DATAERR, EX_NOINPUT, EX_UNAVAILABLE, EX_USAGE};
use huntsman_recon::fsio::read_bounded;
use huntsman_recon::radar::{self, LoggedDevice, LoggedSweep, MAX_TRACK_LOG_BYTES};
use huntsman_recon::wifi_radar::{self, MAX_SCAN_BYTES};

const USAGE: &str = "usage: huntsman-recon radar wifi|cells [--json] [--file TERMUX_SCAN_JSON] | radar track [--json] [--wifi-file FILE] [--cells-file FILE] [--log FILE]";

/// A misbehaving descendant can keep a sensor stdout pipe open after the
/// direct child exits. Bound detached drainers to avoid exhausting a server.
const MAX_ACTIVE_READERS: usize = 4;
static ACTIVE_READERS: AtomicUsize = AtomicUsize::new(0);

struct ReaderSlot;

impl Drop for ReaderSlot {
    fn drop(&mut self) {
        ACTIVE_READERS.fetch_sub(1, Ordering::AcqRel);
    }
}

/// Reserve a drainer without temporarily exceeding the process-wide cap.
/// The CAS loop works on the supported minimum Rust toolchain.
fn reserve_reader_slot() -> bool {
    let mut active = ACTIVE_READERS.load(Ordering::Acquire);
    loop {
        if active >= MAX_ACTIVE_READERS {
            return false;
        }
        match ACTIVE_READERS.compare_exchange_weak(
            active,
            active + 1,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => return true,
            Err(current) => active = current,
        }
    }
}

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
    // Reserving before spawning bounds the threads that could be stranded
    // by inherited stdout descriptors in buggy Termux:API descendants.
    if !reserve_reader_slot() {
        let _ = child.kill();
        let _ = child.wait();
        return Err("Termux sensor output reader limit reached".into());
    }
    let (sender, receiver) = mpsc::sync_channel(1);
    let reader = thread::Builder::new()
        .name("termux-radio-stdout".into())
        .spawn(move || {
            let _slot = ReaderSlot;
            let mut data = Vec::new();
            let result = stdout
                .take(MAX_SCAN_BYTES + 1)
                .read_to_end(&mut data)
                .map(|_| data);
            let _ = sender.send(result);
        });
    if let Err(error) = reader {
        ACTIVE_READERS.fetch_sub(1, Ordering::AcqRel);
        let _ = child.kill();
        let _ = child.wait();
        return Err(format!("cannot start Termux sensor stdout reader: {error}"));
    }
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
    let status = status?;
    if !status.success() {
        return Err(format!(
            "{command} exited with {status}; check the matching Termux:API Android app, permissions and Android location services"
        ));
    }
    // A child may have exited successfully while a grandchild still holds
    // the pipe's write end. Never join a blocking reader without a deadline.
    let data = match receiver.recv_timeout(Duration::from_secs(2)) {
        Ok(result) => result.map_err(|e| format!("cannot read Termux sensor output: {e}"))?,
        Err(RecvTimeoutError::Timeout) => {
            return Err("Termux sensor stdout was not closed after its process exited".into());
        }
        Err(RecvTimeoutError::Disconnected) => {
            return Err("Termux sensor output reader failed".into());
        }
    };
    if usize::try_from(MAX_SCAN_BYTES).is_ok_and(|limit| data.len() > limit) {
        return Err("Termux sensor output exceeds 1 MiB".into());
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

/// The options both radar sources take: `--json` for the report, and `--file PATH` to replay a
/// saved scan instead of reading this device.
struct RadarOptions<'a> {
    json: bool,
    file: Option<&'a str>,
}

/// Parse `[--json] [--file PATH]`, where the path is not another flag. `None` is a usage error.
fn radar_options(args: &[String]) -> Option<RadarOptions<'_>> {
    let mut options = RadarOptions {
        json: false,
        file: None,
    };
    let mut rest = args.iter();
    while let Some(arg) = rest.next() {
        match arg.as_str() {
            "--json" if !options.json => options.json = true,
            "--file" if options.file.is_none() => {
                options.file = Some(rest.next().filter(|path| !path.starts_with("--"))?.as_str());
            }
            _ => return None,
        }
    }
    Some(options)
}

/// The scan to parse: the `--file` replay, read within `cap` bytes, or else this device's own
/// collection. The flag is `true` for a replay. An error is the exit status to stop with.
fn scan_input(
    file: Option<&str>,
    cap: u64,
    collect: impl FnOnce() -> Result<Vec<u8>, String>,
) -> Result<(Vec<u8>, bool), ExitCode> {
    match file {
        Some(path) => match read_bounded(Path::new(path), cap) {
            Ok(raw) => Ok((raw, true)),
            Err(error) => Err(fail(EX_NOINPUT, &error.to_string())),
        },
        None => match collect() {
            Ok(raw) => Ok((raw, false)),
            Err(error) => Err(fail(EX_UNAVAILABLE, &error)),
        },
    }
}

/// Print `parsed` as pretty JSON when `json` is set, otherwise as its text render. A report that
/// does not serialise is a data error, returned as the exit status to stop with.
fn print_report<T: serde::Serialize>(
    parsed: &T,
    json: bool,
    render: fn(&T) -> String,
) -> Result<(), ExitCode> {
    if !json {
        print!("{}", render(parsed));
        return Ok(());
    }
    match terminal_json_pretty(parsed) {
        Ok(output) => {
            println!("{output}");
            Ok(())
        }
        Err(error) => Err(fail(EX_DATAERR, &error.to_string())),
    }
}

pub(super) fn radar_cmd(args: &[String]) -> ExitCode {
    if args.first().map(String::as_str) == Some("cells") {
        return cells_cmd(&args[1..]);
    }
    if args.first().map(String::as_str) == Some("track") {
        return track_cmd(&args[1..]);
    }
    if args.first().map(String::as_str) != Some("wifi") {
        return fail(EX_USAGE, USAGE);
    }
    let Some(options) = radar_options(&args[1..]) else {
        return fail(EX_USAGE, USAGE);
    };
    let (raw, replay) = match scan_input(options.file, MAX_SCAN_BYTES, collect_termux_wifi) {
        Ok(input) => input,
        Err(code) => return code,
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
    if let Err(code) = print_report(&parsed, options.json, wifi_radar::render) {
        return code;
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
    let Some(options) = radar_options(args) else {
        return fail(EX_USAGE, USAGE);
    };
    let (raw, replay) = match scan_input(
        options.file,
        cell_radar::MAX_CELL_SCAN_BYTES,
        collect_termux_cells,
    ) {
        Ok(input) => input,
        Err(code) => return code,
    };
    let result = if replay {
        cell_radar::parse_replay(&raw)
    } else {
        cell_radar::parse_cells(&raw)
    };
    let parsed = match result {
        Ok(parsed) => parsed,
        Err(error) => return fail(EX_DATAERR, &error.to_string()),
    };
    if let Err(code) = print_report(&parsed, options.json, cell_radar::render) {
        return code;
    }
    if parsed.status == "inconclusive" {
        ExitCode::from(EX_UNAVAILABLE)
    } else {
        ExitCode::SUCCESS
    }
}

/// `radar track`'s options: `--json`, replays of a Wi-Fi and a cell scan in place of this
/// device's, and the log to keep the sweeps in.
#[derive(Default)]
struct TrackOptions<'a> {
    json: bool,
    wifi_file: Option<&'a str>,
    cells_file: Option<&'a str>,
    log: Option<&'a str>,
}

fn track_options(args: &[String]) -> Option<TrackOptions<'_>> {
    let mut options = TrackOptions::default();
    let mut rest = args.iter();
    while let Some(arg) = rest.next() {
        let slot = match arg.as_str() {
            "--json" if !options.json => {
                options.json = true;
                continue;
            }
            "--wifi-file" => &mut options.wifi_file,
            "--cells-file" => &mut options.cells_file,
            "--log" => &mut options.log,
            _ => return None,
        };
        if slot.is_some() {
            return None;
        }
        *slot = Some(
            rest.next()
                .filter(|value| !value.starts_with("--"))?
                .as_str(),
        );
    }
    Some(options)
}

/// The place a cell scan says the phone is: its registered serving cell, as an opaque bucket.
/// `None` when the phone is registered to none, so the sweep is kept but not placed.
fn serving_cell(scan: &cell_radar::CellScan) -> Option<String> {
    scan.observations
        .iter()
        .find(|cell| cell.registered == Some(true))
        .map(|cell| {
            format!(
                "{}:{}-{}-{}-{}",
                cell.technology,
                cell.mcc.as_deref().unwrap_or("?"),
                cell.mnc.as_deref().unwrap_or("?"),
                cell.area_code,
                cell.cell_id
            )
        })
}

/// Take one Wi-Fi sweep, place it at the serving cell, add it to the track log and report what
/// the log shows: devices that keep recurring, and devices seen across several of the
/// operator's places (a personal-safety signal that something moved with them). The log is
/// private to the user and keeps the newest [`radar::MAX_TRACK_SWEEPS`] sweeps.
fn track_cmd(args: &[String]) -> ExitCode {
    let Some(options) = track_options(args) else {
        return fail(EX_USAGE, USAGE);
    };
    let Some(log) = options
        .log
        .map(std::path::PathBuf::from)
        .or_else(super::scans::default_radar_log)
    else {
        return fail(
            EX_USAGE,
            "radar track: no log; set HUNTSMAN_HOME or HOME, or pass --log FILE",
        );
    };
    let (raw, replay) = match scan_input(options.wifi_file, MAX_SCAN_BYTES, collect_termux_wifi) {
        Ok(input) => input,
        Err(code) => return code,
    };
    let wifi = if replay {
        wifi_radar::parse_replay(&raw)
    } else {
        wifi_radar::parse_scan(&raw, uptime_secs())
    };
    let wifi = match wifi {
        Ok(wifi) => wifi,
        Err(error) => return fail(EX_DATAERR, &error.to_string()),
    };
    // An empty or wholly stale cache says nothing about what is here now, and a sweep logged
    // from it would read as the operator having heard nothing.
    if matches!(wifi.status, "inconclusive" | "stale_only") {
        return fail(
            EX_UNAVAILABLE,
            &format!(
                "radar track: the Wi-Fi scan is {}; nothing was logged",
                wifi.status
            ),
        );
    }
    // A sweep without its place still counts towards recurrence, so a cell scan Android
    // withholds is noted and the sweep kept; a replay that cannot be read is an error.
    let cell = match options.cells_file {
        Some(path) => {
            let parsed = read_bounded(Path::new(path), cell_radar::MAX_CELL_SCAN_BYTES)
                .map_err(|error| (EX_NOINPUT, error.to_string()))
                .and_then(|raw| {
                    cell_radar::parse_replay(&raw).map_err(|error| (EX_DATAERR, error.to_string()))
                });
            match parsed {
                Ok(scan) => serving_cell(&scan),
                Err((code, error)) => return fail(code, &error),
            }
        }
        None => match collect_termux_cells()
            .and_then(|raw| cell_radar::parse_cells(&raw).map_err(|error| error.to_string()))
        {
            Ok(scan) => serving_cell(&scan),
            Err(error) => {
                eprintln!("radar track: no serving cell, so this sweep is not placed: {error}");
                None
            }
        },
    };
    let sweep = LoggedSweep::new(
        huntsman_recon::clock::unix_now(),
        cell,
        wifi.observations
            .iter()
            .filter(|observation| observation.freshness != "stale")
            .map(|observation| LoggedDevice {
                mac: observation.sighting.network_id.clone(),
                name: observation.sighting.name.clone(),
            }),
    );
    let existing = match std::fs::symlink_metadata(&log) {
        Ok(_) => match read_bounded(&log, MAX_TRACK_LOG_BYTES) {
            Ok(bytes) => bytes,
            Err(error) => return fail(EX_DATAERR, &format!("radar track: {error}")),
        },
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Vec::new(),
        Err(error) => return fail(EX_NOINPUT, &format!("{}: {error}", log.display())),
    };
    let (mut sweeps, skipped) = radar::parse_track_log(&existing);
    let bytes = radar::append_track_log(sweeps.clone(), sweep.clone());
    if let Err(error) = private_parent(&log).and_then(|()| {
        huntsman_recon::fsio::write_atomic_private(&log, &bytes, MAX_TRACK_LOG_BYTES)
            .map_err(|error| error.to_string())
    }) {
        return fail(EX_UNAVAILABLE, &format!("radar track: {error}"));
    }
    sweeps.push(sweep);
    let report = radar::track(
        &sweeps[sweeps.len().saturating_sub(radar::MAX_TRACK_SWEEPS)..],
        skipped,
    );
    match print_report(&report, options.json, render_track) {
        Ok(()) => ExitCode::SUCCESS,
        Err(code) => code,
    }
}

/// Create the log's directory when it is missing, private to the user.
fn private_parent(log: &Path) -> Result<(), String> {
    let Some(parent) = log.parent().filter(|parent| !parent.as_os_str().is_empty()) else {
        return Ok(());
    };
    if parent.is_dir() {
        return Ok(());
    }
    std::fs::create_dir_all(parent).map_err(|error| format!("{}: {error}", parent.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700))
            .map_err(|error| format!("{}: {error}", parent.display()))?;
    }
    Ok(())
}

/// A track report as tab-separated text: a summary line, then each follower and each recurring
/// device. Names are a third party's text, so control characters in them are escaped.
fn render_track(report: &radar::TrackReport) -> String {
    use std::fmt::Write as _;
    let mut out = format!(
        "track\tsweeps={}\tlocated={}\tcells={}\tfollowers={}\trecurring={}\tskipped_lines={}\n",
        report.sweeps,
        report.located_sweeps,
        report.distinct_cells,
        report.followers.len(),
        report.recurring.len(),
        report.skipped_lines
    );
    for follower in &report.followers {
        let _ = writeln!(
            out,
            "follower\tbssid={}\tvendor={}\tcells={}\tcoverage={:.2}\tsightings={}\tspan_secs={}",
            follower.mac,
            follower.vendor.as_deref().unwrap_or("unknown"),
            follower.distinct_cells,
            follower.coverage,
            follower.sightings,
            follower.span_secs
        );
    }
    for device in &report.recurring {
        let name = device
            .name
            .as_deref()
            .map(huntsman_recon::textnorm::escape_controls)
            .unwrap_or_default();
        let _ = writeln!(
            out,
            "recurring\tbssid={}\tssid={}\tvendor={}\tsweeps={}\tfirst_ts={}\tlast_ts={}",
            device.mac,
            name,
            device.vendor.as_deref().unwrap_or("unknown"),
            device.sweeps_seen,
            device.first_ts,
            device.last_ts
        );
    }
    out
}
