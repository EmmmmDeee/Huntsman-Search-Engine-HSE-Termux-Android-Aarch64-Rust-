//! Operator-invoked, rootless Wi-Fi MITM/evil-twin assessment.
use std::collections::BTreeSet;
use std::fs::OpenOptions;
use std::io::Write as _;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::process::ExitCode;

use super::{fail, terminal_json_pretty};
use huntsman_recon::exit::{EX_DATAERR, EX_NOINPUT, EX_UNAVAILABLE, EX_USAGE};
use huntsman_recon::fsio::read_bounded;
use huntsman_recon::mitm_guard::{self, Baseline, Report};
use huntsman_recon::textnorm::escape_controls;
use huntsman_recon::wifi_radar;

pub(super) const USAGE: &str = "mitm audit [--file WIFI_JSON_OR_WIGLE_JSONL] [--baseline TRUSTED_JSON] [--json] [--require-evaluated]\nmitm baseline --ssid SSID --bssid MAC [--bssid MAC ...] --minimum-security OPEN|WEP|WPA|WPA2|WPA3 --output FILE --confirmed\nThe baseline command writes a private new file from independently verified operator input only; it never trusts a captured scan or overwrites an existing baseline. --confirmed records an operator assertion, not authentication.\nWithout --file, read the existing rootless Termux OS-cached Wi-Fi radar; offline --file accepts a Termux scan JSON array or Huntsman-normalized WiGLE JSONL. Baseline JSON format: {\"networks\":[{\"ssid\":\"Office\",\"bssids\":[\"3c:5a:b4:11:22:33\"],\"minimum_security\":\"WPA3\"}]}. This tool only reports unconfirmed indicators; it never forcibly disconnects networks. Remediation requires verifying the authorised access point and making manual Android network settings changes.";

fn print_text(report: &Report) {
    println!(
        "mitm\tsource={}\tstatus={}\taccess_points={}\trejected={}\tbaseline_supplied={}\tconfirmed={}",
        report.source,
        report.status,
        report.evaluated_access_points,
        report.rejected_records,
        report.trusted_baseline_supplied,
        report.mitm_confirmed
    );
    if let Some(e) = &report.eligibility {
        println!(
            "eligibility\tobserved={}\tstale={}\tunknown_freshness={}\tmissing_ssid={}\toversized_ssid={}\thidden_ssid={}\tinvalid_bssid={}\tduplicates={}\teligible={}",
            e.observed_records,
            e.excluded_stale,
            e.excluded_unknown_freshness,
            e.excluded_missing_ssid,
            e.excluded_oversized_ssid,
            e.excluded_hidden_ssid,
            e.excluded_invalid_bssid,
            e.duplicate_rows,
            e.eligible_access_points
        );
    }
    for finding in &report.findings {
        println!(
            "finding\tseverity={}\tcode={}\tssid={}\tbssid={}\tevidence={}\tresolution={}",
            finding.severity,
            finding.code,
            escape_controls(&finding.ssid),
            finding.bssid.as_deref().unwrap_or("none"),
            escape_controls(&finding.evidence),
            finding.resolution
        );
    }
    println!("limitation\t{}", report.capability_limit);
}

pub(super) fn mitm_cmd(args: &[String]) -> ExitCode {
    if args.first().map(String::as_str) == Some("baseline") {
        return baseline_cmd(&args[1..]);
    }
    if args.first().map(String::as_str) != Some("audit") {
        return fail(EX_USAGE, USAGE);
    }
    let mut file = None;
    let mut baseline_file = None;
    let mut json = false;
    // Optional strict exit semantics preserve legacy default behavior.
    let mut require_evaluated = false;
    let mut iter = args[1..].iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--json" if !json => json = true,
            "--require-evaluated" if !require_evaluated => require_evaluated = true,
            "--file" if file.is_none() => {
                let Some(path) = iter.next().filter(|s| !s.starts_with("--")) else {
                    return fail(EX_USAGE, USAGE);
                };
                file = Some(path);
            }
            "--baseline" if baseline_file.is_none() => {
                let Some(path) = iter.next().filter(|s| !s.starts_with("--")) else {
                    return fail(EX_USAGE, USAGE);
                };
                baseline_file = Some(path);
            }
            _ => return fail(EX_USAGE, USAGE),
        }
    }
    let baseline: Option<Baseline> = match baseline_file {
        Some(path) => {
            let bytes = match read_bounded(Path::new(path), mitm_guard::MAX_BASELINE_BYTES) {
                Ok(b) => b,
                Err(e) => return fail(EX_NOINPUT, &e.to_string()),
            };
            match mitm_guard::parse_baseline(&bytes) {
                Ok(b) => Some(b),
                Err(e) => return fail(EX_DATAERR, &e),
            }
        }
        None => None,
    };
    let report = if let Some(path) = file {
        let bytes = match read_bounded(Path::new(path), mitm_guard::MAX_IMPORT_BYTES) {
            Ok(b) => b,
            Err(e) => return fail(EX_NOINPUT, &e.to_string()),
        };
        if bytes.iter().copied().find(|b| !b.is_ascii_whitespace()) == Some(b'[') {
            match wifi_radar::parse_replay(&bytes) {
                Ok(scan) => mitm_guard::from_wifi_replay(&scan, baseline.as_ref()),
                Err(error) => return fail(EX_DATAERR, &error.to_string()),
            }
        } else {
            match mitm_guard::from_wigle_jsonl(&bytes, baseline.as_ref()) {
                Ok(report) => report,
                Err(error) => return fail(EX_DATAERR, &error),
            }
        }
    } else {
        let scan = match super::radar::capture_wifi() {
            Ok(s) => s,
            Err(error) => return fail(EX_UNAVAILABLE, &error),
        };
        mitm_guard::from_wifi_scan(&scan, baseline.as_ref())
    };
    if json {
        match terminal_json_pretty(&report) {
            Ok(value) => println!("{value}"),
            Err(error) => return fail(EX_DATAERR, &error.to_string()),
        }
    } else {
        print_text(&report);
    }
    if require_evaluated && report.evaluated_access_points == 0 {
        ExitCode::from(EX_UNAVAILABLE)
    } else {
        ExitCode::SUCCESS
    }
}

/** Write a trusted inventory from explicitly entered, independently checked values.
 * No scan-derived enrollment: a nearby rogue AP must not poison a baseline.
 */
fn baseline_cmd(args: &[String]) -> ExitCode {
    let mut ssid = None;
    let mut security = None;
    let mut output = None;
    let mut confirmed = false;
    let mut bssids = BTreeSet::new();
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--ssid" if ssid.is_none() => {
                ssid = iter
                    .next()
                    .filter(|s| !s.starts_with("--"))
                    .map(String::as_str);
                if ssid.is_none() {
                    return fail(EX_USAGE, USAGE);
                }
            }
            "--minimum-security" if security.is_none() => {
                security = iter
                    .next()
                    .filter(|s| !s.starts_with("--"))
                    .map(String::as_str);
                if security.is_none() {
                    return fail(EX_USAGE, USAGE);
                }
            }
            "--output" if output.is_none() => {
                output = iter
                    .next()
                    .filter(|s| !s.starts_with("--"))
                    .map(String::as_str);
                if output.is_none() {
                    return fail(EX_USAGE, USAGE);
                }
            }
            "--bssid" if bssids.len() < 256 => {
                let Some(bssid) = iter.next().filter(|s| !s.starts_with("--")) else {
                    return fail(EX_USAGE, USAGE);
                };
                if !bssids.insert(bssid.to_ascii_lowercase()) {
                    return fail(EX_DATAERR, "duplicate operator-supplied BSSID");
                }
            }
            "--confirmed" if !confirmed => confirmed = true,
            _ => return fail(EX_USAGE, USAGE),
        }
    }
    let (Some(ssid), Some(security), Some(output), true) = (ssid, security, output, confirmed)
    else {
        return fail(EX_USAGE, USAGE);
    };
    let value = serde_json::json!({
        "networks": [{
            "ssid": ssid,
            "bssids": bssids.into_iter().collect::<Vec<_>>(),
            "minimum_security": security.to_ascii_uppercase()
        }]
    });
    let encoded = match serde_json::to_vec_pretty(&value) {
        Ok(encoded) => encoded,
        Err(error) => return fail(EX_DATAERR, &error.to_string()),
    };
    if let Err(error) = mitm_guard::parse_baseline(&encoded) {
        return fail(EX_DATAERR, &error);
    }
    let mut options = OpenOptions::new();
    options.write(true).create_new(true).mode(0o600);
    let mut file = match options.open(output) {
        Ok(file) => file,
        Err(error) => return fail(EX_NOINPUT, &format!("baseline not created: {error}")),
    };
    let result = file
        .write_all(&encoded)
        .and_then(|()| file.write_all(b"\n"))
        .and_then(|()| file.sync_all());
    drop(file);
    if let Err(error) = result {
        let _ = std::fs::remove_file(output);
        return fail(EX_UNAVAILABLE, &format!("baseline write failed: {error}"));
    }
    println!(
        "baseline\tstatus=operator_supplied_unverified\tssid={}\tpath={}",
        escape_controls(ssid),
        escape_controls(output)
    );
    ExitCode::SUCCESS
}
