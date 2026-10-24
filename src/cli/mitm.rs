//! Operator-invoked, rootless Wi-Fi MITM/evil-twin assessment.
use std::path::Path;
use std::process::ExitCode;

use super::{fail, terminal_json_pretty};
use huntsman_recon::exit::{EX_DATAERR, EX_NOINPUT, EX_UNAVAILABLE, EX_USAGE};
use huntsman_recon::fsio::read_bounded;
use huntsman_recon::mitm_guard::{self, Baseline, Report};
use huntsman_recon::textnorm::escape_controls;
use huntsman_recon::wifi_radar;

pub(super) const USAGE: &str =
    "mitm audit [--file WIFI_JSON_OR_WIGLE_JSONL] [--baseline TRUSTED_JSON] [--json]\nWithout --file, read the existing rootless Termux OS-cached Wi-Fi radar; offline --file accepts a Termux scan JSON array or Huntsman-normalized WiGLE JSONL. Baseline JSON format: {\"networks\":[{\"ssid\":\"Office\",\"bssids\":[\"3c:5a:b4:11:22:33\"],\"minimum_security\":\"WPA3\"}]}. This tool only reports unconfirmed indicators; it never forcibly disconnects networks. Remediation requires verifying the authorised access point and making manual Android network settings changes.";

fn print_text(report: &Report) {
    println!(
        "mitm\tsource={}\tstatus={}\taccess_points={}\trejected={}\tbaseline_supplied={}\tconfirmed={}",
        report.source, report.status, report.evaluated_access_points,
        report.rejected_records, report.trusted_baseline_supplied, report.mitm_confirmed
    );
    for finding in &report.findings {
        println!(
            "finding\tseverity={}\tcode={}\tssid={}\tbssid={}\tevidence={}\tresolution={}",
            finding.severity, finding.code,
            escape_controls(&finding.ssid),
            finding.bssid.as_deref().unwrap_or("none"),
            escape_controls(&finding.evidence),
            finding.resolution
        );
    }
    println!("limitation\t{}", report.capability_limit);
}

pub(super) fn mitm_cmd(args: &[String]) -> ExitCode {
    if args.first().map(String::as_str) != Some("audit") {
        return fail(EX_USAGE, USAGE);
    }
    let mut file = None;
    let mut baseline_file = None;
    let mut json = false;
    let mut iter = args[1..].iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--json" if !json => json = true,
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
    let report = match file {
        Some(path) => {
            let bytes = match read_bounded(Path::new(path), mitm_guard::MAX_IMPORT_BYTES) {
                Ok(b) => b,
                Err(e) => return fail(EX_NOINPUT, &e.to_string()),
            };
            if bytes.iter().copied().find(|b| !b.is_ascii_whitespace()) == Some(b'[') {
                match wifi_radar::parse_replay(&bytes) {
                    Ok(scan) => mitm_guard::from_wifi_scan(&scan, baseline.as_ref()),
                    Err(error) => return fail(EX_DATAERR, &error.to_string()),
                }
            } else {
                match mitm_guard::from_wigle_jsonl(&bytes, baseline.as_ref()) {
                    Ok(report) => report,
                    Err(error) => return fail(EX_DATAERR, &error),
                }
            }
        }
        None => {
            let scan = match super::radar::capture_wifi() {
                Ok(s) => s,
                Err(error) => return fail(EX_UNAVAILABLE, &error),
            };
            mitm_guard::from_wifi_scan(&scan, baseline.as_ref())
        }
    };
    if json {
        match terminal_json_pretty(&report) {
            Ok(value) => println!("{value}"),
            Err(error) => return fail(EX_DATAERR, &error.to_string()),
        }
    } else {
        print_text(&report);
    }
    ExitCode::SUCCESS
}
