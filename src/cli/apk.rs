//! Read-only Android APK intelligence CLI adapter. Library owns analysis.

use std::path::Path;
use std::process::ExitCode;

use huntsman_recon::apk_intel::{self, APK_HELP, MAX_FILE_BYTES};
use huntsman_recon::clock;
use huntsman_recon::exit::{EX_DATAERR, EX_IOERR, EX_NOINPUT, EX_USAGE};
use huntsman_recon::fsio::read_bounded;
use huntsman_recon::lookup_report;

use super::{fail, terminal_json_pretty};

fn diff_cmd(old: &str, new: &str, as_json: bool) -> ExitCode {
    if old.is_empty() || new.is_empty() {
        return fail(EX_USAGE, APK_HELP);
    }
    let old_data = match read_bounded(Path::new(old), MAX_FILE_BYTES) {
        Ok(bytes) => bytes,
        Err(error) => return fail(EX_NOINPUT, &error.to_string()),
    };
    let new_data = match read_bounded(Path::new(new), MAX_FILE_BYTES) {
        Ok(bytes) => bytes,
        Err(error) => return fail(EX_NOINPUT, &error.to_string()),
    };
    let delta = match apk_intel::lineage::compare(&old_data, &new_data) {
        Ok(delta) => delta,
        Err(error) => return fail(EX_DATAERR, &error.to_string()),
    };
    if as_json {
        match terminal_json_pretty(&delta) {
            Ok(value) => println!("{value}"),
            Err(error) => return fail(EX_IOERR, &error.to_string()),
        }
    } else {
        println!("old_sha256={}", delta.old_sha256);
        println!("new_sha256={}", delta.new_sha256);
        println!(
            "added={} removed={} modified={} unchanged={} changes_omitted={}",
            delta.added, delta.removed, delta.modified, delta.unchanged, delta.omitted_changes
        );
        for change in &delta.changes {
            // Debug formatting escapes control characters from untrusted member names.
            println!(
                "{} {:?} [{}]",
                change.disposition, change.path, change.component
            );
        }
        println!("{}", delta.limitations);
    }
    ExitCode::SUCCESS
}

pub(super) fn apk_cmd(args: &[String]) -> ExitCode {
    match args {
        [operation, old, new] if operation == "diff" => {
            return diff_cmd(old, new, false);
        }
        [operation, old, new, flag] if operation == "diff" && flag == "--json" => {
            return diff_cmd(old, new, true);
        }
        _ => {}
    }
    if matches!(args, [flag] if flag == "--help") {
        println!("{APK_HELP}");
        return ExitCode::SUCCESS;
    }
    let (file, as_json) = match args {
        [file] => (file.as_str(), false),
        [file, flag] if flag == "--json" => (file.as_str(), true),
        _ => return fail(EX_USAGE, APK_HELP),
    };
    if file.is_empty() {
        return fail(EX_USAGE, APK_HELP);
    }
    let data = match read_bounded(Path::new(file), MAX_FILE_BYTES) {
        Ok(data) => data,
        Err(e) => return fail(EX_NOINPUT, &e.to_string()),
    };
    let report = match apk_intel::run(&data, file, clock::unix_now()) {
        Ok(report) => report,
        Err(e) => return fail(EX_DATAERR, &e.to_string()),
    };
    if as_json {
        match terminal_json_pretty(&report) {
            Ok(json) => println!("{json}"),
            Err(e) => return fail(EX_IOERR, &e.to_string()),
        }
    } else {
        match lookup_report::render(&report.entities, &report.outcomes) {
            Ok(text) => print!("{text}"),
            Err(e) => return fail(EX_IOERR, &e),
        }
    }
    ExitCode::SUCCESS
}
