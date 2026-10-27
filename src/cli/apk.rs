//! Read-only Android APK intelligence CLI adapter. Library owns analysis.

use std::path::Path;
use std::process::ExitCode;

use huntsman_recon::apk_intel::{self, APK_HELP, MAX_FILE_BYTES};
use huntsman_recon::clock;
use huntsman_recon::exit::{EX_DATAERR, EX_IOERR, EX_NOINPUT, EX_USAGE};
use huntsman_recon::fsio::read_bounded;
use huntsman_recon::lookup_report;

use super::{fail, terminal_json_pretty};

pub(super) fn apk_cmd(args: &[String]) -> ExitCode {
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
