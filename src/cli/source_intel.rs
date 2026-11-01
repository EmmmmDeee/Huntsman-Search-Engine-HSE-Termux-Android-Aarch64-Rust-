//! Offline APK-to-OSINT-source-candidate CLI. All analysis belongs to the library.

use std::path::Path;
use std::process::ExitCode;

use huntsman_recon::apk_intel::{self, MAX_FILE_BYTES};
use huntsman_recon::clock;
use huntsman_recon::exit::{EX_DATAERR, EX_IOERR, EX_NOINPUT, EX_USAGE};
use huntsman_recon::fsio::read_bounded;
use huntsman_recon::source_intel;

use super::{fail, terminal_json_pretty};

pub(super) const HELP: &str = "source-intel apk FILE --json\nProject the existing offline APK DEX URL analysis into canonical, provenance-scoped OSINT source leads. No network requests; references are not proof of live endpoints, public access, method or ownership. No original per-DEX-string offsets are claimed.";

pub(super) fn run(args: &[String]) -> ExitCode {
    let file = match args {
        [kind, file, flag] if kind == "apk" && flag == "--json" && !file.is_empty() => file,
        _ => return fail(EX_USAGE, HELP),
    };
    let data = match read_bounded(Path::new(file), MAX_FILE_BYTES) {
        Ok(data) => data,
        Err(error) => return fail(EX_NOINPUT, &error.to_string()),
    };
    let apk = match apk_intel::run(&data, file, clock::unix_now()) {
        Ok(report) => report,
        Err(error) => return fail(EX_DATAERR, &error.to_string()),
    };
    let candidates = source_intel::from_apk_report(&apk);
    match terminal_json_pretty(&candidates) {
        Ok(output) => println!("{output}"),
        Err(error) => return fail(EX_IOERR, &error),
    }
    ExitCode::SUCCESS
}
