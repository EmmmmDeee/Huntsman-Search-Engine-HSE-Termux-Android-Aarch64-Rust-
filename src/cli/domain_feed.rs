//! CLI adapter for explicit, offline Domains-Monitor text-list ingestion.

use std::fs::{self, File};
use std::io::BufReader;
use std::path::Path;
use std::process::ExitCode;

use super::{fail, terminal_json_pretty};
use huntsman_recon::domain_feed::{Dataset, MAX_TARGETS, USAGE, scan};
use huntsman_recon::exit::{EX_DATAERR, EX_IOERR, EX_NOINPUT, EX_USAGE};

pub(super) fn run(args: &[String]) -> ExitCode {
    if args == ["--help"] || args == ["-h"] {
        println!("{USAGE}");
        return ExitCode::SUCCESS;
    }
    if args.len() < 6 || args[0] != "match" || args[3] != "--as-of" {
        return fail(EX_USAGE, USAGE);
    }
    let Some(dataset) = Dataset::parse(&args[1]) else {
        return fail(EX_USAGE, USAGE);
    };
    if args.len() - 5 > MAX_TARGETS {
        return fail(EX_USAGE, "too many domain targets");
    }
    let path = Path::new(&args[2]);
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) => return fail(EX_NOINPUT, &format!("feed file unavailable: {error}")),
    };
    // Never follow symlinks or accept a pipe with unbounded/infinite input.
    if !metadata.file_type().is_file() {
        return fail(EX_NOINPUT, "feed path must be a regular file (not a symlink)");
    }
    let file = match File::open(path) {
        Ok(file) => file,
        Err(error) => return fail(EX_NOINPUT, &format!("feed file unreadable: {error}")),
    };
    let report = match scan(
        BufReader::with_capacity(64 * 1024, file),
        dataset,
        &args[4],
        &args[5..],
    ) {
        Ok(report) => report,
        Err(error) => return fail(EX_DATAERR, &error),
    };
    // A changing input cannot be represented as one stable, dated snapshot.
    let current_size = fs::metadata(path).map(|m| m.len());
    if report.bytes_read != metadata.len() || current_size != Ok(metadata.len()) {
        return fail(EX_IOERR, "feed changed while reading; no report emitted");
    }
    match terminal_json_pretty(&report) {
        Ok(json) => {
            println!("{json}");
            ExitCode::SUCCESS
        }
        Err(error) => fail(EX_DATAERR, &format!("feed json: {error}")),
    }
}
