//! CLI adapter for explicit, offline Domains-Monitor text-list ingestion.

use std::fs::{self, File};
use std::io::BufReader;
use std::path::Path;
use std::process::ExitCode;

use super::{fail, terminal_json_pretty};
use huntsman_recon::domain_feed::{Dataset, MAX_TARGETS, USAGE, scan};
use huntsman_recon::exit::{EX_DATAERR, EX_IOERR, EX_NOINPUT, EX_USAGE};

/// A path and an opened handle must refer to the same unchanged regular file.
/// Size alone misses same-length replacements; comparing the handle and path
/// also detects a symlink swap between the initial check and open.
fn same_snapshot(first: &fs::Metadata, second: &fs::Metadata) -> bool {
    if !first.is_file()
        || !second.is_file()
        || first.len() != second.len()
        || first.modified().ok() != second.modified().ok()
    {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        first.dev() == second.dev()
            && first.ino() == second.ino()
            && first.ctime() == second.ctime()
            && first.ctime_nsec() == second.ctime_nsec()
    }
    #[cfg(not(unix))]
    {
        true
    }
}

pub(super) fn run(args: &[String]) -> ExitCode {
    if args.len() == 1 && matches!(args[0].as_str(), "--help" | "-h") {
        println!("{USAGE}");
        return ExitCode::SUCCESS;
    }
    if args.len() < 6 || args[0] != "match" || args[3] != "--as-of" {
        return fail(EX_USAGE, USAGE);
    }
    let Some(dataset) = Dataset::parse(&args[1]) else {
        return fail(EX_USAGE, USAGE);
    };
    // A trusted external manifest can pin the original downloaded bytes.
    // This optional checksum never authenticates the provider by itself.
    let (expected_hash, targets) = if args.get(5).is_some_and(|arg| arg == "--expect-sha256") {
        let Some(hash) = args.get(6) else {
            return fail(EX_USAGE, "--expect-sha256 requires a 64-digit hexadecimal hash");
        };
        if hash.len() != 64 || !hash.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return fail(EX_USAGE, "--expect-sha256 requires a 64-digit hexadecimal hash");
        }
        (Some(hash.as_str()), &args[7..])
    } else {
        (None, &args[5..])
    };
    if targets.is_empty() || targets.len() > MAX_TARGETS {
        return fail(EX_USAGE, USAGE);
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
    let opened = match file.metadata() {
        Ok(opened) => opened,
        Err(error) => return fail(EX_NOINPUT, &format!("feed file metadata unavailable: {error}")),
    };
    if !same_snapshot(&metadata, &opened) {
        return fail(EX_IOERR, "feed changed between path check and file open");
    }
    let report = match scan(
        BufReader::with_capacity(64 * 1024, &file),
        dataset,
        &args[4],
        targets,
    ) {
        Ok(report) => report,
        Err(error) => return fail(EX_DATAERR, &error),
    };
    // A changing input cannot be represented as one stable, dated snapshot.
    let handle_after = file.metadata();
    let path_after = fs::symlink_metadata(path);
    if report.bytes_read != metadata.len()
        || !handle_after.is_ok_and(|after| same_snapshot(&metadata, &after))
        || !path_after.is_ok_and(|after| same_snapshot(&metadata, &after))
    {
        return fail(EX_IOERR, "feed changed while reading; no report emitted");
    }
    if expected_hash.is_some_and(|expected| !report.file_sha256.eq_ignore_ascii_case(expected)) {
        return fail(EX_DATAERR, "feed SHA-256 differs from expected manifest; no report emitted");
    }
    match terminal_json_pretty(&report) {
        Ok(json) => {
            println!("{json}");
            ExitCode::SUCCESS
        }
        Err(error) => fail(EX_DATAERR, &format!("feed json: {error}")),
    }
}
