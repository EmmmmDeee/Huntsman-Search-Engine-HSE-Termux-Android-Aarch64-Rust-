//! Shared utilities for harvest commands.

use crate::core::error::{Error, Result};

/// Check that sufficient free disk space exists before starting a harvest write.
///
/// Runs `df -k <dir>` as a subprocess and parses the available-KiB field.
/// If the check cannot be performed (e.g. `df` is not on `PATH`, or we cannot
/// read its output), the function returns `Ok(())` so harvests are never
/// silently blocked on exotic environments.
///
/// # Errors
///
/// Returns [`Error::Other`] when free space is measured and found to be below
/// `min_free_mb` megabytes.
pub fn check_disk_space(path: &str, min_free_mb: u64) -> Result<()> {
    // Resolve the directory that will hold the DB file.
    let dir = std::path::Path::new(path)
        .parent()
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_else(|| ".".to_string());

    // `df -k <dir>` outputs two lines; the second (data) line has:
    //   Filesystem  1K-blocks  Used  Available  Use%  Mounted-on
    // field index 3 is Available, in 1 KiB blocks.
    let output = std::process::Command::new("df")
        .arg("-k")
        .arg(&dir)
        .output();

    let Ok(output) = output else {
        // `df` not found or couldn't spawn — skip the check silently.
        return Ok(());
    };

    let stdout = String::from_utf8_lossy(&output.stdout);
    if let Some(line) = stdout.lines().nth(1) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if let Some(avail_mb) = fields.get(3).and_then(|s| s.parse::<u64>().ok()) {
            // `df -k` gives KiB; convert to MiB.
            let avail_mb = avail_mb / 1024;
            if avail_mb < min_free_mb {
                return Err(Error::Other(format!(
                    "Insufficient disk space: {avail_mb} MB available, \
                     {min_free_mb} MB required. Free up space or use \
                     --sidecar-db to write to external storage."
                )));
            }
        }
    }
    Ok(())
}
