/// Write one complete archive file (mode 0600 on unix), creating the archive
/// directory if missing. Each file is written once and never appended to, so no
/// cross-writer locking is needed — the unique `seq` in the name guarantees a
/// distinct path per call.
pub(super) fn write_file(path: &std::path::Path, body: &str) -> std::io::Result<()> {
    use std::io::Write;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    #[cfg(unix)]
    let mut f = {
        use std::os::unix::fs::OpenOptionsExt;
        std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)?
    };
    #[cfg(not(unix))]
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(path)?;
    f.write_all(body.as_bytes())
}
