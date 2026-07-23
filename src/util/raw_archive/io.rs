/// Write one complete archive file (mode 0600 on unix), atomically via
/// temp+fsync+rename to survive OOM-kill mid-write. Creating the archive
/// directory if missing. Each file is written once and never appended to, so no
/// cross-writer locking is needed — the unique `seq` in the name guarantees a
/// distinct path per call.
pub(super) fn write_file(path: &std::path::Path, body: &str) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        crate::util::atomic_file::create_dir_private(parent)?;
    }
    crate::util::atomic_file::write(path, body.as_bytes())
}
