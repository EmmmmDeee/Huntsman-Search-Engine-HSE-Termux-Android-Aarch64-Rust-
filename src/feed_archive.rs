//! Append-only, content-addressed original HTTP feed bodies and acquisition receipts.
//!
//! This is separate from the mutable operational feed cache. Each body is stored by SHA-256;
//! each acquisition gets a distinct receipt, including response metadata. A second body never
//! replaces the first. Writes are staged privately and installed through an atomic hard link,
//! which refuses to overwrite an existing archive path, including under concurrent writers.
//! No automatic pruning or normalisation of original bytes occurs.

use std::fs;
use std::io::ErrorKind;
use std::path::Path;

use serde_json::Value;

fn ensure_private_dir(path: &Path) -> Result<(), String> {
    let mut builder = fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    match builder.create(path) {
        Ok(()) => {}
        Err(error) if error.kind() == ErrorKind::AlreadyExists => {}
        Err(error) => return Err(format!("{}: {error}", path.display())),
    }
    let meta = fs::symlink_metadata(path).map_err(|e| e.to_string())?;
    if !meta.is_dir() || meta.file_type().is_symlink() {
        return Err(format!("{}: archive directory is not a real directory", path.display()));
    }
    Ok(())
}

/// Atomically create a private immutable-by-policy file, or verify the bytes of an existing one.
/// A corrupt existing file is an error: it is never silently replaced with the new body.
fn write_once(path: &Path, body: &[u8]) -> Result<(), String> {
    let bound = u64::try_from(body.len()).map_err(|e| e.to_string())?;
    let verify = || {
        let existing = crate::fsio::read_bounded(path, bound).map_err(|e| e.to_string())?;
        if existing != body {
            return Err(format!("{}: existing archived bytes differ", path.display()));
        }
        Ok(())
    };
    match fs::symlink_metadata(path) {
        Ok(_) => return verify(),
        Err(error) if error.kind() == ErrorKind::NotFound => {}
        Err(error) => return Err(error.to_string()),
    }
    let name = crate::entity::scan_id("feed-archive-stage", "write");
    let staged = path.with_file_name(format!(".{name}.pending"));
    crate::fsio::write_atomic_private(&staged, body, bound)
        .map_err(|error| error.to_string())?;
    let installed = fs::hard_link(&staged, path);
    let _ = fs::remove_file(&staged);
    match installed {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == ErrorKind::AlreadyExists => verify(),
        Err(error) => Err(format!("{}: {error}", path.display())),
    }
}

/// Store the complete raw response bytes and an independent, append-only receipt.
///
/// The receipt's `context` is the caller's acquisition metadata (URLs, status, complete
/// response headers, timing and truncation state), not a parsed or sanitised view.
pub(crate) fn store(
    dir: &Path,
    feed_id: &str,
    body: &[u8],
    context: &Value,
) -> Result<String, String> {
    fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    let dir_meta = fs::symlink_metadata(dir).map_err(|e| e.to_string())?;
    if !dir_meta.is_dir() || dir_meta.file_type().is_symlink() {
        return Err(format!("{}: refusing linked cache directory", dir.display()));
    }
    let root = dir.join("originals");
    ensure_private_dir(&root)?;
    let folder = root.join(feed_id);
    ensure_private_dir(&folder)?;

    let digest = crate::sha256::hex32(&crate::sha256::sha256(body));
    write_once(&folder.join(format!("{digest}.raw")), body)?;

    let receipt = serde_json::json!({
        "schema": "huntsman-raw-feed-acquisition-v1",
        "sha256": digest,
        "bytes": body.len(),
        "acquisition": context,
    });
    let bytes = serde_json::to_vec(&receipt).map_err(|e| e.to_string())?;
    let id = crate::entity::scan_id("feed-acquisition-receipt", &digest);
    write_once(&folder.join(format!("{id}.json")), &bytes)?;
    Ok(digest)
}

/// Preserve a copy created by a prior HSE version before the mutable cache replaces it.
/// Its original request headers were not recorded; the receipt explicitly marks them unknown.
/// A byte-identical copy already archived is verified but does not create repeated receipts.
pub(crate) fn backfill(
    dir: &Path,
    feed_id: &str,
    body: &[u8],
    cache_mtime: u64,
) -> Result<(), String> {
    let digest = crate::sha256::hex32(&crate::sha256::sha256(body));
    let path = dir
        .join("originals")
        .join(feed_id)
        .join(format!("{digest}.raw"));
    match fs::symlink_metadata(&path) {
        Ok(_) => {
            let bound = u64::try_from(body.len()).map_err(|e| e.to_string())?;
            let previous = crate::fsio::read_bounded(&path, bound).map_err(|e| e.to_string())?;
            if previous != body {
                return Err(format!(
                    "{}: existing archived bytes differ",
                    path.display()
                ));
            }
            Ok(())
        }
        Err(error) if error.kind() == ErrorKind::NotFound => {
            let context = serde_json::json!({
                "origin": "legacy_cache",
                "cache_file_mtime_unix": cache_mtime,
                "original_response_headers_known": false,
                "original_http_status_known": false,
            });
            store(dir, feed_id, body, &context).map(|_| ())
        }
        Err(error) => Err(error.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_versions_and_acquisition_receipts_are_append_only() {
        let dir = std::env::temp_dir().join(format!(
            "hse-originals-{}",
            crate::entity::scan_id("archive-test", "versions")
        ));
        fs::create_dir_all(&dir).expect("test directory");
        let first = b"a,b\r\n1,\"x,y\"\r\n";
        let second = b"a,b\r\n2,\"x,y\"\r\n";
        let meta = serde_json::json!({
            "request_url": "https://example.org/list.csv",
            "response_status": 200,
            "headers": [["ETag", "\"one\""]],
            "observed_at_unix": 1000
        });
        let one = store(&dir, "test.csv", first, &meta).expect("archive first");
        assert_eq!(store(&dir, "test.csv", first, &meta).unwrap(), one);
        let two = store(&dir, "test.csv", second, &meta).expect("archive update");
        assert_ne!(one, two);
        let archive = dir.join("originals/test.csv");
        assert_eq!(fs::read(archive.join(format!("{one}.raw"))).unwrap(), first);
        assert_eq!(
            fs::read(archive.join(format!("{two}.raw"))).unwrap(),
            second
        );
        let receipts = fs::read_dir(&archive)
            .unwrap()
            .filter_map(Result::ok)
            .filter(|entry| entry.path().extension().is_some_and(|x| x == "json"))
            .count();
        assert_eq!(receipts, 3, "one receipt for every acquisition");
        fs::remove_dir_all(dir).expect("cleanup");
    }

    #[test]
    fn archived_content_corruption_is_detected_not_overwritten() {
        let dir = std::env::temp_dir().join(format!(
            "hse-originals-{}",
            crate::entity::scan_id("archive-test", "corruption")
        ));
        fs::create_dir_all(&dir).expect("test directory");
        let body = b"unaltered original";
        let meta = serde_json::json!({"response_status": 200});
        let hash = store(&dir, "test.csv", body, &meta).unwrap();
        let archived = dir.join("originals/test.csv").join(format!("{hash}.raw"));
        fs::write(&archived, b"tampered original").unwrap();
        assert!(store(&dir, "test.csv", body, &meta).is_err());
        assert_eq!(fs::read(&archived).unwrap(), b"tampered original");
        fs::remove_dir_all(dir).expect("cleanup");
    }
}
