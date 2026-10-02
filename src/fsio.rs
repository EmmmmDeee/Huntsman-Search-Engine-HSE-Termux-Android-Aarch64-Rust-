//! Bounded, symlink-refusing file IO shared by the session store and the ledger.
//! A read never exceeds its bound, even if the file grows after `stat`.
//! A write lands whole or not at all: temp file in the same directory, then rename.

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use crate::error::Error;

fn store_err(path: &Path, e: &std::io::Error) -> Error {
    Error::Store(format!("{}: {e}", path.display()))
}

fn refuse_symlink(path: &Path) -> Result<(), Error> {
    match fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_symlink() => Err(Error::Store(format!(
            "{}: refusing symlink",
            path.display()
        ))),
        Ok(_) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(store_err(path, &e)),
    }
}

/// Read at most `max` bytes. Larger files, symlinks, and non-files are refused.
///
/// # Errors
/// `Error::Store` on a symlink, non-file, IO failure, or a file over `max` bytes.
pub fn read_bounded(path: &Path, max: u64) -> Result<Vec<u8>, Error> {
    refuse_symlink(path)?;
    let file = File::open(path).map_err(|e| store_err(path, &e))?;
    let meta = file.metadata().map_err(|e| store_err(path, &e))?;
    if !meta.is_file() {
        return Err(Error::Store(format!(
            "{}: not a regular file",
            path.display()
        )));
    }
    let mut body = Vec::new();
    file.take(max.saturating_add(1))
        .read_to_end(&mut body)
        .map_err(|e| store_err(path, &e))?;
    if body.len() as u64 > max {
        return Err(Error::Store(format!(
            "{}: exceeds {max} bytes",
            path.display()
        )));
    }
    Ok(body)
}

/// Replace `path` atomically. A symlink at `path` or at its parent directory is refused.
///
/// # Errors
/// `Error::Store` on a symlink, a body over `max` bytes, or IO failure.
pub fn write_atomic(path: &Path, body: &[u8], max: u64) -> Result<(), Error> {
    write_atomic_mode(path, body, max, false)
}

/// Atomically write a secret file, creating it mode 600 on Unix before any bytes land.
pub fn write_atomic_private(path: &Path, body: &[u8], max: u64) -> Result<(), Error> {
    write_atomic_mode(path, body, max, true)
}

fn write_atomic_mode(path: &Path, body: &[u8], max: u64, private: bool) -> Result<(), Error> {
    if body.len() as u64 > max {
        return Err(Error::Store(format!(
            "{}: exceeds {max} bytes",
            path.display()
        )));
    }
    let parent = match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p.to_path_buf(),
        _ => PathBuf::from("."),
    };
    refuse_symlink(&parent)?;
    fs::create_dir_all(&parent).map_err(|e| store_err(&parent, &e))?;
    refuse_symlink(path)?;
    let name = path
        .file_name()
        .ok_or_else(|| Error::Store(format!("{}: no file name", path.display())))?;
    let mut tmp_name = name.to_os_string();
    tmp_name.push(format!(".{}.tmp", std::process::id()));
    let tmp = parent.join(tmp_name);
    let result = (|| {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        if private {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        #[cfg(not(unix))]
        let _ = private;
        let mut file = options.open(&tmp).map_err(|e| store_err(&tmp, &e))?;
        file.write_all(body).map_err(|e| store_err(&tmp, &e))?;
        file.sync_all().map_err(|e| store_err(&tmp, &e))?;
        fs::rename(&tmp, path).map_err(|e| store_err(path, &e))
    })();
    if result.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("huntsman-fsio-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn bound_is_enforced_on_read_and_write() {
        let dir = scratch("bound");
        let path = dir.join("f.json");
        write_atomic(&path, b"12345", 5).unwrap();
        assert_eq!(read_bounded(&path, 5).unwrap(), b"12345");
        assert!(read_bounded(&path, 4).is_err());
        assert!(write_atomic(&path, b"123456", 5).is_err());
        assert_eq!(
            read_bounded(&path, 5).unwrap(),
            b"12345",
            "refused write leaves the old file"
        );
        assert_eq!(
            fs::read_dir(&dir).unwrap().count(),
            1,
            "no temp file left behind"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn symlinks_are_refused() {
        let dir = scratch("link");
        let target = dir.join("target.json");
        fs::write(&target, b"{}").unwrap();
        let link = dir.join("link.json");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert!(read_bounded(&link, 10).is_err());
        assert!(write_atomic(&link, b"[]", 10).is_err());
        assert_eq!(
            fs::read(&target).unwrap(),
            b"{}",
            "symlink target untouched"
        );
        let real = dir.join("real");
        fs::create_dir_all(&real).unwrap();
        let linked_dir = dir.join("linked");
        std::os::unix::fs::symlink(&real, &linked_dir).unwrap();
        assert!(write_atomic(&linked_dir.join("x.json"), b"[]", 10).is_err());
        assert!(!real.join("x.json").exists());
        let _ = fs::remove_dir_all(&dir);
    }
}
