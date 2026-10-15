//! Bounded, symlink-refusing file IO shared by the session store, the ledger, the keys file,
//! the directive files and every other file the crate reads whole.
//! A read never exceeds its bound, even if the file grows after `stat`, and it reads the inode
//! `lstat` checked: a link or a replacement planted between the check and the open is refused.
//! A write lands whole or not at all: temp file in the same directory, then rename.

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};

use crate::error::Error;

static TEMP_SEQUENCE: AtomicUsize = AtomicUsize::new(0);

fn store_err(path: &Path, e: &std::io::Error) -> Error {
    Error::Store(format!("{}: {e}", path.display()))
}

/// The text a refused symbolic link is reported with.
pub(crate) const REFUSED_SYMLINK: &str = "refusing symlink";

/// The text a path that is not a regular file is reported with.
pub(crate) const NOT_REGULAR_FILE: &str = "not a regular file";

/// The text a path whose opened descriptor is not the inode `lstat` checked is reported with.
pub(crate) const CHANGED_WHILE_OPENING: &str = "changed between the check and the open";

/// Why a path may not be written through: it is a symbolic link, or it could not be inspected.
pub(crate) enum SymlinkRefusal {
    Linked,
    Unreadable(std::io::Error),
}

/// The policy for every write in this crate: a symbolic link is refused, so a write cannot land in
/// whatever file the link points at. A path that does not exist yet is allowed.
pub(crate) fn check_not_symlink(path: &Path) -> Result<(), SymlinkRefusal> {
    match fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_symlink() => Err(SymlinkRefusal::Linked),
        Ok(_) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(SymlinkRefusal::Unreadable(e)),
    }
}

fn refuse_symlink(path: &Path) -> Result<(), Error> {
    check_not_symlink(path).map_err(|refusal| match refusal {
        SymlinkRefusal::Linked => Error::Store(format!("{}: {REFUSED_SYMLINK}", path.display())),
        SymlinkRefusal::Unreadable(e) => store_err(path, &e),
    })
}

fn require_regular_file(path: &Path, meta: &fs::Metadata) -> Result<(), Error> {
    if meta.file_type().is_symlink() {
        return Err(Error::Store(format!(
            "{}: {REFUSED_SYMLINK}",
            path.display()
        )));
    }
    if !meta.is_file() {
        return Err(Error::Store(format!(
            "{}: {NOT_REGULAR_FILE}",
            path.display()
        )));
    }
    Ok(())
}

/// Did `open` reach the inode `lstat` described (`linked`), and not a link or a replacement
/// swapped in between the two calls? Device and inode number together name a file. The one
/// comparison behind every checked read and in-place write in the crate: the keys file, the
/// run history and [`read_bounded`]. Off Unix the metadata carries no inode, so the two are
/// taken to agree, as every read did before this check.
#[cfg(unix)]
pub(crate) fn same_inode(linked: &fs::Metadata, opened: &fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    (linked.dev(), linked.ino()) == (opened.dev(), opened.ino())
}

#[cfg(not(unix))]
pub(crate) fn same_inode(_linked: &fs::Metadata, _opened: &fs::Metadata) -> bool {
    true
}

/// Read at most `max` bytes. Larger files, symlinks, and non-files are refused.
///
/// The path is checked before opening so FIFOs/devices are rejected instead of
/// potentially blocking or triggering device behavior. The opened handle is
/// checked again before reading: it must be the inode `lstat` saw and a regular
/// file, so a link or a replacement planted between the check and the open is
/// refused rather than followed. `O_NOFOLLOW` is not set, because its value
/// differs per architecture and would need the `libc` crate; comparing the
/// descriptor with the `lstat` result closes the same window.
///
/// # Errors
/// `Error::Store` on a symlink, non-file, IO failure, a file over `max` bytes, or
/// a path that changed between the check and the open.
pub fn read_bounded(path: &Path, max: u64) -> Result<Vec<u8>, Error> {
    let path_meta = fs::symlink_metadata(path).map_err(|e| store_err(path, &e))?;
    require_regular_file(path, &path_meta)?;
    let file = File::open(path).map_err(|e| store_err(path, &e))?;
    read_opened(path, &path_meta, file, max)
}

/// The descriptor half of [`read_bounded`]: `file` must be the inode `linked` (the `lstat`
/// result for `path`) describes and a regular file; then at most `max` bytes are read from it.
fn read_opened(path: &Path, linked: &fs::Metadata, file: File, max: u64) -> Result<Vec<u8>, Error> {
    let opened = file.metadata().map_err(|e| store_err(path, &e))?;
    if !same_inode(linked, &opened) {
        return Err(Error::Store(format!(
            "{}: {CHANGED_WHILE_OPENING}",
            path.display()
        )));
    }
    require_regular_file(path, &opened)?;
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

/// Replace `path` atomically and durably. A symlink at `path` or at its parent directory is
/// refused. The bytes are flushed before the rename and the directory after it: on ext4 and
/// f2fs (Android's data partition) a rename whose directory was not flushed can be lost to a
/// power cut or a kernel crash, leaving the old file or none. (A killed process, such as one
/// Android's low-memory killer ends, loses nothing: the kernel still writes the rename back.)
///
/// # Errors
/// `Error::Store` on a symlink, a body over `max` bytes, or IO failure.
pub fn write_atomic(path: &Path, body: &[u8], max: u64) -> Result<(), Error> {
    write_atomic_mode(path, body, max, false)
}

/// Atomically and durably write a private file, creating it mode 600 on Unix before any bytes
/// land. Use it for anything holding credentials or the people a lookup found: ledgers,
/// sessions, scan artifacts, tokens. Replacing an older, more open file leaves it mode 600.
///
/// # Errors
/// As [`write_atomic`], and on Unix when the filesystem leaves the new file readable by others
/// (see `private_mode_verdict`); on shared storage that case warns and writes.
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
    let (mut file, tmp) = create_temp_file(&parent, name, private, &TEMP_SEQUENCE)?;
    let result = (|| {
        if private {
            check_private_mode(path, &file)?;
        }
        file.write_all(body).map_err(|e| store_err(&tmp, &e))?;
        file.sync_all().map_err(|e| store_err(&tmp, &e))?;
        fs::rename(&tmp, path).map_err(|e| store_err(path, &e))
    })();
    drop(file);
    if result.is_err() {
        let _ = fs::remove_file(&tmp);
    } else {
        sync_directory(&parent);
    }
    result
}

/// Flush a directory's entries so a completed rename in it survives a crash. Opening a
/// directory as a file works on Unix and not on every other platform, and the rename has
/// already succeeded, so a failure here does not fail the write.
fn sync_directory(dir: &Path) {
    if let Ok(handle) = File::open(dir) {
        let _ = handle.sync_all();
    }
}

/// Android's shared storage. Its FAT, exFAT and FUSE mounts do not keep Unix mode bits, so a
/// private file there cannot be made private.
#[cfg(unix)]
const SHARED_STORAGE_ROOTS: [&str; 5] = [
    "/sdcard",
    "/storage",
    "/mnt/sdcard",
    "/mnt/media_rw",
    "/mnt/runtime",
];

#[cfg(unix)]
fn is_shared_storage(path: &Path) -> bool {
    SHARED_STORAGE_ROOTS
        .iter()
        .any(|root| path.starts_with(root))
}

/// Judge the mode a private file was created with. A private file has no group or other bits:
/// the creation request is 600 and the umask can only narrow it, so wider bits mean the
/// filesystem did not honour the request. Off shared storage that refuses the write; on shared
/// storage, where the mode cannot be enforced, it warns on stderr and lets the write land. The
/// warning is a plain write, not `eprintln!`, so a closed stderr cannot abort the save.
#[cfg(unix)]
fn private_mode_verdict(path: &Path, mode: u32) -> Result<(), Error> {
    let group_and_other = mode & 0o077;
    if group_and_other == 0 {
        return Ok(());
    }
    if is_shared_storage(path) {
        let _ = writeln!(
            std::io::stderr(),
            "{}: mode {mode:o} on shared storage, which does not keep Unix modes; readable by others",
            path.display()
        );
        return Ok(());
    }
    Err(Error::Store(format!(
        "{}: created with mode {mode:o}, readable by others; this filesystem does not honour Unix modes, so a private file is refused",
        path.display()
    )))
}

/// Check the new temp file before any bytes land, so a refused write leaves nothing behind.
#[cfg(unix)]
fn check_private_mode(path: &Path, file: &File) -> Result<(), Error> {
    use std::os::unix::fs::PermissionsExt;
    let mode = file
        .metadata()
        .map_err(|e| store_err(path, &e))?
        .permissions()
        .mode()
        & 0o777;
    private_mode_verdict(path, mode)
}

#[cfg(not(unix))]
fn check_private_mode(_path: &Path, _file: &File) -> Result<(), Error> {
    Ok(())
}

fn create_temp_file(
    parent: &Path,
    name: &std::ffi::OsStr,
    private: bool,
    sequence: &AtomicUsize,
) -> Result<(File, PathBuf), Error> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    if private {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    #[cfg(not(unix))]
    let _ = private;
    loop {
        let mut tmp_name = name.to_os_string();
        tmp_name.push(format!(
            ".{}.{}.tmp",
            std::process::id(),
            sequence.fetch_add(1, Ordering::Relaxed)
        ));
        let tmp = parent.join(tmp_name);
        match options.open(&tmp) {
            Ok(file) => return Ok((file, tmp)),
            // A stale file or another writer owns this name; never remove it.
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(store_err(&tmp, &e)),
        }
    }
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

    #[test]
    fn temp_collisions_are_retried_without_touching_existing_files() {
        let dir = scratch("collision");
        let name = std::ffi::OsStr::new("tokens.json");
        let sequence = AtomicUsize::new(0);
        let sentinels: Vec<_> = (0..2)
            .map(|id| dir.join(format!("tokens.json.{}.{id}.tmp", std::process::id())))
            .collect();
        for sentinel in &sentinels {
            fs::write(sentinel, b"owned by another writer").unwrap();
        }
        let (file, tmp) = create_temp_file(&dir, name, true, &sequence).unwrap();
        assert_eq!(
            tmp,
            dir.join(format!("tokens.json.{}.2.tmp", std::process::id()))
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(file.metadata().unwrap().permissions().mode() & 0o777, 0o600);
        }
        for sentinel in &sentinels {
            assert_eq!(fs::read(sentinel).unwrap(), b"owned by another writer");
        }
        drop(file);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn failed_rename_cleans_up_only_its_own_temp_file() {
        let dir = scratch("rename-failure");
        let path = dir.join("tokens.json");
        fs::create_dir(&path).unwrap();
        let sentinel = dir.join(format!("tokens.json.{}.tmp", std::process::id()));
        fs::write(&sentinel, b"owned by another writer").unwrap();
        assert!(write_atomic_private(&path, b"{}", 10).is_err());
        assert_eq!(fs::read(&sentinel).unwrap(), b"owned by another writer");
        assert!(path.is_dir());
        assert_eq!(fs::read_dir(&dir).unwrap().count(), 2);
        fs::remove_dir_all(dir).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn same_inode_tells_a_file_from_another() {
        let dir = scratch("inode");
        let one = dir.join("one.json");
        let two = dir.join("two.json");
        fs::write(&one, b"1").unwrap();
        fs::write(&two, b"2").unwrap();
        let linked = fs::symlink_metadata(&one).unwrap();
        assert!(
            same_inode(&linked, &fs::metadata(&one).unwrap()),
            "a file is its own inode"
        );
        assert!(
            same_inode(&linked, &File::open(&one).unwrap().metadata().unwrap()),
            "a descriptor opened on the file is its inode"
        );
        assert!(
            !same_inode(&linked, &fs::metadata(&two).unwrap()),
            "two files are two inodes"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn a_descriptor_that_is_not_the_checked_inode_is_refused() {
        // `read_bounded` checks the path with `lstat`, opens it, then reads through the
        // descriptor. A swap between the check and the open cannot be scheduled from a test, so
        // the descriptor half is given, by construction, the `lstat` result of one file and a
        // descriptor on another: what a link or a replacement planted in that window produces.
        let dir = scratch("swap");
        let checked = dir.join("checked.json");
        let planted = dir.join("planted.json");
        fs::write(&checked, b"checked").unwrap();
        fs::write(&planted, b"planted").unwrap();
        let linked = fs::symlink_metadata(&checked).unwrap();
        assert_eq!(
            read_opened(&checked, &linked, File::open(&checked).unwrap(), 10).unwrap(),
            b"checked"
        );
        let error = read_opened(&checked, &linked, File::open(&planted).unwrap(), 10)
            .expect_err("a descriptor on another inode must be refused")
            .to_string();
        assert!(error.contains(CHANGED_WHILE_OPENING), "{error}");
        assert!(error.contains(&checked.display().to_string()), "{error}");
        let _ = fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn a_private_file_is_created_with_no_group_or_other_bits() {
        use std::os::unix::fs::PermissionsExt;
        let dir = scratch("private-mode");
        let path = dir.join("tokens.json");
        write_atomic_private(&path, b"{}", 10).unwrap();
        assert_eq!(fs::metadata(&path).unwrap().permissions().mode() & 0o077, 0);
        fs::remove_dir_all(dir).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn a_mode_readable_by_others_is_refused_off_shared_storage() {
        let refused = private_mode_verdict(
            Path::new("/data/data/com.termux/files/home/.huntsman/tokens.json"),
            0o644,
        );
        let err = refused.expect_err("a private file readable by others is refused");
        assert!(err.to_string().contains("readable by others"), "{err}");
        assert!(private_mode_verdict(Path::new("/data/x/tokens.json"), 0o600).is_ok());
        assert!(private_mode_verdict(Path::new("/data/x/tokens.json"), 0o400).is_ok());
        assert!(private_mode_verdict(Path::new("/data/x/tokens.json"), 0o640).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn shared_storage_warns_and_writes_instead_of_refusing() {
        assert!(private_mode_verdict(Path::new("/sdcard/Download/tokens.json"), 0o666).is_ok());
        assert!(
            private_mode_verdict(Path::new("/storage/emulated/0/huntsman/x.json"), 0o644).is_ok()
        );
        assert!(is_shared_storage(Path::new("/storage/emulated/0/x")));
        assert!(!is_shared_storage(Path::new("/storagex/huntsman")));
        assert!(!is_shared_storage(Path::new(
            "/data/data/com.termux/files/home/.huntsman"
        )));
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
