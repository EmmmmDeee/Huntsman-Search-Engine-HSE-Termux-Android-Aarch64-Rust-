//! Operator credentials: loading, presence checks, and hygiene.
//!
//! Credentials are welcome here; leaking them is not. A `Secret` cannot be printed,
//! serialised or compared by value: it exposes its text only through `expose`, and
//! its `Debug` shows the credential fingerprint, which is what ledgers and logs
//! record. Values come from a keys file (`NAME=value` lines, mode 0600) or the
//! process environment; the file wins so a project can pin its own keys.
//!
//! The keys file is `--keys FILE` when given, otherwise `$HOME/.huntsman.env` when
//! it exists (see [`Keys::resolve`]). Both go through [`Keys::load`].

use std::collections::BTreeMap;
use std::env;
use std::ffi::OsStr;
use std::fmt;
use std::fs::{File, Metadata};
use std::io::{ErrorKind, Read};
use std::path::{Path, PathBuf};

use crate::credential_origin::CredentialFingerprint;
use crate::error::Error;
use crate::fsio::read_bounded;

const MAX_KEYS_FILE_BYTES: u64 = 64 * 1024;

/// Keys file read from `$HOME` when no `--keys FILE` is given.
pub const DEFAULT_KEYS_FILE: &str = ".huntsman.env";

/// `$HOME/.huntsman.env`, or `None` when `home` is unset or empty.
#[must_use]
pub fn default_keys_path(home: Option<&OsStr>) -> Option<PathBuf> {
    let home = home.filter(|home| !home.is_empty())?;
    Some(Path::new(home).join(DEFAULT_KEYS_FILE))
}

/// The keys for one command run, plus a warning for stderr when the default file
/// was skipped. The warning names the path and the fix; it never holds a value.
#[derive(Debug)]
pub struct ResolvedKeys {
    pub keys: Keys,
    pub warning: Option<String>,
}

/// Is this a real credential rather than a blank or a template placeholder?
///
/// Rejects empty/whitespace values and the placeholders operators leave in
/// `.env.example` files (`insert_key_here`, `<your-key>`, `changeme`, `xxxx`).
#[must_use]
pub fn is_configured_value(value: &str) -> bool {
    let v = value.trim();
    if v.is_empty() || v.chars().any(char::is_control) {
        return false;
    }
    let lower = v.to_ascii_lowercase();
    let placeholder_words = [
        "changeme",
        "change_me",
        "your_key",
        "your-key",
        "todo",
        "null",
        "none",
    ];
    if placeholder_words.contains(&lower.as_str()) {
        return false;
    }
    if (lower.starts_with("insert_") || lower.starts_with("your_") || lower.starts_with("your-"))
        && (lower.ends_with("_here") || lower.ends_with("-here"))
    {
        return false;
    }
    if (lower.starts_with('<') && lower.ends_with('>'))
        || (lower.starts_with("${") && lower.ends_with('}'))
    {
        return false;
    }
    // "xxxx", "****", "....": one repeated filler character, four or more times.
    let mut chars = lower.chars();
    if let Some(first) = chars.next() {
        if matches!(first, 'x' | '*' | '.' | '-' | '_' | '0')
            && v.len() >= 4
            && chars.all(|c| c == first)
        {
            return false;
        }
    }
    true
}

/// A credential value. No `Display`, no `Serialize`, no `PartialEq`.
#[derive(Clone)]
pub struct Secret(String);

impl Secret {
    /// # Errors
    /// `Error::Invalid` for blank/placeholder values and for control characters,
    /// which would allow header injection.
    pub fn new(value: impl Into<String>) -> Result<Self, Error> {
        let value = value.into();
        if !is_configured_value(&value) {
            return Err(Error::Invalid(
                "credential is blank or a placeholder".into(),
            ));
        }
        Ok(Self(value.trim().to_owned()))
    }

    /// The only way to read the value; call it where it is sent, nowhere else.
    #[must_use]
    pub fn expose(&self) -> &str {
        &self.0
    }

    #[must_use]
    pub fn fingerprint(&self) -> CredentialFingerprint {
        CredentialFingerprint::of_secret(&self.0)
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Secret({:?})", self.fingerprint())
    }
}

/// Slot names are environment-variable shaped so they cannot smuggle separators.
#[must_use]
pub fn valid_slot(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name.starts_with(|c: char| c.is_ascii_uppercase())
        && name
            .chars()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
}

/// Parsed keys file plus an environment fallback.
#[derive(Default)]
pub struct Keys {
    entries: BTreeMap<String, Secret>,
    use_env: bool,
}

impl Keys {
    /// Environment only.
    #[must_use]
    pub fn from_env() -> Self {
        Self {
            entries: BTreeMap::new(),
            use_env: true,
        }
    }

    /// Parse `NAME=value` lines. Accepts `export NAME=value`, single or double
    /// quotes, blank lines and `#` comments. A later line overrides an earlier one.
    /// Placeholder values are skipped, not stored.
    ///
    /// # Errors
    /// `Error::Invalid` (line number only, never the value) for a line that is not
    /// `NAME=value` or whose name is not a valid slot.
    pub fn parse(text: &str) -> Result<Self, Error> {
        let mut entries = BTreeMap::new();
        for (idx, raw) in text.lines().enumerate() {
            let line = raw.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let line = line.strip_prefix("export ").map_or(line, str::trim_start);
            let Some((name, value)) = line.split_once('=') else {
                return Err(Error::Invalid(format!(
                    "keys line {}: expected NAME=value",
                    idx + 1
                )));
            };
            let name = name.trim();
            if !valid_slot(name) {
                return Err(Error::Invalid(format!(
                    "keys line {}: bad slot name",
                    idx + 1
                )));
            }
            let value = unquote(value.trim());
            if let Ok(secret) = Secret::new(value) {
                entries.insert(name.to_owned(), secret);
            } else {
                entries.remove(name);
            }
        }
        Ok(Self {
            entries,
            use_env: false,
        })
    }

    /// Load a keys file, falling back to the environment for slots it lacks.
    /// On Unix a file readable by group or others is refused: fix with `chmod 600`.
    ///
    /// # Errors
    /// `Error::Store` for I/O problems or loose permissions; `Error::Invalid` for
    /// malformed content.
    pub fn load(path: &Path) -> Result<Self, Error> {
        if let Some(mode) = loose_mode(path)? {
            return Err(Error::Store(format!(
                "{} is accessible by group/others (mode {mode:o}); run chmod 600",
                path.display()
            )));
        }
        Self::from_file_bytes(read_bounded(path, MAX_KEYS_FILE_BYTES)?)
    }

    /// The file half of [`Keys::load`]: UTF-8 check, [`Keys::parse`], environment
    /// fallback on. Shared by `--keys` and the default file.
    fn from_file_bytes(bytes: Vec<u8>) -> Result<Self, Error> {
        let text = String::from_utf8(bytes)
            .map_err(|_| Error::Invalid("keys file is not utf-8".into()))?;
        let mut keys = Self::parse(&text)?;
        keys.use_env = true;
        Ok(keys)
    }

    /// Keys for a command run.
    ///
    /// With `explicit` (`--keys FILE`) this is exactly [`Keys::load`] on that path
    /// and the default file is not read. Otherwise `$HOME/.huntsman.env` is parsed
    /// with the same parser when it exists and passes the default-file gate. If it
    /// does not exist, or `home` is unset, the result is [`Keys::from_env`], as
    /// before the default file existed.
    ///
    /// The gate decides on `lstat` (the path is never followed): a symlink, a
    /// non-regular file, a file owned by another uid, a file accessible by group
    /// or others (`mode & 0o077 != 0`), or an undeterminable current uid is not
    /// read. The result is then [`Keys::from_env`] plus one warning naming the path
    /// and the reason. The file is read through the descriptor that was opened,
    /// after checking it is the same inode `lstat` saw and re-checking the gate on
    /// it, so a swap between check and read is refused rather than followed.
    ///
    /// Precedence is that of [`Keys::load`]: a slot in the file wins over the same
    /// variable in the process environment; slots the file lacks fall back to it.
    ///
    /// # Errors
    /// As [`Keys::load`] for the `--keys` file; for the default file, I/O errors
    /// other than "not found" and malformed content.
    pub fn resolve(explicit: Option<&Path>, home: Option<&OsStr>) -> Result<ResolvedKeys, Error> {
        if let Some(path) = explicit {
            return Ok(ResolvedKeys {
                keys: Self::load(path)?,
                warning: None,
            });
        }
        let env_only = |warning| ResolvedKeys {
            keys: Self::from_env(),
            warning,
        };
        let Some(path) = default_keys_path(home) else {
            return Ok(env_only(None));
        };
        match load_default_file(&path)? {
            None => Ok(env_only(None)),
            Some(Err(refusal)) => Ok(env_only(Some(format!(
                "warning: not loading {}: {}",
                path.display(),
                refusal.reason()
            )))),
            Some(Ok(keys)) => Ok(ResolvedKeys {
                keys,
                warning: None,
            }),
        }
    }

    /// File entry first, then the environment. Blank or placeholder values read as
    /// absent, so "not configured" is a single state.
    #[must_use]
    pub fn get(&self, slot: &str) -> Option<Secret> {
        if !valid_slot(slot) {
            return None;
        }
        if let Some(s) = self.entries.get(slot) {
            return Some(s.clone());
        }
        if self.use_env {
            return env::var(slot).ok().and_then(|v| Secret::new(v).ok());
        }
        None
    }

    /// Slot names present in the file (never values), for `doctor`-style listings.
    #[must_use]
    pub fn slots(&self) -> Vec<&str> {
        self.entries.keys().map(String::as_str).collect()
    }
}

impl fmt::Debug for Keys {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Keys")
            .field("slots", &self.slots())
            .finish_non_exhaustive()
    }
}

/// Why `$HOME/.huntsman.env` was not read. Carries metadata only, never content.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DefaultFileRefusal {
    Symlink,
    NotRegularFile,
    ForeignOwner { file_uid: u32, current_uid: u32 },
    UnknownCurrentUser,
    LoosePermissions { mode: u32 },
    ChangedWhileOpening,
}

impl DefaultFileRefusal {
    fn reason(self) -> String {
        match self {
            Self::Symlink => format!(
                "it is a symlink; replace it with a regular file (`chmod 600 ~/{DEFAULT_KEYS_FILE}`) or pass --keys"
            ),
            Self::NotRegularFile => "it is not a regular file".to_owned(),
            Self::ForeignOwner {
                file_uid,
                current_uid,
            } => format!(
                "it is owned by uid {file_uid}, not the current uid {current_uid}; recreate it as the current user"
            ),
            Self::UnknownCurrentUser => {
                "the current uid cannot be determined, so ownership cannot be checked; pass --keys"
                    .to_owned()
            }
            Self::LoosePermissions { mode } => format!(
                "mode {mode:o} is accessible by group/others; fix with `chmod 600 ~/{DEFAULT_KEYS_FILE}`"
            ),
            Self::ChangedWhileOpening => "it changed between the check and the open".to_owned(),
        }
    }
}

/// The metadata the default-file gate decides on, taken from `lstat` or `fstat`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FileFacts {
    is_symlink: bool,
    is_file: bool,
    /// Permission bits (`mode & 0o777`); `0o600` off Unix.
    mode: u32,
    /// Owner uid; `None` off Unix, where there is no uid to compare.
    uid: Option<u32>,
}

impl FileFacts {
    fn of(meta: &Metadata) -> Self {
        #[cfg(unix)]
        let (mode, uid) = {
            use std::os::unix::fs::MetadataExt;
            (meta.mode() & 0o777, Some(meta.uid()))
        };
        #[cfg(not(unix))]
        let (mode, uid) = (0o600, None);
        Self {
            is_symlink: meta.file_type().is_symlink(),
            is_file: meta.is_file(),
            mode,
            uid,
        }
    }
}

/// The default-file gate. `current_uid` is the effective uid of this process
/// (`None` when it cannot be determined); it is only consulted on Unix.
fn default_file_refusal(facts: &FileFacts, current_uid: Option<u32>) -> Option<DefaultFileRefusal> {
    if facts.is_symlink {
        return Some(DefaultFileRefusal::Symlink);
    }
    if !facts.is_file {
        return Some(DefaultFileRefusal::NotRegularFile);
    }
    if let Some(file_uid) = facts.uid {
        match current_uid {
            None => return Some(DefaultFileRefusal::UnknownCurrentUser),
            Some(current_uid) if current_uid != file_uid => {
                return Some(DefaultFileRefusal::ForeignOwner {
                    file_uid,
                    current_uid,
                });
            }
            Some(_) => {}
        }
    }
    if facts.mode & 0o077 != 0 {
        return Some(DefaultFileRefusal::LoosePermissions { mode: facts.mode });
    }
    None
}

/// Effective uid from `/proc/self/status` (Linux, Android/Termux). `None` where
/// procfs is unavailable, which makes the default-file gate refuse.
#[cfg(unix)]
fn current_uid() -> Option<u32> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    let uids = status.lines().find_map(|line| line.strip_prefix("Uid:"))?;
    uids.split_whitespace().nth(1)?.parse().ok()
}

#[cfg(not(unix))]
fn current_uid() -> Option<u32> {
    None
}

/// `None` when `path` does not exist; otherwise the parsed file or the refusal.
fn load_default_file(path: &Path) -> Result<Option<Result<Keys, DefaultFileRefusal>>, Error> {
    let store = |e: std::io::Error| Error::Store(format!("{}: {e}", path.display()));
    let linked = match std::fs::symlink_metadata(path) {
        Ok(meta) => meta,
        Err(e) if matches!(e.kind(), ErrorKind::NotFound | ErrorKind::NotADirectory) => {
            return Ok(None);
        }
        Err(e) => return Err(store(e)),
    };
    let uid = current_uid();
    if let Some(refusal) = default_file_refusal(&FileFacts::of(&linked), uid) {
        return Ok(Some(Err(refusal)));
    }
    let file = match File::open(path) {
        Ok(file) => file,
        Err(e) if e.kind() == ErrorKind::NotFound => {
            return Ok(Some(Err(DefaultFileRefusal::ChangedWhileOpening)));
        }
        Err(e) => return Err(store(e)),
    };
    let opened = file.metadata().map_err(store)?;
    if !same_inode(&linked, &opened) {
        return Ok(Some(Err(DefaultFileRefusal::ChangedWhileOpening)));
    }
    if let Some(refusal) = default_file_refusal(&FileFacts::of(&opened), uid) {
        return Ok(Some(Err(refusal)));
    }
    let mut bytes = Vec::new();
    file.take(MAX_KEYS_FILE_BYTES.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(store)?;
    if bytes.len() as u64 > MAX_KEYS_FILE_BYTES {
        return Err(Error::Store(format!(
            "{}: exceeds {MAX_KEYS_FILE_BYTES} bytes",
            path.display()
        )));
    }
    Keys::from_file_bytes(bytes).map(|keys| Some(Ok(keys)))
}

/// Did `open` reach the inode `lstat` described (not a replacement or a link)?
#[cfg(unix)]
fn same_inode(linked: &Metadata, opened: &Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    (linked.dev(), linked.ino()) == (opened.dev(), opened.ino())
}

#[cfg(not(unix))]
fn same_inode(_linked: &Metadata, _opened: &Metadata) -> bool {
    true
}

/// The permission bits (`mode & 0o777`) when group or others have any access to
/// `path`, `None` when it is private. Always `None` off Unix.
#[cfg(unix)]
fn loose_mode(path: &Path) -> Result<Option<u32>, Error> {
    use std::os::unix::fs::PermissionsExt;
    let mode = std::fs::metadata(path)
        .map_err(|e| Error::Store(format!("{}: {e}", path.display())))?
        .permissions()
        .mode();
    Ok((mode & 0o077 != 0).then_some(mode & 0o777))
}

#[cfg(not(unix))]
#[allow(clippy::unnecessary_wraps)]
fn loose_mode(_path: &Path) -> Result<Option<u32>, Error> {
    Ok(None)
}

fn unquote(v: &str) -> &str {
    for q in ['"', '\''] {
        if v.len() >= 2 && v.starts_with(q) && v.ends_with(q) {
            return &v[1..v.len() - 1];
        }
    }
    // An unquoted trailing " # comment" is a comment.
    v.split_once(" #").map_or(v, |(a, _)| a.trim_end())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blanks_and_placeholders_are_not_configured() {
        for v in [
            "",
            "   ",
            "\t\n",
            "insert_api_key_here",
            "INSERT_TOKEN_HERE",
            "your_key_here",
            "your-api-key-here",
            "<your key>",
            "${SHODAN_KEY}",
            "changeme",
            "xxxxxxxx",
            "********",
            "0000",
            "null",
            "with\ncontrol",
        ] {
            assert!(!is_configured_value(v), "{v:?}");
        }
        for v in ["k3y-8f2a91", "abcd1234", "xoxb-1234", "0123", "a"] {
            assert!(is_configured_value(v), "{v:?}");
        }
    }

    #[test]
    fn secret_never_prints_its_value() {
        let s = Secret::new("super-secret-value-1").expect("secret");
        let shown = format!("{s:?}");
        assert!(!shown.contains("super-secret"));
        assert!(shown.starts_with("Secret(CredentialFingerprint("));
        assert_eq!(s.expose(), "super-secret-value-1");
        assert_eq!(
            s.fingerprint(),
            Secret::new("super-secret-value-1")
                .expect("s")
                .fingerprint()
        );
        assert!(Secret::new("insert_key_here").is_err());
        assert!(Secret::new("a\r\nX-Evil: 1").is_err(), "header injection");
    }

    #[test]
    fn keys_file_syntax() {
        let k = Keys::parse(
            "# comment\n\nexport A_KEY=\"quoted value\"\nB_KEY = 'single'\nC_KEY=plain # trailing\n\
             D_KEY=insert_key_here\nA_KEY=\"override\"\n",
        )
        .expect("parse");
        assert_eq!(k.get("A_KEY").expect("a").expose(), "override");
        assert_eq!(k.get("B_KEY").expect("b").expose(), "single");
        assert_eq!(k.get("C_KEY").expect("c").expose(), "plain");
        assert!(k.get("D_KEY").is_none(), "placeholder reads as absent");
        assert_eq!(k.slots(), ["A_KEY", "B_KEY", "C_KEY"]);
        let shown = format!("{k:?}");
        assert!(!shown.contains("override") && shown.contains("A_KEY"));
    }

    #[test]
    fn a_placeholder_line_unsets_an_earlier_real_value() {
        let k = Keys::parse("A_KEY=real-value-1\nA_KEY=insert_here\n").expect("parse");
        assert!(k.get("A_KEY").is_none());
    }

    #[test]
    fn malformed_lines_report_line_numbers_not_values() {
        let err = Keys::parse("OK_KEY=value1\nthis is not a pair secretword\n").expect_err("bad");
        let msg = err.to_string();
        assert!(msg.contains("line 2") && !msg.contains("secretword"));
        assert!(Keys::parse("lowercase=value1\n").is_err());
        assert!(Keys::parse("BAD NAME=value1\n").is_err());
        assert!(Keys::parse("A=b\n").is_ok());
    }

    #[test]
    fn slot_names_are_constrained() {
        assert!(valid_slot("SHODAN_API_KEY"));
        for s in ["", "lower", "1ABC", "A-B", "A B", "A=B", &"A".repeat(65)] {
            assert!(!valid_slot(s), "{s:?}");
        }
        assert!(Keys::default().get("bad slot").is_none());
    }

    #[test]
    fn environment_is_a_fallback_only_when_enabled() {
        // PATH is set in every test environment and is a valid-looking slot name.
        assert!(Keys::default().get("PATH").is_none());
        assert!(Keys::from_env().get("PATH").is_some());
        assert!(
            Keys::from_env()
                .get("HUNTSMAN_SURELY_UNSET_SLOT_9")
                .is_none()
        );
    }

    /// A fresh `$HOME` stand-in; never the real home directory.
    fn fake_home(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("huntsman-keys-home-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("dir");
        dir
    }

    #[cfg(unix)]
    fn write_mode(path: &Path, text: &str, mode: u32) {
        use std::os::unix::fs::PermissionsExt;
        std::fs::write(path, text).expect("write");
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).expect("chmod");
    }

    #[test]
    fn default_path_needs_a_home() {
        assert_eq!(default_keys_path(None), None);
        assert_eq!(default_keys_path(Some(OsStr::new(""))), None);
        assert_eq!(
            default_keys_path(Some(OsStr::new("/h"))),
            Some(PathBuf::from("/h/.huntsman.env"))
        );
    }

    #[test]
    fn missing_default_file_is_environment_only_and_silent() {
        let home = fake_home("missing");
        for h in [Some(home.as_os_str()), None] {
            let resolved = Keys::resolve(None, h).expect("resolve");
            assert!(resolved.warning.is_none());
            assert_eq!(resolved.keys.slots(), [] as [&str; 0]);
            assert!(resolved.keys.get("PATH").is_some(), "env fallback kept");
        }
        std::fs::remove_dir_all(&home).expect("cleanup");
    }

    #[cfg(unix)]
    #[test]
    fn private_default_file_is_loaded() {
        let home = fake_home("private");
        write_mode(
            &home.join(DEFAULT_KEYS_FILE),
            "HSE_TEST_DEFAULT_KEY=TEST_ONLY_VALUE_DEFAULT\n",
            0o600,
        );
        let resolved = Keys::resolve(None, Some(home.as_os_str())).expect("resolve");
        assert!(resolved.warning.is_none());
        assert_eq!(
            resolved
                .keys
                .get("HSE_TEST_DEFAULT_KEY")
                .expect("slot")
                .expose(),
            "TEST_ONLY_VALUE_DEFAULT"
        );
        assert!(resolved.keys.get("PATH").is_some(), "env fallback kept");
        std::fs::remove_dir_all(&home).expect("cleanup");
    }

    #[cfg(unix)]
    #[test]
    fn readable_default_file_is_skipped_with_a_valueless_warning() {
        let home = fake_home("loose");
        let path = home.join(DEFAULT_KEYS_FILE);
        for mode in [0o644, 0o640, 0o604, 0o660] {
            write_mode(&path, "HSE_TEST_LOOSE_KEY=TEST_ONLY_VALUE_LOOSE\n", mode);
            let resolved = Keys::resolve(None, Some(home.as_os_str())).expect("resolve");
            assert_eq!(resolved.keys.slots(), [] as [&str; 0], "{mode:o}");
            assert!(resolved.keys.get("HSE_TEST_LOOSE_KEY").is_none());
            let warning = resolved.warning.expect("warning");
            assert!(warning.contains(&path.display().to_string()), "{warning}");
            assert!(warning.contains("chmod 600 ~/.huntsman.env"), "{warning}");
            assert!(warning.contains("accessible by group/others"), "{warning}");
            assert!(!warning.contains("TEST_ONLY_VALUE"), "{warning}");
            assert!(!warning.contains("HSE_TEST_LOOSE_KEY"), "{warning}");
        }
        std::fs::remove_dir_all(&home).expect("cleanup");
    }

    const PRIVATE_FILE: FileFacts = FileFacts {
        is_symlink: false,
        is_file: true,
        mode: 0o600,
        uid: Some(1000),
    };

    #[test]
    fn gate_accepts_a_private_regular_file_owned_by_the_current_uid() {
        assert_eq!(default_file_refusal(&PRIVATE_FILE, Some(1000)), None);
    }

    #[test]
    fn gate_refuses_a_file_owned_by_another_uid() {
        assert_eq!(
            default_file_refusal(&PRIVATE_FILE, Some(1001)),
            Some(DefaultFileRefusal::ForeignOwner {
                file_uid: 1000,
                current_uid: 1001
            })
        );
        let root_owned = FileFacts {
            uid: Some(0),
            ..PRIVATE_FILE
        };
        assert!(matches!(
            default_file_refusal(&root_owned, Some(1000)),
            Some(DefaultFileRefusal::ForeignOwner { file_uid: 0, .. })
        ));
        let reason = DefaultFileRefusal::ForeignOwner {
            file_uid: 0,
            current_uid: 1000,
        }
        .reason();
        assert!(
            reason.contains("uid 0") && reason.contains("uid 1000"),
            "{reason}"
        );
    }

    #[test]
    fn gate_refuses_symlinks_non_files_unknown_users_and_loose_modes() {
        let link = FileFacts {
            is_symlink: true,
            is_file: false,
            ..PRIVATE_FILE
        };
        assert_eq!(
            default_file_refusal(&link, Some(1000)),
            Some(DefaultFileRefusal::Symlink)
        );
        let dir = FileFacts {
            is_file: false,
            ..PRIVATE_FILE
        };
        assert_eq!(
            default_file_refusal(&dir, Some(1000)),
            Some(DefaultFileRefusal::NotRegularFile)
        );
        assert_eq!(
            default_file_refusal(&PRIVATE_FILE, None),
            Some(DefaultFileRefusal::UnknownCurrentUser)
        );
        for mode in [0o644, 0o640, 0o604, 0o620, 0o610, 0o601, 0o700 | 0o070] {
            let loose = FileFacts {
                mode,
                ..PRIVATE_FILE
            };
            assert_eq!(
                default_file_refusal(&loose, Some(1000)),
                Some(DefaultFileRefusal::LoosePermissions { mode }),
                "{mode:o}"
            );
        }
        for mode in [0o600, 0o400, 0o700] {
            let tight = FileFacts {
                mode,
                ..PRIVATE_FILE
            };
            assert_eq!(default_file_refusal(&tight, Some(1000)), None, "{mode:o}");
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn current_uid_matches_the_owner_of_a_new_file() {
        use std::os::unix::fs::MetadataExt;
        let home = fake_home("uid");
        let path = home.join("probe");
        std::fs::write(&path, "x").expect("write");
        let owner = std::fs::metadata(&path).expect("meta").uid();
        assert_eq!(current_uid(), Some(owner));
        std::fs::remove_dir_all(&home).expect("cleanup");
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_default_file_is_refused_even_to_a_private_file() {
        let home = fake_home("symlink");
        let target = home.join("real.env");
        write_mode(&target, "HSE_TEST_LINK_KEY=TEST_ONLY_VALUE_LINK\n", 0o600);
        let path = home.join(DEFAULT_KEYS_FILE);
        std::os::unix::fs::symlink(&target, &path).expect("symlink");
        let resolved = Keys::resolve(None, Some(home.as_os_str())).expect("resolve");
        assert_eq!(resolved.keys.slots(), [] as [&str; 0]);
        assert!(resolved.keys.get("HSE_TEST_LINK_KEY").is_none());
        let warning = resolved.warning.expect("warning");
        assert!(warning.contains(&path.display().to_string()), "{warning}");
        assert!(warning.contains("symlink"), "{warning}");
        assert!(!warning.contains("TEST_ONLY_VALUE"), "{warning}");
        assert!(
            !warning.contains(&target.display().to_string()),
            "{warning}"
        );
        std::fs::remove_dir_all(&home).expect("cleanup");
    }

    #[cfg(unix)]
    #[test]
    fn directory_at_default_path_is_refused_with_a_warning() {
        let home = fake_home("dir");
        std::fs::create_dir(home.join(DEFAULT_KEYS_FILE)).expect("dir");
        let resolved = Keys::resolve(None, Some(home.as_os_str())).expect("resolve");
        assert!(
            resolved
                .warning
                .expect("warning")
                .contains("not a regular file")
        );
        std::fs::remove_dir_all(&home).expect("cleanup");
    }

    #[cfg(unix)]
    #[test]
    fn explicit_file_replaces_the_default_file() {
        let home = fake_home("explicit");
        write_mode(
            &home.join(DEFAULT_KEYS_FILE),
            "HSE_TEST_DEFAULT_ONLY=TEST_ONLY_VALUE_DEFAULT\n",
            0o644,
        );
        let explicit = home.join("explicit.env");
        write_mode(
            &explicit,
            "HSE_TEST_EXPLICIT=TEST_ONLY_VALUE_EXPLICIT\n",
            0o600,
        );
        let resolved = Keys::resolve(Some(&explicit), Some(home.as_os_str())).expect("resolve");
        assert!(resolved.warning.is_none(), "default file not inspected");
        assert_eq!(resolved.keys.slots(), ["HSE_TEST_EXPLICIT"]);
        assert!(resolved.keys.get("HSE_TEST_DEFAULT_ONLY").is_none());
        // `--keys` keeps its own behaviour, including the hard permission error.
        write_mode(
            &explicit,
            "HSE_TEST_EXPLICIT=TEST_ONLY_VALUE_EXPLICIT\n",
            0o644,
        );
        let err = Keys::resolve(Some(&explicit), Some(home.as_os_str())).expect_err("loose");
        assert!(err.to_string().contains("chmod 600"));
        std::fs::remove_dir_all(&home).expect("cleanup");
    }

    #[cfg(unix)]
    #[test]
    fn loose_permissions_are_refused_and_tight_ones_load() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("huntsman-keys-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("dir");
        let path = dir.join("keys.env");
        std::fs::write(&path, "T_KEY=value-12345\n").expect("write");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).expect("chmod");
        let err = Keys::load(&path).expect_err("loose");
        assert!(err.to_string().contains("chmod 600"));
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).expect("chmod");
        let k = Keys::load(&path).expect("tight");
        assert_eq!(k.get("T_KEY").expect("t").expose(), "value-12345");
        std::fs::remove_dir_all(&dir).expect("cleanup");
    }
}
