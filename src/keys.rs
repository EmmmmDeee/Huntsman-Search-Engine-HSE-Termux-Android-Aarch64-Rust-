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
use std::ffi::OsStr;
use std::fmt;
use std::fs::Metadata;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, PoisonError};

use crate::credential_origin::CredentialFingerprint;
use crate::environment;
use crate::error::Error;
use crate::fsio::{
    CHANGED_WHILE_OPENING, NOT_REGULAR_FILE, read_bounded, read_to_bound, same_inode, store_err,
    write_atomic_private,
};

pub(crate) const MAX_KEYS_FILE_BYTES: u64 = 64 * 1024;

/// The longest key [`store_slot`] writes. Provider keys and tokens are far shorter.
pub const MAX_KEY_BYTES: usize = 4096;

/// Keys file read from `$HOME` when no `--keys FILE` is given.
pub const DEFAULT_KEYS_FILE: &str = ".huntsman.env";

/// `$HOME/.huntsman.env`, or `None` when `home` is unset, empty or relative. A
/// relative `HOME` would make the default file depend on the working directory.
#[must_use]
pub fn default_keys_path(home: Option<&OsStr>) -> Option<PathBuf> {
    let home = Path::new(home?);
    home.is_absolute().then(|| home.join(DEFAULT_KEYS_FILE))
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
            let Some(line) = statement(raw) else {
                continue;
            };
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
    /// before the default file existed. An empty or relative `home` also gives
    /// [`Keys::from_env`], plus one warning that does not print the `HOME` value.
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
        let Some(home) = home else {
            return Ok(env_only(None));
        };
        let Some(path) = default_keys_path(Some(home)) else {
            return Ok(env_only(Some(format!(
                "warning: not loading ~/{DEFAULT_KEYS_FILE}: HOME is not an absolute path"
            ))));
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

    /// The keys a lookup uses: the ones `credential-status` reports, read by
    /// [`Keys::resolve`] from `$HOME/.huntsman.env` (when it passes the default-file gate)
    /// and the process environment. A configured key is never left unused because it sits in
    /// the file instead of the environment. A file that cannot be read or parsed does not stop
    /// the lookup: the result is then [`Keys::from_env`] and a warning that names the error,
    /// never a value.
    #[must_use]
    pub fn for_lookup(home: Option<&OsStr>) -> ResolvedKeys {
        Self::resolve(None, home).unwrap_or_else(|error| ResolvedKeys {
            keys: Self::from_env(),
            warning: Some(format!(
                "warning: not loading ~/{DEFAULT_KEYS_FILE}: {error}"
            )),
        })
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
            return environment::variable(slot).and_then(|v| Secret::new(v).ok());
        }
        None
    }

    /// Resolve one of the two provider slots that accept the same operator-issued
    /// abuse.ch Auth-Key. The explicitly configured slot always takes precedence.
    /// A fallback is read only when its paired slot is absent; no secret is copied
    /// to persistent storage.
    #[must_use]
    pub fn provider_key(&self, slot: &str) -> Option<Secret> {
        self.get(slot).or_else(|| {
            let other = match slot {
                environment::THREATFOX_KEY_ENV => environment::ABUSECH_KEY_ENV,
                environment::ABUSECH_KEY_ENV => environment::THREATFOX_KEY_ENV,
                _ => return None,
            };
            self.get(other)
        })
    }

    /// A runtime setting kept beside the keys, by the chain [`Self::get`] reads: the file's value,
    /// else the environment's when this `Keys` reads it. A setting is not a credential, so the
    /// environment's text is returned as it is, however it is shaped; only a value that is not
    /// UTF-8 is `None`.
    #[must_use]
    pub fn setting(&self, slot: &str) -> Option<String> {
        if !valid_slot(slot) {
            return None;
        }
        if let Some(value) = self.entries.get(slot) {
            return Some(value.expose().to_owned());
        }
        if self.use_env {
            return environment::variable(slot);
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
pub(crate) enum DefaultFileRefusal {
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
            Self::Symlink => "it is a symlink; remove the symlink and create a regular file \
                 owned by you with mode 600"
                .to_owned(),
            Self::NotRegularFile => format!("it is {NOT_REGULAR_FILE}"),
            Self::ForeignOwner {
                file_uid,
                current_uid,
            } => format!(
                "it is owned by uid {file_uid}, not the current uid {current_uid}; recreate it as the current user"
            ),
            Self::UnknownCurrentUser => "the current uid cannot be determined, so ownership \
                 cannot be checked; set the keys in the environment instead"
                .to_owned(),
            Self::LoosePermissions { mode } => format!(
                "mode {mode:o} is accessible by group/others; fix with `chmod 600 ~/{DEFAULT_KEYS_FILE}`"
            ),
            Self::ChangedWhileOpening => format!("it {CHANGED_WHILE_OPENING}"),
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
///
/// The open is [`fsio::open_unfollowed`](crate::fsio::open_unfollowed): on Linux and Android, on
/// the architectures whose flag values it knows, it neither follows a symlink nor blocks on a FIFO
/// swapped in after `lstat`. The opened descriptor must still be the inode `lstat` saw and pass
/// the gate again.
fn load_default_file(path: &Path) -> Result<Option<Result<Keys, DefaultFileRefusal>>, Error> {
    match read_private_file(path, MAX_KEYS_FILE_BYTES)? {
        None => Ok(None),
        Some(Err(refusal)) => Ok(Some(Err(refusal))),
        Some(Ok(bytes)) => Keys::from_file_bytes(bytes).map(|keys| Some(Ok(keys))),
    }
}

/// The shared private-file gate for every on-disk secret (the keys file, the
/// HIBP and `DeHashed` `api_key` files): refuses a symlink, a non-regular file, a
/// file owned by another uid, an unknown current uid, or group/other mode bits,
/// re-checking the opened descriptor against the `lstat`ed inode.
///
/// `Ok(None)` when `path` does not exist. A refusal carries metadata only, never
/// file content, so it is safe to print.
pub(crate) fn read_private_file(
    path: &Path,
    max: u64,
) -> Result<Option<Result<Vec<u8>, DefaultFileRefusal>>, Error> {
    read_private_file_with(path, max, || {})
}

/// [`read_private_file`], running `after_check` between the `lstat` gate and the open.
fn read_private_file_with(
    path: &Path,
    max: u64,
    after_check: impl FnOnce(),
) -> Result<Option<Result<Vec<u8>, DefaultFileRefusal>>, Error> {
    let store = |e: std::io::Error| store_err(path, &e);
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
    after_check();
    let file = match crate::fsio::open_unfollowed(path) {
        Ok(file) => file,
        Err(e) if e.kind() == ErrorKind::NotFound || crate::fsio::is_refused_link(&e) => {
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
    read_to_bound(path, file, max).map(|bytes| Some(Ok(bytes)))
}

/// A keys-file line as [`Keys::parse`] reads it: `None` for a blank or `#` comment line, otherwise
/// the line trimmed and without a leading `export `.
fn statement(raw: &str) -> Option<&str> {
    let line = raw.trim();
    if line.is_empty() || line.starts_with('#') {
        return None;
    }
    Some(line.strip_prefix("export ").map_or(line, str::trim_start))
}

/// Whether a keys-file line sets `slot`.
fn assigns(raw: &str, slot: &str) -> bool {
    statement(raw)
        .and_then(|line| line.split_once('='))
        .is_some_and(|(name, _)| name.trim() == slot)
}

/// `SLOT='value'`: single quotes keep the value whole for [`Keys::parse`], and keep a shell that
/// sources the file from expanding it. A value holding a single quote is double-quoted when a
/// shell would not expand it there either.
fn key_line(slot: &str, value: &str) -> Result<String, Error> {
    if !value.contains('\'') {
        return Ok(format!("{slot}='{value}'"));
    }
    if !value.contains(['"', '$', '`', '\\']) {
        return Ok(format!("{slot}=\"{value}\""));
    }
    Err(Error::Invalid(
        "a key holding a single quote and a shell character cannot be saved here; \
         add it to the keys file by hand"
            .into(),
    ))
}

/// The keys file's text before [`store_slots`] rewrites it, or nothing when there is no file. A
/// file the default-file gate refuses is left alone, except one that is only too open: the
/// rewrite leaves it mode 600, and lookups read it again.
fn read_for_rewrite(path: &Path) -> Result<String, Error> {
    let bytes = match read_private_file(path, MAX_KEYS_FILE_BYTES)? {
        None => return Ok(String::new()),
        Some(Ok(bytes)) => bytes,
        Some(Err(DefaultFileRefusal::LoosePermissions { .. })) => {
            read_bounded(path, MAX_KEYS_FILE_BYTES)?
        }
        Some(Err(refusal)) => {
            return Err(Error::Store(format!(
                "not changing {}: {}",
                path.display(),
                refusal.reason()
            )));
        }
    };
    String::from_utf8(bytes).map_err(|_| Error::Invalid("keys file is not utf-8".into()))
}

/// Sets `slot` to `value` in the keys file at `path`, or removes it when `value` is `None`, and
/// keeps every other line as it was: [`store_slots`] with one change.
///
/// # Errors
/// As [`store_slots`].
pub fn store_slot(path: &Path, slot: &str, value: Option<&str>) -> Result<(), Error> {
    store_slots(path, &[(slot, value)])
}

/// Applies `changes` to the keys file at `path` in one rewrite: each sets its slot to the value,
/// or removes the slot when the value is `None`, and a later change to a slot replaces an earlier
/// one. Every other line stays as it was. The first line that set a slot takes its new value and
/// any later one goes, since a later line would override it; a slot no line set is appended, in
/// the order of `changes`. The result must read back through [`Keys::parse`] with exactly these
/// values (and without the removed slots) before it replaces the file, atomically and at mode
/// 600, so a save never leaves a file that lookups would refuse or read differently, and a change
/// that cannot be saved saves nothing. Saves in this process run one at a time, so two never
/// lose each other's keys.
///
/// # Errors
/// `Error::Invalid` for no change, a bad slot name, a blank, placeholder, over-long or
/// unquotable value, or a file whose other lines do not parse (by line number, never a value);
/// `Error::Store` for a file the default-file gate refuses for any reason but loose permissions,
/// or an I/O failure.
pub fn store_slots(path: &Path, changes: &[(&str, Option<&str>)]) -> Result<(), Error> {
    static SAVING: Mutex<()> = Mutex::new(());
    if changes.is_empty() {
        return Err(Error::Invalid("no key to save".into()));
    }
    // Each slot once, at its first change, with its last value and the line that sets it.
    let mut planned: Vec<(&str, Option<Secret>, Option<String>)> = Vec::new();
    for &(slot, value) in changes {
        if !valid_slot(slot) {
            return Err(Error::Invalid("bad slot name".into()));
        }
        let secret = value.map(Secret::new).transpose()?;
        if secret
            .as_ref()
            .is_some_and(|secret| secret.expose().len() > MAX_KEY_BYTES)
        {
            return Err(Error::Invalid(format!(
                "a key is at most {MAX_KEY_BYTES} bytes"
            )));
        }
        let line = secret
            .as_ref()
            .map(|secret| key_line(slot, secret.expose()))
            .transpose()?;
        match planned.iter_mut().find(|(known, _, _)| *known == slot) {
            Some(change) => *change = (slot, secret, line),
            None => planned.push((slot, secret, line)),
        }
    }
    let _saving = SAVING.lock().unwrap_or_else(PoisonError::into_inner);
    let current = read_for_rewrite(path)?;
    let mut text = String::with_capacity(current.len() + 80 * planned.len());
    for raw in current.lines() {
        if let Some((_, _, line)) = planned.iter_mut().find(|(slot, _, _)| assigns(raw, slot)) {
            if let Some(line) = line.take() {
                text.push_str(&line);
                text.push('\n');
            }
            continue;
        }
        text.push_str(raw);
        text.push('\n');
    }
    for line in planned.iter_mut().filter_map(|(_, _, line)| line.take()) {
        text.push_str(&line);
        text.push('\n');
    }
    let reread = Keys::parse(&text)?;
    if planned.iter().any(|(slot, secret, _)| {
        reread.entries.get(*slot).map(Secret::expose) != secret.as_ref().map(Secret::expose)
    }) {
        return Err(Error::Invalid(
            "the key would not read back as written; add it to the keys file by hand".into(),
        ));
    }
    write_atomic_private(path, text.as_bytes(), MAX_KEYS_FILE_BYTES)
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
        let Some(inner) = v.strip_prefix(q) else {
            continue;
        };
        // A quoted value ends at its closing quote, and only a comment may follow that quote.
        if let Some(close) = inner.find(q) {
            let after = &inner[close + q.len_utf8()..];
            if after.is_empty()
                || (after.starts_with(char::is_whitespace) && after.trim_start().starts_with('#'))
            {
                return &inner[..close];
            }
        }
    }
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

    /// A runtime setting rides in the keys file beside the keys and is read by the same chain,
    /// but as text, not as a credential.
    #[test]
    fn a_setting_is_read_from_the_file_as_text() {
        let keys = Keys::parse("HUNTSMAN_CONTINUOUS_TARGETS=example.com;1.1.1.1\n").expect("keys");
        assert_eq!(
            keys.setting("HUNTSMAN_CONTINUOUS_TARGETS").as_deref(),
            Some("example.com;1.1.1.1")
        );
        assert_eq!(
            keys.setting("HUNTSMAN_CONTINUOUS_INTERVAL_MINUTES"),
            None,
            "unset, and a parsed file does not read the environment"
        );
        assert_eq!(keys.setting("not a slot"), None);
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
    fn a_quoted_value_ends_at_its_closing_quote() {
        // A comment after the closing quote is a comment, whatever it holds; a `#` inside the
        // quotes is part of the value.
        for (line, want) in [
            ("A_KEY=\"abcdef1234\"\n", "abcdef1234"),
            ("A_KEY=\"abcdef1234\" # prod\n", "abcdef1234"),
            ("A_KEY='abcdef1234' # prod\n", "abcdef1234"),
            ("A_KEY=\"abcdef1234\"   # \"prod\"\n", "abcdef1234"),
            ("A_KEY=\"abcdef #1234\"\n", "abcdef #1234"),
            ("A_KEY=\"abcdef #1234\" # prod\n", "abcdef #1234"),
            ("A_KEY=abcdef1234 # prod\n", "abcdef1234"),
        ] {
            let keys = Keys::parse(line).expect("parse");
            assert_eq!(keys.get("A_KEY").expect("a").expose(), want, "{line:?}");
        }
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
    fn default_path_needs_an_absolute_home() {
        assert_eq!(default_keys_path(None), None);
        for relative in ["", ".", "relative/dir", " ", "./h"] {
            assert_eq!(
                default_keys_path(Some(OsStr::new(relative))),
                None,
                "{relative:?}"
            );
        }
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
    fn relative_or_empty_home_is_skipped_with_a_short_warning() {
        for home in [".", "relative/dir", ""] {
            let resolved = Keys::resolve(None, Some(OsStr::new(home))).expect("resolve");
            assert_eq!(resolved.keys.slots(), [] as [&str; 0], "{home:?}");
            assert!(resolved.keys.get("PATH").is_some(), "env fallback kept");
            let warning = resolved.warning.expect("warning");
            assert_eq!(
                warning,
                "warning: not loading ~/.huntsman.env: HOME is not an absolute path"
            );
        }
        let unset = Keys::resolve(None, None).expect("resolve");
        assert!(unset.warning.is_none(), "unset HOME stays silent");
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
    fn a_lookup_uses_a_key_set_only_in_the_default_file() {
        let home = fake_home("lookup");
        write_mode(
            &home.join(DEFAULT_KEYS_FILE),
            "HSE_TEST_LOOKUP_KEY=TEST_ONLY_VALUE_LOOKUP\n",
            0o600,
        );
        let resolved = Keys::for_lookup(Some(home.as_os_str()));
        assert!(resolved.warning.is_none());
        assert_eq!(
            resolved
                .keys
                .get("HSE_TEST_LOOKUP_KEY")
                .expect("a key in the default file reaches the lookup")
                .expose(),
            "TEST_ONLY_VALUE_LOOKUP"
        );
        assert!(resolved.keys.get("PATH").is_some(), "env fallback kept");
        std::fs::remove_dir_all(&home).expect("cleanup");
    }

    #[cfg(unix)]
    #[test]
    fn a_malformed_default_file_leaves_a_lookup_its_environment_keys() {
        let home = fake_home("lookup-bad");
        write_mode(
            &home.join(DEFAULT_KEYS_FILE),
            "HSE_TEST_BAD=TEST_ONLY_VALUE_BAD\nnot a line\n",
            0o600,
        );
        let resolved = Keys::for_lookup(Some(home.as_os_str()));
        let warning = resolved.warning.expect("the skipped file is named");
        assert!(
            warning.starts_with("warning: not loading ~/.huntsman.env:"),
            "{warning}"
        );
        assert!(!warning.contains("TEST_ONLY_VALUE_BAD"), "{warning}");
        assert_eq!(resolved.keys.slots(), [] as [&str; 0]);
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

    #[test]
    fn a_refusal_never_advises_a_flag_the_printing_command_lacks() {
        // `keys set`, the Settings page and lookups print these and take no `--keys`.
        for refusal in [
            DefaultFileRefusal::Symlink,
            DefaultFileRefusal::NotRegularFile,
            DefaultFileRefusal::UnknownCurrentUser,
            DefaultFileRefusal::ChangedWhileOpening,
        ] {
            assert!(!refusal.reason().contains("--keys"), "{refusal:?}");
        }
        assert!(
            DefaultFileRefusal::UnknownCurrentUser
                .reason()
                .ends_with("; set the keys in the environment instead")
        );
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
        assert!(
            warning.contains("regular file owned by you with mode 600"),
            "{warning}"
        );
        assert!(
            !warning.contains("--keys"),
            "`keys set` and lookups take no --keys: {warning}"
        );
        assert!(
            !warning.contains("chmod"),
            "chmod follows the link: {warning}"
        );
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

    // --- Shared private-file gate (keys file, HIBP and DeHashed api_key files) ---

    const GATE_SECRET: &str = "TEST_ONLY_GATE_SECRET_9f2c";

    fn refusal_text(refusal: DefaultFileRefusal) -> String {
        format!("{refusal:?} {}", refusal.reason())
    }

    #[cfg(unix)]
    #[test]
    fn private_file_gate_accepts_0600() {
        let home = fake_home("gate-0600");
        let path = home.join("api_key");
        write_mode(&path, GATE_SECRET, 0o600);
        let got = read_private_file(&path, 4096).expect("io").expect("exists");
        assert_eq!(got.expect("accepted"), GATE_SECRET.as_bytes());
        std::fs::remove_dir_all(&home).expect("cleanup");
    }

    #[cfg(unix)]
    #[test]
    fn private_file_gate_refuses_0644_without_key_material() {
        let home = fake_home("gate-0644");
        let path = home.join("api_key");
        write_mode(&path, GATE_SECRET, 0o644);
        let refusal = read_private_file(&path, 4096)
            .expect("io")
            .expect("exists")
            .expect_err("0644 must be refused");
        assert_eq!(
            refusal,
            DefaultFileRefusal::LoosePermissions { mode: 0o644 }
        );
        assert!(!refusal_text(refusal).contains(GATE_SECRET));
        std::fs::remove_dir_all(&home).expect("cleanup");
    }

    #[cfg(unix)]
    #[test]
    fn private_file_gate_refuses_symlink_to_private_file_without_key_material() {
        let home = fake_home("gate-symlink");
        let target = home.join("real_key");
        write_mode(&target, GATE_SECRET, 0o600);
        let path = home.join("api_key");
        std::os::unix::fs::symlink(&target, &path).expect("symlink");
        let refusal = read_private_file(&path, 4096)
            .expect("io")
            .expect("exists")
            .expect_err("symlink must be refused");
        assert_eq!(refusal, DefaultFileRefusal::Symlink);
        assert!(!refusal_text(refusal).contains(GATE_SECRET));
        std::fs::remove_dir_all(&home).expect("cleanup");
    }

    /// A private file swapped after the gate is refused without being read or blocking: for a
    /// symlink to another private file and for a FIFO with no writer.
    #[cfg(all(
        any(target_os = "linux", target_os = "android"),
        any(
            target_arch = "aarch64",
            target_arch = "arm",
            target_arch = "powerpc",
            target_arch = "powerpc64",
            target_arch = "x86",
            target_arch = "x86_64",
            target_arch = "riscv64",
            target_arch = "s390x",
            target_arch = "loongarch64"
        )
    ))]
    #[test]
    fn private_file_gate_refuses_a_swap_after_the_check_without_blocking() {
        use std::sync::mpsc;
        use std::time::Duration;

        let home = fake_home("gate-swap");
        let target = home.join("real_key");
        write_mode(&target, GATE_SECRET, 0o600);
        let path = home.join("api_key");
        // Each replacement is made beside the checked file and renamed over it, so its inode
        // differs from the checked one.
        let swaps: [fn(&Path, &Path); 2] = [
            |swapped, target| std::os::unix::fs::symlink(target, swapped).expect("symlink"),
            |swapped, _| {
                let made = std::process::Command::new("mkfifo")
                    .arg(swapped)
                    .status()
                    .expect("mkfifo available on Linux/Termux");
                assert!(made.success(), "mkfifo {}", swapped.display());
            },
        ];
        for swap in swaps {
            write_mode(&path, "TEST_ONLY_CHECKED", 0o600);
            let (answer, answered) = mpsc::channel();
            let (worker_path, worker_target) = (path.clone(), target.clone());
            let worker = std::thread::spawn(move || {
                let result = read_private_file_with(&worker_path, 4096, || {
                    let swapped = worker_path.with_file_name("swapped");
                    swap(&swapped, &worker_target);
                    std::fs::rename(&swapped, &worker_path).expect("rename over the checked file");
                });
                let _ = answer.send(result.map_err(|error| error.to_string()));
            });
            let result = answered
                .recv_timeout(Duration::from_secs(3))
                .expect("the gate must not block on a swapped-in FIFO");
            worker.join().expect("gate worker");
            let refusal = result
                .expect("io")
                .expect("exists")
                .expect_err("a swapped file must be refused");
            assert_eq!(refusal, DefaultFileRefusal::ChangedWhileOpening);
            assert!(!refusal_text(refusal).contains(GATE_SECRET));
            std::fs::remove_file(&path).expect("remove swapped path");
        }
        std::fs::remove_dir_all(&home).expect("cleanup");
    }

    #[test]
    fn private_file_gate_refuses_other_uid_without_key_material() {
        let facts = FileFacts {
            is_symlink: false,
            is_file: true,
            mode: 0o600,
            uid: Some(4242),
        };
        let refusal = default_file_refusal(&facts, Some(1000)).expect("refused");
        assert_eq!(
            refusal,
            DefaultFileRefusal::ForeignOwner {
                file_uid: 4242,
                current_uid: 1000
            }
        );
        assert!(!refusal_text(refusal).contains(GATE_SECRET));
    }

    #[test]
    fn private_file_gate_missing_file_is_none() {
        let home = fake_home("gate-missing");
        assert!(
            read_private_file(&home.join("absent"), 4096)
                .expect("io")
                .is_none()
        );
        std::fs::remove_dir_all(&home).expect("cleanup");
    }

    #[cfg(unix)]
    #[test]
    fn hibp_file_source_uses_the_shared_gate() {
        use crate::hibp::key::{FileSource, KeySource};
        let home = fake_home("gate-hibp");
        let key = "0123456789abcdef0123456789abcdef";
        let ok = home.join("ok_key");
        write_mode(&ok, key, 0o600);
        assert!(FileSource(ok.clone()).load().is_some(), "0600 accepted");
        let loose = home.join("loose_key");
        write_mode(&loose, key, 0o644);
        assert!(FileSource(loose).load().is_none(), "0644 refused");
        let link = home.join("link_key");
        std::os::unix::fs::symlink(&ok, &link).expect("symlink");
        assert!(FileSource(link).load().is_none(), "symlink refused");
        std::fs::remove_dir_all(&home).expect("cleanup");
    }

    #[test]
    fn dehashed_refusal_text_carries_no_key_material() {
        let text = crate::dehashed::client::DehashedError::KeyFilePermissions.to_string();
        assert!(!text.contains(GATE_SECRET));
        assert!(text.contains("0600"), "{text}");
    }

    // --- Saving one key into the keys file ---

    const SAVED_KEY: &str = "TEST_ONLY_SAVED_KEY_7d41";

    fn read_back(path: &Path) -> Keys {
        Keys::parse(&std::fs::read_to_string(path).expect("read")).expect("parses")
    }

    #[cfg(unix)]
    #[test]
    fn a_saved_key_creates_a_private_file_that_reads_back() {
        use std::os::unix::fs::PermissionsExt;
        let home = fake_home("store-new");
        let path = home.join(DEFAULT_KEYS_FILE);
        store_slot(&path, "HUNTSMAN_T_KEY", Some(&format!("  {SAVED_KEY}  "))).expect("saved");
        let mode = std::fs::metadata(&path).expect("meta").permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        assert_eq!(
            std::fs::read_to_string(&path).expect("read"),
            format!("HUNTSMAN_T_KEY='{SAVED_KEY}'\n")
        );
        let resolved = Keys::resolve(None, Some(home.as_os_str())).expect("resolve");
        assert!(resolved.warning.is_none(), "{:?}", resolved.warning);
        assert_eq!(
            resolved.keys.get("HUNTSMAN_T_KEY").expect("set").expose(),
            SAVED_KEY
        );
        std::fs::remove_dir_all(&home).expect("cleanup");
    }

    #[cfg(unix)]
    #[test]
    fn saving_replaces_only_its_own_slot_and_drops_a_later_line_that_would_override_it() {
        let home = fake_home("store-replace");
        let path = home.join(DEFAULT_KEYS_FILE);
        let before = "# my keys\nexport HUNTSMAN_A_KEY=first-1234\n\nHUNTSMAN_B_KEY=\"other-5678\" # kept\nHUNTSMAN_A_KEY=later-9999\n";
        write_mode(&path, before, 0o600);
        store_slot(&path, "HUNTSMAN_A_KEY", Some(SAVED_KEY)).expect("saved");
        assert_eq!(
            std::fs::read_to_string(&path).expect("read"),
            format!(
                "# my keys\nHUNTSMAN_A_KEY='{SAVED_KEY}'\n\nHUNTSMAN_B_KEY=\"other-5678\" # kept\n"
            )
        );
        let keys = read_back(&path);
        assert_eq!(keys.get("HUNTSMAN_A_KEY").expect("a").expose(), SAVED_KEY);
        assert_eq!(
            keys.get("HUNTSMAN_B_KEY").expect("b").expose(),
            "other-5678"
        );
        std::fs::remove_dir_all(&home).expect("cleanup");
    }

    #[cfg(unix)]
    #[test]
    fn several_changes_land_in_one_rewrite_and_a_later_change_to_a_slot_wins() {
        let home = fake_home("store-many");
        let path = home.join(DEFAULT_KEYS_FILE);
        write_mode(
            &path,
            "HUNTSMAN_A_KEY=old-1234\nHUNTSMAN_B_KEY=gone-5678\n# end\n",
            0o600,
        );
        store_slots(
            &path,
            &[
                ("HUNTSMAN_C_KEY", Some("first-c-1111")),
                ("HUNTSMAN_A_KEY", Some(SAVED_KEY)),
                ("HUNTSMAN_B_KEY", None),
                ("HUNTSMAN_D_KEY", Some("new-d-2222")),
                ("HUNTSMAN_C_KEY", Some("last-c-3333")),
            ],
        )
        .expect("saved");
        assert_eq!(
            std::fs::read_to_string(&path).expect("read"),
            format!(
                "HUNTSMAN_A_KEY='{SAVED_KEY}'\n# end\nHUNTSMAN_C_KEY='last-c-3333'\nHUNTSMAN_D_KEY='new-d-2222'\n"
            )
        );
        std::fs::remove_dir_all(&home).expect("cleanup");
    }

    #[cfg(unix)]
    #[test]
    fn one_change_that_cannot_be_saved_saves_none_of_the_others() {
        let home = fake_home("store-none");
        let path = home.join(DEFAULT_KEYS_FILE);
        let before = "HUNTSMAN_A_KEY=old-1234\n";
        write_mode(&path, before, 0o600);
        for bad in [
            ("HUNTSMAN_B_KEY", Some("changeme")),
            ("not a slot", Some("value-5678")),
            ("HUNTSMAN_B_KEY", Some("a'b\"c$d")),
        ] {
            let error = store_slots(&path, &[("HUNTSMAN_A_KEY", Some(SAVED_KEY)), bad])
                .expect_err("refused");
            assert!(matches!(error, Error::Invalid(_)), "{error}");
            assert!(!error.to_string().contains(SAVED_KEY));
            assert_eq!(std::fs::read_to_string(&path).expect("read"), before);
        }
        assert!(matches!(store_slots(&path, &[]), Err(Error::Invalid(_))));
        std::fs::remove_dir_all(&home).expect("cleanup");
    }

    #[cfg(unix)]
    #[test]
    fn removing_a_key_drops_every_line_that_set_it_and_nothing_else() {
        let home = fake_home("store-remove");
        let path = home.join(DEFAULT_KEYS_FILE);
        write_mode(
            &path,
            "HUNTSMAN_A_KEY=one-1234\nHUNTSMAN_B_KEY=two-5678\nexport HUNTSMAN_A_KEY = three-9999\n",
            0o600,
        );
        store_slot(&path, "HUNTSMAN_A_KEY", None).expect("removed");
        assert_eq!(
            std::fs::read_to_string(&path).expect("read"),
            "HUNTSMAN_B_KEY=two-5678\n"
        );
        // Removing a slot the file never had leaves it as it was.
        store_slot(&path, "HUNTSMAN_C_KEY", None).expect("nothing to remove");
        assert_eq!(read_back(&path).slots(), vec!["HUNTSMAN_B_KEY"]);
        std::fs::remove_dir_all(&home).expect("cleanup");
    }

    #[test]
    fn a_key_with_quotes_or_a_comment_mark_reads_back_whole() {
        let home = fake_home("store-quotes");
        let path = home.join(DEFAULT_KEYS_FILE);
        for value in ["a#b c #d", "it's-1234", "say \"hi\" #1", "$(not run)`x`"] {
            store_slot(&path, "HUNTSMAN_Q_KEY", Some(value)).expect(value);
            assert_eq!(
                read_back(&path)
                    .get("HUNTSMAN_Q_KEY")
                    .expect(value)
                    .expose(),
                value
            );
        }
        // A single quote with a shell character cannot be quoted safely for both readers.
        let refused = store_slot(&path, "HUNTSMAN_Q_KEY", Some("it's $HOME")).expect_err("refused");
        assert!(refused.to_string().contains("by hand"), "{refused}");
        assert!(!refused.to_string().contains("HOME"), "{refused}");
        std::fs::remove_dir_all(&home).expect("cleanup");
    }

    #[cfg(unix)]
    #[test]
    fn a_bad_slot_or_value_is_refused_and_the_file_is_left_alone() {
        let home = fake_home("store-refused");
        let path = home.join(DEFAULT_KEYS_FILE);
        write_mode(&path, "HUNTSMAN_A_KEY=one-1234\n", 0o600);
        let long = "k".repeat(MAX_KEY_BYTES + 1);
        for (slot, value) in [
            ("lower_case", SAVED_KEY),
            ("HUNTSMAN=X", SAVED_KEY),
            ("HUNTSMAN_A_KEY", ""),
            ("HUNTSMAN_A_KEY", "changeme"),
            ("HUNTSMAN_A_KEY", "two\nHUNTSMAN_B_KEY=injected"),
            ("HUNTSMAN_A_KEY", long.as_str()),
        ] {
            let refused = store_slot(&path, slot, Some(value)).expect_err(slot);
            assert!(!refused.to_string().contains("injected"), "{refused}");
        }
        assert_eq!(
            std::fs::read_to_string(&path).expect("read"),
            "HUNTSMAN_A_KEY=one-1234\n"
        );
        std::fs::remove_dir_all(&home).expect("cleanup");
    }

    #[cfg(unix)]
    #[test]
    fn a_file_another_line_of_which_does_not_parse_is_not_rewritten() {
        let home = fake_home("store-malformed");
        let path = home.join(DEFAULT_KEYS_FILE);
        let before = "HUNTSMAN_A_KEY=one-1234\nnot a key line\n";
        write_mode(&path, before, 0o600);
        let refused = store_slot(&path, "HUNTSMAN_B_KEY", Some(SAVED_KEY)).expect_err("refused");
        assert!(refused.to_string().contains("line 2"), "{refused}");
        assert_eq!(std::fs::read_to_string(&path).expect("read"), before);
        std::fs::remove_dir_all(&home).expect("cleanup");
    }

    #[cfg(unix)]
    #[test]
    fn a_symlinked_file_is_refused_and_a_too_open_one_is_saved_private() {
        use std::os::unix::fs::PermissionsExt;
        let home = fake_home("store-gate");
        let target = home.join("elsewhere.env");
        write_mode(&target, "HUNTSMAN_A_KEY=one-1234\n", 0o600);
        let link = home.join(DEFAULT_KEYS_FILE);
        std::os::unix::fs::symlink(&target, &link).expect("symlink");
        let refused = store_slot(&link, "HUNTSMAN_B_KEY", Some(SAVED_KEY)).expect_err("symlink");
        assert!(refused.to_string().contains("symlink"), "{refused}");
        assert_eq!(
            std::fs::read_to_string(&target).expect("read"),
            "HUNTSMAN_A_KEY=one-1234\n"
        );
        std::fs::remove_file(&link).expect("unlink");
        write_mode(&link, "HUNTSMAN_A_KEY=one-1234\n", 0o644);
        store_slot(&link, "HUNTSMAN_B_KEY", Some(SAVED_KEY)).expect("saved");
        let mode = std::fs::metadata(&link).expect("meta").permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "the rewrite closes a too-open file");
        let keys = Keys::load(&link).expect("loads now");
        assert_eq!(keys.get("HUNTSMAN_A_KEY").expect("a").expose(), "one-1234");
        assert_eq!(keys.get("HUNTSMAN_B_KEY").expect("b").expose(), SAVED_KEY);
        std::fs::remove_dir_all(&home).expect("cleanup");
    }
}
