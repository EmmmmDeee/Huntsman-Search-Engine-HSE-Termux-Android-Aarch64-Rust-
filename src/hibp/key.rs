//! HIBP API key loading, behind one small interface.
//!
//! A key is an [`ApiKey`]: a newtype whose `Debug`/`Display` never print the
//! value, so it cannot leak through a `{:?}`, an error message or a log line.
//! Only [`ApiKey::expose`] returns the raw value, and the only callers are the
//! code that writes the `hibp-api-key` request header.
//!
//! Where a key comes from is a [`KeySource`]. [`KeyLoader::default_chain`]
//! tries them in this order and uses the first that yields a key:
//!
//! 1. the `HIBP_API_KEY` environment variable;
//! 2. the `HUNTSMAN_HIBP_KEY` slot: the value the caller passes in (for
//!    example from a keys file it loaded with `keys::Keys::load`), else the
//!    `HUNTSMAN_HIBP_KEY` environment variable. Nothing here reads a keys file
//!    implicitly;
//! 3. the key file `~/.config/hibp/api_key` (trimmed; ignored unless it has no
//!    group or other permission bits, i.e. mode 600 or stricter);
//! 4. the key embedded at build time by `build.rs` (see [`EmbeddedSource`]).
//!
//! Runtime sources therefore always override the embedded default. Each value
//! is trimmed, and a blank value or an unedited `insert_..._here` provisioning
//! placeholder counts as "not configured".

use std::fmt;
use std::path::PathBuf;

/// Environment variable holding the HIBP API key (highest precedence).
pub const HIBP_API_KEY_ENV: &str = "HIBP_API_KEY";

/// What a redacted secret prints as.
pub const REDACTED: &str = "<redacted>";

/// The key compiled in by `build.rs` from `HIBP_API_KEY` or
/// `~/.config/hibp/api_key` on the build machine. Generated into `OUT_DIR`, so
/// it is never in the source tree. Empty when the build machine had no key.
const EMBEDDED_RAW: &str = include_str!(concat!(env!("OUT_DIR"), "/hibp_embedded_key.txt"));

/// An HIBP API key. The value is never shown by `Debug` or `Display`.
#[derive(Clone)]
pub struct ApiKey(crate::keys::Secret);

impl ApiKey {
    /// Wrap a raw value. Trims whitespace; returns `None` for a blank value or
    /// an unedited `insert_..._here` provisioning placeholder.
    pub fn new(raw: &str) -> Option<Self> {
        crate::keys::Secret::new(raw).ok().map(Self)
    }

    /// The raw key, for writing the `hibp-api-key` header. Never log or format
    /// the returned value.
    #[must_use]
    pub fn expose(&self) -> &str {
        self.0.expose()
    }

    /// `text` with every occurrence of this key replaced by [`REDACTED`]. Used
    /// on upstream error bodies before they reach an error message.
    #[must_use]
    pub fn redact_in(&self, text: &str) -> String {
        text.replace(self.expose(), REDACTED)
    }
}

impl fmt::Debug for ApiKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ApiKey({REDACTED})")
    }
}

impl fmt::Display for ApiKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(REDACTED)
    }
}

/// Where a loaded key came from. Safe to log: it names the source, never the
/// value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyOrigin {
    /// An environment variable, by name.
    Env(&'static str),
    /// The scan's `HUNTSMAN_HIBP_KEY` slot.
    HuntsmanSlot,
    /// A key file, by path.
    File(PathBuf),
    /// The key compiled in at build time.
    Embedded,
    /// A value supplied directly by the caller.
    Provided,
}

/// One place a key can be loaded from.
pub trait KeySource: Send + Sync {
    /// Load the key, or `None` when this source has none.
    fn load(&self) -> Option<(ApiKey, KeyOrigin)>;
}

/// Reads an environment variable.
pub struct EnvSource(pub &'static str);

impl KeySource for EnvSource {
    fn load(&self) -> Option<(ApiKey, KeyOrigin)> {
        let raw = std::env::var(self.0).ok()?;
        ApiKey::new(&raw).map(|k| (k, KeyOrigin::Env(self.0)))
    }
}

/// A value the caller already holds (for example the `HUNTSMAN_HIBP_KEY` slot
/// from a keys file the caller loaded).
pub struct ValueSource {
    value: Option<String>,
    origin: KeyOrigin,
}

impl ValueSource {
    /// A source that yields `value` (if configured) tagged with `origin`.
    pub fn new(value: Option<&str>, origin: KeyOrigin) -> Self {
        Self {
            value: value.map(str::to_string),
            origin,
        }
    }
}

impl KeySource for ValueSource {
    fn load(&self) -> Option<(ApiKey, KeyOrigin)> {
        let k = ApiKey::new(self.value.as_deref()?)?;
        Some((k, self.origin.clone()))
    }
}

/// Reads a key file (whole file, trimmed).
pub struct FileSource(pub PathBuf);

impl KeySource for FileSource {
    fn load(&self) -> Option<(ApiKey, KeyOrigin)> {
        if !private_file(&self.0) {
            return None;
        }
        let raw = String::from_utf8(crate::fsio::read_bounded(&self.0, 4096).ok()?).ok()?;
        ApiKey::new(&raw).map(|k| (k, KeyOrigin::File(self.0.clone())))
    }
}

/// The key `build.rs` embedded. Empty (no key) unless the build machine had
/// one. A compile-time default only: every runtime source outranks it.
pub struct EmbeddedSource;

impl EmbeddedSource {
    /// Whether this binary carries an embedded key. Never reveals the value.
    #[must_use]
    pub fn is_present() -> bool {
        ApiKey::new(EMBEDDED_RAW).is_some()
    }
}

impl KeySource for EmbeddedSource {
    fn load(&self) -> Option<(ApiKey, KeyOrigin)> {
        ApiKey::new(EMBEDDED_RAW).map(|k| (k, KeyOrigin::Embedded))
    }
}

/// `~/.config/hibp/api_key`, when `HOME` is set.
#[must_use]
pub fn default_key_file() -> Option<PathBuf> {
    let home = std::env::var_os("HOME")?;
    Some(
        PathBuf::from(home)
            .join(".config")
            .join("hibp")
            .join("api_key"),
    )
}

/// An ordered list of [`KeySource`]s; the first that yields a key wins.
pub struct KeyLoader {
    sources: Vec<Box<dyn KeySource>>,
}

impl fmt::Debug for KeyLoader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeyLoader")
            .field("sources", &self.sources.len())
            .finish()
    }
}

impl KeyLoader {
    /// A loader over exactly `sources`, in order.
    #[must_use]
    pub fn new(sources: Vec<Box<dyn KeySource>>) -> Self {
        Self { sources }
    }

    /// The documented precedence: `HIBP_API_KEY`, then the
    /// `HUNTSMAN_HIBP_KEY` slot value passed in, then `~/.config/hibp/api_key`,
    /// then the build-time embedded key.
    #[must_use]
    pub fn default_chain(huntsman_slot: Option<&str>) -> Self {
        let env_slot = std::env::var("HUNTSMAN_HIBP_KEY").ok();
        Self::from_parts(
            std::env::var("HIBP_API_KEY").ok(),
            huntsman_slot.or(env_slot.as_deref()),
            default_key_file(),
            EMBEDDED_RAW,
        )
    }

    /// [`Self::default_chain`] with every input explicit: the `HIBP_API_KEY`
    /// value, the `HUNTSMAN_HIBP_KEY` slot, the key-file path and the embedded
    /// value (empty for a build without a key). The precedence lives here
    /// only, so a future compile-time or other source slots in one place.
    #[must_use]
    pub fn from_parts(
        env_value: Option<String>,
        huntsman_slot: Option<&str>,
        key_file: Option<PathBuf>,
        embedded: &str,
    ) -> Self {
        let mut sources: Vec<Box<dyn KeySource>> = vec![
            Box::new(ValueSource {
                value: env_value,
                origin: KeyOrigin::Env(HIBP_API_KEY_ENV),
            }),
            Box::new(ValueSource::new(huntsman_slot, KeyOrigin::HuntsmanSlot)),
        ];
        if let Some(path) = key_file {
            sources.push(Box::new(FileSource(path)));
        }
        sources.push(Box::new(ValueSource::new(
            Some(embedded),
            KeyOrigin::Embedded,
        )));
        Self { sources }
    }

    /// The first key any source yields, with where it came from.
    #[must_use]
    pub fn load(&self) -> Option<(ApiKey, KeyOrigin)> {
        self.sources.iter().find_map(|s| s.load())
    }
}

#[cfg(unix)]
fn private_file(path: &std::path::Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path).is_ok_and(|meta| meta.permissions().mode().trailing_zeros() >= 6)
}

#[cfg(not(unix))]
fn private_file(_path: &std::path::Path) -> bool {
    true
}
