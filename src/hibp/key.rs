//! HIBP API key loading, behind one small runtime-only interface.
//!
//! A key is an [`ApiKey`]: a newtype whose `Debug`/`Display` never print the
//! value. Runtime sources are tried in this order:
//!
//! 1. `HIBP_API_KEY`;
//! 2. the caller's `HUNTSMAN_HIBP_KEY` slot, else that environment variable;
//! 3. private `~/.config/hibp/api_key`.
//!
//! HIBP API keys are never embedded into the binary at build time.

use std::fmt;
use std::path::PathBuf;

pub const HIBP_API_KEY_ENV: &str = "HIBP_API_KEY";
pub const REDACTED: &str = "<redacted>";

#[derive(Clone)]
pub struct ApiKey(crate::keys::Secret);

impl ApiKey {
    pub fn new(raw: &str) -> Option<Self> {
        crate::keys::Secret::new(raw).ok().map(Self)
    }

    #[must_use]
    pub fn expose(&self) -> &str { self.0.expose() }

    #[must_use]
    pub fn redact_in(&self, text: &str) -> String { text.replace(self.expose(), REDACTED) }
}

impl fmt::Debug for ApiKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { write!(f, "ApiKey({REDACTED})") }
}

impl fmt::Display for ApiKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { f.write_str(REDACTED) }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyOrigin {
    Env(&'static str),
    HuntsmanSlot,
    File(PathBuf),
    Provided,
}

pub trait KeySource: Send + Sync {
    fn load(&self) -> Option<(ApiKey, KeyOrigin)>;
}

pub struct EnvSource(pub &'static str);
impl KeySource for EnvSource {
    fn load(&self) -> Option<(ApiKey, KeyOrigin)> {
        let raw = std::env::var(self.0).ok()?;
        ApiKey::new(&raw).map(|k| (k, KeyOrigin::Env(self.0)))
    }
}

pub struct ValueSource { value: Option<String>, origin: KeyOrigin }
impl ValueSource {
    pub fn new(value: Option<&str>, origin: KeyOrigin) -> Self {
        Self { value: value.map(str::to_string), origin }
    }
}
impl KeySource for ValueSource {
    fn load(&self) -> Option<(ApiKey, KeyOrigin)> {
        let k = ApiKey::new(self.value.as_deref()?)?;
        Some((k, self.origin.clone()))
    }
}

pub struct FileSource(pub PathBuf);
impl KeySource for FileSource {
    fn load(&self) -> Option<(ApiKey, KeyOrigin)> {
        if !private_file(&self.0) { return None; }
        let raw = String::from_utf8(crate::fsio::read_bounded(&self.0, 4096).ok()?).ok()?;
        ApiKey::new(&raw).map(|k| (k, KeyOrigin::File(self.0.clone())))
    }
}

#[must_use]
pub fn default_key_file() -> Option<PathBuf> {
    let home = std::env::var_os("HOME")?;
    Some(PathBuf::from(home).join(".config").join("hibp").join("api_key"))
}

pub struct KeyLoader { sources: Vec<Box<dyn KeySource>> }
impl fmt::Debug for KeyLoader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeyLoader").field("sources", &self.sources.len()).finish()
    }
}
impl KeyLoader {
    #[must_use]
    pub fn new(sources: Vec<Box<dyn KeySource>>) -> Self { Self { sources } }

    #[must_use]
    pub fn default_chain(huntsman_slot: Option<&str>) -> Self {
        let env_slot = std::env::var("HUNTSMAN_HIBP_KEY").ok();
        Self::from_parts(
            std::env::var(HIBP_API_KEY_ENV).ok(),
            huntsman_slot.or(env_slot.as_deref()),
            default_key_file(),
        )
    }

    #[must_use]
    pub fn from_parts(
        env_value: Option<String>,
        huntsman_slot: Option<&str>,
        key_file: Option<PathBuf>,
    ) -> Self {
        let mut sources: Vec<Box<dyn KeySource>> = vec![
            Box::new(ValueSource { value: env_value, origin: KeyOrigin::Env(HIBP_API_KEY_ENV) }),
            Box::new(ValueSource::new(huntsman_slot, KeyOrigin::HuntsmanSlot)),
        ];
        if let Some(path) = key_file { sources.push(Box::new(FileSource(path))); }
        Self { sources }
    }

    #[must_use]
    pub fn load(&self) -> Option<(ApiKey, KeyOrigin)> { self.sources.iter().find_map(|s| s.load()) }
}

#[cfg(unix)]
fn private_file(path: &std::path::Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path).is_ok_and(|meta| meta.is_file() && meta.permissions().mode() & 0o077 == 0)
}

#[cfg(not(unix))]
fn private_file(_path: &std::path::Path) -> bool { true }
