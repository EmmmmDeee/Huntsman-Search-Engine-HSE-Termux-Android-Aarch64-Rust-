//! HIBP API key loading behind a runtime-only interface.
//!
//! Production key precedence is `HIBP_API_KEY`, the caller's
//! `HUNTSMAN_HIBP_KEY` slot (or that environment variable), then private
//! `~/.config/hibp/api_key`. No production build embeds an API key.

use std::fmt;
use std::path::PathBuf;

use crate::environment;

pub use crate::environment::HIBP_API_KEY_ENV;
pub const REDACTED: &str = "<redacted>";

#[derive(Clone)]
pub struct ApiKey(crate::keys::Secret);
impl ApiKey {
    pub fn new(raw: &str) -> Option<Self> {
        crate::keys::Secret::new(raw).ok().map(Self)
    }
    #[must_use]
    pub fn expose(&self) -> &str {
        self.0.expose()
    }
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyOrigin {
    Env(&'static str),
    HuntsmanSlot,
    File(PathBuf),
    /// Compatibility-only origin. Production key loaders never construct it.
    Embedded,
    Provided,
}

pub trait KeySource: Send + Sync {
    fn load(&self) -> Option<(ApiKey, KeyOrigin)>;
}

pub struct EnvSource(pub &'static str);
impl KeySource for EnvSource {
    fn load(&self) -> Option<(ApiKey, KeyOrigin)> {
        let raw = environment::variable(self.0)?;
        ApiKey::new(&raw).map(|k| (k, KeyOrigin::Env(self.0)))
    }
}

pub struct ValueSource {
    value: Option<String>,
    origin: KeyOrigin,
}
impl ValueSource {
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

pub struct FileSource(pub PathBuf);
impl KeySource for FileSource {
    fn load(&self) -> Option<(ApiKey, KeyOrigin)> {
        let crate::keys::PrivateFile::Contents(bytes) =
            crate::keys::read_private_file(&self.0, 4096)
        else {
            return None;
        };
        let raw = String::from_utf8(bytes).ok()?;
        ApiKey::new(&raw).map(|k| (k, KeyOrigin::File(self.0.clone())))
    }
}

/// Compatibility marker retained for callers/tests that previously inspected
/// build-time embedding. Production binaries can no longer carry such a key.
pub struct EmbeddedSource;
impl EmbeddedSource {
    #[must_use]
    pub const fn is_present() -> bool {
        false
    }
}

#[must_use]
pub fn default_key_file() -> Option<PathBuf> {
    let home = environment::home()?;
    Some(
        PathBuf::from(home)
            .join(".config")
            .join("hibp")
            .join("api_key"),
    )
}

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
    #[must_use]
    pub fn new(sources: Vec<Box<dyn KeySource>>) -> Self {
        Self { sources }
    }

    #[must_use]
    pub fn default_chain(huntsman_slot: Option<&str>) -> Self {
        let env_slot = environment::huntsman_hibp_key();
        Self::from_parts(
            environment::hibp_api_key(),
            huntsman_slot.or(env_slot.as_deref()),
            default_key_file(),
            "",
        )
    }

    /// The fourth argument is retained for source compatibility. In production
    /// it is deliberately ignored. Unit tests may inject it to exercise the old
    /// precedence contract without placing a secret in any built artifact.
    #[must_use]
    pub fn from_parts(
        env_value: Option<String>,
        huntsman_slot: Option<&str>,
        key_file: Option<PathBuf>,
        test_embedded: &str,
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
        #[cfg(test)]
        sources.push(Box::new(ValueSource::new(
            Some(test_embedded),
            KeyOrigin::Embedded,
        )));
        #[cfg(not(test))]
        let _ = test_embedded;
        Self { sources }
    }

    #[must_use]
    pub fn load(&self) -> Option<(ApiKey, KeyOrigin)> {
        self.sources.iter().find_map(|s| s.load())
    }
}
