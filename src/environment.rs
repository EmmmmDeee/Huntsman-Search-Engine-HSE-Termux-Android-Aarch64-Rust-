//! The process environment, read in one place.
//!
//! Library code that needs a setting calls an accessor here. Each named accessor is one variable
//! the library reads, so the configuration the library depends on is listed in this file.
//! `tests/architecture_boundaries.rs` refuses any other production module that reads the
//! environment. The binary's adapters (`src/cli`, `src/main.rs`, `src/bin`) are the process
//! boundary and may read it.

use std::ffi::OsString;

/// The variable holding the user's home directory.
pub const HOME_ENV: &str = "HOME";
/// The HIBP API key. It is read before any keys file.
pub const HIBP_API_KEY_ENV: &str = "HIBP_API_KEY";
/// The HIBP key under the Huntsman keys-file slot name. The same name is read from the environment.
pub const HUNTSMAN_HIBP_KEY_ENV: &str = "HUNTSMAN_HIBP_KEY";
/// The HIBP request budget per minute, as a whole number. `0` disables client-side limiting.
pub const HIBP_RATE_LIMIT_ENV: &str = "HIBP_RATE_LIMIT_PER_MINUTE";
/// The prefix of the per-provider cost variables. The provider id, upper-cased, follows it.
pub const PROVIDER_COST_ENV_PREFIX: &str = "HSE_PROVIDER_COST_";

/// `$HOME`, when it is set. Its value need not be valid Unicode.
#[must_use]
pub fn home() -> Option<OsString> {
    std::env::var_os(HOME_ENV)
}

/// The HIBP API key from the environment, when it is set and valid Unicode.
#[must_use]
pub fn hibp_api_key() -> Option<String> {
    variable(HIBP_API_KEY_ENV)
}

/// The HIBP key from the `HUNTSMAN_HIBP_KEY` variable, when it is set and valid Unicode.
#[must_use]
pub fn huntsman_hibp_key() -> Option<String> {
    variable(HUNTSMAN_HIBP_KEY_ENV)
}

/// The HIBP request budget text, when `HIBP_RATE_LIMIT_PER_MINUTE` is set. The caller parses it.
#[must_use]
pub fn hibp_rate_limit_per_minute() -> Option<String> {
    variable(HIBP_RATE_LIMIT_ENV)
}

/// The cost text of one provider, when its variable is set. The caller parses the value.
#[must_use]
pub fn provider_cost_per_request(provider_id: &str) -> Option<String> {
    variable(&format!(
        "{PROVIDER_COST_ENV_PREFIX}{}",
        provider_id.trim().to_ascii_uppercase()
    ))
}

/// The named variable, when it is set and valid Unicode. It reads whatever name it is given, so a
/// caller whose name comes from data must check the name first. Keys-file slots are checked.
#[must_use]
pub fn variable(name: &str) -> Option<String> {
    std::env::var(name).ok()
}
