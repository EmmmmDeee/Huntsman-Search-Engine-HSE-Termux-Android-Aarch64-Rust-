//! The process environment, read in one place.
//!
//! Library code that needs a setting calls an accessor here. Each named accessor is one variable
//! the library reads, so the configuration the library depends on is listed in this file.
//! `tests/architecture_boundaries.rs` refuses any other production module that reads the
//! environment. The binary's adapters (`src/cli`, `src/main.rs`, `src/bin`) are the process
//! boundary and may read it.
//!
//! The credential slot names are listed here too. A slot is read from the keys file first and from
//! the environment second, so the two spellings are one name. Production code refers to these
//! constants, and `tests/architecture_boundaries.rs` refuses a slot written as a string elsewhere.

use std::ffi::OsString;

/// The variable holding the user's home directory.
pub const HOME_ENV: &str = "HOME";
/// The variable the Termux app sets to its version in every shell it starts.
pub const TERMUX_VERSION_ENV: &str = "TERMUX_VERSION";
/// The install prefix. Termux sets it to a directory under its app data.
pub const PREFIX_ENV: &str = "PREFIX";
/// The HIBP API key. It is read before any keys file.
pub const HIBP_API_KEY_ENV: &str = "HIBP_API_KEY";
/// The HIBP key under the Huntsman keys-file slot name. The same name is read from the environment.
pub const HUNTSMAN_HIBP_KEY_ENV: &str = "HUNTSMAN_HIBP_KEY";
/// The HIBP request budget per minute, as a whole number. `0` disables client-side limiting.
pub const HIBP_RATE_LIMIT_ENV: &str = "HIBP_RATE_LIMIT_PER_MINUTE";
/// The prefix of the per-provider cost variables. The provider id, upper-cased, follows it.
pub const PROVIDER_COST_ENV_PREFIX: &str = "HSE_PROVIDER_COST_";
/// The state directory `install.sh` uses instead of `~/.huntsman` when this is set.
pub const HUNTSMAN_HOME_ENV: &str = "HUNTSMAN_HOME";
/// The runtime variables file `install.sh` creates instead of `~/.huntsman.env` when this is set.
/// `huntsman-recon` reads only `~/.huntsman.env`; `doctor` reports the difference.
pub const HUNTSMAN_ENV_FILE_ENV: &str = "HUNTSMAN_ENV_FILE";
/// The address `serve` binds when no `--bind` is given.
pub const SERVE_BIND_ENV: &str = "HSE_BIND";
/// A PEM bundle of root certificates that replaces the bundled Mozilla roots for every
/// outbound TLS connection, for networks that intercept TLS with their own CA.
pub const CA_BUNDLE_ENV: &str = "HUNTSMAN_CA_BUNDLE";

// Credential slots: keys-file names that `keys::Keys::get` also reads from the environment.
pub const ABUSECH_KEY_ENV: &str = "HUNTSMAN_ABUSECH_KEY";
pub const ABUSEIPDB_KEY_ENV: &str = "HUNTSMAN_ABUSEIPDB_KEY";
pub const BRAVE_KEY_ENV: &str = "HUNTSMAN_BRAVE_KEY";
pub const CENSYS_ID_ENV: &str = "HUNTSMAN_CENSYS_ID";
pub const CENSYS_SECRET_ENV: &str = "HUNTSMAN_CENSYS_SECRET";
pub const CRIMINALIP_KEY_ENV: &str = "HUNTSMAN_CRIMINALIP_KEY";
pub const DEHASHED_KEY_ENV: &str = "HUNTSMAN_DEHASHED_KEY";
pub const DOMAINSDB_KEY_ENV: &str = "HUNTSMAN_DOMAINSDB_KEY";
pub const EXA_KEY_ENV: &str = "HUNTSMAN_EXA_KEY";
pub const FULLCONTACT_KEY_ENV: &str = "HUNTSMAN_FULLCONTACT_KEY";
pub const GEMINI_KEY_ENV: &str = "HUNTSMAN_GEMINI_KEY";
pub const GITHUB_TOKEN_ENV: &str = "HUNTSMAN_GITHUB_TOKEN";
pub const GREYNOISE_KEY_ENV: &str = "HUNTSMAN_GREYNOISE_KEY";
pub const HLR_KEY_ENV: &str = "HUNTSMAN_HLR_KEY";
pub const HUNTER_KEY_ENV: &str = "HUNTSMAN_HUNTER_KEY";
pub const INTELX_KEY_ENV: &str = "HUNTSMAN_INTELX_KEY";
pub const IPINFO_KEY_ENV: &str = "HUNTSMAN_IPINFO_KEY";
pub const IPQS_KEY_ENV: &str = "HUNTSMAN_IPQS_KEY";
pub const LEAKIX_KEY_ENV: &str = "HUNTSMAN_LEAKIX_KEY";
pub const NETLAS_KEY_ENV: &str = "HUNTSMAN_NETLAS_KEY";
pub const NIAMONX_KEY_ENV: &str = "HUNTSMAN_NIAMONX_KEY";
pub const NUMVERIFY_KEY_ENV: &str = "HUNTSMAN_NUMVERIFY_KEY";
pub const OATHNET_KEY_ENV: &str = "HUNTSMAN_OATHNET_KEY";
pub const ONYPHE_KEY_ENV: &str = "HUNTSMAN_ONYPHE_KEY";
pub const OPENCNAM_KEY_ENV: &str = "HUNTSMAN_OPENCNAM_KEY";
pub const OPENROUTER_KEY_ENV: &str = "HUNTSMAN_OPENROUTER_KEY";
pub const OTX_KEY_ENV: &str = "HUNTSMAN_OTX_KEY";
pub const OSINTCAT_KEY_ENV: &str = "HUNTSMAN_OSINTCAT_KEY";
pub const PULSEDIVE_KEY_ENV: &str = "HUNTSMAN_PULSEDIVE_KEY";
pub const SECTRAILS_KEY_ENV: &str = "HUNTSMAN_SECTRAILS_KEY";
pub const SEEKNOW_KEY_ENV: &str = "HUNTSMAN_SEEKNOW_KEY";
pub const SHODAN_KEY_ENV: &str = "HUNTSMAN_SHODAN_KEY";
pub const STOLEN_TAX_KEY_ENV: &str = "HUNTSMAN_STOLEN_TAX_KEY";
pub const THREATFOX_KEY_ENV: &str = "HUNTSMAN_THREATFOX_KEY";
pub const TROVE_KEY_ENV: &str = "HUNTSMAN_TROVE_KEY";
pub const URLSCAN_KEY_ENV: &str = "HUNTSMAN_URLSCAN_KEY";
pub const VIRUSTOTAL_KEY_ENV: &str = "HUNTSMAN_VIRUSTOTAL_KEY";
pub const WHOXY_KEY_ENV: &str = "HUNTSMAN_WHOXY_KEY";
pub const WIGLE_TOKEN_ENV: &str = "HUNTSMAN_WIGLE_TOKEN";
pub const WIGLE_USER_ENV: &str = "HUNTSMAN_WIGLE_USER";

// The bearer token that protects the `serve` listener. The binary's adapter reads it. It is named
// here with the other credentials, so every credential name is declared in this file.
pub const SERVE_TOKEN_ENV: &str = "HSE_AUTH_TOKEN";

/// `$HOME`, when it is set. Its value need not be valid Unicode.
#[must_use]
pub fn home() -> Option<OsString> {
    std::env::var_os(HOME_ENV)
}

/// `$TERMUX_VERSION`, when it is set. The Termux app exports it in every shell it starts.
#[must_use]
pub fn termux_version() -> Option<OsString> {
    std::env::var_os(TERMUX_VERSION_ENV)
}

/// `$PREFIX`, when it is set. Termux sets it to its install prefix. It need not be valid Unicode.
#[must_use]
pub fn prefix() -> Option<OsString> {
    std::env::var_os(PREFIX_ENV)
}

/// The `HUNTSMAN_CA_BUNDLE` path, when it is set and not empty. It need not be valid Unicode.
#[must_use]
pub fn ca_bundle() -> Option<OsString> {
    std::env::var_os(CA_BUNDLE_ENV).filter(|path| !path.is_empty())
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
