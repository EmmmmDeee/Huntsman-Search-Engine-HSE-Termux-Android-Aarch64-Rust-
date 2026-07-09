//! Loads and writes API keys from `$HOME/.huntsman.env`.
//!
//! Only variables prefixed `HUNTSMAN_` are exposed to modules.
//! `write_keys` is opt-in (CLI `--allow-key-write` + loopback-only) and
//! is the only path that mutates the env file; modules never call it.

mod constants;
mod io;
#[cfg(test)]
mod tests;

pub use constants::{
    DEFAULT_SEED_ENV, HIBP_DEFAULT_KEY, KNOWN_KEYS, KeyAcquisition, OATHNET_DEFAULT_KEY,
    SEEKNOW_DEFAULT_KEY, SEEKNOW_SUPERSEDED_KEY, WIGLE_DEFAULT_TOKEN, WIGLE_DEFAULT_USER,
    acquisition_status, own_api_keys, resolve_or_default, signup_hint, wigle_credentials,
};
pub use io::{
    default_seed, env_path, load, load_from_file_only, populate_and_load, write_keys, write_keys_at,
};
