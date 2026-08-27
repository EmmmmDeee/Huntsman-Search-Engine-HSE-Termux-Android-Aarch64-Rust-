//! Loads and writes API keys from `$HOME/.huntsman.env`.
//!
//! Only variables prefixed `HUNTSMAN_` are exposed to modules.
//! `write_keys` is opt-in (CLI `--allow-key-write` + loopback-only) and
//! is the only path that mutates the env file; modules never call it.

mod constants;
mod embedded_credentials;
mod io;
#[cfg(test)]
mod tests;

pub use constants::{
    DEFAULT_SEED_ENV, KNOWN_KEYS, is_compromised_embedded, is_template_placeholder, own_api_keys,
    resolve_key, signup_hint, wigle_credentials,
};
pub use embedded_credentials::get_embedded_keys;
pub use io::{
    compromised_key_purges, default_seed, env_path, load, load_from_file_only, populate_and_load,
    write_keys, write_keys_at,
};
