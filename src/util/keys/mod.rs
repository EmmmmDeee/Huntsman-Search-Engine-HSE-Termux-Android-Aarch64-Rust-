//! Loads and writes API keys from `$HOME/.huntsman.env`.
//!
//! Only variables prefixed `HUNTSMAN_` are exposed to modules.
//! `write_keys` is loopback-only, on by default and switched off by
//! `hse serve --no-key-write`; it is the only path that mutates the env file
//! and modules never call it.

mod constants;
mod io;
#[cfg(test)]
mod tests;

pub use constants::{
    DEFAULT_SEED_ENV, KNOWN_KEYS, is_compromised_embedded, is_template_placeholder, own_api_keys,
    resolve_key, signup_hint, wigle_credentials,
};
pub use io::{
    compromised_key_purges, default_seed, env_path, load, load_from_file_only, populate_and_load,
    write_keys, write_keys_at,
};
