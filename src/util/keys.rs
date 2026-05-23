//! Loads API keys from `$HOME/.huntsman.env` plus the process environment.
//! Only variables prefixed `HUNTSMAN_` are exposed to modules.

use std::collections::HashMap;
use std::path::PathBuf;

/// Resolve the keys env-file path.
///
/// Termux: `$HOME/.huntsman.env` (typically `/data/data/com.termux/files/home/...`).
/// Falls back to `.huntsman.env` in the current directory if `$HOME` is unset.
pub fn env_path() -> String {
    std::env::var("HOME").map_or_else(
        |_| ".huntsman.env".to_string(),
        |home| {
            PathBuf::from(home)
                .join(".huntsman.env")
                .to_string_lossy()
                .into_owned()
        },
    )
}

/// Load `HUNTSMAN_*` keys from the env file + process environment.
/// File entries are loaded first; process env wins on conflict.
pub fn load() -> HashMap<String, String> {
    let _ = dotenvy::from_path(env_path());

    std::env::vars()
        .filter(|(k, _)| k.starts_with("HUNTSMAN_"))
        .collect()
}
