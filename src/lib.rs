//! Huntsman Search Engine (HSE) — prototype.
//!
//! Lightweight pure-Rust OSINT/GEOINT scaffold designed to run inside Termux
//! on aarch64 Android with no root. Boots either as a CLI (`hse scan|live|
//! modules|doctor`) or as `hse serve` — an axum HTTP server with a minimal
//! hand-rolled SPA bound to `127.0.0.1` for use from Chrome / Firefox on
//! the device.
//!
//! Architecture invariants (do not change):
//!   - `#![forbid(unsafe_code)]`
//!   - No native-TLS or C-linked deps (rustls + bundled-sqlite only)
//!   - GREATEST-semantics entity merge
//!   - SHA-256 deterministic entity UIDs

#![forbid(unsafe_code)]

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Default bind address for the HTTP server. Localhost only — no LAN exposure.
pub const DEFAULT_BIND: &str = "127.0.0.1:8080";

/// Per-module timeout in milliseconds (architecture invariant).
pub const MODULE_TIMEOUT_MS: u64 = 3000;

/// Tokio worker thread count (architecture invariant — tuned for Termux).
pub const WORKER_THREADS: usize = 2;

// Live-mode tuning constants (used from v0.5+):
pub const LIVE_DEFAULT_INTERVAL_SECS: u64 = 30;
pub const LIVE_MAX_DEPTH: u32 = 5;
pub const LIVE_DEFAULT_THROTTLE_MS: u64 = 100;
pub const LIVE_DEFAULT_CONCURRENT: usize = 4;

pub mod api;
pub mod cli;
pub mod core;
pub mod modules;
pub mod selftest;
pub mod storage;
pub mod util;

/// True if we appear to be running inside Termux on Android.
pub fn is_termux() -> bool {
    std::env::var_os("TERMUX_VERSION").is_some()
        || std::path::Path::new("/data/data/com.termux").exists()
}

/// Resolve the default database path, creating the parent directory if needed.
///
/// Termux: `$HOME/.huntsman/huntsman.db` (typically under `/data/data/com.termux/files/home`).
/// Falls back to `./huntsman.db` if `$HOME` is unset.
pub fn default_db_path() -> String {
    std::env::var("HOME").map_or_else(
        |_| "huntsman.db".to_string(),
        |home| {
            let dir = std::path::Path::new(&home).join(".huntsman");
            let _ = std::fs::create_dir_all(&dir);
            dir.join("huntsman.db").to_string_lossy().into_owned()
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_is_non_empty() {
        assert!(!VERSION.is_empty());
    }

    #[test]
    fn architecture_constants_are_correct() {
        assert_eq!(DEFAULT_BIND, "127.0.0.1:8080");
        assert_eq!(MODULE_TIMEOUT_MS, 3000);
        assert_eq!(WORKER_THREADS, 2);
        assert_eq!(LIVE_DEFAULT_INTERVAL_SECS, 30);
        assert_eq!(LIVE_MAX_DEPTH, 5);
        assert_eq!(LIVE_DEFAULT_THROTTLE_MS, 100);
        assert_eq!(LIVE_DEFAULT_CONCURRENT, 4);
    }

    #[test]
    fn is_termux_returns_false_in_ci() {
        if std::env::var_os("TERMUX_VERSION").is_none() {
            assert!(!is_termux());
        }
    }

    #[test]
    fn default_db_path_is_non_empty() {
        let p = default_db_path();
        assert!(!p.is_empty());
        assert!(p.ends_with("huntsman.db"));
    }

    #[test]
    fn default_db_path_uses_home_when_set() {
        if std::env::var("HOME").is_ok() {
            let p = default_db_path();
            assert!(p.contains(".huntsman"));
        }
    }
}
