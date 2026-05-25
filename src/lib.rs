//! Architecture invariants (do not change):
//!   - `#![forbid(unsafe_code)]`
//!   - No native-TLS or C-linked deps (rustls + bundled-sqlite only)
//!   - GREATEST-semantics entity merge
//!   - SHA-256 deterministic entity UIDs

#![forbid(unsafe_code)]

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
pub const DEFAULT_BIND: &str = "127.0.0.1:8080";
pub const MODULE_TIMEOUT_MS: u64 = 3000;
pub const WORKER_THREADS: usize = 2;

pub const LIVE_DEFAULT_INTERVAL_SECS: u64 = 30;
pub const LIVE_MAX_DEPTH: u32 = 5;
pub const LIVE_DEFAULT_THROTTLE_MS: u64 = 100;
pub const LIVE_DEFAULT_CONCURRENT: usize = 4;

pub mod api;
pub mod cli;
pub mod core;
pub mod modules;
pub mod storage;
pub mod util;

pub fn is_termux() -> bool {
    std::env::var_os("TERMUX_VERSION").is_some()
        || std::path::Path::new("/data/data/com.termux").exists()
}

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
