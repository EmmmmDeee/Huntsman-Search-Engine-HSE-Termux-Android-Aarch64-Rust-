use std::path::PathBuf;
use std::sync::atomic::AtomicU64;

/// Process-local monotonic sequence, zero-padded into every filename so two
/// responses archived in the same second (e.g. a retry) never collide or
/// overwrite — each paid response keeps its own file.
pub(super) static SEQ: AtomicU64 = AtomicU64::new(1);

/// Env toggle. ON by default (the operator's standing directive is total
/// retention of paid data); set `HUNTSMAN_RAW_ARCHIVE=0` (or `off`/`false`) to
/// disable it for a session that must leave no on-disk trace.
pub(super) fn enabled() -> bool {
    enabled_from(std::env::var("HUNTSMAN_RAW_ARCHIVE").ok().as_deref())
}

/// Pure disable-switch policy (no env read) so it is unit-testable: ON unless
/// the value is explicitly `0`/`off`/`false`.
pub(super) fn enabled_from(val: Option<&str>) -> bool {
    match val {
        Some(v) => {
            let v = v.trim();
            !(v == "0" || v.eq_ignore_ascii_case("off") || v.eq_ignore_ascii_case("false"))
        }
        None => true,
    }
}

/// Archive directory: `$HUNTSMAN_RAW_ARCHIVE_DIR` if set, else
/// `$HOME/.huntsman/raw`. Mirrors the `$HOME/.huntsman/` convention used by the
/// module ledger and key pool.
pub(super) fn archive_dir() -> PathBuf {
    if let Ok(dir) = std::env::var("HUNTSMAN_RAW_ARCHIVE_DIR")
        && !dir.trim().is_empty()
    {
        return PathBuf::from(dir);
    }
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
    PathBuf::from(home).join(".huntsman").join("raw")
}
