//! Persistent cross-scan key vault — `~/.huntsman/key_vault.db`.
//!
//! Every foreign API key HSE encounters during any scan is written here in
//! addition to the per-scan entity store. The vault is:
//!
//!   * **Permanent** — survives scan cleanup/expiry. Keys accumulate across the
//!     full lifetime of the installation and are never automatically purged.
//!   * **Cross-scan** — records when a key was first and last seen and how many
//!     independent scans surfaced it. Frequency is intelligence: a key that
//!     recurs across three unrelated investigations is far more significant than
//!     one seen once.
//!   * **Provenance-complete** — stores the service vendor, the module/endpoint
//!     that discovered the key, and the query value that triggered the hit.
//!   * **Deduplication-safe** — primary key is the key value itself (text); an
//!     `INSERT OR IGNORE` followed by an UPDATE accumulates discovery_count and
//!     extends last_seen in one round trip.
//!   * **Zero-alloc hot path** — the vault is only written when
//!     [`persist_batch`] is called (at scan finalisation), not on every HTTP
//!     response. The hot path (`found_keys::scan_body`) remains allocation-free.
//!
//! Schema (SQLite):
//! ```text
//! found_keys (
//!     key_value      TEXT PRIMARY KEY,
//!     service        TEXT NOT NULL,
//!     provider       TEXT NOT NULL,
//!     query          TEXT NOT NULL,
//!     first_scan_id  TEXT NOT NULL,
//!     last_scan_id   TEXT NOT NULL,
//!     discovery_count INTEGER NOT NULL DEFAULT 1,
//!     first_seen_at  INTEGER NOT NULL,
//!     last_seen_at   INTEGER NOT NULL
//! )
//! ```

use std::path::PathBuf;

use rusqlite::{Connection, params};

use crate::util::found_keys::FoundKey;

// ── Path ─────────────────────────────────────────────────────────────────────

/// `$HOME/.huntsman/key_vault.db` — separate from the scan DB so it is never
/// touched by scan-level cleanup operations.
#[must_use]
pub fn vault_path() -> PathBuf {
    std::env::var("HOME").map_or_else(
        |_| PathBuf::from("key_vault.db"),
        |home| {
            let dir = PathBuf::from(&home).join(".huntsman");
            let _ = std::fs::create_dir_all(&dir);
            // Restrict to owner-only on Unix so harvested keys are not world-readable.
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700));
            }
            dir.join("key_vault.db")
        },
    )
}

// ── Connection ────────────────────────────────────────────────────────────────

/// Open (or create) the vault for read-write access and ensure the schema exists.
/// Each call opens a fresh connection — the vault is written once per scan
/// finalisation, not held open across the whole process lifetime.
fn open() -> rusqlite::Result<Connection> {
    let conn = Connection::open(vault_path())?;
    // WAL mode: safe for concurrent server-mode scans; fine-grained locking.
    conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL;")?;
    ensure_schema(&conn)?;
    Ok(conn)
}

fn ensure_schema(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS found_keys (
            key_value       TEXT    PRIMARY KEY,
            service         TEXT    NOT NULL,
            provider        TEXT    NOT NULL,
            query           TEXT    NOT NULL,
            first_scan_id   TEXT    NOT NULL,
            last_scan_id    TEXT    NOT NULL,
            discovery_count INTEGER NOT NULL DEFAULT 1,
            first_seen_at   INTEGER NOT NULL,
            last_seen_at    INTEGER NOT NULL
        ) STRICT;
        CREATE INDEX IF NOT EXISTS idx_fk_service ON found_keys(service);
        CREATE INDEX IF NOT EXISTS idx_fk_last_seen ON found_keys(last_seen_at);",
    )
}

// ── Public API ────────────────────────────────────────────────────────────────

/// Persist a batch of [`FoundKey`]s discovered in `scan_id` to the vault.
///
/// Called once per scan from `modules::drain_found_key_entities` — zero I/O
/// during the scan itself. Best-effort and infallible: a vault write failure
/// (disk full, permissions) logs a warning but never fails the scan.
pub fn persist_batch(keys: &[FoundKey], scan_id: &str) {
    if keys.is_empty() {
        return;
    }
    let now = crate::core::entity::unix_now();
    match open().and_then(|conn| write_batch(&conn, keys, scan_id, now)) {
        Ok(written) => {
            tracing::debug!(scan_id, count = written, "key_vault: persisted keys");
        }
        Err(e) => {
            tracing::warn!(scan_id, error = %e, "key_vault: failed to persist found keys (scan data unaffected)");
        }
    }
}

fn write_batch(
    conn: &Connection,
    keys: &[FoundKey],
    scan_id: &str,
    now: u64,
) -> rusqlite::Result<usize> {
    let now_i = now as i64;
    for fk in keys {
        // First touch: INSERT OR IGNORE — no-op if the key value already exists.
        conn.execute(
            "INSERT OR IGNORE INTO found_keys
                (key_value, service, provider, query, first_scan_id, last_scan_id,
                 discovery_count, first_seen_at, last_seen_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?5, 1, ?6, ?6)",
            params![fk.key, fk.service, fk.provider, fk.query, scan_id, now_i],
        )?;
        // Subsequent touch: update provenance + increment count + update last_seen.
        conn.execute(
            "UPDATE found_keys
             SET last_scan_id     = ?1,
                 service          = ?2,
                 provider         = ?3,
                 query            = ?4,
                 discovery_count  = discovery_count + 1,
                 last_seen_at     = ?5
             WHERE key_value = ?6
               AND last_scan_id != ?1",
            params![scan_id, fk.service, fk.provider, fk.query, now_i, fk.key],
        )?;
    }
    Ok(keys.len())
}

// ── Query helpers ─────────────────────────────────────────────────────────────

/// A key entry read back from the vault.
#[derive(Debug, Clone)]
pub struct VaultEntry {
    pub key_value: String,
    pub service: String,
    pub provider: String,
    pub first_scan_id: String,
    pub last_scan_id: String,
    pub discovery_count: u32,
    pub first_seen_at: u64,
    pub last_seen_at: u64,
}

/// Return all vault entries, ordered by `last_seen_at DESC`. Returns an empty
/// Vec when the vault file does not yet exist.
pub fn all_entries() -> Vec<VaultEntry> {
    let path = vault_path();
    if !path.exists() {
        return Vec::new();
    }
    let Ok(conn) = open() else {
        return Vec::new();
    };
    query_all(&conn).unwrap_or_default()
}

fn query_all(conn: &Connection) -> rusqlite::Result<Vec<VaultEntry>> {
    let mut stmt = conn.prepare(
        "SELECT key_value, service, provider, first_scan_id, last_scan_id,
                discovery_count, first_seen_at, last_seen_at
         FROM found_keys
         ORDER BY last_seen_at DESC",
    )?;
    let rows = stmt.query_map([], |row| {
        Ok(VaultEntry {
            key_value: row.get(0)?,
            service: row.get(1)?,
            provider: row.get(2)?,
            first_scan_id: row.get(3)?,
            last_scan_id: row.get(4)?,
            discovery_count: row.get::<_, i64>(5)? as u32,
            first_seen_at: row.get::<_, i64>(6)? as u64,
            last_seen_at: row.get::<_, i64>(7)? as u64,
        })
    })?;
    rows.collect()
}

/// Total count of distinct key values stored in the vault. Returns 0 when the
/// vault does not exist.
pub fn total_count() -> u64 {
    let path = vault_path();
    if !path.exists() {
        return 0;
    }
    open()
        .and_then(|conn| {
            conn.query_row("SELECT COUNT(*) FROM found_keys", [], |r| {
                r.get::<_, i64>(0)
            })
        })
        .map_or(0, |n| n as u64)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::found_keys::FoundKey;

    fn test_key(service: &str, key: &str) -> FoundKey {
        FoundKey {
            service: service.to_string(),
            key: key.to_string(),
            provider: "test_module".to_string(),
            query: "test@example.com".to_string(),
            count: 1,
        }
    }

    #[test]
    fn vault_path_contains_huntsman() {
        let p = vault_path();
        assert!(
            p.to_string_lossy().contains("huntsman") || p.to_string_lossy().contains("key_vault")
        );
    }

    #[test]
    fn persist_and_query_roundtrip() {
        // Use an in-memory DB by temporarily overriding via the open() path is
        // not straightforward, so we write to a temp file and clean up.
        let dir = std::env::temp_dir().join("hse_kv_test");
        let _ = std::fs::create_dir_all(&dir);
        let db_path = dir.join("test_vault.db");
        let _ = std::fs::remove_file(&db_path); // clean slate

        let conn = Connection::open(&db_path).unwrap();
        ensure_schema(&conn).unwrap();

        let keys = vec![
            test_key("stripe_live", "sk-live-abc123xyz789"),
            test_key("aws_access_key", "AKIAIOSFODNN7EXAMPLE"),
        ];
        write_batch(&conn, &keys, "scan-001", 1_000_000).unwrap();

        let entries = query_all(&conn).unwrap();
        assert_eq!(entries.len(), 2);
        assert!(entries.iter().any(|e| e.service == "stripe_live"));
        assert!(entries.iter().any(|e| e.service == "aws_access_key"));

        // Second scan with same key — should increment discovery_count.
        let same = vec![test_key("stripe_live", "sk-live-abc123xyz789")];
        write_batch(&conn, &same, "scan-002", 1_000_100).unwrap();

        let entries2 = query_all(&conn).unwrap();
        let stripe = entries2
            .iter()
            .find(|e| e.service == "stripe_live")
            .unwrap();
        assert_eq!(stripe.first_scan_id, "scan-001");
        assert_eq!(stripe.last_scan_id, "scan-002");
        assert_eq!(stripe.discovery_count, 2);

        let _ = std::fs::remove_dir_all(dir);
    }
}
