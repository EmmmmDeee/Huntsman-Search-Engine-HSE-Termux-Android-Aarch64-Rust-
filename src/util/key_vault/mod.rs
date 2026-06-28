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
//!   * **Categorised** — every entry is classified on read via
//!     [`crate::util::osint_providers`]: an OSINT/recon provider's key
//!     ([`VaultEntry::is_osint`]) flags its holder as an OSINT practitioner, and
//!     [`osint_entries`] / [`osint_provider_census`] give a sorted, maintained
//!     view of exactly those first-class pivots.
//!   * **Retention-only** — the vault is never read back into the dispatch
//!     environment; keys are kept as intelligence, not used to authenticate.
//!   * **Deduplication-safe** — primary key is the key value itself (text); a
//!     single `INSERT … ON CONFLICT(key_value) DO UPDATE` upsert accumulates
//!     discovery_count and extends last_seen in one statement, and the whole
//!     batch commits in one transaction (one fsync).
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
///
/// `journal_mode=WAL` is a **persistent**, on-disk property of the database
/// header: SQLite records it once and every subsequent connection reopens in WAL
/// without the pragma being re-issued. We therefore set it lazily only when the
/// DB does not yet carry it (a fresh file, or a legacy rollback-journal file),
/// rather than re-running the journal-mode switch on every `persist_batch`
/// finalisation. `synchronous=NORMAL` is per-connection (durable + WAL-safe: the
/// hard constraint here is to keep NORMAL and never OFF) and is always set.
fn open() -> rusqlite::Result<Connection> {
    let path = vault_path();
    let conn = Connection::open(&path)?;
    // synchronous=NORMAL is a per-connection setting — durable under WAL, and the
    // engine's invariant is to never drop below it. Always applied.
    conn.execute_batch("PRAGMA synchronous=NORMAL;")?;
    // Set WAL only when this DB is not already in WAL — querying the current mode
    // costs nothing, while re-issuing `journal_mode=WAL` creates/touches the
    // -wal/-shm sidecars and does a checkpoint-class operation each time.
    let mode: String = conn.query_row("PRAGMA journal_mode;", [], |r| r.get(0))?;
    if !mode.eq_ignore_ascii_case("wal") {
        // WAL mode: safe for concurrent server-mode scans; fine-grained locking.
        // Persisted in the DB header, so this runs at most once per file lifetime.
        let _: String = conn.query_row("PRAGMA journal_mode=WAL;", [], |r| r.get(0))?;
    }
    ensure_schema(&conn)?;
    // The -wal/-shm sidecars hold harvested key plaintext between checkpoints;
    // SQLite creates them at default umask, so tighten them to owner-only like
    // the main DB and its containing dir. Best-effort: a sidecar may not exist
    // yet (it is created on first WAL write), in which case there is nothing to
    // restrict and the absence is not an error.
    #[cfg(unix)]
    {
        for suffix in ["-wal", "-shm"] {
            let mut sidecar = path.clone().into_os_string();
            sidecar.push(suffix);
            let _ = crate::util::atomic_file::set_private(std::path::Path::new(&sidecar));
        }
    }
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
    // One transaction for the whole batch: collapses N implicit transactions
    // (each its own fsync) into a single commit/fsync — the win on slow Termux
    // flash. `unchecked_transaction` borrows `&Connection` (matching this
    // function's signature) instead of requiring `&mut`. Dropped without commit
    // it rolls back, so a mid-batch error leaves the vault unchanged.
    let tx = conn.unchecked_transaction()?;
    {
        // Single upsert reused across the loop via the statement cache, so the
        // SQL is compiled once. `ON CONFLICT(key_value)` folds the former
        // INSERT-OR-IGNORE-then-UPDATE pair into one statement: a brand-new key
        // inserts with discovery_count=1; an already-present key updates
        // provenance + last_seen and increments discovery_count — but only when
        // this is a DIFFERENT scan than the one last recorded, so re-seeing a key
        // within the same scan does not double-count (preserving the prior
        // `last_scan_id != ?` guard). first_scan_id / first_seen_at are never
        // overwritten, so the original discovery provenance is retained.
        let mut stmt = tx.prepare_cached(
            "INSERT INTO found_keys
                (key_value, service, provider, query, first_scan_id, last_scan_id,
                 discovery_count, first_seen_at, last_seen_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?5, 1, ?6, ?6)
             ON CONFLICT(key_value) DO UPDATE SET
                 last_scan_id    = excluded.last_scan_id,
                 service         = excluded.service,
                 provider        = excluded.provider,
                 query           = excluded.query,
                 discovery_count = discovery_count + 1,
                 last_seen_at    = excluded.last_seen_at
             WHERE found_keys.last_scan_id != excluded.last_scan_id",
        )?;
        for fk in keys {
            stmt.execute(params![
                fk.key,
                fk.service,
                fk.provider,
                fk.query,
                scan_id,
                now_i
            ])?;
        }
    }
    tx.commit()?;
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

impl VaultEntry {
    /// The OSINT category slug of this key's provider, or `None` when the
    /// provider is not catalogued OSINT/recon tooling (generic infra). Derived
    /// from `service` via [`crate::util::osint_providers`] — the single source of
    /// truth — so the bank is categorised without storing a redundant column.
    #[must_use]
    pub fn osint_category(&self) -> Option<&'static str> {
        crate::util::osint_providers::osint_category(&self.service)
            .map(crate::util::osint_providers::OsintCategory::slug)
    }

    /// True when this key belongs to an OSINT/recon provider — its holder is, by
    /// possession, an OSINT practitioner.
    #[must_use]
    pub fn is_osint(&self) -> bool {
        self.osint_category().is_some()
    }
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

/// All vault entries whose provider is catalogued OSINT/recon tooling, ordered
/// OSINT-category then most-recently-seen. These are the keys that identify
/// their holders as OSINT practitioners — the operator's testing focus and the
/// highest-value pivots. Empty when the vault does not exist.
pub fn osint_entries() -> Vec<VaultEntry> {
    let mut v: Vec<VaultEntry> = all_entries()
        .into_iter()
        .filter(VaultEntry::is_osint)
        .collect();
    v.sort_by(|a, b| {
        a.osint_category()
            .cmp(&b.osint_category())
            .then(b.last_seen_at.cmp(&a.last_seen_at))
            .then(a.service.cmp(&b.service))
    });
    v
}

/// Distinct OSINT providers in the vault, each with how many keys it holds,
/// grouped by category — a maintained, sorted census of the practitioner-tool
/// keys retained. `(category_slug, service, key_count)`, sorted by category then
/// service. Empty when the vault does not exist.
pub fn osint_provider_census() -> Vec<(&'static str, String, usize)> {
    use std::collections::BTreeMap;
    let mut counts: BTreeMap<(&'static str, String), usize> = BTreeMap::new();
    for e in all_entries() {
        if let Some(cat) = e.osint_category() {
            *counts.entry((cat, e.service.clone())).or_default() += 1;
        }
    }
    counts
        .into_iter()
        .map(|((cat, svc), n)| (cat, svc, n))
        .collect()
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

    fn entry(service: &str) -> VaultEntry {
        VaultEntry {
            key_value: "k".into(),
            service: service.into(),
            provider: "p".into(),
            first_scan_id: "s".into(),
            last_scan_id: "s".into(),
            discovery_count: 1,
            first_seen_at: 0,
            last_seen_at: 0,
        }
    }

    #[test]
    fn classifies_osint_providers_and_excludes_infra() {
        // OSINT/recon providers are flagged with their category.
        assert_eq!(entry("shodan").osint_category(), Some("attack-surface"));
        assert_eq!(entry("dehashed").osint_category(), Some("breach-leak"));
        assert!(entry("maltego").is_osint());
        // Generic infra keys are retained but NOT flagged as practitioner tooling.
        assert!(!entry("aws_access_key").is_osint());
        assert!(!entry("stripe_live").is_osint());
        assert_eq!(entry("openai").osint_category(), None);
    }
}
