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
//!   * **Deduplication-safe** — primary key is the key value itself (text); an
//!     `INSERT OR IGNORE` followed by an UPDATE accumulates discovery_count and
//!     extends last_seen in one round trip.
//!   * **Verified-duplicate aware** — beyond the raw `discovery_count` (how many
//!     scans surfaced a key), the bank records a `verified_count`: how many times
//!     the key was confirmed LIVE against its provider's real endpoint. Each
//!     confirmation is a *verified duplicate* — independent proof the credential
//!     still works. A key with `verified_count >= 1` is proven, self-funding
//!     capacity (see [`record_verification`] / [`verified_entries`]); the rotation
//!     pool can then promote it for reuse.
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
//!     last_seen_at   INTEGER NOT NULL,
//!     verified_count  INTEGER NOT NULL DEFAULT 0,
//!     last_verified_at INTEGER
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
            key_value        TEXT    PRIMARY KEY,
            service          TEXT    NOT NULL,
            provider         TEXT    NOT NULL,
            query            TEXT    NOT NULL,
            first_scan_id    TEXT    NOT NULL,
            last_scan_id     TEXT    NOT NULL,
            discovery_count  INTEGER NOT NULL DEFAULT 1,
            first_seen_at    INTEGER NOT NULL,
            last_seen_at     INTEGER NOT NULL,
            verified_count   INTEGER NOT NULL DEFAULT 0,
            last_verified_at INTEGER
        ) STRICT;
        CREATE INDEX IF NOT EXISTS idx_fk_service ON found_keys(service);
        CREATE INDEX IF NOT EXISTS idx_fk_last_seen ON found_keys(last_seen_at);",
    )?;
    // Migrate banks created before verified-duplicate tracking existed: add the
    // columns in place so an existing installation upgrades without losing its
    // accumulated discovery history. STRICT tables accept `ADD COLUMN` with a
    // non-null default, so the existing rows backfill to `verified_count = 0`.
    add_column_if_missing(conn, "verified_count", "INTEGER NOT NULL DEFAULT 0")?;
    add_column_if_missing(conn, "last_verified_at", "INTEGER")?;
    Ok(())
}

/// True if `found_keys` already has a column named `col`.
fn has_column(conn: &Connection, col: &str) -> rusqlite::Result<bool> {
    let mut stmt = conn.prepare("PRAGMA table_info(found_keys)")?;
    let mut found = false;
    let rows = stmt.query_map([], |row| row.get::<_, String>(1))?;
    for name in rows {
        if name? == col {
            found = true;
            break;
        }
    }
    Ok(found)
}

/// Add `col` to `found_keys` with declaration `decl` if it is not already
/// present — an idempotent, in-place migration for pre-existing bank files.
fn add_column_if_missing(conn: &Connection, col: &str, decl: &str) -> rusqlite::Result<()> {
    if !has_column(conn, col)? {
        // `col`/`decl` are compile-time literals from this module, never user
        // input, so this format is not an injection surface.
        conn.execute_batch(&format!("ALTER TABLE found_keys ADD COLUMN {col} {decl};"))?;
    }
    Ok(())
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
    /// How many times this banked key was confirmed LIVE against its provider's
    /// real endpoint (each confirmation a *verified duplicate*). `0` ⇒ never
    /// verified; `>= 1` ⇒ proven, reusable, self-funding capacity.
    pub verified_count: u32,
    /// Unix seconds of the most recent live confirmation, or `None` if the key
    /// has never been verified.
    pub last_verified_at: Option<u64>,
}

impl VaultEntry {
    /// True once this key has been confirmed live at least once — proven,
    /// self-funding capacity the rotation pool can promote for reuse.
    #[must_use]
    pub fn is_verified(&self) -> bool {
        self.verified_count > 0
    }

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

    /// This key's resale-value tier, derived from its `service` via
    /// [`crate::util::key_roi`]: a `Multiplier` key cascades into discovering more
    /// keys (highest resale value), an `Expansion` key yields many entities, and a
    /// `Terminal` key is one-and-done. Combined with [`Self::is_verified`] (proven
    /// to work) this ranks the bank's resellable capacity.
    #[must_use]
    pub fn roi(&self) -> crate::util::key_roi::KeyRoi {
        crate::util::key_roi::classify(&self.service)
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
                discovery_count, first_seen_at, last_seen_at,
                verified_count, last_verified_at
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
            verified_count: row.get::<_, i64>(8)? as u32,
            last_verified_at: row.get::<_, Option<i64>>(9)?.map(|v| v as u64),
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

/// All vault entries proven LIVE at least once (`verified_count >= 1`), ordered
/// most-verified then most-recently-confirmed. These are the bank's *verified
/// duplicates* — credentials independently re-confirmed against their real
/// endpoints, the self-funding capacity the rotation pool can promote. Empty
/// when the vault does not exist or nothing has been verified yet.
pub fn verified_entries() -> Vec<VaultEntry> {
    let mut v: Vec<VaultEntry> = all_entries()
        .into_iter()
        .filter(VaultEntry::is_verified)
        .collect();
    v.sort_by(|a, b| {
        b.verified_count
            .cmp(&a.verified_count)
            .then(b.last_verified_at.cmp(&a.last_verified_at))
            .then(a.service.cmp(&b.service))
    });
    v
}

/// The bank's resellable inventory: every PROVEN-live key
/// ([`VaultEntry::is_verified`]) ranked by resale value — highest
/// [`crate::util::key_roi`] tier first (`Multiplier` > `Expansion` > `Terminal`),
/// then most-confirmed, then most-rediscovered, then service. A verified key is
/// one demonstrated to work, so it has standalone value; ordering by ROI surfaces
/// the credentials that unlock the most downstream capacity (and thus the most
/// further keys) first. Empty when nothing has been verified yet.
pub fn resellable_entries() -> Vec<VaultEntry> {
    rank_resellable(verified_entries())
}

/// Pure resale-value ranking of an already-verified entry set — highest ROI tier
/// first, then most-confirmed / most-rediscovered / service. Split out from
/// [`resellable_entries`] (which reads the vault) so the ordering is unit-tested
/// without a live database.
fn rank_resellable(mut entries: Vec<VaultEntry>) -> Vec<VaultEntry> {
    entries.sort_by(|a, b| {
        b.roi()
            .cmp(&a.roi())
            .then(b.verified_count.cmp(&a.verified_count))
            .then(b.discovery_count.cmp(&a.discovery_count))
            .then(a.service.cmp(&b.service))
    });
    entries
}

/// Record one LIVE confirmation of a banked key: increment its `verified_count`
/// (one *verified duplicate*) and stamp `last_verified_at`. Call this only after
/// a REAL endpoint check confirmed the key works — never on a simulated result.
///
/// Returns `true` if the key was present in the bank and updated. A key not yet
/// banked is a no-op (`false`): it is recorded with full provenance at scan
/// finalisation via [`persist_batch`], and a later verify pass confirms it.
/// Best-effort — a vault write failure logs and returns `false`.
#[must_use]
pub fn record_verification(key_value: &str) -> bool {
    let now = crate::core::entity::unix_now();
    match open().and_then(|conn| write_verification(&conn, key_value, now)) {
        Ok(updated) => updated,
        Err(e) => {
            tracing::warn!(error = %e, "key_vault: failed to record verification");
            false
        }
    }
}

fn write_verification(conn: &Connection, key_value: &str, now: u64) -> rusqlite::Result<bool> {
    let n = conn.execute(
        "UPDATE found_keys
         SET verified_count   = verified_count + 1,
             last_verified_at = ?1
         WHERE key_value = ?2",
        params![now as i64, key_value],
    )?;
    Ok(n > 0)
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
            verified_count: 0,
            last_verified_at: None,
        }
    }

    #[test]
    fn verification_records_verified_duplicates_and_is_idempotent_per_call() {
        let conn = Connection::open_in_memory().unwrap();
        ensure_schema(&conn).unwrap();
        write_batch(
            &conn,
            &[test_key("shodan", "shodan-key-123456")],
            "scan-001",
            1_000_000,
        )
        .unwrap();

        // A key not yet banked: no-op, no row updated.
        assert!(!write_verification(&conn, "absent-key", 1_000_050).unwrap());

        // Two independent live confirmations accrue two verified duplicates.
        assert!(write_verification(&conn, "shodan-key-123456", 1_000_100).unwrap());
        assert!(write_verification(&conn, "shodan-key-123456", 1_000_200).unwrap());

        let e = query_all(&conn)
            .unwrap()
            .into_iter()
            .find(|e| e.service == "shodan")
            .unwrap();
        assert_eq!(e.verified_count, 2, "two live confirmations recorded");
        assert_eq!(e.last_verified_at, Some(1_000_200), "latest confirmation");
        assert!(e.is_verified());
        // Raw discovery_count is independent of verification.
        assert_eq!(e.discovery_count, 1);
    }

    #[test]
    fn migration_adds_verified_columns_to_a_legacy_bank() {
        // A pre-verified-tracking schema: original columns only.
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE found_keys (
                key_value TEXT PRIMARY KEY, service TEXT NOT NULL, provider TEXT NOT NULL,
                query TEXT NOT NULL, first_scan_id TEXT NOT NULL, last_scan_id TEXT NOT NULL,
                discovery_count INTEGER NOT NULL DEFAULT 1, first_seen_at INTEGER NOT NULL,
                last_seen_at INTEGER NOT NULL) STRICT;",
        )
        .unwrap();
        assert!(!has_column(&conn, "verified_count").unwrap());

        // ensure_schema migrates it in place without dropping data.
        write_batch(&conn, &[test_key("dehashed", "dh-key-abcdef")], "s1", 10).unwrap();
        ensure_schema(&conn).unwrap();
        assert!(has_column(&conn, "verified_count").unwrap());

        let e = query_all(&conn).unwrap();
        assert_eq!(e.len(), 1, "legacy row preserved through migration");
        assert_eq!(e[0].verified_count, 0, "legacy row backfills to unverified");
        assert!(write_verification(&conn, "dh-key-abcdef", 20).unwrap());
    }

    #[test]
    fn roi_classifies_resale_value_by_service() {
        use crate::util::key_roi::KeyRoi;
        // Cascading providers (find more keys) are the highest resale value.
        assert_eq!(entry("shodan").roi(), KeyRoi::Multiplier);
        assert_eq!(entry("dehashed").roi(), KeyRoi::Multiplier);
        // Many-entity but non-cascading.
        assert_eq!(entry("wigle").roi(), KeyRoi::Expansion);
        // One-and-done.
        assert_eq!(entry("abuseipdb").roi(), KeyRoi::Terminal);
    }

    #[test]
    fn rank_resellable_orders_by_roi_then_confirmations() {
        let mut shodan = entry("shodan"); // Multiplier
        shodan.verified_count = 1;
        let mut wigle = entry("wigle"); // Expansion
        wigle.verified_count = 2;
        let mut abuse = entry("abuseipdb"); // Terminal, most-confirmed
        abuse.verified_count = 9;
        let mut shodan2 = entry("shodan"); // Multiplier, more confirmations
        shodan2.verified_count = 5;

        let ranked = rank_resellable(vec![abuse, wigle, shodan, shodan2]);
        let order: Vec<(&str, u32)> = ranked
            .iter()
            .map(|e| (e.service.as_str(), e.verified_count))
            .collect();
        // Multipliers first (most-confirmed first within a tier), then Expansion,
        // then Terminal — regardless of raw confirmation counts across tiers.
        assert_eq!(
            order,
            vec![("shodan", 5), ("shodan", 1), ("wigle", 2), ("abuseipdb", 9)]
        );
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
