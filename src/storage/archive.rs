// Inter-scan entity cache (C9 / SOL-CACHE-INTERSCAN). Methods on `Store`
// backed by the `raw_archive` table defined in SCHEMA_DDL.

use rusqlite::{Connection, params};

use crate::core::{entity::Entity, error::Result};

use super::Store;

/// Delete every `raw_archive` row whose TTL has lapsed
/// (`archived_at + ttl_secs <= unixepoch()`), returning the number removed.
///
/// Single source of truth for the expiry SQL, shared by
/// [`Store::prune_archive`] (the scan-boundary / on-demand path) and the
/// startup garbage-collect in [`super::Store::open`] — which runs against a
/// bare [`Connection`] before the [`Store`] wrapper exists, so it cannot call
/// the method form. Operating on `&Connection` keeps both callers on the exact
/// same predicate the cache lookup uses, so a pruned row is provably one
/// [`Store::lookup_module_result_fresh`] already treats as a miss.
pub(super) fn prune_archive_conn(conn: &Connection) -> rusqlite::Result<usize> {
    conn.execute(
        "DELETE FROM raw_archive WHERE archived_at + ttl_secs <= unixepoch()",
        [],
    )
}

impl Store {
    /// Persist `entities` under `key` with `ttl_secs`. Replaces any
    /// existing entry for the same key (`INSERT OR REPLACE`) so a fresh
    /// query always overwrites a stale one. Best-effort — callers ignore
    /// errors so a storage failure cannot abort an in-progress scan.
    pub fn archive_module_result(
        &self,
        key: &str,
        ttl_secs: u64,
        entities: &[Entity],
    ) -> Result<()> {
        let json = serde_json::to_string(entities)?;
        let conn = self.conn.lock();
        conn.prepare_cached(
            "INSERT OR REPLACE INTO raw_archive(id, archived_at, ttl_secs, result_json)
             VALUES(?1, unixepoch(), ?2, ?3)",
        )?
        .execute(params![key, ttl_secs as i64, json])?;
        Ok(())
    }

    /// Return archived entities for `key` if the entry exists and has not
    /// exceeded its TTL (`archived_at + ttl_secs > unixepoch()`). Returns
    /// `None` on a cache miss or expired entry so the caller falls through
    /// to the live provider.
    pub fn lookup_module_result_fresh(&self, key: &str) -> Result<Option<Vec<Entity>>> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare_cached(
            "SELECT result_json FROM raw_archive
             WHERE id = ?1 AND archived_at + ttl_secs > unixepoch()",
        )?;
        match stmt.query_row(params![key], |r| r.get::<_, String>(0)) {
            Ok(json) => Ok(Some(serde_json::from_str(&json)?)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// Garbage-collect expired inter-scan cache rows, returning the number
    /// pruned. Mirrors [`Store::prune_events`]: `raw_archive` is an unkeyed
    /// cache keyed on distinct `module:kind:target` strings, so without a GC it
    /// grows the database file unbounded across scans of fresh targets on a
    /// low-RAM device — the same bounded-growth rationale that motivates the
    /// events prune. Expired rows are already dead to
    /// [`Store::lookup_module_result_fresh`] (its `WHERE` filters them out), so
    /// deleting them only reclaims space and never changes a lookup result.
    ///
    /// Pruning by the TTL predicate rather than a row cap means no extra index
    /// is required: each row carries its own expiry, the delete touches only
    /// already-stale entries, and a still-fresh cache is left wholly intact.
    /// Called automatically at startup ([`super::Store::open`]) and at each scan
    /// boundary. Best-effort at every call site — a failed GC wastes disk, never
    /// correctness.
    pub fn prune_archive(&self) -> Result<usize> {
        let conn = self.conn.lock();
        let pruned = prune_archive_conn(&conn)?;
        if pruned > 0 {
            tracing::info!("pruned {pruned} expired raw_archive entries");
        }
        Ok(pruned)
    }
}

#[cfg(test)]
mod tests {
    include!("archive_tests.rs");
}
