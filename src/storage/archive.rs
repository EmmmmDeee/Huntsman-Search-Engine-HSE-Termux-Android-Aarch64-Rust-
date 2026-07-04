// Inter-scan entity cache (C9 / SOL-CACHE-INTERSCAN). Methods on `Store`
// backed by the `raw_archive` table defined in SCHEMA_DDL.

use rusqlite::params;

use crate::core::{entity::Entity, error::Result};

use super::Store;

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

    /// Bound the `raw_archive` cache: delete every row past its per-entry TTL,
    /// then cap the table to the newest `max_rows` by insertion time. Expired
    /// rows are already ignored on lookup but were never deleted — over weeks of
    /// scanning distinct `(module, target)` pairs the table (and the DB/WAL) grew
    /// without bound on a low-disk device, the same way the `events` table would
    /// without [`Store::prune_events`]. The cache is best-effort, so evicting a
    /// still-fresh row past the cap only costs a re-query, never correctness.
    /// Returns the number of rows deleted. Called at each scan boundary + startup.
    pub fn prune_raw_archive(&self, max_rows: usize) -> Result<usize> {
        let conn = self.conn.lock();
        let expired = conn.execute(
            "DELETE FROM raw_archive WHERE archived_at + ttl_secs <= unixepoch()",
            [],
        )?;
        // Keep the newest `max_rows` (by insertion time, id as a stable tie-break)
        // and drop the rest — a bounded LRU-by-archival backstop for the case where
        // many entries are still within TTL.
        let excess = conn.execute(
            "DELETE FROM raw_archive WHERE id NOT IN \
             (SELECT id FROM raw_archive ORDER BY archived_at DESC, id DESC LIMIT ?1)",
            params![max_rows as i64],
        )?;
        let total = expired + excess;
        if total > 0 {
            tracing::info!("pruned {total} raw_archive rows ({expired} expired, {excess} excess)");
        }
        Ok(total)
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
}

#[cfg(test)]
mod tests {
    include!("archive_tests.rs");
}
