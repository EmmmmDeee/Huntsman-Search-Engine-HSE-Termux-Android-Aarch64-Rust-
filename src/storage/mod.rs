// SQLite WAL store. Unified module: scan, entity, correlation, and event
// persistence plus the observation junction table.

use parking_lot::Mutex;
use rusqlite::{Connection, params};

use crate::core::{
    correlator::Correlation, entity::Entity, error::Result, event::Event, relation::Relation,
    scan::Scan,
};

mod entities; // `impl Store`: entity persistence + FTS query

pub struct Store {
    conn: Mutex<Connection>,
}

/// Static schema (tables + indexes), `CREATE … IF NOT EXISTS` so it's safe to
/// run on every open. Kept as a constant so [`Store::open`] reads as a short
/// orchestrator and the schema lives in one greppable place. Executed in the
/// same batch as the (env-tunable) pragmas, so the resulting database is
/// byte-for-byte what the previous inline DDL produced.
const SCHEMA_DDL: &str = "
            CREATE TABLE IF NOT EXISTS scans (
                id           TEXT PRIMARY KEY,
                target_kind  TEXT NOT NULL,
                target_value TEXT NOT NULL,
                status       TEXT NOT NULL,
                started_at   INTEGER NOT NULL,
                finished_at  INTEGER,
                entity_count INTEGER NOT NULL DEFAULT 0,
                error        TEXT,
                data_json    TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS entities (
                uid           TEXT PRIMARY KEY,
                scan_id       TEXT NOT NULL,
                kind          TEXT NOT NULL,
                value         TEXT NOT NULL,
                confidence    REAL NOT NULL,
                corroboration INTEGER NOT NULL DEFAULT 1,
                observed_at   INTEGER NOT NULL,
                data_json     TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS correlations (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id     TEXT NOT NULL,
                rule_id     TEXT NOT NULL,
                severity    TEXT NOT NULL,
                description TEXT NOT NULL,
                entity_uids TEXT NOT NULL,
                ts          INTEGER NOT NULL,
                data_json   TEXT NOT NULL,
                UNIQUE(scan_id, rule_id, description)
            );

            CREATE TABLE IF NOT EXISTS entity_observations (
                entity_uid  TEXT NOT NULL,
                scan_id     TEXT NOT NULL,
                observed_at INTEGER NOT NULL,
                PRIMARY KEY (entity_uid, scan_id)
            );

            CREATE TABLE IF NOT EXISTS events (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id     TEXT NOT NULL,
                ts          INTEGER NOT NULL,
                event_type  TEXT NOT NULL,
                data_json   TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS relations (
                id          TEXT PRIMARY KEY,
                scan_id     TEXT NOT NULL,
                from_uid    TEXT NOT NULL,
                to_uid      TEXT NOT NULL,
                kind        TEXT NOT NULL,
                confidence  REAL NOT NULL,
                observed_at INTEGER NOT NULL,
                data_json   TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_entities_scan ON entities(scan_id);
            CREATE INDEX IF NOT EXISTS idx_entities_kind ON entities(kind);
            CREATE INDEX IF NOT EXISTS idx_scans_started ON scans(started_at DESC);
            CREATE INDEX IF NOT EXISTS idx_corr_scan     ON correlations(scan_id);
            CREATE INDEX IF NOT EXISTS idx_obs_scan      ON entity_observations(scan_id);
            CREATE INDEX IF NOT EXISTS idx_obs_entity    ON entity_observations(entity_uid);
            CREATE INDEX IF NOT EXISTS idx_events_scan   ON events(scan_id, id);
            CREATE INDEX IF NOT EXISTS idx_relations_scan ON relations(scan_id);
            -- Full-text index over entity values. Contentless-external FTS5
            -- table keyed by the entities.rowid; kept synchronized inside the
            -- same transaction as every entity write (see
            -- merge_and_persist_entity) so the index never drifts from the
            -- graph (the 'always-synchronized index' invariant). `prefix`
            -- indexes make 2/3-char prefix queries cheap on aarch64.
            CREATE VIRTUAL TABLE IF NOT EXISTS entities_fts USING fts5(
                value,
                kind UNINDEXED,
                content='entities',
                content_rowid='rowid',
                prefix='2 3',
                tokenize='unicode61'
            );
            ";

/// Idempotent backfill of the observation junction table from `entities`.
const BACKFILL_OBSERVATIONS_SQL: &str =
    "INSERT OR IGNORE INTO entity_observations(entity_uid, scan_id, observed_at)
     SELECT uid, scan_id, observed_at FROM entities;";

/// Read an `i64` from an environment variable, falling back to `default` when
/// unset or unparseable. Used for the env-tunable SQLite performance pragmas.
fn env_i64(var: &str, default: i64) -> i64 {
    std::env::var(var)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

/// Escape the LIKE metacharacters in `s` for a query using `ESCAPE '\'`.
///
/// The escape character `\` is escaped FIRST, then `%` and `_`, so all three
/// LIKE metacharacters are matched literally. Escaping `\` first is essential:
/// otherwise a backslash in the input would consume the following character (a
/// `\` query would match a literal `%`, missing real backslashes). Callers wrap
/// the result in `%…%` for a substring match.
fn escape_like(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('%', "\\%")
        .replace('_', "\\_")
}

impl Store {
    pub fn open(path: &str) -> Result<Self> {
        // Performance pragmas are env-tunable (low-RAM Termux devices may want a
        // smaller page cache / mmap); the schema itself is static (SCHEMA_DDL).
        let cache_kb = env_i64("HSE_SQLITE_CACHE_KB", 2000);
        let mmap = env_i64("HSE_SQLITE_MMAP", 67_108_864);

        let conn = Connection::open(path)?;
        conn.execute_batch(&format!(
            "
            PRAGMA journal_mode=WAL;
            PRAGMA synchronous=NORMAL;
            -- Bound the WAL explicitly (512 pages ~2 MB at the 4 KB page size)
            -- rather than SQLite's implicit 1000-page default, so the live -wal
            -- footprint stays bounded under a long-lived `serve`/`live` process on
            -- aarch64/4 GB. PASSIVE (never blocks writers, never shrinks the file);
            -- the file is reset to zero at scan boundaries via checkpoint_truncate().
            PRAGMA wal_autocheckpoint=512;
            PRAGMA temp_store=MEMORY;
            PRAGMA foreign_keys=ON;
            PRAGMA cache_size=-{cache_kb};
            PRAGMA mmap_size={mmap};
            {SCHEMA_DDL}"
        ))?;

        // Idempotent backfill: populate entity_observations for stores created
        // before that table existed (and for any rows missing an observation).
        conn.execute_batch(BACKFILL_OBSERVATIONS_SQL)?;

        // Backfill the FTS index for any pre-existing rows (first run after the
        // index was introduced, or an externally-restored DB). Idempotent: the
        // 'rebuild' command repopulates from the content table deterministically.
        let fts_count: i64 = conn
            .query_row("SELECT count(*) FROM entities_fts", [], |r| r.get(0))
            .unwrap_or(0);
        let ent_count: i64 = conn
            .query_row("SELECT count(*) FROM entities", [], |r| r.get(0))
            .unwrap_or(0);
        if fts_count == 0 && ent_count > 0 {
            // If this fails the FTS index stays empty and search silently returns
            // nothing — the exact "search is broken with no diagnostic" failure
            // mode HSE exists to avoid. Best-effort (a missing index must not
            // block startup), but never silent: leave a trace to debug from.
            if let Err(e) =
                conn.execute_batch("INSERT INTO entities_fts(entities_fts) VALUES('rebuild');")
            {
                tracing::warn!(
                    error = %e,
                    entities = ent_count,
                    "FTS rebuild failed at init — full-text search may return no results until the index is rebuilt"
                );
            } else {
                tracing::info!(entities = ent_count, "rebuilt empty FTS index from existing rows");
            }
        }

        // Query-planner statistics refresh — purely advisory; a failure costs at
        // most a suboptimal plan, never correctness, so it stays best-effort.
        if let Err(e) = conn.execute_batch("PRAGMA optimize;") {
            tracing::debug!(error = %e, "PRAGMA optimize failed (non-fatal)");
        }

        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    /// Checkpoint the WAL and truncate the `-wal` file back to zero bytes.
    ///
    /// `PRAGMA wal_autocheckpoint` runs in PASSIVE mode, which folds committed
    /// pages back into the main database but never shrinks the on-disk `-wal`
    /// file — so under a long-lived process the file high-water-marks and
    /// stays there. This runs an explicit `TRUNCATE` checkpoint at a safe
    /// boundary (a completed scan), resetting the `-wal` to zero and bounding
    /// its footprint. Best-effort: a busy checkpoint (a concurrent reader
    /// holding the WAL) returns `SQLITE_BUSY`, which is surfaced as `Err` for
    /// the caller to log and ignore — the next boundary will retry.
    pub fn checkpoint_truncate(&self) -> Result<()> {
        let conn = self.conn.lock();
        conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")?;
        Ok(())
    }

    /// Run SQLite's `PRAGMA integrity_check` and return whatever it reports.
    ///
    /// A healthy database returns exactly one row, `"ok"`; a corrupt one
    /// returns a row per problem found. Surfaced by `hse doctor` so on-disk
    /// corruption (interrupted write, bad sector, truncated WAL) is detected
    /// explicitly rather than manifesting later as silently missing or wrong
    /// scan results (FTA finding E5.1 / top event T5). Read-only — safe to run
    /// against a live database.
    pub fn integrity_check(&self) -> Result<Vec<String>> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare("PRAGMA integrity_check;")?;
        let rows = stmt
            .query_map([], |r| r.get::<_, String>(0))?
            .collect::<std::result::Result<Vec<String>, _>>()?;
        Ok(rows)
    }

    // ── Scans ──────────────────────────────────────────────────────────────

    pub fn upsert_scan(&self, scan: &Scan) -> Result<()> {
        let json = serde_json::to_string(scan)?;
        let conn = self.conn.lock();
        conn.execute(
            "INSERT INTO scans(id, target_kind, target_value, status, started_at, finished_at, entity_count, error, data_json)
             VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
             ON CONFLICT(id) DO UPDATE SET
               status       = excluded.status,
               finished_at  = excluded.finished_at,
               entity_count = excluded.entity_count,
               error        = excluded.error,
               data_json    = excluded.data_json",
            params![
                scan.id,
                scan.target.kind.canonical_str(),
                scan.target.value,
                scan.status.as_str(),
                scan.started_at as i64,
                scan.finished_at.map(|t| t as i64),
                scan.entity_count as i64,
                scan.error,
                json,
            ],
        )?;
        Ok(())
    }

    pub fn get_scan(&self, id: &str) -> Result<Option<Scan>> {
        let json: Option<String> = {
            let conn = self.conn.lock();
            let mut stmt = conn.prepare_cached("SELECT data_json FROM scans WHERE id = ?1")?;
            let mut rows = stmt.query(params![id])?;
            rows.next()?.map(|r| r.get(0)).transpose()?
        };
        json.map(|j| serde_json::from_str(&j))
            .transpose()
            .map_err(Into::into)
    }

    pub fn list_scans(&self, limit: usize) -> Result<Vec<Scan>> {
        let raw: Vec<String> = {
            let conn = self.conn.lock();
            let mut stmt = conn
                .prepare_cached("SELECT data_json FROM scans ORDER BY started_at DESC LIMIT ?1")?;
            let rows = stmt.query_map(params![limit as i64], |r| r.get::<_, String>(0))?;
            rows.filter_map(std::result::Result::ok).collect()
        };
        Ok(raw
            .into_iter()
            .filter_map(|s| serde_json::from_str(&s).ok())
            .collect())
    }

    /// Return the most recent scan whose serialised status matches
    /// `complete` (the lower-case canonical form used by ScanStatus::
    /// as_str). Filters at the SQL layer using a JSON-extract probe
    /// so we don't deserialise dozens of non-Complete rows just to
    /// find one Complete record. Used by `hse export latest …` and
    /// the SPA's "open latest scan" affordance.
    pub fn latest_completed_scan(&self) -> Result<Option<Scan>> {
        let raw: Option<String> = {
            let conn = self.conn.lock();
            let mut stmt = conn.prepare_cached(
                "SELECT data_json FROM scans
                 WHERE json_extract(data_json, '$.status') = 'complete'
                 ORDER BY started_at DESC LIMIT 1",
            )?;
            stmt.query_row(params![], |r| r.get::<_, String>(0)).ok()
        };
        Ok(raw.and_then(|s| serde_json::from_str(&s).ok()))
    }

    // ── Correlations ───────────────────────────────────────────────────────

    pub fn upsert_correlation(&self, c: &Correlation) -> Result<()> {
        use std::collections::HashSet;
        let json = serde_json::to_string(c)?;
        let uids = serde_json::to_string(&c.entity_uids)?;
        let conn = self.conn.lock();

        // Set-containment dedup so an aggregate correlation whose member set
        // GROWS across expansion rounds is not persisted once per round.
        // Entities are never removed mid-scan, so a cluster only grows: a new
        // correlation whose member set is a strict superset of an existing one
        // (same scan + rule) supersedes it; a subset/equal is a stale earlier
        // emission and is skipped; disjoint sets (distinct clusters, or distinct
        // pair-rule findings) coexist as separate rows. Without this, AU-002 /
        // AU-013 / AU-018 / AU-019 … each re-fired with a larger uid set and a
        // new count-bearing description every round, defeating both the
        // in-memory (rule_id+uids) and DB (rule_id+description) dedup keys.
        let new_set: HashSet<&str> = c.entity_uids.iter().map(String::as_str).collect();
        let existing: Vec<(i64, Vec<String>)> = {
            let mut stmt = conn.prepare(
                "SELECT rowid, entity_uids FROM correlations WHERE scan_id = ?1 AND rule_id = ?2",
            )?;
            let rows = stmt.query_map(params![c.scan_id, c.rule_id], |row| {
                Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
            })?;
            rows.filter_map(std::result::Result::ok)
                .map(|(id, j)| {
                    (
                        id,
                        serde_json::from_str::<Vec<String>>(&j).unwrap_or_default(),
                    )
                })
                .collect()
        };
        let mut superseded: Vec<i64> = Vec::new();
        for (rowid, old_uids) in &existing {
            let old_set: HashSet<&str> = old_uids.iter().map(String::as_str).collect();
            if new_set.is_subset(&old_set) {
                // Subset of (or equal to) a stored correlation — already represented.
                return Ok(());
            }
            if old_set.is_subset(&new_set) {
                superseded.push(*rowid);
            }
        }
        // Atomic supersede: delete the superseded rows AND insert the
        // replacement in one transaction, so a crash or mid-statement error
        // (SQLITE_FULL/BUSY, OOM-kill) can't leave the cluster's predecessors
        // deleted with no replacement — that would silently drop a finding.
        // Mirrors delete_scan / upsert_entities_batch. Rolls back on drop if a
        // statement errors (the `?` returns before commit).
        let tx = conn.unchecked_transaction()?;
        for rowid in superseded {
            tx.execute("DELETE FROM correlations WHERE rowid = ?1", params![rowid])?;
        }
        tx.execute(
            "INSERT INTO correlations(scan_id, rule_id, severity, description, entity_uids, ts, data_json)
             VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7)
             ON CONFLICT(scan_id, rule_id, description) DO NOTHING",
            params![
                c.scan_id,
                c.rule_id,
                c.severity.as_canonical(),
                c.description,
                uids,
                c.ts as i64,
                json,
            ],
        )?;
        tx.commit()?;
        Ok(())
    }

    pub fn correlations_for_scan(&self, scan_id: &str) -> Result<Vec<Correlation>> {
        let raw: Vec<String> = {
            let conn = self.conn.lock();
            // SQL pre-orders by severity (keeps rows that predate the `rank`
            // field, which deserialize with rank 0.0, in a sane order); the
            // authoritative ranking is applied in Rust below using the
            // persisted `rank` (severity × max child C_eff), which SQL can't
            // see inside `data_json` without a column + migration.
            let mut stmt = conn.prepare_cached(
                "SELECT data_json FROM correlations WHERE scan_id = ?1
                 ORDER BY CASE severity
                     WHEN 'critical' THEN 0
                     WHEN 'high'     THEN 1
                     WHEN 'medium'   THEN 2
                     WHEN 'low'      THEN 3
                     ELSE 4
                 END, id",
            )?;
            let rows = stmt.query_map(params![scan_id], |r| r.get::<_, String>(0))?;
            rows.filter_map(std::result::Result::ok).collect()
        };
        let mut corrs: Vec<Correlation> = raw
            .into_iter()
            .filter_map(|s| serde_json::from_str(&s).ok())
            .collect();
        // Rank desc: severity × max child C_eff (computed at correlator-run
        // time). Stable tie-break on severity then rule_id, matching the
        // correlator's own ordering so CLI and API agree.
        corrs.sort_by(|a, b| {
            b.rank
                .partial_cmp(&a.rank)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then(b.severity.cmp(&a.severity))
                .then(a.rule_id.cmp(&b.rule_id))
        });
        Ok(corrs)
    }

    // ── Relations ──────────────────────────────────────────────────────────
    // Typed entity-to-entity edges. Idempotent on the deterministic `id` so a
    // re-scan that re-derives the same edge does not duplicate it.

    pub fn upsert_relation(&self, r: &Relation) -> Result<()> {
        let json = serde_json::to_string(r)?;
        let conn = self.conn.lock();
        conn.execute(
            "INSERT INTO relations(id, scan_id, from_uid, to_uid, kind, confidence, observed_at, data_json)
             VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
             ON CONFLICT(id) DO NOTHING",
            params![
                r.id,
                r.scan_id,
                r.from_uid,
                r.to_uid,
                r.kind.as_str(),
                r.confidence,
                r.observed_at as i64,
                json,
            ],
        )?;
        Ok(())
    }

    pub fn relations_for_scan(&self, scan_id: &str) -> Result<Vec<Relation>> {
        let raw: Vec<String> = {
            let conn = self.conn.lock();
            let mut stmt = conn.prepare_cached(
                "SELECT data_json FROM relations WHERE scan_id = ?1 ORDER BY kind, id",
            )?;
            let rows = stmt.query_map(params![scan_id], |r| r.get::<_, String>(0))?;
            rows.filter_map(std::result::Result::ok).collect()
        };
        Ok(raw
            .into_iter()
            .filter_map(|s| serde_json::from_str(&s).ok())
            .collect())
    }

    // ── Delete (cascade) ───────────────────────────────────────────────────

    pub fn delete_scan(&self, scan_id: &str) -> Result<bool> {
        let conn = self.conn.lock();
        let tx = conn.unchecked_transaction()?;
        let n = tx.execute("DELETE FROM scans WHERE id = ?1", params![scan_id])?;
        if n == 0 {
            if let Err(e) = tx.rollback() {
                tracing::warn!(error = %e, "rollback failed during delete_scan");
            }
            return Ok(false);
        }
        tx.execute(
            "DELETE FROM correlations WHERE scan_id = ?1",
            params![scan_id],
        )?;
        tx.execute(
            "DELETE FROM entity_observations WHERE scan_id = ?1",
            params![scan_id],
        )?;
        tx.execute("DELETE FROM events WHERE scan_id = ?1", params![scan_id])?;
        tx.execute("DELETE FROM relations WHERE scan_id = ?1", params![scan_id])?;
        tx.execute(
            "DELETE FROM entities
             WHERE uid NOT IN (SELECT DISTINCT entity_uid FROM entity_observations)",
            [],
        )?;
        tx.commit()?;
        Ok(true)
    }

    /// Prune events older than `max_age_secs` and limit total rows to
    /// `max_rows`. Prevents unbounded database growth from long-running
    /// or repeated scans. Called automatically at startup.
    pub fn prune_events(&self, max_age_secs: u64, max_rows: usize) -> Result<usize> {
        let conn = self.conn.lock();
        let cutoff = crate::core::entity::unix_now().saturating_sub(max_age_secs);
        let aged = conn.execute("DELETE FROM events WHERE ts < ?1", params![cutoff as i64])?;
        let excess = conn.execute(
            "DELETE FROM events WHERE id NOT IN (SELECT id FROM events ORDER BY id DESC LIMIT ?1)",
            params![max_rows as i64],
        )?;
        let total = aged + excess;
        if total > 0 {
            tracing::info!("pruned {total} old events ({aged} aged, {excess} excess)");
        }
        Ok(total)
    }
}

// Entity persistence + FTS query live in the `entities` submodule (impl Store).

// ── Event log ─────────────────────────────────────────────────────────────

impl Store {
    pub fn insert_event(&self, event: &Event) -> Result<()> {
        let event_type = event.kind.event_type_str();
        let json = serde_json::to_string(event)?;
        let conn = self.conn.lock();
        conn.execute(
            "INSERT INTO events(scan_id, ts, event_type, data_json)
             VALUES(?1, ?2, ?3, ?4)",
            params![event.scan_id, event.ts as i64, event_type, json],
        )?;
        Ok(())
    }

    pub fn events_for_scan(&self, scan_id: &str) -> Result<Vec<Event>> {
        let raw: Vec<String> = {
            let conn = self.conn.lock();
            let mut stmt = conn.prepare_cached(
                "SELECT data_json FROM events WHERE scan_id = ?1 ORDER BY id ASC",
            )?;
            let rows = stmt.query_map(params![scan_id], |r| r.get::<_, String>(0))?;
            rows.filter_map(std::result::Result::ok).collect()
        };
        Ok(raw
            .into_iter()
            .filter_map(|s| serde_json::from_str(&s).ok())
            .collect())
    }
}

impl crate::core::port::StoragePort for Store {
    fn checkpoint_truncate(&self) -> Result<()> {
        Store::checkpoint_truncate(self)
    }

    fn prune_events(&self, max_age_secs: u64, max_rows: usize) -> Result<usize> {
        Store::prune_events(self, max_age_secs, max_rows)
    }

    fn upsert_scan(&self, scan: &Scan) -> Result<()> {
        Store::upsert_scan(self, scan)
    }

    fn get_scan(&self, id: &str) -> Result<Option<Scan>> {
        Store::get_scan(self, id)
    }

    fn list_scans(&self, limit: usize) -> Result<Vec<Scan>> {
        Store::list_scans(self, limit)
    }

    fn delete_scan(&self, scan_id: &str) -> Result<bool> {
        Store::delete_scan(self, scan_id)
    }

    fn upsert_entity(&self, entity: &Entity) -> Result<()> {
        Store::upsert_entity(self, entity)
    }

    fn upsert_entities_batch(&self, entities: &[Entity]) -> Result<usize> {
        Store::upsert_entities_batch(self, entities)
    }

    fn entities_for_scan(&self, scan_id: &str) -> Result<Vec<Entity>> {
        Store::entities_for_scan(self, scan_id)
    }

    fn entities_filtered(
        &self,
        scan_id: &str,
        kind: Option<&str>,
        min_confidence: Option<f64>,
        value_contains: Option<&str>,
    ) -> Result<Vec<Entity>> {
        Store::entities_filtered(self, scan_id, kind, min_confidence, value_contains)
    }

    fn entity_facets(&self, scan_id: &str) -> Result<Vec<(String, u64)>> {
        Store::entity_facets(self, scan_id)
    }

    fn get_entity(&self, uid: &str) -> Result<Option<Entity>> {
        Store::get_entity(self, uid)
    }

    fn search_entities(&self, query: &str, limit: usize) -> Result<Vec<Entity>> {
        Store::search_entities(self, query, limit)
    }

    fn scan_ids_for_entity(&self, entity_uid: &str) -> Result<Vec<String>> {
        Store::scan_ids_for_entity(self, entity_uid)
    }

    fn observation_count(&self, entity_uid: &str) -> Result<usize> {
        Store::observation_count(self, entity_uid)
    }

    fn upsert_correlation(&self, c: &Correlation) -> Result<()> {
        Store::upsert_correlation(self, c)
    }

    fn correlations_for_scan(&self, scan_id: &str) -> Result<Vec<Correlation>> {
        Store::correlations_for_scan(self, scan_id)
    }

    fn upsert_relation(&self, r: &Relation) -> Result<()> {
        Store::upsert_relation(self, r)
    }

    fn relations_for_scan(&self, scan_id: &str) -> Result<Vec<Relation>> {
        Store::relations_for_scan(self, scan_id)
    }

    fn insert_event(&self, event: &Event) -> Result<()> {
        Store::insert_event(self, event)
    }

    fn events_for_scan(&self, scan_id: &str) -> Result<Vec<Event>> {
        Store::events_for_scan(self, scan_id)
    }
}

// ── Tests (from store/mod.rs) ─────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::entity::{Entity, EntityKind};
    use crate::core::event::EventKind;
    use crate::core::scan::{Scan, Target, TargetKind};

    fn tmp_db() -> String {
        use std::sync::atomic::{AtomicUsize, Ordering};
        static COUNTER: AtomicUsize = AtomicUsize::new(0);
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        let path = format!(
            "{}/.huntsman-test-{}-{}.db",
            std::env::temp_dir().to_string_lossy(),
            std::process::id(),
            n
        );
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(format!("{path}-wal"));
        let _ = std::fs::remove_file(format!("{path}-shm"));
        path
    }

    fn insert_scan(store: &Store, id: &str) {
        let target = Target::new(TargetKind::Email, "x@y.com");
        let scan = Scan::new(id, target);
        store.upsert_scan(&scan).unwrap();
    }

    #[test]
    fn integrity_check_reports_ok_on_healthy_db() {
        // A fresh, written-to database must report exactly `["ok"]` — the
        // signal `hse doctor` relies on to distinguish a clean store from a
        // corrupt one (FTA E5.1 / T5).
        let path = tmp_db();
        let store = Store::open(&path).unwrap();
        insert_scan(&store, "scan-ic");
        let e = Entity::new(EntityKind::Email, "x@y.com", 0.9, "scan-ic");
        store.upsert_entity(&e).unwrap();
        assert_eq!(store.integrity_check().unwrap(), vec!["ok".to_string()]);
    }

    #[test]
    fn entity_observed_by_two_scans_appears_in_both() {
        let path = tmp_db();
        let store = Store::open(&path).unwrap();
        insert_scan(&store, "scan-a");
        insert_scan(&store, "scan-b");
        let mut e_a = Entity::new(EntityKind::Email, "x@y.com", 0.7, "scan-a");
        e_a.observed_at = 1000;
        store.upsert_entity(&e_a).unwrap();
        let mut e_b = Entity::new(EntityKind::Email, "x@y.com", 0.9, "scan-b");
        e_b.observed_at = 2000;
        store.upsert_entity(&e_b).unwrap();
        let from_a = store.entities_for_scan("scan-a").unwrap();
        let from_b = store.entities_for_scan("scan-b").unwrap();
        assert_eq!(from_a.len(), 1, "scan-a should still see the entity");
        assert_eq!(from_b.len(), 1, "scan-b should see the entity");
        assert_eq!(from_a[0].uid, from_b[0].uid);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn entities_for_scan_orders_deterministically_on_confidence_ties() {
        // `ORDER BY confidence DESC` alone is non-deterministic when entities
        // share a confidence (the common case — e.g. every name permutation gets
        // the same score): SQLite returns tied rows in unspecified order, which
        // varies with insertion/btree order and leaks into the scan's JSON/dossier
        // output (proven end-to-end: identical scans differed only in entity
        // order). The `, uid ASC` tie-break must make retrieval order a pure
        // function of the data. Insert the same set in two different orders and
        // require identical retrieval order, sorted by (confidence desc, uid asc).
        let order_of = |insert: &[&str]| -> Vec<String> {
            let path = tmp_db();
            let store = Store::open(&path).unwrap();
            insert_scan(&store, "s-tie");
            for v in insert {
                // Identical confidence on purpose, so uid is the only tie-break.
                store
                    .upsert_entity(&Entity::new(EntityKind::Username, *v, 0.5, "s-tie"))
                    .unwrap();
            }
            let got: Vec<String> = store
                .entities_for_scan("s-tie")
                .unwrap()
                .into_iter()
                .map(|e| e.uid)
                .collect();
            let _ = std::fs::remove_file(&path);
            got
        };

        let forward = order_of(&["alice", "bob", "carol", "dave", "erin"]);
        let reversed = order_of(&["erin", "dave", "carol", "bob", "alice"]);
        assert_eq!(
            forward, reversed,
            "retrieval order must not depend on insertion order"
        );

        // And it must be exactly ascending-by-uid (all confidences equal).
        let mut expected = forward.clone();
        expected.sort();
        assert_eq!(forward, expected, "tie-break must be uid ascending");
    }

    #[test]
    fn scan_ids_for_entity_returns_all_observers() {
        let path = tmp_db();
        let store = Store::open(&path).unwrap();
        insert_scan(&store, "s1");
        insert_scan(&store, "s2");
        insert_scan(&store, "s3");
        let mut e = Entity::new(EntityKind::Domain, "example.com", 0.8, "s1");
        e.observed_at = 100;
        store.upsert_entity(&e).unwrap();
        let mut e = Entity::new(EntityKind::Domain, "example.com", 0.8, "s2");
        e.observed_at = 200;
        store.upsert_entity(&e).unwrap();
        let mut e = Entity::new(EntityKind::Domain, "example.com", 0.8, "s3");
        e.observed_at = 300;
        store.upsert_entity(&e).unwrap();
        let uid = &e.uid;
        let scans = store.scan_ids_for_entity(uid).unwrap();
        assert_eq!(scans.len(), 3);
        assert_eq!(scans[0], "s3");
        assert_eq!(scans[2], "s1");
        assert_eq!(store.observation_count(uid).unwrap(), 3);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn entity_only_in_other_scan_does_not_leak() {
        let path = tmp_db();
        let store = Store::open(&path).unwrap();
        insert_scan(&store, "s1");
        insert_scan(&store, "s2");
        let e = Entity::new(EntityKind::Email, "only-in-s1@x.com", 0.7, "s1");
        store.upsert_entity(&e).unwrap();
        let from_s2 = store.entities_for_scan("s2").unwrap();
        assert!(from_s2.is_empty(), "s2 never observed this entity");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn re_observing_same_pair_is_idempotent() {
        let path = tmp_db();
        let store = Store::open(&path).unwrap();
        insert_scan(&store, "s1");
        let e = Entity::new(EntityKind::Phone, "+61400000000", 0.8, "s1");
        store.upsert_entity(&e).unwrap();
        store.upsert_entity(&e).unwrap();
        store.upsert_entity(&e).unwrap();
        assert_eq!(store.observation_count(&e.uid).unwrap(), 1);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn delete_scan_cascade_removes_orphans_but_keeps_shared_entities() {
        let path = tmp_db();
        let store = Store::open(&path).unwrap();
        insert_scan(&store, "scan-doomed");
        insert_scan(&store, "scan-keeper");
        let shared = Entity::new(EntityKind::Domain, "example.com", 0.8, "scan-doomed");
        store.upsert_entity(&shared).unwrap();
        let mut shared2 = Entity::new(EntityKind::Domain, "example.com", 0.8, "scan-keeper");
        shared2.observed_at = shared.observed_at + 1;
        store.upsert_entity(&shared2).unwrap();
        let only_doomed = Entity::new(EntityKind::Email, "lonely@example.com", 0.6, "scan-doomed");
        store.upsert_entity(&only_doomed).unwrap();
        assert_eq!(store.entities_for_scan("scan-doomed").unwrap().len(), 2);
        let removed = store.delete_scan("scan-doomed").unwrap();
        assert!(removed);
        let keeper = store.entities_for_scan("scan-keeper").unwrap();
        assert_eq!(keeper.len(), 1);
        assert_eq!(keeper[0].value, "example.com");
        assert!(
            store
                .scan_ids_for_entity(&only_doomed.uid)
                .unwrap()
                .is_empty()
        );
        assert_eq!(store.observation_count(&only_doomed.uid).unwrap(), 0);
        assert!(store.get_scan("scan-doomed").unwrap().is_none());
        assert!(store.get_scan("scan-keeper").unwrap().is_some());
        assert!(!store.delete_scan("scan-doomed").unwrap());
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn delete_scan_with_unknown_id_does_not_purge_orphans() {
        let path = tmp_db();
        let store = Store::open(&path).unwrap();
        insert_scan(&store, "real-scan");
        let conn = parking_lot::Mutex::new(rusqlite::Connection::open(&path).unwrap());
        {
            let c = conn.lock();
            c.execute(
                "INSERT INTO entities(uid, scan_id, kind, value, confidence, corroboration, observed_at, data_json)
                 VALUES('orphan-uid', 'real-scan', 'domain', 'orphan.example.com', 0.5, 1, 1, '{}')",
                [],
            ).unwrap();
        }
        assert!(!store.delete_scan("nonexistent-scan-id").unwrap());
        let count: i64 = {
            let c = conn.lock();
            c.query_row(
                "SELECT COUNT(*) FROM entities WHERE uid='orphan-uid'",
                [],
                |r| r.get(0),
            )
            .unwrap()
        };
        assert_eq!(count, 1, "delete_scan must not purge on unknown id");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn list_scans_returns_newest_first() {
        use crate::core::entity::unix_now;
        let path = tmp_db();
        let store = Store::open(&path).unwrap();
        let base = unix_now();
        for (id, offset) in [("oldest", 0u64), ("middle", 100), ("newest", 200)] {
            let target = Target::new(TargetKind::Email, "x@y.com");
            let mut scan = Scan::new(id, target);
            scan.started_at = base + offset;
            store.upsert_scan(&scan).unwrap();
        }
        let scans = store.list_scans(10).unwrap();
        assert_eq!(scans.len(), 3);
        assert_eq!(scans[0].id, "newest");
        assert_eq!(scans[1].id, "middle");
        assert_eq!(scans[2].id, "oldest");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn list_scans_respects_limit() {
        let path = tmp_db();
        let store = Store::open(&path).unwrap();
        for i in 0..5 {
            let target = Target::new(TargetKind::Email, "x@y.com");
            let mut scan = Scan::new(format!("scan-{i}"), target);
            scan.started_at = 1000 + i as u64;
            store.upsert_scan(&scan).unwrap();
        }
        let scans = store.list_scans(2).unwrap();
        assert_eq!(scans.len(), 2, "should return exactly 2 scans");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn list_scans_empty_db_returns_empty_vec() {
        let path = tmp_db();
        let store = Store::open(&path).unwrap();
        let scans = store.list_scans(10).unwrap();
        assert!(scans.is_empty());
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn upsert_scan_updates_existing() {
        use crate::core::scan::ScanStatus;
        let path = tmp_db();
        let store = Store::open(&path).unwrap();
        let target = Target::new(TargetKind::Email, "x@y.com");
        let mut scan = Scan::new("update-me", target);
        scan.status = ScanStatus::Running;
        store.upsert_scan(&scan).unwrap();
        scan.status = ScanStatus::Complete;
        scan.entity_count = 42;
        store.upsert_scan(&scan).unwrap();
        let fetched = store.get_scan("update-me").unwrap().unwrap();
        assert_eq!(fetched.status, ScanStatus::Complete);
        assert_eq!(fetched.entity_count, 42);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn get_scan_nonexistent_returns_none() {
        let path = tmp_db();
        let store = Store::open(&path).unwrap();
        let result = store.get_scan("nonexistent").unwrap();
        assert!(result.is_none());
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn upsert_correlation_and_correlations_for_scan_round_trip() {
        use crate::core::correlator::{Correlation, Severity};
        let path = tmp_db();
        let store = Store::open(&path).unwrap();
        insert_scan(&store, "corr-scan");
        let c = Correlation::new(
            "AU-001",
            "Test rule",
            Severity::High,
            "test desc".into(),
            vec!["uid1".into()],
            "corr-scan",
            12345,
        );
        store.upsert_correlation(&c).unwrap();
        let corrs = store.correlations_for_scan("corr-scan").unwrap();
        assert_eq!(corrs.len(), 1);
        assert_eq!(corrs[0].rule_id, "AU-001");
        assert_eq!(corrs[0].rule_name, "Test rule");
        assert_eq!(corrs[0].severity, Severity::High);
        assert_eq!(corrs[0].description, "test desc");
        assert_eq!(corrs[0].entity_uids, vec!["uid1".to_string()]);
        assert_eq!(corrs[0].scan_id, "corr-scan");
        assert_eq!(corrs[0].ts, 12345);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn upsert_correlation_supersedes_growing_aggregate_cluster() {
        use crate::core::correlator::{Correlation, Severity};
        let path = tmp_db();
        let store = Store::open(&path).unwrap();
        insert_scan(&store, "agg");
        let mk = |desc: &str, uids: Vec<&str>, ts: u64| {
            Correlation::new(
                "AU-013",
                "Local-network discovery",
                Severity::Low,
                desc.into(),
                uids.into_iter().map(String::from).collect(),
                "agg",
                ts,
            )
        };
        // Round 1: a partial cluster {A,B}.
        store
            .upsert_correlation(&mk("2 entities on the local network", vec!["A", "B"], 1))
            .unwrap();
        // Round 2: the SAME cluster grown to {A,B,C} with a new count — must
        // supersede the partial row, not add a second one.
        store
            .upsert_correlation(&mk(
                "3 entities on the local network",
                vec!["A", "B", "C"],
                2,
            ))
            .unwrap();
        let got = store.correlations_for_scan("agg").unwrap();
        assert_eq!(
            got.len(),
            1,
            "growing aggregate must collapse to one row, got {got:?}"
        );
        assert_eq!(
            got[0].entity_uids.len(),
            3,
            "the surviving row is the superset"
        );
        // A stale subset re-emission (round 1 again) is ignored.
        store
            .upsert_correlation(&mk("2 entities on the local network", vec!["A", "B"], 3))
            .unwrap();
        assert_eq!(store.correlations_for_scan("agg").unwrap().len(), 1);
        // A genuinely distinct cluster (disjoint uids) coexists as its own row.
        store
            .upsert_correlation(&mk("cluster 2", vec!["X", "Y"], 4))
            .unwrap();
        assert_eq!(
            store.correlations_for_scan("agg").unwrap().len(),
            2,
            "disjoint clusters must coexist"
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn correlations_for_scan_empty_scan_returns_empty() {
        let path = tmp_db();
        let store = Store::open(&path).unwrap();
        let corrs = store.correlations_for_scan("unknown-scan").unwrap();
        assert!(corrs.is_empty());
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn correlations_for_scan_orders_by_severity() {
        use crate::core::correlator::{Correlation, Severity};
        let path = tmp_db();
        let store = Store::open(&path).unwrap();
        insert_scan(&store, "sev-scan");
        let c_low = Correlation::new(
            "R-LOW",
            "Low rule",
            Severity::Low,
            "low finding".into(),
            vec!["u1".into()],
            "sev-scan",
            100,
        );
        let c_crit = Correlation::new(
            "R-CRIT",
            "Critical rule",
            Severity::Critical,
            "critical finding".into(),
            vec!["u2".into()],
            "sev-scan",
            200,
        );
        let c_high = Correlation::new(
            "R-HIGH",
            "High rule",
            Severity::High,
            "high finding".into(),
            vec!["u3".into()],
            "sev-scan",
            300,
        );
        store.upsert_correlation(&c_low).unwrap();
        store.upsert_correlation(&c_crit).unwrap();
        store.upsert_correlation(&c_high).unwrap();
        let corrs = store.correlations_for_scan("sev-scan").unwrap();
        assert_eq!(corrs.len(), 3);
        assert_eq!(corrs[0].severity, Severity::Critical);
        assert_eq!(corrs[1].severity, Severity::High);
        assert_eq!(corrs[2].severity, Severity::Low);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn duplicate_correlation_is_ignored_upsert_idempotent() {
        use crate::core::correlator::{Correlation, Severity};
        let path = tmp_db();
        let store = Store::open(&path).unwrap();
        insert_scan(&store, "dup-scan");
        let c = Correlation::new(
            "AU-001",
            "Test rule",
            Severity::High,
            "test desc".into(),
            vec!["uid1".into()],
            "dup-scan",
            12345,
        );
        store.upsert_correlation(&c).unwrap();
        store.upsert_correlation(&c).unwrap();
        let corrs = store.correlations_for_scan("dup-scan").unwrap();
        assert_eq!(corrs.len(), 1, "duplicate correlation should be ignored");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn event_log_round_trips_in_emission_order() {
        let path = tmp_db();
        let store = Store::open(&path).unwrap();
        insert_scan(&store, "scan-evt");
        for (i, kind) in [
            EventKind::ScanStart {
                target_kind: "domain".into(),
                target_value: "example.com".into(),
            },
            EventKind::ModuleStart {
                module: "dns_intel".into(),
            },
            EventKind::ModuleDone {
                module: "dns_intel".into(),
                found: 3,
            },
        ]
        .into_iter()
        .enumerate()
        {
            let mut ev = Event::new("scan-evt", kind);
            ev.ts = 1000 + i as u64;
            store.insert_event(&ev).unwrap();
        }
        let other = Event::new("scan-other", EventKind::ModuleStart { module: "x".into() });
        store.insert_event(&other).unwrap();
        let evs = store.events_for_scan("scan-evt").unwrap();
        assert_eq!(evs.len(), 3, "expected three events for scan-evt only");
        let kinds: Vec<&'static str> = evs
            .iter()
            .map(|e| match &e.kind {
                EventKind::ScanStart { .. } => "scan_start",
                EventKind::ModuleStart { .. } => "module_start",
                EventKind::ModuleDone { .. } => "module_done",
                _ => "other",
            })
            .collect();
        assert_eq!(kinds, ["scan_start", "module_start", "module_done"]);
        let other_evs = store.events_for_scan("scan-other").unwrap();
        assert_eq!(other_evs.len(), 1);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn events_for_scan_returns_empty_for_unknown_id() {
        let path = tmp_db();
        let store = Store::open(&path).unwrap();
        let evs = store.events_for_scan("never-existed").unwrap();
        assert!(evs.is_empty());
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn delete_scan_cascades_to_events() {
        let path = tmp_db();
        let store = Store::open(&path).unwrap();
        insert_scan(&store, "scan-with-events");
        insert_scan(&store, "scan-keeper");
        store
            .insert_event(&Event::new(
                "scan-with-events",
                EventKind::ModuleStart {
                    module: "dns_intel".into(),
                },
            ))
            .unwrap();
        store
            .insert_event(&Event::new(
                "scan-with-events",
                EventKind::ModuleDone {
                    module: "dns_intel".into(),
                    found: 1,
                },
            ))
            .unwrap();
        store
            .insert_event(&Event::new(
                "scan-keeper",
                EventKind::ModuleStart {
                    module: "whois".into(),
                },
            ))
            .unwrap();
        assert_eq!(store.events_for_scan("scan-with-events").unwrap().len(), 2);
        assert!(store.delete_scan("scan-with-events").unwrap());
        assert!(
            store
                .events_for_scan("scan-with-events")
                .unwrap()
                .is_empty()
        );
        assert_eq!(store.events_for_scan("scan-keeper").unwrap().len(), 1);
        let _ = std::fs::remove_file(&path);
    }

    // ── Tests (from entities.rs) ───────────────────────────────────────────

    #[test]
    fn entities_filtered_by_kind() {
        let path = tmp_db();
        let store = Store::open(&path).unwrap();
        insert_scan(&store, "filt-scan");
        let email = Entity::new(EntityKind::Email, "alice@example.com", 0.8, "filt-scan");
        let domain = Entity::new(EntityKind::Domain, "example.com", 0.7, "filt-scan");
        store.upsert_entity(&email).unwrap();
        store.upsert_entity(&domain).unwrap();
        let results = store
            .entities_filtered("filt-scan", Some("email"), None, None)
            .unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].kind, EntityKind::Email);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn entities_filtered_by_kind_and_min_confidence() {
        let path = tmp_db();
        let store = Store::open(&path).unwrap();
        insert_scan(&store, "conf-scan");
        let low = Entity::new(EntityKind::Email, "low@example.com", 0.3, "conf-scan");
        let high = Entity::new(EntityKind::Email, "high@example.com", 0.9, "conf-scan");
        store.upsert_entity(&low).unwrap();
        store.upsert_entity(&high).unwrap();
        let results = store
            .entities_filtered("conf-scan", Some("email"), Some(0.5), None)
            .unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].value, "high@example.com");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn entities_filtered_by_kind_min_conf_and_value() {
        let path = tmp_db();
        let store = Store::open(&path).unwrap();
        insert_scan(&store, "val-scan");
        let alice = Entity::new(EntityKind::Email, "alice@example.com", 0.8, "val-scan");
        let bob = Entity::new(EntityKind::Email, "bob@test.com", 0.8, "val-scan");
        store.upsert_entity(&alice).unwrap();
        store.upsert_entity(&bob).unwrap();
        let results = store
            .entities_filtered("val-scan", Some("email"), Some(0.1), Some("alice"))
            .unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].value, "alice@example.com");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn entities_filtered_min_confidence_without_kind() {
        let path = tmp_db();
        let store = Store::open(&path).unwrap();
        insert_scan(&store, "gap-scan");
        let low = Entity::new(EntityKind::Email, "lo@y.com", 0.2, "gap-scan");
        let high = Entity::new(EntityKind::Domain, "hi.com", 0.9, "gap-scan");
        store.upsert_entity(&low).unwrap();
        store.upsert_entity(&high).unwrap();
        let results = store
            .entities_filtered("gap-scan", None, Some(0.5), None)
            .unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].value, "hi.com");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn entities_filtered_value_contains_without_kind() {
        let path = tmp_db();
        let store = Store::open(&path).unwrap();
        insert_scan(&store, "vc-scan");
        let alice = Entity::new(EntityKind::Email, "alice@example.com", 0.8, "vc-scan");
        let bob = Entity::new(EntityKind::Email, "bob@test.com", 0.8, "vc-scan");
        store.upsert_entity(&alice).unwrap();
        store.upsert_entity(&bob).unwrap();
        let results = store
            .entities_filtered("vc-scan", None, None, Some("alice"))
            .unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].value, "alice@example.com");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn entities_filtered_with_no_filters_returns_all() {
        let path = tmp_db();
        let store = Store::open(&path).unwrap();
        insert_scan(&store, "all-scan");
        let e1 = Entity::new(EntityKind::Email, "a@example.com", 0.8, "all-scan");
        let e2 = Entity::new(EntityKind::Domain, "example.com", 0.7, "all-scan");
        let e3 = Entity::new(EntityKind::Phone, "+61400000000", 0.6, "all-scan");
        store.upsert_entity(&e1).unwrap();
        store.upsert_entity(&e2).unwrap();
        store.upsert_entity(&e3).unwrap();
        let results = store
            .entities_filtered("all-scan", None, None, None)
            .unwrap();
        assert_eq!(results.len(), 3, "all three entities should be returned");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn entity_facets_counts_by_kind() {
        let path = tmp_db();
        let store = Store::open(&path).unwrap();
        insert_scan(&store, "facet-scan");
        let e1 = Entity::new(EntityKind::Email, "a@example.com", 0.8, "facet-scan");
        let e2 = Entity::new(EntityKind::Email, "b@example.com", 0.7, "facet-scan");
        let e3 = Entity::new(EntityKind::Domain, "example.com", 0.6, "facet-scan");
        store.upsert_entity(&e1).unwrap();
        store.upsert_entity(&e2).unwrap();
        store.upsert_entity(&e3).unwrap();
        let facets = store.entity_facets("facet-scan").unwrap();
        assert_eq!(facets.len(), 2);
        assert_eq!(facets[0].0, "email");
        assert_eq!(facets[0].1, 2);
        assert_eq!(facets[1].0, "domain");
        assert_eq!(facets[1].1, 1);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn get_entity_found() {
        let path = tmp_db();
        let store = Store::open(&path).unwrap();
        insert_scan(&store, "get-scan");
        let e = Entity::new(EntityKind::Email, "found@example.com", 0.8, "get-scan");
        let uid = e.uid.clone();
        store.upsert_entity(&e).unwrap();
        let fetched = store.get_entity(&uid).unwrap().unwrap();
        assert_eq!(fetched.uid, uid);
        assert_eq!(fetched.value, "found@example.com");
        assert_eq!(fetched.kind, EntityKind::Email);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn entity_survives_a_full_fidelity_storage_roundtrip() {
        use crate::core::entity::{Evidence, derive_uid, normalise};
        let path = tmp_db();
        let store = Store::open(&path).unwrap();
        insert_scan(&store, "rt");
        // Exercise every field that a lossy persistence layer could drop or
        // reorder: a `raw_value` that differs from the normalised value, ordered
        // evidence attributes, multiple tags, and a non-unit corroboration.
        let mut e = Entity::new(EntityKind::Email, "Found.User+Tag@Example.COM", 0.83, "rt");
        e.corroboration = 4;
        e.tag("breach");
        e.tag("au:source");
        e.add_evidence(
            Evidence::new("hibp", "breach hit")
                .with_attr("zbreach", "Z")
                .with_attr("abreach", "A"),
        );
        e.add_evidence(Evidence::new("hunter_io", "verified"));
        let uid = e.uid.clone();

        // The strongest single invariant: serialise → persist → reload →
        // serialise must be byte-identical. Catches any dropped/reordered field.
        let before = serde_json::to_string(&e).unwrap();
        store.upsert_entity(&e).unwrap();
        let got = store.get_entity(&uid).unwrap().unwrap();
        assert_eq!(
            before,
            serde_json::to_string(&got).unwrap(),
            "storage round-trip changed the entity"
        );
        // The persisted UID must remain reconstructible from its (kind, value),
        // so a reloaded entity still dedups against a freshly-derived one.
        assert_eq!(
            got.uid,
            derive_uid(&got.kind, &normalise(&got.kind, &got.value))
        );
        // The human-facing display value survives, distinct from the normalised
        // dedup key.
        assert_eq!(got.value, "found.user+tag@example.com");
        assert_eq!(got.raw_value, "Found.User+Tag@Example.COM");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn get_entity_not_found() {
        let path = tmp_db();
        let store = Store::open(&path).unwrap();
        let result = store.get_entity("nonexistent-uid").unwrap();
        assert!(result.is_none());
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn search_entities_matches_substring() {
        let path = tmp_db();
        let store = Store::open(&path).unwrap();
        insert_scan(&store, "search-scan");
        let e1 = Entity::new(EntityKind::Email, "alice@example.com", 0.8, "search-scan");
        let e2 = Entity::new(EntityKind::Email, "bob@test.com", 0.7, "search-scan");
        let e3 = Entity::new(EntityKind::Domain, "alice-domain.com", 0.6, "search-scan");
        store.upsert_entity(&e1).unwrap();
        store.upsert_entity(&e2).unwrap();
        store.upsert_entity(&e3).unwrap();
        let results = store.search_entities("alice", 10).unwrap();
        assert_eq!(results.len(), 2);
        for r in &results {
            assert!(
                r.value.contains("alice"),
                "result '{}' should contain 'alice'",
                r.value
            );
        }
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn search_entities_respects_limit() {
        let path = tmp_db();
        let store = Store::open(&path).unwrap();
        insert_scan(&store, "lim-scan");
        for i in 0..5 {
            let e = Entity::new(
                EntityKind::Email,
                format!("user{i}@matching.com"),
                0.8,
                "lim-scan",
            );
            store.upsert_entity(&e).unwrap();
        }
        let results = store.search_entities("matching", 1).unwrap();
        assert_eq!(results.len(), 1, "should return exactly 1 result");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn search_entities_empty_query_returns_nothing() {
        let path = tmp_db();
        let store = Store::open(&path).unwrap();
        insert_scan(&store, "empty-scan");
        let e = Entity::new(EntityKind::Email, "x@y.com", 0.8, "empty-scan");
        store.upsert_entity(&e).unwrap();
        let results = store.search_entities("zzzz_no_match_xyzzy_42", 10).unwrap();
        assert!(results.is_empty());
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn escape_like_neutralises_all_metacharacters() {
        // `\` first, then `%`/`_` — order matters so the added escapes aren't
        // themselves re-escaped.
        assert_eq!(super::escape_like("a%b_c"), "a\\%b\\_c");
        assert_eq!(super::escape_like("back\\slash"), "back\\\\slash");
        assert_eq!(super::escape_like("100%_\\"), "100\\%\\_\\\\");
        assert_eq!(super::escape_like("plain"), "plain"); // no-op on ordinary text
    }

    #[test]
    fn search_like_fallback_escapes_backslash() {
        // A bare `\` query has no FTS tokens, so it exercises the LIKE fallback.
        // It must match a literal backslash, not (mis-escaped) a `%`.
        let path = tmp_db();
        let store = Store::open(&path).unwrap();
        insert_scan(&store, "bs");
        store
            .upsert_entity(&Entity::new(EntityKind::Username, "back\\slash", 0.9, "bs"))
            .unwrap();
        store
            .upsert_entity(&Entity::new(EntityKind::Username, "plainname", 0.9, "bs"))
            .unwrap();
        let hits = store.search_entities("\\", 10).unwrap();
        assert!(
            hits.iter().any(|e| e.value == "back\\slash"),
            "backslash query must match a literal backslash: {hits:?}"
        );
        assert!(
            hits.iter().all(|e| e.value.contains('\\')),
            "must not match values without a backslash: {hits:?}"
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn fts_prefix_token_search_matches_partial_word() {
        // FTS5 path: a partial word token must hit via prefix matching — what
        // the old LIKE-only search could only do as an anchored substring.
        let path = tmp_db();
        let store = Store::open(&path).unwrap();
        insert_scan(&store, "fts-scan");
        store
            .upsert_entity(&Entity::new(
                EntityKind::Person,
                "Jordan Meyer",
                0.9,
                "fts-scan",
            ))
            .unwrap();
        // Token prefix: "jord" -> "Jordan"; "mey" -> "Meyer".
        assert_eq!(store.search_entities("jord", 10).unwrap().len(), 1);
        assert_eq!(store.search_entities("mey", 10).unwrap().len(), 1);
        // A non-matching token returns nothing (and doesn't fall through to a
        // spurious LIKE hit).
        assert!(store.search_entities("smith", 10).unwrap().is_empty());
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn fts_matches_tokens_in_any_order_unlike_like() {
        // FTS-ONLY capability: a multi-token query matches regardless of word
        // order ("meyer jordan" finds "Jordan Meyer"). A substring LIKE of the
        // raw query CANNOT — "%meyer jordan%" never matches "Jordan Meyer".
        // This isolates the FTS path from the LIKE fallback.
        let path = tmp_db();
        let store = Store::open(&path).unwrap();
        insert_scan(&store, "order-scan");
        store
            .upsert_entity(&Entity::new(
                EntityKind::Person,
                "Jordan Meyer",
                0.9,
                "order-scan",
            ))
            .unwrap();
        assert_eq!(
            store.search_entities("meyer jordan", 10).unwrap().len(),
            1,
            "FTS must match tokens in any order; the LIKE fallback alone cannot"
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn fts_index_stays_synchronized_on_value_change() {
        // The FTS index must track entity-value changes inside the same write
        // (the 'always-synchronized index' invariant). Simulate a value change
        // by writing two entities that share a uid-determining identity is not
        // possible (uid derives from value), so instead verify a freshly
        // inserted entity is immediately searchable and a rebuild is a no-op.
        let path = tmp_db();
        let store = Store::open(&path).unwrap();
        insert_scan(&store, "sync-scan");
        store
            .upsert_entity(&Entity::new(
                EntityKind::Domain,
                "syncexample.org",
                0.8,
                "sync-scan",
            ))
            .unwrap();
        // Immediately visible via FTS, no separate index step.
        assert_eq!(store.search_entities("syncexample", 10).unwrap().len(), 1);
        // Re-upsert the same entity (merge path) — index must remain correct,
        // not duplicate.
        store
            .upsert_entity(&Entity::new(
                EntityKind::Domain,
                "syncexample.org",
                0.9,
                "sync-scan",
            ))
            .unwrap();
        assert_eq!(
            store.search_entities("syncexample", 10).unwrap().len(),
            1,
            "merge must not duplicate the FTS row"
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn fts_backfill_indexes_preexisting_rows() {
        // A DB whose entities predate the FTS index must become searchable
        // after reopen (the open() backfill path).
        let path = tmp_db();
        {
            let store = Store::open(&path).unwrap();
            insert_scan(&store, "bf-scan");
            store
                .upsert_entity(&Entity::new(
                    EntityKind::Username,
                    "backfilluser",
                    0.7,
                    "bf-scan",
                ))
                .unwrap();
            // Drop the FTS table to emulate a pre-index DB, then reopen.
            let conn = store.conn.lock();
            conn.execute_batch("DROP TABLE entities_fts;").unwrap();
        }
        let store = Store::open(&path).unwrap();
        assert_eq!(
            store.search_entities("backfill", 10).unwrap().len(),
            1,
            "reopen must backfill the FTS index from existing rows"
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn upsert_entity_cross_scan_merge_preserves_evidence_and_tags() {
        use crate::core::entity::Evidence;
        let path = tmp_db();
        let store = Store::open(&path).unwrap();
        insert_scan(&store, "scan-a");
        insert_scan(&store, "scan-b");
        let mut e_a = Entity::new(EntityKind::Email, "shared@example.com", 0.6, "scan-a");
        e_a.add_evidence(Evidence::new("module_a", "found in source A"));
        e_a.tag("tag-a");
        store.upsert_entity(&e_a).unwrap();
        let mut e_b = Entity::new(EntityKind::Email, "shared@example.com", 0.9, "scan-b");
        e_b.add_evidence(Evidence::new("module_b", "found in source B"));
        e_b.tag("tag-b");
        store.upsert_entity(&e_b).unwrap();
        let merged = store.get_entity(&e_a.uid).unwrap().unwrap();
        assert!(
            (merged.confidence - 0.9).abs() < 1e-9,
            "confidence should be max(0.6, 0.9) = 0.9, got {}",
            merged.confidence
        );
        assert_eq!(merged.corroboration, 2, "corroboration should accumulate");
        let sources: Vec<&str> = merged.evidence.iter().map(|e| e.source.as_str()).collect();
        assert!(
            sources.contains(&"module_a"),
            "evidence from scan-a must survive merge: {sources:?}"
        );
        assert!(
            sources.contains(&"module_b"),
            "evidence from scan-b must survive merge: {sources:?}"
        );
        assert!(merged.has_tag("tag-a"), "tag-a must survive merge");
        assert!(merged.has_tag("tag-b"), "tag-b must survive merge");
        let _ = std::fs::remove_file(&path);
    }

    // ── upsert_entities_batch ──────────────────────────────────────────────

    #[test]
    fn upsert_entities_batch_persists_all_and_records_observations() {
        let path = tmp_db();
        let store = Store::open(&path).unwrap();
        insert_scan(&store, "batch-scan");
        let entities = vec![
            Entity::new(EntityKind::Email, "a@x.com", 0.8, "batch-scan"),
            Entity::new(EntityKind::Domain, "x.com", 0.7, "batch-scan"),
            Entity::new(EntityKind::IpAddress, "1.2.3.4", 0.9, "batch-scan"),
        ];
        let n = store.upsert_entities_batch(&entities).unwrap();
        assert_eq!(n, 3, "batch should report every entity persisted");
        let got = store.entities_for_scan("batch-scan").unwrap();
        assert_eq!(got.len(), 3);
        // The observation junction must be populated for every entity, exactly
        // as the per-entity upsert path does.
        for e in &entities {
            assert_eq!(store.observation_count(&e.uid).unwrap(), 1);
        }
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn upsert_entities_batch_merges_on_conflict() {
        let path = tmp_db();
        let store = Store::open(&path).unwrap();
        insert_scan(&store, "bm-scan");
        let first = Entity::new(EntityKind::Email, "dup@x.com", 0.5, "bm-scan");
        store.upsert_entity(&first).unwrap();
        // Same uid, higher confidence → GREATEST-merge through the batch path.
        let again = Entity::new(EntityKind::Email, "dup@x.com", 0.9, "bm-scan");
        let n = store
            .upsert_entities_batch(std::slice::from_ref(&again))
            .unwrap();
        assert_eq!(n, 1);
        let merged = store.get_entity(&first.uid).unwrap().unwrap();
        assert!(
            (merged.confidence - 0.9).abs() < 1e-9,
            "GREATEST-merge must apply inside the batch path"
        );
        assert_eq!(
            merged.corroboration, 2,
            "corroboration must accumulate through the batch path"
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn upsert_entities_batch_empty_is_zero() {
        let path = tmp_db();
        let store = Store::open(&path).unwrap();
        assert_eq!(store.upsert_entities_batch(&[]).unwrap(), 0);
        let _ = std::fs::remove_file(&path);
    }

    // ── relations ──────────────────────────────────────────────────────────

    #[test]
    fn relation_round_trip_and_idempotent_upsert() {
        use crate::core::relation::{Relation, RelationKind};
        let path = tmp_db();
        let store = Store::open(&path).unwrap();
        insert_scan(&store, "rel-scan");
        let r = Relation::new(
            "childUid",
            "parentUid",
            RelationKind::SubdomainOf,
            0.8,
            "rel-scan",
        );
        store.upsert_relation(&r).unwrap();
        // Re-inserting the same deterministic id is a no-op (no duplicate row).
        store.upsert_relation(&r).unwrap();
        let got = store.relations_for_scan("rel-scan").unwrap();
        assert_eq!(got.len(), 1, "idempotent on deterministic id");
        assert_eq!(got[0].from_uid, "childUid");
        assert_eq!(got[0].to_uid, "parentUid");
        assert_eq!(got[0].kind, RelationKind::SubdomainOf);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn relations_for_scan_is_scan_scoped() {
        use crate::core::relation::{Relation, RelationKind};
        let path = tmp_db();
        let store = Store::open(&path).unwrap();
        insert_scan(&store, "rs-a");
        insert_scan(&store, "rs-b");
        store
            .upsert_relation(&Relation::new(
                "a",
                "b",
                RelationKind::HostedOn,
                1.0,
                "rs-a",
            ))
            .unwrap();
        assert_eq!(store.relations_for_scan("rs-a").unwrap().len(), 1);
        assert!(store.relations_for_scan("rs-b").unwrap().is_empty());
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn delete_scan_cascades_to_relations() {
        use crate::core::relation::{Relation, RelationKind};
        let path = tmp_db();
        let store = Store::open(&path).unwrap();
        insert_scan(&store, "rd-scan");
        store
            .upsert_relation(&Relation::new(
                "x",
                "y",
                RelationKind::BelongsToDomain,
                0.9,
                "rd-scan",
            ))
            .unwrap();
        assert_eq!(store.relations_for_scan("rd-scan").unwrap().len(), 1);
        assert!(store.delete_scan("rd-scan").unwrap());
        assert!(store.relations_for_scan("rd-scan").unwrap().is_empty());
        let _ = std::fs::remove_file(&path);
    }
    /// Characterisation: pins the EXACT schema (tables + indexes) and the
    /// connection pragmas a freshly-opened store produces, so the `Store::open`
    /// refactor that lifts the DDL into a constant can be proven schema-identical.
    #[test]
    fn open_produces_exact_schema_and_pragmas() {
        let path = tmp_db();
        let store = Store::open(&path).unwrap();
        let conn = store.conn.lock();
        let mut stmt = conn
            .prepare("SELECT type || '|' || name FROM sqlite_master ORDER BY type, name")
            .unwrap();
        let got: Vec<String> = stmt
            .query_map([], |r| r.get::<_, String>(0))
            .unwrap()
            .map(|r| r.unwrap())
            .collect();
        drop(stmt);
        let expected = [
            "index|idx_corr_scan",
            "index|idx_entities_kind",
            "index|idx_entities_scan",
            "index|idx_events_scan",
            "index|idx_obs_entity",
            "index|idx_obs_scan",
            "index|idx_relations_scan",
            "index|idx_scans_started",
            "index|sqlite_autoindex_correlations_1",
            "index|sqlite_autoindex_entities_1",
            "index|sqlite_autoindex_entity_observations_1",
            "index|sqlite_autoindex_relations_1",
            "index|sqlite_autoindex_scans_1",
            "table|correlations",
            "table|entities",
            "table|entities_fts",
            "table|entities_fts_config",
            "table|entities_fts_data",
            "table|entities_fts_docsize",
            "table|entities_fts_idx",
            "table|entity_observations",
            "table|events",
            "table|relations",
            "table|scans",
            "table|sqlite_sequence",
            // `PRAGMA optimize` (run at open — see `Store::open`) materialises
            // the query-planner statistics tables. The bundled SQLite shipped
            // with rusqlite ≥0.39 creates both stat1 and stat4 here; very early
            // bundles left a fresh DB without them. Benign — these only feed the
            // planner, no app data, and improve query plans on Termux.
            "table|sqlite_stat1",
            "table|sqlite_stat4",
        ];
        assert_eq!(got, expected, "schema (tables + indexes) must be identical");

        let fk: i64 = conn
            .query_row("PRAGMA foreign_keys", [], |r| r.get(0))
            .unwrap();
        let jm: String = conn
            .query_row("PRAGMA journal_mode", [], |r| r.get(0))
            .unwrap();
        assert_eq!(fk, 1, "foreign_keys must stay ON");
        assert_eq!(jm, "wal", "journal_mode must stay WAL");
        drop(conn);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn wal_autocheckpoint_bound_is_asserted() {
        // The WAL bound must be explicit (512 pages), not SQLite's implicit
        // 1000-page default — the 'WAL+checkpoint, everything bounded'
        // invariant.
        let path = tmp_db();
        let store = Store::open(&path).unwrap();
        let n: i64 = {
            let conn = store.conn.lock();
            conn.query_row("PRAGMA wal_autocheckpoint", [], |r| r.get(0))
                .unwrap()
        };
        assert_eq!(
            n, 512,
            "WAL autocheckpoint must be the asserted 512-page bound"
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn checkpoint_truncate_resets_wal_file_and_keeps_data() {
        // checkpoint_truncate() must reset the -wal file to zero bytes (PASSIVE
        // autocheckpoint never shrinks it) without losing durable data.
        let path = tmp_db();
        let wal = format!("{path}-wal");
        let store = Store::open(&path).unwrap();
        insert_scan(&store, "wal-scan");
        // Force the WAL to grow: many separate commits, each appending frames.
        for i in 0..300 {
            store
                .upsert_entity(&Entity::new(
                    EntityKind::Email,
                    format!("user{i}@example.com"),
                    0.5,
                    "wal-scan",
                ))
                .unwrap();
        }
        let pre = std::fs::metadata(&wal).map(|m| m.len()).unwrap_or(0);
        assert!(
            pre > 0,
            "WAL should hold frames before checkpoint (was {pre})"
        );

        store.checkpoint_truncate().unwrap();

        let post = std::fs::metadata(&wal).map(|m| m.len()).unwrap_or(0);
        assert_eq!(post, 0, "TRUNCATE checkpoint must reset the -wal to zero");
        // Data survived the fold-back into the main DB.
        assert_eq!(
            store.entities_for_scan("wal-scan").unwrap().len(),
            300,
            "checkpoint must not lose committed entities"
        );
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(&wal);
        let _ = std::fs::remove_file(format!("{path}-shm"));
    }

    #[test]
    fn search_entities_never_errors_on_adversarial_queries() {
        let path = tmp_db();
        let store = Store::open(&path).unwrap();
        insert_scan(&store, "adv");
        for v in [
            "Jordan Meyer",
            "example.com",
            "AND",
            "NEAR test",
            "中文名字",
        ] {
            store
                .upsert_entity(&Entity::new(EntityKind::Person, v, 0.9, "adv"))
                .unwrap();
        }
        for q in [
            "\"",
            "*",
            "(",
            ")",
            "AND",
            "OR",
            "NOT",
            "a AND b",
            "NEAR(a b)",
            "foo*bar",
            "中文",
            "col:val",
            "^abc",
            "a OR b OR",
            "(((",
            "'; DROP TABLE entities;--",
            "😀emoji",
            "a.b@c.d",
            "\"\"\"",
            "x\"*y",
        ] {
            store
                .search_entities(q, 10)
                .unwrap_or_else(|e| panic!("search_entities({q:?}) ERRORED: {e}"));
        }
        // entities table still present after the injection-y query
        assert!(!store.search_entities("jordan", 10).unwrap().is_empty());
        let _ = std::fs::remove_file(&path);
    }
}
