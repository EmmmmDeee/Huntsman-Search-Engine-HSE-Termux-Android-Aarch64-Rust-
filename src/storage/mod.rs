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

            CREATE TABLE IF NOT EXISTS api_responses (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id    TEXT    NOT NULL,
                module     TEXT    NOT NULL,
                origin_url TEXT    NOT NULL DEFAULT '',
                cache_key  TEXT    NOT NULL,
                body       TEXT    NOT NULL,
                fetched_at INTEGER NOT NULL,
                is_novel   INTEGER NOT NULL DEFAULT 1
            );

            CREATE INDEX IF NOT EXISTS idx_entities_scan ON entities(scan_id);
            CREATE INDEX IF NOT EXISTS idx_entities_kind ON entities(kind);
            CREATE INDEX IF NOT EXISTS idx_scans_started ON scans(started_at DESC);
            CREATE INDEX IF NOT EXISTS idx_corr_scan     ON correlations(scan_id);
            CREATE INDEX IF NOT EXISTS idx_obs_scan      ON entity_observations(scan_id);
            CREATE INDEX IF NOT EXISTS idx_obs_entity    ON entity_observations(entity_uid);
            CREATE INDEX IF NOT EXISTS idx_events_scan   ON events(scan_id, id);
            CREATE INDEX IF NOT EXISTS idx_relations_scan  ON relations(scan_id);
            CREATE INDEX IF NOT EXISTS idx_api_resp_scan   ON api_responses(scan_id);
            CREATE INDEX IF NOT EXISTS idx_api_resp_module ON api_responses(module);
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
                tracing::info!(
                    entities = ent_count,
                    "rebuilt empty FTS index from existing rows"
                );
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
        // FTS sync: a contentless-external FTS5 index never observes a bare
        // DELETE on its content table, so each orphaned row's text must be
        // removed with an explicit 'delete' command BEFORE the row goes away.
        // Without this the stale posting outlives the row, and once SQLite
        // reuses the freed rowid for a NEW entity, a full-text search for the
        // deleted value silently returns that unrelated entity — breaking the
        // 'always-synchronized index' invariant the write path maintains
        // (see merge_and_persist_entity).
        let orphans: Vec<(i64, String, String)> = {
            let mut stmt = tx.prepare(
                "SELECT rowid, value, kind FROM entities e
                 WHERE NOT EXISTS (SELECT 1 FROM entity_observations o WHERE o.entity_uid = e.uid)",
            )?;
            let rows = stmt.query_map([], |r| {
                Ok((
                    r.get::<_, i64>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                ))
            })?;
            rows.collect::<std::result::Result<_, _>>()?
        };
        for (rowid, value, kind) in orphans {
            tx.execute(
                "INSERT INTO entities_fts(entities_fts, rowid, value, kind)
                 VALUES('delete', ?1, ?2, ?3)",
                params![rowid, value, kind],
            )?;
        }
        tx.execute(
            "DELETE FROM entities
             WHERE NOT EXISTS (SELECT 1 FROM entity_observations o WHERE o.entity_uid = entities.uid)",
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

// ── API response log ──────────────────────────────────────────────────────

/// One recorded raw API response, tied to a scan and its originating module.
#[derive(Debug, serde::Serialize)]
pub struct ApiResponseRecord {
    pub id: i64,
    pub scan_id: String,
    /// Module name — the authoritative origin of the data.
    pub module: String,
    pub origin_url: String,
    pub cache_key: String,
    pub body: String,
    pub fetched_at: u64,
    /// `true` when the body differed from the previously cached value for
    /// this `(module, cache_key)` — i.e. the API returned new data.
    pub is_novel: bool,
}

impl Store {
    /// Persist a raw API response. Best-effort — callers must not treat
    /// failure as fatal (a missing log row is preferable to a failed scan).
    pub fn record_api_response(
        &self,
        scan_id: &str,
        module: &str,
        origin_url: &str,
        cache_key: &str,
        body: &str,
        is_novel: bool,
    ) -> Result<()> {
        let now = crate::core::entity::unix_now() as i64;
        let conn = self.conn.lock();
        conn.execute(
            "INSERT INTO api_responses
                 (scan_id, module, origin_url, cache_key, body, fetched_at, is_novel)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                scan_id,
                module,
                origin_url,
                cache_key,
                body,
                now,
                is_novel as i64
            ],
        )?;
        Ok(())
    }

    /// All API responses recorded for a scan, ordered by insertion.
    pub fn api_responses_for_scan(&self, scan_id: &str) -> Result<Vec<ApiResponseRecord>> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare_cached(
            "SELECT id, scan_id, module, origin_url, cache_key, body, fetched_at, is_novel
             FROM api_responses WHERE scan_id = ?1 ORDER BY id",
        )?;
        let rows = stmt.query_map(params![scan_id], |r| {
            Ok(ApiResponseRecord {
                id: r.get(0)?,
                scan_id: r.get(1)?,
                module: r.get(2)?,
                origin_url: r.get(3)?,
                cache_key: r.get(4)?,
                body: r.get(5)?,
                fetched_at: r.get::<_, i64>(6)? as u64,
                is_novel: r.get::<_, i64>(7)? != 0,
            })
        })?;
        Ok(rows.filter_map(std::result::Result::ok).collect())
    }

    /// API responses recorded for a specific module within a scan.
    pub fn api_responses_for_module(
        &self,
        scan_id: &str,
        module: &str,
    ) -> Result<Vec<ApiResponseRecord>> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare_cached(
            "SELECT id, scan_id, module, origin_url, cache_key, body, fetched_at, is_novel
             FROM api_responses WHERE scan_id = ?1 AND module = ?2 ORDER BY id",
        )?;
        let rows = stmt.query_map(params![scan_id, module], |r| {
            Ok(ApiResponseRecord {
                id: r.get(0)?,
                scan_id: r.get(1)?,
                module: r.get(2)?,
                origin_url: r.get(3)?,
                cache_key: r.get(4)?,
                body: r.get(5)?,
                fetched_at: r.get::<_, i64>(6)? as u64,
                is_novel: r.get::<_, i64>(7)? != 0,
            })
        })?;
        Ok(rows.filter_map(std::result::Result::ok).collect())
    }
}

impl crate::core::module::ApiResponseSink for Store {
    fn record(
        &self,
        scan_id: &str,
        module: &str,
        origin_url: &str,
        cache_key: &str,
        body: &str,
        is_novel: bool,
    ) {
        if let Err(e) =
            self.record_api_response(scan_id, module, origin_url, cache_key, body, is_novel)
        {
            tracing::warn!(module, %e, "failed to record api response");
        }
    }
}

// ── Tests (from store/mod.rs) ─────────────────────────────────────────────

#[cfg(test)]
mod tests;
