// SQLite WAL store. Unified module: scan, entity, correlation, and event
// persistence plus the observation junction table.

use parking_lot::Mutex;
use rusqlite::{Connection, params};

use crate::core::{
    correlator::Correlation, entity::Entity, error::Result, event::Event, relation::Relation,
    scan::Scan,
};

pub struct Store {
    conn: Mutex<Connection>,
}

impl Store {
    pub fn open(path: &str) -> Result<Self> {
        let cache_kb: i64 = std::env::var("HSE_SQLITE_CACHE_KB")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(2000);
        let mmap: i64 = std::env::var("HSE_SQLITE_MMAP")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(67_108_864);

        let conn = Connection::open(path)?;
        conn.execute_batch(&format!(
            "
            PRAGMA journal_mode=WAL;
            PRAGMA synchronous=NORMAL;
            PRAGMA temp_store=MEMORY;
            PRAGMA foreign_keys=ON;
            PRAGMA cache_size=-{cache_kb};
            PRAGMA mmap_size={mmap};

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
            "
        ))?;

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
            let _ = conn.execute_batch(
                "INSERT INTO entities_fts(entities_fts) VALUES('rebuild');",
            );
        }

        conn.execute_batch(
            "INSERT OR IGNORE INTO entity_observations(entity_uid, scan_id, observed_at)
             SELECT uid, scan_id, observed_at FROM entities;",
        )?;

        let _ = conn.execute_batch("PRAGMA optimize;");

        Ok(Self {
            conn: Mutex::new(conn),
        })
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
        let json = serde_json::to_string(c)?;
        let uids = serde_json::to_string(&c.entity_uids)?;
        let conn = self.conn.lock();
        conn.execute(
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
        Ok(())
    }

    pub fn correlations_for_scan(&self, scan_id: &str) -> Result<Vec<Correlation>> {
        let raw: Vec<String> = {
            let conn = self.conn.lock();
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
        Ok(raw
            .into_iter()
            .filter_map(|s| serde_json::from_str(&s).ok())
            .collect())
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

    // ── Entities ───────────────────────────────────────────────────────────
    // Entity persistence + observation junction table.

    pub fn upsert_entity(&self, entity: &Entity) -> Result<()> {
        let conn = self.conn.lock();
        let tx = conn.unchecked_transaction()?;
        Self::merge_and_persist_entity(&tx, entity)?;
        tx.commit()?;
        Ok(())
    }

    /// Persist a batch of entities under one transaction. On the happy path
    /// (every entity new or a clean merge) this collapses N per-entity
    /// commits into a single WAL fsync — a material win on low-power aarch64.
    /// All-or-nothing: any error rolls the whole batch back, and the caller
    /// is expected to fall back to per-entity `upsert_entity` to salvage what
    /// it can. Returns the number of entities persisted (== `entities.len()`).
    pub fn upsert_entities_batch(&self, entities: &[Entity]) -> Result<usize> {
        let conn = self.conn.lock();
        let tx = conn.unchecked_transaction()?;
        for entity in entities {
            Self::merge_and_persist_entity(&tx, entity)?;
        }
        tx.commit()?;
        Ok(entities.len())
    }

    fn merge_and_persist_entity(tx: &rusqlite::Transaction<'_>, entity: &Entity) -> Result<()> {
        let kind_str = entity.kind.to_string();

        // Fast path: INSERT with DO NOTHING. For new entities (the common
        // case during a first-pass scan) this succeeds in one statement
        // with no SELECT round-trip. Serialization is deferred so the
        // conflict path doesn't pay for a wasted to_string.
        let json = serde_json::to_string(entity)?;
        let inserted = tx.execute(
            "INSERT INTO entities(uid, scan_id, kind, value, confidence, corroboration, observed_at, data_json)
             VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
             ON CONFLICT(uid) DO NOTHING",
            params![
                entity.uid,
                entity.scan_id,
                kind_str,
                entity.value,
                entity.confidence,
                entity.corroboration as i64,
                entity.observed_at as i64,
                json,
            ],
        )?;

        if inserted == 0 {
            // Slow path: entity already exists — SELECT, merge, UPDATE.
            let mut stmt =
                tx.prepare_cached("SELECT rowid, data_json FROM entities WHERE uid = ?1")?;
            let (rowid, existing_json): (i64, String) =
                stmt.query_row(params![entity.uid], |r| Ok((r.get(0)?, r.get(1)?)))?;
            let mut merged = serde_json::from_str::<Entity>(&existing_json)?;
            let old_value = merged.value.clone();
            merged.merge(entity.clone());
            let merged_json = serde_json::to_string(&merged)?;
            tx.execute(
                "UPDATE entities SET scan_id = ?1, confidence = ?2, corroboration = ?3,
                 observed_at = ?4, data_json = ?5 WHERE uid = ?6",
                params![
                    merged.scan_id,
                    merged.confidence,
                    merged.corroboration as i64,
                    merged.observed_at as i64,
                    merged_json,
                    merged.uid,
                ],
            )?;
            // Keep the FTS index synchronized. For a contentless-external FTS5
            // table the app must emit an explicit delete (old text, keyed by
            // rowid) then re-insert the new text. Only the value column is
            // indexed, so skip the churn when the value is unchanged (the
            // common merge case — same uid implies same normalised value).
            if old_value != merged.value {
                tx.execute(
                    "INSERT INTO entities_fts(entities_fts, rowid, value, kind)
                     VALUES('delete', ?1, ?2, ?3)",
                    params![rowid, old_value, kind_str],
                )?;
                tx.execute(
                    "INSERT INTO entities_fts(rowid, value, kind) VALUES(?1, ?2, ?3)",
                    params![rowid, merged.value, kind_str],
                )?;
            }
        } else {
            // Fast path inserted a new entity — mirror it into the FTS index
            // under the same rowid, in the same transaction.
            let rowid = tx.last_insert_rowid();
            tx.execute(
                "INSERT INTO entities_fts(rowid, value, kind) VALUES(?1, ?2, ?3)",
                params![rowid, entity.value, kind_str],
            )?;
        }

        tx.execute(
            "INSERT OR IGNORE INTO entity_observations(entity_uid, scan_id, observed_at)
             VALUES(?1, ?2, ?3)",
            params![entity.uid, entity.scan_id, entity.observed_at as i64],
        )?;
        Ok(())
    }

    pub fn entities_for_scan(&self, scan_id: &str) -> Result<Vec<Entity>> {
        let raw: Vec<String> = {
            let conn = self.conn.lock();
            let mut stmt = conn.prepare_cached(
                "SELECT e.data_json
                 FROM entities e
                 JOIN entity_observations o ON o.entity_uid = e.uid
                 WHERE o.scan_id = ?1
                 ORDER BY e.confidence DESC",
            )?;
            let rows = stmt.query_map(params![scan_id], |r| r.get::<_, String>(0))?;
            rows.filter_map(std::result::Result::ok).collect()
        };
        Ok(raw
            .into_iter()
            .filter_map(|s| serde_json::from_str(&s).ok())
            .collect())
    }

    pub fn scan_ids_for_entity(&self, entity_uid: &str) -> Result<Vec<String>> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare_cached(
            "SELECT scan_id FROM entity_observations
             WHERE entity_uid = ?1
             ORDER BY observed_at DESC",
        )?;
        let rows = stmt.query_map(params![entity_uid], |r| r.get::<_, String>(0))?;
        Ok(rows.flatten().collect())
    }

    pub fn observation_count(&self, entity_uid: &str) -> Result<usize> {
        let conn = self.conn.lock();
        let mut stmt =
            conn.prepare_cached("SELECT COUNT(*) FROM entity_observations WHERE entity_uid = ?1")?;
        let n: i64 = stmt.query_row(params![entity_uid], |r| r.get(0))?;
        Ok(n.max(0) as usize)
    }

    pub fn entities_filtered(
        &self,
        scan_id: &str,
        kind: Option<&str>,
        min_confidence: Option<f64>,
        value_contains: Option<&str>,
    ) -> Result<Vec<Entity>> {
        let mut sql = String::from(
            "SELECT e.data_json FROM entities e \
             JOIN entity_observations o ON o.entity_uid = e.uid \
             WHERE o.scan_id = ?1",
        );
        let mut next_param = 2u32;
        if kind.is_some() {
            sql.push_str(&format!(" AND e.kind = ?{next_param}"));
            next_param += 1;
        }
        if min_confidence.is_some() {
            sql.push_str(&format!(" AND e.confidence >= ?{next_param}"));
            next_param += 1;
        }
        if value_contains.is_some() {
            sql.push_str(&format!(" AND e.value LIKE ?{next_param} ESCAPE '\\'"));
            let _ = next_param;
        }
        sql.push_str(" ORDER BY e.confidence DESC LIMIT 500");

        let raw: Vec<String> = {
            let conn = self.conn.lock();
            let mut stmt = conn.prepare_cached(&sql)?;

            let like_pattern = value_contains.map(|v| {
                let escaped = v.replace('%', "\\%").replace('_', "\\_");
                format!("%{escaped}%")
            });

            let rows = stmt.query_map(
                rusqlite::params_from_iter(
                    std::iter::once(scan_id.to_string())
                        .chain(kind.map(std::string::ToString::to_string))
                        .chain(min_confidence.map(|c| c.to_string()))
                        .chain(like_pattern),
                ),
                |r| r.get::<_, String>(0),
            )?;
            rows.filter_map(std::result::Result::ok).collect()
        };
        Ok(raw
            .into_iter()
            .filter_map(|s| serde_json::from_str(&s).ok())
            .collect())
    }

    pub fn entity_facets(&self, scan_id: &str) -> Result<Vec<(String, u64)>> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare_cached(
            "SELECT e.kind, COUNT(*) FROM entities e \
             JOIN entity_observations o ON o.entity_uid = e.uid \
             WHERE o.scan_id = ?1 \
             GROUP BY e.kind ORDER BY COUNT(*) DESC",
        )?;
        let rows = stmt.query_map(params![scan_id], |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)? as u64))
        })?;
        Ok(rows.flatten().collect())
    }

    pub fn get_entity(&self, uid: &str) -> Result<Option<Entity>> {
        let json: Option<String> = {
            let conn = self.conn.lock();
            let mut stmt = conn.prepare_cached("SELECT data_json FROM entities WHERE uid = ?1")?;
            let mut rows = stmt.query(params![uid])?;
            rows.next()?.map(|r| r.get(0)).transpose()?
        };
        json.map(|j| serde_json::from_str(&j))
            .transpose()
            .map_err(Into::into)
    }

    /// Full-text entity search over the synchronized FTS5 index, ranked by
    /// relevance (bm25) with confidence as the tiebreak. Falls back to the
    /// legacy substring `LIKE` scan when the query yields nothing — so a raw
    /// substring like "xampl" (not an FTS token/prefix) still matches
    /// "example.com", preserving the prior contract — and when the query is
    /// not valid FTS5 syntax (bare operators, unbalanced quotes).
    pub fn search_entities(&self, query: &str, limit: usize) -> Result<Vec<Entity>> {
        let trimmed = query.trim();
        if trimmed.is_empty() {
            return Ok(Vec::new());
        }
        let conn = self.conn.lock();

        // Try FTS5 first. Build a prefix MATCH from the query's word tokens so
        // partial words hit ("jord" → "jordan"); quote each token to neutralise
        // FTS operator characters in user input.
        let fts_expr = Self::fts_prefix_query(trimmed);
        if !fts_expr.is_empty() {
            let mut hits: Vec<String> = Vec::new();
            if let Ok(mut stmt) = conn.prepare_cached(
                "SELECT e.data_json
                   FROM entities_fts f
                   JOIN entities e ON e.rowid = f.rowid
                  WHERE entities_fts MATCH ?1
                  ORDER BY bm25(entities_fts), e.confidence DESC
                  LIMIT ?2",
            ) && let Ok(rows) =
                stmt.query_map(params![fts_expr, limit as i64], |r| r.get::<_, String>(0))
            {
                hits = rows.filter_map(std::result::Result::ok).collect();
            }
            if !hits.is_empty() {
                return Ok(hits
                    .into_iter()
                    .filter_map(|s| serde_json::from_str(&s).ok())
                    .collect());
            }
        }

        // Fallback: legacy substring scan (also covers infix matches FTS's
        // token/prefix model can't reach).
        let escaped = trimmed.replace('%', "\\%").replace('_', "\\_");
        let pattern = format!("%{escaped}%");
        let mut stmt = conn.prepare_cached(
            "SELECT data_json FROM entities WHERE value LIKE ?1 ESCAPE '\\' \
             ORDER BY confidence DESC LIMIT ?2",
        )?;
        let rows = stmt.query_map(params![pattern, limit as i64], |r| r.get::<_, String>(0))?;
        let raw: Vec<String> = rows.filter_map(std::result::Result::ok).collect();
        Ok(raw
            .into_iter()
            .filter_map(|s| serde_json::from_str(&s).ok())
            .collect())
    }

    /// Build a safe FTS5 prefix MATCH expression from free-text input:
    /// split on non-alphanumerics, drop empties, double-quote each token and
    /// append `*` for prefix matching, AND-joined. Returns "" when there are
    /// no usable tokens (caller then uses the LIKE fallback).
    fn fts_prefix_query(input: &str) -> String {
        input
            .split(|c: char| !c.is_alphanumeric())
            .filter(|t| !t.is_empty())
            .map(|t| format!("\"{}\"*", t.replace('"', "")))
            .collect::<Vec<_>>()
            .join(" ")
    }
}

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
    fn fts_prefix_token_search_matches_partial_word() {
        // FTS5 path: a partial word token must hit via prefix matching — what
        // the old LIKE-only search could only do as an anchored substring.
        let path = tmp_db();
        let store = Store::open(&path).unwrap();
        insert_scan(&store, "fts-scan");
        store
            .upsert_entity(&Entity::new(EntityKind::Person, "Jordan Meyer", 0.9, "fts-scan"))
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
}
