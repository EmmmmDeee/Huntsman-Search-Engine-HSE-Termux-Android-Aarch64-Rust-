//! SQLite WAL store. v0.4 adds the `correlations` table on top of v0.1's
//! `scans` + `entities`. Batch and debug tables land in v0.7+.

use parking_lot::Mutex;
use rusqlite::{Connection, params};

use crate::core::{correlator::Correlation, entity::Entity, error::Result, scan::Scan};

pub struct Store {
    conn: Mutex<Connection>,
}

impl Store {
    pub fn open(path: &str) -> Result<Self> {
        let conn = Connection::open(path)?;
        conn.execute_batch(
            "
            PRAGMA journal_mode=WAL;
            PRAGMA synchronous=NORMAL;
            PRAGMA temp_store=MEMORY;
            PRAGMA foreign_keys=ON;

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

            CREATE INDEX IF NOT EXISTS idx_entities_scan ON entities(scan_id);
            CREATE INDEX IF NOT EXISTS idx_entities_kind ON entities(kind);
            CREATE INDEX IF NOT EXISTS idx_scans_started ON scans(started_at DESC);
            CREATE INDEX IF NOT EXISTS idx_corr_scan     ON correlations(scan_id);
            ",
        )?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    // ── Scans ────────────────────────────────────────────────────────────────

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
                format!("{:?}", scan.status).to_lowercase(),
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
        let conn = self.conn.lock();
        let mut stmt = conn.prepare("SELECT data_json FROM scans WHERE id = ?1")?;
        let mut rows = stmt.query(params![id])?;
        if let Some(row) = rows.next()? {
            let json: String = row.get(0)?;
            Ok(Some(serde_json::from_str(&json)?))
        } else {
            Ok(None)
        }
    }

    pub fn list_scans(&self, limit: usize) -> Result<Vec<Scan>> {
        let conn = self.conn.lock();
        let mut stmt =
            conn.prepare("SELECT data_json FROM scans ORDER BY started_at DESC LIMIT ?1")?;
        let rows = stmt.query_map(params![limit as i64], |r| r.get::<_, String>(0))?;
        let mut out = Vec::new();
        for row in rows {
            if let Ok(s) = serde_json::from_str(&row?) {
                out.push(s);
            }
        }
        Ok(out)
    }

    // ── Entities ─────────────────────────────────────────────────────────────

    pub fn upsert_entity(&self, entity: &Entity) -> Result<()> {
        let json = serde_json::to_string(entity)?;
        let conn = self.conn.lock();
        // scan_id is updated on conflict so the most recent scan's listing
        // includes the entity. Past scans lose the entity from their listing —
        // accepted trade-off for v0.2. Future: junction table tracking every
        // (entity, scan) pair observed.
        conn.execute(
            "INSERT INTO entities(uid, scan_id, kind, value, confidence, corroboration, observed_at, data_json)
             VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
             ON CONFLICT(uid) DO UPDATE SET
               scan_id       = excluded.scan_id,
               confidence    = MAX(confidence, excluded.confidence),
               corroboration = corroboration + excluded.corroboration,
               observed_at   = MAX(observed_at, excluded.observed_at),
               data_json     = excluded.data_json",
            params![
                entity.uid,
                entity.scan_id,
                entity.kind.to_string(),
                entity.value,
                entity.confidence,
                entity.corroboration as i64,
                entity.observed_at as i64,
                json,
            ],
        )?;
        Ok(())
    }

    pub fn entities_for_scan(&self, scan_id: &str) -> Result<Vec<Entity>> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare(
            "SELECT data_json FROM entities WHERE scan_id = ?1 ORDER BY confidence DESC",
        )?;
        let rows = stmt.query_map(params![scan_id], |r| r.get::<_, String>(0))?;
        let mut out = Vec::new();
        for row in rows {
            if let Ok(e) = serde_json::from_str(&row?) {
                out.push(e);
            }
        }
        Ok(out)
    }

    // ── Correlations (v0.4+) ─────────────────────────────────────────────────

    /// Insert a correlation, ignoring duplicates on
    /// `(scan_id, rule_id, description)` — re-running the correlator on the
    /// same scan is idempotent.
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
                // canonical lowercase matches the ORDER BY expression below
                // and serde's serialised form — keep these three in sync.
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
        let conn = self.conn.lock();
        // Sort by severity desc (Critical > High > Medium > Low) using a CASE
        // because SQLite text comparison alone won't order them correctly.
        let mut stmt = conn.prepare(
            "SELECT data_json FROM correlations WHERE scan_id = ?1
             ORDER BY CASE severity
                 WHEN 'CRITICAL' THEN 0
                 WHEN 'HIGH'     THEN 1
                 WHEN 'MEDIUM'   THEN 2
                 WHEN 'LOW'      THEN 3
                 ELSE 4
             END, id",
        )?;
        let rows = stmt.query_map(params![scan_id], |r| r.get::<_, String>(0))?;
        let mut out = Vec::new();
        for row in rows {
            if let Ok(c) = serde_json::from_str(&row?) {
                out.push(c);
            }
        }
        Ok(out)
    }
}
