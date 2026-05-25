use parking_lot::Mutex;
use rusqlite::{Connection, params};

use crate::core::{
    correlator::Correlation,
    entity::Entity,
    error::Result,
    event::{Event, EventKind},
    scan::Scan,
};

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
            PRAGMA cache_size=-2000;
            PRAGMA mmap_size=67108864;

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

            CREATE INDEX IF NOT EXISTS idx_entities_scan ON entities(scan_id);
            CREATE INDEX IF NOT EXISTS idx_entities_kind ON entities(kind);
            CREATE INDEX IF NOT EXISTS idx_scans_started ON scans(started_at DESC);
            CREATE INDEX IF NOT EXISTS idx_corr_scan     ON correlations(scan_id);
            CREATE INDEX IF NOT EXISTS idx_obs_scan      ON entity_observations(scan_id);
            CREATE INDEX IF NOT EXISTS idx_obs_entity    ON entity_observations(entity_uid);
            CREATE INDEX IF NOT EXISTS idx_events_scan   ON events(scan_id, id);
            ",
        )?;

        // Back-fill observations for pre-v0.7 databases (idempotent).
        conn.execute_batch(
            "INSERT OR IGNORE INTO entity_observations(entity_uid, scan_id, observed_at)
             SELECT uid, scan_id, observed_at FROM entities;",
        )?;

        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

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

    pub fn upsert_entity(&self, entity: &Entity) -> Result<()> {
        let json = serde_json::to_string(entity)?;
        let conn = self.conn.lock();
        let tx = conn.unchecked_transaction()?;
        tx.execute(
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
        tx.execute(
            "INSERT OR IGNORE INTO entity_observations(entity_uid, scan_id, observed_at)
             VALUES(?1, ?2, ?3)",
            params![entity.uid, entity.scan_id, entity.observed_at as i64],
        )?;
        tx.commit()?;
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
        if kind.is_some() {
            sql.push_str(" AND e.kind = ?2");
        }
        if min_confidence.is_some() {
            sql.push_str(" AND e.confidence >= ?3");
        }
        if value_contains.is_some() {
            sql.push_str(" AND e.value LIKE ?4");
        }
        sql.push_str(" ORDER BY e.confidence DESC LIMIT 500");

        let raw: Vec<String> = {
            let conn = self.conn.lock();
            let mut stmt = conn.prepare_cached(&sql)?;

            let like_pattern = value_contains.map(|v| format!("%{v}%"));

            let rows = stmt.query_map(
                rusqlite::params_from_iter(
                    std::iter::once(scan_id.to_string())
                        .chain(kind.map(|k| k.to_string()))
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

    pub fn search_entities(&self, query: &str, limit: usize) -> Result<Vec<Entity>> {
        let pattern = format!("%{query}%");
        let raw: Vec<String> = {
            let conn = self.conn.lock();
            let mut stmt = conn.prepare_cached(
                "SELECT data_json FROM entities WHERE value LIKE ?1 \
                 ORDER BY confidence DESC LIMIT ?2",
            )?;
            let rows = stmt.query_map(params![pattern, limit as i64], |r| r.get::<_, String>(0))?;
            rows.filter_map(std::result::Result::ok).collect()
        };
        Ok(raw
            .into_iter()
            .filter_map(|s| serde_json::from_str(&s).ok())
            .collect())
    }

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

    /// Returns `false` when no scan with that id exists. The orphan-purge
    /// only runs after a real scan row has been deleted, so a stale id
    /// cannot affect unrelated entities.
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
        tx.execute(
            "DELETE FROM entities
             WHERE uid NOT IN (SELECT DISTINCT entity_uid FROM entity_observations)",
            [],
        )?;
        tx.commit()?;
        Ok(true)
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

    pub fn insert_event(&self, event: &Event) -> Result<()> {
        let event_type = match &event.kind {
            EventKind::ScanStart { .. } => "scan_start",
            EventKind::ModuleStart { .. } => "module_start",
            EventKind::ModuleDone { .. } => "module_done",
            EventKind::ModuleError { .. } => "module_error",
            EventKind::ModuleSkipped { .. } => "module_skipped",
            EventKind::EntityFound { .. } => "entity_found",
            EventKind::ExpansionTick { .. } => "expansion_tick",
            EventKind::ExpansionStop { .. } => "expansion_stop",
            EventKind::CorrelationFound { .. } => "correlation_found",
            EventKind::CorrelationsDone { .. } => "correlations_done",
            EventKind::LiveStart { .. } => "live_start",
            EventKind::LiveTick { .. } => "live_tick",
            EventKind::LiveStop { .. } => "live_stop",
            EventKind::ScanComplete { .. } => "scan_complete",
        };
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::entity::{Entity, EntityKind};
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

        // Same deterministic UID — same kind+value
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
        // Most recent first
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

        // Two entities: one observed by both scans, one only by scan-doomed.
        let shared = Entity::new(EntityKind::Domain, "example.com", 0.8, "scan-doomed");
        store.upsert_entity(&shared).unwrap();
        let mut shared2 = Entity::new(EntityKind::Domain, "example.com", 0.8, "scan-keeper");
        shared2.observed_at = shared.observed_at + 1;
        store.upsert_entity(&shared2).unwrap();

        let only_doomed = Entity::new(EntityKind::Email, "lonely@example.com", 0.6, "scan-doomed");
        store.upsert_entity(&only_doomed).unwrap();

        // Sanity: scan-doomed sees both entities.
        assert_eq!(store.entities_for_scan("scan-doomed").unwrap().len(), 2);

        // Delete.
        let removed = store.delete_scan("scan-doomed").unwrap();
        assert!(removed);

        // The shared entity survives (still observed by scan-keeper).
        let keeper = store.entities_for_scan("scan-keeper").unwrap();
        assert_eq!(keeper.len(), 1);
        assert_eq!(keeper[0].value, "example.com");

        // The orphan is gone.
        assert!(
            store
                .scan_ids_for_entity(&only_doomed.uid)
                .unwrap()
                .is_empty()
        );
        assert_eq!(store.observation_count(&only_doomed.uid).unwrap(), 0);

        // The scan record itself is gone.
        assert!(store.get_scan("scan-doomed").unwrap().is_none());
        assert!(store.get_scan("scan-keeper").unwrap().is_some());

        // Deleting again returns false (no-op).
        assert!(!store.delete_scan("scan-doomed").unwrap());

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn delete_scan_with_unknown_id_does_not_purge_orphans() {
        // Regression: a delete on a non-existent scan id must NOT run
        // the orphan-entity purge — that purge is global and would
        // delete entities that legitimately have no observations yet
        // (e.g. mid-insert during a concurrent scan).
        let path = tmp_db();
        let store = Store::open(&path).unwrap();
        insert_scan(&store, "real-scan");

        // Manually plant an entity row WITHOUT a matching observation,
        // simulating an "orphan" — the kind a buggy delete could clobber.
        let conn = parking_lot::Mutex::new(rusqlite::Connection::open(&path).unwrap());
        {
            let c = conn.lock();
            c.execute(
                "INSERT INTO entities(uid, scan_id, kind, value, confidence, corroboration, observed_at, data_json)
                 VALUES('orphan-uid', 'real-scan', 'domain', 'orphan.example.com', 0.5, 1, 1, '{}')",
                [],
            ).unwrap();
        }

        // Delete a scan that doesn't exist.
        assert!(!store.delete_scan("nonexistent-scan-id").unwrap());

        // The orphan row must still be present.
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
    fn event_log_round_trips_in_emission_order() {
        use crate::core::event::{Event, EventKind};
        let path = tmp_db();
        let store = Store::open(&path).unwrap();
        insert_scan(&store, "scan-evt");

        // Emit three events; the auto-increment id should preserve order.
        for (i, kind) in [
            EventKind::ScanStart {
                target_kind: "domain".into(),
                target_value: "example.com".into(),
            },
            EventKind::ModuleStart {
                module: "dns_resolver".into(),
            },
            EventKind::ModuleDone {
                module: "dns_resolver".into(),
                found: 3,
            },
        ]
        .into_iter()
        .enumerate()
        {
            let mut ev = Event::new("scan-evt", kind);
            // Give events distinct ts in case the test machine moves
            // through epoch-second boundaries fast.
            ev.ts = 1000 + i as u64;
            store.insert_event(&ev).unwrap();
        }

        // Plant an event for a DIFFERENT scan so we can assert the
        // WHERE filter works.
        let other = Event::new("scan-other", EventKind::ModuleStart { module: "x".into() });
        store.insert_event(&other).unwrap();

        let evs = store.events_for_scan("scan-evt").unwrap();
        assert_eq!(evs.len(), 3, "expected three events for scan-evt only");

        // Order: ScanStart, ModuleStart, ModuleDone.
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

        // Other-scan's event is isolated.
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
        use crate::core::event::{Event, EventKind};
        let path = tmp_db();
        let store = Store::open(&path).unwrap();
        insert_scan(&store, "scan-with-events");
        insert_scan(&store, "scan-keeper");

        // Plant two events on the doomed scan and one on the keeper.
        store
            .insert_event(&Event::new(
                "scan-with-events",
                EventKind::ModuleStart {
                    module: "dns_resolver".into(),
                },
            ))
            .unwrap();
        store
            .insert_event(&Event::new(
                "scan-with-events",
                EventKind::ModuleDone {
                    module: "dns_resolver".into(),
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

        // Sanity: events are stored.
        assert_eq!(store.events_for_scan("scan-with-events").unwrap().len(), 2);

        // Delete the doomed scan and confirm its event rows are gone
        // (otherwise `events.history` would leak the prior timeline if
        // a future scan reused the same id, and the events table would
        // grow without bound across delete cycles).
        assert!(store.delete_scan("scan-with-events").unwrap());
        assert!(
            store
                .events_for_scan("scan-with-events")
                .unwrap()
                .is_empty()
        );

        // The keeper's event is untouched.
        assert_eq!(store.events_for_scan("scan-keeper").unwrap().len(), 1);

        let _ = std::fs::remove_file(&path);
    }
}
