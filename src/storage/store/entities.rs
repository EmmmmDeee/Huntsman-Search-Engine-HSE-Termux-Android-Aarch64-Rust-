//! Entity persistence + observation junction table.

use rusqlite::params;

use crate::core::{entity::Entity, error::Result};

use super::Store;

impl Store {
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
}
