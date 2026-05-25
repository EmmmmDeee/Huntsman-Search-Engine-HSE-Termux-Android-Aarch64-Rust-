//! Entity persistence + observation junction table.

use rusqlite::params;

use crate::core::{entity::Entity, error::Result};

use super::Store;

impl Store {
    pub fn upsert_entity(&self, entity: &Entity) -> Result<()> {
        let conn = self.conn.lock();
        let tx = conn.unchecked_transaction()?;

        let mut merged = entity.clone();
        {
            let mut stmt = tx.prepare_cached("SELECT data_json FROM entities WHERE uid = ?1")?;
            let mut rows = stmt.query(rusqlite::params![entity.uid])?;
            if let Some(row) = rows.next()? {
                let existing_json: String = row.get(0)?;
                if let Ok(existing) = serde_json::from_str::<Entity>(&existing_json) {
                    merged = existing;
                    merged.merge(entity.clone());
                }
            }
        }

        let json = serde_json::to_string(&merged)?;
        tx.execute(
            "INSERT INTO entities(uid, scan_id, kind, value, confidence, corroboration, observed_at, data_json)
             VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
             ON CONFLICT(uid) DO UPDATE SET
               scan_id       = excluded.scan_id,
               confidence    = excluded.confidence,
               corroboration = excluded.corroboration,
               observed_at   = excluded.observed_at,
               data_json     = excluded.data_json",
            params![
                merged.uid,
                merged.scan_id,
                merged.kind.to_string(),
                merged.value,
                merged.confidence,
                merged.corroboration as i64,
                merged.observed_at as i64,
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
            sql.push_str(&format!(" AND e.value LIKE ?{next_param}"));
            let _ = next_param; // suppress unused warning
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::entity::{Entity, EntityKind};
    use crate::core::scan::{Target, TargetKind};

    fn tmp_db() -> String {
        use std::sync::atomic::{AtomicUsize, Ordering};
        static COUNTER: AtomicUsize = AtomicUsize::new(0);
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        let path = format!(
            "{}/.huntsman-ent-test-{}-{}.db",
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
        let scan = crate::core::scan::Scan::new(id, target);
        store.upsert_scan(&scan).unwrap();
    }

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
        // ordered by count DESC
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
}
