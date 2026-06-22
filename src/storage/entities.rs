//! Entity persistence and query: the GREATEST-semantics upsert/merge, batch
//! write, FTS5-backed search (with a LIKE fallback), and the per-scan / faceted
//! reads. The `impl super::Store` block keeps these on the same `Store` type;
//! split out of the unified store module so the persistence core is navigable.

use std::collections::HashMap;

use rusqlite::params;

use crate::core::entity::Entity;
use crate::core::error::Result;

impl super::Store {
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
        // Cached: this INSERT fires once per entity, and `upsert_entities_batch`
        // drives it in a tight loop under one transaction — recompiling the same
        // SQL per row is wasted work on aarch64.
        let inserted = tx.prepare_cached(
            "INSERT INTO entities(uid, scan_id, kind, value, confidence, corroboration, observed_at, data_json)
             VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
             ON CONFLICT(uid) DO NOTHING",
        )?.execute(
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
            tx.prepare_cached(
                "UPDATE entities SET scan_id = ?1, confidence = ?2, corroboration = ?3,
                 observed_at = ?4, data_json = ?5 WHERE uid = ?6",
            )?
            .execute(params![
                merged.scan_id,
                merged.confidence,
                merged.corroboration as i64,
                merged.observed_at as i64,
                merged_json,
                merged.uid,
            ])?;
            // Keep the FTS index synchronized. For a contentless-external FTS5
            // table the app must emit an explicit delete (old text, keyed by
            // rowid) then re-insert the new text. Only the value column is
            // indexed, so skip the churn when the value is unchanged (the
            // common merge case — same uid implies same normalised value).
            if old_value != merged.value {
                // `prepare_cached` so a batch of value-changing merges reuses
                // the compiled statements instead of recompiling the same SQL
                // per entity — statement compilation is pure overhead on
                // aarch64.
                tx.prepare_cached(
                    "INSERT INTO entities_fts(entities_fts, rowid, value, kind)
                     VALUES('delete', ?1, ?2, ?3)",
                )?
                .execute(params![rowid, old_value, kind_str])?;
                tx.prepare_cached(
                    "INSERT INTO entities_fts(rowid, value, kind) VALUES(?1, ?2, ?3)",
                )?
                .execute(params![rowid, merged.value, kind_str])?;
            }
        } else {
            // Fast path inserted a new entity — mirror it into the FTS index
            // under the same rowid, in the same transaction. Cached because
            // this is the hot first-pass insert path (one per new entity in a
            // batch).
            let rowid = tx.last_insert_rowid();
            tx.prepare_cached("INSERT INTO entities_fts(rowid, value, kind) VALUES(?1, ?2, ?3)")?
                .execute(params![rowid, entity.value, kind_str])?;
        }

        tx.prepare_cached(
            "INSERT OR IGNORE INTO entity_observations(entity_uid, scan_id, observed_at)
             VALUES(?1, ?2, ?3)",
        )?
        .execute(params![
            entity.uid,
            entity.scan_id,
            entity.observed_at as i64
        ])?;
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
                 ORDER BY e.confidence DESC, e.uid ASC",
            )?;
            let rows = stmt.query_map(params![scan_id], |r| r.get::<_, String>(0))?;
            rows.filter_map(std::result::Result::ok).collect()
        };
        let mut entities: Vec<Entity> = raw
            .into_iter()
            .filter_map(|s| serde_json::from_str(&s).ok())
            .collect();
        // Recovery fallback. The `entities` table is only populated when a scan
        // FINALISES; a scan still running, interrupted, or killed before
        // finalisation (routine on Termux/Android, where the OS reclaims
        // backgrounded processes) leaves it empty even though the module run
        // already discovered — and durably logged — hundreds of entities. Rather
        // than report nothing and lose that intelligence, rebuild it from the
        // real-time event log. A genuinely empty scan has no `EntityFound`
        // events, so this still returns empty — never a false positive — and the
        // common finalised-read path never pays for it.
        if entities.is_empty() {
            return self.entities_from_events(scan_id);
        }
        Self::sort_entities_for_display(&mut entities);
        Ok(entities)
    }

    /// Authoritative operator-facing entity ranking, shared by every read path
    /// (`entities_for_scan` and the event-log recovery `entities_from_events`)
    /// so a recovered in-flight scan and a finalised one rank identically.
    ///
    /// The SQL `ORDER BY confidence` is only a stable pre-order; the two signals
    /// that actually matter can't be expressed in SQL. First, `c_effective()` —
    /// the corroboration-aware confidence: a finding confirmed by N distinct
    /// sources must outrank an equally-(raw)-confident single-source one, since
    /// ordering by the stored `confidence` column alone buries corroborated
    /// identity under single-source breach noise of the same nominal confidence.
    /// Second, subject-relevance: a CDN/anycast edge IP or a mega/shared-infra
    /// domain is legitimately high-confidence (many sources agree it exists) but
    /// it's the haystack, not the needle, so it's demoted beneath subject-relevant
    /// findings regardless of how corroborated its mere existence is. The
    /// resulting deterministic total order — relevance, then C_eff, then raw
    /// confidence, then uid — serialises identically for identical inputs.
    fn sort_entities_for_display(entities: &mut [Entity]) {
        entities.sort_by(|a, b| {
            is_incidental_infra(a)
                .cmp(&is_incidental_infra(b)) // false (relevant) sorts before true
                .then_with(|| {
                    b.c_effective()
                        .partial_cmp(&a.c_effective())
                        .unwrap_or(std::cmp::Ordering::Equal)
                })
                .then_with(|| {
                    b.confidence
                        .partial_cmp(&a.confidence)
                        .unwrap_or(std::cmp::Ordering::Equal)
                })
                .then_with(|| a.uid.cmp(&b.uid))
        });
    }

    /// Reconstruct a scan's entities from the durable event log.
    ///
    /// The real-time `events` table (written incrementally by the DB-writer
    /// actor the instant a module emits) holds every `EntityFound` for the scan,
    /// whereas the `entities` table is populated only at finalisation. This folds
    /// the logged entities by UID through the SAME `Entity::merge` the engine
    /// applies in-flight — each event is a distinct pre-merge emission, folded
    /// exactly once, so corroboration sums correctly and is never double-counted.
    /// The result is a faithful (if not yet finalise-enriched: no address-locality
    /// consolidation, geo-family promotion, or cross-scan history) view of what
    /// the scan found, ranked identically to a finalised read.
    pub fn entities_from_events(&self, scan_id: &str) -> Result<Vec<Entity>> {
        let mut map: HashMap<String, Entity> = HashMap::new();
        for ev in self.events_for_scan(scan_id)? {
            if let crate::core::event::EventKind::EntityFound { entity } = ev.kind {
                match map.get_mut(&entity.uid) {
                    Some(existing) => existing.merge(entity),
                    None => {
                        map.insert(entity.uid.clone(), entity);
                    }
                }
            }
        }
        let mut entities: Vec<Entity> = map.into_values().collect();
        Self::sort_entities_for_display(&mut entities);
        Ok(entities)
    }

    pub fn scan_ids_for_entity(&self, entity_uid: &str) -> Result<Vec<String>> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare_cached(
            "SELECT scan_id FROM entity_observations
             WHERE entity_uid = ?1
             ORDER BY observed_at DESC, scan_id DESC",
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
        sql.push_str(" ORDER BY e.confidence DESC, e.uid ASC LIMIT 500");

        let raw: Vec<String> = {
            let conn = self.conn.lock();
            let mut stmt = conn.prepare_cached(&sql)?;

            let like_pattern = value_contains.map(|v| format!("%{}%", super::escape_like(v)));

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
             GROUP BY e.kind ORDER BY COUNT(*) DESC, e.kind ASC",
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
                  ORDER BY bm25(entities_fts), e.confidence DESC, e.uid ASC
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
        // token/prefix model can't reach). `escape_like` neutralises the LIKE
        // metacharacters (incl. the escape char itself) under `ESCAPE '\'`.
        let pattern = format!("%{}%", super::escape_like(trimmed));
        let mut stmt = conn.prepare_cached(
            "SELECT data_json FROM entities WHERE value LIKE ?1 ESCAPE '\\' \
             ORDER BY confidence DESC, uid ASC LIMIT ?2",
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

/// True if `e` is incidentally-discovered *shared infrastructure* — a CDN/anycast
/// edge IP or a mega/shared-infra domain — rather than something tied to the
/// subject. Such nodes are legitimately high-confidence (many independent probes
/// agree they exist), so they would otherwise dominate a `c_effective`-ordered
/// result list; but they're the haystack, not the needle, so the operator-facing
/// ranking in [`crate::storage::Store::entities_for_scan`] demotes them beneath subject-relevant
/// findings of equal effective confidence.
///
/// Reuses the canonical predicates the expansion gate uses
/// ([`crate::core::validation::is_cdn_edge_ip`] /
/// [`crate::core::scan::is_noncentral_domain`]) so "shared infrastructure" means
/// exactly one thing across the engine — a ranking that demoted an IP the
/// expander still pivoted on (or vice-versa) would be an inconsistency.
fn is_incidental_infra(e: &Entity) -> bool {
    use crate::core::entity::EntityKind;
    match e.kind {
        EntityKind::IpAddress => crate::core::validation::is_cdn_edge_ip(&e.value),
        EntityKind::Domain => crate::core::scan::is_noncentral_domain(&e.value),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::entity::EntityKind;
    use crate::storage::Store;

    // ── fts_prefix_query ──────────────────────────────────────────────────────

    #[test]
    fn fts_prefix_query_single_token_is_quoted_prefix() {
        assert_eq!(Store::fts_prefix_query("alice"), "\"alice\"*");
    }

    #[test]
    fn fts_prefix_query_multiple_tokens_are_and_joined() {
        assert_eq!(Store::fts_prefix_query("john doe"), "\"john\"* \"doe\"*");
    }

    #[test]
    fn fts_prefix_query_splits_on_non_alphanumerics() {
        // Dots, dashes and `@` are all token separators — an email/handle becomes
        // a sequence of prefix terms.
        assert_eq!(
            Store::fts_prefix_query("a.b-c@d"),
            "\"a\"* \"b\"* \"c\"* \"d\"*"
        );
    }

    #[test]
    fn fts_prefix_query_empty_when_no_usable_tokens() {
        // Empty / punctuation-only input yields "" so the caller falls back to LIKE.
        assert_eq!(Store::fts_prefix_query(""), "");
        assert_eq!(Store::fts_prefix_query("  .-@  "), "");
    }

    // ── is_incidental_infra ───────────────────────────────────────────────────

    #[test]
    fn is_incidental_infra_flags_cdn_edge_ip() {
        // A Cloudflare anycast edge IP — high-confidence but shared infrastructure.
        let e = Entity::new(EntityKind::IpAddress, "104.20.37.187", 0.95, "s");
        assert!(is_incidental_infra(&e));
    }

    #[test]
    fn is_incidental_infra_flags_mega_domain() {
        let e = Entity::new(EntityKind::Domain, "facebook.com", 0.50, "s");
        assert!(is_incidental_infra(&e));
    }

    #[test]
    fn is_incidental_infra_ignores_non_infra_kinds() {
        // The default arm: a person/username is never "shared infrastructure",
        // regardless of value.
        let person = Entity::new(EntityKind::Person, "104.20.37.187", 0.50, "s");
        let user = Entity::new(EntityKind::Username, "facebook.com", 0.50, "s");
        assert!(!is_incidental_infra(&person));
        assert!(!is_incidental_infra(&user));
    }
}
