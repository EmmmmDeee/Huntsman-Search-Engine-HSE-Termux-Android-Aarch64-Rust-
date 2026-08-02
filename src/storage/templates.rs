// Cross-scan pathway-template learning (C1 universal linking). Methods on
// `Store` backed by the `pathway_templates` table defined in SCHEMA_DDL: a
// route confirmed in one scan is sought in every later scan.

use rusqlite::params;

use crate::core::error::Result;

use super::Store;

impl Store {
    /// Record that a direction-canonical pathway `template` was confirmed by a
    /// scan, incrementing its cross-scan seen-count (creating the row at 1 on
    /// first sight). Best-effort — callers ignore the error so a storage failure
    /// cannot abort an in-progress scan.
    pub fn record_pathway_template(&self, template: &str) -> Result<()> {
        let conn = self.conn.lock();
        conn.prepare_cached(
            "INSERT INTO pathway_templates(template, seen_count, last_seen)
             VALUES(?1, 1, unixepoch())
             ON CONFLICT(template) DO UPDATE SET
                 seen_count = seen_count + 1,
                 last_seen  = unixepoch()",
        )?
        .execute(params![template])?;
        Ok(())
    }

    /// The number of scans that have previously confirmed `template` (0 if it has
    /// never been seen). Consulted *before* the current scan records its own
    /// templates, so a non-zero count means a strictly earlier scan proved the
    /// route — the basis for crediting it as historically corroborated.
    pub fn pathway_template_count(&self, template: &str) -> Result<u32> {
        let conn = self.conn.lock();
        let mut stmt =
            conn.prepare_cached("SELECT seen_count FROM pathway_templates WHERE template = ?1")?;
        match stmt.query_row(params![template], |r| r.get::<_, i64>(0)) {
            Ok(n) => Ok(n.max(0) as u32),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(0),
            Err(e) => Err(e.into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::storage::Store;

    #[test]
    fn pathway_template_count_starts_at_zero_and_accumulates() {
        let store = Store::open(":memory:").expect("in-memory store");
        let t = "email →belongs_to_domain→ domain →registered_by→ person";

        assert_eq!(
            store.pathway_template_count(t).expect("should succeed"),
            0,
            "never seen"
        );
        store.record_pathway_template(t).expect("should succeed");
        assert_eq!(
            store.pathway_template_count(t).expect("should succeed"),
            1,
            "after one scan"
        );
        store.record_pathway_template(t).expect("should succeed");
        assert_eq!(
            store.pathway_template_count(t).expect("should succeed"),
            2,
            "after two scans"
        );
        // A different template is independent.
        assert_eq!(
            store
                .pathway_template_count("other")
                .expect("should succeed"),
            0
        );
    }

    /// End-to-end of the engine's universal-learning loop, exercised against a
    /// real store across the generate → record → consult boundary: a route
    /// generalised in one scan is credited when a *later* scan reproduces it.
    /// This is exactly the sequence `Engine::finalise` runs (minus the trivial
    /// `AU-065` `Correlation::new`), so it pins the cross-scan crediting the
    /// component tests can't see individually.
    #[test]
    fn a_route_proven_in_one_scan_is_credited_in_a_later_scan() {
        use crate::core::entity::{Entity, EntityKind};
        use crate::core::relation::{Relation, RelationKind, connection_templates};

        let store = Store::open(":memory:").expect("in-memory store");
        let mk = |k: EntityKind, v: &str| Entity::new(k, v, 0.8, "s");
        let edge = |f: &Entity, t: &Entity, k: RelationKind| {
            Relation::new(f.uid.clone(), t.uid.clone(), k, 0.8, "s")
        };

        // A multi-step identity route: Email → Domain → Person.
        let e = mk(EntityKind::Email, "a@x.com");
        let d = mk(EntityKind::Domain, "x.com");
        let p = mk(EntityKind::Person, "Alice");
        let ents = [e.clone(), d.clone(), p.clone()];
        let rels = [
            edge(&e, &d, RelationKind::BelongsToDomain),
            edge(&d, &p, RelationKind::RegisteredBy),
        ];
        let templates = connection_templates(&ents, &rels, 4);
        assert!(!templates.is_empty(), "the route generalises to a template");

        // Scan 1: every route is new — nothing is credited, everything recorded.
        for ct in &templates {
            assert_eq!(
                store
                    .pathway_template_count(&ct.template)
                    .expect("should succeed"),
                0,
                "first sight is uncredited"
            );
            store
                .record_pathway_template(&ct.template)
                .expect("should succeed");
        }

        // Scan 2 (consult step): the same route is now known, so the engine would
        // emit AU-065 for it.
        for ct in &templates {
            assert!(
                store
                    .pathway_template_count(&ct.template)
                    .expect("should succeed")
                    >= 1,
                "a route proven in scan 1 is credited in scan 2"
            );
        }
    }
}
