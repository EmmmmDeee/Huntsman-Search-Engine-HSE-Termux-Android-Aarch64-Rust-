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

        assert_eq!(store.pathway_template_count(t).unwrap(), 0, "never seen");
        store.record_pathway_template(t).unwrap();
        assert_eq!(
            store.pathway_template_count(t).unwrap(),
            1,
            "after one scan"
        );
        store.record_pathway_template(t).unwrap();
        assert_eq!(
            store.pathway_template_count(t).unwrap(),
            2,
            "after two scans"
        );
        // A different template is independent.
        assert_eq!(store.pathway_template_count("other").unwrap(), 0);
    }
}
