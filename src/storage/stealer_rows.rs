//! Persistence for `core::stealer_row::StealerRow` — the paired stealer-log
//! credential rows the Stealer Logs Viewer reads. Kept in its own table
//! (`stealer_rows`), separate from the generic `entities` graph: see the
//! `CREATE TABLE` comment in `storage::mod` for why.

use rusqlite::params;

use crate::core::error::Result;
use crate::core::stealer_row::{StealerRow, StealerRowKind};

impl super::Store {
    /// Persist a batch of rows for one scan/import under one transaction —
    /// mirrors `upsert_entities_batch`'s all-or-nothing batch-commit shape.
    /// A no-op (not an error) on an empty slice, so the importer can call
    /// this unconditionally.
    pub fn insert_stealer_rows_batch(&self, scan_id: &str, rows: &[StealerRow]) -> Result<usize> {
        if rows.is_empty() {
            return Ok(0);
        }
        let conn = self.conn.lock();
        let tx = conn.unchecked_transaction()?;
        {
            let mut stmt = tx.prepare_cached(
                "INSERT INTO stealer_rows(scan_id, log_id, domain, login, password, pwned_at, row_kind)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            )?;
            for r in rows {
                stmt.execute(params![
                    scan_id,
                    r.log_id,
                    r.domain,
                    r.login,
                    r.password,
                    r.pwned_at,
                    r.kind.as_db_str(),
                ])?;
            }
        }
        tx.commit()?;
        Ok(rows.len())
    }

    /// Every persisted row for `scan_id`, insertion order (the order the
    /// importer discovered them in the source file).
    pub fn stealer_rows_for_scan(&self, scan_id: &str) -> Result<Vec<StealerRow>> {
        #[allow(clippy::type_complexity)]
        let rows: Vec<(
            Option<String>,
            Option<String>,
            Option<String>,
            Option<String>,
            Option<String>,
            String,
        )> = {
            let conn = self.conn.lock();
            let mut stmt = conn.prepare_cached(
                "SELECT log_id, domain, login, password, pwned_at, row_kind
                   FROM stealer_rows WHERE scan_id = ?1 ORDER BY id ASC",
            )?;
            let mapped = stmt.query_map(params![scan_id], |r| {
                Ok((
                    r.get(0)?,
                    r.get(1)?,
                    r.get(2)?,
                    r.get(3)?,
                    r.get(4)?,
                    r.get(5)?,
                ))
            })?;
            mapped.collect::<rusqlite::Result<Vec<_>>>()?
        };
        Ok(rows
            .into_iter()
            .map(
                |(log_id, domain, login, password, pwned_at, kind)| StealerRow {
                    log_id,
                    domain,
                    login,
                    password,
                    pwned_at,
                    kind: StealerRowKind::from_db_str(&kind),
                },
            )
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::super::Store;
    use super::*;

    fn row(log_id: &str, domain: Option<&str>, login: &str, password: &str) -> StealerRow {
        StealerRow {
            log_id: Some(log_id.to_string()),
            domain: domain.map(str::to_string),
            login: Some(login.to_string()),
            password: Some(password.to_string()),
            pwned_at: Some("2026-05-20T21:00:00Z".to_string()),
            kind: StealerRowKind::classify(domain),
        }
    }

    #[test]
    fn insert_and_read_back_round_trips_every_field() {
        let store = Store::open(":memory:").expect("in-memory store");
        let rows = vec![
            row("abc123", Some("example.com"), "alice", "hunter2"),
            row("abc123", None, "bob", "correcthorse"),
        ];
        let n = store
            .insert_stealer_rows_batch("scan-1", &rows)
            .expect("insert");
        assert_eq!(n, 2);

        let back = store.stealer_rows_for_scan("scan-1").expect("read back");
        assert_eq!(back.len(), 2);
        assert_eq!(back[0], rows[0]);
        assert_eq!(back[1], rows[1]);
        assert_eq!(back[0].kind, StealerRowKind::Password);
        assert_eq!(back[1].kind, StealerRowKind::Combo);
    }

    #[test]
    fn insert_empty_batch_is_a_no_op_not_an_error() {
        let store = Store::open(":memory:").expect("in-memory store");
        assert_eq!(
            store
                .insert_stealer_rows_batch("scan-1", &[])
                .expect("should succeed"),
            0
        );
        assert!(
            store
                .stealer_rows_for_scan("scan-1")
                .expect("should succeed")
                .is_empty()
        );
    }

    #[test]
    fn rows_are_scoped_to_their_own_scan_id() {
        let store = Store::open(":memory:").expect("in-memory store");
        store
            .insert_stealer_rows_batch("scan-a", &[row("m1", Some("a.com"), "u1", "p1")])
            .expect("should succeed");
        store
            .insert_stealer_rows_batch("scan-b", &[row("m2", Some("b.com"), "u2", "p2")])
            .expect("should succeed");
        let a = store
            .stealer_rows_for_scan("scan-a")
            .expect("should succeed");
        let b = store
            .stealer_rows_for_scan("scan-b")
            .expect("should succeed");
        assert_eq!(a.len(), 1);
        assert_eq!(b.len(), 1);
        assert_eq!(a[0].login.as_deref(), Some("u1"));
        assert_eq!(b[0].login.as_deref(), Some("u2"));
    }
}
