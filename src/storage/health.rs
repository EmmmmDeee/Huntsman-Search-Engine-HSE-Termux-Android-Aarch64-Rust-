// `impl Store`: per-module health ledger (T2.7 / SOL-HEALTH-SIGNAL).
//
// One row per module in `module_health`, upserted after every dispatch run.
// `consecutive_failures` resets to 0 on any success and increments on every
// error or timeout, giving `hse doctor` a fast "is this module degraded?"
// signal without scanning the full event log.

use rusqlite::params;

use crate::core::{
    entity::unix_now,
    error::Result,
    port::{ModuleHealthRow, ModuleRunOutcome},
};

use super::Store;

impl Store {
    pub fn record_module_run(&self, module_name: &str, outcome: &ModuleRunOutcome) -> Result<()> {
        let now = unix_now() as i64;
        let conn = self.conn.lock();
        match outcome {
            ModuleRunOutcome::Success { .. } => {
                conn.prepare_cached(
                    "INSERT INTO module_health \
                     (module_name, last_success_at, last_failure_at, \
                      consecutive_failures, total_runs, total_successes, \
                      last_error, updated_at) \
                     VALUES(?1, ?2, NULL, 0, 1, 1, NULL, ?2) \
                     ON CONFLICT(module_name) DO UPDATE SET \
                       last_success_at      = excluded.last_success_at, \
                       consecutive_failures = 0, \
                       last_error           = NULL, \
                       total_runs           = total_runs + 1, \
                       total_successes      = total_successes + 1, \
                       updated_at           = excluded.updated_at",
                )?
                .execute(params![module_name, now])?;
            }
            ModuleRunOutcome::Error { message } => {
                conn.prepare_cached(
                    "INSERT INTO module_health \
                     (module_name, last_success_at, last_failure_at, \
                      consecutive_failures, total_runs, total_successes, \
                      last_error, updated_at) \
                     VALUES(?1, NULL, ?2, 1, 1, 0, ?3, ?2) \
                     ON CONFLICT(module_name) DO UPDATE SET \
                       last_failure_at      = excluded.last_failure_at, \
                       consecutive_failures = consecutive_failures + 1, \
                       last_error           = excluded.last_error, \
                       total_runs           = total_runs + 1, \
                       updated_at           = excluded.updated_at",
                )?
                .execute(params![module_name, now, message])?;
            }
            ModuleRunOutcome::Timeout => {
                conn.prepare_cached(
                    "INSERT INTO module_health \
                     (module_name, last_success_at, last_failure_at, \
                      consecutive_failures, total_runs, total_successes, \
                      last_error, updated_at) \
                     VALUES(?1, NULL, ?2, 1, 1, 0, 'timeout', ?2) \
                     ON CONFLICT(module_name) DO UPDATE SET \
                       last_failure_at      = excluded.last_failure_at, \
                       consecutive_failures = consecutive_failures + 1, \
                       last_error           = 'timeout', \
                       total_runs           = total_runs + 1, \
                       updated_at           = excluded.updated_at",
                )?
                .execute(params![module_name, now])?;
            }
        }
        Ok(())
    }

    pub fn module_health_summary(&self) -> Result<Vec<ModuleHealthRow>> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare_cached(
            "SELECT module_name, last_success_at, last_failure_at, \
                    consecutive_failures, total_runs, total_successes, \
                    last_error, updated_at \
             FROM module_health \
             ORDER BY consecutive_failures DESC, module_name",
        )?;
        let rows = stmt.query_map([], |r| {
            Ok(ModuleHealthRow {
                module_name: r.get(0)?,
                last_success_at: r.get::<_, Option<i64>>(1)?.map(|v| v as u64),
                last_failure_at: r.get::<_, Option<i64>>(2)?.map(|v| v as u64),
                consecutive_failures: r.get::<_, i64>(3)? as u64,
                total_runs: r.get::<_, i64>(4)? as u64,
                total_successes: r.get::<_, i64>(5)? as u64,
                last_error: r.get(6)?,
                updated_at: r.get::<_, i64>(7)? as u64,
            })
        })?;
        rows.collect::<std::result::Result<_, _>>()
            .map_err(Into::into)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::port::ModuleRunOutcome;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn tmp_store() -> Store {
        static C: AtomicUsize = AtomicUsize::new(0);
        let n = C.fetch_add(1, Ordering::SeqCst);
        let path = format!(
            "{}/.huntsman-health-test-{}-{}.db",
            std::env::temp_dir().to_string_lossy(),
            std::process::id(),
            n
        );
        let _ = std::fs::remove_file(&path);
        Store::open(&path).expect("open")
    }

    #[test]
    fn success_clears_failure_streak() {
        let s = tmp_store();
        // Two failures, then a success — streak resets.
        s.record_module_run(
            "m",
            &ModuleRunOutcome::Error {
                message: "e".into(),
            },
        )
        .unwrap();
        s.record_module_run(
            "m",
            &ModuleRunOutcome::Error {
                message: "e".into(),
            },
        )
        .unwrap();
        s.record_module_run("m", &ModuleRunOutcome::Success { result_count: 3 })
            .unwrap();
        let rows = s.module_health_summary().unwrap();
        let row = rows.iter().find(|r| r.module_name == "m").unwrap();
        assert_eq!(row.consecutive_failures, 0, "success must reset streak");
        assert_eq!(row.total_runs, 3);
        assert_eq!(row.total_successes, 1);
        assert!(row.last_error.is_none(), "last_error cleared on success");
        assert!(row.last_success_at.is_some());
    }

    #[test]
    fn failure_increments_streak() {
        let s = tmp_store();
        s.record_module_run(
            "m",
            &ModuleRunOutcome::Error {
                message: "http 429".into(),
            },
        )
        .unwrap();
        s.record_module_run(
            "m",
            &ModuleRunOutcome::Error {
                message: "http 429".into(),
            },
        )
        .unwrap();
        s.record_module_run("m", &ModuleRunOutcome::Timeout)
            .unwrap();
        let rows = s.module_health_summary().unwrap();
        let row = rows.iter().find(|r| r.module_name == "m").unwrap();
        assert_eq!(row.consecutive_failures, 3);
        assert_eq!(row.total_runs, 3);
        assert_eq!(row.total_successes, 0);
        assert_eq!(row.last_error.as_deref(), Some("timeout"));
    }

    #[test]
    fn timeout_records_as_timeout_string() {
        let s = tmp_store();
        s.record_module_run("t", &ModuleRunOutcome::Timeout)
            .unwrap();
        let rows = s.module_health_summary().unwrap();
        let row = rows.iter().find(|r| r.module_name == "t").unwrap();
        assert_eq!(row.last_error.as_deref(), Some("timeout"));
        assert_eq!(row.consecutive_failures, 1);
    }

    #[test]
    fn summary_ordered_by_consecutive_failures_desc() {
        let s = tmp_store();
        // "a" = 1 failure, "b" = 3 failures
        s.record_module_run(
            "a",
            &ModuleRunOutcome::Error {
                message: "e".into(),
            },
        )
        .unwrap();
        for _ in 0..3 {
            s.record_module_run(
                "b",
                &ModuleRunOutcome::Error {
                    message: "e".into(),
                },
            )
            .unwrap();
        }
        let rows = s.module_health_summary().unwrap();
        assert_eq!(rows[0].module_name, "b", "highest streak first");
        assert_eq!(rows[1].module_name, "a");
    }

    #[test]
    fn empty_summary_when_no_runs_recorded() {
        let s = tmp_store();
        let rows = s.module_health_summary().unwrap();
        assert!(rows.is_empty());
    }
}
