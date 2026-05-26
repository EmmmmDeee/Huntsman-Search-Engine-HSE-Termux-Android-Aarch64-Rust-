//! Event log persistence (v0.10+).

use rusqlite::params;

use crate::core::{
    error::Result,
    event::{Event, EventKind},
};

use super::Store;

impl Store {
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
