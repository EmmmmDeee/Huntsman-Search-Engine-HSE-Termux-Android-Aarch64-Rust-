//! Shared application runtime construction.

use std::sync::Arc;

use crate::{
    core::{
        engine::ScanEngine,
        error::{Error, Result},
        event::EventBus,
        port::{EVENTS_MAX_ROWS, EVENTS_RETENTION_SECS, RAW_ARCHIVE_MAX_ROWS, StoragePort},
    },
    default_db_path,
    modules::{module_runtime, registry},
    storage::Store,
};

/// Concrete application services shared by CLI commands and the HTTP server.
///
/// The store is exposed through [`StoragePort`]; SQLite remains a composition
/// detail owned by this module.
pub struct ApplicationRuntime {
    pub store: Arc<dyn StoragePort>,
    pub bus: EventBus,
    pub engine: Arc<ScanEngine>,
}

/// Open and maintain the store, create the event bus, and construct the scan
/// engine over the complete module registry.
pub fn build_runtime(bus_capacity: usize) -> Result<ApplicationRuntime> {
    let db = Store::open(&default_db_path())?;
    let _ = db.prune_events(EVENTS_RETENTION_SECS, EVENTS_MAX_ROWS);
    let _ = db.prune_raw_archive(RAW_ARCHIVE_MAX_ROWS);
    let store: Arc<dyn StoragePort> = Arc::new(db);
    let (bus, _rx) = tokio::sync::broadcast::channel(bus_capacity);
    let engine = Arc::new(ScanEngine::with_module_runtime(
        registry(),
        Arc::clone(&store),
        bus.clone(),
        module_runtime(),
    ));
    Ok(ApplicationRuntime { store, bus, engine })
}

/// Resolve `latest` or validate an explicit scan id for read-oriented use cases.
pub fn resolve_scan_id(store: &Store, raw: &str) -> Result<String> {
    if raw == "latest" {
        return store
            .latest_completed_scan()?
            .map(|scan| scan.id)
            .ok_or_else(|| Error::Other("no completed scans in store".into()));
    }

    match store.get_scan(raw)? {
        None => Err(Error::Other(format!("scan {raw} not found"))),
        Some(scan) => {
            if scan.status != crate::core::scan::ScanStatus::Complete {
                eprintln!(
                    "⚠ scan {raw} is {status}, not complete — recovering its checkpointed \
                     (partial) entities; results may be incomplete",
                    status = scan.status.as_str()
                );
            }
            Ok(raw.to_string())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::ApplicationRuntime;

    #[test]
    fn application_runtime_is_publicly_nameable() {
        fn accepts_runtime(_: Option<ApplicationRuntime>) {}
        accepts_runtime(None);
    }
}
