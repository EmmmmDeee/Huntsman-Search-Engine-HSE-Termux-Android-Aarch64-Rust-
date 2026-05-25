use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use tokio::time::sleep;
use tracing::{info, warn};

use crate::core::{
    cancel::CancelHandle,
    engine::ScanEngine,
    entity::unix_now,
    event::{Event, EventBus, EventKind},
    module::ModuleContext,
    scan::{Scan, ScanOptions, Target},
};
use crate::storage::store::Store;
use crate::util::{http::build_client, keys, uid::scan_id};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LiveOptions {
    #[serde(default = "default_interval_secs")]
    pub interval_secs: u64,

    #[serde(default)]
    pub iterations: Option<u32>,
}

impl Default for LiveOptions {
    fn default() -> Self {
        Self {
            interval_secs: default_interval_secs(),
            iterations: None,
        }
    }
}

fn default_interval_secs() -> u64 {
    crate::LIVE_DEFAULT_INTERVAL_SECS
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LiveStatus {
    Running,
    Completed,
    Stopped,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LiveSession {
    pub id: String,
    pub target: Target,
    pub scan_options: ScanOptions,
    pub live_options: LiveOptions,
    pub status: LiveStatus,
    pub started_at: u64,
    pub last_iteration_at: Option<u64>,
    pub iteration: u32,
    pub scan_ids: std::collections::HashSet<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LiveRequest {
    pub kind: crate::core::scan::TargetKind,
    pub value: String,
    #[serde(default)]
    pub options: ScanOptions,
    #[serde(default)]
    pub live: LiveOptions,
}

#[derive(Clone)]
pub struct LiveScanner {
    inner: Arc<LiveInner>,
}

struct LiveInner {
    sessions: RwLock<HashMap<String, LiveSession>>,
    cancels: RwLock<HashMap<String, CancelHandle>>,
    engine: Arc<ScanEngine>,
    bus: EventBus,
    store: Arc<Store>,
}

impl LiveScanner {
    pub fn new(engine: Arc<ScanEngine>, bus: EventBus, store: Arc<Store>) -> Self {
        Self {
            inner: Arc::new(LiveInner {
                sessions: RwLock::new(HashMap::new()),
                cancels: RwLock::new(HashMap::new()),
                engine,
                bus,
                store,
            }),
        }
    }

    pub fn start(&self, target: Target, scan_options: ScanOptions, live: LiveOptions) -> String {
        const MAX_SESSIONS: usize = 100;
        if self.inner.sessions.read().len() >= MAX_SESSIONS {
            return String::new();
        }

        let live_id = new_live_id(&target);
        let session = LiveSession {
            id: live_id.clone(),
            target: target.clone(),
            scan_options: scan_options.clone(),
            live_options: live.clone(),
            status: LiveStatus::Running,
            started_at: unix_now(),
            last_iteration_at: None,
            iteration: 0,
            scan_ids: std::collections::HashSet::new(),
        };

        let cancel = CancelHandle::new();
        self.inner.sessions.write().insert(live_id.clone(), session);
        self.inner
            .cancels
            .write()
            .insert(live_id.clone(), cancel.clone());

        let inner = Arc::clone(&self.inner);
        let live_id_for_task = live_id.clone();
        let cancel_for_task = cancel.clone();

        tokio::spawn(async move {
            session_loop(
                inner,
                live_id_for_task,
                target,
                scan_options,
                live,
                cancel_for_task,
            )
            .await;
        });

        info!(live_id = %live_id, "live session started");
        live_id
    }

    pub fn stop(&self, live_id: &str) -> bool {
        self.inner.cancels.read().get(live_id).is_some_and(|c| {
            c.cancel();
            true
        })
    }

    pub fn get(&self, live_id: &str) -> Option<LiveSession> {
        self.inner.sessions.read().get(live_id).cloned()
    }

    pub fn list(&self) -> Vec<LiveSession> {
        self.inner.sessions.read().values().cloned().collect()
    }

    pub fn session_owns_scan(&self, live_id: &str, scan_id: &str) -> bool {
        self.inner
            .sessions
            .read()
            .get(live_id)
            .is_some_and(|s| s.scan_ids.contains(scan_id))
    }
}

async fn session_loop(
    inner: Arc<LiveInner>,
    live_id: String,
    target: Target,
    scan_options: ScanOptions,
    live: LiveOptions,
    cancel: CancelHandle,
) {
    let interval = Duration::from_secs(live.interval_secs.max(1));
    let max_iter = live.iterations;
    let http = build_client();
    let loaded_keys = keys::load();

    let _ = inner.bus.send(Event::new(
        &live_id,
        EventKind::LiveStart {
            live_id: live_id.clone(),
            target_kind: target.kind.canonical_str().to_string(),
            target_value: target.value.clone(),
            interval_secs: live.interval_secs,
        },
    ));

    loop {
        if cancel.is_cancelled() {
            break;
        }

        let current = {
            let mut s = inner.sessions.write();
            if let Some(sess) = s.get_mut(&live_id) {
                sess.iteration += 1;
                sess.last_iteration_at = Some(unix_now());
                sess.iteration
            } else {
                    break;
            }
        };

        let sid = scan_id(target.kind.canonical_str(), &target.value);

        if let Some(s) = inner.sessions.write().get_mut(&live_id) {
            s.scan_ids.insert(sid.clone());
        }

        let _ = inner.bus.send(Event::new(
            &live_id,
            EventKind::LiveTick {
                live_id: live_id.clone(),
                iteration: current,
                scan_id: sid.clone(),
            },
        ));

        let scan = Scan::new(sid.clone(), target.clone()).with_options(scan_options.clone());
        let ctx = ModuleContext {
            scan_id: sid.clone(),
            bus: inner.bus.clone(),
            http: http.clone(),
            keys: loaded_keys.clone(),
            // Shared with the session so stop() aborts the in-flight iteration too.
            cancel: cancel.clone(),
            store: Arc::clone(&inner.store),
        };

        if let Err(e) = inner.engine.run(scan, target.clone(), ctx).await {
            warn!(live_id = %live_id, scan_id = %sid, error = %e, "iteration failed");
        }

        if let Some(max) = max_iter
            && current >= max
        {
            mark_completed(&inner, &live_id, "iterations reached");
            return;
        }

        let mut remaining = interval;
        let tick = Duration::from_millis(250);
        while remaining > Duration::ZERO {
            if cancel.is_cancelled() {
                break;
            }
            let step = remaining.min(tick);
            sleep(step).await;
            remaining = remaining.saturating_sub(step);
        }
    }

    mark_stopped(&inner, &live_id);
}

fn mark_completed(inner: &LiveInner, live_id: &str, reason: &'static str) {
    if let Some(s) = inner.sessions.write().get_mut(live_id) {
        s.status = LiveStatus::Completed;
    }
    inner.cancels.write().remove(live_id);
    let _ = inner.bus.send(Event::new(
        live_id,
        EventKind::LiveStop {
            live_id: live_id.into(),
            reason: reason.into(),
        },
    ));
}

fn mark_stopped(inner: &LiveInner, live_id: &str) {
    let mut emit_event = true;
    if let Some(s) = inner.sessions.write().get_mut(live_id) {
        if matches!(s.status, LiveStatus::Completed) {
            emit_event = false;
        } else {
            s.status = LiveStatus::Stopped;
        }
    }
    inner.cancels.write().remove(live_id);
    if emit_event {
        let _ = inner.bus.send(Event::new(
            live_id,
            EventKind::LiveStop {
                live_id: live_id.into(),
                reason: "stopped".into(),
            },
        ));
    }
}

fn new_live_id(target: &Target) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    let ns = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    h.update(format!("live-{ns}-{:?}-{}", target.kind, target.value).as_bytes());
    let full = hex::encode(h.finalize());
    format!("live-{}", &full[..16])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::scan::TargetKind;

    #[test]
    fn live_id_format_is_deterministic_prefix() {
        let t = Target::new(TargetKind::Domain, "example.com");
        let a = new_live_id(&t);
        let b = new_live_id(&t);
        // Different nanosecond timestamps → different ids
        assert!(a.starts_with("live-"));
        assert!(b.starts_with("live-"));
        assert_ne!(a, b);
        assert_eq!(a.len(), "live-".len() + 16);
    }

    #[test]
    fn live_options_default() {
        let o = LiveOptions::default();
        assert_eq!(o.interval_secs, crate::LIVE_DEFAULT_INTERVAL_SECS);
        assert!(o.iterations.is_none());
    }

    #[test]
    fn live_options_round_trip_json() {
        let o = LiveOptions {
            interval_secs: 60,
            iterations: Some(3),
        };
        let s = serde_json::to_string(&o).unwrap();
        let back: LiveOptions = serde_json::from_str(&s).unwrap();
        assert_eq!(back.interval_secs, 60);
        assert_eq!(back.iterations, Some(3));
    }

    #[test]
    fn live_request_default_options_inert() {
        let json = r#"{"kind":"domain","value":"x.com"}"#;
        let req: LiveRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.kind, TargetKind::Domain);
        assert_eq!(req.live.interval_secs, crate::LIVE_DEFAULT_INTERVAL_SECS);
        assert!(req.live.iterations.is_none());
    }
}
