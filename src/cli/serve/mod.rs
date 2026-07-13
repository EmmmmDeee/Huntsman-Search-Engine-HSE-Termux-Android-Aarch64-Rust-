//! `hse serve` — start the HSE HTTP server with SPA + SSE.
//!
//! Boots axum on the given bind address, wrapping a shared `AppState` (scan
//! engine, live scanner, store, HTTP client). The loopback-only key-mutation
//! endpoint (`PUT /api/v1/settings/keys`) is ENABLED BY DEFAULT so the Settings
//! page works out of the box; `--no-key-write` disables it. The loopback peer
//! check is unconditional, so a network-exposed bind still can't write keys
//! regardless of the flag.
//!
//! Reachability / robustness (Termux + Chrome-on-localhost):
//!   * a `localhost:<port>` bind is pinned to `127.0.0.1:<port>` — `TcpListener`
//!     binds a SINGLE resolved address, and `localhost` resolving to `::1` while
//!     Chrome connects to `127.0.0.1` (or vice-versa) is a classic on-device
//!     "can't connect";
//!   * binding a NON-loopback address logs a prominent warning (LAN exposure);
//!   * the startup self-test runs in the BACKGROUND so a slow check never delays
//!     the bind — the UI is reachable immediately;
//!   * shutdown-signal handlers degrade gracefully instead of panicking;
//!   * a `bind` failure carries an actionable hint (port-in-use is the common
//!     on-device cause).

use std::sync::Arc;

use crate::core::error::{Error, Result};
use crate::util::http::build_client;

use super::build_runtime;

pub(super) async fn cmd_serve(bind: String, allow_key_write: bool) -> Result<()> {
    use std::net::SocketAddr;

    use crate::api::{AppState, UpdateInfo, UpdatePhase, routes::router};
    use crate::cli::update::{apply_update, check_updates, self_restart};
    use crate::core::live::LiveScanner;

    // Pin `localhost` to the v4 loopback for reliable Chrome-on-device access.
    let bind = normalise_bind(&bind);

    let (store, bus, engine) = build_runtime(1024)?;
    let http = build_client();
    let live = LiveScanner::new(
        Arc::clone(&engine),
        bus.clone(),
        http.clone(),
        crate::util::keys::populate_and_load().await,
    );
    let update_info = Arc::new(std::sync::Mutex::new(UpdateInfo::default()));
    let state = Arc::new(AppState {
        store,
        engine,
        bus,
        live,
        http,
        allow_key_write,
        cancellations: Arc::new(parking_lot::Mutex::new(std::collections::HashMap::new())),
        scan_semaphore: Arc::new(tokio::sync::Semaphore::new(
            crate::api::MAX_CONCURRENT_SCANS,
        )),
        update_info: Arc::clone(&update_info),
    });

    // A separate clone for the shutdown path — `router` consumes `state` by
    // value, and shutdown needs the SAME `cancellations`/`live` registries to
    // signal in-flight work to stop before the process exits.
    let state_for_shutdown = Arc::clone(&state);
    let app = router(state, &bind);
    let listener = tokio::net::TcpListener::bind(&bind)
        .await
        .map_err(|e| bind_error(&bind, &e))?;

    warn_if_exposed(&bind);

    // Search-engine liveness: sweep at startup and on an interval, populating the
    // cache that backs the web liveness panel + `GET /api/v1/engines/health` and
    // emitting structured events into the unified debug log. Interval is
    // configurable via `HUNTSMAN_ENGINE_HEALTH_SECS` (default 900s = 15 min; min
    // 60s). Detached background task — best-effort, never blocks serving.
    let health_secs = std::env::var("HUNTSMAN_ENGINE_HEALTH_SECS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .filter(|&n| n >= 60)
        .unwrap_or(crate::modules::search_engines::health::DEFAULT_REFRESH_SECS);
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(std::time::Duration::from_secs(health_secs));
        loop {
            // First tick fires immediately → a sweep at startup, then every interval.
            tick.tick().await;
            let _ = crate::modules::search_engines::health::refresh_cache().await;
        }
    });

    // Autonomous self-update: check for upstream commits on a schedule and apply
    // them automatically when feature.auto_update is ON (the default). The first
    // check is intentionally deferred 2 min so the server is fully up and the
    // engine health sweep is done before we touch git. The update interval is
    // configurable via HUNTSMAN_AUTO_UPDATE_INTERVAL_SECS (default 6 h; min 30
    // min). Detached background task — never blocks serving.
    {
        let update_info = Arc::clone(&update_info);
        let state_for_restart = Arc::clone(&state_for_shutdown);
        let interval_secs = std::env::var("HUNTSMAN_AUTO_UPDATE_INTERVAL_SECS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .filter(|&n| n >= 1800) // min 30 min
            .unwrap_or(21_600); // default 6 h
        tokio::spawn(async move {
            // Stagger first check by 2 min.
            tokio::time::sleep(std::time::Duration::from_secs(120)).await;
            let mut tick = tokio::time::interval(std::time::Duration::from_secs(interval_secs));
            loop {
                tick.tick().await;
                if let Ok(mut info) = update_info.lock() {
                    info.phase = UpdatePhase::Checking;
                }
                let behind = tokio::task::spawn_blocking(check_updates)
                    .await
                    .unwrap_or(None);
                let now_secs = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                if let Ok(mut info) = update_info.lock() {
                    info.commits_behind = behind;
                    info.last_checked = now_secs;
                    info.phase = UpdatePhase::Idle;
                }
                // Share the check timestamp with the CLI auto-update gate so a
                // recent server-side check throttles the CLI path too (one device,
                // one cadence) — and vice-versa.
                crate::cli::update::record_check_stamp(now_secs);
                if behind.unwrap_or(0) > 0
                    && crate::util::settings::get_bool("feature.auto_update", true)
                {
                    if let Ok(mut info) = update_info.lock() {
                        info.phase = UpdatePhase::Applying;
                    }
                    let result = apply_update(None).await;
                    match result {
                        Ok(()) => {
                            if let Ok(mut info) = update_info.lock() {
                                info.phase = UpdatePhase::Restarting;
                            }
                            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                            // `self_restart()`'s `exec()` atomically replaces the
                            // process image with zero cooperative cancellation —
                            // without this, an in-flight scan or live session at
                            // the moment of a scheduled auto-update was simply
                            // abandoned mid-request, exactly like an undrained
                            // Ctrl-C once was.
                            crate::api::drain_in_flight_work(
                                &state_for_restart.cancellations,
                                &state_for_restart.live,
                                crate::api::SHUTDOWN_DRAIN_GRACE,
                            )
                            .await;
                            self_restart();
                        }
                        Err(e) => {
                            if let Ok(mut info) = update_info.lock() {
                                info.phase = UpdatePhase::Error(e.to_string());
                            }
                        }
                    }
                }
            }
        });
    }

    tracing::info!("hse v{} — listening on http://{}", crate::VERSION, bind);
    tracing::info!("  open in Chrome / Firefox on this device");
    if allow_key_write {
        tracing::info!("  Settings → API keys: editable here (loopback only)");
    } else {
        tracing::info!("  --no-key-write: Settings key editing is disabled");
    }
    tracing::info!("  Ctrl-C to stop");

    // Self-validate modules + core in the BACKGROUND so the server binds and
    // serves immediately — a slow self-test must never delay reachability on a
    // low-power device. Results are logged when ready and re-run on demand at
    // GET /api/v1/selftest. Non-fatal: a panic in the task can't take the server
    // down (panic = unwind).
    tokio::spawn(async {
        let report = crate::selftest::run().await;
        if report.ok {
            tracing::info!("{}", report.summary());
        } else {
            tracing::warn!("{}", report.summary());
            for c in report
                .checks
                .iter()
                .filter(|c| c.status == crate::selftest::Status::Fail)
            {
                tracing::warn!(check = %c.name, "self-test FAIL: {}", c.detail);
            }
        }
    });

    // `shutdown_fired` is only notified once `shutdown_signal` resolves (OS
    // signal observed AND in-flight scans/live sessions drained) — so the
    // deadline race below is dormant for the server's entire normal lifetime
    // and only starts counting during an actual shutdown.
    let shutdown_fired = Arc::new(tokio::sync::Notify::new());
    let shutdown_fired_for_signal = Arc::clone(&shutdown_fired);
    let serve_fut = axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(async move {
        shutdown_signal(state_for_shutdown).await;
        shutdown_fired_for_signal.notify_one();
    });

    tokio::select! {
        result = serve_fut => {
            result.map_err(|e| Error::Other(format!("serve: {e}")))?;
        }
        () = async {
            shutdown_fired.notified().await;
            tokio::time::sleep(HTTP_DRAIN_DEADLINE).await;
        } => {
            // axum's own HTTP-connection drain (waiting for in-flight
            // requests — e.g. a long-idle SSE stream — to close) has no
            // built-in deadline of its own. Without this, a stream whose
            // underlying scan/live session has already stopped (per
            // `drain_in_flight_work`, above) could still hold the connection
            // open for up to `SSE_IDLE_TIMEOUT` (120s) before its own idle
            // timer closes it — keeping `hse serve` from actually exiting on
            // Ctrl-C/SIGTERM for that whole window. Give the drain a
            // generous but BOUNDED extra window, then exit anyway (dropping
            // the serve future forcibly closes whatever is still open) —
            // turning "could hang indefinitely" into "exits within a bounded
            // total time", matching the "Ctrl-C to stop" the banner promises.
            tracing::warn!(
                "HTTP connection drain exceeded {HTTP_DRAIN_DEADLINE:?} after the \
                 shutdown signal — exiting anyway (any still-open connection is dropped)"
            );
        }
    }

    tracing::info!("server stopped");
    Ok(())
}

/// Bounded extra window for axum's own HTTP-connection drain (in-flight
/// requests / open SSE streams) once `shutdown_signal` has already finished
/// signalling and draining in-flight scans/live sessions. Generous over
/// [`crate::api::SHUTDOWN_DRAIN_GRACE`] since a now-idle SSE stream still
/// needs its own `SSE_IDLE_TIMEOUT`-bounded close to complete, not just the
/// underlying session to stop.
const HTTP_DRAIN_DEADLINE: std::time::Duration = std::time::Duration::from_secs(30);

/// Pin a `localhost:<port>` bind to `127.0.0.1:<port>`. `TcpListener::bind` binds
/// only ONE resolved address; `localhost` can resolve to `::1` first while Chrome
/// connects to `127.0.0.1` (or vice-versa) → an on-device "can't connect". Any
/// other bind string passes through unchanged.
fn normalise_bind(bind: &str) -> String {
    match bind.strip_prefix("localhost:") {
        Some(port) => format!("127.0.0.1:{port}"),
        None => bind.to_string(),
    }
}

/// True if `bind`'s host is a loopback address (or `localhost`). Drives the
/// LAN-exposure warning.
fn is_loopback_bind(bind: &str) -> bool {
    // Strip the trailing `:port`, then any IPv6 brackets, to isolate the host.
    let host = bind.rsplit_once(':').map_or(bind, |(h, _)| h);
    let host = host.trim_start_matches('[').trim_end_matches(']');
    match host.parse::<std::net::IpAddr>() {
        Ok(ip) => ip.is_loopback(),
        Err(_) => host == "localhost",
    }
}

/// Warn loudly when bound to a non-loopback address: the UI and API are then
/// reachable from the local network with no authentication on most
/// endpoints — not just read access to results, but the ability to TRIGGER
/// new scans/live sessions/radar sweeps. The loopback peer-check still
/// blocks key writes regardless of bind. `127.0.0.1` (the default) is the
/// localhost-only convention, not an enforced restriction — nothing stops an
/// operator from binding elsewhere, so this warning is the only safeguard.
fn warn_if_exposed(bind: &str) {
    if !is_loopback_bind(bind) {
        tracing::warn!(
            "bound to a NON-loopback address ({bind}) — the UI and API are reachable from the \
             local network with NO AUTHENTICATION on most endpoints. This is not just read \
             visibility: anyone reachable at this address can TRIGGER new scans, start live \
             sessions (consuming your API key quota), and run radar (the device's own WiFi/ \
             Bluetooth/cell/GPS sensor sweep) — not only view existing results. Key-writing \
             (PUT /settings/keys) is the sole exception and always stays loopback-only \
             regardless of this bind. Use 127.0.0.1 for the localhost-only default."
        );
    }
}

/// Turn a `TcpListener::bind` failure into an actionable error. The common
/// on-device cause is a port already held by a previous `hse serve`.
fn bind_error(bind: &str, e: &std::io::Error) -> Error {
    use std::io::ErrorKind;
    let hint = match e.kind() {
        ErrorKind::AddrInUse => {
            " — port already in use (another `hse serve` running? stop it, or pass a free port, \
             e.g. --bind 127.0.0.1:8090)"
        }
        ErrorKind::PermissionDenied => {
            " — permission denied (no root on Termux; use a port >= 1024, e.g. 8080)"
        }
        ErrorKind::AddrNotAvailable => {
            " — address not available (the host part isn't a local interface; try 127.0.0.1)"
        }
        _ => "",
    };
    Error::Other(format!("bind {bind}: {e}{hint}"))
}

async fn shutdown_signal(state: Arc<crate::api::AppState>) {
    // Degrade gracefully if a handler can't be installed (rather than panicking,
    // which would crash the server): fall back to a pending future so the OTHER
    // signal branch — and `kill` — can still stop the process.
    let ctrl_c = async {
        if let Err(e) = tokio::signal::ctrl_c().await {
            tracing::warn!("Ctrl-C handler unavailable ({e}); use SIGTERM / kill to stop");
            std::future::pending::<()>().await;
        }
    };

    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut sig) => {
                sig.recv().await;
            }
            Err(e) => {
                tracing::warn!("SIGTERM handler unavailable ({e})");
                std::future::pending::<()>().await;
            }
        }
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        () = ctrl_c => {},
        () = terminate => {},
    }

    // Before letting axum start its own HTTP-connection drain: signal every
    // in-flight scan and live session to stop cooperatively, then wait
    // (bounded) for them to actually reach a terminal state. Without this, a
    // background scan/live-session task — spawned via `tokio::spawn` and
    // detached, never an axum request handler axum's own graceful-shutdown
    // drain can see — was simply abandoned mid-request on Ctrl-C/SIGTERM: the
    // scan row stayed stuck at `Running` forever, and a live session's
    // `session_loop` kept running undisturbed, in turn keeping any SSE stream
    // forwarding its events open and blocking axum's drain indefinitely.
    //
    // Shared with every `self_restart()` call site (`crate::api`), not just
    // this Ctrl-C/SIGTERM path — see [`crate::api::drain_in_flight_work`].
    crate::api::drain_in_flight_work(
        &state.cancellations,
        &state.live,
        crate::api::SHUTDOWN_DRAIN_GRACE,
    )
    .await;
}

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
