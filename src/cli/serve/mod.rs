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

    use crate::api::{AppState, routes::router};
    use crate::core::live::LiveScanner;

    // Pin `localhost` to the v4 loopback for reliable Chrome-on-device access.
    let bind = normalise_bind(&bind);

    let (store, bus, engine) = build_runtime(1024)?;
    crate::core::api_cache::init(
        &crate::default_db_path().with_file_name("api_cache.db"),
    );
    let http = build_client();
    let live = LiveScanner::new(
        Arc::clone(&engine),
        bus.clone(),
        http.clone(),
        crate::util::keys::populate_and_load().await,
    );
    let state = Arc::new(AppState {
        store,
        engine,
        bus,
        live,
        http,
        allow_key_write,
        cancellations: Arc::new(parking_lot::Mutex::new(std::collections::HashMap::new())),
        proxy_pool: std::sync::Arc::new(crate::util::proxy::ProxyPool::new()),
        scan_semaphore: Arc::new(tokio::sync::Semaphore::new(
            crate::api::MAX_CONCURRENT_SCANS,
        )),
    });

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
        .unwrap_or(900);
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(std::time::Duration::from_secs(health_secs));
        loop {
            // First tick fires immediately → a sweep at startup, then every interval.
            tick.tick().await;
            let _ = crate::modules::search_engines::health::refresh_cache().await;
        }
    });

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

    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await
    .map_err(|e| Error::Other(format!("serve: {e}")))?;

    tracing::info!("server stopped");
    Ok(())
}

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
/// reachable from the local network. The loopback peer-check still blocks key
/// writes, but scans and results become network-visible. `127.0.0.1` (the
/// default) is the localhost-only architecture invariant.
fn warn_if_exposed(bind: &str) {
    if !is_loopback_bind(bind) {
        tracing::warn!(
            "bound to a NON-loopback address ({bind}) — the UI and API are reachable from the \
             local network. Key writing stays loopback-only, but scans and results are \
             network-visible. Use 127.0.0.1 for the localhost-only default."
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

async fn shutdown_signal() {
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
}

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
