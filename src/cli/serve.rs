//! `hse serve` — start the HSE HTTP server with SPA + SSE.
//!
//! Boots axum on the given bind address. Wraps a shared
//! `AppState` carrying the scan engine, live scanner, store and
//! HTTP client. `--allow-key-write` opens the loopback-only key
//! mutation endpoints; off by default.

use std::sync::Arc;

use crate::core::error::{Error, Result};
use crate::util::http::build_client;

use super::build_runtime;

pub(super) async fn cmd_serve(bind: String, allow_key_write: bool) -> Result<()> {
    use std::net::SocketAddr;

    use crate::api::{AppState, routes::router};
    use crate::core::live::LiveScanner;

    let (store, bus, engine) = build_runtime(1024)?;
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
        .map_err(|e| Error::Other(format!("bind {bind}: {e}")))?;

    tracing::info!("hse v{} — listening on http://{}", crate::VERSION, bind);
    tracing::info!("  open in Chrome / Firefox on this device");
    if allow_key_write {
        tracing::warn!("--allow-key-write: PUT /api/v1/settings/keys enabled (loopback only)");
    }
    tracing::info!("  Ctrl-C to stop");

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

async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("install Ctrl-C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("install SIGTERM handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        () = ctrl_c => {},
        () = terminate => {},
    }
}
