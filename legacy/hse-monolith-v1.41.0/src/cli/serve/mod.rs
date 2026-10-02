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
//!   * binding a NON-loopback address requires a bearer token on every request
//!     (`api::auth`) — minted and printed once at startup unless `--auth-token`
//!     pins one, or `--allow-unauthenticated` deliberately opens the bind;
//!   * the startup self-test runs in the BACKGROUND so a slow check never delays
//!     the bind — the UI is reachable immediately;
//!   * shutdown-signal handlers degrade gracefully instead of panicking;
//!   * a `bind` failure carries an actionable hint (port-in-use is the common
//!     on-device cause).

use std::sync::Arc;

/// Loopback detection, taken from `api::routes` rather than reimplemented here.
///
/// This module used to carry its own copy and the two had already drifted: on a
/// bare `::1` (no port) the local copy split at the LAST colon, left the host as
/// `":"`, and reported the v6 loopback as EXPOSED. That was cosmetic while its
/// only consumer was a warning string. It stopped being cosmetic once the same
/// question decides both whether the bearer-token gate is installed
/// (`api::auth::resolve`, which asks the `routes` copy) and whether the token is
/// printed at all (`announce_auth`, which asked this one) — two answers to one
/// security question is how an operator ends up with a server demanding a token
/// it never showed them. One definition, one answer.
use crate::api::routes::is_loopback_bind;
use crate::core::error::{Error, Result};
use crate::util::http::build_client;

pub(super) async fn cmd_serve(
    bind: String,
    allow_key_write: bool,
    auth_token: Option<String>,
    allow_unauthenticated: bool,
) -> Result<()> {
    use std::net::SocketAddr;

    use crate::api::{AppState, UpdateInfo, UpdatePhase, routes::router};
    use crate::app::update::{apply_update, check_updates, self_restart};
    use crate::core::live::LiveScanner;

    // Pin `localhost` to the v4 loopback for reliable Chrome-on-device access.
    let bind = normalise_bind(&bind);

    let crate::app::runtime::ApplicationRuntime { store, bus, engine } =
        crate::app::runtime::build_runtime(1024)?;
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
        cells_import: Arc::new(std::sync::Mutex::new(
            crate::api::CellsImportPhase::default(),
        )),
    });

    // A separate clone for the shutdown path — `router` consumes `state` by
    // value, and shutdown needs the SAME `cancellations`/`live` registries to
    // signal in-flight work to stop before the process exits.
    let state_for_shutdown = Arc::clone(&state);

    // Resolve the auth posture BEFORE binding: a misconfigured token (an empty
    // `HSE_AUTH_TOKEN`) must fail the command outright rather than open a
    // listener that then rejects every request — or, worse, accepts them.
    let auth = crate::api::auth::resolve(&bind, auth_token, allow_unauthenticated)?
        .map(std::sync::Arc::new);

    let app = router(state, &bind, auth.clone());
    let listener = tokio::net::TcpListener::bind(&bind)
        .await
        .map_err(|e| bind_error(&bind, &e))?;

    announce_auth(&bind, auth.as_deref(), allow_unauthenticated);

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
        // Skip missed ticks rather than firing them back-to-back: a slow sweep
        // (or a stalled runtime) must not queue a burst of catch-up sweeps that
        // then hammer every search engine in quick succession — one sweep per
        // interval, drop the backlog. (Same rationale as the housekeeping and
        // auto-update ticks below.)
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            // First tick fires immediately → a sweep at startup, then every interval.
            tick.tick().await;
            let _ = crate::modules::search_engines::health::refresh_cache().await;
        }
    });

    // Autonomous housekeeping: keep the on-device `~/.huntsman` footprint
    // bounded and arranged without operator intervention — trim the
    // regenerable dossier cache, apply the canonical event-log / raw-archive
    // retention bounds, truncate the WAL, and re-assert the 0700 layout (see
    // `app::tidy`). This is what keeps a long-lived Termux install tidy: the
    // per-scan prune only runs when a scan COMPLETES, so a server left running
    // for weeks without finishing one would otherwise never reclaim anything.
    // Interval is configurable via `HUNTSMAN_TIDY_INTERVAL_SECS` (default 24 h;
    // min 1 h). First pass is staggered 5 min so startup stays responsive and
    // it never contends with the engine-health sweep. `spawn_blocking` — the
    // pass does blocking filesystem + SQLite work. Detached and best-effort:
    // it never blocks serving and a failure is logged, not fatal.
    {
        let tidy_secs = std::env::var("HUNTSMAN_TIDY_INTERVAL_SECS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .filter(|&n| n >= 3600) // min 1 h
            .unwrap_or(86_400); // default 24 h
        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_secs(300)).await;
            let mut tick = tokio::time::interval(std::time::Duration::from_secs(tidy_secs));
            // Skip missed ticks rather than firing them back-to-back: if a pass
            // (or a stalled runtime) overruns the interval, `Burst` — tokio's
            // default — would run several housekeeping passes with no gap to
            // "catch up", exactly the wrong behaviour for expensive filesystem +
            // SQLite work. `Skip` keeps the original cadence and drops the
            // backlog.
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                tick.tick().await;
                match tokio::task::spawn_blocking(|| crate::app::tidy::run(false)).await {
                    Ok(Ok(report)) => tracing::info!(
                        dossiers_removed = report.dossiers_removed,
                        bytes_reclaimed = report.dossier_bytes_reclaimed,
                        events_pruned = report.events_pruned,
                        archive_pruned = report.archive_pruned,
                        wal_truncated = report.wal_truncated,
                        "housekeeping pass complete"
                    ),
                    Ok(Err(e)) => tracing::warn!(error = %e, "housekeeping pass failed"),
                    // A `JoinError` is a panic OR a cancellation (the runtime
                    // shutting down aborts this task). Only the former is a fault
                    // worth a warning; reporting a normal-shutdown cancel as a
                    // "panic" is a false alarm in the logs.
                    Err(e) if e.is_cancelled() => {
                        tracing::debug!("housekeeping task cancelled (runtime shutting down)");
                    }
                    Err(e) => tracing::warn!(error = %e, "housekeeping task panicked"),
                }
            }
        });
    }

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
            // Skip missed ticks rather than bursting: applying an update can take
            // a while (git fetch + rebuild + restart), so a check that overruns
            // the interval must not immediately trigger another — one check per
            // interval, drop the backlog. (Same rationale as the health and
            // housekeeping ticks above.)
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
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
                crate::app::update::record_check_stamp(now_secs);
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

/// Report the authentication posture for this bind.
///
/// Four cases, and the operator must be able to tell them apart at a glance:
///
///  * **loopback, no token** (the default) — nothing to say; only this device
///    can connect.
///  * **loopback, token supplied** — say the gate is ON. `resolve` honours an
///    explicit `--auth-token`/`HSE_AUTH_TOKEN` even on loopback (defence in
///    depth behind a reverse proxy), and staying silent about that would strand
///    an operator who left the variable in their shell profile: every request
///    401s with nothing on screen explaining why. The token itself is not
///    reprinted — they supplied it.
///  * **non-loopback, authenticated** — print the token once, with a
///    ready-to-open URL. This is the sole place the plaintext token is
///    disclosed; it goes to the operator's own terminal, never to a request
///    log, an API response, or an export.
///  * **non-loopback, `--allow-unauthenticated`** — the operator disabled the
///    gate deliberately, so keep the full-strength warning describing exactly
///    what they have exposed.
///
/// Key-writing stays loopback-only in every case, independent of this.
fn announce_auth(bind: &str, auth: Option<&crate::api::auth::AuthToken>, opted_out: bool) {
    if is_loopback_bind(bind) {
        if auth.is_some() {
            tracing::info!(
                "authentication is enabled on this loopback bind (token supplied via \
                 --auth-token / HSE_AUTH_TOKEN). Every request must carry it: \
                 `Authorization: Bearer <token>`, or open http://{bind}/?t=<token> once."
            );
        }
        return;
    }
    match auth {
        Some(token) => {
            tracing::info!(
                "bound to a NON-loopback address ({bind}) — authentication is REQUIRED. Open:"
            );
            tracing::info!("    http://{bind}/?t={}", token.reveal());
            tracing::info!(
                "  that link sets a session cookie and drops the token from the address bar. \
                 Scripts send `Authorization: Bearer <token>`. The token is shown ONCE, here — \
                 it is never written to a log, an API response, or an export. Pass \
                 --auth-token to pin your own."
            );
        }
        None if opted_out => {
            tracing::warn!(
                "bound to a NON-loopback address ({bind}) with --allow-unauthenticated — the UI \
                 and API are reachable from the local network with NO AUTHENTICATION. This is \
                 not just read visibility: anyone reachable at this address can TRIGGER new \
                 scans, start live sessions (consuming your API key quota), and run radar (the \
                 device's own WiFi/Bluetooth/cell/GPS sensor sweep) — not only view existing \
                 results. Key-writing (PUT /settings/keys) is the sole exception and always \
                 stays loopback-only. Drop --allow-unauthenticated to require a token."
            );
        }
        // Unreachable: `auth::resolve` returns `None` for a non-loopback bind
        // only when `opted_out` is set. Kept as a defensive branch rather than
        // an `unreachable!()` so a future change to `resolve` degrades into a
        // warning instead of aborting a running server.
        None => {
            tracing::warn!(
                "bound to a NON-loopback address ({bind}) with no authentication configured."
            );
        }
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
