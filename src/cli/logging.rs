//! CLI tracing subscriber setup.

use tracing_subscriber::EnvFilter;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

const DEFAULT_RAW_LOG: &str = "trace,\
    hyper=info,hyper_util=info,h2=info,rustls=info,reqwest=info,\
    tokio_util=info,tower=info,want=info,mio=info,\
    hickory_resolver=info,hickory_proto=info,hickory_net=info,trust_dns_proto=info";

pub(super) fn initialize() {
    // Raw logs by default (operator directive: the entire project outputs raw
    // logs). When `RUST_LOG` is unset we default to TRACE — the rawest level —
    // so every curl invocation, full endpoint payload, JSON-parse step, and
    // retry/backoff decision is emitted without the operator having to opt in.
    // An explicit `RUST_LOG` still wins (e.g. `RUST_LOG=warn` to quieten, or
    // `RUST_LOG=hyper=info,huntsman_search_engine=trace` to scope).
    //
    // Logs go to STDERR so stdout carries only the requested payload — without
    // this, log lines interleave into `--output json` (and live/export
    // streams), producing output downstream parsers cannot consume.
    //
    // FORMAT: one JSON object per line (NDJSON) — a single structured format
    // across the whole system, machine-readable and ingestible by virtually any
    // LLM or log pipeline without a bespoke parser. Each line carries the
    // metadata needed for debugging AND cross-correlation: `timestamp`, `level`,
    // `target` + `line_number` (call site), the event's own fields
    // flattened to the top level, and the enclosing span chain (`span`/`spans`)
    // `target` defaults to the emitting module path; the few subsystems that
    // want a short, stable, greppable tag (engine-health, search, the SERP
    // parser, per-provider fetch lines) use the `huntsman::<area>` convention.
    //
    // Default filter: HSE's own crate at TRACE (raw logs for every module, curl
    // call, parse, retry), but the noisy plumbing crates capped at INFO. An
    // explicit `RUST_LOG` overrides this wholesale.
    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(DEFAULT_RAW_LOG));

    // One JSON event format, two writers behind one EnvFilter: the operator's
    // stderr console and a tee into the in-memory ring buffer, so the identical
    // NDJSON stream is downloadable from the Web UI (`GET /api/v1/logs`) /
    // `hse logs` and is byte-for-byte the same as what scrolled past.
    tracing_subscriber::registry()
        .with(filter)
        .with(
            tracing_subscriber::fmt::layer()
                .json()
                .flatten_event(true)
                .with_current_span(true)
                .with_span_list(true)
                .with_target(true)
                .with_line_number(true)
                .with_writer(std::io::stderr),
        )
        .with(
            tracing_subscriber::fmt::layer()
                .json()
                .flatten_event(true)
                .with_current_span(true)
                .with_span_list(true)
                .with_target(true)
                .with_line_number(true)
                .with_writer(crate::util::log_capture::RingMakeWriter),
        )
        .init();
}
