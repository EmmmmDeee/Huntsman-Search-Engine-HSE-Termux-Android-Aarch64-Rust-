# Roadmap

HSE iterates up from a working prototype. Every tagged version compiles,
passes tests, and ships something demonstrably useful.

Versions are SemVer with `0.x` semantics — minor can break the public API,
patch is bug-fix-only. The first stable line will be `1.0` once the modules,
correlator, live mode, and HTTP/SPA are all production-tested on Termux.

## Shipped

### v0.1.0 — Foundation (2026-05-23)

Core types, engine, store, CLI, five free modules, 31 + 2 tests.
Proves the architecture and the trait + dispatch + storage chain.

### v0.2.0 — Autonomous expansion (2026-05-23)

The engine now auto-chains modules via a depth-bounded graph walk. Same
modules, dramatically more output. Five new tests cover depth, threshold,
budget, and cycle behaviour. One real bug fixed (`scan_id` preservation in
upsert).

### v0.3.0 — HTTP + SPA + SSE (2026-05-23)

`hse serve` boots an axum 0.8 HTTP server bound to `127.0.0.1:8080` with
an embedded single-file SPA (no CDN, no JS frameworks, ~520 lines). Eight
endpoints covering health/version, modules, scans CRUD + entities + SSE
events. The SPA mirrors the CLI's full `ScanOptions` surface — same
modular customisation before launching a scan, plus live progress feed.
4 jobs CI green; 4.6 MB stripped binary.

## In flight

### v0.4.0 — Correlator + breach/identity module catalog

- `src/core/correlator.rs` with rule-based post-scan analysis.
  Initial rules (AU-001 → AU-003): multi-source breach corroboration,
  identity cluster (Email + Username + Phone), AU business exposure
  (ABN + breach email).
- Severity scoring (Low / Medium / High / Critical), persisted to a
  `correlations` table.
- Surfaced in CLI table output and SPA's new "Correlate" tab.
- New free modules:
  - `breach_directory` — free, no key
  - `alienvault_otx` — public, no key
  - `urlscan` — public search, no key
  - `whois` — TCP/43 query (no root)
  - `asn_lookup` — via ip-api free tier
- New key-gated modules (free tier where available):
  - `hibp` — Have I Been Pwned (paid key required)
  - `hunter` — Hunter.io (free tier 25 req/month)
  - `virustotal` — VT (free tier 500 req/day)

### v0.5.0 — Live mode

- `hse live` CLI subcommand and `/api/v1/live` endpoints.
- A scan that re-runs on a configurable interval and uses the v0.2
  expansion engine each iteration. Same `ScanOptions` plus:
  - `interval_secs` (default 30)
  - `iterations` (default infinite)
  - Live SSE stream of new entities only (diff against prior iteration).
- SPA "Live" tab with start/stop, tick counter, rolling event log
  capped at 200 events.

### v0.6.0 — Termux sensor modules

Now that termux-api wiring is well-understood:

- `arp_scan` — reads `/proc/net/arp`, no termux-api needed
- `net_interfaces` — reads `/sys/class/net/*/address`
- `wifi_scan` — calls `termux-wifi-scaninfo`
- `wifi_connect` — calls `termux-wifi-connectioninfo`
- `gps_fix` — calls `termux-location -p network -r once`
- `cell_survey` — calls `termux-telephony-cellinfo`

All graceful no-ops off-device (missing binary → empty `ModuleResult`).
`is_passive() == true` for each (no network, local sensors only).

### v0.7.0+ — Hardening

- Junction table `entity_observations(entity_uid, scan_id, observed_at)`
  to track every (entity, scan) pair, replacing the v0.2 last-scan-wins
  upsert. Migration path documented.
- Batch query CLI (`hse batch --file targets.csv`) and matching
  `/api/v1/batch` endpoints.
- Debug harness: per-module health check that runs a synthetic target
  through one module and reports timing + sample output.
- Paid-key modules: `dehashed`, `oathnet_pro`, `shodan` etc., all gated
  behind `cost() == Paid` so `--free-only` covers them.
- Parallel module dispatch using `tokio::sync::Semaphore` (honours the
  existing `ScanOptions::max_concurrent` field).
- Adaptive throttling: per-source circuit breaker on 429 responses.

## After 1.0

- Plugin system (modules as dynamically-loaded `.so` files? — TBD; the
  current static-link model is simpler and ships a single binary).
- Distributed mode: multiple HSE instances sharing one store via libsql or
  pglite. Only if there's demand.
- Mobile-native UI (Jetpack Compose / Swift UI), talking to the local HTTP
  server. The current SPA already works in Chrome on Android; a native UI
  would be a separate project.

## Non-goals

These are deliberate exclusions to keep HSE focused:

- **LLM / AI features.** The "intelligent autonomy" the project provides
  is deterministic — confidence thresholds, depth caps, visited sets.
  Not heuristic / model-based.
- **GUI desktop app.** Browser SPA serves the same purpose without
  platform-specific code.
- **Online dashboard / hosted service.** HSE runs entirely on the user's
  device. Telemetry-free, by design.
- **Active reconnaissance** (port scanning at scale, exploit attempts,
  spam, etc.). HSE focuses on passive OSINT and on-device GEOINT.
