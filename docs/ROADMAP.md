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

### v0.4.0 — Correlator + 2 new free modules (2026-05-23)

Rule-based post-scan correlator with 4 initial rules
(AU-001 multi-breach, AU-002 identity cluster, AU-003 high
corroboration, AU-010 infrastructure consensus). Severity scoring
(Low/Medium/High/Critical), persisted to a new `correlations` table,
surfaced in CLI table output + SPA Correlate tab + `GET /api/v1/scans/
{id}/correlations` endpoint + SSE `correlation_found` events. Two new
free modules: `alienvault_otx` (HTTP, no key, threat-intel pulses) and
`whois` (TCP/43, no key, registrar metadata). 56 tests pass; 4.7 MB
stripped binary.

### v0.5.0 — Live mode (2026-05-23)

`hse live` and the `/api/v1/live/*` endpoints. Re-runs a scan on a
fixed interval with the same `ScanOptions` and the same engine path
(expansion + correlator included). Sessions are tokio tasks tracked
in an in-memory registry; cancellation is via `Arc<AtomicBool>` — no
extra dependency. New event variants (`live_start` / `live_tick` /
`live_stop`); the per-session SSE stream demultiplexes events from
every scan a session spawned. SPA gains a Live tab. 62 tests; 4.7 MB.

### v0.6.0 — Termux sensor modules (2026-05-23)

Shipped as the v0.6.0 release. Six new free passive modules for
on-device GEOINT enrichment. Two work on any Linux (`arp_scan` reads
`/proc/net/arp`, `net_interfaces` reads `/sys/class/net`), four call
termux-api binaries (`termux-wifi-scaninfo`, `termux-wifi-connectioninfo`,
`termux-location`, `termux-telephony-cellinfo`). Off-device, all four
termux-* modules gracefully no-op via the new `util::termux::termux_cmd`
helper. New `MacAddress` / `Coordinates` / `DeviceId` entity flow gives
the correlator (AU-010 infrastructure consensus) more local data to
cluster on. 80 tests pass; 4.8 MB stripped binary.

### v0.7.0 — Junction table for multi-scan entity tracking (2026-05-23)

Shipped. `entity_observations(entity_uid, scan_id, observed_at)`
replaces the v0.2 last-scan-wins behaviour. `entities_for_scan` joins
through the junction, so an entity observed by multiple scans appears
in every observer's listing with corroboration intact across all of
them. Idempotent backfill from existing `entities` table on Store::open.
84 tests pass; 4.8 MB stripped binary.

### v0.8.0 — Parallel module dispatch (2026-05-23)

Shipped. `ScanOptions::max_concurrent` has been a documented field
since v0.1 but was never honoured. Engine now spawns up to N module
tasks in flight at once via `tokio::sync::Semaphore` +
`tokio::task::JoinSet`. Default stays `max_concurrent = 0` →
sequential, byte-identical to v0.1–v0.7. Sequential and concurrent
paths share `module_skip_reason` so event payloads are identical
between modes. 94 tests (84 lib + 10 integration; +3 cover the
concurrency cap). 4.8 MB stripped binary.

## In flight

Three free-module slots originally planned for v0.4/v0.5 are still
deferred: `breach_directory`, `urlscan`, `asn_lookup`. Key-gated
modules also deferred: `hibp`, `hunter`, `virustotal`, `dehashed`,
`oathnet_pro`, `shodan`. They land alongside the hardening work below
when there's a natural place to slot them.

## Planned

- Batch query CLI (`hse batch --file targets.csv`) and matching
  `/api/v1/batch` endpoints.
- Debug harness: per-module health check that runs a synthetic target
  through one module and reports timing + sample output.
- Paid-key modules behind `cost() == Paid` so `--free-only` covers them.
- Adaptive throttling: per-source circuit breaker on 429 responses.
- Three deferred free modules: `breach_directory`, `urlscan`, `asn_lookup`.
- Global semaphore on `scan_create` HTTP task spawning so a flood of
  POST /api/v1/scans can't OOM `hse serve` (PR #9 review item — held
  open for a real-world measurement before picking a default cap).

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
