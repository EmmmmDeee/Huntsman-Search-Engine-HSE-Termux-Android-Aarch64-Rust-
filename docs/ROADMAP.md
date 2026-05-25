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

### v0.9.0 — 14 new modules + Spiderfoot vendor bundle (2026-05-23)

Shipped. Registry grows from 21 → 36 modules. `hse provision` and
`hse set-key` CLI subcommands. Spiderfoot-faithful vendor CSS/JS
bundle embedded for the SPA.

### v0.10+ — PRs #30–#37 (2026-05-24 → 2026-05-25)

Eight feature PRs implemented across multiple engineering cycles:

- **PR #30** — Event persistence: `events` table, `events.history`
  endpoint, SSE-before-history in SPA, cascade delete, `insert_event`
  with exhaustive match, `/api/v1/stats` dashboard, `/report.json`
  scan export. Closes #24.
- **PR #31** — Scan cancellation: `CancelHandle`, RAII
  `CancelRegistryGuard`, `ScanStatus::Aborted`, Abort button,
  `spawn_scan` helper, live-session mid-iteration cancel,
  `mid_flight_cancellation_aborts_running_scan` test. Closes #23.
- **PR #32** — Module descriptions: `description()` trait, 50 module
  tooltips, `#[non_exhaustive]` on `ModuleInfo`, 303-site Maigret +
  Sherlock username_search expansion. Closes #27, #28.
- **PR #33** — Correlation rules 4 → 15: 11 new AU rules, TI_SOURCES
  whitelist, entity-kind guards, `Correlation::new()` constructor.
  Closes #26.
- **PR #34** — 14 new modules (36 → 50): `shodan_internetdb`,
  `caa_records`, `threatfox`, `rdap_domain`, `emailrep`, `ipinfo`,
  `ip2location`, `nominatim`, `abuseipdb`, `greynoise`,
  `haveibeenpwned`, `fullhunt`, `name_to_email`, plus
  `unreachable!()` → `Error::module()` hardening. Closes #25.
- **PR #35** — HTTP timeout fix: drop client-level 3s timeout, add
  5s `connect_timeout`.
- **PR #36** — In-flight budget gate: sequential `continue` → `break`,
  concurrent early gate + finalise-before-budget + JoinSet drain,
  `emit_skip` + `should_skip_module` + `module_timeout_ms` helpers.
- **PR #37** — JSON 404 for `/api/*` typos via nested axum router.

Architecture improvements: module pre-indexing by `TargetKind`,
shared HTTP client in `LiveScanner`, bus capacity 64 → 256,
`Target::trimmed()` / `Entity::tag_country()` / `Evidence::opt_attr()`
helpers cascaded across 25+ modules.

**50 modules, 303 username sites, 15 correlation rules, all 9 target
kinds covered, 183 unit + 12 smoke tests, 5.9 MB binary.**

## Planned

- Batch query CLI (`hse batch --file targets.csv`).
- Adaptive throttling: per-source circuit breaker on 429 responses.
- Additional module batches: `pgp_keyserver`, `bitcoin_blockchain`,
  `ethereum_address`, `dns_blacklist_zen`, `dns_blacklist_barracuda`.
- Authentication middleware for non-localhost deployments.
- Cron-style scan scheduling (beyond live-mode interval repeats).
- Webhook / notification hooks on scan completion.

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
