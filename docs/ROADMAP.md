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

## In flight

Three free-module slots originally planned for v0.4/v0.5 are still
deferred: `breach_directory`, `urlscan`, `asn_lookup`. Key-gated modules
deferred to v0.7+: `hibp`, `hunter`, `virustotal`, `dehashed`,
`oathnet_pro`, `shodan`. They'll land alongside the v0.7 hardening
work below when there's a natural place to slot them.

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
