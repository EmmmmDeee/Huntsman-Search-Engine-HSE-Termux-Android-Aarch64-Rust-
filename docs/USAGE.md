# Usage

Complete CLI reference for `hse`. All commands are non-interactive and
suitable for scripting.

## Subcommands

```
hse scan      Run a single scan, print results
hse live      Re-run a scan periodically (v0.5+)
hse modules   List registered modules with cost / target / passive flags
hse selftest  Offline 5-stage install health check (no network); run it first
hse doctor    Verify environment (DB, keys, Termux, modules)
hse proxies   Proxy retriever: refresh/list a validated free-proxy pool
hse serve     Start the HTTP server + SPA (browse to http://127.0.0.1:8080)
hse --help    Top-level help
hse --version Print version
```

### First-run pre-configuration (automatic)

The first time you run any subcommand, HSE configures itself with zero setup:

- creates `$HOME/.huntsman/` (database + logs) and writes a self-documenting
  key manifest at `$HOME/.huntsman.env` (mode `0600`);
- fills the **bundled, always-on credentials** (OathNet / HIBP / WiGLE /
  SeekNow) into the empty/placeholder slots, so breach, geo and SIGINT
  modules work out of the box — no API keys to obtain first;
- leaves every other key as an editable `insert_..._here` placeholder.

It never clobbers a real value you've set, and placeholders are never treated
as keys (they're filtered before modules see them, and `doctor` counts only
real keys). Add your own keys with `hse set-key NAME VALUE`, by editing the
manifest, or via the Settings tab in the Web UI. `hse provision` re-merges the
manifest against the latest template (backing it up first).

---

## `hse scan` — full reference

```
hse scan [OPTIONS] --kind <KIND> --value <VALUE>
```

### Required

| Flag | Description |
|------|-------------|
| `-k, --kind <KIND>`   | Target type: `email`, `username`, `phone`, `name`, `ip`, `domain`, `asn`, `coords`, `address`, `url`, `org`, `abn`, `mac` |
| `-v, --value <VALUE>` | Target value (e.g. `example.com`, `foo@bar.com`) |

### Module selection

| Flag | Description |
|------|-------------|
| `-m, --modules <CSV>`  | Allowlist: only these modules run (e.g. `crtsh,dns_resolver`) |
| `--exclude <CSV>`      | Denylist: these modules are skipped |
| `--free-only`          | Skip key-gated and paid modules (only `cost() == Free`) |
| `--passive-only`       | Skip non-passive modules (only `is_passive() == true`) |

### Per-module timing

| Flag | Description |
|------|-------------|
| `-t, --throttle <MS>`  | Sleep this long between module dispatches (default 0) |
| `--timeout <MS>`       | Per-module timeout override (default 3000) |
| `--max-concurrent <N>` | Modules to run in parallel; `0` (default) = sequential. Opt-in since v0.8 — useful with `--depth` for big expansion rounds. |

### Filtering output

| Flag | Description |
|------|-------------|
| `--min-confidence <F>` | Drop entities whose base `confidence` is below this |

### Autonomous expansion (v0.2+)

| Flag | Default | Description |
|------|---------|-------------|
| `-d, --depth <N>`             | *auto* | Rounds of recursive expansion. **Omit for intelligent auto-depth** (the default): HSE picks the optimal rounds from the seed type + available keys. Pass `0` to force a single-round scan (legacy v0.1 behaviour); `1+` for a fixed depth. |
| `-A, --auto`                  | —      | Explicitly request auto-depth. Now the default when neither `--depth` nor `--recursive` is given; kept for back-compat / scripting clarity. |
| `-R, --recursive`             | —      | Aggressive deep sweep: depth=7, expansion confidence ≤0.40, `max_concurrent`≥4. Overridden by an explicit `--depth`. |
| `--min-expand-confidence <F>` | `0.50` | Only expand entities whose `c_effective()` is ≥ this. Set `0.75` for strict Verified-only expansion. |
| `--max-entities <N>`          | none   | Stop expansion when entity count reaches this. |
| `--max-wall-time <SECS>`      | none   | Stop expansion when wall-time exceeds this. |

### Output

| Flag | Description |
|------|-------------|
| `-o, --output <table\|json\|dossier>` | `table` (human summary), `json` (full scan + entities + relations, machine-readable), or `dossier` (full intel grouped by category, incl. the relation graph) |

### Global flags (all subcommands)

| Flag | Description |
|------|-------------|
| `-v` / `-vv` | Terminal verbosity: `-v` = `debug`, `-vv` = `trace` on stderr. The always-on `debug` file log (`$HOME/.huntsman/logs/hse.log`) and Web-UI **Logs** stream are unaffected — full `debug` is captured regardless. See [`DEBUGGING.md`](DEBUGGING.md). |

Override the filter precisely with `RUST_LOG`, e.g.
`RUST_LOG=huntsman_search_engine::core::engine=trace hse scan …`.

### Example invocations

```bash
# Default scan — auto-recurses to the optimal depth for the seed type
hse scan --kind domain --value example.com

# Force a single round (legacy v0.1 behaviour), no expansion
hse scan --kind domain --value example.com --depth 0

# Only run two specific modules, throttle, JSON output
hse scan --kind domain --value example.com \
  --modules crtsh,dns_resolver --throttle 500 --output json

# Free APIs only (good for unattended runs)
hse scan --kind email --value target@example.com --free-only

# Autonomous expansion: 2 rounds deep, cap at 500 entities
hse scan --kind domain --value example.com \
  --depth 2 --max-entities 500

# Aggressive expansion: lower confidence bar + longer wall-time budget
hse scan --kind domain --value example.com \
  --depth 3 --min-expand-confidence 0.5 \
  --max-entities 1000 --max-wall-time 120

# Local-only (no network at all): only modules where is_passive() == true
hse scan --kind email --value foo@bar.com --passive-only
```

---

## Output formats

### Table (default)

```
Scan ea7282a5 — 5 entities for email=alice.smith+work@example.com

KIND             VALUE                                            CONF  C_EFF  CLASS
--------------------------------------------------------------------------------------
username         alicesmith                                      0.450  0.450  PROBABLE
username         smith                                           0.450  0.450  PROBABLE
username         alice.smith+work                                0.450  0.450  PROBABLE
username         alice.smith                                     0.450  0.450  PROBABLE
username         alice                                           0.450  0.450  PROBABLE
```

Columns:
- **KIND** — `EntityKind`, snake_case
- **VALUE** — normalised value (truncated to 46 chars in table; full in JSON / DB)
- **CONF** — base confidence assigned by the producing module
- **C_EFF** — effective confidence `clamp(C × (1 + 0.15 × ln(corroboration)), 0, 1)`
- **CLASS** — derived tier: `CANDIDATE` (< 0.40), `PROBABLE` (0.40–0.74), `VERIFIED` (≥ 0.75)

### JSON

```bash
hse scan --kind domain --value example.com --output json
```

Returns a JSON object:

```json
{
  "scan": {
    "id": "ea7282a5...",
    "target": { "kind": "domain", "value": "example.com" },
    "status": "complete",
    "started_at": 1716468000,
    "finished_at": 1716468002,
    "entity_count": 12,
    "error": null,
    "options": { "...": "..." }
  },
  "entities": [
    {
      "uid": "abc123...",
      "kind": "ip_address",
      "value": "93.184.216.34",
      "confidence": 0.95,
      "corroboration": 1,
      "observed_at": 1716468001,
      "evidence": [
        {
          "source": "dns_resolver",
          "summary": "A record for example.com",
          "attributes": { "record_type": "A", "domain": "example.com" },
          "recorded_at": 1716468001
        }
      ],
      "tags": [],
      "scan_id": "ea7282a5..."
    }
  ]
}
```

Schemas:
- `EntityKind`: `email | username | phone | person | credential | password | ip_address | domain | url | asn | address | coordinates | organisation | abn_acn | mac_address | device_id | { other: "<string>" }`
- `Classification` (derived, not stored): `CANDIDATE | PROBABLE | VERIFIED`
- `TargetKind`: `email | username | phone | full_name | ip_address | domain | asn | coordinates | address`
- `ScanStatus`: `pending | running | complete | failed`
- `ModuleCost`: `free | key_gated | paid`

---

## `hse modules`

Lists all registered modules in priority order, with cost and target acceptance:

```
MODULE                      PRI  COST       PASSIVE  ACCEPTS
--------------------------------------------------------------------------------
hudsonrock                  130  free       no       email,domain
email_to_username            95  free       yes      email
crtsh                        35  free       no       domain
dns_resolver                 30  free       no       domain
ip_geo                       28  free       no       ip
```

See [`MODULES.md`](MODULES.md) for what each one does and its synergy notes.

---

## `hse serve` (v0.3+)

Starts an axum HTTP server with an embedded single-file SPA. Browse to
`http://127.0.0.1:8080` from Chrome or Firefox on the device.

```
hse serve [--bind <HOST:PORT>]
```

| Flag / env | Default | Notes |
|------------|---------|-------|
| `-b, --bind <HOST:PORT>` | `127.0.0.1:8080` | Localhost-only. Architecture invariant; change at your own risk. |
| env `HSE_BIND`           | (overrides flag) | |

Graceful shutdown on `Ctrl-C` / `SIGTERM`.

### API endpoints

All endpoints are under `/api/v1/`.

| Method | Path                       | Notes |
|--------|----------------------------|-------|
| GET    | `/health`                  | `{ "status": "ok", "version": "0.3.0" }` |
| GET    | `/version`                 | `{ "version": "0.3.0" }` |
| GET    | `/modules`                 | `{ "count": N, "modules": [{ name, priority, cost, passive }, ...] }` |
| POST   | `/scans`                   | Body: `ScanRequest` (`{ kind, value, options? }`). Returns `202 { scan_id, status }`. |
| GET    | `/scans`                   | 200 most recent scans. |
| GET    | `/scans/{id}`              | Single scan record. 404 if unknown. |
| GET    | `/scans/{id}/entities`     | `{ count, entities: [Entity, ...] }`. |
| GET    | `/scans/{id}/correlations` | `{ count, correlations: [Correlation, ...] }` (v0.4+). |
| GET    | `/scans/{id}/relations`    | `{ count, relations: [Relation, ...] }` — the typed entity-relation graph edges (structural / lineage / geo co-location / DNS resolution / WHOIS registration), each with a deterministic SHA-256 `id`, `kind`, `from`/`to` entity UIDs, and evidence. |
| GET    | `/scans/{id}/events`       | **SSE** — `text/event-stream` of `EventKind` JSON payloads. |
| GET    | `/logs/recent`             | On-disk backfill of the runtime debug log (redacted, plain text). |
| GET    | `/logs/stream`             | **SSE** — live, secret-redacted `debug` trace of the running process (the Web-UI **Logs** tab consumes this). |
| POST   | `/live`                    | `LiveRequest` body. Returns `202 { live_id, status }` (v0.5+). |
| GET    | `/live`                    | `{ count, sessions: [LiveSession, ...] }`. |
| GET    | `/live/{id}`               | Single `LiveSession`. 404 if unknown. |
| DELETE | `/live/{id}`               | Request graceful stop. |
| GET    | `/live/{id}/events`        | **SSE** — live-level + owned-scan events. |

### SSE event types

Each SSE `data:` payload is a JSON object discriminated by a `type` field:

```json
{ "type": "scan_start",      "target_kind": "domain", "target_value": "example.com" }
{ "type": "module_start",    "module": "crtsh" }
{ "type": "module_done",     "module": "crtsh", "found": 47 }
{ "type": "module_error",    "module": "ip_geo", "error": "timeout" }
{ "type": "module_skipped",  "module": "hudsonrock", "reason": "not in allowlist" }
{ "type": "entity_found",    "entity": { ...Entity... } }
{ "type": "expansion_tick",  "depth": 1, "queued": 12, "visited": 47 }
{ "type": "expansion_stop",  "reason": "no more high-confidence candidates" }
{ "type": "correlation_found", "correlation": { "rule_id": "AU-010", "severity": "medium", ... } }
{ "type": "correlations_done", "count": 2 }
{ "type": "scan_complete",   "scan_id": "...", "entity_count": 47 }
{ "type": "live_start",      "live_id": "live-abc...", "target_kind": "domain", "target_value": "...", "interval_secs": 30 }
{ "type": "live_tick",       "live_id": "live-abc...", "iteration": 3, "scan_id": "..." }
{ "type": "live_stop",       "live_id": "live-abc...", "reason": "iterations reached" }
```

The browser's `EventSource` API decodes these as `event.data` strings;
parse with `JSON.parse(event.data)`. The SPA at `/` does exactly this.

### Example session

```bash
# In one terminal:
hse serve

# In another (or from the browser DevTools console):
curl -s http://127.0.0.1:8080/api/v1/health
curl -X POST -H 'Content-Type: application/json' \
  -d '{"kind":"domain","value":"example.com","options":{"depth":1}}' \
  http://127.0.0.1:8080/api/v1/scans
# → {"scan_id":"abc...","status":"queued"}

curl -N http://127.0.0.1:8080/api/v1/scans/abc.../events
# (stays open, streams SSE)
```

---

## `hse live` (v0.5+)

Re-runs a target on a fixed interval. Each iteration is a normal scan
(same expansion + correlator + ScanOptions filters); the live session
owns the spawned scans and demultiplexes their events through one SSE
stream.

```
hse live --kind <KIND> --value <VALUE>
         [--interval <SECS>] [--iterations <N>]
         [--depth <N>] [--modules <CSV>]
         [--free-only] [--passive-only]
```

| Flag | Default | Notes |
|------|---------|-------|
| `-i, --interval <SECS>` | `30` | Seconds between iterations. |
| `--iterations <N>`      | none | Stop after this many; omit for infinite (Ctrl-C to stop). |
| `-d, --depth <N>`       | `0`  | Per-iteration expansion (same semantics as `scan --depth`). |
| `-m, --modules <CSV>`   | none | Same allowlist as `scan --modules`. |
| `--free-only`           | off  | Same as `scan --free-only`. |
| `--passive-only`        | off  | Same as `scan --passive-only`. |

Prints each event as one line of compact JSON. Ctrl-C requests a
graceful stop; the session ends after the current iteration finishes.

### Example

```bash
hse live --kind domain --value example.com --interval 60 --iterations 5 --depth 1
# {"type":"live_start","live_id":"live-...","interval_secs":60,...}
# {"type":"live_tick","live_id":"...","iteration":1,"scan_id":"..."}
# {"type":"module_start","module":"crtsh"}
# {"type":"entity_found","entity":{...}}
# ... etc, one event per line ...
# {"type":"live_stop","live_id":"...","reason":"iterations reached"}
```

---

## `hse doctor`

Verifies the environment. Run after install and after any system change:

```
HSE v0.2.0 — doctor

Termux:    detected
DB path:   /data/data/com.termux/files/home/.huntsman/huntsman.db
Keys path: /data/data/com.termux/files/home/.huntsman.env

Storage:
  ok — database opens cleanly

Modules (5 registered):
  free       5

HUNTSMAN_* keys loaded: 0
  (none set; all free modules still work)
```

(Key **names** only are listed — values are never printed.)

### `hse doctor --bundle`

Emits a full, **offline, secret-redacted** diagnostic report to stdout
*and* `$HOME/.huntsman/hse-debug-report.txt` — the artefact to paste to
Claude Code when an install or scan misbehaves. On top of the plain
output it adds: environment (`os/arch`, `HOME`/`PREFIX`/`SHELL`/
`TERMUX_VERSION`/`PATH`/`RUST_LOG`), which Termux:API **sensor tools**
resolve on `PATH` (missing ⇒ those sensor modules no-op, expected), the
10 most recent scans incl. any `Failed` status + error, and redacted
tails of the runtime and install logs. It makes **no network calls and
spawns no subprocess** — pure introspection + local file reads. See
[`DEBUGGING.md`](DEBUGGING.md).

---

## Environment variables read by HSE

| Variable | Purpose |
|----------|---------|
| `HOME` | Resolves DB path and keys path (Termux: `/data/data/com.termux/files/home`) |
| `RUST_LOG` | Standard `tracing_subscriber` filter, e.g. `RUST_LOG=debug` or `RUST_LOG=huntsman_search_engine::modules=trace` |
| `TERMUX_VERSION` | Set by Termux; used for `is_termux()` detection |
| `HUNTSMAN_*` | Per-module API keys (loaded from `$HOME/.huntsman.env`); never logged |
| `HUNTSMAN_PROXY` | Route all module HTTP through a proxy: an explicit `scheme://host:port`, or `auto` to use the fastest validated proxy from the pool (`hse proxies refresh`). Unset → direct. |
| `HUNTSMAN_SEARCH_PROXY` | Proxy used by the search-engine modules when a direct fetch is blocked (falls back to the validated pool if unset). |

---

## Verbose / debug logging

HSE captures a full `debug` trace **on every run regardless of terminal
verbosity** to an always-on, secret-redacted log file — so a failure on
an ordinary run is already recorded; you don't have to reproduce it.

| Sink | Where | Level |
|------|-------|-------|
| Terminal (stderr) | live | `info` (default), `debug` with `-v`, `trace` with `-vv` |
| File | `$HOME/.huntsman/logs/hse.log` (size-rotated → `hse.log.1` past 5 MB) | always `debug` |
| Web UI | **Logs** tab / `GET /api/v1/logs/stream` (SSE) + `/logs/recent` | always `debug` |

```bash
hse -v  scan --kind domain --value example.com   # debug on the terminal too
hse -vv serve                                     # trace everything

# Precise per-target filtering still works via RUST_LOG:
RUST_LOG=huntsman_search_engine=trace hse scan ...            # everything HSE emits
RUST_LOG=huntsman_search_engine::modules::crtsh=trace hse ... # single-module trace
```

Output is human-readable structured logging, suitable for `grep`/`jq`
when combined with `--output json`. Credentials (`HUNTSMAN_*=…`,
`api_key:…`, `token=…`, `password=…`, `bearer …`) are masked before any
line is written or streamed. For the full install→fail→diagnose→fix loop
see [`DEBUGGING.md`](DEBUGGING.md).
