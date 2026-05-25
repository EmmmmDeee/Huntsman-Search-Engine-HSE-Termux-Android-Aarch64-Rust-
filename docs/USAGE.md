# Usage

Complete CLI reference for `hse`. All commands are non-interactive and
suitable for scripting.

## Subcommands

```
hse scan        Run a single scan, print results
hse live        Re-run a scan periodically (v0.5+)
hse modules     List registered modules with cost / target / passive flags
hse doctor      Verify environment (DB, keys, Termux, modules)
hse serve       Start the HTTP server + SPA (browse to http://127.0.0.1:8080)
hse provision   Run the post-install pipeline (DB init, key file, Termux checks)
hse set-key     Set an API key in $HOME/.huntsman.env
hse --help      Top-level help
hse --version   Print version
```

---

## `hse scan` — full reference

```
hse scan [OPTIONS] --kind <KIND> --value <VALUE>
```

### Required

| Flag | Description |
|------|-------------|
| `-k, --kind <KIND>`   | Target type: `email`, `username`, `phone`, `name`, `ip`, `domain`, `asn`, `coords`, `address` |
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
| `-d, --depth <N>`             | `0`    | Rounds of recursive expansion. `0` = single-round scan (v0.1 behaviour). |
| `--min-expand-confidence <F>` | `0.75` | Only expand entities whose `c_effective()` is ≥ this. Default is the Verified tier — strong filter. |
| `--max-entities <N>`          | none   | Stop expansion when entity count reaches this. |
| `--max-wall-time <SECS>`      | none   | Stop expansion when wall-time exceeds this. |

### Output

| Flag | Description |
|------|-------------|
| `-o, --output <table\|json>` | `table` (human) or `json` (full scan + entities) |

### Example invocations

```bash
# Plain single-shot scan against a domain
hse scan --kind domain --value example.com

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
| `--allow-key-write`      | off | Enables `PUT /api/v1/settings/keys` for the SPA key-management UI. Loopback-only even when enabled. |
| env `HSE_BIND`           | (overrides flag) | |

Graceful shutdown on `Ctrl-C` / `SIGTERM`.

### API endpoints

All endpoints are under `/api/v1/`.

| Method | Path                          | Notes |
|--------|-------------------------------|-------|
| GET    | `/health`                     | `{ "status": "ok", "version": "..." }` |
| GET    | `/version`                    | `{ "version": "..." }` |
| GET    | `/stats`                      | Dashboard aggregate stats (v0.10+). |
| GET    | `/modules`                    | `{ "count": N, "modules": [{ name, priority, cost, passive, description, accepts }, ...] }` |
| POST   | `/scans`                      | Body: `ScanRequest`. Returns `202 { scan_id, status }`. |
| GET    | `/scans`                      | 200 most recent scans. |
| GET    | `/scans/{id}`                 | Single scan record. 404 if unknown. |
| DELETE | `/scans/{id}`                 | Cascade-delete scan + entities + correlations + events. |
| POST   | `/scans/{id}/rerun`           | Clone scan with fresh id. |
| POST   | `/scans/{id}/cancel`          | Abort in-flight scan (v0.10+). |
| GET    | `/scans/{id}/entities`        | `{ count, entities }`. |
| GET    | `/scans/{id}/entities.csv`    | CSV download. |
| GET    | `/scans/{id}/report.json`     | Full JSON report download (v0.10+). |
| GET    | `/scans/{id}/correlations`    | `{ count, correlations }` (v0.4+). |
| GET    | `/scans/{id}/events`          | **SSE** — live event stream. |
| GET    | `/scans/{id}/events.history`  | Historical event log (v0.10+). |
| POST   | `/live`                       | `LiveRequest` body. Returns `202 { live_id }` (v0.5+). |
| GET    | `/live`                       | `{ count, sessions }`. |
| GET    | `/live/{id}`                  | Single `LiveSession`. 404 if unknown. |
| DELETE | `/live/{id}`                  | Request graceful stop. |
| GET    | `/live/{id}/events`           | **SSE** — live-level + owned-scan events. |
| GET    | `/settings/keys`              | List configured API keys (names only, not values). |
| PUT    | `/settings/keys`              | Set API keys (requires `--allow-key-write`). |

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

## `hse provision` (v0.9+)

Run the post-install pipeline. Idempotent — safe to re-run.

```bash
hse provision
```

Steps:
1. Creates `$HOME/.huntsman/` directory if missing.
2. Initializes SQLite database at `$HOME/.huntsman/huntsman.db`.
3. Creates API key template at `$HOME/.huntsman.env` with commented-out
   key placeholders for all key-gated modules.
4. Checks Termux environment (termux-api package, storage permissions).
5. Reports any issues found.

---

## `hse set-key` (v0.9+)

Set an API key in the `$HOME/.huntsman.env` file:

```bash
hse set-key HUNTSMAN_SHODAN_KEY abc123def456
hse set-key HUNTSMAN_HIBP_KEY your-hibp-key-here
```

Keys are stored one-per-line in `KEY=VALUE` format. The file is
never logged or transmitted. Modules read keys at scan time via
`ModuleContext::key()`.

Available key names:
- `HUNTSMAN_SHODAN_KEY` — Shodan premium API
- `HUNTSMAN_HIBP_KEY` — Have I Been Pwned ($3.50/mo)
- `HUNTSMAN_DEHASHED_USER` / `HUNTSMAN_DEHASHED_KEY` — DeHashed
- `HUNTSMAN_INTELX_KEY` — Intelligence X
- `HUNTSMAN_WIGLE_USER` / `HUNTSMAN_WIGLE_TOKEN` — WiGLE WiFi
- `HUNTSMAN_IPQS_KEY` — IPQualityScore
- `HUNTSMAN_OATHNET_KEY` — OathNet Pro
- `HUNTSMAN_SECURITYTRAILS_KEY` — SecurityTrails
- `HUNTSMAN_ABUSEIPDB_KEY` — AbuseIPDB
- `HUNTSMAN_GREYNOISE_KEY` — GreyNoise (optional)
- `HUNTSMAN_FULLHUNT_KEY` — FullHunt
- `HUNTSMAN_THREATFOX_KEY` — ThreatFox
- `HUNTSMAN_EMAILREP_KEY` — EmailRep.io (optional)
- `HUNTSMAN_IPINFO_KEY` — ipinfo.io (optional)
- `HUNTSMAN_IP2LOCATION_KEY` — ip2location.io (optional)
- `HUNTSMAN_CRIMINAL_IP_KEY` — Criminal IP
- `HUNTSMAN_LEAKIX_KEY` — LeakIX
- `HUNTSMAN_NUMVERIFY_KEY` — Numverify

---

## `hse doctor`

Verifies the environment. Run after install and after any system change:

```
HSE v0.10.0 — doctor

Termux:    detected
DB path:   /data/data/com.termux/files/home/.huntsman/huntsman.db
Keys path: /data/data/com.termux/files/home/.huntsman.env

Storage:
  ok — database opens cleanly

Modules (50 registered):
  free       33
  key_gated  13
  paid        4

HUNTSMAN_* keys loaded: 2
  HUNTSMAN_SHODAN_KEY: set
  HUNTSMAN_WIGLE_TOKEN: set
```

---

## Environment variables read by HSE

| Variable | Purpose |
|----------|---------|
| `HOME` | Resolves DB path and keys path (Termux: `/data/data/com.termux/files/home`) |
| `RUST_LOG` | Standard `tracing_subscriber` filter, e.g. `RUST_LOG=debug` or `RUST_LOG=huntsman_search_engine::modules=trace` |
| `TERMUX_VERSION` | Set by Termux; used for `is_termux()` detection |
| `HUNTSMAN_*` | Per-module API keys (loaded from `$HOME/.huntsman.env`); never logged |

---

## Verbose / debug logging

```bash
RUST_LOG=debug hse scan --kind domain --value example.com
RUST_LOG=huntsman_search_engine=trace hse scan ...           # everything HSE emits
RUST_LOG=huntsman_search_engine::modules::crtsh=trace hse ... # single-module trace
```

Trace output is human-readable structured logging, suitable for `grep`/`jq`
when combined with `--output json`.
