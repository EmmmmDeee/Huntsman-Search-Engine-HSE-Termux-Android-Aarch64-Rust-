# Usage

Complete CLI reference for `hse`. All commands are non-interactive and
suitable for scripting.

## Subcommands

```
hse scan      Run a single scan, print results
hse live      Re-run a scan periodically (v0.5+)
hse diff      Compare two scans: entities added / removed / re-scored
hse modules   List registered modules with cost / target / passive flags
hse engines   Liveness panel: probe each free search engine (up/blocked/down)
hse config    View/set persistent capability toggles (e.g. engine.google off)
hse doctor    Verify environment (DB, keys, Termux, modules)
hse serve     Start the HTTP server + SPA (browse to http://127.0.0.1:8080)
hse --help    Top-level help
hse --version Print version
```

---

## `hse scan` — full reference

```
hse scan [OPTIONS] --value <VALUE>          # unified scan: kind auto-detected
hse scan [OPTIONS] --kind <KIND> --value <VALUE>
```

### Required

| Flag | Description |
|------|-------------|
| `-v, --value <VALUE>` | Target value (e.g. `example.com`, `foo@bar.com`) |

### Target kind

| Flag | Description |
|------|-------------|
| `-k, --kind <KIND>`   | Target type: `email`, `username`, `phone`, `name`, `ip`, `domain`, `url`, `asn`, `coords`, `address`, `org`, `abn`, `mac`, `apikey`. **Optional** — omit it (or pass `auto`) and HSE infers the kind from the value's shape (the unified scan), printing the detected kind to stderr. An explicit `--kind` always wins; pass it to force a kind the detector wouldn't pick (e.g. `apikey`, or `username` for a dotted handle). |

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
| `-t, --throttle <MS>`  | Sleep this long between module dispatches (default 250 — paces dispatch to avoid flooding/rate limits; `0` = burst) |
| `--timeout <MS>`       | Per-module timeout override (default 3000) |
| `--max-concurrent <N>` | Modules to run in parallel per round (default 2 — gentle; raise when the network can take it, `0` = fully sequential). |

### Filtering output

| Flag | Description |
|------|-------------|
| `--min-confidence <F>` | Drop entities whose base `confidence` is below this |

### Autonomous expansion (v0.2+)

| Flag | Default | Description |
|------|---------|-------------|
| `-d, --depth <N>`             | `2`    | Rounds of recursive expansion. Omit to use the product default (2); `0` = single-round scan (v0.1 behaviour). `--auto`/`--recursive` override an omitted value. |
| `--min-expand-confidence <F>` | `0.75` | Only expand entities whose `c_effective()` is ≥ this. Default is the Verified tier — strong filter. |
| `--max-entities <N>`          | none   | Stop expansion when entity count reaches this. |
| `--max-wall-time <SECS>`      | none   | Stop expansion when wall-time exceeds this. |

### Output

| Flag | Description |
|------|-------------|
| `-o, --output <table\|json>` | `table` (human) or `json` (full scan + entities) |

### Example invocations

```bash
# Unified scan — no --kind; HSE detects the type from the value
hse scan -v example.com              # → domain
hse scan -v alice@example.com        # → email
hse scan -v 8.8.8.8                  # → ip_address
hse scan -v "Matthew Diegmann"       # → full_name
hse scan -v AS13335                  # → asn

# Plain single-shot scan against a domain (explicit kind)
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

## `hse engines`

Liveness panel — probes every keyless search engine concurrently and reports
whether each is `Up`, `Blocked` (reachable but rate-limited/CAPTCHA), or `Down`.
An engine turned off with `hse config engine.<name> off` is **not** probed and is
listed as `disabled` (so the roster — and the summary tally `up + blocked + down
+ disabled = total` — stays complete and re-enablable). Add `--json` for machine
output (disabled engines appear with `"enabled": false` and null latency/results).
The same data is served live at `GET /api/v1/engines/health` and in the web SPA
(`#/engines`, which also offers an inline Enable/Disable per engine); `hse serve`
runs a startup sweep plus a periodic background refresh, and every probe is
written to the structured debug log (`huntsman::engine_health`).

```
hse engines            # table (incl. disabled engines)
hse engines --json     # JSON roster
```

---

## `hse config`

View and set **persistent capability toggles** (SpiderFoot-style on/off
switches). Changes are written to `~/.huntsman/settings.json` and take effect on
the next command — no rebuild. Only overrides are stored, so any toggle you never
touch keeps its built-in default.

```
hse config                          # list every known toggle and its state
hse config engine.yandex off        # stop querying one search engine
hse config module.wikidata off      # disable a module across ALL scans
hse config module.wikidata on       # re-enable it
hse config module.wikidata          # show one toggle's current state
```

Toggle keys:

- `feature.<name>` — a capability switch that isn't a single engine or module.
  The first is `feature.regional` (default **off**): the standing default for
  autonomous region-scoped search. Regional augmentation applies when **either**
  `feature.regional` is on **or** the per-scan `--regional` flag is passed, so
  `hse config feature.regional on` makes regional the baseline for every scan
  while `--regional` still forces it on for a one-off run.
- `engine.<name>` — a single search engine (names from `hse engines`). Honoured
  by the search dispatch, the priority waterfall, and the liveness probe.
- `module.<name>` — any registered module (names from `hse modules`). A disabled
  module is skipped at the scan gate (reason `disabled in config`) and never
  reaches the network; it shows up in the scan summary's `skipped` count.

`engine.*` and `module.*` keys default to **on**; a `feature.*` key uses its
documented default (e.g. `feature.regional` is off). An unset key — or a
brand-new toggle added in a later release — resolves to that default, so old
settings files stay forward-compatible.

The same toggles are manageable from the web dashboard's **Settings** page as a
click-to-flip grid (backed by `GET`/`PUT /api/v1/settings/toggles`, loopback-only).

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
| `--no-key-write`         | (writes **on**) | Disables the Settings page's key-write endpoint (`PUT /settings/keys`). Key editing is enabled by default; the endpoint *always* additionally requires a loopback peer, so a network-exposed bind still cannot write keys. Pass this to lock writes down for shared/hardened deployments. |

Graceful shutdown on `Ctrl-C` / `SIGTERM`.

### API endpoints

All endpoints are under `/api/v1/`.

| Method | Path                       | Notes |
|--------|----------------------------|-------|
| GET    | `/health`                  | `{ "status": "ok", "version": "0.3.0" }` |
| GET    | `/version`                 | `{ "version": "0.3.0" }` |
| GET    | `/modules`                 | `{ "count": N, "modules": [{ name, priority, cost, passive }, ...] }` |
| GET    | `/keys/status`             | `{ count, services: [{ service, total, active, rate_limited, exhausted, invalid, untested, uses, errors }, ...] }` — key-pool quota health, **never key values**. |
| GET    | `/settings/keys`           | `{ keys: [{ name, set }], count, write_enabled, env_path }` — which `HUNTSMAN_*` keys are configured, **never their values**. Drives the Settings page. |
| PUT    | `/settings/keys`           | Body `{ updates: { "HUNTSMAN_X": "val", ... }, deletes: ["HUNTSMAN_Y", ...] }`. Atomically writes `~/.huntsman.env` (preserves comments). **Loopback-only**, enabled by default (`--no-key-write` to disable). Powers "paste & save a key" in the UI. |
| GET    | `/settings/toggles`        | `{ count, groups: [{ group, label, toggles: [{ key, name, enabled }] }] }` — the full capability catalogue (every engine + module) with live on/off state. Drives the Settings page's toggle grid. |
| PUT    | `/settings/toggles`        | Body `{ key, enabled }` (e.g. `{ "key": "module.wikidata", "enabled": false }`). Persists one toggle to `~/.huntsman/settings.json`. **Loopback-only**, bounded to known `engine.*`/`module.*` keys (unknown → 400). No `--allow-key-write` needed (no secret). |
| POST   | `/scans`                   | Body: `ScanRequest` (`{ kind?, value, options? }`). Returns `202 { scan_id, status }`. **`kind` is optional** — omit it and the server auto-detects the target type from `value` (the unified scan). |
| GET    | `/scans`                   | 200 most recent scans. |
| GET    | `/scans/{id}`              | Single scan record. 404 if unknown. |
| GET    | `/scans/{id}/entities`     | `{ count, entities: [Entity, ...] }`. |
| GET    | `/scans/{a}/diff/{b}`      | `ScanDiff` of scan `a` vs `b`: `{ added, removed, common, confidence_shifts }`. 404 if either unknown. The HTTP surface of `hse diff`. |
| GET    | `/scans/{id}/correlations` | `{ count, correlations: [Correlation, ...] }` (v0.4+). |
| GET    | `/scans/{id}/events`       | **SSE** — `text/event-stream` of `EventKind` JSON payloads. |
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

# Unified scan — omit "kind" and the server detects it from "value":
curl -X POST -H 'Content-Type: application/json' \
  -d '{"value":"alice@example.com"}' \
  http://127.0.0.1:8080/api/v1/scans
# → {"scan_id":"def...","status":"queued"}   (detected kind: email)

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
hse live --value <VALUE>                    # kind auto-detected
hse live --kind <KIND> --value <VALUE>
         [--interval <SECS>] [--iterations <N>]
         [--depth <N>] [--modules <CSV>]
         [--free-only] [--passive-only]
```

`--kind` is optional here too — omit it (or pass `auto`) to infer the
target type from the value, exactly like `hse scan`.

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

## `hse diff`

Compare two scans' entity graphs and report what each found that the other
didn't, what they share, and which common entities were re-scored.

```bash
hse diff <FROM> <TO> [--format text|json]
```

Each of `<FROM>` / `<TO>` is either a **scan id** in the store (or `latest`
for the most-recent completed scan) or a path to a **JSON entity snapshot**
written by `hse export --format json`. Entities are matched by their
deterministic uid (`SHA-256(kind:value)`).

Two workflows:

```bash
# Link analysis — what two targets share (their common infrastructure /
# identity surface) and where they diverge:
hse scan --kind domain --value a.example --output json > /dev/null   # id A
hse scan --kind domain --value b.example --output json > /dev/null   # id B
hse diff <A> <B>

# Time-series monitoring — a scan id is the deterministic SHA-256(kind:value),
# so re-scanning a target overwrites its row. Snapshot first, re-scan later,
# then diff against the snapshot file:
hse scan --kind domain --value target.example --output json \
  | jq .entities > before.json
# ... time passes; re-scan the same target ...
hse scan --kind domain --value target.example >/dev/null
hse diff before.json latest
```

`text` (default) prints a `+added / -removed / ~re-scored` summary and lists;
`json` emits `{ added, removed, common, confidence_shifts }` for tooling.

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

---

## Environment variables read by HSE

| Variable | Purpose |
|----------|---------|
| `HOME` | Resolves DB path and keys path (Termux: `/data/data/com.termux/files/home`) |
| `RUST_LOG` | Standard `tracing_subscriber` filter, e.g. `RUST_LOG=debug` or `RUST_LOG=huntsman_search_engine::modules=trace` |
| `TERMUX_VERSION` | Set by Termux; used for `is_termux()` detection |
| `HUNTSMAN_*` | Per-module API keys (loaded from `$HOME/.huntsman.env`); never logged |
| `HUNTSMAN_SEARCH_PROXY` | Proxy (or **comma-separated list**, rotated round-robin) for `curl`-based fetches, e.g. `socks5://127.0.0.1:9050,http://host:3128`. Listed hosts are auto-excluded from being scanned. |
| `HUNTSMAN_DNS_RESOLVERS` | Rotate HTTP-client DNS across public resolvers — any of `cloudflare,google,quad9`. Falls back to the system resolver on error; listed resolvers are auto-excluded from being scanned. |

---

## Verbose / debug logging

```bash
RUST_LOG=debug hse scan --kind domain --value example.com
RUST_LOG=huntsman_search_engine=trace hse scan ...           # everything HSE emits
RUST_LOG=huntsman_search_engine::modules::crtsh=trace hse ... # single-module trace
```

Trace output is human-readable structured logging, suitable for `grep`/`jq`
when combined with `--output json`.
