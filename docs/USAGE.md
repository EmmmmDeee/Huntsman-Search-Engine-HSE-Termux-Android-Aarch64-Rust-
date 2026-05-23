# Usage

Complete CLI reference for `hse`. All commands are non-interactive and
suitable for scripting.

## Subcommands

```
hse scan      Run a single scan, print results
hse modules   List registered modules with cost / target / passive flags
hse doctor    Verify environment (DB, keys, Termux, modules)
hse --help    Top-level help
hse --version Print version
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

---

## Verbose / debug logging

```bash
RUST_LOG=debug hse scan --kind domain --value example.com
RUST_LOG=huntsman_search_engine=trace hse scan ...           # everything HSE emits
RUST_LOG=huntsman_search_engine::modules::crtsh=trace hse ... # single-module trace
```

Trace output is human-readable structured logging, suitable for `grep`/`jq`
when combined with `--output json`.
