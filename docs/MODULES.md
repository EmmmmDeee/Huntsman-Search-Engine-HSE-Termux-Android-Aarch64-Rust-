# Modules

A **module** is a self-contained collector that takes one `Target`, hits a
data source (or runs a local computation), and emits zero-or-more `Entity`
records. The engine knows nothing else — every module is a one-file change.

## Catalogue (v0.2)

| Module | Targets | Cost | Passive | Priority | Output kinds |
|--------|---------|------|---------|----------|--------------|
| [`hudsonrock`](#hudsonrock)                 | `email`, `domain`     | free       | no  | 130 | Email / Domain (with stealer-log evidence) |
| [`email_to_username`](#email_to_username)   | `email`               | free       | **yes** | 95  | Username × N candidates |
| [`crtsh`](#crtsh)                           | `domain`              | free       | no  | 35  | Domain (subdomains) |
| [`dns_resolver`](#dns_resolver)             | `domain`              | free       | no  | 30  | IpAddress (A), Domain (MX), Domain (TXT) |
| [`ip_geo`](#ip_geo)                         | `ip`                  | free       | no  | 28  | Coordinates, Organisation |

All v0.2 modules are **free** (no API key required). They were picked
specifically for synergy under the v0.2+ autonomous-expansion engine.

---

## Synergy map

The expansion engine chains modules by producing entities whose `EntityKind`
maps to a `TargetKind` other modules accept. With **`hse scan --depth 2`**
the following chains emerge automatically from the 5 modules above:

```
Seed: Email (foo@example.com)
├─ hudsonrock       → Email (with breach evidence — same as input)
└─ email_to_username → Username × N
   └─ (no v0.2 module accepts Username yet — chain ends here)

Seed: Domain (example.com)
├─ hudsonrock      → Domain (with breach evidence)
├─ crtsh           → Domain × N subdomains  ↘
│                                            ↓ depth=2 round
└─ dns_resolver    → IpAddress, Domain (MX) — re-feed via expansion
   └─ per subdomain (depth=1): dns_resolver, hudsonrock, crtsh
      └─ per discovered IP (depth=2): ip_geo → Coordinates, Organisation
```

`min_expand_confidence` (default 0.75) prevents low-confidence speculative
expansions from runaway. Adjust as needed via `--min-expand-confidence`.

---

## Modules in detail

### `hudsonrock`

Public stealer-log lookup. Free, no key. Source: HudsonRock Cavalier API
(`cavalier.hudsonrock.com/api/json/v2/osint-tools/...`).

**Targets accepted**: `email`, `domain`.

**Returns**: the input as an `Email` or `Domain` entity, tagged
`breach` + `stealer-log`, with one evidence record per affected machine
containing aggregate metadata only:

- `computer_name`
- `operating_system`
- `date_compromised`
- `malware_path`
- `credential_count` (integer count — **no credentials themselves**)

**Security**: credential field arrays are read for counting purposes only;
their contents are never persisted. This is enforced by the module's
`Deserialize` only pulling `serde_json::Value` and immediately discarding it.

**Quirks**: returns HTTP 404 for unknown targets — handled as "no hits"
rather than an error.

### `email_to_username`

Pure local derivation. **No network**. Marked `is_passive() == true`.

**Targets accepted**: `email`.

**Algorithm**: from the email local part it produces these `Username`
candidates (deduplicated, each `length > 2`):

1. The full local part (`john.doe+work`).
2. Local part with `+tag` suffix stripped (`john.doe`).
3. De-tagged local with trailing digits stripped (`john.doe` → `john.doe`,
   `joe42` → `joe`).
4. De-tagged local with separators collapsed (`john.doe` → `johndoe`).
5. Each token from splitting on `.`, `_`, `-` (`john`, `doe`).

Confidence: 0.45 (Probable) — low enough that, with the default
`min_expand_confidence = 0.75`, derived usernames do NOT auto-trigger
further scans. Pass `--min-expand-confidence 0.4` to opt into chaining.

### `crtsh`

Certificate-transparency subdomain enumeration. Free, no key. Source:
`crt.sh?q=%.<domain>&output=json`.

**Targets accepted**: `domain`.

**Returns**: one `Domain` entity per unique subdomain found (excluding the
parent), confidence 0.88, tagged `ct-log`. Evidence records the issuer
name and not-before timestamp.

**Quirks**: `crt.sh` occasionally returns truncated JSON when the result
set is huge — modules that fail this way return a `module error` event
rather than crashing the scan.

### `dns_resolver`

Cloudflare DNS resolver (`hickory-resolver` 0.24 with `cloudflare()`
config). Free, no key.

**Targets accepted**: `domain`.

**Returns**:
- One `IpAddress` entity per A record (confidence 0.95).
- One `Domain` entity per MX record exchange (confidence 0.85, tagged `mx`).
- One enriched `Domain` entity for the parent if any TXT records exist
  (confidence 0.90, with `txt_records` evidence attribute joining them with
  ` | `).

**Quirks**: errors from any individual record type (A / MX / TXT) are
silently swallowed inside the module — partial results are still returned.

### `ip_geo`

ip-api.com IP geolocation. Free tier, **HTTP only** (HTTPS requires paid plan).

**Targets accepted**: `ip`.

**Returns**:
- One `Coordinates` entity (`lat,lon` with 6-dp precision) if lat/lon present,
  tagged `geoint`, confidence 0.70. Evidence captures country, region, city.
- One `Organisation` entity from the `org` field if present, confidence 0.65.
  Evidence carries the ASN.

**Quirks**: ip-api free tier is rate-limited to 45 req/min from a single IP.
For bulk use, throttle with `--throttle 1400` (≈ 43 req/min). Failures
return an empty `ModuleResult` rather than an error.

---

## Adding a module

The full walkthrough is in [`CONTRIBUTING.md`](../CONTRIBUTING.md#adding-a-new-module).
TL;DR — three changes, all in one PR:

1. `src/modules/your_module.rs` — implement `Module`.
2. `src/modules/mod.rs` — `pub mod your_module;` + push `Arc::new(your_module::YourModule)` into `registry()`.
3. `docs/MODULES.md` — add a row to the catalogue and a section explaining
   what it returns and its quirks.

### Module-author checklist

Before opening the PR, confirm:

- [ ] `name()` is `snake_case` and unique
- [ ] `priority()` slots sensibly into the existing ordering
- [ ] `cost()` is correctly `Free` / `KeyGated` / `Paid`
- [ ] `is_passive()` returns `true` only for genuinely zero-network modules
- [ ] `accepts()` covers every `TargetKind` the module can handle and only those
- [ ] If key-gated: uses `ctx.key("HUNTSMAN_FOO_KEY")?` (returns `Error::MissingKey`,
  which the engine handles as a logged skip rather than scan failure)
- [ ] All errors go through `Error::module("module_name", "message")`
- [ ] Passwords / credentials are never written to evidence — even if the
  upstream API returns them (see `hudsonrock` for the pattern)
- [ ] At least one unit test (the `accepts()` test is the minimum)
- [ ] Module survives upstream API outage: 4xx / 5xx / malformed JSON /
  timeout are handled without panicking
