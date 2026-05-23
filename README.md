# Huntsman Search Engine (HSE)

Prototype pure-Rust OSINT/GEOINT scaffold designed to run inside Termux on
Android aarch64 with no root, viewed through any web browser on the device
(planned for v0.2+).

**Status: v0.2.0 prototype.** Foundation + autonomous expansion engine.
Five free modules now act like a tightly-integrated suite via depth-bounded
auto-chaining. No HTTP server / SPA yet (next). See `CLAUDE.md` for the
long-term design north star.

## Roadmap

| Tag | Scope |
|---|---|
| v0.1.0 | core + 5 free modules + CLI |
| **v0.2.0** | autonomous expansion engine (auto-chain modules, depth + budgets) |
| v0.3.0 | axum HTTP server + minimal SPA + SSE |
| v0.4.0 | correlator + more breach/identity modules |
| v0.5.0 | `live` mode (re-poll on interval + sensor modules) |
| v0.6.0 | Termux sensor modules (arp/wifi/gps/cell) |
| v0.7.0+ | batch, paid modules, debug harness, junction table for multi-scan entity tracking |

## Build (Termux aarch64)

```bash
pkg install rust git
git clone <this repo>
cd Huntsman-Search-Engine-HSE-Termux-Android-Aarch64-Rust-
cargo build --release
./target/release/hse doctor
```

Builds without root, without openssl, without native TLS — only rustls and
bundled SQLite. Default storage path is `$HOME/.huntsman/huntsman.db`.

## Usage

```bash
# List registered modules with cost tier and accepted target kinds:
hse modules

# Run a fully-customised scan:
hse scan --kind domain --value example.com
hse scan --kind email  --value foo@bar.com --modules hudsonrock,email_to_username
hse scan --kind domain --value example.com --throttle 200 --free-only --output json

# Autonomous expansion — engine auto-feeds discovered entities as new targets
# (depth=2 means up to 2 rounds of follow-on scans).
# Defaults are conservative: only entities with c_eff ≥ 0.75 (Verified) expand.
hse scan --kind domain --value example.com --depth 2

# Loosen the expansion threshold and add budgets:
hse scan --kind domain --value example.com \
  --depth 3 --min-expand-confidence 0.5 \
  --max-entities 500 --max-wall-time 60

# Verify environment:
hse doctor
```

## Autonomous expansion (v0.2+)

A single scan can run multiple rounds of dispatch without manual chaining.
Each round picks high-confidence entities discovered so far, converts them
to new scan targets via `TargetKind::from_entity_kind`, and runs every
accepting module on each one. This makes the 5 modules synergistic:

```
hse scan --kind domain --value example.com --depth 2
└─ Round 0 (seed):  example.com
   ├─ crtsh         → 50 subdomain entities
   └─ dns_resolver  → A / MX / TXT records
└─ Round 1: each high-confidence subdomain becomes a new Domain target
   ├─ crtsh         → more subdomains (skipped if already visited)
   └─ dns_resolver  → IPs discovered
└─ Round 2: each high-confidence IP becomes a new IpAddress target
   └─ ip_geo        → coordinates + ASN / org
```

The engine guarantees termination:
- **Visited set** — `(target_kind, normalised_value)` pairs are never scanned twice in one scan.
- **`--min-expand-confidence`** — default `0.75` (Verified tier). Low-confidence findings don't trigger more scanning.
- **`--max-entities`** — hard cap on total entities collected.
- **`--max-wall-time`** — hard cap on total scan seconds.
- **`--depth`** — hard cap on rounds.

Combine these with `--free-only`, `--passive-only`, `--modules`, or
`--exclude` for full control. Every knob is a `ScanOptions` field
serialisable to JSON, so the future SPA can render exactly the same
controls as the CLI flags.

### Available v0.1.0 modules (all free, no keys required)

| Module | Targets | What it does |
|---|---|---|
| `hudsonrock` | email, domain | Public stealer-log lookup (Cavalier API). Aggregate metadata only — credentials never stored |
| `crtsh` | domain | Certificate-transparency subdomain enumeration |
| `dns_resolver` | domain | Cloudflare DNS: A, MX, TXT records |
| `ip_geo` | ip | ip-api.com free-tier geolocation + ASN/org |
| `email_to_username` | email | Local derivation of plausible usernames (no network) |

## API keys (optional, for future modules)

Keys live in `$HOME/.huntsman.env` (0600). Variables must be prefixed
`HUNTSMAN_`. v0.1.0 modules don't require any.

## Architecture invariants

These are enforced and must not be relaxed:

- `#![forbid(unsafe_code)]`
- No native-TLS, no openssl, no C-linked deps (rustls + bundled-sqlite only)
- GREATEST-semantics entity merge (confidence/corroboration only ever increase)
- SHA-256 deterministic entity UIDs
- `C_eff = clamp(confidence × (1 + 0.15 × ln(corroboration)), 0.0, 1.0)`
- Classification is derived, never stored
- Passwords / credentials never appear in evidence

## Modularity

Adding a new module is a one-file change:

1. Create `src/modules/foo.rs` implementing `Module`.
2. `pub mod foo;` in `src/modules/mod.rs`.
3. Push `Arc::new(foo::Foo)` into `registry()`.

Nothing else needs to know about the new module. The engine never imports
from `modules/`.

## Customisability

Every scan accepts `ScanOptions` — allowlist/denylist of modules, throttle,
per-module timeout, min-confidence filter, free-only / passive-only toggles,
recursion depth (for future live mode). The CLI surfaces all of these as
flags; the SPA (v0.2+) will render them as form controls before each scan.

## Licence

MIT OR Apache-2.0.
