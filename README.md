# Huntsman Search Engine (HSE)

Prototype pure-Rust OSINT/GEOINT scaffold designed to run inside Termux on
Android aarch64 with no root, viewed through any web browser on the device
(planned for v0.2+).

**Status: v0.1.0 prototype.** Foundation only — CLI, storage, engine, five
free modules. No HTTP server, no SPA, no live mode yet. See `CLAUDE.md` for
the long-term design north star.

## Roadmap

| Tag | Scope |
|---|---|
| **v0.1.0** | core + 5 free modules + CLI |
| v0.2.0 | axum HTTP server + minimal SPA + SSE |
| v0.3.0 | per-scan customisation in the UI (module selection, throttle, depth) |
| v0.4.0 | correlator + more breach/identity modules |
| v0.5.0 | `live` mode (re-poll + recursive expansion) |
| v0.6.0 | Termux sensor modules (arp/wifi/gps/cell) |
| v0.7.0+ | batch, paid modules, debug harness |

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

# Verify environment:
hse doctor
```

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
