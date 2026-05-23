# Huntsman Search Engine (HSE)

[![CI](https://github.com/EmmmmDeee/Huntsman-Search-Engine-HSE-Termux-Android-Aarch64-Rust-/actions/workflows/ci.yml/badge.svg)](https://github.com/EmmmmDeee/Huntsman-Search-Engine-HSE-Termux-Android-Aarch64-Rust-/actions/workflows/ci.yml)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#licence)
[![Rust 1.85+](https://img.shields.io/badge/rust-1.85%2B-orange.svg)](https://www.rust-lang.org)
[![Edition 2024](https://img.shields.io/badge/edition-2024-orange.svg)](https://doc.rust-lang.org/edition-guide/rust-2024/)
[![Termux aarch64](https://img.shields.io/badge/Termux-aarch64-darkgreen.svg)](https://termux.dev/)
[![Status: prototype](https://img.shields.io/badge/status-prototype%20(0.2.x)-yellow.svg)](docs/ROADMAP.md)

Pure-Rust OSINT / GEOINT scaffold that runs **entirely inside Termux on
Android aarch64** with no root, and is operable through any local browser
on the device (Chrome / Firefox, Web UI from v0.3).

Designed around three principles:

1. **Synergy over feature accretion.** A small set of free, key-less
   sources, automatically chained via depth-bounded expansion, produces
   more useful intelligence than a large catalogue of disconnected modules.
2. **Intelligent autonomy without LLMs.** All "smart" behaviour is
   deterministic — confidence thresholds, depth caps, visited sets,
   wall-time budgets. No models, no heuristics that need tuning.
3. **One-file modularity.** Adding a data source is a single new file
   plus two-line registry change. The engine never imports a specific
   module by name.

---

## Install (one command)

```bash
curl -fsSL https://raw.githubusercontent.com/EmmmmDeee/Huntsman-Search-Engine-HSE-Termux-Android-Aarch64-Rust-/main/install.sh | bash
```

Works on Termux (aarch64), Debian/Ubuntu, and macOS. The installer:

- detects the platform (Termux / Linux / macOS)
- installs build deps (`rust`, `git`, `clang`, `make`, `pkg-config`)
- sanity-checks clock / disk / RAM and applies workarounds (e.g. `CARGO_BUILD_JOBS=1` on low-RAM devices)
- retries `pkg update`, `pkg install`, and `cargo build` on transient network failure
- clones / updates to `$HOME/.local/share/hse`
- installs the binary to `$PREFIX/bin/hse` (or `$HOME/.local/bin/hse`)
- creates a chmod-0600 keys template at `$HOME/.huntsman.env`
- runs `hse doctor` to verify
- logs everything to `$HOME/.cache/hse-install.log`

For manual installation, tuning knobs, and uninstall steps, see
[`docs/INSTALL.md`](docs/INSTALL.md).

---

## Quick start

```bash
hse doctor                                                  # verify environment
hse modules                                                 # list registered modules
hse scan --kind domain --value example.com                  # single-round scan
hse scan --kind domain --value example.com --depth 2        # autonomous expansion
hse scan --kind email  --value foo@bar.com --free-only      # no key-gated modules
hse scan --kind domain --value example.com --output json    # machine-readable
```

Five free modules (no API keys required) ship in v0.2:
`hudsonrock`, `crtsh`, `dns_resolver`, `ip_geo`, `email_to_username`.
See [`docs/MODULES.md`](docs/MODULES.md) for the full catalogue and the
synergy map that makes them chain automatically.

---

## Autonomous expansion (v0.2+)

One `hse scan` invocation can dispatch modules across **multiple bounded
rounds**, feeding each round's high-confidence entities into the next as
fresh scan targets:

```
hse scan --kind domain --value example.com --depth 2
└─ Round 0 (seed):  example.com
   ├─ crtsh         → ~50 subdomain entities
   └─ dns_resolver  → A / MX / TXT records
└─ Round 1: each high-confidence subdomain → new Domain target
   ├─ crtsh         → more subdomains (visited set skips dupes)
   └─ dns_resolver  → IPs discovered
└─ Round 2: each high-confidence IP → new IpAddress target
   └─ ip_geo        → coordinates + ASN / org
```

Every expansion is bounded by deterministic guards:

| Knob | Default | Purpose |
|------|---------|---------|
| `--depth N`                  | `0`    | Hard cap on expansion rounds |
| `--min-expand-confidence F`  | `0.75` | Only Verified-tier entities trigger more scans |
| `--max-entities N`           | none   | Stop when total entities reach N |
| `--max-wall-time SECS`       | none   | Stop when wall-time exceeds SECS |
| (visited set)                | n/a    | Same target never scanned twice in one scan |

Combine with `--modules`, `--exclude`, `--free-only`, `--passive-only`,
`--throttle`, `--timeout`, `--min-confidence` for full pre-scan customisation.
Every knob is a `ScanOptions` field, serialisable to JSON — the future SPA
renders the same controls as the CLI flags.

---

## Architecture invariants

These are enforced and reviewed on every PR
([`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) has the full list and
rationale):

- `#![forbid(unsafe_code)]`
- rustls + bundled-sqlite only (no openssl, no native TLS, no C-linked deps)
- GREATEST-semantics entity merge (confidence and corroboration only ever increase)
- SHA-256 deterministic entity UIDs
- `C_eff = clamp(C × (1 + 0.15 × ln(corroboration)), 0, 1)`
- Classification is derived, never stored
- Passwords / hashes / credentials never appear in evidence

---

## Status

**v0.2.0 — prototype.** 4.3 MB stripped binary, 38 tests, zero unsafe.
Foundation + autonomous expansion engine + five free modules + CLI.

Coming next: HTTP server + browser SPA (v0.3), correlator + more modules
(v0.4), live re-poll mode (v0.5), Termux sensors (v0.6). Full plan in
[`docs/ROADMAP.md`](docs/ROADMAP.md).

---

## Documentation

| Document | What it covers |
|----------|----------------|
| [`docs/INSTALL.md`](docs/INSTALL.md)         | Every install path + every Termux quirk |
| [`docs/USAGE.md`](docs/USAGE.md)             | Full CLI reference + JSON schema |
| [`docs/MODULES.md`](docs/MODULES.md)         | Module catalogue, synergy map, author checklist |
| [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) | Design, invariants, data flow, engine internals |
| [`docs/TROUBLESHOOTING.md`](docs/TROUBLESHOOTING.md) | Common errors and their fixes |
| [`docs/ROADMAP.md`](docs/ROADMAP.md)         | Version-by-version plan and non-goals |
| [`docs/DESIGN.md`](docs/DESIGN.md)           | Long-term design north-star (large features not yet built) |
| [`CHANGELOG.md`](CHANGELOG.md)               | Versioned change log (Keep a Changelog format) |
| [`SECURITY.md`](SECURITY.md)                 | Security model + responsible disclosure |
| [`CONTRIBUTING.md`](CONTRIBUTING.md)         | How to add a module + code style + PR workflow |

---

## Licence

Dual-licensed under either:

- [MIT licence](LICENSE-MIT)
- [Apache Licence, Version 2.0](LICENSE-APACHE)

at your option.

Unless you explicitly state otherwise, any contribution intentionally
submitted for inclusion in HSE by you, as defined in the Apache-2.0
licence, shall be dual-licensed as above, without any additional terms
or conditions.
