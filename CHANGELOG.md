# Changelog

All notable changes to this project are documented in this file.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
project versioning follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

While the project is `0.x`, the public API may change at any point — minor
versions can include breaking changes; patch versions are bug-fix-only.

## [Unreleased]

### Added
- Single-shot installer script (`install.sh`) with full Termux aarch64
  support, dependency installation, retry-with-backoff, clock / disk /
  RAM sanity checks, idempotent re-install, and post-install verification.
- GitHub Actions CI: `cargo fmt`, `cargo check`, `cargo clippy -D warnings`,
  `cargo test`, MSRV check (1.85), and `install.sh` shellcheck.
- Issue templates (bug report, feature request) and PR template enforcing
  the architecture invariants.
- Dual MIT / Apache-2.0 license files (Rust ecosystem standard).
- Documentation tree under `docs/`:
  - `INSTALL.md` — every install path + every known Termux quirk.
  - `USAGE.md` — full CLI reference with examples.
  - `MODULES.md` — module catalogue with cost / target / synergy notes.
  - `ARCHITECTURE.md` — design decisions and invariants.
  - `TROUBLESHOOTING.md` — Termux-specific failure modes and workarounds.
  - `ROADMAP.md` — version-by-version delivery plan.
  - `DESIGN.md` — long-term north-star spec (moved from `CLAUDE.md`).
- `SECURITY.md` (security model + responsible disclosure).
- `CONTRIBUTING.md` (how to add a module, code style, commit format).
- `CODE_OF_CONDUCT.md` (Contributor Covenant 2.1).

### Changed
- `CLAUDE.md` (5,099-line design north-star) moved to `docs/DESIGN.md`.
- `README.md` rewritten to industry-standard format with badges, short
  quick-start, and links into `docs/`.

## [0.2.0] — 2026-05-23

### Added
- **Autonomous expansion engine** (`ScanEngine::run_expansion`). When
  `ScanOptions::depth > 0`, each round picks high-confidence entities
  produced so far, converts them to scan targets via
  `TargetKind::from_entity_kind`, and re-dispatches every accepting module.
  Five free modules now chain automatically into a domain → subdomain →
  IP → geo enumeration without manual command stitching.
- `TargetKind::from_entity_kind()` / `to_entity_kind()` — bidirectional
  mapper with explicit unscannable kinds (Organisation, MacAddress,
  Credential, Password, …).
- `ScanOptions` fields: `min_expand_confidence` (default 0.75 = Verified
  tier), `max_entities`, `max_wall_time_secs`. All serde-defaulted.
- `EventKind::ExpansionTick { depth, queued, visited }` and
  `EventKind::ExpansionStop { reason }` for observers.
- CLI flags on `hse scan`: `--depth`, `--min-expand-confidence`,
  `--max-entities`, `--max-wall-time`.
- Five new integration tests covering expansion depth, threshold filtering,
  budget enforcement, cycle detection.

### Fixed
- `Store::upsert_entity` was preserving the old `scan_id` column on
  conflict, so re-scanning a target left `entities_for_scan(new_sid)`
  returning zero. Last-scan-wins semantics are correct for v0.2; a
  junction table for full multi-scan tracking is deferred to v0.7+.

### Notes
- No new dependencies. No new files. ~120 lines added to `engine.rs`.
- Binary still 4.3 MB stripped.

## [0.1.0] — 2026-05-23

### Added
- Foundation: `core` (entity, error, scan, event, module trait, engine),
  `util` (rustls HTTP, key loading, scan-id), `storage` (SQLite WAL).
- Five free modules — `hudsonrock`, `crtsh`, `dns_resolver`, `ip_geo`,
  `email_to_username`.
- CLI: `scan` / `modules` / `doctor` subcommands surfacing the full
  `ScanOptions` API.
- `#![forbid(unsafe_code)]` and Termux-first defaults
  (`$HOME/.huntsman/huntsman.db`, `WORKER_THREADS = 2`,
  release profile `opt-level=z` + `lto` + `strip` → 4.3 MB binary).
- 31 unit tests + 2 integration smoke tests, all passing.
- Architecture invariants enforced:
  - rustls + bundled-sqlite only (no openssl, no native TLS, no C deps)
  - GREATEST-semantics entity merge
  - SHA-256 deterministic UIDs
  - `C_eff = clamp(C × (1 + 0.15 × ln(corroboration)), 0, 1)`
  - Classification derived, never stored
  - Passwords / credentials never written to evidence

[Unreleased]: https://github.com/EmmmmDeee/Huntsman-Search-Engine-HSE-Termux-Android-Aarch64-Rust-/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/EmmmmDeee/Huntsman-Search-Engine-HSE-Termux-Android-Aarch64-Rust-/releases/tag/v0.2.0
[0.1.0]: https://github.com/EmmmmDeee/Huntsman-Search-Engine-HSE-Termux-Android-Aarch64-Rust-/releases/tag/v0.1.0
