# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
The crate (`huntsman-recon`, version `0.2.0` in `Cargo.toml`) has no tagged
release yet. Release policy: only pre-releases (`main-<sha7>` plus a rolling
`latest`); a stable release needs the owner's explicit approval.

## [Unreleased]

### Added

- Android aarch64 cross-build in CI (`android-aarch64` job, API level 24),
  with ELF machine and `/system/bin/linker64` interpreter checks, a SHA-256
  sidecar, and a 14-day `huntsman-recon-aarch64-linux-android` artifact on
  pushes to `main`. HIBP key embedding is disabled for that artifact
  (`HUNTSMAN_HIBP_NO_EMBED=1`). Contract tests in `tests/android_ci.rs` (#670).
- Opt-in HIBP library (`huntsman_recon::hibp`): REST v3 read endpoints,
  Pwned Passwords SHA-1/NTLM ranges, entitlement checks, a shared 10/minute
  rate limit (`HIBP_RATE_LIMIT_PER_MINUTE`), bounded 429 retries, OAuth PKCE
  for the MCP resource, and optional build-time key embedding for personal
  builds (`tests/hibp_build.rs`) (#662).
- `tests/readme.rs` and `tests/dispositions.rs`, which check the README
  examples, exit codes and gate range, and the legacy disposition counts,
  against the binary and `legacy/` (#669).
- Guarded network layer (`egress`, `http`, `fetch`, `keys`) with `fetch` and
  `keys` commands and `check` gate 11; both legacy archives kept in the
  repository root and extracted into `legacy/`, pinned by
  `tests/legacy_reference.rs`; per-file accounting in `docs/DISPOSITIONS.md`
  (#667, #668).
- `id`, `geohash` and `coarsen` commands, and the rebuilt `au_id`, `geohash`,
  `confidence` and `redact` modules (`check` gate 10).
- Refactor-overlay foundations as library modules: `source_outcome`,
  `evidence_ancestry`, `identity_resolution`, `termination`,
  `credential_origin` and `eval` (`check` gate 5).
- Offline `huntsman-recon` core: RCVF session recorder, hash-chained ledger
  (`verify` command), local document search (`search QUERY [DIR]`), challenge
  page classification (`classify`), GEOINT distance (`geo`), and STIX and
  ATT&CK Navigator export gated on implemented techniques (`check`)
  (7dca720b to dcc60bcb, #666).
- ATT&CK capability ledger v0 with flag-based status (#660; superseded by the
  reconstruction).
- `CHANGELOG.md`.

### Changed

- `huntsman-recon` is the only current tree. The HSE v1.41.0 monolith and the
  refactor overlay are read-only reference under `legacy/` (f0a1c64c, #668).
- `search` is local retrieval over operator-supplied documents; a challenge
  page or a 429 is not a hit (c03e78a2 to dcc60bcb).
- CI test matrix is Rust 1.87 (MSRV) and stable; tests fixed for Rust 1.99
  clippy (`assert_is_empty`) (#669).
- README documents build and install steps, the `fetch` options, how keys are
  supplied, the CI artifact download, and the release state.

### Removed

- The monolith's release, audit, bench-smoke, copilot-setup-steps, fuzz,
  live-drift, rust-clippy and secret-scan workflows, `rust-toolchain.toml`, `docs/INSTALL.md` and the previous
  `CHANGELOG.md` (f0a1c64c). The current workflow publishes no GitHub Release.

### Fixed

- Legacy snapshot restored to its pinned bytes after #665 edited files under
  `legacy/` (78ce7723). #665 therefore has no effect on the current tree, and
  #663 merged no changes.
- SeekNow bulk import build on the pre-reconstruction tree (#661).
- `src/hibp/key.rs` documentation no longer refers to `~/.huntsman.env` or a
  `ModuleContext`, neither of which this crate has.
- README said `check` gate 5 exercises `credential_origin` and `eval`; it
  exercises `source_outcome`, `evidence_ancestry`, `identity_resolution` and
  `termination` only.
- `docs/RECONSTRUCTION_2026-10-02.md` names the archives as committed and
  gives the monolith archive's file count (1314 files, 1727 zip entries).
