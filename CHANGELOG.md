# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
The crate (`huntsman-recon`, version `0.2.0` in `Cargo.toml`) has no stable
release yet; pushes to `main` publish `main-<sha7>` pre-releases (#672). Release policy: only pre-releases (`main-<sha7>` plus a rolling
`latest`); a stable release needs the owner's explicit approval.

## [Unreleased]

### Added

- `recon dns TARGET`: DNS-over-HTTPS lookup of A/AAAA/MX/NS/TXT plus `_dmarc`
  and `_smtp._tls`, parsing SPF/DMARC/TLSRPT from TXT over the injected
  transport (offline fake-transport tests; no live receipt).
- `sources` command: classifies an input and prints curated public search
  routes from `source_registry`, offline and `LeadOnly`; the classifier also
  recognises decimal-degree coordinates (#671).
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
- README has a "Which binary to use" section. The legacy `hse` (pre-release
  `main-7dca720`) has the original person-lookup providers. `huntsman-recon`
  provides a subset through `people` and ships only as `main-<sha7>` pre-releases.
- README documents build and install steps, the `fetch` options, how keys are
  supplied, the CI artifact download, and the release state.

### Removed

- The monolith's release, audit, bench-smoke, copilot-setup-steps, fuzz,
  live-drift, rust-clippy and secret-scan workflows, `rust-toolchain.toml`, `docs/INSTALL.md` and the previous
  `CHANGELOG.md` (f0a1c64c). A release workflow for `huntsman-recon` was
  restored in #672.

### Fixed

- Legacy snapshot restored to its pinned bytes after #665 edited files under
  `legacy/` (78ce7723). #665 therefore has no effect on the current tree, and
  #663 merged no changes.
- SeekNow bulk import build on the pre-reconstruction tree (#661).
- `src/hibp/key.rs` documentation no longer refers to a `ModuleContext`, which
  this crate does not have, or says the HIBP key chain reads `~/.huntsman.env`;
  it does not (the binary's `~/.huntsman.env` auto-load, #674, supplies `fetch`
  credential slots).
- README said `check` gate 5 exercises `credential_origin` and `eval`; it
  exercises `source_outcome`, `evidence_ancestry`, `identity_resolution` and
  `termination` of the overlay modules.
- `docs/RECONSTRUCTION_2026-10-02.md` names the archives as committed and
  gives the monolith archive's file count (1314 files, 1727 zip entries).
