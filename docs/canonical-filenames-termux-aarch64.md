# Canonical filenames and Android-first layout

## Primary runtime contract

Huntsman is a pure-Rust OSINT application targeting **rootless Termux on Android AArch64**. Its embedded HTTP server and phone-browser Web UI are first-class interfaces. The default workflow must remain usable without paid API keys or a runtime language model. Bash is permitted for build, installation and test orchestration, not investigative application logic.

## Filename conventions

| Content | Canonical convention | Example |
| --- | --- | --- |
| Rust modules | lowercase `snake_case.rs` or `snake_case/mod.rs` | `src/scan_service.rs` |
| Rust tests | lowercase `snake_case.rs` | `tests/manifest_policy.rs` |
| Rust crates | existing Cargo package names; do not rename without migration | `huntsman-recon` |
| Shell scripts | lowercase `kebab-case.sh` | `scripts/termux-online-acceptance.sh` |
| Workflow files | lowercase `kebab-case.yml` | `.github/workflows/ci.yml` (existing name retained) |
| Documentation | existing public entrypoints retained; new guides use `kebab-case.md` | `docs/canonical-filenames-termux-aarch64.md` |
| Web assets | lowercase `kebab-case` for new public assets | existing routes and assets retained |
| Persisted evidence | preserve original names and bytes; use a separate canonical index | never rename acquired evidence |

## Migration and compatibility rules

1. Inventory tracked files, Rust module declarations, `include_str!`/`include_bytes!` paths, Cargo targets, scripts, workflows, Web UI asset references, installation paths, persisted configuration and external documentation before proposing renames.
2. Distinguish case-only collisions, duplicate content, legacy aliases and genuinely distinct modules. Similar filenames are not proof of redundancy.
3. Never mass-rename or delete working source files merely for style. Rename only with a verified dependency map, compatibility plan and regression fixtures.
4. Preserve the `huntsman-recon` binary, existing CLI commands, HTTP endpoints, Web UI routes, installed launcher and user configuration unless a separately verified compatibility migration is supplied.
5. Keep raw evidence, source filenames, metadata, timestamps, provenance and integrity hashes unchanged. Derived canonical names belong in a separate index; no destructive migration of acquired data.
6. Prefer incremental, independently reviewable renames on a dedicated branch. Update all references atomically; retain aliases when external consumers depend on old paths.
7. Verify `cargo fmt --all -- --check`, strict Clippy, complete workspace tests, Web UI/browser checks, install script checks and Android AArch64 cross-build for every affected change.
8. Require physical rootless Termux acceptance for claims of handset functionality. CI cross-compilation alone is not device acceptance.
9. Preserve API-free providers, optional authenticated providers, evidence storage, recovery and Web UI functionality through each migration.
10. Record an old-to-new filename mapping, test evidence and rollback instructions before any rename is merged.

## Android AArch64 acceptance focus

- Rootless Termux installation and upgrade without assuming `sudo`, systemd, Docker or a desktop.
- AArch64 native binary and supported Android linker/runtime; bounded memory, disk and concurrency.
- Local HTTP binding and usable phone Web UI at the documented address.
- Working keyless acquisition, original-evidence preservation, exports, restart and recovery.
- No mandatory runtime LLM or external paid service.

## Current status

This document establishes a naming and migration contract only. It does **not** assert that the complete repository filename inventory has been audited, that every file is already canonical, or that any source file has been renamed.
