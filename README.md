# Huntsman Search Engine

Rust-native OSINT search engine and SpiderFoot-compatible recon for **rootless Termux on Android AArch64**, with an embedded mobile web UI.

## Primary platform

- GitHub is the canonical source, development, CI and release host; the runtime runs locally on the handset, not on GitHub Pages or a mandatory cloud server.
- Target native Android AArch64/Bionic in the Termux app userland: no root, PRoot, container or system-partition modification.
- Prefer a checksum-verified, commit-bound prebuilt executable; do not require a compiler on the normal installation path.
- Use the mobile browser as the primary operator interface. Keep CLI and local API behaviour consistent with the web UI through shared Rust contracts. Bind to loopback by default.
- Use Rust for first-party executable code, including engineering tooling and tests. Justify necessary platform bootstrap and browser interoperability exceptions; avoid mandatory external runtimes or runtime LLMs.
- Judge changes by measured low-end Android memory, storage, latency, battery, installation effort, reliability and web UI functionality. Host CI and cross-compilation complement but do not replace physical handset acceptance.

## Install or update in Termux

Recommended for low-memory handsets: require the verified prebuilt for the requested revision, without silently compiling or selecting an older revision.

```sh
curl -fsSL https://raw.githubusercontent.com/EmmmmDeee/Huntsman-Search-Engine-HSE-Termux-Android-Aarch64-Rust-/main/install.sh -o "$TMPDIR/huntsman-install.sh" && HUNTSMAN_REQUIRE_PREBUILT=1 bash "$TMPDIR/huntsman-install.sh"
```

If the current commit has no published prebuilt, the strict installer refuses the upgrade and preserves an existing installation. See [installation details](docs/INSTALL.md) for pinned revisions and explicit source builds.

When the service is running, open **http://127.0.0.1:8080** in the phone browser. If deliberately stopped, use `huntsman start`. Check the installed runtime using `huntsman-recon doctor` and `huntsman-recon doctor serve`.

## Development and acceptance

Use the existing [implementation handoff](docs/implementation/README.md), [architecture](ARCHITECTURE.md) and [agent instructions](AGENTS.md). Reuse the repository's canonical completion register and implementation queue; do not introduce a competing roadmap or replace the existing executable with a reference-only crate.

Release gates include locked Rust builds, existing repository quality gates, Android AArch64 cross-build, checksum and commit provenance, and physical rootless Termux acceptance. Verify web UI/API parity, persistent state after interruption, installation and rollback, and resource budgets on the handset. Report incomplete parity and missing live receipts explicitly.

The current reconstruction is partial; documented or offline-tested functionality is not proof of complete operational parity. See [usage and current limitations](docs/USAGE.md).
