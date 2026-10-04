# Termux and SpiderFoot compatibility

This matrix is deliberately evidence-based. A successful cross-build proves
that the source compiles for a target; it does not prove the binary installs or
runs on an Android handset. “Supported” below means the stated behavior has
automated evidence, not that all Termux devices or SpiderFoot workflows are
compatible.

## Termux Android arm64

| Target | Status | Current evidence | Remaining acceptance |
| --- | --- | --- | --- |
| No-root installation | **Documented; handset unverified** | `docs/INSTALL.md` gives an on-device Cargo install and a checksum-verified release path under `$PREFIX`. | Install both paths on a clean, no-root Termux arm64 handset. |
| Rust source build | **Cross-build verified** | `.github/workflows/ci.yml` builds the release binary for `aarch64-linux-android` with Android API 24 and Rust 1.87. | Build on-device with the Termux-packaged toolchain; confirm package-specific linker behavior. |
| Android executable format | **Cross-build verified** | CI checks AArch64 ELF and `/system/bin/linker64`; the release pipeline records provenance and SHA-256. | Execute the installed artifact on a handset. |
| CLI startup and offline functions | **Host-tested; Android unverified** | The full test suite exercises CLI behavior on Linux. | Run `--help`, `check`, local `search`, and `verify` on-device. |
| Web UI startup | **Host-tested; Android unverified** | Unit tests bind an ephemeral loopback listener and exchange HTTP over a real local socket. | Start `huntsman-recon web` on a handset and load `http://127.0.0.1:8787/` in its browser. |
| Listener exposure | **Loopback enforced in source** | The server binds specifically to IPv4 `127.0.0.1`; request Host validation rejects other names to reduce DNS-rebinding exposure. | Confirm handset routing/firewall behavior; do not treat loopback as authentication against other local apps/users. |
| Storage and resource limits | **Partially verified** | HTTP headers are capped at 8 KiB, read timeout is two seconds, and search query size is capped at 512 bytes. The current UI uses bundled records and writes no settings. | Measure memory/CPU on low-memory devices; test Termux storage permissions and process lifecycle. |
| Networking | **Local UI only; remote collection not implemented in UI** | UI status and search endpoints are local. Existing guarded `fetch` remains a separate CLI command; the web server has no remote-bind option. | Verify local browser access on handset; define and test any future web-driven egress policy before adding scan actions. |
| Performance and battery | **Unverified** | No Android handset benchmark or long-run measurement is available. | Measure startup, idle CPU/RAM, repeated requests, and Android background behavior on target devices. |

## SpiderFoot 4.0 comparison scope

“Like SpiderFoot” is a product direction, not a compatibility claim. There is
no agreed SpiderFoot 4.0 version/build, plugin inventory, or acceptance suite
in this repository. The following are candidate parity areas to confirm with
the project owner; each remains **not implemented or not verified** by the
current web UI.

| Candidate workflow/feature | Huntsman web UI status |
| --- | --- |
| Start, pause, resume, and stop a target scan | **Not implemented.** The UI has no scan engine or scan lifecycle. |
| Module/plugin selection, configuration, and dependency handling | **Not implemented in UI.** Huntsman contains Rust analysis modules, but they are not exposed as a SpiderFoot-compatible plugin system. |
| Live scan progress, event stream, and persisted scan history | **Not implemented.** `/api/status` reports service status only; no scan records are created. |
| Findings table, filtering, detail views, and relationship graph | **Not implemented in UI.** The first UI searches two bundled demonstration records. |
| Export/report workflows | **Not implemented in UI.** Existing library ledger/STIX capabilities are not connected to web sessions. |
| SpiderFoot API, data model, plugins, or wire compatibility | **Not claimed.** No compatibility adapter or SpiderFoot acceptance tests exist. |
| Current first-slice behavior | **Implemented and host-tested.** Loopback-only page, read-only status/config APIs, and ranked search over bundled sample records. |

Before expanding parity, agree on the exact SpiderFoot 4.0 release and a
workflow-by-workflow acceptance list. For each row, distinguish a native
Huntsman equivalent from an adapter or an intentional non-goal. Do not describe
the project as “100% compatible” unless every agreed handset and feature
acceptance test passes on its target environment.
