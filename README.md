# Huntsman Search Engine

Rust OSINT search engine and SpiderFoot-compatible recon for Termux on Android ARM64 (aarch64), no root, with a phone Web UI.

Install or update (the same command does both; run it in Termux):

```sh
installer="${TMPDIR:-$PREFIX/tmp}/huntsman-install.sh"
curl -fsSL https://raw.githubusercontent.com/EmmmmDeee/Huntsman-Search-Engine-HSE-Termux-Android-Aarch64-Rust-/main/install.sh -o "$installer" && bash "$installer"
```

A successful managed installation reports the actual installed commit and Web UI status.
Open `http://127.0.0.1:8080` on the phone when the service is running
(or use `huntsman start`). Check the installed revision with
`huntsman-recon build-sha` and `cat ~/.huntsman/installed-revision`.

Low-memory prebuilt-only mode: `HUNTSMAN_REQUIRE_PREBUILT=1 bash "$installer"`.
An unpublished exact build is refused without modifying the existing binary.
An explicit source build uses `HUNTSMAN_FROM_SOURCE=1 bash "$installer"`.
Both mode flags accept only `0` or `1` and cannot simultaneously be `1`;
invalid values are rejected before package, network, or persistent-state work.

Build/test status on GitHub is not physical handset validation. For physical
Termux acceptance, run `scripts/termux-runtime-acceptance.sh` as documented in
[docs/INSTALL.md](docs/INSTALL.md).

Full usage, commands and reference: [docs/USAGE.md](docs/USAGE.md). Installation details: [docs/INSTALL.md](docs/INSTALL.md).
