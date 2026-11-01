# Huntsman Search Engine

Rust OSINT search engine and SpiderFoot-compatible recon for Termux on Android ARM64 (aarch64), no root, with a phone Web UI.

Install or update (the same command does both; run it in Termux):

```sh
curl -fsSL https://raw.githubusercontent.com/EmmmmDeee/Huntsman-Search-Engine-HSE-Termux-Android-Aarch64-Rust-/main/install.sh -o "$TMPDIR/huntsman-install.sh" && bash "$TMPDIR/huntsman-install.sh"
```

It ends by printing `Web UI: running at http://127.0.0.1:8080`; open that address in the phone's browser (if it is not running, `huntsman start`).

Full usage, commands and reference: [docs/USAGE.md](docs/USAGE.md). Installation details: [docs/INSTALL.md](docs/INSTALL.md).
