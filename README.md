# Huntsman Search Engine

Rust OSINT search engine and SpiderFoot-compatible recon for Termux on Android ARM64 (aarch64), no root, with a phone Web UI.

Install or update (the same command does both; run it in Termux):

```sh
curl -fsSL https://raw.githubusercontent.com/EmmmmDeee/Huntsman-Search-Engine-HSE-Termux-Android-Aarch64-Rust-/main/install.sh -o "$TMPDIR/huntsman-install.sh" && bash "$TMPDIR/huntsman-install.sh"
```

It ends by printing `Web UI: running at http://127.0.0.1:8080`; open that address in the phone's browser (if it is not running, `huntsman start`).

Full usage, commands and reference: [docs/USAGE.md](docs/USAGE.md). Installation details: [docs/INSTALL.md](docs/INSTALL.md).

## Low-memory Android installation

On a memory-constrained phone, prefer the strict prebuilt-only installer.
It will not fall back to a local Rust compilation or an older revision:

```sh
curl -fsSL https://raw.githubusercontent.com/EmmmmDeee/Huntsman-Search-Engine-HSE-Termux-Android-Aarch64-Rust-/main/install.sh -o "$TMPDIR/huntsman-install.sh" &&
  HUNTSMAN_REQUIRE_PREBUILT=1 bash "$TMPDIR/huntsman-install.sh"
```

If the requested revision has no published prebuilt, the existing installation
is left unchanged. See [installation details](docs/INSTALL.md) for revision
pinning and intentional source builds.

After installation, verify the actual binary revision and runtime health:

```sh
huntsman-recon build-sha
huntsman-recon doctor
huntsman-recon doctor serve
```

For reproducible comparisons of builds, record the device model, Android
version, accepted commit SHA, binary size and available memory. Compare
the same offline workload on the same device before and after a change;
report timings as measurements, not guarantees. Do not introduce additional
runtime dependencies solely on the basis of upstream benchmarks.
