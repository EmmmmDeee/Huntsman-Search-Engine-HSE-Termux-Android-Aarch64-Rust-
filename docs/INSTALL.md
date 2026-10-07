# Install and upgrade

Huntsman Recon is the current Rust package and installs as `huntsman-recon`.
It is distinct from the legacy `hse` monolith. Rebuilt people, email, username,
phone, scan-routing, query, investigate, SpiderFoot-compatible, and read-only
Web UI/API paths are present, but the full legacy surface is not yet at parity.
The legacy archives and their extracted copies are read-only references, not
installation sources.

## Termux on Android arm64 (build from source)

Install Termux from [F-Droid](https://f-droid.org/packages/com.termux/) or the
[official GitHub releases](https://github.com/termux/termux-app/releases).
Do not use the abandoned Play Store build. In Termux, run:

```sh
pkg update && pkg install -y git rust clang && HUNTSMAN_HIBP_NO_EMBED=1 cargo install --git https://github.com/EmmmmDeee/Huntsman-Search-Engine-HSE-Termux-Android-Aarch64-Rust-.git --locked --root "$PREFIX" huntsman-recon
```

The Rust package must provide Rust 1.87 or newer (`rustc --version`). The command
builds the default branch on the handset and installs the binary to
`$PREFIX/bin/huntsman-recon`. `HUNTSMAN_HIBP_NO_EMBED=1` prevents build-time
embedding of a key from the build environment or local HIBP key file; runtime
key use remains available.

Start with:

```sh
huntsman-recon --help
huntsman-recon check
huntsman-recon search "brisbane port"
```

Upgrade by running the same `cargo install` command again. The repository's
`install.sh` wrapper keeps Cargo intermediates under
`$HOME/.cache/huntsman-recon-target` by default and does not force-rebuild an
already matching install; set `CARGO_TARGET_DIR` to override that cache path.
To build a specific commit instead of the moving default branch, append
`--rev COMMIT` immediately after the repository URL.

## Prebuilt Termux release

The release workflow attaches a checksum-verified Termux installer to each
`main-<commit>` pre-release. Select the commit tag from the repository's
[Releases](https://github.com/EmmmmDeee/Huntsman-Search-Engine-HSE-Termux-Android-Aarch64-Rust-/releases)
page, replacing `main-<commit>` below with that exact tag:

```sh
TAG=main-<commit>
curl -fsSL "https://github.com/EmmmmDeee/Huntsman-Search-Engine-HSE-Termux-Android-Aarch64-Rust-/releases/download/$TAG/install-termux.sh" -o install-termux.sh
HUNTSMAN_CHANNEL=recon bash ./install-termux.sh
```

The `recon` channel installs `huntsman-recon`; the installer's default `hse`
channel is retained for compatibility with the legacy monolith. The installer
checks the downloaded binary against the release's SHA-256 file, stages it in a
private directory on the destination filesystem, then runs `check` and
`verify var/ledger.json` from the staged recon binary with bounded timeouts.
Only a staged binary that passes both offline runtime checks can replace the
existing executable. Reinstalling identical verified bytes keeps the existing
live inode. A checksum detects transfer/corruption errors; review the release
provenance and attestation if you need to verify publisher/build identity.

## Linux or another Rust host

Install Rust 1.87 or newer, then from a checkout:

```sh
HUNTSMAN_HIBP_NO_EMBED=1 cargo install --path . --locked
```

This places the binary in Cargo's configured install directory (usually
`~/.cargo/bin`). Ensure that directory is on `PATH`. To install from the
default branch without cloning first:

```sh
HUNTSMAN_HIBP_NO_EMBED=1 cargo install --git https://github.com/EmmmmDeee/Huntsman-Search-Engine-HSE-Termux-Android-Aarch64-Rust-.git --locked huntsman-recon
```

## Build, test, and run from a checkout

```sh
cargo test --locked
cargo run --locked -- --help
cargo run --locked -- check
```

`check` is offline and regenerates `var/*.json`; CI verifies these artifacts
remain byte-identical to their committed versions. See the [README](../README.md)
for runnable examples, credential-file rules, command exit codes, and project
boundaries.


## Real-device Termux acceptance

Cross-build CI proves that Huntsman compiles as an Android aarch64 ELF, but it
does not prove execution inside a real Termux userspace. After installing
`huntsman-recon` on a handset, run:

```sh
bash scripts/termux-runtime-acceptance.sh
```

The harness verifies the current binary metadata, runs offline `check` plus
ledger verification in a disposable directory, starts the embedded loopback
server on an isolated high port, checks `/api/health`, `/api/modules`, and
`/api/command`, stops it, then repeats the server lifecycle once. Relative
binary and output paths are anchored before the disposable-directory step,
every offline prerequisite must succeed, and the isolated child server ignores
an unrelated inherited API token so local account configuration cannot create
a false rejection. Results are written to
`~/.huntsman/termux-acceptance.txt`. A passing CI cross-build is not reported
as a handset-runtime pass; this harness must actually run on the device for that
claim.
