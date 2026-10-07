# Install and upgrade

Huntsman Recon is the current Rust package and installs as `huntsman-recon`.
It is distinct from the legacy `hse` monolith. Rebuilt people, email, username,
phone, scan-routing, query, investigate, SpiderFoot-compatible, and read-only
Web UI/API paths are present, but the full legacy surface is not yet at parity.
The legacy archives and their extracted copies are read-only references, not
installation sources.

## Termux on Android arm64 (build from source)

Install Termux from [F-Droid](https://f-droid.org/packages/com.termux/) or the
[official GitHub releases](https://github.com/termux/termux-app/releases), and
keep every Termux plugin on the same distribution source. On an ARM64 handset,
run:

```sh
curl -fsSL https://raw.githubusercontent.com/EmmmmDeee/Huntsman-Search-Engine-HSE-Termux-Android-Aarch64-Rust-/main/install.sh -o "$TMPDIR/huntsman-install.sh"
bash "$TMPDIR/huntsman-install.sh"
```

The installer is no-root userland only. It refreshes Termux repository metadata,
installs `git rust clang curl coreutils`, aligns the Termux Rust compiler with
its host `rust-std-<target>` package, compiles a native toolchain probe, resolves
`main` once to a full immutable commit SHA (unless `HUNTSMAN_REV` already names
one), builds that exact locked revision, creates `~/.huntsman` and a private
`~/.huntsman.env`, then runs `check` and ledger verification in the same
disposable directory. Only after those gates pass does it atomically write
`~/.huntsman/installed-revision` with the accepted source revision and toolchain
provenance. It reports success only after runtime acceptance and provenance
verification pass.

The crate MSRV remains Rust 1.87. `HUNTSMAN_HIBP_NO_EMBED=1` is exported by
the installer so build-time key embedding stays disabled; runtime key use remains
available.

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
By default the wrapper freezes the current `main` head and supplies that full SHA
to Cargo, so a branch movement during compilation cannot change the source being
built. To request a specific revision explicitly, run the installer with a full
40-character SHA in `HUNTSMAN_REV`.

## Prebuilt Termux release

The release workflow attaches a checksum-verified Termux installer to each
published `main-<commit>` pre-release. Relevant main pushes are always built and verified, but a build superseded before publication remains an Actions artifact rather than minting a historical release tag. Select an available commit tag from the repository's
[Releases](https://github.com/EmmmmDeee/Huntsman-Search-Engine-HSE-Termux-Android-Aarch64-Rust-/releases)
page, replacing `main-<commit>` below with that exact tag:

```sh
TAG=main-<commit>
curl -fsSL "https://github.com/EmmmmDeee/Huntsman-Search-Engine-HSE-Termux-Android-Aarch64-Rust-/releases/download/$TAG/install-termux.sh" -o install-termux.sh
HUNTSMAN_CHANNEL=recon bash ./install-termux.sh
```

The `recon` channel installs `huntsman-recon`; the installer's default `hse`
channel is retained for compatibility with the legacy monolith. Legacy in-app
`hse update` invocations use the historical `HSE_REQUIRE_SHA` / `HSE_REF`
contract. Current `main/install.sh` treats that contract as a product-line
handoff, discards any reconstructed-main target SHA, and executes the maintained
`legacy-hse/install.sh` with `HSE_REF=legacy-hse`. The legacy installer then
verifies that the fetched Cargo package is `huntsman-search-engine` before any
build or binary replacement. New reconstruction installs use `HUNTSMAN_REV`,
which takes precedence.
The installer
checks the downloaded binary against the release's SHA-256 file, stages it in a
private directory on the destination filesystem, then runs `check` and
`verify var/ledger.json` from the staged recon binary with bounded timeouts.
Only a staged binary that passes both offline runtime checks can replace the
existing executable. Reinstalling identical verified bytes keeps the existing
live inode. A checksum detects transfer/corruption errors; review the release
provenance and attestation if you need to verify publisher/build identity.

## Railway deployment

The current `huntsman-recon` Railway path uses the root `Dockerfile` and
`.railway/railway.ts`. New Railway services should use `/api/health` as the
healthcheck path. Railway's injected `PORT` is consumed automatically by the
binary, and the container entrypoint also sets the same bind explicitly.

For durable state, attach one volume at `/data`. A volume is optional for a
stateless deployment. Set `HSE_AUTH_TOKEN` as a Railway variable for a stable
token; if omitted, the entrypoint generates one from `/dev/urandom`, stores it
under `/data/.huntsman` when that location is persistent, and emits the newly
generated value once to deployment logs.

See [`RAILWAY.md`](RAILWAY.md) for the complete deployment contract.

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
