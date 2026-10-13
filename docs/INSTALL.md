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

Upgrade by running the same two commands again. The installer resolves the
current `main` head to a full SHA and hands that SHA to Cargo, so a branch
movement during compilation cannot change the source being built. Cargo rebuilds
only when that revision differs from the installed one, and the installer then
repeats the runtime acceptance and the provenance record. Do not upgrade with a
bare `cargo install`: without the installer's `--root "$PREFIX"` it installs
into `~/.cargo/bin`, and Termux keeps running the old
`$PREFIX/bin/huntsman-recon`. Cargo intermediates stay under
`$HOME/.cache/huntsman-recon-target` by default; set `CARGO_TARGET_DIR` to
override that cache path. To build a specific revision, run the installer with a
full 40-character SHA in `HUNTSMAN_REV`.

## Prebuilt Termux release

Installing the newest verified build needs no compiler. It downloads one
binary of about 5 MB instead of compiling on the phone:

```sh
curl -fsSL https://raw.githubusercontent.com/EmmmmDeee/Huntsman-Search-Engine-HSE-Termux-Android-Aarch64-Rust-/main/.github/scripts/install-termux.sh -o "$TMPDIR/install-termux.sh"
bash "$TMPDIR/install-termux.sh"
```

This copy of the installer finds the newest build itself. A `main-<commit>`
pre-release is published only while its commit is the head of `main`. So the
installer walks back from the head of `main`, at most 30 commits, through the
GitHub API, and installs the build of the first commit that has one. Run the
same two commands again to upgrade.

The release workflow also attaches a checksum-verified installer to each
published `main-<commit>` pre-release. That installer always installs its own
release. Relevant main pushes are always built and verified, but a build
superseded before publication remains an Actions artifact rather than minting a
historical release tag. To install one specific build, select a commit tag from
the repository's
[Releases](https://github.com/EmmmmDeee/Huntsman-Search-Engine-HSE-Termux-Android-Aarch64-Rust-/releases)
page and replace `main-<commit>` below with that exact tag:

```sh
TAG=main-<commit>
curl -fsSL "https://github.com/EmmmmDeee/Huntsman-Search-Engine-HSE-Termux-Android-Aarch64-Rust-/releases/download/$TAG/install-termux.sh" -o install-termux.sh
bash ./install-termux.sh
```

The installer defaults to the current `huntsman-recon` build (into
`$PREFIX/bin/huntsman-recon`). The legacy `hse` monolith stays available as an
explicit opt-in — `HUNTSMAN_CHANNEL=hse bash ./install-termux.sh` (into
`$PREFIX/bin/hse`) — because recon does not yet cover the complete legacy
surface. Legacy in-app `hse update` invocations use the historical
`HSE_REQUIRE_SHA` / `HSE_REF` contract. Current `main/install.sh` treats that
contract as a product-line handoff, discards any reconstructed-main target SHA,
and executes the maintained `legacy-hse/install.sh` with `HSE_REF=legacy-hse`.
The legacy installer then verifies that the fetched Cargo package is
`huntsman-search-engine` before any build or binary replacement. New
reconstruction installs use `HUNTSMAN_REV`, which takes precedence.
The installer
checks the downloaded binary against the release's SHA-256 file, stages it in a
private directory on the destination filesystem, then runs `check` and
`verify var/ledger.json` from the staged recon binary with bounded timeouts.
Only a staged binary that passes both offline runtime checks can replace the
existing executable. Reinstalling identical verified bytes keeps the existing
live inode. A checksum detects transfer/corruption errors; review the release
provenance and attestation if you need to verify publisher/build identity.

## Uninstall from Termux

Remove the binary the way it was installed. A build from source (`install.sh`)
is registered with Cargo:

```sh
cargo uninstall --root "$PREFIX" huntsman-recon
```

A prebuilt install (`install-termux.sh`) is a single file:

```sh
rm -f "$PREFIX/bin/huntsman-recon"   # or "$PREFIX/bin/hse" for the legacy channel
```

Installing and running Huntsman also creates state that those commands keep.
Remove it only when you no longer need it; `~/.huntsman.env` holds your
provider keys:

```sh
rm -rf ~/.huntsman ~/.cache/huntsman-recon-target
rm -f ~/.huntsman.env
```

If you set `HUNTSMAN_HOME`, `HUNTSMAN_ENV_FILE` or `CARGO_TARGET_DIR` when
installing, remove those locations instead.

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
`huntsman-recon` on a handset, run these two commands; they need no checkout:

```sh
curl -fsSL https://raw.githubusercontent.com/EmmmmDeee/Huntsman-Search-Engine-HSE-Termux-Android-Aarch64-Rust-/main/scripts/termux-runtime-acceptance.sh -o "$TMPDIR/termux-runtime-acceptance.sh"
bash "$TMPDIR/termux-runtime-acceptance.sh"
```

From a checkout, `bash scripts/termux-runtime-acceptance.sh` runs the same
harness. It verifies the current binary metadata, runs offline `check` plus
ledger verification in a disposable directory, starts the embedded loopback
server on an isolated high port, checks `/api/health`, `/api/modules`,
`/api/command` and an offline `/api/lookup`, holds two idle connections open as
a browser's speculative sockets would and checks that a request is still
answered, stops it, then repeats the server lifecycle once. Relative
binary and output paths are anchored before the disposable-directory step,
every offline prerequisite must succeed, and the isolated child server ignores
an unrelated inherited API token so local account configuration cannot create
a false rejection. Results are written to
`~/.huntsman/termux-acceptance.txt`. A passing CI cross-build is not reported
as a handset-runtime pass; this harness must actually run on the device for that
claim.

CI runs the same harness against each build on its x86_64 host with
`HSE_ACCEPTANCE_HOST=1`, so the harness cannot drift from the binary or its
API. That run skips the ARM64 and Termux `PREFIX` checks and ends with
`HOST_RUNTIME_ACCEPTANCE (not a handset pass)`, never
`TERMUX_RUNTIME_ACCEPTANCE`.
