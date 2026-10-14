# Install and upgrade

Huntsman Recon is the current Rust package and installs as `huntsman-recon`.
It is distinct from the legacy `hse` monolith. Rebuilt people, email, username,
phone, scan-routing, query, investigate, SpiderFoot-compatible, and read-only
Web UI/API paths are present, but the full legacy surface is not yet at parity.
The legacy archives and their extracted copies are read-only references, not
installation sources.

## Termux on Android arm64

Install Termux from [F-Droid](https://f-droid.org/packages/com.termux/) or the
[official GitHub releases](https://github.com/termux/termux-app/releases), and
keep every Termux plugin on the same distribution source. On an ARM64 handset,
run:

```sh
curl -fsSL https://raw.githubusercontent.com/EmmmmDeee/Huntsman-Search-Engine-HSE-Termux-Android-Aarch64-Rust-/main/install.sh -o "$TMPDIR/huntsman-install.sh"
bash "$TMPDIR/huntsman-install.sh"
```

The installer is no-root userland only. It refreshes Termux repository metadata,
installs `git curl coreutils`, and resolves `main` once to a full immutable
commit SHA (unless `HUNTSMAN_REV` already names one). Then it installs, in this
order:

1. **The verified prebuilt build of that commit**, when CI published one as the
   `main-<sha7>` pre-release: about 5 MB, no compiler. The download must match
   the release's SHA-256 file, `build-sha` must print the commit, and `check`
   plus ledger verification must pass, all before the binary is staged next to
   `$PREFIX/bin/huntsman-recon`, re-checked there and renamed into place.
2. **The newest published build of `main`**, when the head of `main` has none
   yet (CI is still building it, or a newer push superseded it) and no
   `HUNTSMAN_REV` was given: the installer walks back from the head, at most 30
   commits, through the GitHub API.
3. **A source build**, only when no published build fits, or when
   `HUNTSMAN_FROM_SOURCE=1` asks for one. It installs `rust clang`, aligns the
   Termux Rust compiler with its host `rust-std-<target>` package, compiles a
   native toolchain probe, then builds the locked revision with the SHA
   embedded. When Cargo keeps an already-installed binary whose `build-sha`
   does not match (for example one built before the SHA was embedded), the
   installer rebuilds once with `--force` and fails if the result still does
   not match.

A published build that fails its checksum, `build-sha` or acceptance stops the
install with the old binary untouched; it never falls back to compiling. Either
way the installer creates `~/.huntsman` and a private `~/.huntsman.env`, and
only after every gate passes does it atomically write
`~/.huntsman/installed-revision` with the accepted revision and how it was
installed (`installed_from=prebuilt main-<sha7>` or `installed_from=source
rustc …`). It reports success only after runtime acceptance and provenance
verification pass.

Last, it sets up the web UI as a background service that restarts on its own;
see [Keep serve running on Android](#keep-serve-running-on-android).

The crate MSRV remains Rust 1.87. No build reads a key: keys are read at run
time only, from the environment or a key file such as `~/.huntsman.env`.

Start with:

```sh
huntsman-recon --help
huntsman-recon diagnostics
huntsman-recon search "brisbane port"
```

`diagnostics` reports the build, whether it runs in Termux, and how many
provider keys are configured, without values and without the network. The
installer has already run `check`, the offline self-test, in a scratch
directory. To run it yourself, do so in an empty directory: it writes
`var/*.json` into the current one.

Upgrade by running the same two commands again. The installer resolves the
current `main` head to a full SHA once, so a branch movement during the install
cannot change what is installed, then repeats the checks, the runtime
acceptance and the provenance record. Do not upgrade with a bare
`cargo install`: without the installer's `--root "$PREFIX"` it installs into
`~/.cargo/bin`, and Termux keeps running the old `$PREFIX/bin/huntsman-recon`.
For a source build, Cargo intermediates stay under
`$HOME/.cache/huntsman-recon-target` by default; set `CARGO_TARGET_DIR` to
override that cache path. To install a specific revision, run the installer
with a full 40-character SHA in `HUNTSMAN_REV`: its published build when it has
one, otherwise a source build of exactly that commit.

### Check and repair an install

After an install or an upgrade, and whenever something stops working:

```sh
huntsman-recon doctor   # what is wrong, and the command that fixes each problem
huntsman-recon fix      # make every repair that can be undone, then check again
```

`fix` never deletes a ledger or scan data and never writes a key. When the
binary itself is missing or stale, it prints the installer command above.

## Prebuilt Termux release (`install-termux.sh`)

`install.sh` above already installs the verified build when one exists. The
release installer below is the same download and checks without the source
fallback, for a phone that should never compile. Installing the newest verified
build needs no compiler. It downloads one
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

Stop and remove the web UI service and the `huntsman` command first:

```sh
sv-disable huntsman-serve
rm -rf "$PREFIX/var/service/huntsman-serve" "$PREFIX/var/log/sv/huntsman-serve"
rm -f "$PREFIX/bin/huntsman" "$PREFIX/bin/huntsmanctl" "$PREFIX/etc/profile.d/huntsman.sh"
```

Remove the binary the way it was installed. `~/.huntsman/installed-revision`
says which: `installed_from=source …` is registered with Cargo:

```sh
cargo uninstall --root "$PREFIX" huntsman-recon
```

A prebuilt install (`installed_from=prebuilt …`, or `install-termux.sh`) is a
single file:

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

## Keep serve running on Android

The installer runs the web UI as a
[termux-services](https://wiki.termux.com/wiki/Termux-services) service named
`huntsman-serve` and installs the `huntsman` command, which drives it. Open
the page in the phone's browser, signed in:

```sh
huntsman open
```

| Command | What it does |
| --- | --- |
| `huntsman start`, `stop`, `restart` | Start, stop or restart the web UI. `stop` keeps it off across reboots and reinstalls. |
| `huntsman status` | Whether it runs, its PID, memory, threads and address; exits 0 only when the page works. |
| `huntsman open` | Open the page in the phone's browser, signed in with the service's token. Needs the Termux:API app and `pkg install termux-api`. |
| `huntsman logs` | Follow the server's log. |
| `huntsman clean` | Remove the Rust build cache and Huntsman temporary files. |
| `huntsman scan-pipe TARGET [KIND]` | Scan, save the ledger under `~/huntsman-reports`, verify it, and write a Markdown report next to it. |
| `huntsman report SCAN.json` | Write the Markdown report for a saved scan: the full ledger, unredacted, with the result of `verify`. With Termux:API installed, it is also copied to the clipboard. |
| `huntsman` anything else | Runs `huntsman-recon` with the same arguments, for example `huntsman doctor` or `huntsman email ADDR`. |

New Termux sessions also load shortcuts from `$PREFIX/etc/profile.d/huntsman.sh`.
`h`, `start`, `stop`, `restart`, `status`, `logs`, `ui` (`open`), `clean`, `doc`
and `cred` are short for the `huntsman` commands. `domain`, `email`, `username`, `asx`
(`id`), `query` and `pipe` (`scan-pipe`) run lookups. `claims`, `verified`,
`did`, `dossier`, `latest_json`, `latest_md` and `clean_reports` read the saved
scans. Your `~/.bashrc` is left alone.

The page's analysis form runs entirely on the phone: it links the seeds you
enter, ranks the next pivots, names the seeds left unlinked and plans the
sources to query, with no network request and no API key, so it works with
mobile data off.

The service takes a wake lock for Termux, restarts the server within a second
whenever it stops, starts again the next time Termux opens after a reboot, and
is restarted onto the new binary by every install or upgrade. The installer's
last lines say whether the page answers. `HUNTSMAN_SERVE_SERVICE=off` or `on`
when running the installer is the same as `huntsman stop` or `huntsman start`.

Other apps on the phone can reach 127.0.0.1 too, and a lookup spends your
provider keys, so the installer gives the service a random token in
`~/.huntsman/serve.token` (readable only by Termux). The page and every API
call except the health check need it. `huntsman open` passes it to the browser
in the address's `#token=` part, which the browser keeps and never sends to a
server, so you sign in once per browser; `huntsman status` and the installer
send it too. Reinstalls keep the token. To use a different one, delete the file
and run the installer again; to turn it off, empty the file and run
`huntsman restart`.

Port 8080 is also the default of other servers people run in Termux, such as
code-server and File Browser. When another program holds it, `huntsman start`
picks the next free port, says which, and keeps using it (it is stored in
`~/.huntsman/serve.bind`) until 8080 is free again. If the port is taken while
the service runs, `serve` exits 69 and the service waits a minute before trying
again instead of retrying every second. To run the server by hand instead, stop
the service and pass `--bind`:

```sh
huntsman stop
termux-wake-lock
huntsman-recon serve --bind 127.0.0.1:8081
termux-open-url http://127.0.0.1:8081/
```

A server started this way has no token unless you export `HSE_AUTH_TOKEN`
first. The service's page is at `termux-open-url http://127.0.0.1:8080/` when
you open it without `huntsman open`; it then asks for the token.

`serve` prints the address it listens on as `serving=http://…/`;
`--bind 127.0.0.1:0` has the system pick a free port. A port below 1024 needs
root, which Termux does not have.

Android may still stop Termux's processes. The wake lock keeps the CPU awake
for Termux until `termux-wake-unlock` releases it. On Android 12 or later, the
system's limit on processes started by apps (the "phantom process killer") can
still stop the server. On Android 14 or later, turn on
"Disable child process restrictions" in Developer options and leave Developer
options on; turning them off restores the limit. On Android 12 and 13 the limit can only be changed
over `adb`; Termux's
[issue 2366](https://github.com/termux/termux-app/issues/2366) describes how.

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
cargo install --path . --locked
```

This places the binary in Cargo's configured install directory (usually
`~/.cargo/bin`). Ensure that directory is on `PATH`. To install from the
default branch without cloning first:

```sh
cargo install --git https://github.com/EmmmmDeee/Huntsman-Search-Engine-HSE-Termux-Android-Aarch64-Rust-.git --locked huntsman-recon
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
