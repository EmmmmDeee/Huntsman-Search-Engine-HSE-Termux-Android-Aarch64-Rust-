# Installation guide

HSE is designed primarily for **Termux on Android aarch64** but works on
any Unix with Rust 1.88+ and git. The installer is idempotent — re-running
upgrades in place.

---

## The one-liner — the single installation (Termux, Linux, macOS)

Open Termux (or any shell) and paste:

```bash
curl -fsSL https://raw.githubusercontent.com/EmmmmDeee/Huntsman-Search-Engine-HSE-Termux-Android-Aarch64-Rust-/main/install.sh | bash
```

That's everything. The installer:

1. Detects Termux vs standard Unix.
2. Sanity-checks: clock, disk (≥ 2 GB), RAM (≥ 1.5 GB else uses `CARGO_BUILD_JOBS=1`).
3. Installs system dependencies (rust, git, clang, make, pkg-config, openssl-tool).
4. Verifies `rustc >= 1.88`; bootstraps `rustup` on non-Termux Unix if missing.
5. Clones / updates the repo to `$HOME/.local/share/hse`.
6. Builds in release mode (`--locked`) with retry-on-network-error.
7. Installs the binary to `$PREFIX/bin` (Termux) or `$HOME/.local/bin`.
8. Creates `$HOME/.huntsman.env` (chmod `0600`) with a commented key template.
9. Runs `hse doctor` to verify.

Everything is logged to `$HOME/.cache/hse-install.log` for post-mortem.

### No-build fast path (no toolchain, no compile)

The installer skips the Rust toolchain and the on-device build entirely when a
precompiled aarch64 `hse` is available: drop a binary named `hse` or
`hse-aarch64-linux-android` into your **Downloads** folder and the installer
validates it (ELF magic + optional `.sha256` sidecar + a run-test) and installs
it directly. After a *source* build it **caches the freshly-built binary back to
Downloads**, so the next install — this device after a wipe, or another aarch64
phone — takes the instant path automatically. Point at a specific file with
`HSE_PREBUILT=/abs/path/to/hse`, or force a source build with
`HSE_PREFER_BUILD=1`. (The cached binary is one you built from this repo — there
is no separate release download to go stale.)

### Tuning knobs (environment variables)

| Variable | Default | Purpose |
|----------|---------|---------|
| `HSE_INSTALL_DIR` | `$HOME/.local/share/hse` | Where to clone source |
| `HSE_BIN_DIR`     | `$PREFIX/bin` (Termux) or `$HOME/.local/bin` | Where to install `hse` |
| `HSE_REF`         | `main` | Git branch / tag / SHA to install |
| `HSE_REPO_URL`    | upstream | Override fork URL |
| `HSE_SKIP_BUILD`  | `0` | Stop after clone (useful for review) |
| `HSE_NO_PKG`      | `0` | Skip `pkg`/`apt` install (assume deps present) |
| `HSE_INSTALL_DEBUG` | `0` | Enable shell trace (`set -x`) |
| `CARGO_TARGET_DIR` | `$HOME/.cache/hse-build` | Build cache location |
| `CARGO_BUILD_JOBS` | (auto) | Limit parallel rustc jobs (set 1 on <1.5 GB RAM) |

Example — install a specific tag from a fork without touching apt:

```bash
HSE_REF=v0.2.0 HSE_NO_PKG=1 HSE_REPO_URL=https://github.com/you/hse.git \
  curl -fsSL https://raw.githubusercontent.com/EmmmmDeee/Huntsman-Search-Engine-HSE-Termux-Android-Aarch64-Rust-/main/install.sh | bash
```

---

## Optional: a default scan target (skip retyping `--value`)

If you scan the same target often — typically **your own** identity, to watch
your exposure — set it once as an operator-local default instead of retyping it
every run. Add a single line to `$HOME/.huntsman.env` (created by the installer,
chmod `0600`, git-ignored):

```bash
echo 'HUNTSMAN_DEFAULT_SEED=your-handle-or-target' >> ~/.huntsman.env
```

Then a bare `hse scan` (or `hse live`) uses it, with kind auto-detected:

```bash
hse scan            # scans HUNTSMAN_DEFAULT_SEED
hse scan -v someone-else   # an explicit --value always overrides the default
```

This value is read **only** from your local env file (or your shell) — it is
never embedded in the binary, the repository, or the installer, so it stays on
your device and installing HSE never points it at anyone. Leave the line unset
to require an explicit `--value` each time.

---

## Manual install

If you'd rather not pipe a script:

### Termux

```bash
pkg update -y
pkg install -y rust git clang make pkg-config openssl-tool
git clone --depth 1 https://github.com/EmmmmDeee/Huntsman-Search-Engine-HSE-Termux-Android-Aarch64-Rust-.git ~/hse
cd ~/hse
cargo build --release --locked
install -m 0755 target/release/hse $PREFIX/bin/hse
hse doctor
```

### Debian / Ubuntu

```bash
sudo apt-get update && sudo apt-get install -y build-essential git pkg-config curl
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source "$HOME/.cargo/env"
git clone --depth 1 https://github.com/EmmmmDeee/Huntsman-Search-Engine-HSE-Termux-Android-Aarch64-Rust-.git ~/hse
cd ~/hse
cargo build --release --locked
install -m 0755 target/release/hse ~/.local/bin/hse
hse doctor
```

### macOS

```bash
xcode-select --install   # if not already installed
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source "$HOME/.cargo/env"
git clone --depth 1 https://github.com/EmmmmDeee/Huntsman-Search-Engine-HSE-Termux-Android-Aarch64-Rust-.git ~/hse
cd ~/hse
cargo build --release --locked
install -m 0755 target/release/hse /usr/local/bin/hse
hse doctor
```

---

## Developer setup (build / test / contribute)

To set up a **development** environment — toolchain + `rustfmt`/`clippy` + build
deps + the keys file — without installing the binary, clone the repo and run:

```bash
git clone https://github.com/EmmmmDeee/Huntsman-Search-Engine-HSE-Termux-Android-Aarch64-Rust-.git ~/hse
cd ~/hse
scripts/setup-dev.sh        # idempotent; detects Termux / Debian / macOS
```

It installs the system build deps, ensures a Rust toolchain (≥ MSRV 1.88) with
`rustfmt` + `clippy`, creates `~/.huntsman.env` (chmod 0600) if absent, then
verifies the environment with `cargo fmt --check`, `cargo clippy -D warnings`,
and `cargo build`. Pass `--deps-only` to skip the verification step. After it
completes:

```bash
cargo test --all --locked      # full suite
cargo run -- doctor            # environment report
```

> `install.sh` is the **end-user** path (it builds + installs the `hse` binary);
> `scripts/setup-dev.sh` is the **contributor** path (toolchain + checks, no
> install). Claude Code on the web reuses `scripts/setup-dev.sh --deps-only` via
> its `SessionStart` hook.

---

## Updating

Just re-run the same command you used to install. The installer detects an
existing clone and pulls the latest changes:

```bash
curl -fsSL https://raw.githubusercontent.com/EmmmmDeee/Huntsman-Search-Engine-HSE-Termux-Android-Aarch64-Rust-/main/install.sh | bash
```

Or, if you cloned manually:

```bash
cd ~/hse && git pull && cargo build --release --locked && install -m 0755 target/release/hse $PREFIX/bin/hse
```

---

## Uninstall

```bash
rm -f $PREFIX/bin/hse                       # Termux; use ~/.local/bin/hse on Linux/macOS
rm -rf $HOME/.local/share/hse               # source clone
rm -rf $HOME/.cache/hse-build               # build cache
rm -rf $HOME/.huntsman                      # database
rm -f  $HOME/.huntsman.env                  # API keys (CAUTION — back up first if you have keys)
rm -f  $HOME/.cache/hse-install.log         # install log
```

---

## Termux-specific notes

### Required Termux setup

Install Termux from **F-Droid**, not Google Play (the Play version is
deprecated and ships an old userland). After installing:

```bash
termux-setup-storage    # grants access to /sdcard etc. — only needed if you want HSE to read files there
pkg update -y
```

### Optional: termux-api for on-device sensors (v0.6+)

The four `termux-*` sensor modules (`wifi_scan`, `wifi_connect`,
`gps_fix`, `cell_survey`) need both the binaries and the companion app:

```bash
pkg install termux-api
# Then install the "Termux:API" app from F-Droid (separate APK):
#   https://f-droid.org/en/packages/com.termux.api/
```

After installing the app, grant it the relevant Android permissions
(Location, Phone, Wi-Fi as required) in Android Settings. The Termux:API
app must have *Allow all the time* location permission for `cell_survey`
to work (Android Q+ restricts cell info to apps with foreground
location).

When termux-api is unavailable, the four sensor modules return empty
results rather than erroring (via `util::termux::termux_cmd` helper),
so HSE remains fully usable. The two file-reading sensors (`arp_scan`,
`net_interfaces`) don't need termux-api and work on any Linux host.

### Storage paths

| What | Where |
|------|-------|
| Source | `$HOME/.local/share/hse/` |
| Binary | `$PREFIX/bin/hse` |
| Database | `$HOME/.huntsman/huntsman.db` (+ `-wal`, `-shm`) |
| API keys | `$HOME/.huntsman.env` (chmod 0600) |
| Build cache | `$HOME/.cache/hse-build/` |
| Install log | `$HOME/.cache/hse-install.log` |

In Termux, `$HOME` resolves to `/data/data/com.termux/files/home`.

---

## Verifying the install

```bash
hse --version           # → hse 1.4.0
hse doctor              # environment report — should print "Termux: detected" on-device
hse modules             # 114 modules listed (see docs/MODULES.md for full catalogue)
hse scan --kind email --value test@example.com --modules email_parse,gravatar
```

### Web UI smoke test

```bash
hse serve               # listens on 127.0.0.1:8080
```

Open Chrome (or Firefox) on the device and visit
[`http://127.0.0.1:8080`](http://127.0.0.1:8080). The SPA loads with six
nav tabs: Dashboard, New Scan, Scans, Live, Engines, Settings. Start a scan
from **New Scan** — module-progress events stream into the scan's Event Log
tab via SSE as the engine dispatches.

If anything looks wrong, see [`TROUBLESHOOTING.md`](TROUBLESHOOTING.md).
