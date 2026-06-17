# Troubleshooting

Specific errors and the fix. If your issue isn't here, please
[open a bug](https://github.com/EmmmmDeee/Huntsman-Search-Engine-HSE-Termux-Android-Aarch64-Rust-/issues/new?template=bug_report.md)
and include the full `~/.cache/hse-install.log` plus `hse doctor` output.

## Installation

### `awk: fatal: attempt to access field -2` during sanity checks

Seen on Termux 0.118.x where `df -m $HOME` emits a row with too few
fields and the disk-space probe in `install.sh` indexes a negative
field. Fixed in commit `4ee49ec` (the awk now guards `NF >= 4` and
falls back to "could not read free disk space — skipping check").

If you still hit it, you're on an older `install.sh`. Pull the latest
and retry, or use the manual install path in
[`INSTALL.md`](INSTALL.md#manual-install) which skips the probe.

### `pkg update: failed`

Termux's `pkg` is just a wrapper around `apt` with their package mirror.
This fails for one of:

- **No network.** Confirm with `ping 1.1.1.1`. Switch to Wi-Fi if on a flaky cell connection.
- **Mirror outage.** Use `termux-change-repo` to pick a different mirror.
- **DNS broken.** Try `pkg --check-mirror update` or set DNS manually
  (`echo 'nameserver 1.1.1.1' > $PREFIX/etc/resolv.conf` — usually not needed).

The installer auto-retries `pkg update` 4 times with exponential backoff, so
transient failures resolve themselves.

### `cargo build` fails with `linker 'cc' not found`

You're missing the C toolchain. On Termux:

```bash
pkg install -y clang make pkg-config
```

The installer does this automatically; if you ran `cargo build` manually,
install these first.

### Build OOMs (`signal: 9, SIGKILL: kill`)

Cargo runs `rustc` jobs in parallel. On a phone with < 1.5 GB free RAM
(many Android devices), this exhausts memory. Two workarounds:

```bash
# Limit to one job (slower but reliable):
CARGO_BUILD_JOBS=1 cargo build --release --locked

# Or re-run install.sh — it auto-detects RAM and sets this for you.
```

### `failed to authenticate with the remote: SSL_ERROR_SYSCALL`

System clock is wrong → TLS handshake fails. Fix:

```bash
pkg install termux-tools
date -s "$(curl -fsSL https://www.google.com -I | awk -F': ' '/^[Dd]ate:/ {sub(/\r$/,""); print $2}')"
```

Then retry the install.

### `error: package XYZ has been yanked from the registry`

Stale `Cargo.lock` from a fork. Update:

```bash
cd ~/.local/share/hse && cargo update && cargo build --release
```

### `Out of disk space`

Build artefacts and cargo cache combined can reach 2 GB. Free up:

```bash
rm -rf ~/.cache/hse-build ~/.cargo/registry/cache ~/.cargo/git
cargo build --release   # re-fetches what's needed
```

Or set `CARGO_TARGET_DIR` to external storage:

```bash
termux-setup-storage    # if not done already
export CARGO_TARGET_DIR=/sdcard/hse-build
```

Note: builds to `/sdcard` are slow (FUSE), but workable on low-storage devices.

---

## Runtime

### `hse: command not found` after install

Either `install.sh` finished but `$PREFIX/bin` isn't in `$PATH` (unusual on
Termux), or you installed to `$HOME/.local/bin` on Linux and don't have it
in path:

```bash
# Termux — should already work; if not, re-source:
source $PREFIX/etc/profile

# Linux / macOS:
echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc
source ~/.bashrc
```

### `hse scan` returns 0 entities but I expected results

Several possibilities:

1. **No network.** Almost every module needs network; the exceptions are the
   local-only derivers (e.g. `name_intel`, `email_parse`, `email_canonical`,
   `username_variants`) and the on-device sensors. Confirm with
   `curl -I https://crt.sh`.
2. **Wrong target kind for the module.** Run `hse modules` and check the
   `ACCEPTS` column. E.g. `hudsonrock` accepts `email` and `domain` only —
   passing `--kind username` will skip it.
3. **All modules filtered out.** Check `--modules`, `--exclude`, `--free-only`,
   `--passive-only` flags aren't overly restrictive. With `RUST_LOG=debug`
   you'll see `ModuleSkipped` events with the reason.
4. **Upstream API returned no hits.** Genuine zero. Try `--output json` to
   see the full scan record, including any `ModuleError` evidence.

### Expansion doesn't trigger even with `--depth 2`

Default `--min-expand-confidence` is 0.50 (Probable tier). Entities below this
are deliberately not expanded, to avoid runaway speculation. Lower the bar:

```bash
hse scan --kind domain --value example.com --depth 2 --min-expand-confidence 0.4
```

Or use specific modules that produce high-confidence entities (`dns_intel`
resolves A records at high confidence, which always expand).

### `database is locked`

Two HSE processes scanning concurrently against the same DB. SQLite WAL
handles concurrent reads, but writes serialise. Solutions:

- Wait for the other scan to finish.
- Use `HSE_DB=$HOME/.huntsman/other.db hse scan ...` to use a different
  database (note: not yet a CLI flag; configure via env if needed in v0.3+).

### `module timeout` on every module

`MODULE_TIMEOUT_MS = 3000` is fixed at compile time as an architecture
invariant, but per-scan you can override with `--timeout 10000` (10 s).
Useful on slow cell connections.

### `error sending request for url (https://crt.sh/...): error trying to connect`

Module-specific network failure — not fatal to the scan, just that module
produced nothing. Common causes:

- Site temporarily down. Retry later.
- ISP blocks the target (some carriers block `crt.sh`). Try via a VPN.
- TLS issue. See clock-skew fix above.

### `permission denied (os error 13)` on `/data/data/com.termux/...`

This shouldn't happen for HSE's own paths. If it does, your `$HOME` has
weird permissions:

```bash
chmod 700 $HOME $HOME/.huntsman 2>/dev/null
chmod 600 $HOME/.huntsman.env 2>/dev/null
```

---

## Termux-specific

### Termux says "Bootstrap installation failed"

Old Termux from Google Play. **Uninstall and reinstall from F-Droid:**
<https://f-droid.org/en/packages/com.termux/>. The Play Store version is
deprecated and broken.

### `termux-location` / `termux-wifi-scaninfo` returns nothing (v0.6+ sensor modules)

You need both the package and the companion app:

```bash
pkg install termux-api    # provides the CLI binaries
# Then install "Termux:API" app from F-Droid
```

Then grant Location / Wi-Fi permissions to the Termux:API app via Android
settings. Without the app, the binaries print nothing on stdout — sensor
modules treat this as "no data" and return empty results.

### Cell info empty even with termux-api

Android Q+ restricts cell-tower data to "fine location" + foreground apps.
Termux:API must be allowed background location use:

`Settings → Apps → Termux:API → Permissions → Location → Allow all the time`

### Database file is huge

After many scans, the SQLite file can grow. Compact it:

```bash
sqlite3 ~/.huntsman/huntsman.db 'VACUUM;'
```

Note: needs `pkg install sqlite`. Or just delete it — HSE recreates the
schema on next run (you lose history, of course).

---

## Reporting a bug

Please include:

- Output of `hse doctor`.
- Output of the failing command run with `RUST_LOG=debug`.
- Last 50 lines of `~/.cache/hse-install.log` if install-related.
- Your Termux version (`termux-info | head -20` if termux-api installed,
  otherwise the version shown when Termux launches).
- `uname -srm`.

[File a bug](https://github.com/EmmmmDeee/Huntsman-Search-Engine-HSE-Termux-Android-Aarch64-Rust-/issues/new?template=bug_report.md).
