# Installation

HSE targets **Termux on Android aarch64** (no root required). The same
`install.sh` also works on Linux and macOS with Rust 1.88+.

---

## Install prebuilt binary (recommended — no toolchain, no compile)

Download **`hse-aarch64-linux-android`** and its **`.sha256`** sidecar from
the [GitHub Releases page](https://github.com/EmmmmDeee/Huntsman-Search-Engine-HSE-Termux-Android-Aarch64-Rust-/releases/latest)
in Chrome (both land in your Downloads folder), then run the curl installer
below (or `bash install.sh` from a manual clone). Its prebuilt-binary scan
(`maybe_use_prebuilt` in `install.sh`) finds the file in Downloads / shared
storage, verifies it (size + ELF magic + the `.sha256` sidecar + an actual
`--version` run-test), and installs it directly — **no Rust toolchain, no
compile, seconds instead of minutes**. This is also the automatic fallback
when the on-device build can't proceed (e.g. a broken Termux `rust` package),
and the installer can fetch this same asset over the network itself if you
skip the manual download (see "No-build fast path" in the main
[README](../README.md)).

**Storage permission (one-time, only needed to read the Downloads folder):**
Android Settings → Apps → Termux → Permissions → Files and media → **Allow
management of all files**.

Knobs: point at a file that isn't in a scanned Downloads path with
`HSE_PREBUILT=/path/to/hse`, skip the scan entirely with `HSE_PREFER_BUILD=1`.

---

## Install via curl (internet required)

```bash
curl -fsSL https://raw.githubusercontent.com/EmmmmDeee/Huntsman-Search-Engine-HSE-Termux-Android-Aarch64-Rust-/main/install.sh | bash
```

Private repo — supply a token (never echoed to screen). This fetches
install.sh's own text via the GitHub Contents API; it does **not** by itself
authenticate the source clone install.sh performs internally, which still
needs credentials of its own (see the `GITHUB_TOKEN` row below):

```bash
read -rsp 'GitHub token: ' GITHUB_TOKEN && export GITHUB_TOKEN
curl -fsSL \
  -H "Authorization: token $GITHUB_TOKEN" \
  -H "Accept: application/vnd.github.raw" \
  "https://api.github.com/repos/EmmmmDeee/Huntsman-Search-Engine-HSE-Termux-Android-Aarch64-Rust-/contents/install.sh?ref=main" \
  | bash
```

---

## After install

```bash
hse --version        # confirm install
hse doctor           # environment report
hse-bg start         # start web server with Android wake-lock
# Open Chrome → http://127.0.0.1:8080
```

To stop the server:
```bash
hse-bg stop
```

---

## Environment knobs

| Variable | Default | Purpose |
|----------|---------|--------|
| `HSE_BUILD_PROFILE` | `fast` (Termux) / `release` (Linux/macOS) | `fast` ≈ 4-6 min; `release` ≈ 15-20 min, smaller binary |
| `HSE_INSTALL_DIR` | `~/.local/share/hse` | Source clone location (curl mode only) |
| `HSE_REF` | `main` | Branch/tag/SHA to install |
| `HSE_REPO_URL` | upstream GitHub URL | Override for forks; embed a token here (`https://<token>@github.com/...`) or use an `ssh://` URL to authenticate install.sh's own internal `git clone`/`fetch` against a private repo |
| `GITHUB_TOKEN` | (none) | **Not read by install.sh itself.** Only used by the private-repo curl example above — a PAT to fetch install.sh's own text via the GitHub Contents API. It does not authenticate the source clone; see `HSE_REPO_URL` for that |
| `HSE_PREFER_BUILD` | `0` | `1` = skip the prebuilt scan/download, always build from source |
| `HSE_PREBUILT` | (none) | Path to a specific prebuilt binary to install (skips the Downloads-folder scan) |
| `HSE_PREBUILT_TAG` | `latest` | Pin the release tag to download the prebuilt binary from |
| `HSE_NO_DOWNLOAD` | `0` | `1` = don't fetch the prebuilt binary from GitHub Releases over the network |
| `HSE_KEEP_MIRROR` | `0` | `1` = keep your own `termux-change-repo` package-mirror choice instead of the installer pinning Termux's apt sources to the Cloudflare CDN mirror |
| `CARGO_TARGET_DIR` | `~/.cache/hse-build` | Build artefact location |

---

## Manual build (Termux)

```bash
pkg install -y rust clang make pkg-config openssl-tool
git clone --depth 1 \
  https://github.com/EmmmmDeee/Huntsman-Search-Engine-HSE-Termux-Android-Aarch64-Rust-.git \
  ~/hse
cd ~/hse
cargo build --profile fast --locked
install -m755 target/fast/hse "$PREFIX/bin/hse"
hse doctor
```

---

## Storage paths

| What | Where |
|------|-------|
| Binary | `$PREFIX/bin/hse` |
| Database | `~/.huntsman/huntsman.db` |
| API keys | `~/.huntsman.env` (chmod 0600) |
| Build cache | `~/.cache/hse-build/` |
| Install log | `~/.cache/hse-install.log` |

---

## Uninstall

```bash
rm -f "$PREFIX/bin/hse" "$PREFIX/bin/hse-bg"
rm -rf ~/.local/share/hse ~/.cache/hse-build ~/.huntsman ~/.cache/hse-install.log
rm -f ~/.huntsman.env   # caution: back up your API keys first
```

---

## Troubleshooting

**"Permission denied" when copying HSE.zip**
The zip is in Android's scoped storage. Fix:
- Android Settings → Apps → Termux → Permissions → Files and media → Allow management of all files
- Then retry the install command

**Build hangs / appears frozen**
The final link step (`Compiling huntsman-search-engine`) emits no output for
several minutes on aarch64 — this is normal. The installer prints a heartbeat
every 30 s. Do not interrupt.

**"cargo: not found"**
Run `pkg install rust` and retry.

**Low RAM (< 1.5 GB)**
Set `CARGO_BUILD_JOBS=1` before running the installer to limit parallel compilation.

See [`TROUBLESHOOTING.md`](TROUBLESHOOTING.md) for a full list of known issues.
