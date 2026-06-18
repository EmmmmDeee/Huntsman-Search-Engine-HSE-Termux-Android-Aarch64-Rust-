# Installation

HSE targets **Termux on Android aarch64** (no root required). The same
`install.sh` also works on Linux and macOS with Rust 1.88+.

---

## Install from zip (recommended — works offline)

Download **HSE.zip** from the GitHub Releases page in Chrome on your phone,
then run these three commands in Termux:

```bash
# Step 1 — grant storage access (one-time setup)
termux-setup-storage
# Tap Allow in the Android dialog, then:
# Settings → Apps → Termux → Permissions → Files and media
#   → Allow management of all files

# Step 2 — copy and extract
cp ~/storage/downloads/HSE.zip ~/ && unzip -q ~/HSE.zip

# Step 3 — install
bash ~/Huntsman*/install.sh
```

The installer detects it’s running inside the extracted source tree and
handles everything automatically:
1. Checks for a prebuilt `hse-aarch64-linux-android` binary inside the zip
   (instant install, no compile).
2. If no prebuilt is bundled, runs `cargo build` from the source in the zip
   (~4-6 min on aarch64 with the `fast` profile).
3. Installs `hse` to `$PREFIX/bin`, sets up the `hse-bg` background wrapper,
   and writes a keys template to `~/.huntsman.env`.

After the first source build the binary is cached to your Downloads folder, so
re-installing (after a wipe, or on another aarch64 phone) skips the compile.

---

## Install via curl (internet required)

```bash
curl -fsSL https://raw.githubusercontent.com/EmmmmDeee/Huntsman-Search-Engine-HSE-Termux-Android-Aarch64-Rust-/claude/vigilant-galileo-vmjk3e/install.sh | bash
```

Private repo — supply a token (never echoed to screen):

```bash
read -rsp 'GitHub token: ' GITHUB_TOKEN && export GITHUB_TOKEN
curl -fsSL \
  -H "Authorization: token $GITHUB_TOKEN" \
  -H "Accept: application/vnd.github.raw" \
  "https://api.github.com/repos/EmmmmDeee/Huntsman-Search-Engine-HSE-Termux-Android-Aarch64-Rust-/contents/install.sh?ref=claude/vigilant-galileo-vmjk3e" \
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
| `HSE_REF` | `claude/vigilant-galileo-vmjk3e` | Branch/tag/SHA to install |
| `HSE_REPO_URL` | upstream GitHub URL | Override for forks |
| `GITHUB_TOKEN` | (none) | PAT for private repo clone/download |
| `HSE_PREFER_BUILD` | `0` | `1` = skip prebuilt scan, always build |
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
The zip is in Android’s scoped storage. Fix:
- Run `termux-setup-storage` and tap Allow
- Android Settings → Apps → Termux → Permissions → Files and media → Allow management of all files
- Then retry `cp ~/storage/downloads/HSE.zip ~/`

**Build hangs / appears frozen**
The final link step (`Compiling huntsman-search-engine`) emits no output for
several minutes on aarch64 — this is normal. The installer prints a heartbeat
every 30 s. Do not interrupt.

**"cargo: not found"**
Run `pkg install rust` and retry.

**Low RAM (< 1.5 GB)**
Set `CARGO_BUILD_JOBS=1` before running the installer to limit parallel compilation.

See [`TROUBLESHOOTING.md`](TROUBLESHOOTING.md) for a full list of known issues.
