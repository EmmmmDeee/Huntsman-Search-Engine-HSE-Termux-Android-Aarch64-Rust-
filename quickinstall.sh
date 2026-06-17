#!/usr/bin/env bash
# Huntsman Search Engine — Termux aarch64 quick-install.
#
# Paste this ONE command into Termux and press Enter:
#
#   curl -fsSL https://raw.githubusercontent.com/EmmmmDeee/Huntsman-Search-Engine-HSE-Termux-Android-Aarch64-Rust-/claude/vigilant-galileo-vmjk3e/quickinstall.sh | bash
#
# Or, if you already cloned the repo to ~/hse or ~/hse-src:
#   bash ~/hse/quickinstall.sh
#
# What it does (in order, stops at first success):
#   1. Finds hse-aarch64-linux-android (or hse) already in your Downloads folder
#      and installs it directly — zero compile, zero network.
#   2. Downloads the latest prebuilt binary from GitHub Releases to Downloads,
#      verifies it runs, then installs — ~30-60 sec on a decent connection.
#   3. Falls back to the full install.sh (compiles from source, ~4-6 min).
#
# No root required. Termux F-Droid only. Android API 24+, aarch64.

REPO="EmmmmDeee/Huntsman-Search-Engine-HSE-Termux-Android-Aarch64-Rust-"
BRANCH="claude/vigilant-galileo-vmjk3e"
BIN_NAME="hse-aarch64-linux-android"
DEST="${PREFIX:-/data/data/com.termux/files/usr}/bin/hse"
_STAGE="$HOME/.cache/.hse-qs-$$"

trap 'rm -f "$_STAGE"' EXIT

# sdcard is mounted noexec, so copy the candidate to $HOME/.cache before
# the run-test — that path is always executable in Termux.
_try_bin() {
    local src="$1" label="$2"
    cp "$src" "$_STAGE" 2>/dev/null && chmod 755 "$_STAGE" || return 1
    if "$_STAGE" --version >/dev/null 2>&1; then
        install -m755 "$_STAGE" "$DEST"
        printf '  installed → %s\n' "$DEST"
        "$DEST" --version
        exit 0
    fi
    printf '  WARN: binary at %s failed run-test (wrong arch or corrupt)\n' "$label" >&2
    return 1
}

# ─── 1. Scan Download directories ─────────────────────────────────────────────
printf '\n==> HSE quick-install\n'
printf '  step 1/3 — scanning Downloads for an existing prebuilt...\n'
for _D in \
    "$HOME/storage/downloads" \
    "$HOME/storage/shared/Download" "$HOME/storage/shared/Downloads" \
    "/storage/emulated/0/Download" "/storage/emulated/0/Downloads" \
    "/sdcard/Download" "/sdcard/Downloads" \
    "$HOME/Downloads" "$HOME/Download"
do
    [[ -d "$_D" ]] || continue
    for _N in "$BIN_NAME" "hse"; do
        if [[ -f "$_D/$_N" ]]; then
            printf '  found: %s/%s — testing...\n' "$_D" "$_N"
            _try_bin "$_D/$_N" "$_D/$_N"
        fi
    done
done
printf '  nothing usable found in Downloads.\n'

# ─── 2. GitHub Releases download ──────────────────────────────────────────────
printf '  step 2/3 — downloading latest prebuilt from GitHub Releases...\n'
_DL_DIR="$HOME/storage/downloads"
if [[ ! -d "$_DL_DIR" ]] || [[ ! -w "$_DL_DIR" ]]; then
    _DL_DIR="$HOME/.cache/hse-dl"
    mkdir -p "$_DL_DIR"
fi
_GH_URL="https://github.com/$REPO/releases/latest/download/$BIN_NAME"
printf '  URL: %s\n' "$_GH_URL"
if curl -fSL --progress-bar "$_GH_URL" -o "$_DL_DIR/$BIN_NAME" 2>&1; then
    printf '  saved to %s — testing...\n' "$_DL_DIR/$BIN_NAME"
    _try_bin "$_DL_DIR/$BIN_NAME" "GitHub Release" || true
    printf '  release binary failed run-test; falling back to source build.\n' >&2
else
    printf '  download failed (no release yet, or no network). Falling back.\n' >&2
fi

# ─── 3. Full install.sh fallback ──────────────────────────────────────────────
printf '  step 3/3 — running full install.sh (compiles from source, ~4-6 min)...\n'
for _C in "$HOME/hse" "$HOME/hse-src" "$HOME/.local/share/hse"; do
    if [[ -f "$_C/install.sh" ]]; then
        printf '  using existing clone at %s\n' "$_C"
        exec bash "$_C/install.sh"
    fi
done
printf '  fetching install.sh from GitHub...\n'
curl -fsSL "https://raw.githubusercontent.com/$REPO/$BRANCH/install.sh" | bash
