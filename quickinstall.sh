#!/usr/bin/env bash
# Huntsman Search Engine — Termux aarch64 quick-install.
#
# ── PUBLIC repo: paste this ONE line ─────────────────────────────────────────
#
#   curl -fsSL "https://raw.githubusercontent.com/EmmmmDeee/Huntsman-Search-Engine-HSE-Termux-Android-Aarch64-Rust-/claude/vigilant-galileo-vmjk3e/quickinstall.sh" | bash
#
# ── PRIVATE repo: paste this block (token prompt, never echoed to screen) ───
#
#   read -rsp $'GitHub token: ' GITHUB_TOKEN && export GITHUB_TOKEN && curl -fsSL -H "Authorization: token $GITHUB_TOKEN" -H "Accept: application/vnd.github.raw" "https://api.github.com/repos/EmmmmDeee/Huntsman-Search-Engine-HSE-Termux-Android-Aarch64-Rust-/contents/quickinstall.sh?ref=claude/vigilant-galileo-vmjk3e" | bash
#
# Or, if you already cloned the repo to ~/hse or ~/hse-src:
#   bash ~/hse/quickinstall.sh          # (set GITHUB_TOKEN first if private)
#
# What it does (in order, stops at first success):
#   1. Finds hse-aarch64-linux-android (or hse) already in your Downloads folder
#      and installs it directly — zero compile, zero network.
#   2. Downloads the latest prebuilt binary from GitHub Releases to Downloads,
#      verifies it runs, then installs — ~30-60 sec on a decent connection.
#   3. Falls back to the full install.sh (compiles from source, ~4-6 min).
#
# Token: set GITHUB_TOKEN (or HSE_GITHUB_TOKEN) in your environment before
#        running if the repository is private. The read -rsp block above does
#        this for you without the token appearing in shell history.
#        Note: raw.githubusercontent.com does not support Authorization headers
#        for private repos — this script uses api.github.com instead.
#
# No root required. Termux F-Droid only. Android API 24+, aarch64.

REPO="EmmmmDeee/Huntsman-Search-Engine-HSE-Termux-Android-Aarch64-Rust-"
BRANCH="claude/vigilant-galileo-vmjk3e"
BIN_NAME="hse-aarch64-linux-android"
DEST="${PREFIX:-/data/data/com.termux/files/usr}/bin/hse"
_STAGE="$HOME/.cache/.hse-qs-$$"

# Honour either spelling; GITHUB_TOKEN takes precedence.
GITHUB_TOKEN="${GITHUB_TOKEN:-${HSE_GITHUB_TOKEN:-}}"

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
[[ -n "$GITHUB_TOKEN" ]] && printf '  (private repo: using GITHUB_TOKEN for auth)\n'
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

# For private repos the direct releases/latest/download URL is gated by auth.
# Use the GitHub API to resolve the asset URL, then download with the token.
# For public repos: fall straight through to the direct URL (no API needed).
_DEST_BIN="$_DL_DIR/$BIN_NAME"
_DOWNLOADED=0
if [[ -n "$GITHUB_TOKEN" ]]; then
    printf '  resolving asset via GitHub API...\n'
    _API_JSON=$(curl -fsSL --connect-timeout 15 \
        -H "Authorization: token $GITHUB_TOKEN" \
        -H "Accept: application/vnd.github+json" \
        "https://api.github.com/repos/$REPO/releases/latest" 2>/dev/null || true)
    _ASSET_URL=$(printf '%s' "$_API_JSON" \
        | grep -o '"browser_download_url":"[^"]*hse-aarch64-linux-android"' \
        | sed 's/.*:"//; s/"$//')
    if [[ -n "$_ASSET_URL" ]]; then
        printf '  downloading from %s\n' "$_ASSET_URL"
        if curl -fSL --connect-timeout 30 --max-time 300 --progress-bar \
                -H "Authorization: token $GITHUB_TOKEN" \
                "$_ASSET_URL" -o "$_DEST_BIN" 2>&1; then
            _DOWNLOADED=1
        fi
    else
        printf '  WARN: no release found via API (no tag pushed yet?). Falling back.\n' >&2
    fi
else
    _GH_URL="https://github.com/$REPO/releases/latest/download/$BIN_NAME"
    printf '  URL: %s\n' "$_GH_URL"
    if curl -fSL --connect-timeout 30 --max-time 300 --progress-bar \
            "$_GH_URL" -o "$_DEST_BIN" 2>&1; then
        _DOWNLOADED=1
    fi
fi

if [[ "$_DOWNLOADED" == "1" ]]; then
    printf '  saved to %s — testing...\n' "$_DEST_BIN"
    _try_bin "$_DEST_BIN" "GitHub Release" || true
    printf '  release binary failed run-test; falling back to source build.\n' >&2
else
    printf '  download failed (no release yet, network error, or auth issue). Falling back.\n' >&2
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
if [[ -n "$GITHUB_TOKEN" ]]; then
    # raw.githubusercontent.com doesn't support Authorization headers for private
    # repos — use the GitHub Contents API with Accept: application/vnd.github.raw
    curl -fsSL \
        -H "Authorization: token $GITHUB_TOKEN" \
        -H "Accept: application/vnd.github.raw" \
        "https://api.github.com/repos/$REPO/contents/install.sh?ref=$BRANCH" | bash
else
    curl -fsSL "https://raw.githubusercontent.com/$REPO/$BRANCH/install.sh" | bash
fi
