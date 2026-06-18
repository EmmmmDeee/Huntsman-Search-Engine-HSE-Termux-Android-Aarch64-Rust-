#!/usr/bin/env bash
# Huntsman Search Engine — installer
#
# ZIP INSTALL (recommended — no internet needed after download):
#   1. Download HSE.zip from the GitHub Releases page in Chrome
#   2. In Termux:
#        cp ~/storage/downloads/HSE.zip ~/ && unzip -q ~/HSE.zip
#   3. Run: bash ~/Huntsman*/install.sh
#
# CURL INSTALL (internet required):
#   curl -fsSL https://raw.githubusercontent.com/EmmmmDeee/Huntsman-Search-Engine-HSE-Termux-Android-Aarch64-Rust-/claude/vigilant-galileo-vmjk3e/install.sh | bash
#
# ENV KNOBS (all optional):
#   HSE_BUILD_PROFILE  fast|release  (fast ≈ 4-6 min on aarch64; default on Termux)
#   HSE_REPO_URL       Git URL override (for forks)
#   HSE_REF            Branch/tag/SHA to install (default: claude/vigilant-galileo-vmjk3e)
#   HSE_INSTALL_DIR    Where to clone source in curl mode (default: ~/.local/share/hse)
#   GITHUB_TOKEN       Personal access token for private repo access
#   HSE_PREFER_BUILD   1 = skip prebuilt scan, always build from source

set -euo pipefail

# ── Logging ─────────────────────────────────────────────────────
LOG="$HOME/.cache/hse-install.log"
mkdir -p "$HOME/.cache"
: > "$LOG"
exec > >(tee -a "$LOG") 2>&1

[[ -t 1 ]] \
    && { C0=$'\033[0m' CB=$'\033[1m' CG=$'\033[0;32m' CY=$'\033[1;33m' CR=$'\033[0;31m' CC=$'\033[0;36m'; } \
    || { C0= CB= CG= CY= CR= CC=; }

step() { printf "${CC}==>%s ${CB}%s%s\n" "" "$*" "$C0"; }
ok()   { printf "  ${CG}✓%s %s\n" "$C0" "$*"; }
warn() { printf "  ${CY}!%s %s\n" "$C0" "$*" >&2; }
die()  { printf "  ${CR}✗%s %s\n" "$C0" "$*" >&2; printf 'Log: %s\n' "$LOG"; exit 1; }

HB_PID=""; STAGE="$HOME/.cache/.hse-stage-$$"
trap '{ [[ -n "$HB_PID" ]] && kill "$HB_PID" 2>/dev/null || true; rm -f "$STAGE"; }' EXIT

# ── Environment ─────────────────────────────────────────────────────
IS_TERMUX=0
[[ -n "${TERMUX_VERSION:-}" || -d /data/data/com.termux ]] && IS_TERMUX=1
: "${PREFIX:=/data/data/com.termux/files/usr}"
DEST_DIR="$([[ $IS_TERMUX -eq 1 ]] && echo "$PREFIX/bin" || echo "$HOME/.local/bin")"
mkdir -p "$DEST_DIR"

# Detect zip/local mode: if Cargo.toml is alongside this script, use that source
# directory directly — no cloning, no internet needed for the source.
_SD="$(cd "$(dirname "${BASH_SOURCE[0]:-}")" 2>/dev/null && pwd || true)"
LOCAL_SRC=""
if [[ -n "$_SD" && -f "$_SD/Cargo.toml" ]] \
   && grep -q 'huntsman-search-engine' "$_SD/Cargo.toml" 2>/dev/null; then
    LOCAL_SRC="$_SD"
fi

step "HSE installer"
[[ -n "$LOCAL_SRC" ]] \
    && ok "Mode: local/zip ($LOCAL_SRC) — no git or internet required" \
    || ok "Mode: curl/remote — will clone from GitHub"
[[ $IS_TERMUX -eq 1 ]] && ok "Termux ${TERMUX_VERSION:-detected}" || ok "Standard Unix environment"

# ── Prebuilt binary scan ───────────────────────────────────────────────────
# Try a candidate binary: copy to cache (sdcard is noexec), run-test, install.
_try() {
    local src="$1"
    [[ -f "$src" ]] || return 1
    cp "$src" "$STAGE" 2>/dev/null && chmod 755 "$STAGE" || return 1
    local v
    v=$("$STAGE" --version 2>/dev/null) && [[ "$v" == hse\ * ]] \
        || { warn "skip $(basename "$src") — wrong arch or corrupt"; return 1; }
    install -m755 "$STAGE" "$DEST_DIR/hse"
    ok "Installed prebuilt: $DEST_DIR/hse ($v)"
    return 0
}

INSTALLED=0
if [[ "${HSE_PREFER_BUILD:-0}" != "1" ]]; then
    step "Scanning for prebuilt aarch64 binary"
    # 1. Same directory as install.sh (inside extracted zip)
    if [[ -n "$LOCAL_SRC" ]]; then
        for _n in hse-aarch64-linux-android hse-aarch64 hse; do
            _try "$LOCAL_SRC/$_n" && { INSTALLED=1; break; } || true
        done
    fi
    # 2. Downloads folder
    if [[ "$INSTALLED" != "1" ]]; then
        for _d in "$HOME/storage/downloads" "/storage/emulated/0/Download" "$HOME/Downloads"; do
            [[ -d "$_d" ]] || continue
            for _n in hse-aarch64-linux-android hse; do
                _try "$_d/$_n" && { INSTALLED=1; break 2; } || true
            done
        done
    fi
    [[ "$INSTALLED" == "1" ]] || ok "No prebuilt found — will build from source"
fi

# ── Source build ──────────────────────────────────────────────────────
if [[ "$INSTALLED" != "1" ]]; then
    if [[ -n "$LOCAL_SRC" ]]; then
        SRC="$LOCAL_SRC"
    else
        REPO="${HSE_REPO_URL:-https://github.com/EmmmmDeee/Huntsman-Search-Engine-HSE-Termux-Android-Aarch64-Rust-.git}"
        REF="${HSE_REF:-claude/vigilant-galileo-vmjk3e}"
        SRC="${HSE_INSTALL_DIR:-$HOME/.local/share/hse}"
        _REMOTE="$REPO"
        [[ -n "${GITHUB_TOKEN:-}" && "$REPO" == https://github.com/* ]] && \
            _REMOTE="https://x-access-token:${GITHUB_TOKEN}@${REPO#https://}"
        step "Cloning source → $SRC"
        export GIT_TERMINAL_PROMPT=0
        mkdir -p "$(dirname "$SRC")"
        if [[ -d "$SRC/.git" ]]; then
            git -C "$SRC" remote set-url origin "$_REMOTE" 2>/dev/null || true
            git -C "$SRC" fetch --depth 1 origin "$REF" \
                || die "git fetch failed — private repo? Set: export GITHUB_TOKEN=<your-token>"
            git -C "$SRC" checkout -B "$REF" "origin/$REF"
            ok "Updated: $SRC"
        else
            git clone --depth 1 --branch "$REF" "$_REMOTE" "$SRC" \
                || die "git clone failed — private repo? Set: export GITHUB_TOKEN=<your-token>"
            ok "Cloned: $SRC"
        fi
    fi

    step "Installing build dependencies"
    if [[ $IS_TERMUX -eq 1 ]]; then
        pkg install -y rust binutils clang make pkg-config openssl-tool 2>/dev/null || true
    fi
    command -v cargo >/dev/null 2>&1 || die "cargo not found — on Termux: pkg install rust"
    ok "rustc $(rustc --version | awk '{print $2}')"

    PROFILE="${HSE_BUILD_PROFILE:-$([[ $IS_TERMUX -eq 1 ]] && echo fast || echo release)}"
    [[ "$PROFILE" == fast ]] && ETA="~4-6 min" || ETA="~15-20 min"
    step "Building HSE [profile=$PROFILE, $ETA on aarch64]"
    warn "The final link step is silent for a few minutes — do not interrupt"

    export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$HOME/.cache/hse-build}"
    export CARGO_TERM_PROGRESS_WHEN=always
    export CARGO_TERM_PROGRESS_WIDTH=70
    if [[ $IS_TERMUX -eq 1 ]]; then
        export TMPDIR="${TMPDIR:-$HOME/tmp}"
        mkdir -p "$TMPDIR"
    fi
    mkdir -p "$CARGO_TARGET_DIR"

    _t0=$(date +%s)
    (while sleep 30; do
        printf '    … still compiling (%ds elapsed)\n' "$(( $(date +%s) - _t0 ))"
    done) &
    HB_PID=$!

    (cd "$SRC" && cargo build --profile "$PROFILE" --locked) \
        || die "Build failed — see: $LOG"

    kill "$HB_PID" 2>/dev/null; HB_PID=""

    BUILT="$CARGO_TARGET_DIR/$PROFILE/hse"
    [[ -x "$BUILT" ]] || die "Binary missing after build: $BUILT"
    ok "Built: $BUILT"

    _T="$DEST_DIR/.hse.new.$$"
    install -m755 "$BUILT" "$_T" && mv -f "$_T" "$DEST_DIR/hse" \
        || { rm -f "$_T"; die "Install failed — is $DEST_DIR writable?"; }
    ok "Installed: $DEST_DIR/hse ($($DEST_DIR/hse --version))"

    # Cache built binary to Downloads so the next install is instant (no recompile)
    if [[ $IS_TERMUX -eq 1 ]]; then
        for _dl in "$HOME/storage/downloads" "/storage/emulated/0/Download"; do
            [[ -d "$_dl" && -w "$_dl" ]] \
                && cp -f "$BUILT" "$_dl/hse-aarch64-linux-android" 2>/dev/null \
                && { ok "Cached prebuilt → $_dl/hse-aarch64-linux-android"; break; } || true
        done
    fi
fi

# ── hse-bg background wrapper (Termux) ─────────────────────────────────────────────
if [[ $IS_TERMUX -eq 1 ]]; then
    cat > "$DEST_DIR/hse-bg" << 'HSE_BG'
#!/data/data/com.termux/files/usr/bin/bash
P="$HOME/.cache/hse-bg.pid"
L="$HOME/.cache/hse-bg.log"
mkdir -p "$(dirname "$P")"
case "${1:-start}" in
  start)
    [[ -f "$P" ]] && kill -0 "$(cat "$P")" 2>/dev/null \
        && { echo "Already running (pid $(cat "$P"))"; exit 0; }
    command -v termux-wake-lock >/dev/null && termux-wake-lock
    nohup hse serve >> "$L" 2>&1 &
    echo $! > "$P"
    echo "Started (pid $!). Open: http://127.0.0.1:8080 in Chrome"
    ;;
  stop)
    [[ -f "$P" ]] && kill "$(cat "$P")" 2>/dev/null
    rm -f "$P"
    command -v termux-wake-unlock >/dev/null && termux-wake-unlock
    echo "Stopped."
    ;;
  status)
    [[ -f "$P" ]] && kill -0 "$(cat "$P")" 2>/dev/null \
        && echo "Running (pid $(cat "$P"))" || echo "Not running"
    ;;
  log)
    tail -f "$L"
    ;;
  *)
    echo "Usage: hse-bg [start|stop|status|log]"
    ;;
esac
HSE_BG
    chmod 755 "$DEST_DIR/hse-bg"
    ok "Installed hse-bg (start|stop|status|log)"
fi

# ── API keys template ─────────────────────────────────────────────────────
KEYS="$HOME/.huntsman.env"
if [[ ! -f "$KEYS" ]]; then
    cat > "$KEYS" << 'KEYS_EOF'
# HSE API keys — uncomment and paste a value to enable key-gated modules.
# File is chmod 0600. Never commit it. The Settings page (hse serve → Settings)
# lets you paste and save keys from the browser.
#
#HUNTSMAN_HIBP_KEY=
#HUNTSMAN_SHODAN_KEY=
#HUNTSMAN_DEHASHED_KEY=
#HUNTSMAN_HUNTER_KEY=
#HUNTSMAN_VIRUSTOTAL_KEY=
#HUNTSMAN_SECTRAILS_KEY=
#HUNTSMAN_LEAKIX_KEY=
#HUNTSMAN_WIGLE_USER=
#HUNTSMAN_WIGLE_TOKEN=
#HUNTSMAN_IPQS_KEY=
#HUNTSMAN_CRIMINALIP_KEY=
#HUNTSMAN_EMAILREP_KEY=
#HUNTSMAN_EXA_KEY=
#
# Optional: set a default scan seed so bare `hse scan` works without --value.
# Read only from this file — never embedded in the binary or sent anywhere.
#HUNTSMAN_DEFAULT_SEED=
KEYS_EOF
    chmod 0600 "$KEYS"
    ok "Created ~/.huntsman.env (chmod 0600)"
else
    ok "Keys file already present: $KEYS"
fi

# ── Verify ─────────────────────────────────────────────────────────────────
step "Verifying installation"
"$DEST_DIR/hse" --version
"$DEST_DIR/hse" doctor

echo
printf '%s%s==> Done!%s\n' "$CG" "$CB" "$C0"
if [[ $IS_TERMUX -eq 1 ]]; then
    printf '  hse-bg start   → runs in background with wake-lock\n'
    printf '  Chrome: http://127.0.0.1:8080\n'
else
    printf '  hse serve   → http://127.0.0.1:8080\n'
fi
printf '  Install log: %s\n' "$LOG"

trap - EXIT
