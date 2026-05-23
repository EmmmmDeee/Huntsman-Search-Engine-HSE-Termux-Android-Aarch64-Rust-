#!/usr/bin/env bash
# Huntsman Search Engine (HSE) — one-shot installer.
#
# Designed primarily for Termux on Android aarch64 (no root). Also works on
# any Linux / macOS with rustc 1.85+ and git. Idempotent: re-running upgrades
# in place.
#
# Usage (Termux or any Unix):
#   curl -fsSL https://raw.githubusercontent.com/EmmmmDeee/Huntsman-Search-Engine-HSE-Termux-Android-Aarch64-Rust-/main/install.sh | bash
#
# Or, if you've already cloned the repo:
#   ./install.sh
#
# Environment knobs (all optional):
#   HSE_INSTALL_DIR   Where to clone the source (default: $HOME/.local/share/hse)
#   HSE_BIN_DIR       Where to install the binary (default: $PREFIX/bin on Termux, $HOME/.local/bin elsewhere)
#   HSE_REF           Git ref to install (branch / tag / SHA). Default: main
#   HSE_REPO_URL      Upstream URL (default: the GitHub repo)
#   HSE_INSTALL_DEBUG Set to 1 to enable shell trace (set -x)
#   HSE_SKIP_BUILD    Set to 1 to clone-only and stop before cargo build
#   HSE_NO_PKG        Set to 1 to skip `pkg`/`apt` install (assume deps present)
#
# Log file:
#   $HOME/.cache/hse-install.log  (everything captured for post-mortem)

set -euo pipefail
[[ "${HSE_INSTALL_DEBUG:-0}" == "1" ]] && set -x

# ─── Logging ─────────────────────────────────────────────────────────────────
LOG_DIR="$HOME/.cache"
mkdir -p "$LOG_DIR"
LOG_FILE="$LOG_DIR/hse-install.log"
: > "$LOG_FILE"

# Mirror everything to the log file from here on.
exec > >(tee -a "$LOG_FILE") 2>&1

if [[ -t 1 ]]; then
    BOLD=$'\033[1m'; DIM=$'\033[2m'; RED=$'\033[0;31m'; GREEN=$'\033[0;32m'
    YELLOW=$'\033[1;33m'; BLUE=$'\033[0;34m'; CYAN=$'\033[0;36m'; NC=$'\033[0m'
else
    BOLD=""; DIM=""; RED=""; GREEN=""; YELLOW=""; BLUE=""; CYAN=""; NC=""
fi

step() { printf "${BLUE}==>${NC} ${BOLD}%s${NC}\n" "$*"; }
ok()   { printf "  ${GREEN}✓${NC} %s\n" "$*"; }
warn() { printf "  ${YELLOW}!${NC} %s\n" "$*"; }
die()  { printf "  ${RED}✗${NC} %s\n" "$*" >&2; echo; echo "Full log: $LOG_FILE"; exit 1; }
hint() { printf "    ${DIM}%s${NC}\n" "$*"; }

on_exit() {
    local rc=$?
    if [[ $rc -ne 0 ]]; then
        printf '\n%sInstallation failed (exit %d).%s\n  Full log: %s\n' "$RED" "$rc" "$NC" "$LOG_FILE" >&2
    fi
}
trap on_exit EXIT

# ─── Defaults ────────────────────────────────────────────────────────────────
HSE_REPO_URL="${HSE_REPO_URL:-https://github.com/EmmmmDeee/Huntsman-Search-Engine-HSE-Termux-Android-Aarch64-Rust-.git}"
HSE_REF="${HSE_REF:-main}"
HSE_INSTALL_DIR="${HSE_INSTALL_DIR:-$HOME/.local/share/hse}"
RUST_MIN_VERSION="1.88"

# ─── Detect environment ──────────────────────────────────────────────────────
step "Detecting environment"

IS_TERMUX=0
if [[ -n "${TERMUX_VERSION:-}" ]] || [[ -d /data/data/com.termux ]]; then
    IS_TERMUX=1
    ok "Termux ${TERMUX_VERSION:-(version unknown)}"
else
    ok "Standard Unix environment"
fi

OS="$(uname -s)"
ARCH="$(uname -m)"
ok "OS=$OS  ARCH=$ARCH"

case "$ARCH" in
    aarch64|arm64) : ;;
    x86_64|amd64)  warn "Untested arch ($ARCH); proceeding — please report any issues" ;;
    *)             warn "Unusual arch ($ARCH); installation may not work" ;;
esac

# Termux quirks: PREFIX defaults to /data/data/com.termux/files/usr.
if [[ $IS_TERMUX -eq 1 ]]; then
    : "${PREFIX:=/data/data/com.termux/files/usr}"
    HSE_BIN_DIR="${HSE_BIN_DIR:-$PREFIX/bin}"
else
    HSE_BIN_DIR="${HSE_BIN_DIR:-$HOME/.local/bin}"
fi
mkdir -p "$HSE_BIN_DIR"

# ─── Sanity checks ───────────────────────────────────────────────────────────
step "Sanity checks"

# Clock — TLS handshakes fail with a wildly wrong clock.
CURRENT_YEAR="$(date +%Y)"
if [[ "$CURRENT_YEAR" -lt 2024 ]]; then
    warn "System clock looks wrong ($(date)). TLS will likely fail."
    hint "Fix on Termux: Android Settings -> System -> Date & time -> Set automatically"
    hint "Or manually: date -s 'YYYY-MM-DD HH:MM:SS'"
fi

# Disk space — release build takes ~500MB, target dir up to 2GB.
# Use END + NF-based indexing — robust to df wrapping long filesystem names
# onto a second line (per gemini-code-assist review on PR #4).
if command -v df >/dev/null 2>&1; then
    DISK_AVAIL_MB=$(df -m "$HOME" 2>/dev/null | awk 'END {print $(NF-2)}')
    if ! [[ "$DISK_AVAIL_MB" =~ ^[0-9]+$ ]]; then
        DISK_AVAIL_MB=0
    fi
    if [[ "$DISK_AVAIL_MB" -lt 2048 ]]; then
        warn "Only ${DISK_AVAIL_MB}MB free in \$HOME. Build needs ~2GB."
        hint "Free space or set HSE_INSTALL_DIR / CARGO_TARGET_DIR to a larger volume."
    else
        ok "Disk: ${DISK_AVAIL_MB}MB free"
    fi
fi

# Memory — cargo can OOM with <1GB on aarch64; recommend swap.
if [[ -r /proc/meminfo ]]; then
    MEM_TOTAL_MB=$(awk '/^MemTotal/ {print int($2/1024)}' /proc/meminfo)
    if [[ "$MEM_TOTAL_MB" -lt 1500 ]]; then
        warn "Only ${MEM_TOTAL_MB}MB RAM. Build may OOM."
        hint "Workaround: set CARGO_BUILD_JOBS=1 to limit parallelism."
        export CARGO_BUILD_JOBS=1
    else
        ok "RAM: ${MEM_TOTAL_MB}MB"
    fi
fi

# ─── Install system dependencies ─────────────────────────────────────────────
if [[ "${HSE_NO_PKG:-0}" != "1" ]]; then
    if [[ $IS_TERMUX -eq 1 ]]; then
        step "Installing Termux packages (rust, git, clang, make, pkg-config, openssl-tool)"

        # Termux package list refresh — retry, pkg can fail on flaky mobile networks.
        attempts=0
        until pkg update -y; do
            attempts=$((attempts + 1))
            [[ $attempts -ge 4 ]] && die "pkg update failed after 4 attempts — check network"
            warn "pkg update failed (attempt $attempts); retrying in $((attempts * 2))s"
            sleep $((attempts * 2))
        done

        # Install build chain. clang covers all C dep build.rs cases on Termux.
        pkg install -y rust git clang make pkg-config openssl-tool || \
            die "pkg install failed — check $LOG_FILE for missing packages"

        # Optional: termux-api is needed for sensor modules (v0.6+).
        if ! pkg show termux-api >/dev/null 2>&1; then
            warn "termux-api package metadata unavailable"
        elif ! command -v termux-info >/dev/null 2>&1; then
            warn "termux-api is not installed — sensor modules (v0.6+) will no-op"
            hint "Install later: pkg install termux-api"
            hint "And install the Termux:API app from F-Droid for sensor access."
        fi
    elif [[ "$OS" == "Linux" ]] && command -v apt-get >/dev/null 2>&1; then
        step "Installing apt packages (build-essential, git, pkg-config)"
        sudo apt-get update -y && sudo apt-get install -y build-essential git pkg-config curl
    elif [[ "$OS" == "Darwin" ]]; then
        step "macOS detected — ensuring Xcode CLT and rustup"
        if ! xcode-select -p >/dev/null 2>&1; then
            warn "Xcode Command Line Tools not installed."
            hint "Install with: xcode-select --install"
        fi
    fi
fi

# ─── Rust toolchain ──────────────────────────────────────────────────────────
step "Verifying Rust toolchain"

if ! command -v cargo >/dev/null 2>&1; then
    if [[ $IS_TERMUX -eq 1 ]]; then
        die "cargo missing after pkg install rust — re-run installer or run: pkg install rust"
    fi
    warn "cargo not found — bootstrapping rustup"
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable
    # shellcheck source=/dev/null
    source "$HOME/.cargo/env"
fi

RUST_FULL="$(rustc --version | awk '{print $2}')"
RUST_MAJ_MIN="$(echo "$RUST_FULL" | cut -d. -f1,2)"

ver_ge() {
    [[ "$(printf '%s\n%s\n' "$1" "$2" | sort -V | head -n1)" == "$2" ]]
}

if ! ver_ge "$RUST_MAJ_MIN" "$RUST_MIN_VERSION"; then
    die "rustc $RUST_FULL < required $RUST_MIN_VERSION. On Termux: pkg upgrade rust"
fi
ok "rustc $RUST_FULL (>= $RUST_MIN_VERSION required)"

# ─── Clone or update ─────────────────────────────────────────────────────────
step "Fetching source ($HSE_REF) → $HSE_INSTALL_DIR"

mkdir -p "$(dirname "$HSE_INSTALL_DIR")"

if [[ -d "$HSE_INSTALL_DIR/.git" ]]; then
    git -C "$HSE_INSTALL_DIR" fetch --depth 1 origin "$HSE_REF" \
        || die "git fetch failed"
    git -C "$HSE_INSTALL_DIR" checkout -B "$HSE_REF" "origin/$HSE_REF" \
        || die "git checkout failed"
    ok "Updated existing clone"
else
    git clone --depth 1 --branch "$HSE_REF" "$HSE_REPO_URL" "$HSE_INSTALL_DIR" \
        || die "git clone failed"
    ok "Cloned fresh"
fi

cd "$HSE_INSTALL_DIR"

if [[ "${HSE_SKIP_BUILD:-0}" == "1" ]]; then
    ok "HSE_SKIP_BUILD=1 set — stopping before build"
    exit 0
fi

# ─── Build ───────────────────────────────────────────────────────────────────
step "Building release binary (1–3 min on aarch64; first run downloads crates)"

# Termux: keep build artefacts in $HOME, not /data, to avoid app-data pressure.
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$HOME/.cache/hse-build}"
mkdir -p "$CARGO_TARGET_DIR"

# Termux quirk: $TMPDIR sometimes too small. Override to $HOME/tmp if not big enough.
if [[ $IS_TERMUX -eq 1 ]]; then
    export TMPDIR="${TMPDIR:-$HOME/tmp}"
    mkdir -p "$TMPDIR"
fi

# Retry the build twice — flaky mobile networks can interrupt crate downloads.
attempts=0
until cargo build --release --locked; do
    attempts=$((attempts + 1))
    [[ $attempts -ge 3 ]] && die "cargo build failed after 3 attempts — check $LOG_FILE"
    warn "Build attempt $attempts failed; retrying (slow mobile network?)"
    sleep $((attempts * 3))
done

BUILT="$CARGO_TARGET_DIR/release/hse"
[[ -x "$BUILT" ]] || die "Build claimed success but $BUILT is missing"
ok "Built: $BUILT ($(du -h "$BUILT" | awk '{print $1}'))"

# ─── Install binary ──────────────────────────────────────────────────────────
step "Installing binary to $HSE_BIN_DIR/hse"

install -m 0755 "$BUILT" "$HSE_BIN_DIR/hse"
ok "Installed"

if ! echo ":$PATH:" | grep -q ":$HSE_BIN_DIR:"; then
    warn "$HSE_BIN_DIR is not in your PATH"
    hint "Add to ~/.bashrc or ~/.zshrc: export PATH=\"$HSE_BIN_DIR:\$PATH\""
fi

# ─── Keys template ───────────────────────────────────────────────────────────
KEYS_PATH="$HOME/.huntsman.env"
if [[ ! -f "$KEYS_PATH" ]]; then
    step "Creating keys template at $KEYS_PATH"
    cat > "$KEYS_PATH" <<'TEMPLATE'
# Huntsman Search Engine API keys.
#
# Uncomment and paste a value to enable the corresponding key-gated module.
# All HSE keys MUST be prefixed HUNTSMAN_. File mode is 0600 — never commit.
#
# v0.2 free modules need no keys at all. Keys below are for future modules:
#
#HUNTSMAN_HIBP_KEY=
#HUNTSMAN_OATHNET_KEY=
#HUNTSMAN_DEHASHED_KEY=
#HUNTSMAN_HUNTER_KEY=
#HUNTSMAN_SHODAN_KEY=
#HUNTSMAN_VIRUSTOTAL_KEY=
#HUNTSMAN_WIGLE_TOKEN=
#HUNTSMAN_ABR_GUID=
TEMPLATE
    chmod 0600 "$KEYS_PATH"
    ok "Template created (chmod 0600)"
else
    ok "Keys file already present at $KEYS_PATH"
fi

# ─── Verify ──────────────────────────────────────────────────────────────────
step "Verifying installation"
"$HSE_BIN_DIR/hse" --version
echo
"$HSE_BIN_DIR/hse" doctor

# ─── Done ────────────────────────────────────────────────────────────────────
echo
printf '%s%sInstallation complete!%s\n\n' "$GREEN" "$BOLD" "$NC"
printf '%sWeb UI (recommended on Termux):%s\n' "$CYAN" "$NC"
printf '  hse serve                                           # binds 127.0.0.1:8080\n'
printf '  Then open in Chrome (or Firefox) on the device:\n'
printf '    %shttp://127.0.0.1:8080%s\n\n' "$BOLD" "$NC"
printf '%sCLI quick start:%s\n' "$CYAN" "$NC"
printf '  hse modules                                         # list available modules\n'
printf '  hse scan --kind domain --value example.com          # one-shot scan\n'
printf '  hse scan --kind domain --value example.com --depth 2 # autonomous expansion\n'
printf '  hse live --kind domain --value example.com --interval 60  # re-scan every 60s\n'
printf '  hse doctor                                          # re-check environment\n\n'
printf '%sLogs:%s\n' "$CYAN" "$NC"
printf '  Install log:  %s\n' "$LOG_FILE"
printf '  Build cache:  %s\n' "$CARGO_TARGET_DIR"
printf '  Database:     %s/.huntsman/huntsman.db\n' "$HOME"
printf '  Keys file:    %s\n\n' "$KEYS_PATH"
printf '%sAdd an API key (optional):%s\n' "$CYAN" "$NC"
printf '  edit %s and uncomment a line\n\n' "$KEYS_PATH"
printf '%sRe-install or upgrade:%s re-run the same curl-pipe command.\n' "$CYAN" "$NC"

trap - EXIT
