#!/usr/bin/env bash
# Huntsman Search Engine (HSE) — one-shot installer.
#
# Designed primarily for Termux on Android aarch64 (no root). Also works on
# any Linux / macOS with rustc 1.88+ and git. Idempotent: re-running upgrades
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
#   HSE_BUILD_PROFILE release | fast  (default: fast on Termux, release elsewhere)
#                     `fast` ≈4-6 min build; `release` ≈15-20 min, smallest binary
#   HSE_FULL_BUILD    Set to 1 to force the size-optimised `release` profile
#   HSE_PREBUILT      Abs path to a precompiled aarch64 `hse` to install directly
#                     (validated + run-tested) instead of building. By default the
#                     installer auto-scans Downloads / shared storage for one.
#   HSE_DOWNLOADS     Extra dir to add to the prebuilt scan (before the defaults)
#   HSE_PREFER_BUILD  Set to 1 to skip the prebuilt scan and always build
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

step()     { printf "${BLUE}==>${NC} ${BOLD}%s${NC}\n" "$*"; }
ok()       { printf "  ${GREEN}✓${NC} %s\n" "$*"; }
log_warn() { printf "  ${YELLOW}!${NC} %s\n" "$*"; }
die()      { printf "  ${RED}✗${NC} %s\n" "$*" >&2; echo; echo "Full log: $LOG_FILE"; exit 1; }
hint()     { printf "    ${DIM}%s${NC}\n" "$*"; }

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
# If invoked from inside an existing HSE clone (`./install.sh` from `~/hse`),
# upgrade THAT clone in place — so a manual `git clone` install and the
# scripted / curl-pipe install converge on one source tree instead of leaving
# two. Gated on the exact package name so it can't hijack an unrelated dir.
if [[ -z "${HSE_INSTALL_DIR:-}" && -d .git && -f Cargo.toml ]] \
    && grep -q '^name *= *"huntsman-search-engine"' Cargo.toml 2>/dev/null; then
    HSE_INSTALL_DIR="$(pwd)"
fi
HSE_INSTALL_DIR="${HSE_INSTALL_DIR:-$HOME/.local/share/hse}"
RUST_MIN_VERSION="1.88"

# ─── Detect environment ──────────────────────────────────────────────────────
step "Detecting environment"

IS_TERMUX=0
if [[ -n "${TERMUX_VERSION:-}" ]] || [[ -d /data/data/com.termux ]]; then
    IS_TERMUX=1
    ok "Termux ${TERMUX_VERSION:-(version unknown)}"

    # Termux from the Play Store is abandoned (last build 2020) and will
    # fail at `pkg update` because Google blocked it. Only F-Droid and
    # GitHub releases ship a working build.
    if [[ -f /data/data/com.termux/files/usr/etc/termux-build-info ]]; then
        TBI="$(cat /data/data/com.termux/files/usr/etc/termux-build-info 2>/dev/null || echo '')"
        if echo "$TBI" | grep -qi "playstore"; then
            die "Play Store Termux detected (abandoned, broken since 2020). \
Uninstall and reinstall from F-Droid: https://f-droid.org/packages/com.termux/"
        fi
    fi
else
    ok "Standard Unix environment"
fi

OS="$(uname -s)"
ARCH="$(uname -m)"
ok "OS=$OS  ARCH=$ARCH"

case "$ARCH" in
    aarch64|arm64) : ;;
    x86_64|amd64)  log_warn "Untested arch ($ARCH); proceeding — please report any issues" ;;
    *)             log_warn "Unusual arch ($ARCH); installation may not work" ;;
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
    log_warn "System clock looks wrong ($(date)). TLS will likely fail."
    hint "Fix on Termux: Android Settings -> System -> Date & time -> Set automatically"
    hint "Or manually: date -s 'YYYY-MM-DD HH:MM:SS'"
fi

# Disk space — release build takes ~500MB, target dir up to 2GB.
# `df -Pk` (POSIX, 1 KiB blocks) is the portable form: Termux's toybox `df`
# does NOT implement `-m` (the cause of the on-device "could not read" warning),
# but `-P` + `-k` are universal and `-P` also guarantees one fixed 6-column row
# per filesystem (no wrapping). Available is `$(NF-2)` in KiB → /1024 = MiB.
# Guard NF >= 4 so a degenerate single-field row can't make `$(NF-2)` a fatal
# awk error under `set -e`; the `|| true` is belt-and-braces.
if command -v df >/dev/null 2>&1; then
    DISK_AVAIL_MB=$({ df -Pk "$HOME" 2>/dev/null \
        | awk 'END { if (NF >= 4) print int($(NF-2)/1024) }' 2>/dev/null; } || true)
    if ! [[ "$DISK_AVAIL_MB" =~ ^[0-9]+$ ]]; then
        DISK_AVAIL_MB=0
    fi
    if [[ "$DISK_AVAIL_MB" -eq 0 ]]; then
        log_warn "Could not read free disk space from df — skipping check"
    elif [[ "$DISK_AVAIL_MB" -lt 2048 ]]; then
        log_warn "Only ${DISK_AVAIL_MB}MB free in \$HOME. Build needs ~2GB."
        hint "Free space or set HSE_INSTALL_DIR / CARGO_TARGET_DIR to a larger volume."
    else
        ok "Disk: ${DISK_AVAIL_MB}MB free"
    fi
fi

# Memory — cargo can OOM with <1GB on aarch64; recommend swap.
if [[ -r /proc/meminfo ]]; then
    MEM_TOTAL_MB=$(awk '/^MemTotal/ {print int($2/1024)}' /proc/meminfo)
    if [[ "$MEM_TOTAL_MB" -lt 1500 ]]; then
        log_warn "Only ${MEM_TOTAL_MB}MB RAM. Build may OOM."
        hint "Workaround: set CARGO_BUILD_JOBS=1 to limit parallelism."
        export CARGO_BUILD_JOBS=1
    else
        ok "RAM: ${MEM_TOTAL_MB}MB"
    fi
fi

# ─── Prebuilt-binary fast path (PRIMARY; source build is the fallback) ───────
# Look for a precompiled aarch64 `hse` in Downloads / shared storage; if one
# validates and runs, install it and skip the toolchain + source build entirely
# (seconds, no Rust needed). Robust to the usual Android gotchas: sdcard is
# mounted noexec, so a candidate is copied into $HOME before the run-test;
# integrity is checked against a sidecar `.sha256` when present; many download
# dirs + filenames are probed. Override the file with HSE_PREBUILT=/abs/path;
# force a source build with HSE_PREFER_BUILD=1.
PREBUILT=0
BUILT=""
STAGED=""

_prebuilt_dirs() {
    [[ -n "${HSE_PREBUILT:-}" ]] && printf '%s\n' "$(dirname -- "$HSE_PREBUILT")"
    printf '%s\n' \
        "${HSE_DOWNLOADS:-}" \
        "$HOME/storage/downloads" \
        "$HOME/storage/shared/Download" "$HOME/storage/shared/Downloads" \
        "$HOME/downloads" "$HOME/Download" "$HOME/Downloads" \
        "/sdcard/Download" "/sdcard/Downloads" \
        "/storage/emulated/0/Download" "/storage/emulated/0/Downloads"
}

_validate_prebuilt() {
    # $1 = candidate path. On success sets STAGED to an exec-ok copy under $HOME.
    local cand="$1" base sz magic want got ver staged
    base="$(basename -- "$cand")"
    [[ -f "$cand" && -r "$cand" ]] || return 1
    sz=$(wc -c < "$cand" 2>/dev/null || echo 0)
    [[ "$sz" =~ ^[0-9]+$ && "$sz" -gt 1000000 ]] || { log_warn "skip $base (size ${sz}B < 1MB)"; return 1; }
    # ELF magic (\x7fELF) — cheap pre-filter before we bother exec-testing.
    magic=$(od -An -tx1 -N4 "$cand" 2>/dev/null | tr -d ' \n')
    [[ "$magic" == "7f454c46" ]] || { log_warn "skip $base (not an ELF binary)"; return 1; }
    # Optional integrity check against a sidecar `<file>.sha256`.
    if [[ -f "$cand.sha256" ]] && command -v sha256sum >/dev/null 2>&1; then
        want=$(awk 'NR==1{print $1}' "$cand.sha256" 2>/dev/null)
        got=$(sha256sum "$cand" 2>/dev/null | awk '{print $1}')
        [[ -n "$want" && "$want" != "$got" ]] && { log_warn "skip $base (sha256 mismatch — corrupt/tampered)"; return 1; }
        [[ -n "$want" ]] && ok "sha256 verified ($base)"
    fi
    # sdcard/Downloads is typically mounted noexec → copy into $HOME, then the
    # run-test is the definitive arch/integrity check (a valid aarch64 binary
    # runs on aarch64 Termux; wrong-arch or corrupt fails).
    staged="$HOME/.cache/hse-prebuilt"
    mkdir -p "$HOME/.cache"
    cp -f "$cand" "$staged" 2>/dev/null || { log_warn "skip $base (copy into \$HOME failed)"; return 1; }
    chmod 0755 "$staged" 2>/dev/null || true
    if ver=$("$staged" --version 2>/dev/null) && [[ "$ver" == hse\ * ]]; then
        ok "Prebuilt validated: $cand ($ver)"
        STAGED="$staged"
        return 0
    fi
    log_warn "skip $base (won't run --version — wrong arch or corrupt)"
    rm -f "$staged" 2>/dev/null || true
    return 1
}

maybe_use_prebuilt() {
    [[ "${HSE_PREFER_BUILD:-0}" == "1" ]] && { hint "HSE_PREFER_BUILD=1 — skipping prebuilt scan, building from source"; return 1; }
    step "Looking for a prebuilt aarch64 binary (Downloads / shared storage)"
    local d n cand names
    names=(hse-aarch64-linux-android hse-aarch64 hse hse.bin)
    [[ -n "${HSE_PREBUILT:-}" ]] && names=("$(basename -- "$HSE_PREBUILT")" "${names[@]}")
    while IFS= read -r d; do
        [[ -n "$d" && -d "$d" ]] || continue
        for n in "${names[@]}"; do
            cand="$d/$n"
            [[ -f "$cand" ]] || continue
            if _validate_prebuilt "$cand"; then
                BUILT="$STAGED"
                PREBUILT=1
                ok "Using prebuilt binary — skipping toolchain + source build"
                return 0
            fi
        done
    done < <(_prebuilt_dirs)
    hint "No usable prebuilt in Downloads — building from source instead"
    return 1
}

maybe_use_prebuilt || true

# Everything from the toolchain install through the source build is skipped
# when a validated prebuilt was found above (closed with `fi` before install).
if [[ "$PREBUILT" != "1" ]]; then

# ─── Install system dependencies ─────────────────────────────────────────────
if [[ "${HSE_NO_PKG:-0}" != "1" ]]; then
    if [[ $IS_TERMUX -eq 1 ]]; then
        step "Installing Termux packages (rust, binutils, git, clang, make, pkg-config, openssl-tool, curl)"

        # Termux package list refresh — retry, pkg can fail on flaky mobile networks.
        attempts=0
        until pkg update -y; do
            attempts=$((attempts + 1))
            [[ $attempts -ge 4 ]] && die "pkg update failed after 4 attempts — check network"
            log_warn "pkg update failed (attempt $attempts); retrying in $((attempts * 2))s"
            sleep $((attempts * 2))
        done

        # Install build chain. clang covers all C dep build.rs cases on Termux.
        pkg install -y rust binutils git clang make pkg-config openssl-tool curl || \
            die "pkg install failed — check $LOG_FILE for missing packages"

        # Optional: termux-api is needed for sensor modules (v0.6+).
        if ! pkg show termux-api >/dev/null 2>&1; then
            log_warn "termux-api package metadata unavailable"
        elif ! command -v termux-info >/dev/null 2>&1; then
            log_warn "termux-api is not installed — sensor modules (v0.6+) will no-op"
            hint "Install later: pkg install termux-api"
            hint "And install the Termux:API app from F-Droid for sensor access."
        fi
    elif [[ "$OS" == "Linux" ]] && command -v apt-get >/dev/null 2>&1; then
        step "Installing apt packages (build-essential, git, pkg-config)"
        sudo apt-get update -y && sudo apt-get install -y build-essential git pkg-config curl
    elif [[ "$OS" == "Darwin" ]]; then
        step "macOS detected — ensuring Xcode CLT and rustup"
        if ! xcode-select -p >/dev/null 2>&1; then
            log_warn "Xcode Command Line Tools not installed."
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
    log_warn "cargo not found — bootstrapping rustup"
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

# Fail fast instead of hanging on an interactive username/password prompt:
# a *public* repo never asks for credentials, so a prompt means the repo is
# private (or the URL is wrong). GIT_TERMINAL_PROMPT=0 turns that prompt into
# an immediate error we can explain, rather than a stuck install.
export GIT_TERMINAL_PROMPT=0

# Shared, credential-aware diagnosis for any clone/fetch auth failure. The SSH
# and token URLs are derived from $HSE_REPO_URL (not hardcoded), so the hints
# stay correct for forks / mirrors / a custom HSE_REPO_URL.
clone_help() {
    local ssh_url="$HSE_REPO_URL" token_url="$HSE_REPO_URL"
    if [[ "$HSE_REPO_URL" == https://github.com/* ]]; then
        # https://github.com/owner/repo.git -> git@github.com:owner/repo.git
        ssh_url="git@github.com:${HSE_REPO_URL#https://github.com/}"
    fi
    if [[ "$HSE_REPO_URL" == https://* ]]; then
        token_url="https://<TOKEN>@${HSE_REPO_URL#https://}"
    fi
    log_warn "git could not access $HSE_REPO_URL without credentials."
    hint "A *public* repo never asks for a username/password. This usually means:"
    hint "  • the repository is PRIVATE — ask the owner to make it public, or"
    hint "  • use SSH with a key already on your GitHub account:"
    hint "      HSE_REPO_URL=$ssh_url ./install.sh"
    hint "  • or pass a token in the URL (export it to keep it out of history):"
    hint "      HSE_REPO_URL=$token_url ./install.sh"
}

if [[ -d "$HSE_INSTALL_DIR/.git" ]]; then
    # Re-point origin at $HSE_REPO_URL first, so an SSH/token override
    # (HSE_REPO_URL=git@... ./install.sh) actually takes effect on a re-install
    # whose existing origin is the private HTTPS URL — otherwise the fetch
    # below would keep using the old, credential-gated remote.
    git -C "$HSE_INSTALL_DIR" remote set-url origin "$HSE_REPO_URL" 2>/dev/null || true
    git -C "$HSE_INSTALL_DIR" fetch --depth 1 origin "$HSE_REF" \
        || { clone_help; die "git fetch failed"; }
    git -C "$HSE_INSTALL_DIR" checkout -B "$HSE_REF" "origin/$HSE_REF" \
        || die "git checkout failed"
    ok "Updated existing clone"
else
    git clone --depth 1 --branch "$HSE_REF" "$HSE_REPO_URL" "$HSE_INSTALL_DIR" \
        || { clone_help; die "git clone failed"; }
    ok "Cloned fresh"
fi

cd "$HSE_INSTALL_DIR"

if [[ "${HSE_SKIP_BUILD:-0}" == "1" ]]; then
    ok "HSE_SKIP_BUILD=1 set — stopping before build"
    exit 0
fi

# ─── Build ───────────────────────────────────────────────────────────────────
# Build profile. On Termux the `release` profile's single-threaded LTO link
# (codegen-units=1, lto=true) takes ~15-20 min on aarch64; the `fast` profile
# (lto off, codegen-units=16, opt-level=2) cuts that to ~4-6 min for a ~35%
# larger binary and a negligible runtime cost (HSE is network/IO-bound). So
# Termux defaults to `fast`; other hosts default to `release`. Override with
# HSE_BUILD_PROFILE=<release|fast>, or the shortcut HSE_FULL_BUILD=1 for the
# smallest/fastest `release` artifact.
if [[ -n "${HSE_BUILD_PROFILE:-}" ]]; then
    PROFILE="$HSE_BUILD_PROFILE"
elif [[ "${HSE_FULL_BUILD:-0}" == "1" ]]; then
    PROFILE="release"
elif [[ $IS_TERMUX -eq 1 ]]; then
    PROFILE="fast"
else
    PROFILE="release"
fi
case "$PROFILE" in
    fast)    BUILD_ETA="~4-6 min on aarch64" ;;
    release) BUILD_ETA="~15-20 min on aarch64 (size-optimised; LTO)" ;;
    *)       BUILD_ETA="" ;;
esac
step "Building binary [profile: $PROFILE] ($BUILD_ETA; first run downloads crates)"
hint "Slow? Re-run with HSE_BUILD_PROFILE=fast for a quicker build, or HSE_FULL_BUILD=1 for the smallest."

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
until cargo build --profile "$PROFILE" --locked; do
    attempts=$((attempts + 1))
    [[ $attempts -ge 3 ]] && die "cargo build failed after 3 attempts — check $LOG_FILE"
    log_warn "Build attempt $attempts failed; retrying (slow mobile network?)"
    sleep $((attempts * 3))
done

# `--profile release` outputs to target/release; `--profile fast` to target/fast.
BUILT="$CARGO_TARGET_DIR/$PROFILE/hse"
[[ -x "$BUILT" ]] || die "Build claimed success but $BUILT is missing"
ok "Built: $BUILT ($(du -h "$BUILT" | awk '{print $1}'))"

fi  # end PREBUILT guard — toolchain + clone + source build skipped when a prebuilt was used

# ─── Install binary ──────────────────────────────────────────────────────────
step "Installing binary to $HSE_BIN_DIR/hse"

[[ -n "$BUILT" && -x "$BUILT" ]] || die "internal: no binary to install (BUILT='$BUILT')"
install -m 0755 "$BUILT" "$HSE_BIN_DIR/hse"
ok "Installed ($([[ "$PREBUILT" == "1" ]] && echo 'from prebuilt' || echo "built [$PROFILE]"))"

# Self-bootstrapping prebuilt cache: copy a freshly-BUILT binary back to
# Downloads so the next install — this device after a wipe, or another aarch64
# phone — finds it on the prebuilt fast path and skips the build entirely. Skip
# when we already came FROM a prebuilt (nothing new to cache). Best-effort.
if [[ "$PREBUILT" != "1" && $IS_TERMUX -eq 1 ]]; then
    for _dl in "$HOME/storage/downloads" "/sdcard/Download" "/storage/emulated/0/Download"; do
        [[ -d "$_dl" && -w "$_dl" ]] || continue
        if cp -f "$BUILT" "$_dl/hse-aarch64-linux-android" 2>/dev/null; then
            if command -v sha256sum >/dev/null 2>&1; then
                ( cd "$_dl" && sha256sum hse-aarch64-linux-android > hse-aarch64-linux-android.sha256 ) 2>/dev/null || true
            fi
            ok "Cached prebuilt → $_dl/hse-aarch64-linux-android (reused on the next install)"
        fi
        break
    done
fi

# ─── PATH persistence ────────────────────────────────────────────────────────
# Termux's $PREFIX/bin is already in PATH by default; only patch shell-rc
# when the user (or override) put the binary somewhere else.
if ! echo ":$PATH:" | grep -q ":$HSE_BIN_DIR:"; then
    log_warn "$HSE_BIN_DIR is not in current PATH"
    PATH_LINE="export PATH=\"$HSE_BIN_DIR:\$PATH\""
    PATH_TAG="# added by hse installer"
    for rc in "$HOME/.bashrc" "$HOME/.zshrc" "$HOME/.profile"; do
        if [[ -f "$rc" ]] && ! grep -qF "$PATH_TAG" "$rc"; then
            {
                printf '\n%s\n%s\n' "$PATH_TAG" "$PATH_LINE"
            } >> "$rc"
            ok "Added PATH to $rc — restart shell or: source $rc"
            break
        fi
    done
fi

# ─── Termux-native setup (no-op on other Unix) ───────────────────────────────
if [[ $IS_TERMUX -eq 1 ]]; then
    step "Termux-native setup"

    # Shared-storage symlink — needed for import command + sensor modules
    # that read GPS NMEA logs / WiFi scans from external storage.
    if [[ ! -d "$HOME/storage" ]]; then
        if [[ -t 0 && -t 1 ]]; then
            printf "  ${CYAN}?${NC} Grant shared-storage access now? (recommended for sensor modules) [y/N] "
            read -r reply || reply=""
            if [[ "${reply,,}" == "y" || "${reply,,}" == "yes" ]]; then
                termux-setup-storage \
                    && ok "Shared storage linked at $HOME/storage" \
                    || log_warn "termux-setup-storage failed (denied permission?)"
            else
                hint "Skipped. Run later: termux-setup-storage"
            fi
        else
            hint "Non-interactive install — run later: termux-setup-storage"
        fi
    else
        ok "Shared storage already configured at $HOME/storage"
    fi

    # Background-scan wrapper. Wraps `hse serve` in nohup + wake-lock so
    # the scan engine survives Android's aggressive process kills.
    BG_WRAPPER="$HSE_BIN_DIR/hse-bg"
    cat > "$BG_WRAPPER" <<'WRAPPER'
#!/data/data/com.termux/files/usr/bin/bash
# hse-bg — run `hse serve` in background with wake-lock so Android can't
# kill the process when the screen turns off. Stop with: hse-bg stop
set -e
PID_FILE="$HOME/.cache/hse-bg.pid"
LOG_FILE="$HOME/.cache/hse-bg.log"
mkdir -p "$(dirname "$PID_FILE")"

case "${1:-start}" in
    start)
        if [[ -f "$PID_FILE" ]] && kill -0 "$(cat "$PID_FILE")" 2>/dev/null; then
            echo "hse-bg already running (pid $(cat "$PID_FILE"))"
            exit 0
        fi
        command -v termux-wake-lock >/dev/null && termux-wake-lock || true
        nohup hse serve >> "$LOG_FILE" 2>&1 &
        echo $! > "$PID_FILE"
        echo "Started hse serve (pid $(cat "$PID_FILE"))"
        echo "Logs: $LOG_FILE"
        echo "Open: http://127.0.0.1:8080"
        ;;
    stop)
        if [[ -f "$PID_FILE" ]] && kill -0 "$(cat "$PID_FILE")" 2>/dev/null; then
            kill "$(cat "$PID_FILE")"
            rm -f "$PID_FILE"
            command -v termux-wake-unlock >/dev/null && termux-wake-unlock || true
            echo "Stopped"
        else
            echo "Not running"
            rm -f "$PID_FILE"
        fi
        ;;
    status)
        if [[ -f "$PID_FILE" ]] && kill -0 "$(cat "$PID_FILE")" 2>/dev/null; then
            echo "Running: pid $(cat "$PID_FILE")"
        else
            echo "Not running"
        fi
        ;;
    log)
        tail -f "$LOG_FILE"
        ;;
    *)
        echo "usage: hse-bg [start|stop|status|log]"
        exit 1
        ;;
esac
WRAPPER
    chmod 0755 "$BG_WRAPPER"
    ok "Installed hse-bg wrapper (start|stop|status|log)"

    # Termux:Boot autostart — only set up if the boot dir already exists
    # (created by Termux:Boot app). We don't force-create it because that
    # implies the user installed the APK.
    BOOT_DIR="$HOME/.termux/boot"
    if [[ -d "$BOOT_DIR" ]]; then
        BOOT_SCRIPT="$BOOT_DIR/hse-autostart"
        if [[ ! -f "$BOOT_SCRIPT" ]]; then
            cat > "$BOOT_SCRIPT" <<'BOOT'
#!/data/data/com.termux/files/usr/bin/bash
termux-wake-lock 2>/dev/null || true
hse-bg start
BOOT
            chmod 0755 "$BOOT_SCRIPT"
            ok "Termux:Boot autostart installed → ${BOOT_SCRIPT}"
        fi
    else
        hint "Optional: install Termux:Boot from F-Droid for auto-start on device boot"
        hint "  https://f-droid.org/packages/com.termux.boot/"
    fi

    # termux-api package + APK reminder. The package is the CLI tools;
    # the APK from F-Droid is the actual sensor bridge.
    if ! command -v termux-info >/dev/null 2>&1; then
        if [[ "${HSE_NO_PKG:-0}" != "1" ]]; then
            pkg install -y termux-api 2>/dev/null \
                && ok "Installed termux-api package" \
                || log_warn "Could not install termux-api (sensor modules will no-op)"
        fi
    else
        ok "termux-api CLI present"
    fi
    if ! pm list packages 2>/dev/null | grep -q com.termux.api; then
        hint "Install Termux:API APK from F-Droid for sensor access (GPS / WiFi / cell):"
        hint "  https://f-droid.org/packages/com.termux.api/"
    fi
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
# v0.2 free modules need no keys at all. Keys below are for key-gated modules.
# Several are embedded in the build (OathNet, HIBP, WiGLE, SeekNow) and are
# auto-written/auto-rotated on first `hse scan`/`serve` — listed here only so
# you can override them. The Settings page (hse serve → Settings) shows the
# full key list and lets you paste/save any of them from the browser.
#
# Identity / breach
#HUNTSMAN_HIBP_KEY=
#HUNTSMAN_OATHNET_KEY=
#HUNTSMAN_SEEKNOW_KEY=
#HUNTSMAN_DEHASHED_USER=
#HUNTSMAN_DEHASHED_KEY=
#HUNTSMAN_HUNTER_KEY=
#HUNTSMAN_INTELX_KEY=
# Infrastructure / threat intel
#HUNTSMAN_SHODAN_KEY=
#HUNTSMAN_SECTRAILS_KEY=
#HUNTSMAN_LEAKIX_KEY=
#HUNTSMAN_CRIMINALIP_KEY=
#HUNTSMAN_IPQS_KEY=
#HUNTSMAN_VIRUSTOTAL_KEY=
# Search
#HUNTSMAN_EXA_KEY=
# Validation / enrichment
#HUNTSMAN_NUMVERIFY_KEY=
#HUNTSMAN_WIGLE_USER=
#HUNTSMAN_WIGLE_TOKEN=
#HUNTSMAN_ABR_GUID=
# OSINT orchestration / identity
#HUNTSMAN_SEON_KEY=
#HUNTSMAN_EMAILREP_KEY=
#HUNTSMAN_EPIEOS_KEY=
#HUNTSMAN_PROXYCURL_KEY=
#HUNTSMAN_OPENCORP_KEY=
#
# Optional operator-local default seed. Set this to YOUR OWN default scan
# target so `hse scan` / `hse live` can run without retyping --value. Read only
# from this file (or your shell) — never embedded in the binary or installer,
# so it stays on this device. An explicit --value always overrides it.
#HUNTSMAN_DEFAULT_SEED=
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
printf '%sCLI quick start:%s\n' "$CYAN" "$NC"
printf '  hse modules                                         # list available modules\n'
printf '  hse scan --kind domain --value example.com -A       # auto-depth scan\n'
printf '  hse scan --kind email --value foo@bar.com --depth 5 # max expansion\n'
printf '  hse live --kind domain --value example.com -i 60    # re-scan every 60s\n'
printf '  hse keys status                                     # show key pool\n'
printf '  hse doctor                                          # re-check environment\n\n'
if [[ $IS_TERMUX -eq 1 ]]; then
    printf '%sBackground operation (Termux):%s\n' "$CYAN" "$NC"
    printf '  hse-bg start                                        # wake-lock + nohup\n'
    printf '  hse-bg status                                       # is it running?\n'
    printf '  hse-bg log                                          # tail the log\n'
    printf '  hse-bg stop                                         # release wake-lock\n'
    printf '  Then open: %shttp://127.0.0.1:8080%s in Chrome on the device\n\n' "$BOLD" "$NC"
    printf '%sBattery & process survival:%s\n' "$CYAN" "$NC"
    printf '  Android > Settings > Apps > Termux > Battery: unrestricted\n'
    printf '  Android > Settings > Apps > Termux > Allow background data\n\n'
else
    printf '%sWeb UI:%s\n' "$CYAN" "$NC"
    printf '  hse serve                                           # binds 127.0.0.1:8080\n\n'
fi
printf '%sLogs:%s\n' "$CYAN" "$NC"
printf '  Install log:  %s\n' "$LOG_FILE"
printf '  Build cache:  %s\n' "$CARGO_TARGET_DIR"
printf '  Database:     %s/.huntsman/huntsman.db\n' "$HOME"
printf '  Keys file:    %s\n\n' "$KEYS_PATH"
printf '%sAdd an API key (optional):%s\n' "$CYAN" "$NC"
printf '  hse set-key HUNTSMAN_SHODAN_KEY <value>             # write to keys file\n'
printf '  hse keys add shodan <value>                         # write to multi-key pool\n\n'
printf '%sRe-install or upgrade:%s re-run the same curl-pipe command.\n' "$CYAN" "$NC"

trap - EXIT
