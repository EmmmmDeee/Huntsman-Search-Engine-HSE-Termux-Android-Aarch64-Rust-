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

HB_PID=""
on_exit() {
    local rc=$?
    # Stop the build heartbeat ticker if it's still running (any exit path).
    [[ -n "$HB_PID" ]] && kill "$HB_PID" 2>/dev/null
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
    # Integrity: required for auto-discovered binaries from world-writable paths (§7 S5);
    # optional when the caller passes 0 for an explicitly-set HSE_PREBUILT.
    local require_sha="${2:-1}"
    if [[ "$require_sha" == "1" ]]; then
        command -v sha256sum >/dev/null 2>&1 || { log_warn "skip $base (sha256sum unavailable — cannot verify integrity)"; return 1; }
        [[ -f "$cand.sha256" ]] || { log_warn "skip $base (no .sha256 sidecar — place <binary>.sha256 alongside it, or set HSE_PREBUILT=/abs/path)"; return 1; }
        want=$(awk 'NR==1{print $1}' "$cand.sha256" 2>/dev/null)
        [[ -n "$want" ]] || { log_warn "skip $base (empty .sha256 sidecar)"; return 1; }
        got=$(sha256sum "$cand" 2>/dev/null | awk '{print $1}')
        [[ "$want" == "$got" ]] || { log_warn "skip $base (sha256 mismatch — corrupt/tampered)"; return 1; }
        ok "sha256 verified ($base)"
    elif [[ -f "$cand.sha256" ]] && command -v sha256sum >/dev/null 2>&1; then
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
    local d n cand names require_sha
    names=(hse-aarch64-linux-android hse-aarch64 hse hse.bin)
    [[ -n "${HSE_PREBUILT:-}" ]] && names=("$(basename -- "$HSE_PREBUILT")" "${names[@]}")
    # sha256 optional when user nominated HSE_PREBUILT (lower risk, trusted choice); required otherwise.
    [[ -n "${HSE_PREBUILT:-}" ]] && require_sha=0 || require_sha=1
    while IFS= read -r d; do
        [[ -n "$d" && -d "$d" ]] || continue
        for n in "${names[@]}"; do
            cand="$d/$n"
            [[ -f "$cand" ]] || continue
            if _validate_prebuilt "$cand" "$require_sha"; then
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

# Fetch the published aarch64 Termux binary from GitHub Releases (the artifact
# built + signed by .github/workflows/release.yml). This is the robust fallback
# when the local Rust toolchain cannot build — e.g. a broken Termux `rust`
# package that ships no static std — and a hands-off fast path in general. The
# asset is an Android/bionic ELF, so this is gated to aarch64 Termux; the
# --version run-test in _validate_prebuilt is the final arbiter and rejects a
# binary that wouldn't run here. Best effort: any failure (no release yet,
# network blocked, bad asset) falls through to the source build. Opt out with
# HSE_NO_DOWNLOAD=1; pin a specific release with HSE_PREBUILT_TAG=vX.Y.Z.
maybe_download_prebuilt() {
    [[ "${HSE_PREFER_BUILD:-0}" == "1" ]] && return 1
    [[ "${HSE_NO_DOWNLOAD:-0}" == "1" ]] && { hint "HSE_NO_DOWNLOAD=1 — skipping release download"; return 1; }
    [[ $IS_TERMUX -eq 1 ]] || return 1
    case "$ARCH" in aarch64 | arm64) : ;; *) return 1 ;; esac
    command -v curl >/dev/null 2>&1 || return 1

    local base asset url_bin url_sha tmp tag sha_dl_ok
    base="${HSE_REPO_URL%.git}"
    asset="hse-aarch64-linux-android"
    tag="${HSE_PREBUILT_TAG:-latest}"
    if [[ "$tag" == "latest" ]]; then
        url_bin="$base/releases/latest/download/$asset"
        url_sha="$base/releases/latest/download/$asset.sha256"
    else
        url_bin="$base/releases/download/$tag/$asset"
        url_sha="$base/releases/download/$tag/$asset.sha256"
    fi

    step "Fetching prebuilt aarch64 binary from GitHub Releases ($tag)"
    tmp="$HOME/.cache/hse-dl"
    mkdir -p "$tmp"
    printf "  Downloading %s…" "$asset"
    if ! curl -fsSL -m 180 -o "$tmp/$asset" "$url_bin" >> "$LOG_FILE" 2>&1; then
        printf " unavailable\n"
        hint "No published release binary yet (or network blocked) — building from source"
        return 1
    fi
    printf " done\n"
    # Require the sha256 sidecar for a network-fetched binary. It is fetched
    # over the SAME TLS channel as the binary, so it is NOT an authenticity
    # control against a hostile origin (an attacker who can swap the binary can
    # swap its checksum too) — curl's certificate validation is what
    # authenticates the source. What requiring it DOES buy: integrity against a
    # corrupt/truncated download or a partial CDN object, and parity with the
    # local-Downloads path (where a trusted local process places the sidecar).
    # Bail rather than fall back to run-test-only validation if it's missing.
    printf "  Downloading %s.sha256…" "$asset"
    sha_dl_ok=1
    curl -fsSL -m 30 -o "$tmp/$asset.sha256" "$url_sha" >> "$LOG_FILE" 2>&1 || sha_dl_ok=0
    [[ -s "$tmp/$asset.sha256" ]] || sha_dl_ok=0
    if [[ $sha_dl_ok -eq 0 ]]; then
        printf " unavailable\n"
        log_warn "sha256 sidecar download failed — skipping release binary (cannot verify integrity)"
        hint "Re-run with HSE_NO_DOWNLOAD=1 to skip the release download entirely."
        return 1
    fi
    printf " done\n"
    if _validate_prebuilt "$tmp/$asset" 1; then
        BUILT="$STAGED"
        PREBUILT=1
        ok "Using downloaded prebuilt — skipping toolchain + source build"
        return 0
    fi
    log_warn "Downloaded binary failed validation — building from source instead"
    return 1
}

# Prebuilt resolution order: local Downloads scan → GitHub Releases download →
# (both miss) fall through to the from-source build below.
maybe_use_prebuilt || maybe_download_prebuilt || true

# Establish CARGO_TARGET_DIR now so the final summary block (below the fi) can
# always reference it, regardless of whether a prebuilt was used. The export
# inside the build block below re-uses this value via `:-` so it's idempotent.
CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$HOME/.cache/hse-build}"

# Everything from the toolchain install through the source build is skipped
# when a validated prebuilt was found above (closed with `fi` before install).
if [[ "$PREBUILT" != "1" ]]; then

# ─── Install system dependencies ─────────────────────────────────────────────
if [[ "${HSE_NO_PKG:-0}" != "1" ]]; then
    if [[ $IS_TERMUX -eq 1 ]]; then
        step "Installing Termux packages (rust, binutils, git, clang, make, pkg-config, openssl-tool, curl)"

        # ── Mirror: pin Cloudflare CDN, bypass pkg's 50-mirror speed test ─────
        # On a fresh repo, pkg(1) runs an interactive mirror selector on the
        # first `pkg update`/`install` — printing "No mirror or mirror group
        # selected" and speed-testing 50+ mirrors (slow and noisy over a curl
        # pipe). We sidestep it two ways: (1) pin the Cloudflare anycast CDN
        # mirror (global, consistently fast), and (2) drive `apt-get` directly,
        # since only the `pkg` wrapper runs the selector — `apt-get` just reads
        # sources.list. Keep your own termux-change-repo choice with
        # HSE_KEEP_MIRROR=1.
        _SLIST="$PREFIX/etc/apt/sources.list"
        if [[ "${HSE_KEEP_MIRROR:-0}" != "1" ]]; then
            mkdir -p "$(dirname "$_SLIST")"
            printf '%s\n%s\n%s\n' \
                '# Pinned by the hse installer (set HSE_KEEP_MIRROR=1 to keep your own).' \
                '# Change manually any time with: termux-change-repo' \
                'deb https://packages-cf.termux.dev/apt/termux-main stable main' \
                > "$_SLIST"
            ok "Mirror pinned → packages-cf.termux.dev (Cloudflare CDN)"
        fi

        # ── Package install ──────────────────────────────────────────────────
        # Verbose apt/dpkg output goes to $LOG_FILE only (>> bypasses the exec
        # tee); a compact one-liner shows here. apt-get (not pkg) avoids the
        # mirror selector. Retry the index refresh on flaky mobile networks.
        _apt() {
            local label="$1"; shift
            printf "  %s…" "$label"
            local _rc=0
            DEBIAN_FRONTEND=noninteractive apt-get "$@" >> "$LOG_FILE" 2>&1 || _rc=$?
            if [[ $_rc -eq 0 ]]; then printf " done\n"; else printf " failed\n"; fi
            return $_rc
        }
        attempts=0
        until _apt "Refreshing package index" update -y; do
            attempts=$((attempts + 1))
            [[ $attempts -ge 4 ]] && \
                die "package index refresh failed after 4 attempts — mirror down? Run: termux-change-repo (then re-run installer)"
            log_warn "index refresh failed (attempt $attempts); retrying in $((attempts * 2))s"
            hint "Persistent mirror trouble? Run: termux-change-repo"
            sleep $((attempts * 2))
        done

        # Install build chain. clang covers all C dep build.rs cases on Termux.
        _apt "Installing packages" install -y rust binutils git clang make pkg-config openssl-tool curl \
            || die "package install failed — check $LOG_FILE for missing packages"
        ok "Packages installed: rust, binutils, git, clang, make, pkg-config, openssl-tool, curl"
    elif [[ "$OS" == "Linux" ]] && command -v apt-get >/dev/null 2>&1; then
        step "Installing apt packages (build-essential, git, pkg-config)"
        sudo apt-get update -y && sudo apt-get install -y build-essential git pkg-config curl \
            || die "apt package install failed — install build-essential, git, pkg-config, curl manually and re-run"
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

# ─── Rust standard library integrity (Termux) ────────────────────────────────
# A broken / partially-installed Termux `rust` package can ship libstd as only a
# shared object (.so) and omit the static archive (.rlib). Every build-script
# and proc-macro then fails to *link* with:
#   error: crate `std` required to be available in rlib format, but was not found
# (library crates still compile — they emit metadata and never link std — so the
# failure looks baffling: "only the build scripts break"). Detect it up front
# and self-heal with a reinstall, turning a 3×-retry mystery into a repair or a
# clear diagnosis BEFORE the long source build.
if [[ $IS_TERMUX -eq 1 ]]; then
    SYSROOT="$(rustc --print sysroot 2>/dev/null || true)"
    HOST_TRIPLE="$(rustc -vV 2>/dev/null | awk '/^host:/ {print $2}')"
    RLIB_DIR="$SYSROOT/lib/rustlib/$HOST_TRIPLE/lib"
    if [[ -n "$SYSROOT" && -n "$HOST_TRIPLE" && -d "$RLIB_DIR" ]]; then
        if ls "$RLIB_DIR"/libstd-*.rlib >/dev/null 2>&1; then
            ok "rust std OK (static libstd present for $HOST_TRIPLE)"
        elif ls "$RLIB_DIR"/libstd-*.so >/dev/null 2>&1; then
            # High-confidence broken signal: dynamic libstd present, static absent.
            log_warn "rust sysroot has no static std (libstd-*.rlib) — builds would fail to link"
            hint "Repairing the Termux 'rust' package (apt reinstall)…"
            if DEBIAN_FRONTEND=noninteractive apt-get install -y --reinstall rust >> "$LOG_FILE" 2>&1 \
                && ls "$RLIB_DIR"/libstd-*.rlib >/dev/null 2>&1; then
                ok "rust std repaired (reinstalled)"
            else
                die "Termux 'rust' package is broken: no static std in $RLIB_DIR
  Upstream Termux packaging issue, not an HSE bug — and the prebuilt download
  above didn't resolve it either. Options:
    • check network + re-run (the installer auto-fetches a prebuilt aarch64 binary)
    • pin a release:      HSE_PREBUILT_TAG=vX.Y.Z bash install.sh
    • use a local file:   HSE_PREBUILT=/path/to/hse bash install.sh
    • wait for Termux:    pkg upgrade rust   (then re-run)
    • report it:          https://github.com/termux/termux-packages/issues"
            fi
        fi
        # Any other layout (neither .rlib nor .so matched) → unexpected; skip the
        # check rather than risk a false positive.
    fi
fi

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

# One unified path for both a fresh install and an update, built on `git
# fetch <ref>` + `checkout FETCH_HEAD` rather than `git clone --branch <ref>` /
# `checkout origin/<ref>`. This matters because HSE_REF is documented to
# accept a branch, a tag, OR a raw commit SHA, but the old two-path version
# only actually worked for a branch: `git clone --branch` rejects a bare SHA
# outright (it only resolves branches/tags), and on an EXISTING clone (which
# `git clone --depth 1 --branch X` narrows to a single-branch fetch refspec,
# `+refs/heads/X:refs/remotes/origin/X`) a later `git fetch origin <tag-or-
# other-ref>` downloads the object fine but never creates `origin/<ref>` —
# that name only exists for the one branch the refspec was narrowed to — so
# `checkout -B "$HSE_REF" "origin/$HSE_REF"` died with "not a commit and a
# branch ... cannot be created from it" for any HSE_REF other than the
# original clone's branch. `FETCH_HEAD` is set correctly by `git fetch` for
# a branch, a tag, or a SHA alike (empirically verified against a real repo
# for all three, plus switching ref on an existing clone), so checking it
# out directly removes the asymmetry instead of patching one branch of it.
mkdir -p "$HSE_INSTALL_DIR"
if [[ -d "$HSE_INSTALL_DIR/.git" ]]; then
    # Re-point origin at $HSE_REPO_URL first, so an SSH/token override
    # (HSE_REPO_URL=git@... ./install.sh) actually takes effect on a re-install
    # whose existing origin is the private HTTPS URL — otherwise the fetch
    # below would keep using the old, credential-gated remote.
    git -C "$HSE_INSTALL_DIR" remote set-url origin "$HSE_REPO_URL" 2>/dev/null || true
    ACTION="Updated existing clone"
else
    git -C "$HSE_INSTALL_DIR" init -q \
        || die "could not init $HSE_INSTALL_DIR"
    git -C "$HSE_INSTALL_DIR" remote add origin "$HSE_REPO_URL" \
        || die "could not configure origin remote"
    ACTION="Cloned fresh"
fi
git -C "$HSE_INSTALL_DIR" fetch --depth 1 origin "$HSE_REF" \
    || { clone_help; die "git fetch failed"; }
git -C "$HSE_INSTALL_DIR" checkout -B "$HSE_REF" FETCH_HEAD \
    || die "git checkout failed"
ok "$ACTION"

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

# Stale-artifact guard: a `pkg upgrade rust` between installs (Termux upgrades
# the toolchain often) leaves this cache built against the OLD rustc. Mixing
# toolchain outputs can surface as obscure metadata/format errors, so clear the
# profile outputs when the compiler version changed since the cache was last
# written. Cheap — a first install builds clean anyway; this only fires on a
# real version delta.
RUSTC_STAMP="$CARGO_TARGET_DIR/.hse-rustc-version"
RUSTC_NOW="$(rustc --version 2>/dev/null || echo unknown)"
if [[ -f "$RUSTC_STAMP" ]] && [[ "$(cat "$RUSTC_STAMP" 2>/dev/null)" != "$RUSTC_NOW" ]]; then
    log_warn "rustc changed since last build ($(cat "$RUSTC_STAMP") → $RUSTC_NOW) — clearing stale build cache"
    rm -rf "${CARGO_TARGET_DIR:?}/release" "${CARGO_TARGET_DIR:?}/fast" "${CARGO_TARGET_DIR:?}/debug" 2>/dev/null || true
fi

# Termux quirk: $TMPDIR sometimes too small. Override to $HOME/tmp if not big enough.
if [[ $IS_TERMUX -eq 1 ]]; then
    export TMPDIR="${TMPDIR:-$HOME/tmp}"
    mkdir -p "$TMPDIR"
fi

# This build has no `--target` — it always compiles for whatever `rustc`'s host
# is, i.e. host == target, unconditionally (on a real Termux device that's
# aarch64-linux-android; on a dev's own machine it's whatever that machine is).
# `-C target-cpu=native` is therefore always safe HERE specifically — unlike in
# `.cargo/config.toml`, which is keyed by target triple and can't tell this
# native build apart from CI's cross-compile of the SAME triple from a
# different host arch (where "native" would mean the wrong CPU). Exporting
# RUSTFLAGS (rather than editing config.toml) confines the flag to this one
# on-device invocation; it also REPLACES rather than merges with config.toml's
# `target.*.rustflags` for this call, so `--as-needed` is repeated here to keep
# that benefit rather than silently dropping it.
export RUSTFLAGS="${RUSTFLAGS:-} -C target-cpu=native -C link-arg=-Wl,--as-needed"

# Live progress so a long build never looks frozen:
#  1. Force cargo's progress bar ON even though stdout is piped to `tee` (a pipe
#     is not a TTY, so cargo would otherwise stay silent through the whole
#     compile — the #1 reason people Ctrl-C thinking it hung).
#  2. A heartbeat ticker for the final `Compiling huntsman-search-engine` step,
#     which is a single codegen+link unit that emits no progress for minutes.
export CARGO_TERM_PROGRESS_WHEN=always
export CARGO_TERM_PROGRESS_WIDTH=70
__hb_start=$(date +%s)
( while sleep 20; do
    printf '    %s… still compiling (%ss elapsed) — do NOT interrupt; the final huntsman-search-engine step is silent for a few minutes%s\n' \
        "$DIM" "$(( $(date +%s) - __hb_start ))" "$NC"
  done ) &
HB_PID=$!

# Retry the build twice — flaky mobile networks can interrupt crate downloads.
attempts=0
until cargo build --profile "$PROFILE" --locked; do
    attempts=$((attempts + 1))
    # Reactive net for the broken-sysroot case the pre-flight check missed: the
    # rlib-format error never recovers, so bail on first sight rather than
    # burning retries (and a confusing "slow network?" message) on it.
    if grep -q "required to be available in rlib format" "$LOG_FILE" 2>/dev/null; then
        die "build failed: the Termux 'rust' package has no static std (rlib).
  Upstream Termux packaging bug, not an HSE bug. The installer tries to download
  a prebuilt binary first; if you're here it wasn't available. Options:
    • check network + re-run (auto-fetches the prebuilt aarch64 binary)
    • pin a release:      HSE_PREBUILT_TAG=vX.Y.Z bash install.sh
    • use a local file:   HSE_PREBUILT=/path/to/hse bash install.sh
    • report it:          https://github.com/termux/termux-packages/issues"
    fi
    [[ $attempts -ge 3 ]] && die "cargo build failed after 3 attempts — check $LOG_FILE"
    log_warn "Build attempt $attempts failed; retrying (slow mobile network?)"
    sleep $((attempts * 3))
done

# Stop the heartbeat — build finished.
kill "$HB_PID" 2>/dev/null; HB_PID=""

# Record the toolchain that produced this cache, so the next run can detect a
# `pkg upgrade rust` and clear stale artifacts (see the stale-artifact guard).
printf '%s\n' "$RUSTC_NOW" > "$RUSTC_STAMP" 2>/dev/null || true

# `--profile release` outputs to target/release; `--profile fast` to target/fast.
BUILT="$CARGO_TARGET_DIR/$PROFILE/hse"
[[ -x "$BUILT" ]] || die "Build claimed success but $BUILT is missing"
ok "Built: $BUILT ($(du -h "$BUILT" | awk '{print $1}'))"

fi  # end PREBUILT guard — toolchain + clone + source build skipped when a prebuilt was used

# ─── Runtime dependencies for the prebuilt fast-path ─────────────────────────
# When a prebuilt binary was used the whole pkg-install block above was skipped,
# but the RUNTIME still needs `curl` (every paid-API and egress transport shells
# out to it — src/util/curl*, src/util/egress, src/util/key_pool/validation,
# api_key_probe, abn_lookup) and `git` (`hse update`'s self-update). Termux base
# ships neither, so a prebuilt install would otherwise produce a binary whose
# curl-backed modules all fail with command-not-found. The local-Downloads
# prebuilt path may run offline, so this is strictly best-effort: install what's
# missing, but never `die` — a prebuilt binary that merely lacks curl-backed
# modules still beats a failed install. Source builds already got both above.
if [[ "$PREBUILT" == "1" && $IS_TERMUX -eq 1 && "${HSE_NO_PKG:-0}" != "1" ]]; then
    _rt_missing=()
    command -v curl >/dev/null 2>&1 || _rt_missing+=(curl)
    command -v git >/dev/null 2>&1 || _rt_missing+=(git)
    if ((${#_rt_missing[@]})); then
        step "Installing runtime dependencies for the prebuilt binary (${_rt_missing[*]})"
        DEBIAN_FRONTEND=noninteractive apt-get update -y >> "$LOG_FILE" 2>&1 || true
        if DEBIAN_FRONTEND=noninteractive apt-get install -y "${_rt_missing[@]}" >> "$LOG_FILE" 2>&1; then
            ok "Runtime dependencies installed: ${_rt_missing[*]}"
        else
            log_warn "Could not install ${_rt_missing[*]} — curl-backed modules and 'hse update' may not work offline."
            hint "Install them later with: pkg install ${_rt_missing[*]}"
        fi
    fi
fi

# ─── Install binary ──────────────────────────────────────────────────────────
step "Installing binary to $HSE_BIN_DIR/hse"

[[ -n "$BUILT" && -x "$BUILT" ]] || die "internal: no binary to install (BUILT='$BUILT')"

# Existing-installation awareness: note whether a background server is already
# running the OLD binary, so we can restart it onto the new one after verifying
# (otherwise an upgrade silently keeps serving the previous version). hse-bg
# (Termux) records a PID file; a hand-started `hse serve` is found via pgrep.
RESTART_BG=0
RESTART_BARE=0
BG_PID_FILE="$HOME/.cache/hse-bg.pid"
if [[ -f "$BG_PID_FILE" ]] && kill -0 "$(cat "$BG_PID_FILE" 2>/dev/null)" 2>/dev/null; then
    RESTART_BG=1
    ok "Detected a running hse-bg server — will restart it onto the new build"
elif command -v pgrep >/dev/null 2>&1 && pgrep -f '[h]se serve' >/dev/null 2>&1; then
    RESTART_BARE=1
    ok "Detected a running 'hse serve' — will flag it for restart"
fi

# Atomic swap: stage the new binary under a temp name on the SAME filesystem,
# then rename(2) over the target. Rename is atomic and succeeds even while the
# old `hse` is mid-execution (a live `hse serve` upgrade) — overwriting it in
# place with `install` can fail with ETXTBSY or expose a half-written binary.
TMP_BIN="$HSE_BIN_DIR/.hse.new.$$"
install -m 0755 "$BUILT" "$TMP_BIN" \
    || die "could not stage the new binary in $HSE_BIN_DIR (writable?)"
mv -f "$TMP_BIN" "$HSE_BIN_DIR/hse" \
    || { rm -f "$TMP_BIN"; die "could not move the new binary onto $HSE_BIN_DIR/hse"; }
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
    # the APK from F-Droid is the actual sensor bridge. The single check here
    # (moved from a now-removed, earlier duplicate in the package-install
    # section above) always reports status, install-attempt or not — the old
    # early copy only ever printed a warning and never installed anything,
    # and both copies were gated on HSE_NO_PKG, so setting HSE_NO_PKG=1 left
    # an operator with NO sensor-module warning at all when termux-api was
    # missing. This one warns unconditionally when absent, and only attempts
    # the actual install when package installs aren't suppressed.
    if ! command -v termux-info >/dev/null 2>&1; then
        if [[ "${HSE_NO_PKG:-0}" != "1" ]]; then
            pkg install -y termux-api 2>/dev/null \
                && ok "Installed termux-api package" \
                || log_warn "Could not install termux-api (sensor modules will no-op)"
        else
            log_warn "termux-api is not installed — sensor modules (v0.6+) will no-op"
            hint "Install later: pkg install termux-api"
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
# Huntsman Search Engine (HSE) — API keys & configuration
# All-source OSINT / GEOINT / NETINT recon in the GhostSec tradition (SpiderFoot-inspired).
#
# Uncomment and paste a value to enable the corresponding key-gated module.
# File is chmod 0600 — never commit this file.
#
# The large majority of modules are free and need no keys at all — only the
# key-gated sources listed below require one. Run `hse doctor` for the live
# free / key-gated / paid split, or `hse keys status` for the key pool.
# The Settings page (hse serve → http://127.0.0.1:8080/settings) lets you
# paste and save any key directly from Chrome on the device.
#
# ── Identity / breach ─────────────────────────────────────────────────────────
#HUNTSMAN_HIBP_KEY=
#HUNTSMAN_OATHNET_KEY=
#HUNTSMAN_SEEKNOW_KEY=
#HUNTSMAN_FULLCONTACT_KEY=
#HUNTSMAN_NIAMONX_KEY=
# DeHashed — active search subscription + credits required:
#HUNTSMAN_DEHASHED_KEY=
#HUNTSMAN_INTELX_KEY=
#HUNTSMAN_HUNTER_KEY=
#HUNTSMAN_OPENSANCTIONS_KEY=
# ── Infrastructure / threat intel ─────────────────────────────────────────────
#HUNTSMAN_SHODAN_KEY=
#HUNTSMAN_SECTRAILS_KEY=
#HUNTSMAN_CENSYS_ID=
#HUNTSMAN_CENSYS_SECRET=
#HUNTSMAN_NETLAS_KEY=
#HUNTSMAN_ONYPHE_KEY=
#HUNTSMAN_LEAKIX_KEY=
#HUNTSMAN_ABUSEIPDB_KEY=
# abuse.ch — one key powers URLhaus, ThreatFox and MalwareBazaar:
#HUNTSMAN_ABUSECH_KEY=
#HUNTSMAN_THREATFOX_KEY=
#HUNTSMAN_ALIENVAULT_KEY=
#HUNTSMAN_GREYNOISE_KEY=
#HUNTSMAN_URLSCAN_KEY=
#HUNTSMAN_DOMAINSDB_KEY=
#HUNTSMAN_CRIMINALIP_KEY=
#HUNTSMAN_IPQS_KEY=
#HUNTSMAN_VIRUSTOTAL_KEY=
#HUNTSMAN_ZOOMEYE_KEY=
#HUNTSMAN_OSINTCAT_KEY=
# ── Search ────────────────────────────────────────────────────────────────────
#HUNTSMAN_EXA_KEY=
# ── Phone / HLR ───────────────────────────────────────────────────────────────
#HUNTSMAN_HLR_KEY=
#HUNTSMAN_OPENCNAM_KEY=
# ── Geolocation / cell towers ─────────────────────────────────────────────────
#HUNTSMAN_OPENCELLID_KEY=
# ── Validation / enrichment ───────────────────────────────────────────────────
#HUNTSMAN_NUMVERIFY_KEY=
#HUNTSMAN_WHOISXML_KEY=
#HUNTSMAN_WIGLE_USER=
#HUNTSMAN_WIGLE_TOKEN=
#HUNTSMAN_TROVE_KEY=
#HUNTSMAN_ABR_GUID=
# ── OSINT orchestration / identity ────────────────────────────────────────────
#HUNTSMAN_SEON_KEY=
#HUNTSMAN_EMAILREP_KEY=
#HUNTSMAN_EPIEOS_KEY=
#HUNTSMAN_PROXYCURL_KEY=
#HUNTSMAN_OPENCORP_KEY=
# GitHub token — OPTIONAL: github_* modules run unauthenticated but a classic
# PAT (no scopes needed for public data) raises GitHub's low anonymous rate limit.
#HUNTSMAN_GITHUB_TOKEN=
#
# ── Operator defaults ─────────────────────────────────────────────────────────
# Set your own default scan target to avoid retyping --value every run.
# An explicit --value always overrides this.
#HUNTSMAN_DEFAULT_SEED=
#
# ── Egress rotation (optional) ────────────────────────────────────────────────
# Route scans through a proxy / rotate DNS resolvers to avoid per-source limits.
# Hosts listed here are auto-excluded from being scanned as targets.
#   HUNTSMAN_SEARCH_PROXY=socks5://127.0.0.1:9050,http://host:3128
#   HUNTSMAN_DNS_RESOLVERS=cloudflare,google,quad9
#HUNTSMAN_SEARCH_PROXY=
#HUNTSMAN_DNS_RESOLVERS=
TEMPLATE
    chmod 0600 "$KEYS_PATH"
    ok "Template created (chmod 0600)"
else
    ok "Keys file already present at $KEYS_PATH"
fi

# ─── Record install location for `hse update` ────────────────────────────────
# hse update reads HUNTSMAN_INSTALL_DIR from ~/.huntsman.env to find install.sh,
# then git-pulls + re-runs it. Only record the dir when it is ACTUALLY a source
# tree: a prebuilt install skips the clone above, so $HSE_INSTALL_DIR then has no
# install.sh/Cargo.toml, and recording it would point `hse update` (and the
# background auto-updater) at a directory with no `.git` — where every git call
# silently fails, so the updater no-ops while still burning a git subprocess
# each throttle window. When there is no source tree, leave HUNTSMAN_INSTALL_DIR
# unset: `find_install_dir()` then falls through cleanly and `hse update` reports
# the reinstall one-liner instead of a silent, wasteful no-op. Prebuilt users
# upgrade by re-running the installer (which re-detects a newer prebuilt).
# Use grep+printf instead of sed so special characters in HSE_INSTALL_DIR
# (e.g. & | \ in the path) are never interpreted as sed metacharacters.
# chmod 0600 before mv preserves the key-file mode that Rust sets on creation.
if [[ -f "$HSE_INSTALL_DIR/install.sh" && -f "$HSE_INSTALL_DIR/Cargo.toml" ]]; then
    {
        grep -v '^HUNTSMAN_INSTALL_DIR=' "$KEYS_PATH" 2>/dev/null || true
        printf '\n# Written by install.sh — used by `hse update`\nHUNTSMAN_INSTALL_DIR=%s\n' \
            "$HSE_INSTALL_DIR"
    } > "$KEYS_PATH.tmp" \
        && chmod 0600 "$KEYS_PATH.tmp" \
        && mv -f "$KEYS_PATH.tmp" "$KEYS_PATH"
else
    # Prebuilt install (no source tree) — drop any stale dir a prior source
    # install recorded, so `hse update` doesn't git against a now-absent repo.
    if grep -q '^HUNTSMAN_INSTALL_DIR=' "$KEYS_PATH" 2>/dev/null; then
        { grep -v '^HUNTSMAN_INSTALL_DIR=' "$KEYS_PATH" 2>/dev/null || true; } > "$KEYS_PATH.tmp" \
            && chmod 0600 "$KEYS_PATH.tmp" \
            && mv -f "$KEYS_PATH.tmp" "$KEYS_PATH"
    fi
    hint "Prebuilt install: to upgrade later, re-run the installer (curl … | bash) — it re-detects a newer prebuilt."
fi

# Seed the auto-update throttle stamp so the freshly-installed binary (which is,
# by definition, current with main right now) doesn't immediately re-check on its
# first CLI invocation. The CLI gate reads this file (~/.cache/hse-autoupdate.stamp).
mkdir -p "$LOG_DIR" 2>/dev/null || true
date +%s > "$LOG_DIR/hse-autoupdate.stamp" 2>/dev/null || true

# ─── Verify ──────────────────────────────────────────────────────────────────
step "Verifying installation"
"$HSE_BIN_DIR/hse" --version
echo
# `hse doctor` is an informational health report here — `--version` above is the
# install-success gate. `doctor` now exits non-zero on a CRITICAL storage fault
# (e.g. a pre-existing corrupt database this fresh binary did not create and
# cannot fix), so `|| true` keeps that from aborting an otherwise-successful
# install under `set -e`; the FAIL lines still print for the operator to see.
"$HSE_BIN_DIR/hse" doctor || true

# ─── Restart an already-running server onto the new binary ───────────────────
# Completes the "all-in-one upgrade" contract: a re-install over a live server
# leaves the new binary on disk but the old code in memory until something
# restarts it. The hse-bg wrapper (rewritten above) is safe to bounce; a bare
# foreground `hse serve` is left alone (the operator is watching it) with a hint.
if [[ "${RESTART_BG:-0}" -eq 1 && -x "$HSE_BIN_DIR/hse-bg" ]]; then
    step "Restarting background server onto the new build"
    "$HSE_BIN_DIR/hse-bg" stop  >/dev/null 2>&1 || true
    if "$HSE_BIN_DIR/hse-bg" start; then
        ok "hse-bg restarted on hse $("$HSE_BIN_DIR/hse" --version 2>/dev/null | awk '{print $NF}')"
    else
        log_warn "Could not auto-restart hse-bg — run it yourself: hse-bg start"
    fi
elif [[ "${RESTART_BG:-0}" -eq 1 || "${RESTART_BARE:-0}" -eq 1 ]]; then
    log_warn "A foreground 'hse serve' is still running the PREVIOUS binary."
    hint "Restart it to pick up this upgrade:"
    hint "  press Ctrl-C in its terminal, then re-run:  hse serve"
fi

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
