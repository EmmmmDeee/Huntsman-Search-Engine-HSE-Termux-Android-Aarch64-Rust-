#!/usr/bin/env bash
# HSE diagnostic — run this in Termux, paste the full output back to Claude.
# Usage: bash diagnose.sh [path/to/HSE.zip]
set -uo pipefail

ZIP_ARG="${1:-}"

SEP="━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
sec()  { echo; echo "$SEP"; echo "  $*"; echo "$SEP"; }
kv()   { printf "  %-34s %s\n" "$1:" "$2"; }
ok()   { printf "  %-34s %s\n" "$1:" "[OK] $2"; }
fail() { printf "  %-34s %s\n" "$1:" "[FAIL] $2"; }
na()   { printf "  %-34s %s\n" "$1:" "(not found)"; }

echo
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║           HSE Install Diagnostic Report                     ║"
echo "╚══════════════════════════════════════════════════════════════╝"
printf "  Generated: %s\n" "$(date -Iseconds 2>/dev/null || date)"

# ── 1. Device & OS ───────────────────────────────────────────────────────────
sec "1. DEVICE & OS"
kv "uname -m (arch)"         "$(uname -m 2>/dev/null || echo unknown)"
kv "uname -r (kernel)"       "$(uname -r 2>/dev/null || echo unknown)"
kv "uname -o (OS)"           "$(uname -o 2>/dev/null || echo unknown)"
kv "Android SDK"             "${ANDROID_DATA:+set (SDK likely via prop)}"
# Try getprop
if command -v getprop >/dev/null 2>&1; then
    kv "ro.build.version.sdk"  "$(getprop ro.build.version.sdk 2>/dev/null || echo n/a)"
    kv "ro.build.version.release" "$(getprop ro.build.version.release 2>/dev/null || echo n/a)"
    kv "ro.product.model"      "$(getprop ro.product.model 2>/dev/null || echo n/a)"
    kv "ro.product.manufacturer" "$(getprop ro.product.manufacturer 2>/dev/null || echo n/a)"
else
    kv "getprop"               "not available"
fi

# ── 2. Termux environment ────────────────────────────────────────────────────
sec "2. TERMUX ENVIRONMENT"
kv "TERMUX_VERSION"      "${TERMUX_VERSION:-not set}"
kv "PREFIX"              "${PREFIX:-not set}"
kv "HOME"                "${HOME:-not set}"
kv "TMPDIR"              "${TMPDIR:-not set}"
kv "ANDROID_DATA"        "${ANDROID_DATA:-not set}"
kv "EXTERNAL_STORAGE"    "${EXTERNAL_STORAGE:-not set}"

# Check Termux pkg
if command -v pkg >/dev/null 2>&1; then
    VER=$(pkg --version 2>/dev/null | head -1 || echo unknown)
    ok "pkg" "$VER"
else
    fail "pkg" "not in PATH"
fi

# ── 3. PATH & key binaries ───────────────────────────────────────────────────
sec "3. PATH & KEY BINARIES"
kv "PATH" "$PATH"
for BIN in bash cargo rustc git curl unzip cp install termux-setup-storage termux-wake-lock; do
    LOC=$(command -v "$BIN" 2>/dev/null)
    if [[ -n "$LOC" ]]; then
        case "$BIN" in
            cargo)  ok  "$BIN" "$LOC  ($(cargo --version 2>/dev/null | head -1 || echo ?))";;
            rustc)  ok  "$BIN" "$LOC  ($(rustc --version 2>/dev/null | head -1 || echo ?))";;
            git)    ok  "$BIN" "$LOC  ($(git --version 2>/dev/null | head -1 || echo ?))";;
            *)      ok  "$BIN" "$LOC" ;;
        esac
    else
        fail "$BIN" "not found"
    fi
done

# ── 4. Storage symlinks ──────────────────────────────────────────────────────
sec "4. STORAGE SYMLINKS (~/storage/)"
STOR="$HOME/storage"
if [[ -d "$STOR" ]]; then
    ok "~/storage exists" ""
    for LINK in downloads dcim movies music pictures shared; do
        TARGET=$(readlink "$STOR/$LINK" 2>/dev/null || echo "(not a symlink)")
        if [[ -L "$STOR/$LINK" ]]; then
            printf "  %-34s -> %s\n" "~/storage/$LINK" "$TARGET"
        else
            fail "~/storage/$LINK" "missing"
        fi
    done
else
    fail "~/storage" "directory missing — run: termux-setup-storage"
fi

# ── 5. Storage permission probe ──────────────────────────────────────────────
sec "5. STORAGE PERMISSION PROBE"
# This is the critical section — tests stat vs open (the EACCES issue)

_probe_dir() {
    local label="$1" dir="$2"
    printf "\n  Testing: %s\n" "$dir"

    # a) directory exists?
    if [[ ! -e "$dir" ]]; then
        fail "  exists"   "no such path"
        return
    fi
    ok "  exists" ""

    # b) stat works?
    if stat "$dir" >/dev/null 2>&1; then
        ok "  stat()" "works"
    else
        fail "  stat()" "failed (EACCES on stat itself)"
    fi

    # c) readdir / ls?
    COUNT=$(ls "$dir" 2>/dev/null | wc -l || echo "ERR")
    if [[ "$COUNT" =~ ^[0-9]+$ ]]; then
        ok "  readdir/ls" "$COUNT entries visible"
    else
        fail "  readdir/ls" "failed — scoped storage blocking directory listing"
    fi

    # d) write probe
    PROBE="$dir/.hse_probe_$$"
    if touch "$PROBE" 2>/dev/null; then
        ok "  write" "works"
        rm -f "$PROBE" 2>/dev/null || true
    else
        fail "  write" "failed — read-only or permission denied"
    fi
}

_probe_dir "downloads symlink" "$HOME/storage/downloads"
_probe_dir "primary external"  "/storage/emulated/0"
_probe_dir "Download dir"      "/storage/emulated/0/Download"

# e) Probe any zip candidates
echo
echo "  Zip file candidates:"
FOUND_ZIP=0
for CANDIDATE in \
    "$ZIP_ARG" \
    "$HOME/storage/downloads/HSE.zip" \
    "/storage/emulated/0/Download/HSE.zip" \
    "$HOME/storage/downloads/hse.zip" \
    "/storage/emulated/0/Download/hse.zip"; do
    [[ -z "$CANDIDATE" ]] && continue

    printf "\n  Path: %s\n" "$CANDIDATE"
    # stat
    if stat "$CANDIDATE" >/dev/null 2>&1; then
        SIZE=$(stat -c%s "$CANDIDATE" 2>/dev/null || stat -f%z "$CANDIDATE" 2>/dev/null || echo "?")
        ok "    stat()" "exists, size=${SIZE} bytes"
    else
        fail "    stat()" "does not exist or EACCES on stat"
        continue
    fi
    FOUND_ZIP=1
    # open for reading
    if dd if="$CANDIDATE" bs=1 count=4 >/dev/null 2>&1; then
        ok "    open()+read" "works — cp/unzip will succeed"
    else
        fail "    open()+read" "EACCES — scoped storage blocking read (fix: Settings → Apps → Termux → Permissions → Files and media → Allow management of all files)"
    fi
    # zip integrity (if unzip available)
    if command -v unzip >/dev/null 2>&1; then
        if unzip -t "$CANDIDATE" >/dev/null 2>&1; then
            ok "    unzip -t"  "zip integrity OK"
        else
            fail "    unzip -t" "either corrupt or unreadable"
        fi
    fi
done
[[ "$FOUND_ZIP" -eq 0 ]] && fail "  HSE.zip" "not found in any standard location — download it from the GitHub Releases page in Chrome"

# ── 6. Disk & memory ────────────────────────────────────────────────────────
sec "6. DISK & MEMORY"
kv "df HOME"   "$(df -h "$HOME" 2>/dev/null | tail -1 || echo n/a)"
kv "df PREFIX" "$(df -h "${PREFIX:-/data/data/com.termux/files/usr}" 2>/dev/null | tail -1 || echo n/a)"
kv "df /tmp"   "$(df -h /tmp 2>/dev/null | tail -1 || echo n/a)"
FREE_KB=$(awk '/MemFree|MemAvailable/{sum+=$2}END{print sum}' /proc/meminfo 2>/dev/null || echo 0)
kv "Free RAM"  "$(( FREE_KB / 1024 )) MB"
TOTAL_KB=$(awk '/MemTotal/{print $2}' /proc/meminfo 2>/dev/null || echo 0)
kv "Total RAM" "$(( TOTAL_KB / 1024 )) MB"

# ── 7. HSE install state ─────────────────────────────────────────────────────
sec "7. HSE INSTALL STATE"
HSE_BIN=$(command -v hse 2>/dev/null || echo "")
if [[ -n "$HSE_BIN" ]]; then
    ok  "hse binary"  "$HSE_BIN"
    kv  "hse --version" "$(hse --version 2>/dev/null || echo '(failed)')"
    kv  "hse doctor"    ""
    hse doctor 2>&1 | sed 's/^/    /' || true
else
    fail "hse binary" "not found in PATH"
fi

HSE_BG=$(command -v hse-bg 2>/dev/null || echo "")
[[ -n "$HSE_BG" ]] && ok "hse-bg" "$HSE_BG" || fail "hse-bg" "not installed"

kv "~/.huntsman.env"  "$([[ -f "$HOME/.huntsman.env" ]] && echo "exists ($(stat -c%a "$HOME/.huntsman.env" 2>/dev/null || echo ?) perms)" || echo "missing")"
kv "~/.huntsman/"     "$([[ -d "$HOME/.huntsman" ]] && echo "exists" || echo "missing")"
kv "~/.cache/hse-build/" "$([[ -d "$HOME/.cache/hse-build" ]] && echo "exists" || echo "missing")"

# ── 8. Build cache / prebuilt ────────────────────────────────────────────────
sec "8. PREBUILT BINARY CACHE"
for P in \
    "$HOME/.cache/hse-build/fast/hse" \
    "$HOME/.cache/hse-build/release/hse" \
    "$HOME/storage/downloads/hse-aarch64-linux-android" \
    "/storage/emulated/0/Download/hse-aarch64-linux-android"; do
    if [[ -f "$P" ]]; then
        SZ=$(stat -c%s "$P" 2>/dev/null || echo "?")
        ok "$P" "${SZ} bytes"
    fi
done

# ── 9. Install log tail ──────────────────────────────────────────────────────
LOG="$HOME/.cache/hse-install.log"
if [[ -f "$LOG" ]]; then
    sec "9. LAST INSTALL LOG (tail -40)"
    tail -40 "$LOG" | sed 's/^/  /'
fi

# ── 10. Git state (if inside repo) ──────────────────────────────────────────
sec "10. GIT STATE"
if git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    kv "branch"  "$(git rev-parse --abbrev-ref HEAD 2>/dev/null)"
    kv "tip SHA" "$(git rev-parse --short HEAD 2>/dev/null)"
    kv "remote"  "$(git remote get-url origin 2>/dev/null || echo none)"
    echo
    echo "  Recent commits:"
    git log --oneline -5 2>/dev/null | sed 's/^/    /'
    echo
    echo "  git status:"
    git status --short 2>/dev/null | sed 's/^/    /' || true
else
    kv "git" "not inside a git repo"
fi

# ── 11. Network probe ────────────────────────────────────────────────────────
sec "11. NETWORK"
for HOST in github.com raw.githubusercontent.com api.github.com 8.8.8.8; do
    if ping -c1 -W2 "$HOST" >/dev/null 2>&1; then
        ok "$HOST" "reachable"
    else
        fail "$HOST" "unreachable (offline, or ping blocked)"
    fi
done

# ── 12. install.sh smoke check ───────────────────────────────────────────────
sec "12. INSTALL.SH SMOKE CHECK"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" 2>/dev/null && pwd || true)"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"
IPATH="$REPO_ROOT/install.sh"
if [[ -f "$IPATH" ]]; then
    ok  "install.sh found" "$IPATH"
    kv  "size"  "$(wc -l < "$IPATH") lines"
    grep -q 'LOCAL_SRC' "$IPATH" \
        && ok  "zip-detect logic" "present (LOCAL_SRC)" \
        || fail "zip-detect logic" "missing — install.sh may be stale"
    grep -q 'BASH_SOURCE' "$IPATH" \
        && ok  "BASH_SOURCE ref"  "present" \
        || fail "BASH_SOURCE ref"  "missing"
    grep -q 'hse-bg' "$IPATH" \
        && ok  "hse-bg embed"     "present" \
        || fail "hse-bg embed"    "missing"
    bash -n "$IPATH" 2>&1 \
        && ok  "bash syntax"      "valid" \
        || fail "bash syntax"     "SYNTAX ERROR (see above)"
else
    fail "install.sh" "not found at $IPATH"
fi

# ── Done ─────────────────────────────────────────────────────────────────────
echo
echo "$SEP"
echo "  END OF REPORT — paste everything above back to Claude"
echo "$SEP"
echo
