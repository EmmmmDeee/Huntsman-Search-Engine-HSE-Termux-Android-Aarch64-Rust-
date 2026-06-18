#!/usr/bin/env bash
# Huntsman Search Engine — smart installer
#
# USAGE (zip already in Downloads):
#   bash install.sh
#
# USAGE (paste directly into Termux):
#   bash << 'EOF'
#   <paste this whole file>
#   EOF
#
# ENV KNOBS (all optional):
#   HSE_BUILD_PROFILE   fast|release   (fast ≈ 4-6 min on aarch64)
#   HSE_PREFER_BUILD    1 = skip prebuilt scan, always build
#   CARGO_TARGET_DIR    build artefact location (default: ~/.cache/hse-build)
#   GITHUB_TOKEN        PAT for private repo clone (curl mode only)
#   HSE_REPO_URL        git URL override
#   HSE_REF             branch/tag/SHA (default: claude/vigilant-galileo-vmjk3e)

set -uo pipefail

# ── Helpers ───────────────────────────────────────────────────────────────────
[[ -t 1 ]] \
  && { G=$'\e[32m' R=$'\e[31m' Y=$'\e[33m' B=$'\e[1m' Z=$'\e[0m'; } \
  || { G=         R=          Y=          B=          Z=;          }

BAR="━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
step() { printf "\n${B}%s\n  ▸ %s\n%s${Z}\n" "$BAR" "$*" "$BAR"; }
ok()   { printf "  ${G}✓${Z}  %s\n" "$*"; }
info() { printf "  ${Y}·${Z}  %s\n" "$*"; }
warn() { printf "  ${Y}!${Z}  %s\n" "$*" >&2; }
die()  { printf "\n  ${R}✗${Z}  %s\n\n" "$*" >&2; exit 1; }

# ── Environment ───────────────────────────────────────────────────────────────
IS_TERMUX=0
[[ -n "${TERMUX_VERSION:-}" || -d /data/data/com.termux ]] && IS_TERMUX=1
: "${PREFIX:=/data/data/com.termux/files/usr}"
DEST="$([[ $IS_TERMUX -eq 1 ]] && echo "$PREFIX/bin" || echo "$HOME/.local/bin")"
CACHE="${CARGO_TARGET_DIR:-$HOME/.cache/hse-build}"
PROFILE="${HSE_BUILD_PROFILE:-$([[ $IS_TERMUX -eq 1 ]] && echo fast || echo release)}"
LOG="$HOME/.cache/hse-install.log"
EXTRACT="$HOME/.hse-extract-$$"
_HB=""

mkdir -p "$HOME/.cache" "$DEST"
: > "$LOG"
exec > >(tee -a "$LOG") 2>&1

# Cleanup: kill heartbeat + remove temp extract dir
trap '[[ -n "$_HB" ]] && kill "$_HB" 2>/dev/null; rm -rf "$EXTRACT"' EXIT

step "HSE Installer"
[[ $IS_TERMUX -eq 1 ]] && ok "Termux ${TERMUX_VERSION:-detected}" \
                        || ok "Standard Unix environment"

# ── 1. Already installed and working? (fast path) ─────────────────────────────
if _v=$(hse --version 2>/dev/null) && [[ "$_v" == hse\ * ]]; then
  ok "Already installed: $_v"
  echo
  hse doctor 2>&1 | sed 's/^/  /'
  echo
  if [[ $IS_TERMUX -eq 1 ]] && command -v hse-bg >/dev/null 2>&1; then
    hse-bg start
  else
    info "Run: hse serve  →  http://127.0.0.1:8080"
  fi
  printf "\n  Log: %s\n\n" "$LOG"
  trap - EXIT; exit 0
fi

# ── 2. Prebuilt binary scan ───────────────────────────────────────────────────
# Copy candidate to exec-safe location (sdcard is noexec), run-test, install.
_try_bin() {
  local src="$1"
  [[ -f "$src" ]] || return 1
  local probe="$HOME/.cache/.hse-probe-$$"
  cp "$src" "$probe" 2>/dev/null && chmod 755 "$probe" || { rm -f "$probe"; return 1; }
  local v; v=$("$probe" --version 2>/dev/null) && [[ "$v" == hse\ * ]] \
    || { warn "skip $(basename "$src") — wrong arch or corrupt"; rm -f "$probe"; return 1; }
  install -m755 "$probe" "$DEST/hse"; rm -f "$probe"
  ok "Prebuilt installed: $DEST/hse  ($v)"
}

INSTALLED=0
if [[ "${HSE_PREFER_BUILD:-0}" != "1" ]]; then
  step "Scanning for prebuilt binary"
  for _src in \
      "$CACHE/fast/hse" \
      "$CACHE/release/hse" \
      "$HOME/storage/downloads/hse-aarch64-linux-android" \
      "/storage/emulated/0/Download/hse-aarch64-linux-android" \
      "/sdcard/Download/hse-aarch64-linux-android"; do
    _try_bin "$_src" && { INSTALLED=1; break; } || true
  done
  [[ $INSTALLED -eq 1 ]] || info "No usable prebuilt found — will build from source"
fi

# ── 3. Source tree scan ───────────────────────────────────────────────────────
SRC=""
if [[ $INSTALLED -eq 0 ]]; then
  step "Scanning for source"

  # Helper: is this directory an HSE source tree?
  _is_hse() { [[ -f "$1/Cargo.toml" ]] && grep -q 'huntsman-search-engine' "$1/Cargo.toml" 2>/dev/null; }

  # Self-detection: if this script sits next to a Cargo.toml, use that tree.
  _SD="$(cd "$(dirname "${BASH_SOURCE[0]:-}")" 2>/dev/null && pwd || true)"
  _is_hse "$_SD" && { SRC="$_SD"; ok "Source: $SRC (script directory)"; }

  # Previously cloned trees
  if [[ -z "$SRC" ]]; then
    for _d in "$HOME/hse" "$HOME/hse-src" "$HOME/.local/share/hse"; do
      _is_hse "$_d" && { SRC="$_d"; ok "Source: $SRC"; break; }
    done
  fi

  # Zip search — tests real open() not just stat(), so blocked zips are detected precisely
  if [[ -z "$SRC" ]]; then
    _blocked=""
    for _z in \
        "$HOME/HSE.zip" \
        "$HOME/storage/downloads/HSE.zip" \
        "/storage/emulated/0/Download/HSE.zip" \
        "/sdcard/Download/HSE.zip"; do
      stat "$_z" >/dev/null 2>&1 || continue
      if dd if="$_z" bs=4 count=1 of=/dev/null 2>/dev/null; then
        ok "Zip: $_z  ($(stat -c%s "$_z" 2>/dev/null) bytes)"
        mkdir -p "$EXTRACT"
        unzip -q "$_z" -d "$EXTRACT" || die "Unzip failed: $_z"
        for _x in "$EXTRACT"/*/; do
          _is_hse "${_x%/}" && { SRC="${_x%/}"; ok "Extracted: $SRC"; break 2; }
        done
        die "No HSE Cargo.toml found inside zip"
      else
        _blocked="$_z"
        warn "Zip found but unreadable (scoped storage): $_z"
      fi
    done

    if [[ -z "$SRC" && -n "$_blocked" ]]; then
      printf "\n  ${R}Storage permission not active for this process.${Z}\n"
      printf "  ${B}Fix:${Z} Android Settings → Apps → Termux → Force Stop\n"
      printf "       Reopen Termux → paste this script again.\n\n"
      printf "  (The permission was granted, but only takes effect in a fresh process.)\n\n"
      exit 1
    fi
  fi

  # Remote clone fallback (curl/git mode)
  if [[ -z "$SRC" ]]; then
    REPO="${HSE_REPO_URL:-https://github.com/EmmmmDeee/Huntsman-Search-Engine-HSE-Termux-Android-Aarch64-Rust-.git}"
    REF="${HSE_REF:-claude/vigilant-galileo-vmjk3e}"
    SRC="${HSE_INSTALL_DIR:-$HOME/.local/share/hse}"
    _REMOTE="$REPO"
    [[ -n "${GITHUB_TOKEN:-}" && "$REPO" == https://github.com/* ]] \
      && _REMOTE="https://x-access-token:${GITHUB_TOKEN}@${REPO#https://}"
    step "Cloning source → $SRC"
    export GIT_TERMINAL_PROMPT=0
    mkdir -p "$(dirname "$SRC")"
    if [[ -d "$SRC/.git" ]]; then
      git -C "$SRC" remote set-url origin "$_REMOTE" 2>/dev/null || true
      git -C "$SRC" fetch --depth 1 origin "$REF" \
        || die "git fetch failed — private repo? set GITHUB_TOKEN=<pat>"
      git -C "$SRC" checkout -B "$REF" "origin/$REF"
      ok "Updated: $SRC"
    else
      git clone --depth 1 --branch "$REF" "$_REMOTE" "$SRC" \
        || die "git clone failed — private repo? set GITHUB_TOKEN=<pat>"
      ok "Cloned: $SRC"
    fi
  fi
fi

# ── 4. Build ──────────────────────────────────────────────────────────────────
if [[ $INSTALLED -eq 0 ]]; then
  [[ -n "$SRC" ]] || die "No source tree found. Download HSE.zip to ~/storage/downloads and retry."

  [[ "$PROFILE" == fast ]] && ETA="~4-6 min" || ETA="~15-20 min"
  step "Building HSE  [profile=$PROFILE, $ETA on aarch64]"

  if [[ $IS_TERMUX -eq 1 ]]; then
    command -v cargo >/dev/null 2>&1 \
      || { pkg install -y rust binutils clang make pkg-config 2>/dev/null || true; }
  fi
  command -v cargo >/dev/null 2>&1 || die "cargo not found — run: pkg install rust"
  ok "$(rustc --version)"
  warn "Final link step is silent for several minutes — do not interrupt"

  export CARGO_TARGET_DIR="$CACHE"
  export CARGO_TERM_PROGRESS_WHEN=always
  export CARGO_TERM_PROGRESS_WIDTH=72
  if [[ $IS_TERMUX -eq 1 ]]; then
    export TMPDIR="${TMPDIR:-$HOME/tmp}"; mkdir -p "$TMPDIR"
  fi
  mkdir -p "$CACHE"

  _t0=$(date +%s)
  ( while sleep 30; do
      printf '    … still compiling (%ds elapsed)\n' "$(( $(date +%s) - _t0 ))"
    done ) &
  _HB=$!

  ( cd "$SRC" && cargo build --profile "$PROFILE" --locked ) \
    || die "Build failed — log: $LOG"

  kill "$_HB" 2>/dev/null; _HB=""

  BUILT="$CACHE/$PROFILE/hse"
  [[ -x "$BUILT" ]] || die "Binary missing after build: $BUILT"
  ok "Built: $BUILT"

  _tmp="$DEST/.hse.new.$$"
  install -m755 "$BUILT" "$_tmp" && mv -f "$_tmp" "$DEST/hse" \
    || { rm -f "$_tmp"; die "Install to $DEST failed"; }
  ok "Installed: $DEST/hse  ($("$DEST/hse" --version))"

  # Cache prebuilt to Downloads — write() works even when read() is blocked,
  # so the next install finds this and skips the compile entirely.
  if [[ $IS_TERMUX -eq 1 ]]; then
    for _dl in "$HOME/storage/downloads" "/storage/emulated/0/Download"; do
      [[ -d "$_dl" && -w "$_dl" ]] \
        && cp -f "$BUILT" "$_dl/hse-aarch64-linux-android" 2>/dev/null \
        && { ok "Prebuilt cached → $_dl/hse-aarch64-linux-android  (next install is instant)"; break; } \
        || true
    done
  fi
fi

# ── 5. hse-bg background wrapper ─────────────────────────────────────────────
if [[ $IS_TERMUX -eq 1 && ! -f "$DEST/hse-bg" ]]; then
  cat > "$DEST/hse-bg" << 'HSBG'
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
    echo "Started (pid $!). Open: http://127.0.0.1:8080";;
  stop)
    [[ -f "$P" ]] && kill "$(cat "$P")" 2>/dev/null; rm -f "$P"
    command -v termux-wake-unlock >/dev/null && termux-wake-unlock
    echo "Stopped.";;
  status)
    [[ -f "$P" ]] && kill -0 "$(cat "$P")" 2>/dev/null \
      && echo "Running (pid $(cat "$P"))" || echo "Not running";;
  log)  tail -f "$L";;
  *)    echo "Usage: hse-bg [start|stop|status|log]";;
esac
HSBG
  chmod 755 "$DEST/hse-bg"
  ok "Installed hse-bg  (start|stop|status|log)"
fi

# ── 6. API keys template ──────────────────────────────────────────────────────
KEYS="$HOME/.huntsman.env"
if [[ -f "$KEYS" ]]; then
  ok "Keys: $KEYS  ($(grep -c '^[A-Z]' "$KEYS" 2>/dev/null || echo 0) active)"
else
  cat > "$KEYS" << 'KEOF'
# HSE API keys — uncomment and fill to enable key-gated modules.
# chmod 0600 — never commit this file.
# Paste via Web UI: hse-bg start → Chrome → Settings tab.
#HUNTSMAN_HIBP_KEY=
#HUNTSMAN_SHODAN_KEY=
#HUNTSMAN_VIRUSTOTAL_KEY=
#HUNTSMAN_SECTRAILS_KEY=
#HUNTSMAN_LEAKIX_KEY=
#HUNTSMAN_CRIMINALIP_KEY=
#HUNTSMAN_EMAILREP_KEY=
#HUNTSMAN_EXA_KEY=
#HUNTSMAN_WIGLE_USER=
#HUNTSMAN_WIGLE_TOKEN=
#HUNTSMAN_DEFAULT_SEED=
KEOF
  chmod 0600 "$KEYS"
  ok "Created $KEYS"
fi

# ── 7. Verify + launch ────────────────────────────────────────────────────────
step "Verify"
"$DEST/hse" --version
"$DEST/hse" doctor 2>&1 | sed 's/^/  /'

step "Done"
if [[ $IS_TERMUX -eq 1 ]]; then
  hse-bg start
  printf "\n  Chrome → http://127.0.0.1:8080\n"
else
  printf "\n  Run: hse serve  →  http://127.0.0.1:8080\n"
fi
printf "  Log:    %s\n\n" "$LOG"

trap - EXIT
