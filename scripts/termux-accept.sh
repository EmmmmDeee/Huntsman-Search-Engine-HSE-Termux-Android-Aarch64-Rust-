#!/usr/bin/env bash
# On-device acceptance: the evidence that one exact commit builds and runs on a
# real Termux arm64 device (REQ-ACCEPT-001).
#
# Cloud CI proves cloud success. It cross-compiles for aarch64-linux-android
# but runs nothing there, so it cannot vouch for the device
# (docs/OPERATING_ARCHITECTURE.md §5). This script is the device-side stage of
# that ladder, reduced to one command and one record:
#
#   checkout   HEAD, with no uncommitted change: the commit under test, not
#              local state that exists nowhere else
#   platform   aarch64 + Termux + Android (getprop), or an explicit --host run
#              marked as such
#   build      cargo build --locked --profile <p> --bin hse    (time, size)
#   identity   the built binary's `hse build-sha --json` is HEAD, verifiable
#   tests      cargo test --locked --lib --bins --tests         (--skip-tests)
#   restart    a setting written by one `hse` process is read back by a new
#              one, in a scratch HOME that never touches the operator's state
#              and has automatic updates off
#   install    opt-in (--install): the commit's installer builds and installs
#              HEAD where it installs for an operator, never into the checkout,
#              and the `hse` on PATH then proves it is HEAD
#   resources  binary size, free disk, battery level if termux-api is present
#   unchanged  the build and the checkout are still the commit, clean, with the
#              same origin: nothing the run started edited either
#
# Build, tests and install run in a private detached worktree of HEAD
# (~/.cache/hse-accept/), in the target directory cargo reports, so an edit git
# status cannot see, an ignored file, or an edit made during the run is never
# what gets tested. The worktree is kept for the next run's incremental build.
#
# It writes one JSON record to $HOME/.huntsman/acceptance/<sha>.json (or
# --out FILE) and prints it. The verdict is:
#   ACCEPTED   a Termux arm64 device, every stage run and passed
#   PARTIAL    a device, and every stage run passed, but tests were skipped
#   HOST-ONLY  --host: passed, but this is not device evidence
#   REJECTED   a stage failed
# Exit 0 unless a stage failed (1) or the run was refused before building (2).
#
# Usage: scripts/termux-accept.sh [--host] [--skip-tests] [--install]
#                                 [--profile fast|release|dev] [--out FILE]
set -uo pipefail

HOST=0
SKIP_TESTS=0
INSTALL=0
PROFILE="${HSE_BUILD_PROFILE:-fast}"
OUT=""
while [ "$#" -gt 0 ]; do
    case "$1" in
        --host) HOST=1 ;;
        --skip-tests) SKIP_TESTS=1 ;;
        --install) INSTALL=1 ;;
        --profile) PROFILE="${2:-}"; shift ;;
        --out) OUT="${2:-}"; shift ;;
        -h | --help) sed -n '2,41p' "$0"; exit 0 ;;
        *) echo "termux-accept: unknown argument '$1' (see --help)" >&2; exit 2 ;;
    esac
    shift
done
case "$PROFILE" in
    fast | release) PROFILE_DIR="$PROFILE" ;;
    dev) PROFILE_DIR=debug ;;
    *) echo "termux-accept: --profile must be fast, release or dev" >&2; exit 2 ;;
esac

log() { printf '\033[1;36m==>\033[0m %s\n' "$*" >&2; }
# A JSON string value: backslash, quote and control characters removed rather
# than escaped. Every value here is a sha, a number, a version or a device
# label, where dropping them loses nothing.
jstr() { printf '"%s"' "$(printf '%s' "$1" | tr -d '"\\' | tr -d '\000-\037')"; }

STAGES=()
FAILED=0
SKIPPED=0
stage() { # stage <name> <PASS|FAIL|SKIP> <detail>
    local name="$1" result="$2" detail="$3"
    STAGES+=("{\"stage\":$(jstr "$name"),\"result\":$(jstr "$result"),\"detail\":$(jstr "$detail")}")
    case "$result" in
        FAIL) FAILED=$((FAILED + 1)) ;;
        SKIP) SKIPPED=$((SKIPPED + 1)) ;;
    esac
    log "$name: $result — $detail"
}

# A relative --out is the operator's path, from where they ran this.
case "$OUT" in "" | /*) ;; *) OUT="$PWD/$OUT" ;; esac
TOP="$(git rev-parse --show-toplevel 2>/dev/null)" || { echo "termux-accept: not inside a git checkout" >&2; exit 2; }
cd "$TOP" || exit 2
SHA="$(git rev-parse HEAD)"
ORIGIN_URL="$(git remote get-url origin 2>/dev/null || true)"

# ── checkout ────────────────────────────────────────────────────────────────
# Fails closed: a `git status` that cannot run (a corrupt index, say) is not a
# clean checkout. fsmonitor is off so a stale monitor cannot hide an edit.
DIRTY="$(git -c core.fsmonitor=false status --porcelain --untracked-files=normal)" || {
    echo "termux-accept: refusing: git status failed, so the checkout cannot be shown clean" >&2
    exit 2
}
if [ -n "$DIRTY" ]; then
    printf 'termux-accept: refusing: the checkout has uncommitted changes, so no commit is\n' >&2
    printf 'being tested. Commit or stash them, then run again.\n%s\n' "$DIRTY" >&2
    exit 2
fi

# ── platform ────────────────────────────────────────────────────────────────
# A device is Termux on aarch64 on Android. The Termux variables and `uname`
# alone are also true of the arm64 termux-docker image on a cloud host, so
# Android's own answer (`getprop`) is required as well.
ARCH="$(uname -m 2>/dev/null || echo unknown)"
ANDROID="$(getprop ro.build.version.release 2>/dev/null || true)"
MODEL="$(getprop ro.product.model 2>/dev/null || true)"
IS_TERMUX=0
if [ -n "${TERMUX_VERSION:-}" ] || [[ ${PREFIX:-} == *com.termux* ]]; then IS_TERMUX=1; fi
KIND=device
if [ "$IS_TERMUX" = 1 ] && [ "$ARCH" = aarch64 ] && [ -n "$ANDROID" ]; then
    :
elif [ "$HOST" = 1 ]; then
    KIND=host
else
    what="$ARCH"
    [ "$IS_TERMUX" = 1 ] && what="$what Termux"
    [ "$IS_TERMUX" = 1 ] && [ "$ARCH" = aarch64 ] && what="$what with no Android version from getprop"
    printf 'termux-accept: refusing: this is %s, not Termux on aarch64 Android. Device evidence\n' "$what" >&2
    printf 'comes only from the device. Pass --host to run the same stages here anyway;\n' >&2
    printf 'the record will say HOST-ONLY.\n' >&2
    exit 2
fi
RUSTC="$(rustc --version 2>/dev/null || echo unavailable)"
stage checkout PASS "HEAD $SHA, no uncommitted change"
stage platform PASS "$KIND: $ARCH${TERMUX_VERSION:+, Termux $TERMUX_VERSION}${ANDROID:+, Android $ANDROID}"

# ── the commit itself ───────────────────────────────────────────────────────
# Where cargo puts the binary is cargo's answer, not an assumed `target/` in the
# checkout: it follows CARGO_TARGET_DIR (docs/INSTALL.md suggests
# ~/.cache/hse-build), a relative one included, and any cargo config. Asked
# here, in the checkout, so the operator's target directory and its compiled
# dependencies are the ones reused.
TARGET_DIR="$(cargo metadata --format-version 1 --no-deps 2>/dev/null \
    | sed -n 's/.*"target_directory":"\([^"]*\)".*/\1/p')"
[ -n "$TARGET_DIR" ] || TARGET_DIR="${CARGO_TARGET_DIR:-$TOP/target}"
export CARGO_TARGET_DIR="$TARGET_DIR"
BIN="$TARGET_DIR/$PROFILE_DIR/hse"

# The build and the tests run on the commit, not on this working tree: a
# private detached worktree of $SHA. `git status` cannot see an edit to a path
# marked assume-unchanged or skip-worktree, nor an ignored file the build reads
# (a local vendor/ tree, say), and an edit made to the checkout while the run
# builds would be tested too. None of them is in the worktree. It is kept, one
# per repository, so the next run rebuilds incrementally.
COMMON="$(cd "$(git rev-parse --git-common-dir)" && pwd -P)" || exit 2
WT="$HOME/.cache/hse-accept/$(printf '%s' "$COMMON" | cksum | cut -d' ' -f1)"
wt_common="$(cd "$WT" 2>/dev/null && cd "$(git rev-parse --git-common-dir 2>/dev/null)" 2>/dev/null && pwd -P)"
if [ "$wt_common" = "$COMMON" ] && [ "$(cd "$WT" && git rev-parse --show-toplevel 2>/dev/null)" = "$(cd "$WT" && pwd -P)" ]; then
    git -C "$WT" checkout -q --detach --force "$SHA" && git -C "$WT" clean -qfdx
else
    rm -rf "$WT" && git worktree prune && mkdir -p "$(dirname "$WT")" \
        && git worktree add -q --detach "$WT" "$SHA"
fi || { echo "termux-accept: refusing: cannot check out $SHA into $WT" >&2; exit 2; }
cd "$WT" || exit 2

# ── build ───────────────────────────────────────────────────────────────────
started=$SECONDS
if cargo build --locked --profile "$PROFILE" --bin hse >&2; then
    BIN_BYTES="$(wc -c <"$BIN" 2>/dev/null | tr -d ' ' || echo 0)"
    stage build PASS "profile $PROFILE in $((SECONDS - started))s, $BIN_BYTES bytes"
else
    BIN_BYTES=0
    stage build FAIL "cargo build --profile $PROFILE failed after $((SECONDS - started))s"
fi

# ── identity ────────────────────────────────────────────────────────────────
# The binary itself says which commit it is; a build that cannot identify
# itself is the failure `hse build-sha` exists to expose.
if [ -x "$BIN" ]; then
    ID="$("$BIN" build-sha --json 2>/dev/null)"
    if [[ $ID == *"\"sha\":\"$SHA\""* ]] && [[ $ID == *'"verifiable":true'* ]]; then
        stage identity PASS "the binary reports HEAD and can prove it"
    else
        stage identity FAIL "the binary reports ${ID:-nothing}, expected $SHA"
    fi
else
    stage identity FAIL "no binary at $BIN"
fi

# ── tests ───────────────────────────────────────────────────────────────────
if [ "$SKIP_TESTS" = 1 ]; then
    stage tests SKIP "--skip-tests"
else
    started=$SECONDS
    if cargo test --locked --lib --bins --tests >&2; then
        stage tests PASS "cargo test in $((SECONDS - started))s"
    else
        stage tests FAIL "cargo test failed after $((SECONDS - started))s"
    fi
fi

# ── restart ─────────────────────────────────────────────────────────────────
# Two separate processes and a value unlike the default: the second can only
# report it if the first really wrote it where a restart reads it. The scratch
# HOME starts with updates and update notices off. `hse config` checks for an
# update first and installs one into the checkout its binary was built under,
# which replaces the commit under test (REQ-UPDATE-001); with notices on it
# would still fetch into that checkout's refs. So the key toggled here is not
# `feature.auto_update` either.
if [ -x "$BIN" ]; then
    SCRATCH="$(mktemp -d)"
    mkdir -p "$SCRATCH/.huntsman"
    printf '{"feature.auto_update":false,"feature.update_notify":false}\n' \
        >"$SCRATCH/.huntsman/settings.json"
    KEY=feature.map_tiles
    if HOME="$SCRATCH" "$BIN" config "$KEY" off >/dev/null 2>&1 \
        && [[ "$(HOME="$SCRATCH" "$BIN" config "$KEY" 2>/dev/null)" == *" off" ]] \
        && HOME="$SCRATCH" "$BIN" config "$KEY" on >/dev/null 2>&1 \
        && [[ "$(HOME="$SCRATCH" "$BIN" config "$KEY" 2>/dev/null)" == *" on" ]]; then
        stage restart PASS "$KEY written by one process, read back by the next, both ways"
    else
        stage restart FAIL "$KEY did not survive a new process"
    fi
    rm -rf "$SCRATCH"
else
    stage restart FAIL "no binary to run"
fi

# ── install (opt-in) ────────────────────────────────────────────────────────
# The installer upgrades in place a clone it is started inside. Started in the
# checkout under test it would point origin at the checkout itself and reset
# its `main` to HEAD. So the commit's own installer installs where it installs
# for an operator (HSE_INSTALL_DIR, else its default), fetching HEAD from the
# checkout's origin; HEAD must be pushed there, as the device stage expects.
# An `hse` for HEAD already on PATH would pass the check below whether or not
# the installer did anything, so that run proves nothing and says so.
if [ "$INSTALL" = 1 ]; then
    IDIR="${HSE_INSTALL_DIR:-$HOME/.local/share/hse}"
    FROM="${ORIGIN_URL:-$TOP}"
    IDIR_REAL="$(cd "$IDIR" 2>/dev/null && pwd -P)"
    PRE="$(command -v hse || true)"
    PRE_ID="$([ -n "$PRE" ] && "$PRE" build-sha --json 2>/dev/null || true)"
    if [ -n "$IDIR_REAL" ] && [ "$IDIR_REAL" = "$(cd "$TOP" && pwd -P)" ]; then
        stage install FAIL "HSE_INSTALL_DIR is the checkout under test; installing there would replace it"
    elif [[ $PRE_ID == *"\"sha\":\"$SHA\""* ]]; then
        stage install SKIP "an hse for HEAD ($PRE) was on PATH before install.sh ran, so this run cannot show the installer installed it; remove it, or install into a fresh HSE_INSTALL_DIR"
    elif HSE_INSTALL_DIR="$IDIR" HSE_REPO_URL="$FROM" HSE_REF="$SHA" HSE_REQUIRE_SHA="$SHA" \
        HSE_PREFER_BUILD=1 HSE_BUILD_PROFILE="$PROFILE" bash "$WT/install.sh" >&2; then
        INSTALLED="$(command -v hse || true)"
        ID="$([ -n "$INSTALLED" ] && "$INSTALLED" build-sha --json 2>/dev/null || true)"
        if [[ $ID == *"\"sha\":\"$SHA\""* ]] && [[ $ID == *'"verifiable":true'* ]]; then
            stage install PASS "install.sh installed HEAD at $INSTALLED, and it can prove it"
        else
            stage install FAIL "install.sh finished, but the hse on PATH (${INSTALLED:-none}) reports ${ID:-nothing}, not a verifiable HEAD"
        fi
    else
        stage install FAIL "install.sh failed installing $SHA from $FROM into $IDIR (log: \$HOME/.cache/hse-install.log)"
    fi
fi

# ── resources ───────────────────────────────────────────────────────────────
FREE_MB="$(df -Pk "$TOP" 2>/dev/null | awk 'NR==2 {print int($4/1024)}')"
BATTERY=""
if command -v termux-battery-status >/dev/null 2>&1; then
    # Termux:API can hang when its app is missing or asleep; a record without a
    # battery level beats no record. The limit covers the helper's children.
    BATTERY="$(timeout -k 2 "${HSE_ACCEPT_API_TIMEOUT:-10}" termux-battery-status 2>/dev/null </dev/null \
        | tr -d ' \n' | sed -n 's/.*"percentage":\([0-9]*\).*/\1/p')"
fi

# ── unchanged ───────────────────────────────────────────────────────────────
# The record speaks for $SHA only if what was built is still $SHA, as
# committed, and the operator's checkout is as it was, origin included. A stage
# that moved or edited either (an update, an installer, a test) was not testing
# $SHA. A `git status` that fails counts as a change.
CHANGED=""
for d in "$WT" "$TOP"; do
    now="$(git -C "$d" rev-parse HEAD 2>/dev/null || echo unknown)"
    edited="$(git -C "$d" -c core.fsmonitor=false status --porcelain --untracked-files=normal 2>&1 \
        | head -3 | tr '\n' ' ')"
    if [ "$now" != "$SHA" ]; then
        CHANGED="$CHANGED $d: HEAD moved to $now;"
    elif [ -n "$edited" ]; then
        CHANGED="$CHANGED $d edited: $edited;"
    fi
done
NOW_ORIGIN="$(git -C "$TOP" remote get-url origin 2>/dev/null || true)"
if [ -n "$CHANGED" ]; then
    stage unchanged FAIL "changed during the run:$CHANGED"
elif [ "$NOW_ORIGIN" != "$ORIGIN_URL" ]; then
    stage unchanged FAIL "origin changed during the run: ${ORIGIN_URL:-none} -> ${NOW_ORIGIN:-none}"
else
    stage unchanged PASS "the build and the checkout are still $SHA, with no change"
fi

# ── verdict and record ──────────────────────────────────────────────────────
if [ "$FAILED" -gt 0 ]; then
    VERDICT=REJECTED
elif [ "$KIND" = host ]; then
    VERDICT="HOST-ONLY"
elif [ "$SKIPPED" -gt 0 ]; then
    VERDICT=PARTIAL
else
    VERDICT=ACCEPTED
fi

stage_list="$(IFS=,; printf '%s' "${STAGES[*]}")"
RECORD="{\"sha\":$(jstr "$SHA"),\"verdict\":$(jstr "$VERDICT"),\"kind\":$(jstr "$KIND"),\
\"recorded\":$(jstr "$(date -u +%Y-%m-%dT%H:%M:%SZ)"),\"arch\":$(jstr "$ARCH"),\
\"termux\":$(jstr "${TERMUX_VERSION:-}"),\"android\":$(jstr "$ANDROID"),\"model\":$(jstr "$MODEL"),\
\"rustc\":$(jstr "$RUSTC"),\"profile\":$(jstr "$PROFILE"),\"binary_bytes\":${BIN_BYTES:-0},\
\"free_mb\":${FREE_MB:-0},\"battery_percent\":$(jstr "$BATTERY"),\"stages\":[$stage_list]}"

if [ -z "$OUT" ]; then
    OUT="${HOME}/.huntsman/acceptance/$SHA.json"
fi
mkdir -p "$(dirname "$OUT")" && printf '%s\n' "$RECORD" >"$OUT"
printf '%s\n' "$RECORD"
log "verdict: $VERDICT — record: $OUT"
[ "$FAILED" -eq 0 ]
