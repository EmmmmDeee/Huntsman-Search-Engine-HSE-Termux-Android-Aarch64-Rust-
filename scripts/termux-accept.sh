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
#   platform   aarch64 + Termux, or an explicit --host run marked as such
#   build      cargo build --locked --profile <p> --bin hse    (time, size)
#   identity   the built binary's `hse build-sha --json` is HEAD, verifiable
#   tests      cargo test --locked --lib --bins --tests         (--skip-tests)
#   restart    a setting written by one `hse` process is read back by a new
#              one, in a scratch HOME that never touches the operator's state
#              and has automatic updates off
#   install    opt-in (--install): the real installer builds and installs HEAD
#              where it installs for an operator, never into this checkout, and
#              the `hse` on PATH then proves it is HEAD
#   resources  binary size, free disk, battery level if termux-api is present
#   unchanged  HEAD is still the commit under test, the tree is clean, and
#              origin is as it was: nothing the run started edited the checkout
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
        -h | --help) sed -n '2,35p' "$0"; exit 0 ;;
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

TOP="$(git rev-parse --show-toplevel 2>/dev/null)" || { echo "termux-accept: not inside a git checkout" >&2; exit 2; }
cd "$TOP" || exit 2
SHA="$(git rev-parse HEAD)"
ORIGIN_URL="$(git remote get-url origin 2>/dev/null || true)"

# ── checkout ────────────────────────────────────────────────────────────────
DIRTY="$(git status --porcelain --untracked-files=normal)"
if [ -n "$DIRTY" ]; then
    printf 'termux-accept: refusing: the checkout has uncommitted changes, so no commit is\n' >&2
    printf 'being tested. Commit or stash them, then run again.\n%s\n' "$DIRTY" >&2
    exit 2
fi

# ── platform ────────────────────────────────────────────────────────────────
ARCH="$(uname -m 2>/dev/null || echo unknown)"
IS_TERMUX=0
if [ -n "${TERMUX_VERSION:-}" ] || [[ ${PREFIX:-} == *com.termux* ]]; then IS_TERMUX=1; fi
KIND=device
if [ "$IS_TERMUX" = 1 ] && [ "$ARCH" = aarch64 ]; then
    :
elif [ "$HOST" = 1 ]; then
    KIND=host
else
    printf 'termux-accept: refusing: this is %s%s, not Termux on aarch64. Device evidence\n' \
        "$ARCH" "$([ "$IS_TERMUX" = 1 ] && echo ' Termux' || true)" >&2
    printf 'comes only from the device. Pass --host to run the same stages here anyway;\n' >&2
    printf 'the record will say HOST-ONLY.\n' >&2
    exit 2
fi
ANDROID="$(getprop ro.build.version.release 2>/dev/null || true)"
MODEL="$(getprop ro.product.model 2>/dev/null || true)"
RUSTC="$(rustc --version 2>/dev/null || echo unavailable)"
stage checkout PASS "HEAD $SHA, no uncommitted change"
stage platform PASS "$KIND: $ARCH${TERMUX_VERSION:+, Termux $TERMUX_VERSION}${ANDROID:+, Android $ANDROID}"

# ── build ───────────────────────────────────────────────────────────────────
BIN="$TOP/target/$PROFILE_DIR/hse"
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
# update first, and from inside this checkout it installs one into it, which
# replaces the commit under test (REQ-UPDATE-001); with notices on it would
# still fetch into this checkout's refs. So the key toggled here is not
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
# The installer upgrades in place a clone it is started inside, and this
# script runs inside the checkout under test: there it would point origin at
# the checkout itself and reset its `main` to HEAD. So it installs where it
# installs for an operator (HSE_INSTALL_DIR, else its own default), fetching
# HEAD from this checkout's origin. HEAD must be pushed there, as the device
# stage expects.
if [ "$INSTALL" = 1 ]; then
    IDIR="${HSE_INSTALL_DIR:-$HOME/.local/share/hse}"
    FROM="${ORIGIN_URL:-$TOP}"
    if [ "$(cd "$IDIR" 2>/dev/null && pwd -P)" = "$(pwd -P)" ]; then
        stage install FAIL "HSE_INSTALL_DIR is this checkout; installing there would replace the commit under test"
    elif HSE_INSTALL_DIR="$IDIR" HSE_REPO_URL="$FROM" HSE_REF="$SHA" HSE_REQUIRE_SHA="$SHA" \
        HSE_PREFER_BUILD=1 HSE_BUILD_PROFILE="$PROFILE" bash "$TOP/install.sh" >&2; then
        INSTALLED="$(command -v hse || true)"
        if [ -n "$INSTALLED" ] && [ "$("$INSTALLED" build-sha 2>/dev/null)" = "$SHA" ]; then
            stage install PASS "install.sh installed HEAD at $INSTALLED"
        else
            stage install FAIL "install.sh finished, but the hse on PATH (${INSTALLED:-none}) is not HEAD"
        fi
    else
        stage install FAIL "install.sh failed installing $SHA from $FROM into $IDIR (log: \$HOME/.cache/hse-install.log)"
    fi
fi

# ── resources ───────────────────────────────────────────────────────────────
FREE_MB="$(df -Pk "$TOP" 2>/dev/null | awk 'NR==2 {print int($4/1024)}')"
BATTERY=""
if command -v termux-battery-status >/dev/null 2>&1; then
    BATTERY="$(termux-battery-status 2>/dev/null | tr -d ' \n' | sed -n 's/.*"percentage":\([0-9]*\).*/\1/p')"
fi

# ── unchanged ───────────────────────────────────────────────────────────────
# The record speaks for $SHA only if the checkout still is $SHA, as committed,
# with the origin it started with. A stage that moved or edited it (an update,
# an installer, a test) was not testing $SHA.
NOW="$(git rev-parse HEAD 2>/dev/null || echo unknown)"
EDITED="$(git status --porcelain --untracked-files=normal | head -3 | tr '\n' ' ')"
NOW_ORIGIN="$(git remote get-url origin 2>/dev/null || true)"
if [ "$NOW" != "$SHA" ]; then
    stage unchanged FAIL "HEAD moved to $NOW during the run"
elif [ -n "$EDITED" ]; then
    stage unchanged FAIL "the checkout was edited during the run: $EDITED"
elif [ "$NOW_ORIGIN" != "$ORIGIN_URL" ]; then
    stage unchanged FAIL "origin changed during the run: ${ORIGIN_URL:-none} -> ${NOW_ORIGIN:-none}"
else
    stage unchanged PASS "HEAD is still $SHA, with no change"
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
