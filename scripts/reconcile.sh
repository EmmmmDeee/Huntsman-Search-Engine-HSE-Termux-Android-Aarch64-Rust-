#!/usr/bin/env bash
# HSE capability reconciler — converge a checkout and a Termux device onto the
# state the live radar needs, transactionally, and claim only what was proven.
#
# Control loop, applied to each phase:
#   OBSERVE → NORMALIZE STATE → DETERMINE REQUIRED TRANSITION → EXECUTE MINIMAL
#   MUTATION → VERIFY EFFECT → ROLLBACK ON FAILURE → RE-OBSERVE → EMIT VERDICT
#
# Facts, actions and claims are kept apart. A FACT is something this script
# observed (a tool is executable on PATH, the bridge answered, a probe exited
# 0, a patch changed the source). An ACTION is a mutation it performed
# (installed a package, patched a file, stopped a process, restored a
# snapshot). A CLAIM ("Termux:API ready", "repository verified", "radar
# evidence admissible") is emitted only when every fact it rests on was proven
# in THIS run. Nothing is inferred from an installer's exit status, from a
# package being listed, or from a tool merely existing.
#
# Repository phase — the defect it repairs
#   install.sh's Termux:API step probed `termux-info` to decide whether the
#   `termux-api` package was installed. `termux-info` ships in `termux-tools`
#   on EVERY Termux install, so `pkg install termux-api` never ran and the
#   installer reported "termux-api CLI present" on devices that had no sensor
#   tool at all. The defect is recognised by SOURCE CONTENT (the exact block,
#   INSTALLER_BUG_REGION below) and the fix by its own signature (the
#   TERMUX_API_CORE_TOOLS definition); the commit the defect was observed at
#   is recorded as provenance only, never used as a control input. A source
#   matching neither shape is refused, unpatched (exit 3).
#
# Device phase
#   PROBE the core tools → INSTALL only if one is missing → `hash -r` →
#   RE-PROBE the same set → VERIFY the Termux:API app (com.termux.api) →
#   VERIFY the bridge answers a harmless bounded call → PROBE each core sensor
#   → CLASSIFY. `pkg` exiting 0 is not the postcondition; the re-probe is.
#   Bluetooth is an independent optional provider and never a readiness
#   condition for the GNSS / Wi-Fi / cell substrate.
#
# Radar process
#   `hse` caches a `termux-*` tool that would not spawn as absent, per process
#   (src/util/termux). A radar that started before the tools were installed is
#   blind to them until it restarts, so it is reported STALE_RESTART_REQUIRED
#   and its subsequent findings are not admissible. It is never touched unless
#   --allow-process-restart is given, in which case it is stopped through its
#   own cooperative Ctrl-C path (SIGINT) and the operator starts a fresh one.
#
# Usage:
#   scripts/reconcile.sh [--repo-only | --device-only] [--verify-only | --dry-run]
#                        [--json] [--allow-process-restart]
#
#   default                 converge the repository AND the device
#   --repo-only             inspect / repair / verify the repository only
#   --device-only           inspect / repair / verify the device only
#   --verify-only           no mutation; prove the current state
#   --dry-run               discovery + decisions; show intended mutations; mutate nothing
#   --json                  emit the final state as JSON on stdout (human report otherwise)
#   --allow-process-restart permit a controlled stop of a stale `hse radar` process
#
# The repository acted on is the git checkout containing the current directory,
# else the one containing this script. Human and JSON output are rendered from
# ONE final-state object. Progress goes to stderr; details of every external
# command to $HOME/.cache/hse-reconcile.log.
#
# Exit codes (stable):
#   0  requested state verified
#   2  degraded state or required verification skipped
#   3  unsupported / unknown repository source shape (or no repository)
#   4  unsafe repository state; mutation refused
#   5  device capability incomplete
#   6  verification failure; rollback executed
#   7  rollback verification failure
#   8  process restart required but not authorized (the sole remaining blocker)
#   9  internal invariant violation (including a bad invocation)
#
# Every mutation is idempotent: a second clean run reports repository.mutation
# UNCHANGED, termux.package_action UNCHANGED and rewrites nothing.

set -uo pipefail
# Deliberately no `set -e`: every command's exit status here is an observation
# that gets classified, never an event that aborts the controller mid-transaction.

# ── Canonical definitions — each defined exactly once, reused everywhere ─────
# The stock Termux:API sensor surface: the four `termux-api` package tools the
# radar / sensor modules invoke. install.sh's detection block and
# src/modules/termux_sensor.rs carry the same list; the Rust test suite holds
# the three in lockstep. Used here for detection, install verification, sensor
# probing, acceptance and reporting alike.
TERMUX_API_CORE_TOOLS=(termux-location termux-wifi-connectioninfo termux-wifi-scaninfo termux-telephony-cellinfo)
# Per-tool probe metadata, index-aligned with TERMUX_API_CORE_TOOLS: the report
# label and the extra argv. GNSS reads the OS's last GPS fix (near-instant)
# rather than taking a fresh lock: readiness means "the pathway answers", and a
# fresh lock indoors would time out and be misreported as unknown.
SENSOR_LABELS=(gnss wifi_connection wifi_scan cell)
SENSOR_ARGV=("-p gps -r last" "" "" "")
TERMUX_API_PACKAGE=termux-api
TERMUX_API_APK=com.termux.api
# Harmless, permission-free, bounded: proves the Termux ↔ Android bridge answers.
TERMUX_API_BRIDGE_PROBE=termux-battery-status
# Independent OPTIONAL provider — not in the stock termux-api package, never a
# readiness condition for the core substrate.
BLE_PROVIDER=termux-bluetooth-scaninfo
PROBE_TIMEOUT_S=15
RADAR_STOP_TIMEOUT_S=20
# Where the defect was first observed. Provenance for the report only.
INSTALLER_DEFECT_PROVENANCE="69b17eb (PR #585, 2026-09-04)"
LOG_FILE="${HOME:-${TMPDIR:-/tmp}}/.cache/hse-reconcile.log"

# The defect, by source content: this exact block, as install.sh shipped it.
# Its first line locates the region; the whole region must match byte for
# byte, or the shape is unknown and nothing is touched.
IFS= read -r -d '' INSTALLER_BUG_REGION <<'INSTALLER_BUG_REGION' || true
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
            pkg install -y termux-api >>"$LOG_FILE" 2>&1 \
                && ok "Installed termux-api package" \
                || { log_warn "Could not install termux-api (sensor modules will no-op)"; hint "See $LOG_FILE"; }
        else
            log_warn "termux-api is not installed — sensor modules (v0.6+) will no-op"
            hint "Install later: pkg install termux-api"
        fi
    else
        ok "termux-api CLI present"
    fi
INSTALLER_BUG_REGION
INSTALLER_BUG_REGION=${INSTALLER_BUG_REGION%$'\n'}
INSTALLER_BUG_SENTINEL='    if ! command -v termux-info >/dev/null 2>&1; then'

# The fix, as install.sh ships it today. `@TERMUX_API_CORE_TOOLS@` is rendered
# from the array above at patch time, so the tool list is defined once in this
# file. Held byte-for-byte against install.sh by tests/install_invariants.rs.
IFS= read -r -d '' INSTALLER_FIX_TEMPLATE <<'INSTALLER_FIX_REGION' || true
    # termux-api package. Three separate facts, none implying the next: the
    # `termux-api` PACKAGE is the CLI tools; the Termux:API app from F-Droid is
    # the Android half of the bridge; and only the bridge answering proves the
    # two are talking. This step establishes the FIRST, by postcondition.
    #
    # Detection probes the stock sensor tools HSE's modules actually invoke —
    # TERMUX_API_CORE_TOOLS, the one list scripts/reconcile.sh and the Rust
    # `termux_sensor` module mirror (held in lockstep by the test suite). An
    # earlier revision probed `termux-info`, which ships in `termux-tools` on
    # EVERY Termux install, so `pkg install termux-api` never ran and
    # "termux-api CLI present" was reported on devices with no sensor tool.
    #
    # `pkg` exiting 0 is not the postcondition either: after an install the
    # command hash is refreshed and the same tool set re-probed, and only a
    # re-probe that finds every tool counts. Warns unconditionally when a tool
    # is still missing (HSE_NO_PKG=1 suppresses only the install attempt).
    TERMUX_API_CORE_TOOLS=(@TERMUX_API_CORE_TOOLS@)
    termux_api_missing_tools() {
        local t
        for t in "${TERMUX_API_CORE_TOOLS[@]}"; do
            command -v "$t" >/dev/null 2>&1 || printf '%s ' "$t"
        done
    }
    MISSING_API_TOOLS="$(termux_api_missing_tools)"
    if [[ -n "$MISSING_API_TOOLS" && "${HSE_NO_PKG:-0}" != "1" ]]; then
        pkg install -y termux-api >>"$LOG_FILE" 2>&1 \
            || { log_warn "pkg install termux-api failed"; hint "See $LOG_FILE"; }
        hash -r
        MISSING_API_TOOLS="$(termux_api_missing_tools)"
        [[ -n "$MISSING_API_TOOLS" ]] || ok "Installed termux-api package"
    fi
    if [[ -n "$MISSING_API_TOOLS" ]]; then
        log_warn "termux-api sensor tools missing — sensor modules will no-op: ${MISSING_API_TOOLS% }"
        hint "Install: pkg install termux-api"
    else
        ok "termux-api core sensor tools present (${#TERMUX_API_CORE_TOOLS[@]}/${#TERMUX_API_CORE_TOOLS[@]})"
    fi
INSTALLER_FIX_REGION
INSTALLER_FIX_TEMPLATE=${INSTALLER_FIX_TEMPLATE%$'\n'}
INSTALLER_FIX_REGION=${INSTALLER_FIX_TEMPLATE//@TERMUX_API_CORE_TOOLS@/${TERMUX_API_CORE_TOOLS[*]}}
INSTALLER_FIX_SIGNATURE='TERMUX_API_CORE_TOOLS=('

# ── The final-state object. Both reports are rendered from this and only this.
declare -A S=(
    [mode]=default [action]=converge
    [repository.path]="" [repository.commit]="" [repository.tree]=skipped
    [repository.source]=skipped [repository.mutation]=none
    [repository.shell_verify]=skipped [repository.structural_verify]=skipped
    [repository.rust_verify]=skipped [repository.rollback]=none
    [repository.final_state]=skipped
    [termux.state]=skipped [termux.package_action]=none
    [termux.cli]=skipped [termux.cli_missing]="" [termux.apk]=skipped [termux.bridge]=skipped
    [sensors.gnss]=skipped [sensors.wifi_connection]=skipped [sensors.wifi_scan]=skipped
    [sensors.cell]=skipped [sensors.ble]=skipped
    [radar.process]=skipped [radar.process_pids]="" [radar.process_action]=none
    [radar.evidence]=skipped
    [exit_code]=0 [reason]=""
)
REASONS=()
reason() { REASONS+=("$*"); }

MODE=default        # default | repo-only | device-only
ACTION=converge     # converge | verify-only | dry-run
JSON=0
ALLOW_RESTART=0
REPO=""
SNAPSHOT=""

log()   { printf '[reconcile] %s\n' "$*" >&2; }
usage() {
    if [[ -f "${BASH_SOURCE[0]:-}" ]]; then
        sed -n '/^# Usage:/,/^# The repository acted on/p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//' >&2
    else
        echo "usage: reconcile.sh [--repo-only|--device-only] [--verify-only|--dry-run] [--json] [--allow-process-restart]" >&2
    fi
}
# An invariant of THIS program failed: report it and stop with the reserved code.
invariant_violation() {
    log "internal invariant violation: $*"
    S[reason]="internal invariant violation: $*"
    S[exit_code]=9
    emit
    exit 9
}
# Run a command with everything it prints appended to the log, keeping its status.
logged() {
    { printf '\n$ %s\n' "$*"; "$@"; } >>"$LOG_FILE" 2>&1
}
mutating() { [[ "$ACTION" == converge ]]; }

# ── Argument parsing ─────────────────────────────────────────────────────────
for arg in "$@"; do
    case "$arg" in
        --repo-only|--device-only)
            [[ "$MODE" == default ]] || { usage; invariant_violation "$arg conflicts with --$MODE"; }
            MODE=${arg#--} ;;
        --verify-only|--dry-run)
            [[ "$ACTION" == converge ]] || { usage; invariant_violation "$arg conflicts with --$ACTION"; }
            ACTION=${arg#--} ;;
        --json) JSON=1 ;;
        --allow-process-restart) ALLOW_RESTART=1 ;;
        -h|--help) usage; exit 0 ;;
        *) usage; invariant_violation "unknown argument: $arg" ;;
    esac
done
S[mode]="$MODE"
S[action]="$ACTION"
mkdir -p "$(dirname "$LOG_FILE")" 2>/dev/null || true
printf '\n==== %s %s ====\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date)" "$*" >>"$LOG_FILE" 2>/dev/null || LOG_FILE=/dev/null

# ═════════════════════════════════════════════════════════════════════════════
# Repository phase
# ═════════════════════════════════════════════════════════════════════════════

# The git checkout containing $PWD, else the one containing this script.
resolve_repo() {
    local top
    top="$(git -C "$PWD" rev-parse --show-toplevel 2>/dev/null)" || top=""
    if [[ -z "$top" && -n "${BASH_SOURCE[0]:-}" && -f "${BASH_SOURCE[0]}" ]]; then
        top="$(git -C "$(dirname "${BASH_SOURCE[0]}")" rev-parse --show-toplevel 2>/dev/null)" || top=""
    fi
    [[ -n "$top" ]] || return 1
    git -C "$top" rev-parse --git-dir >/dev/null 2>&1 || return 1
    [[ -f "$top/install.sh" ]] || return 1
    REPO="$top"
}

# Line number of the block's first line in install.sh (exactly one occurrence),
# or nothing.
bug_region_start() {
    local first hits
    first=${INSTALLER_BUG_REGION%%$'\n'*}
    hits="$(grep -n -F -x -- "$first" "$REPO/install.sh")" || return 1
    [[ "$(printf '%s\n' "$hits" | wc -l)" -eq 1 ]] || return 1
    printf '%s' "${hits%%:*}"
}

bug_region_lines() { printf '%s\n' "$INSTALLER_BUG_REGION" | wc -l; }

# The core-tool array install.sh defines, if it defines exactly one.
installer_core_tools() {
    local defs
    defs="$(grep -E -- "^[[:space:]]*${INSTALLER_FIX_SIGNATURE//(/\\(}" "$REPO/install.sh")" || return 1
    [[ "$(printf '%s\n' "$defs" | wc -l)" -eq 1 ]] || return 1
    defs=${defs#*(}
    printf '%s' "${defs%)}"
}

# Sets S[repository.source] from the source content alone.
classify_installer() {
    local f="$REPO/install.sh" bug=0 fix=0 start n region
    grep -q -F -x -- "$INSTALLER_BUG_SENTINEL" "$f" && bug=1
    grep -q -E -- "^[[:space:]]*${INSTALLER_FIX_SIGNATURE//(/\\(}" "$f" && fix=1
    if (( fix == 1 && bug == 0 )); then
        if [[ "$(installer_core_tools)" != "${TERMUX_API_CORE_TOOLS[*]}" ]]; then
            S[repository.source]=unknown
            reason "install.sh carries a TERMUX_API_CORE_TOOLS definition that differs from this reconciler's"
            return
        fi
        S[repository.source]=already_fixed
    elif (( bug == 1 && fix == 0 )); then
        start="$(bug_region_start)" || {
            S[repository.source]=unknown
            reason "install.sh has the termux-info sentinel but not the known block around it"
            return
        }
        n="$(bug_region_lines)"
        region="$(sed -n "${start},$((start + n - 1))p" "$f")"
        if [[ "$region" != "$INSTALLER_BUG_REGION" ]]; then
            S[repository.source]=unknown
            reason "install.sh's termux-api block differs from the known defective block"
            return
        fi
        S[repository.source]=bug_present
    else
        S[repository.source]=unknown
        reason "install.sh matches neither the known defective shape nor the fixed shape"
    fi
}

# Structural invariants of the fixed shape: no sentinel, the canonical tool
# list defined exactly once. Sets S[repository.structural_verify].
# $1 = "post-mutation" adds the transaction-scope checks.
verify_structural() {
    local f="$REPO/install.sh" changed
    S[repository.structural_verify]=fail
    if grep -q -F -x -- "$INSTALLER_BUG_SENTINEL" "$f"; then
        reason "structural: the termux-info sentinel is still present"; return 1
    fi
    if [[ "$(installer_core_tools)" != "${TERMUX_API_CORE_TOOLS[*]}" ]]; then
        reason "structural: install.sh's TERMUX_API_CORE_TOOLS is not defined exactly once as the canonical list"; return 1
    fi
    if [[ "${1:-}" == post-mutation ]]; then
        # This run wrote the block, so it must read back byte for byte. (An
        # already-fixed checkout is judged by the fix signature and the two
        # invariants above, not by its comments matching this file's copy.)
        if [[ "$(cat "$f")" != *"$INSTALLER_FIX_REGION"* ]]; then
            reason "structural: install.sh does not contain the canonical fixed block"; return 1
        fi
        if ! logged git -C "$REPO" diff --check; then
            reason "structural: git diff --check rejected the patch (see $LOG_FILE)"; return 1
        fi
        changed="$(git -C "$REPO" status --porcelain --untracked-files=no)"
        if [[ "$changed" != " M install.sh" ]]; then
            reason "structural: the transaction changed more than install.sh: ${changed//$'\n'/ | }"; return 1
        fi
    fi
    S[repository.structural_verify]=pass
}

verify_shell() {
    if logged bash -n "$REPO/install.sh"; then
        S[repository.shell_verify]=pass
    else
        S[repository.shell_verify]=fail
        reason "shell: bash -n rejected install.sh (see $LOG_FILE)"
        return 1
    fi
}

# Rust-side verification of the patched tree: rustfmt and the targeted test
# suite that reads install.sh. Sets S[repository.rust_verify] to pass, fail, or
# skipped_environment. Returns 1 only on FAIL — a skip is not a failure, and
# is never reported as a pass.
verify_rust() {
    if ! command -v cargo >/dev/null 2>&1; then
        S[repository.rust_verify]=skipped_environment
        reason "rust: cargo is not available here; run cargo test --test install_invariants where it is"
        return 0
    fi
    if [[ ! -f "$REPO/Cargo.toml" ]]; then
        S[repository.rust_verify]=skipped_environment
        reason "rust: no Cargo.toml at $REPO; nothing for cargo to verify"
        return 0
    fi
    if ! (cd "$REPO" && logged cargo fmt --version); then
        S[repository.rust_verify]=skipped_environment
        reason "rust: rustfmt is not installed (cargo fmt unavailable)"
        return 0
    fi
    if ! (cd "$REPO" && logged cargo fmt --all -- --check); then
        S[repository.rust_verify]=fail
        reason "rust: cargo fmt --check failed (see $LOG_FILE)"
        return 1
    fi
    # A test target that does not BUILD is an environment limitation (offline
    # registry, missing system libraries): this patch touches no Rust source,
    # so it cannot be what broke the build. A test that builds and FAILS is a
    # verification failure.
    if ! (cd "$REPO" && logged cargo test --locked --test install_invariants --no-run); then
        S[repository.rust_verify]=skipped_environment
        reason "rust: the install_invariants test target did not build here (see $LOG_FILE)"
        return 0
    fi
    if (cd "$REPO" && logged cargo test --locked --test install_invariants); then
        S[repository.rust_verify]=pass
    else
        S[repository.rust_verify]=fail
        reason "rust: cargo test --test install_invariants failed (see $LOG_FILE)"
        return 1
    fi
}

snapshot_installer() {
    SNAPSHOT="$(mktemp "${TMPDIR:-/tmp}/hse-reconcile.install.sh.XXXXXX")" || return 1
    cp -p "$REPO/install.sh" "$SNAPSHOT"
}

# Restore the snapshot and PROVE the restoration. Sets S[repository.rollback].
rollback_installer() {
    S[repository.mutation]=rolled_back
    if [[ -n "$SNAPSHOT" && -f "$SNAPSHOT" ]] && cat "$SNAPSHOT" >"$REPO/install.sh" \
        && cmp -s "$SNAPSHOT" "$REPO/install.sh" \
        && [[ -z "$(git -C "$REPO" status --porcelain --untracked-files=no)" ]]; then
        S[repository.rollback]=verified
        rm -f "$SNAPSHOT"
        log "rolled install.sh back to its pre-run bytes (verified)"
    else
        S[repository.rollback]=failed
        reason "rollback: install.sh could not be verified restored; snapshot at ${SNAPSHOT:-<none>}"
        log "ROLLBACK VERIFICATION FAILED — snapshot kept at ${SNAPSHOT:-<none>}"
        return 1
    fi
}

# Replace the defective region with the fixed one. Line-addressed on the region
# located by the classifier, written whole so a partial write cannot be
# observed as a valid script.
apply_installer_fix() {
    local f="$REPO/install.sh" start n tmp
    start="$(bug_region_start)" || return 1
    n="$(bug_region_lines)"
    tmp="$(mktemp "${TMPDIR:-/tmp}/hse-reconcile.patch.XXXXXX")" || return 1
    {
        head -n "$((start - 1))" "$f"
        printf '%s\n' "$INSTALLER_FIX_REGION"
        tail -n "+$((start + n))" "$f"
    } >"$tmp" || { rm -f "$tmp"; return 1; }
    cat "$tmp" >"$f" || { rm -f "$tmp"; return 1; }
    rm -f "$tmp"
    # FACT: the patch changed the source, and the region is now the fix.
    ! cmp -s "$SNAPSHOT" "$f" || return 1
}

repository_phase() {
    if ! resolve_repo; then
        S[repository.source]=absent
        S[repository.final_state]=absent
        reason "no git checkout containing install.sh at $PWD or beside this script"
        return
    fi
    S[repository.path]="$REPO"
    S[repository.commit]="$(git -C "$REPO" rev-parse --short HEAD 2>/dev/null || echo unknown)"
    if [[ -n "$(git -C "$REPO" status --porcelain --untracked-files=no 2>/dev/null)" ]]; then
        S[repository.tree]=dirty
    else
        S[repository.tree]=clean
    fi

    classify_installer
    case "${S[repository.source]}" in
        unknown)
            S[repository.final_state]=unknown
            S[repository.mutation]=refused
            return ;;
        already_fixed)
            S[repository.mutation]=unchanged
            verify_shell || true
            verify_structural || true
            if [[ "${S[repository.shell_verify]}" == pass && "${S[repository.structural_verify]}" == pass ]]; then
                S[repository.final_state]=already_fixed
            else
                # The fix signature is there but the shape is not the shipped one.
                S[repository.source]=unknown
                S[repository.final_state]=unknown
                S[repository.mutation]=refused
            fi
            return ;;
        bug_present) ;;
        *) invariant_violation "unexpected repository.source ${S[repository.source]}" ;;
    esac

    # BUG_PRESENT from here.
    if ! mutating; then
        [[ "$ACTION" == dry-run ]] && S[repository.mutation]=would_apply
        S[repository.final_state]=bug_present
        reason "install.sh carries the termux-info sentinel defect (provenance $INSTALLER_DEFECT_PROVENANCE)"
        return
    fi
    if [[ "${S[repository.tree]}" == dirty ]]; then
        S[repository.mutation]=refused
        S[repository.final_state]=dirty
        reason "working tree has uncommitted changes; refusing to patch install.sh"
        return
    fi

    # Transaction: snapshot → apply → verify → (rollback).
    snapshot_installer || invariant_violation "could not snapshot install.sh"
    log "patching install.sh (${S[repository.commit]}): termux-info sentinel → TERMUX_API_CORE_TOOLS probe"
    if ! apply_installer_fix; then
        reason "patch: could not write the fixed block"
        rollback_installer || true
        S[repository.final_state]=failed
        return
    fi
    S[repository.mutation]=applied

    local failed=0
    verify_shell || failed=1
    verify_structural post-mutation || failed=1
    if (( failed == 0 )); then
        verify_rust || failed=1
    fi
    if (( failed == 1 )); then
        rollback_installer || true
        S[repository.final_state]=failed
        return
    fi
    case "${S[repository.rust_verify]}" in
        pass) S[repository.final_state]=verified ;;
        skipped_environment) S[repository.final_state]=patch_applied ;;
        *) invariant_violation "rust_verify=${S[repository.rust_verify]} after a successful transaction" ;;
    esac
    rm -f "$SNAPSHOT"
}

# ═════════════════════════════════════════════════════════════════════════════
# Device phase
# ═════════════════════════════════════════════════════════════════════════════

is_termux() { [[ -n "${TERMUX_VERSION:-}" ]] || [[ -d /data/data/com.termux ]]; }

# Core tools not executable on PATH, space-separated (empty = all present).
missing_core_tools() {
    local t out=""
    for t in "${TERMUX_API_CORE_TOOLS[@]}"; do
        command -v "$t" >/dev/null 2>&1 || out+="$t "
    done
    printf '%s' "${out% }"
}

# Run a probe under a hard timeout; prints its stdout, returns its status
# (124 when killed by the timeout).
bounded() {
    command -v timeout >/dev/null 2>&1 || return 127
    timeout -k 2 "$PROBE_TIMEOUT_S" "$@" 2>>"$LOG_FILE"
}

# Classify one probe: executed_valid | executed_empty | failed.
#   $1 exit status, $2 stdout.
# FAILED is an unknown sensor state, never "0 observations": a timeout, a
# non-zero exit, an API error object, or non-JSON output all land here.
classify_probe() {
    local status="$1" out="$2"
    (( status == 0 )) || { printf 'failed'; return; }
    out="${out//[$'\t\r\n ']/}"
    case "$out" in
        ""|"{}"|"[]") printf 'executed_empty' ;;
        *API_ERROR*|*'"error"'*) printf 'failed' ;;
        "{"*"}"|"["*"]") printf 'executed_valid' ;;
        *) printf 'failed' ;;
    esac
}

# Is the Termux:API app installed? Prints present | absent | unknown.
# `unknown` means the package manager query itself could not be executed —
# distinct from a query that ran and did not list the app.
apk_state() {
    local listing
    for pm in "pm list packages" "cmd package list packages"; do
        # shellcheck disable=SC2086  # the two commands are fixed words above
        listing="$(timeout -k 2 30 $pm 2>>"$LOG_FILE")" || continue
        printf '%s\n' "$listing" | grep -q '^package:' || continue
        if printf '%s\n' "$listing" | grep -q -x "package:$TERMUX_API_APK"; then
            printf 'present'
        else
            printf 'absent'
        fi
        return
    done
    printf 'unknown'
}

device_phase() {
    if ! is_termux; then
        S[termux.state]=not_termux
        S[radar.evidence]=degraded
        reason "not a Termux host: the device substrate cannot be converged here"
        return
    fi

    # ── CLI: probe → install only if necessary → hash -r → re-probe ──────────
    local missing status out
    missing="$(missing_core_tools)"
    if [[ -n "$missing" ]]; then
        if ! mutating; then
            [[ "$ACTION" == dry-run ]] && S[termux.package_action]=would_install
        elif ! command -v pkg >/dev/null 2>&1; then
            S[termux.package_action]=install_failed
            reason "pkg is not available; cannot install $TERMUX_API_PACKAGE"
        else
            log "installing $TERMUX_API_PACKAGE (missing: $missing)"
            logged pkg install -y "$TERMUX_API_PACKAGE"; status=$?
            hash -r
            missing="$(missing_core_tools)"
            if [[ -z "$missing" ]]; then
                S[termux.package_action]=installed
            else
                S[termux.package_action]=install_failed
                reason "pkg install $TERMUX_API_PACKAGE exited $status and these tools are still missing: $missing"
            fi
        fi
    else
        S[termux.package_action]=unchanged
    fi
    S[termux.cli_missing]="$missing"
    if [[ -n "$missing" ]]; then
        S[termux.cli]=fail
        if [[ "$(wc -w <<<"$missing")" -eq "${#TERMUX_API_CORE_TOOLS[@]}" ]]; then
            S[termux.state]=cli_missing
        else
            S[termux.state]=cli_partial
        fi
        [[ "${S[termux.package_action]}" == install_failed ]] || reason "termux-api sensor tools missing: $missing"
    else
        S[termux.cli]=pass
    fi

    # ── Android companion: an independent fact ───────────────────────────────
    local apk
    apk="$(apk_state)"
    case "$apk" in
        present) S[termux.apk]=pass ;;
        absent)  S[termux.apk]=fail; reason "Termux:API app ($TERMUX_API_APK) is not installed" ;;
        unknown) S[termux.apk]=fail; reason "package manager query failed; $TERMUX_API_APK could not be verified (see $LOG_FILE)" ;;
    esac

    # ── Bridge: only meaningful once the CLI exists; a query that could not
    # run is the one case the bridge itself may settle (it cannot answer
    # without the app), a query that ran and found no app is final.
    if [[ "${S[termux.cli]}" == pass && "$apk" != absent ]]; then
        out="$(bounded "$TERMUX_API_BRIDGE_PROBE")"; status=$?
        if [[ "$(classify_probe "$status" "$out")" == executed_valid ]]; then
            S[termux.bridge]=pass
            if [[ "$apk" == unknown ]]; then
                S[termux.apk]=pass
                reason "$TERMUX_API_APK proven present by the bridge answering (package manager query unavailable)"
            fi
        else
            S[termux.bridge]=fail
            reason "$TERMUX_API_BRIDGE_PROBE did not answer within ${PROBE_TIMEOUT_S}s (exit $status)"
        fi
    fi

    if [[ "${S[termux.cli]}" == pass ]]; then
        if [[ "${S[termux.apk]}" != pass ]]; then
            S[termux.state]=apk_missing
        elif [[ "${S[termux.bridge]}" != pass ]]; then
            S[termux.state]=bridge_failed
        else
            S[termux.state]=ready
        fi
    fi

    # ── Sensors: probed independently, only over a proven bridge ─────────────
    local i label
    if [[ "${S[termux.state]}" == ready ]]; then
        for i in "${!TERMUX_API_CORE_TOOLS[@]}"; do
            label=${SENSOR_LABELS[$i]}
            # shellcheck disable=SC2086  # SENSOR_ARGV entries are fixed words
            out="$(bounded "${TERMUX_API_CORE_TOOLS[$i]}" ${SENSOR_ARGV[$i]})"; status=$?
            S[sensors.$label]="$(classify_probe "$status" "$out")"
            [[ "${S[sensors.$label]}" != failed ]] || reason "$label probe (${TERMUX_API_CORE_TOOLS[$i]}) failed: sensor state unknown, not negative evidence"
        done
        if command -v "$BLE_PROVIDER" >/dev/null 2>&1; then
            out="$(bounded "$BLE_PROVIDER")"; status=$?
            case "$(classify_probe "$status" "$out")" in
                executed_valid|executed_empty) S[sensors.ble]=available ;;
                *) S[sensors.ble]=failed; reason "BLE provider $BLE_PROVIDER failed: Bluetooth state unknown" ;;
            esac
        else
            S[sensors.ble]=unavailable
        fi
    fi
}

# ═════════════════════════════════════════════════════════════════════════════
# Radar process — HSE's process-local absent-tool cache
# ═════════════════════════════════════════════════════════════════════════════

# PIDs whose command line is `hse radar` (argv[0] basename `hse`, argv[1]
# `radar`), one per line.
radar_pids() {
    local d pid argv0 argv1
    for d in /proc/[0-9]*; do
        pid=${d#/proc/}
        [[ "$pid" != "$$" && "$pid" != "$PPID" ]] || continue
        { IFS= read -r -d '' argv0 && IFS= read -r -d '' argv1; } <"$d/cmdline" 2>/dev/null || continue
        [[ "${argv0##*/}" == hse && "$argv1" == radar ]] && printf '%s\n' "$pid"
    done
    return 0
}

# True while the process exists and is not a zombie: an exited child its
# parent has not reaped yet keeps its /proc entry, but it is not a radar.
process_alive() {
    local stat
    stat="$(cat "/proc/$1/stat" 2>/dev/null)" || return 1
    stat=${stat##*) }
    [[ "${stat:0:1}" != Z && "${stat:0:1}" != X ]]
}

# Epoch seconds a process started, from /proc; nothing if it cannot be read.
process_start_epoch() {
    local stat rest btime clk
    stat="$(cat "/proc/$1/stat" 2>/dev/null)" || return 1
    rest=${stat##*) }
    # shellcheck disable=SC2086  # positional split of a fixed-format line
    set -- $rest
    btime="$(awk '/^btime /{print $2}' /proc/stat 2>/dev/null)"
    clk="$(getconf CLK_TCK 2>/dev/null)" || clk=100
    [[ -n "$btime" && -n "${20:-}" && "${20}" =~ ^[0-9]+$ ]] || return 1
    printf '%s' "$(( btime + ${20} / ${clk:-100} ))"
}

# Epoch seconds the termux-api package was last (re)installed: dpkg rewrites
# the package's file list at install time. Nothing when unknown.
termux_api_install_epoch() {
    local list="${PREFIX:-/data/data/com.termux/files/usr}/var/lib/dpkg/info/${TERMUX_API_PACKAGE}.list"
    [[ -f "$list" ]] || return 1
    stat -c %Y "$list" 2>/dev/null
}

# A running radar's absent-tool cache is stale when the tools exist now but
# the process started before they were installed. When freshness cannot be
# proven, it is stale (fail closed). Without the tools, its cache is correct.
radar_process_phase() {
    local pids stale=() pid start installed
    pids="$(radar_pids)"
    if [[ -z "$pids" ]]; then
        S[radar.process]=not_running
        return
    fi
    S[radar.process_pids]="${pids//$'\n'/ }"
    if [[ "${S[termux.cli]}" != pass ]]; then
        S[radar.process]=current
        return
    fi
    installed="$(termux_api_install_epoch)" || installed=""
    for pid in $pids; do
        start="$(process_start_epoch "$pid")" || start=""
        if [[ -z "$installed" || -z "$start" || "$start" -lt "$installed" ]]; then
            stale+=("$pid")
        fi
    done
    if (( ${#stale[@]} == 0 )); then
        S[radar.process]=current
        return
    fi
    S[radar.process]=stale_restart_required
    if (( ALLOW_RESTART == 0 )) || ! mutating; then
        reason "hse radar (pid ${stale[*]}) started before the termux-api tools were installed; its absent-tool cache is stale"
        return
    fi
    # Authorized: stop each stale process through its own Ctrl-C path, prove
    # it exited, then re-observe.
    local waited alive=()
    for pid in "${stale[@]}"; do
        log "stopping stale hse radar pid $pid (SIGINT)"
        kill -INT "$pid" 2>/dev/null
        waited=0
        while process_alive "$pid" && (( waited < RADAR_STOP_TIMEOUT_S )); do sleep 1; waited=$((waited + 1)); done
        if process_alive "$pid"; then
            kill -TERM "$pid" 2>/dev/null; sleep 3
        fi
        process_alive "$pid" && alive+=("$pid")
    done
    if (( ${#alive[@]} == 0 )); then
        S[radar.process_action]=stopped
        pids="$(radar_pids)"
        if [[ -z "$pids" ]]; then
            S[radar.process]=not_running
            S[radar.process_pids]=""
            reason "stale hse radar stopped (pid ${stale[*]}); start it again to resume with a fresh process"
        else
            S[radar.process]=stale_restart_required
            S[radar.process_pids]="${pids//$'\n'/ }"
            reason "a radar process is still running after the stop: ${pids//$'\n'/ }"
        fi
    else
        S[radar.process_action]=stop_failed
        reason "hse radar pid ${alive[*]} did not exit after SIGINT/SIGTERM"
    fi
}

# ═════════════════════════════════════════════════════════════════════════════
# Derivation: radar evidence and the exit code, from observed state only
# ═════════════════════════════════════════════════════════════════════════════

derive_radar_evidence() {
    local reads=0 label
    for label in "${SENSOR_LABELS[@]}"; do
        case "${S[sensors.$label]}" in executed_valid|executed_empty) reads=$((reads + 1)) ;; esac
    done
    if (( reads == ${#SENSOR_LABELS[@]} )); then
        if [[ "${S[sensors.ble]}" == available ]]; then
            S[radar.evidence]=full_ready
        else
            S[radar.evidence]=core_ready
        fi
    else
        S[radar.evidence]=degraded
    fi
    # No new observation is admissible until a fresh radar process is running.
    if [[ "${S[radar.process]}" == stale_restart_required ]]; then
        S[radar.evidence]=degraded
    fi
}

derive_exit_code() {
    local repo="${S[repository.final_state]}" dev="${S[termux.state]}" code=0
    local device_requested=0
    [[ "$MODE" != repo-only ]] && device_requested=1
    if [[ "$repo" == failed && "${S[repository.rollback]}" == failed ]]; then code=7
    elif [[ "$repo" == failed ]]; then code=6
    elif [[ "$repo" == dirty ]]; then code=4
    elif [[ "$repo" == unknown || "$repo" == absent ]]; then code=3
    elif [[ "$dev" == cli_missing || "$dev" == cli_partial || "$dev" == apk_missing || "$dev" == bridge_failed ]]; then code=5
    else
        local degraded=0 sole_blocker_is_process=0
        [[ "$repo" == patch_applied || "$repo" == bug_present ]] && degraded=1
        if (( device_requested )); then
            [[ "$dev" == not_termux ]] && degraded=1
            [[ "${S[radar.evidence]}" != core_ready && "${S[radar.evidence]}" != full_ready ]] && degraded=1
            if [[ "${S[radar.process]}" == stale_restart_required ]]; then
                # Stale process is the ONLY thing between here and the requested
                # state: every core sensor read, repository acceptable.
                local reads=0 label
                for label in "${SENSOR_LABELS[@]}"; do
                    case "${S[sensors.$label]}" in executed_valid|executed_empty) reads=$((reads + 1)) ;; esac
                done
                if (( reads == ${#SENSOR_LABELS[@]} )) \
                    && [[ "$repo" == verified || "$repo" == already_fixed || "$repo" == skipped ]]; then
                    sole_blocker_is_process=1
                fi
            fi
        fi
        if (( sole_blocker_is_process )); then code=8
        elif (( degraded )); then code=2
        else code=0
        fi
    fi
    S[exit_code]=$code
}

# ═════════════════════════════════════════════════════════════════════════════
# Rendering — both forms from the one state object
# ═════════════════════════════════════════════════════════════════════════════

json_str() {
    local s="$1"
    s=${s//\\/\\\\}; s=${s//\"/\\\"}; s=${s//$'\n'/\\n}; s=${s//$'\t'/\\t}
    printf '"%s"' "$s"
}
json_words() { # space-separated words → JSON array of strings
    local w first=1
    printf '['
    for w in $1; do
        (( first )) || printf ', '
        json_str "$w"; first=0
    done
    printf ']'
}

emit_json() {
    printf '{\n'
    printf '  "schema": 1,\n'
    printf '  "mode": %s,\n' "$(json_str "${S[mode]}")"
    printf '  "action": %s,\n' "$(json_str "${S[action]}")"
    printf '  "repository": {\n'
    printf '    "path": %s,\n' "$(json_str "${S[repository.path]}")"
    printf '    "commit": %s,\n' "$(json_str "${S[repository.commit]}")"
    printf '    "tree": %s,\n' "$(json_str "${S[repository.tree]}")"
    printf '    "source": %s,\n' "$(json_str "${S[repository.source]}")"
    printf '    "mutation": %s,\n' "$(json_str "${S[repository.mutation]}")"
    printf '    "shell_verify": %s,\n' "$(json_str "${S[repository.shell_verify]}")"
    printf '    "structural_verify": %s,\n' "$(json_str "${S[repository.structural_verify]}")"
    printf '    "rust_verify": %s,\n' "$(json_str "${S[repository.rust_verify]}")"
    printf '    "rollback": %s,\n' "$(json_str "${S[repository.rollback]}")"
    printf '    "final_state": %s\n' "$(json_str "${S[repository.final_state]}")"
    printf '  },\n'
    printf '  "termux": {\n'
    printf '    "state": %s,\n' "$(json_str "${S[termux.state]}")"
    printf '    "package_action": %s,\n' "$(json_str "${S[termux.package_action]}")"
    printf '    "cli": %s,\n' "$(json_str "${S[termux.cli]}")"
    printf '    "cli_missing": %s,\n' "$(json_words "${S[termux.cli_missing]}")"
    printf '    "apk": %s,\n' "$(json_str "${S[termux.apk]}")"
    printf '    "bridge": %s\n' "$(json_str "${S[termux.bridge]}")"
    printf '  },\n'
    printf '  "sensors": {\n'
    printf '    "gnss": %s,\n' "$(json_str "${S[sensors.gnss]}")"
    printf '    "wifi_connection": %s,\n' "$(json_str "${S[sensors.wifi_connection]}")"
    printf '    "wifi_scan": %s,\n' "$(json_str "${S[sensors.wifi_scan]}")"
    printf '    "cell": %s,\n' "$(json_str "${S[sensors.cell]}")"
    printf '    "ble": %s\n' "$(json_str "${S[sensors.ble]}")"
    printf '  },\n'
    printf '  "radar": {\n'
    printf '    "process": %s,\n' "$(json_str "${S[radar.process]}")"
    printf '    "process_pids": %s,\n' "$(json_words "${S[radar.process_pids]}")"
    printf '    "process_action": %s,\n' "$(json_str "${S[radar.process_action]}")"
    printf '    "evidence": %s\n' "$(json_str "${S[radar.evidence]}")"
    printf '  },\n'
    printf '  "exit_code": %s,\n' "${S[exit_code]}"
    printf '  "reason": %s\n' "$(json_str "${S[reason]}")"
    printf '}\n'
}

up() { printf '%s' "${1^^}"; }

verdict_lines() {
    case "${S[repository.final_state]}" in
        verified)      echo "Repository installer path patched and verified (shell, structural, Rust)." ;;
        patch_applied) echo "Repository installer path patched; Rust verification could not run here — run: cargo test --test install_invariants." ;;
        already_fixed) echo "Repository installer path is at the fixed shape." ;;
        bug_present)   echo "Repository installer path carries the termux-info sentinel defect; run without --verify-only/--dry-run to patch it." ;;
        dirty)         echo "Working tree is dirty; repository mutation refused. Commit or stash, then re-run." ;;
        unknown)       echo "Installer source shape unknown; refusing to patch. Inspect install.sh's termux-api block by hand." ;;
        absent)        echo "No repository found; nothing to reconcile here." ;;
        failed)        [[ "${S[repository.rollback]}" == verified ]] \
                           && echo "Verification failed; install.sh rolled back to its pre-run bytes (verified)." \
                           || echo "Verification failed AND the rollback could not be verified — inspect install.sh and the snapshot named in the reason." ;;
    esac
    case "${S[termux.state]}" in
        ready)
            [[ "${S[termux.package_action]}" == installed ]] \
                && echo "Core Termux acquisition substrate is repaired." \
                || echo "Core Termux acquisition substrate is ready." ;;
        cli_missing|cli_partial) echo "termux-api sensor tools missing (${S[termux.cli_missing]}); install with: pkg install $TERMUX_API_PACKAGE" ;;
        apk_missing)   echo "Termux:API app ($TERMUX_API_APK) not verified present; install it from F-Droid." ;;
        bridge_failed) echo "Termux:API bridge did not answer; check the app is installed, granted permissions, and not battery-restricted." ;;
        not_termux)    echo "Not a Termux host; device substrate not applicable here." ;;
    esac
    local label
    for label in "${SENSOR_LABELS[@]}"; do
        [[ "${S[sensors.$label]}" == failed ]] && echo "$label probe failed: sensor state unknown (not negative evidence)."
    done
    case "${S[radar.process]}" in
        stale_restart_required)
            [[ "${S[radar.process_action]}" == stop_failed ]] \
                && echo "Stale hse radar (pid ${S[radar.process_pids]}) did not stop; stop it manually before accepting subsequent radar findings." \
                || echo "Restart hse radar before accepting subsequent radar findings." ;;
        not_running)
            [[ "${S[radar.process_action]}" == stopped ]] && echo "Stale hse radar stopped; start it again to resume with a fresh absent-tool cache." ;;
    esac
    case "${S[sensors.ble]}" in
        unavailable) echo "BLE remains unavailable and cannot support a negative Bluetooth observation." ;;
        failed)      echo "BLE provider failed; Bluetooth state unknown, not negative evidence." ;;
    esac
}

row()  { printf '  %-18s %s\n' "$1" "$2"; }
rrow() { printf '  %-19s %s\n' "$1" "$2"; }

emit_human() {
    local cli
    cli="$(up "${S[termux.cli]}")"
    [[ -n "${S[termux.cli_missing]}" ]] && cli+=" (missing: ${S[termux.cli_missing]})"
    echo "HSE CAPABILITY RECONCILER"
    echo
    echo "Repository"
    row "source" "$(up "${S[repository.source]}")"
    row "mutation" "$(up "${S[repository.mutation]}")"
    row "shell verification" "$(up "${S[repository.shell_verify]}")"
    row "structural checks" "$(up "${S[repository.structural_verify]}")"
    row "Rust verification" "$(up "${S[repository.rust_verify]}")"
    row "final state" "$(up "${S[repository.final_state]}")"
    echo
    echo "Termux"
    row "CLI" "$cli"
    row "Android companion" "$(up "${S[termux.apk]}")"
    row "bridge" "$(up "${S[termux.bridge]}")"
    echo
    echo "Sensors"
    row "GNSS" "$(up "${S[sensors.gnss]}")"
    row "Wi-Fi connection" "$(up "${S[sensors.wifi_connection]}")"
    row "Wi-Fi scan" "$(up "${S[sensors.wifi_scan]}")"
    row "Cell" "$(up "${S[sensors.cell]}")"
    row "BLE" "$(up "${S[sensors.ble]}")"
    echo
    echo "Radar"
    rrow "process" "$(up "${S[radar.process]}")"
    rrow "evidence" "$(up "${S[radar.evidence]}")"
    echo
    echo "VERDICT"
    verdict_lines | sed 's/^/  /'
    printf '  exit %s' "${S[exit_code]}"
    [[ -z "${S[reason]}" ]] || printf ' — %s' "${S[reason]}"
    echo
}

emit() {
    local r="" x
    for x in "${REASONS[@]}"; do r+="${r:+; }$x"; done
    S[reason]="$r"
    if (( JSON )); then emit_json; else emit_human; fi
}

# ═════════════════════════════════════════════════════════════════════════════
# Main
# ═════════════════════════════════════════════════════════════════════════════
[[ "$MODE" != device-only ]] && repository_phase
if [[ "$MODE" != repo-only ]]; then
    device_phase
    [[ "${S[termux.state]}" != not_termux ]] && radar_process_phase
    [[ "${S[termux.state]}" != not_termux ]] && derive_radar_evidence
fi
derive_exit_code
emit
exit "${S[exit_code]}"
