#!/usr/bin/env bash
# The verification gate — every check CI runs on a pull request, in one command.
#
# Why this exists: the gate is spread across six workflow files, and anyone
# reconstructing it by hand reads .github/workflows/ci.yml, runs four of the
# checks, and calls that "the full gate". The rustdoc lint pass and the MSRV
# pin are the two that get missed most, and both have failed here before —
# PR #303 was specifically a broken-intra-doc-links fix.
#
# Scope vs. the other scripts in this repo:
#   * scripts/setup-dev.sh     — install the developer toolchain.
#   * scripts/standard-test.sh — run the canonical acceptance scan.
#   * THIS script              — prove the tree is shippable. Touches no
#                                operator state and reaches no network.
#
# Usage:
#   scripts/gate.sh            # run everything available on this host
#   scripts/gate.sh --quick    # skip MSRV and the cross-build (inner loop only)
#
# Exit status is 0 only if every check that RAN passed. Checks that cannot run
# on this host are reported as SKIPPED with the reason, never silently omitted:
# a gate that quietly drops a check is worse than no gate, because it reports
# success it did not establish.
#
# Source of truth: .github/workflows/{ci,rust-clippy,fuzz,audit}.yml. If CI
# gains a check, add it here in the same commit — a gate that has drifted from
# CI is a defect, not a convenience.
set -uo pipefail

# ── Disk discipline (REQ-GATE-001) ───────────────────────────────────────────
# `CARGO_INCREMENTAL=0` is not a micro-optimisation here; it is what keeps this
# script from defeating itself. Incremental state is never reclaimed, and this
# is a full-verification script, not an edit-compile loop: it runs a sequence of
# cargo invocations with DIFFERENT flags (check --all-targets, clippy, test,
# test --doc, plus the hse-core and wasm-ui workspaces), so each gets its own
# fingerprint and the cache buys almost nothing. Measured 2026-09-20: one
# from-scratch run took `target/debug/incremental` from 4.0K to **7.6 GiB**, on
# top of a ~9.7 GiB `deps/`. An earlier run died mid-`test` at 98% full with
#
#     rustc-LLVM ERROR: IO failure on output stream: No space left on device
#     collect2: fatal error: ld terminated with signal 7 [Bus error]
#     error: could not compile `huntsman-search-engine` (lib test)
#
# which reads exactly like a compiler or linker defect in the change under test.
# This file's own header says a gate that quietly drops a check is worse than no
# gate, "because it reports success it did not establish". Reporting a FAILURE
# it did not establish is the same defect wearing the other sign.
#
# It is also convergence with CI, not drift from it: CI is this script's
# declared source of truth, and CI never reuses incremental state — every runner
# starts from a fresh disk. The local gate hoarding it was the divergence.
export CARGO_INCREMENTAL=0

# Refuse to start without room to finish, and say so in terms of the DISK.
# Override for a host with a differently-sized volume.
MIN_FREE_MB="${HSE_GATE_MIN_FREE_MB:-8192}"

free_mb() { df -Pk . | awk 'NR==2 {print int($4/1024)}'; }

QUICK=0
[ "${1:-}" = "--quick" ] && QUICK=1

MSRV="$(grep -m1 '^rust-version' Cargo.toml | sed -E 's/.*"([0-9.]+)".*/\1/')"
TARGET=aarch64-linux-android
RUSTDOC_LINTS="-D rustdoc::broken_intra_doc_links -D rustdoc::bare_urls -D rustdoc::invalid_html_tags"

PASS=(); FAIL=(); SKIP=()

run() { # run <name> <command...>
    local name="$1"; shift
    printf '\n\033[1;36m==> %s\033[0m\n' "$name"
    if "$@"; then
        PASS+=("$name")
    else
        FAIL+=("$name")
        printf '\033[1;31m    FAILED: %s\033[0m\n' "$name"
        # A preflight cannot cover growth DURING the run, and a full disk
        # surfaces as a linker/LLVM error that looks like a code defect
        # (REQ-GATE-001). Name the disk here so the next reader does not spend
        # the afternoon bisecting a change that was never at fault.
        local now; now="$(free_mb)"
        if [ "$now" -lt "$MIN_FREE_MB" ]; then
            printf '\033[1;31m    !! %s MiB free on this volume (floor %s MiB) — this failure may be DISK EXHAUSTION, not a real defect. Check the log for "No space left on device" / "ld terminated with signal 7" before believing it.\033[0m\n' \
                "$now" "$MIN_FREE_MB"
        fi
    fi
}

skip() { # skip <name> <reason>
    SKIP+=("$1 — $2")
    printf '\n\033[1;33m==> %s: SKIPPED (%s)\033[0m\n' "$1" "$2"
}

# `--features dep-cooldown` on every step below that takes `--all-targets`
# (except the Termux cross-build further down, deliberately): the
# `dep-cooldown` binary's `toml`/`time` deps are `optional = true` +
# `required-features` specifically so a feature-less build/check/test does
# NOT compile them (see Cargo.toml's `[[bin]] name = "dep-cooldown"` comment)
# — without this flag, `--all-targets` would silently SKIP that binary
# instead of erroring, dropping it out of fmt/check/clippy/test coverage on
# every ordinary PR. An array (not a plain string) so it expands as the two
# distinct words `--features dep-cooldown` under `set -u`/shellcheck SC2086
# rather than relying on unquoted word-splitting.
DEP_COOLDOWN_FEATURE=(--features dep-cooldown)

# ── Preflight: room to finish (REQ-GATE-001) ─────────────────────────────────
# Refuse to start rather than die halfway through `test` with a linker error
# that looks like a code defect. Measured: a from-scratch run needs roughly
# 6 GiB even with incremental disabled, so the floor is set above that.
PREFLIGHT_FREE="$(free_mb)"
if [ "$PREFLIGHT_FREE" -lt "$MIN_FREE_MB" ]; then
    printf '\n\033[1;31m==> REFUSING TO START: %s MiB free, need %s MiB\033[0m\n' \
        "$PREFLIGHT_FREE" "$MIN_FREE_MB"
    printf '    This is the DISK, not the tree. Running anyway would fail partway\n'
    printf '    through with "No space left on device" surfacing as an LLVM/linker\n'
    printf '    error that reads like a defect in your change (REQ-GATE-001).\n\n'
    printf '    Reclaim, largest first:\n'
    du -sh target/debug/incremental target/debug/deps target/release 2>/dev/null |
        sed 's/^/      /'
    printf '\n      rm -rf target/debug/incremental        # pure cache, always safe\n'
    printf '      find target/debug/deps -maxdepth 1 -type f -mmin +180 -delete\n'
    printf '\n    NEVER blanket-delete target/debug/deps: the live artifacts are in there.\n'
    printf '    Override the floor with HSE_GATE_MIN_FREE_MB if this host is sized differently.\n\n'
    exit 1
fi

# ── ci.yml: Check & test (Linux x86_64, stable) ──────────────────────────────
run "fmt"      cargo fmt --all -- --check
run "check"    cargo check --all-targets --locked "${DEP_COOLDOWN_FEATURE[@]}"
run "clippy"   cargo clippy --all-targets --locked "${DEP_COOLDOWN_FEATURE[@]}" -- -D warnings
RUSTDOCFLAGS="$RUSTDOC_LINTS" \
  run "rustdoc lints" cargo doc --no-deps --document-private-items --locked "${DEP_COOLDOWN_FEATURE[@]}"
# ci.yml runs ONE `cargo test --all`, which already includes doctests. This gate
# reports doctests as their own check (`doctests` below), so this step must
# EXCLUDE them — `--lib --bins --tests` does exactly that. A bare `cargo test
# --all` here ran the whole doctest suite a second time under `doctests`. Total
# coverage is unchanged: lib+bins+integration here, doctests below == ci.yml's
# single `--all`.
run "test"     cargo test --all --lib --bins --tests --locked "${DEP_COOLDOWN_FEATURE[@]}"
run "doctests" cargo test --doc --locked
run "doc coverage" scripts/doc_coverage.sh

# ── ci.yml: hse-core + wasm-ui (native; not in the root workspace) ───────────
# Path dependencies of the root crate, deliberately NOT `[workspace]` members
# (see each crate's own Cargo.toml comment), so none of the steps above ever
# lint or test them directly: `cargo check`/`clippy`/`test --all` above only
# compile hse-core as an ordinary dependency (test cfg stripped) and never
# touch wasm-ui at all. Without these lines hse-core's 144 unit tests + 6
# doctests and both crates' deny-level clippy lints ran nowhere — not in CI,
# not here. wasm-ui's `cargo test` step is native-only (crate-type includes
# `rlib` alongside `cdylib` specifically so this works) — it proves the
# source compiles and runs any unit tests added going forward, but is NOT a
# build or test of the real wasm32-unknown-unknown browser artifact.
run "fmt (hse-core)"    cargo fmt --manifest-path hse-core/Cargo.toml --check
run "clippy (hse-core)" cargo clippy --manifest-path hse-core/Cargo.toml --all-targets --locked -- -D warnings
RUSTDOCFLAGS="$RUSTDOC_LINTS" \
  run "rustdoc lints (hse-core)" cargo doc --manifest-path hse-core/Cargo.toml --no-deps --document-private-items --locked
run "test (hse-core)"   cargo test --manifest-path hse-core/Cargo.toml --locked
run "fmt (wasm-ui)"     cargo fmt --manifest-path wasm-ui/Cargo.toml --check
run "clippy (wasm-ui)"  cargo clippy --manifest-path wasm-ui/Cargo.toml --all-targets --locked -- -D warnings
run "test (wasm-ui, native)" cargo test --manifest-path wasm-ui/Cargo.toml --locked

# ── ci.yml: wasm-ui/pkg round-trip drift check ───────────────────────────────
# Regenerates wasm-ui/pkg/ from source and diffs it against the committed
# copy — see scripts/wasm_ui_drift_check.sh for what actually runs and why.
# Was a disclosed, open gap as of this repo's PR #547/#551 (nothing here
# regenerated and diffed the artifact automatically); this closes it.
#
# Exact-version-gated rather than "best effort": a mismatched wasm-bindgen or
# wasm-opt build can produce different bytes from IDENTICAL source, which
# would make this check cry wolf on an unrelated host — worse than not
# running it at all (see the shellcheck severity note below for the same
# philosophy). CI installs an exact pinned toolchain so it always runs there;
# locally this SKIPs rather than guesses.
WASM_BINDGEN_PIN="$(grep -m1 '^wasm-bindgen ' wasm-ui/Cargo.toml | sed -E 's/.*"([0-9.]+)".*/\1/')"
# Read from the drift script itself, the one place the binaryen build is pinned.
WASM_OPT_PIN="$(grep -m1 '^WASM_OPT_PIN=' scripts/wasm_ui_drift_check.sh | cut -d= -f2)"
WASM_BINDGEN_HAVE="$(wasm-bindgen --version 2>/dev/null | awk '{print $2}')"

# A SKIP of this check is not equally safe on every commit. It is harmless when
# nothing feeding the browser bundle changed, and load-bearing exactly when
# something did: `hse-core` is compiled INTO wasm-ui, so a change under either
# leaves the committed `wasm-ui/pkg/` stale and CI's sibling-crates job goes red
# on the next push. That happened twice in a row (REQ-AUBUSINESSID-001 added a
# string to ENRICHMENT_ONLY_SOURCES, REQ-CORRELATOR-005 a tag const) — both gate
# runs reported a bland SKIP naming a missing tool, and neither said the skip
# mattered for THAT change.
#
# The skip stays a skip: it cannot run reliably without the pinned toolchain
# (see the header above), and failing here would block contributors who cannot
# install it. What changes is that its CONSEQUENCE is stated when it applies.
# Both the working tree and, when the ref resolves, the branch against
# origin/main are checked — the stale artifact is a property of the branch head
# CI will build, not only of the edit in front of you.
WASM_DRIFT_STAKES=""
if ! git diff --quiet HEAD -- hse-core/ wasm-ui/src/ 2>/dev/null \
    || { git rev-parse --verify --quiet origin/main >/dev/null 2>&1 \
         && ! git diff --quiet origin/main...HEAD -- hse-core/ wasm-ui/src/ 2>/dev/null; }; then
    WASM_DRIFT_STAKES=" — !! THIS BRANCH CHANGES hse-core/ OR wasm-ui/src/, which are compiled into the committed wasm-ui/pkg/: CI WILL FAIL unless pkg/ is regenerated. Install the pinned toolchain above and run scripts/wasm_ui_drift_check.sh --write, or expect the sibling-crates job to go red"
fi
skip_wasm_drift() { skip "wasm-ui/pkg drift check" "$1$WASM_DRIFT_STAKES"; }

if [ "$QUICK" = 1 ]; then
    skip_wasm_drift "--quick"
elif ! rustup target list --installed 2>/dev/null | grep -q '^wasm32-unknown-unknown$'; then
    skip_wasm_drift "wasm32-unknown-unknown target not installed — rustup target add wasm32-unknown-unknown"
elif ! command -v wasm-bindgen >/dev/null 2>&1; then
    skip_wasm_drift "wasm-bindgen-cli not installed — cargo install wasm-bindgen-cli --version $WASM_BINDGEN_PIN --locked"
elif [ "$WASM_BINDGEN_HAVE" != "$WASM_BINDGEN_PIN" ]; then
    skip_wasm_drift "installed wasm-bindgen-cli $WASM_BINDGEN_HAVE != wasm-ui/Cargo.toml's pinned $WASM_BINDGEN_PIN (a mismatched CLI produces spurious diffs, not real drift) — cargo install wasm-bindgen-cli --version $WASM_BINDGEN_PIN --locked --force"
elif ! command -v wasm-opt >/dev/null 2>&1; then
    skip_wasm_drift "wasm-opt (binaryen) not installed — CI is the authority for this check on hosts without it"
elif ! wasm-opt --version 2>/dev/null | grep -q "version ${WASM_OPT_PIN}\b"; then
    skip_wasm_drift "installed wasm-opt ($(wasm-opt --version 2>/dev/null | head -1)) is not binaryen version_${WASM_OPT_PIN}, the build that produced the committed pkg/ (a different build re-optimises identical input to different bytes — toolchain drift, not source drift) — CI is the authority"
elif ! mkdir -p /tmp/hse-wasm-ui-build-root 2>/dev/null; then
    # The check builds from that ONE fixed absolute path on every host (cargo's
    # metadata hash includes an out-of-workspace path dependency's absolute
    # path, so the same source built from two locations can differ — see the
    # script's header). Termux has no /tmp; CI is the authority there.
    skip_wasm_drift "cannot create the fixed build root /tmp/hse-wasm-ui-build-root on this host — CI is the authority for this check here"
else
    run "wasm-ui/pkg drift check" scripts/wasm_ui_drift_check.sh
fi

# ── ci.yml: MSRV ─────────────────────────────────────────────────────────────
if [ "$QUICK" = 1 ]; then
    skip "MSRV ($MSRV)" "--quick"
elif rustup toolchain list 2>/dev/null | grep -q "^${MSRV}"; then
    run "MSRV ($MSRV)" cargo "+$MSRV" check --all-targets --locked "${DEP_COOLDOWN_FEATURE[@]}"
else
    skip "MSRV ($MSRV)" "toolchain not installed — rustup toolchain install $MSRV"
fi

# ── ci.yml: aarch64-linux-android (the actual deployment target) ─────────────
# Needs the Android NDK: libsqlite3-sys and ring both have C build scripts, so
# even `cargo check --target` fails without aarch64-linux-android-clang.
if [ "$QUICK" = 1 ]; then
    skip "cross-build ($TARGET)" "--quick"
elif ! rustup target list --installed 2>/dev/null | grep -q "$TARGET"; then
    skip "cross-build ($TARGET)" "target not installed — rustup target add $TARGET"
elif ! command -v aarch64-linux-android-clang >/dev/null 2>&1 && [ -z "${ANDROID_NDK_HOME:-}" ]; then
    skip "cross-build ($TARGET)" "no Android NDK (cc-rs needs aarch64-linux-android-clang); CI is the authority"
else
    run "cross-build ($TARGET)" cargo build --locked --lib --bin hse --target "$TARGET"
    run "cross-test-compile ($TARGET)" \
        cargo test --locked --no-run --lib --bin hse --tests --target "$TARGET"
fi

# ── ci.yml: install.sh + scripts/reconcile.sh syntax + shellcheck ────────────
run "install.sh syntax" bash -n install.sh
run "reconcile.sh syntax" bash -n scripts/reconcile.sh
if command -v shellcheck >/dev/null 2>&1; then
    # `--severity=warning` mirrors ci.yml's ShellCheck step exactly. Without it
    # this gate was STRICTER than CI: install.sh carries several long-standing
    # `info`-level notes (SC2015 A && B || C, SC2059 printf format) that CI
    # tolerates, so a host that happens to have shellcheck installed reported a
    # FAIL for something CI passes. A gate that cries wolf is worse than one
    # that skips: it trains you to ignore it.
    run "shellcheck" shellcheck --severity=warning install.sh scripts/gate.sh scripts/reconcile.sh
else
    skip "shellcheck" "not installed"
fi

# ── the workflow files themselves ────────────────────────────────────────────
# A workflow GitHub's schema rejects produces a *startup failure*: a run that
# completes in zero seconds with no job executed. On the blocking `ci.yml` that
# looks exactly like "CI hasn't started yet", so a broken workflow can sit
# unnoticed while the branch merely appears slow — which is how a duplicate
# `with:` key once silenced this repo's entire test gate for a push. A generic
# `yaml.safe_load` cannot catch that (it accepts duplicate keys and keeps the
# last), so `check_workflows.py` parses with a loader that refuses them, and
# also asserts every `pull_request` checkout stays pinned to the PR's real head
# rather than the stale-prone `refs/pull/N/merge` default.
if command -v python3 >/dev/null 2>&1; then
    run "workflow files" python3 scripts/check_workflows.py
else
    skip "workflow files" "python3 not installed"
fi

# ── audit.yml: only fires when a manifest changed, so mirror that ────────────
# Must match audit.yml's `push.paths` exactly (src/bin/dep_cooldown/** included,
# and fuzz/Cargo.{toml,lock} plus hse-core/Cargo.{toml,lock} and
# wasm-ui/Cargo.{toml,lock} because audit.yml's filter is `**/Cargo.{toml,lock}`
# — each of those crates has its own manifest, which that glob covers and this
# list must too) — a mismatch here means this script silently SKIPS the check
# locally on a commit that only touches one of those crates' own manifest,
# while CI still runs it.
if git diff --quiet HEAD -- Cargo.toml Cargo.lock deny.toml dep-cooldown.toml src/bin/dep_cooldown fuzz/Cargo.toml fuzz/Cargo.lock hse-core/Cargo.toml hse-core/Cargo.lock wasm-ui/Cargo.toml wasm-ui/Cargo.lock 2>/dev/null; then
    skip "cargo-audit / deny / machete / dep-cooldown" "no manifest change (audit.yml path filter)"
else
    for t in cargo-audit cargo-deny cargo-machete; do
        command -v "$t" >/dev/null 2>&1 || skip "$t" "not installed"
    done
    command -v cargo-audit   >/dev/null 2>&1 && run "cargo audit"   cargo audit
    command -v cargo-deny    >/dev/null 2>&1 && run "cargo deny"    cargo deny check
    command -v cargo-machete >/dev/null 2>&1 && run "cargo machete" cargo machete --with-metadata
    # Not an external tool — built from this repo's own source, so it needs no
    # `command -v` gate, only network access to crates.io (same requirement
    # cargo-audit/deny already have here). `--features dep-cooldown`: see this
    # script's `DEP_COOLDOWN_FEATURE` comment above.
    run "dep-cooldown" cargo run --locked --bin dep-cooldown "${DEP_COOLDOWN_FEATURE[@]}"

    # hse-core and wasm-ui keep their own separate Cargo.lock (see the
    # `sibling-crates` CI job above for why), so every tool above only ever
    # walked the root crate's graph. Same shared-policy reasoning as the
    # root invocations: `deny.toml`/`dep-cooldown.toml` apply as-is via
    # `--config`/`--policy` rather than forking a copy per crate.
    command -v cargo-audit >/dev/null 2>&1 && run "cargo audit (hse-core)" cargo audit -f hse-core/Cargo.lock
    command -v cargo-audit >/dev/null 2>&1 && run "cargo audit (wasm-ui)" cargo audit -f wasm-ui/Cargo.lock
    command -v cargo-deny  >/dev/null 2>&1 && run "cargo deny (hse-core)" cargo deny --manifest-path hse-core/Cargo.toml --config deny.toml check
    command -v cargo-deny  >/dev/null 2>&1 && run "cargo deny (wasm-ui)"  cargo deny --manifest-path wasm-ui/Cargo.toml --config deny.toml check
    command -v cargo-machete >/dev/null 2>&1 && run "cargo machete (hse-core)" cargo machete --with-metadata hse-core
    command -v cargo-machete >/dev/null 2>&1 && run "cargo machete (wasm-ui)"  cargo machete --with-metadata wasm-ui
    run "dep-cooldown (hse-core)" cargo run --locked --bin dep-cooldown "${DEP_COOLDOWN_FEATURE[@]}" -- --lockfile hse-core/Cargo.lock --policy dep-cooldown.toml
    run "dep-cooldown (wasm-ui)"  cargo run --locked --bin dep-cooldown "${DEP_COOLDOWN_FEATURE[@]}" -- --lockfile wasm-ui/Cargo.lock --policy dep-cooldown.toml
fi

# ── Report ───────────────────────────────────────────────────────────────────
printf '\n\033[1m───────── gate summary ─────────\033[0m\n'
for p in "${PASS[@]:-}"; do [ -n "$p" ] && printf '  \033[32mPASS\033[0m  %s\n' "$p"; done
for s in "${SKIP[@]:-}"; do [ -n "$s" ] && printf '  \033[33mSKIP\033[0m  %s\n' "$s"; done
for f in "${FAIL[@]:-}"; do [ -n "$f" ] && printf '  \033[31mFAIL\033[0m  %s\n' "$f"; done

if [ "${#FAIL[@]}" -gt 0 ]; then
    printf '\n\033[1;31m%d check(s) FAILED — do not commit.\033[0m\n' "${#FAIL[@]}"
    exit 1
fi
# A gate that ran nothing proves nothing — report success only for work that
# actually executed, never for an empty pass list.
if [ "${#PASS[@]}" -eq 0 ]; then
    printf '\n\033[1;31m0 checks executed (%d skipped) — nothing was verified.\033[0m\n' "${#SKIP[@]}"
    exit 2
fi
if [ "${#SKIP[@]}" -gt 0 ]; then
    printf '\n\033[1;33mAll %d executed check(s) passed; %d could not run here (listed above).\033[0m\n' \
        "${#PASS[@]}" "${#SKIP[@]}"
    printf '\033[1;33mCI is the authority for the skipped ones.\033[0m\n'
    exit 0
fi
printf '\n\033[1;32mAll %d checks passed.\033[0m\n' "${#PASS[@]}"
