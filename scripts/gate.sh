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
    fi
}

skip() { # skip <name> <reason>
    SKIP+=("$1 — $2")
    printf '\n\033[1;33m==> %s: SKIPPED (%s)\033[0m\n' "$1" "$2"
}

# ── ci.yml: Check & test (Linux x86_64, stable) ──────────────────────────────
run "fmt"      cargo fmt --all -- --check
run "check"    cargo check --all-targets --locked
run "clippy"   cargo clippy --all-targets --locked -- -D warnings
RUSTDOCFLAGS="$RUSTDOC_LINTS" \
  run "rustdoc lints" cargo doc --no-deps --document-private-items --locked
# ci.yml runs ONE `cargo test --all`, which already includes doctests. This gate
# reports doctests as their own check (`doctests` below), so this step must
# EXCLUDE them — `--lib --bins --tests` does exactly that. A bare `cargo test
# --all` here ran the whole doctest suite a second time under `doctests`. Total
# coverage is unchanged: lib+bins+integration here, doctests below == ci.yml's
# single `--all`.
run "test"     cargo test --all --lib --bins --tests --locked
run "doctests" cargo test --doc --locked
run "doc coverage" scripts/doc_coverage.sh

# ── ci.yml: MSRV ─────────────────────────────────────────────────────────────
if [ "$QUICK" = 1 ]; then
    skip "MSRV ($MSRV)" "--quick"
elif rustup toolchain list 2>/dev/null | grep -q "^${MSRV}"; then
    run "MSRV ($MSRV)" cargo "+$MSRV" check --all-targets --locked
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

# ── ci.yml: install.sh syntax + shellcheck ───────────────────────────────────
run "install.sh syntax" bash -n install.sh
if command -v shellcheck >/dev/null 2>&1; then
    # `--severity=warning` mirrors ci.yml's ShellCheck step exactly. Without it
    # this gate was STRICTER than CI: install.sh carries several long-standing
    # `info`-level notes (SC2015 A && B || C, SC2059 printf format) that CI
    # tolerates, so a host that happens to have shellcheck installed reported a
    # FAIL for something CI passes. A gate that cries wolf is worse than one
    # that skips: it trains you to ignore it.
    run "shellcheck" shellcheck --severity=warning install.sh scripts/gate.sh
else
    skip "shellcheck" "not installed"
fi

# ── audit.yml: only fires when a manifest changed, so mirror that ────────────
if git diff --quiet HEAD -- Cargo.toml Cargo.lock deny.toml 2>/dev/null; then
    skip "cargo-audit / deny / machete" "no manifest change (audit.yml path filter)"
else
    for t in cargo-audit cargo-deny cargo-machete; do
        command -v "$t" >/dev/null 2>&1 || skip "$t" "not installed"
    done
    command -v cargo-audit   >/dev/null 2>&1 && run "cargo audit"   cargo audit
    command -v cargo-deny    >/dev/null 2>&1 && run "cargo deny"    cargo deny check
    command -v cargo-machete >/dev/null 2>&1 && run "cargo machete" cargo machete --with-metadata
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
if [ "${#SKIP[@]}" -gt 0 ]; then
    printf '\n\033[1;33mAll %d executed check(s) passed; %d could not run here (listed above).\033[0m\n' \
        "${#PASS[@]}" "${#SKIP[@]}"
    printf '\033[1;33mCI is the authority for the skipped ones.\033[0m\n'
    exit 0
fi
printf '\n\033[1;32mAll %d checks passed.\033[0m\n' "${#PASS[@]}"
