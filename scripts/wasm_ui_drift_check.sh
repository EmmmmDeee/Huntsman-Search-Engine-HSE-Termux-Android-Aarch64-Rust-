#!/usr/bin/env bash
# Regenerates wasm-ui's compiled output (hse_wasm_ui.js + hse_wasm_ui_bg.wasm)
# from source with the exact pinned pipeline and either diffs it byte-for-byte
# against the committed wasm-ui/pkg/ (default) or installs it there (--write).
#
# Exists to catch the class of drift PR #547 found by hand: a source change
# (to_js_error) landed without anyone regenerating the checked-in compiled
# artifact, so the two silently diverged. Called identically from
# scripts/gate.sh and .github/workflows/ci.yml's sibling-crates job — see
# gate.sh's own header comment for why the two must never diverge. `--write`
# is the ONE regeneration procedure (there is no separate hand-run recipe to
# keep in sync with this file): a change under hse-core/ or wasm-ui/src/ is
# followed by `scripts/wasm_ui_drift_check.sh --write` and a commit of pkg/.
#
# Preconditions this script assumes the CALLER already verified: the
# wasm32-unknown-unknown target is installed, `wasm-bindgen` on PATH matches
# wasm-ui/Cargo.toml's `wasm-bindgen` dependency version exactly, and
# `wasm-opt` is on PATH. A version-mismatched wasm-bindgen or a different
# wasm-opt build can legitimately produce different bytes from IDENTICAL
# source — that is toolchain drift, not source drift, and this script has no
# way to tell the two apart. (gate.sh skips with a clear reason rather than
# risk a false failure when it can't confirm an exact match; ci.yml installs
# an exact pinned wasm-opt build for the same reason.)
#
# THE BUILD RUNS FROM ONE FIXED ABSOLUTE PATH (BUILD_ROOT), NOT FROM THE
# CHECKOUT. Two things make the output depend on where the source sits:
#
#   1. rustc embeds the absolute build path (and, transitively, CARGO_HOME's
#      registry checkout path) into panic-location strings even in a
#      --release wasm32 build. The --remap-path-prefix flags below handle
#      that, and were the first fix (this check's first real CI run FAILED
#      on a clean tree purely because CI checks out at a different absolute
#      path than wherever wasm-ui/pkg/ had been regenerated).
#   2. cargo's per-crate `-C metadata` hash — the crate disambiguator that
#      ends up in every mangled symbol — includes the ABSOLUTE path of a
#      path dependency that lies outside the building package's workspace.
#      hse-core is exactly that for wasm-ui (`../hse-core`; neither crate is
#      in the root workspace), and with `lto = true` / `codegen-units = 1`
#      the final item and data-segment order follows those symbol hashes.
#      --remap-path-prefix does not touch this. Whether the difference is
#      visible depends on the source (the pre-change pkg/ happened to lay out
#      identically from two paths; adding one string literal to hse-core
#      made the same source produce different — equally valid — bytes from
#      /home/runner/work/… and from a development sandbox). Measured, not
#      assumed: two builds from one path are byte-identical, builds from two
#      paths are not, already in cargo's raw .wasm before wasm-bindgen runs.
#
# Copying the two crates to the same fixed absolute path on every machine
# (CI, a Linux dev box, this sandbox) removes the variable at its source.
# The path is under /tmp because that is the one absolute location every
# CI/Linux host shares; a host that cannot create it (Termux has no /tmp)
# gets a clear error, and gate.sh skips there with the reason — CI is the
# authority on such hosts.
#
# Both --remap-path-prefix placeholder strings are arbitrary but MUST stay
# byte-for-byte fixed forever (changing either changes every future
# regeneration's output, which would itself look like drift against
# history) — do not "clean up" them to something path-like or
# environment-derived. The same holds for BUILD_ROOT itself.
#
# Usage: scripts/wasm_ui_drift_check.sh            # check
#        scripts/wasm_ui_drift_check.sh --write    # regenerate into wasm-ui/pkg/
# Exit 0: regenerated output matches wasm-ui/pkg/ byte-for-byte (or, with
#         --write, was installed there).
# Exit non-zero: either a real difference was found (reported on stdout), or
# a pipeline step itself failed (reported by that step, via `set -e`).
set -euo pipefail

WRITE=0
case "${1:-}" in
    "") ;;
    --write) WRITE=1 ;;
    *) echo "usage: $0 [--write]" >&2; exit 2 ;;
esac

cd "$(dirname "${BASH_SOURCE[0]}")/.."
CARGO_HOME="${CARGO_HOME:-$HOME/.cargo}"

# Fixed on every host — see the header. Never derive this from $TMPDIR, $PWD
# or mktemp: the point is that it is the same string everywhere.
BUILD_ROOT=/tmp/hse-wasm-ui-build-root
if ! rm -rf "$BUILD_ROOT" || ! mkdir -p "$BUILD_ROOT"; then
    echo "wasm_ui_drift_check: cannot create the fixed build root $BUILD_ROOT on this host" >&2
    echo "  (the build must run from one fixed absolute path to be reproducible — see this script's header;" >&2
    echo "   CI is the authority for this check on hosts without a writable /tmp)" >&2
    exit 1
fi

# Only the inputs: both crates' sources and lockfiles (plus the LICENSE their
# manifests name). Never a target/ dir (a native hse-core build may have left
# one) and never wasm-ui/pkg/ (the output under test).
tar -C . \
    --exclude='./hse-core/target' \
    --exclude='./wasm-ui/target' \
    --exclude='./wasm-ui/pkg' \
    -cf - LICENSE hse-core wasm-ui | tar -C "$BUILD_ROOT" -xf -

export RUSTFLAGS="${RUSTFLAGS:-} --remap-path-prefix=$BUILD_ROOT=/remapped/wasm-ui-build-root --remap-path-prefix=$CARGO_HOME/registry/src=/remapped/cargo-registry-src"

# --locked: this check exists to validate the COMMITTED artifact against the
# COMMITTED dependency graph — without it, a Cargo.toml/Cargo.lock drifted out
# of sync would make cargo silently update the lock and build against
# different dependency versions than what's actually checked in, instead of
# failing loudly the way gate.sh's/ci.yml's every other build step already
# does with --locked.
CARGO_TARGET_DIR="$BUILD_ROOT/target" cargo build --manifest-path "$BUILD_ROOT/wasm-ui/Cargo.toml" \
    --target wasm32-unknown-unknown --release --locked

wasm-bindgen --target web --no-typescript --out-dir "$BUILD_ROOT/pkg" \
    --out-name hse_wasm_ui "$BUILD_ROOT/target/wasm32-unknown-unknown/release/hse_wasm_ui.wasm"

# Flags pinned to exactly what this toolchain's wasm32-unknown-unknown output
# actually uses (found by starting from none and adding only what wasm-opt's
# own validator complained was missing) — deliberately not --all-features
# (nor MVP-only): MVP-only fails validation outright (the input already uses
# these features), while --all-features risks wasm-opt leaning on much newer
# features (SIMD, GC, threads, …) than this input needs, for a measured
# ~120 B difference — a bad trade when the entire point is a .wasm an older
# Android WebView can still load.
#
# Writes to a distinct temp file rather than wasm-opt's own supported
# in-place `-o X X` form, purely to keep this pipeline robust to a future
# wasm-opt that reads lazily/streams — cheap to avoid, so avoid it, even
# though the currently pinned binaryen build reads its whole input upfront.
wasm-opt -Os --enable-sign-ext --enable-bulk-memory --enable-mutable-globals \
    --enable-nontrapping-float-to-int \
    -o "$BUILD_ROOT/pkg/hse_wasm_ui_bg.wasm.opt" "$BUILD_ROOT/pkg/hse_wasm_ui_bg.wasm"
mv "$BUILD_ROOT/pkg/hse_wasm_ui_bg.wasm.opt" "$BUILD_ROOT/pkg/hse_wasm_ui_bg.wasm"

# Only these two files are pipeline output — wasm-ui/pkg/ also holds
# wasm_test.html, a hand-authored diagnostic page the pipeline never touches.
if [ "$WRITE" -eq 1 ]; then
    cp "$BUILD_ROOT/pkg/hse_wasm_ui.js" "$BUILD_ROOT/pkg/hse_wasm_ui_bg.wasm" wasm-ui/pkg/
    echo "wasm-ui/pkg/ regenerated from source (commit it if git reports a change)."
    exit 0
fi

status=0
for f in hse_wasm_ui.js hse_wasm_ui_bg.wasm; do
    if ! cmp -s "wasm-ui/pkg/$f" "$BUILD_ROOT/pkg/$f"; then
        printf 'DRIFT: wasm-ui/pkg/%s does not match a fresh regeneration from source.\n' "$f"
        printf '       Regenerate it with `scripts/wasm_ui_drift_check.sh --write` and commit the result.\n'
        status=1
    fi
done

if [ "$status" -eq 0 ]; then
    echo "wasm-ui/pkg/ matches a fresh regeneration from source — no drift."
fi
exit "$status"
