#!/usr/bin/env bash
# Regenerates wasm-ui's compiled output (hse_wasm_ui.js + hse_wasm_ui_bg.wasm)
# from source, using the exact pipeline documented in wasm-ui/src/lib.rs's doc
# comment, and diffs it byte-for-byte against the committed wasm-ui/pkg/.
#
# Exists to catch the class of drift PR #547 found by hand: a source change
# (to_js_error) landed without anyone regenerating the checked-in compiled
# artifact, so the two silently diverged. Called identically from
# scripts/gate.sh and .github/workflows/ci.yml's sibling-crates job — see
# gate.sh's own header comment for why the two must never diverge.
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
# Usage: scripts/wasm_ui_drift_check.sh
# Exit 0: regenerated output matches wasm-ui/pkg/ byte-for-byte.
# Exit non-zero: either a real difference was found (reported on stdout), or
# a pipeline step itself failed (reported by that step, via `set -e`).
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

SCRATCH="$(mktemp -d)"
trap 'rm -rf "$SCRATCH"' EXIT

CARGO_TARGET_DIR="$SCRATCH/target" cargo build --manifest-path wasm-ui/Cargo.toml \
    --target wasm32-unknown-unknown --release

wasm-bindgen --target web --no-typescript --out-dir "$SCRATCH/pkg" \
    --out-name hse_wasm_ui "$SCRATCH/target/wasm32-unknown-unknown/release/hse_wasm_ui.wasm"

# Flags pinned to exactly what this toolchain's wasm32-unknown-unknown output
# actually uses — see wasm-ui/src/lib.rs's doc comment for why (not
# --all-features, not MVP-only). Keep the two lists identical.
wasm-opt -Os --enable-sign-ext --enable-bulk-memory --enable-mutable-globals \
    --enable-nontrapping-float-to-int \
    -o "$SCRATCH/pkg/hse_wasm_ui_bg.wasm" "$SCRATCH/pkg/hse_wasm_ui_bg.wasm"

# Only these two files are pipeline output — wasm-ui/pkg/ also holds
# wasm_test.html, a hand-authored diagnostic page the pipeline never touches.
status=0
for f in hse_wasm_ui.js hse_wasm_ui_bg.wasm; do
    if ! cmp -s "wasm-ui/pkg/$f" "$SCRATCH/pkg/$f"; then
        printf 'DRIFT: wasm-ui/pkg/%s does not match a fresh regeneration from source.\n' "$f"
        printf '       Regenerate it (see wasm-ui/src/lib.rs doc comment) and commit the result.\n'
        status=1
    fi
done

if [ "$status" -eq 0 ]; then
    echo "wasm-ui/pkg/ matches a fresh regeneration from source — no drift."
fi
exit "$status"
