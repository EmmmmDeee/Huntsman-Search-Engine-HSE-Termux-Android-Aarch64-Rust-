#!/usr/bin/env bash
# Standard acceptance run for Huntsman Search Engine.
#
# Exercises the free, keyless OSINT pipeline end-to-end on a canonical seed and
# prints EVERY result IN FULL with COMPLETE URLs — no truncation, no omission.
# This is the repo's "make it standard" smoke test: a single command that shows
# the search-engine liveness, the capability toggles, and a real scan's dossier.
#
# Scope vs. the other scripts in this repo:
#   * scripts/setup-dev.sh   — set up a developer toolchain (build/lint/test).
#   * install.sh             — end-user installer (build + install `hse`).
#   * THIS script            — run the canonical Kylo4kylo acceptance scan and
#                              print the full results; touches no operator state.
#
# Usage:
#   scripts/standard-test.sh                 # canonical seed: Kylo4kylo
#   scripts/standard-test.sh "<seed>"        # any username/handle seed
#
# Environment overrides (all optional):
#   HSE_BIN       path to the hse binary       (default: target/release then debug)
#   HSE_KIND      target kind                  (default: username)
#   HSE_DEPTH     recursion depth              (default: 1)
#   HSE_TIMEOUT_MS  per-module timeout in ms   (default: 60000)
#   HSE_WALL      max wall-time in seconds     (default: 240)
#   HSE_JSON      set to 1 to also emit JSON (entities with complete URLs)
set -euo pipefail

SEED="${1:-Kylo4kylo}"
KIND="${HSE_KIND:-username}"
DEPTH="${HSE_DEPTH:-1}"
TIMEOUT_MS="${HSE_TIMEOUT_MS:-60000}"
WALL="${HSE_WALL:-240}"

# Locate the binary: explicit override, else release, else debug.
BIN="${HSE_BIN:-}"
if [ -z "$BIN" ]; then
    if [ -x ./target/release/hse ]; then BIN=./target/release/hse
    elif [ -x ./target/debug/hse ]; then BIN=./target/debug/hse
    else
        echo "error: no hse binary found — run 'cargo build --release' first" >&2
        exit 1
    fi
fi

# Isolated HOME so the run never reads or writes the operator's keys/toggles/DB.
RUN_HOME="$(mktemp -d)"
trap 'rm -rf "$RUN_HOME"' EXIT
export HOME="$RUN_HOME"

rule() { printf '\n\033[1;36m== %s ==\033[0m\n' "$1"; }

rule "HSE standard acceptance run"
"$BIN" --version
echo "seed=$SEED kind=$KIND depth=$DEPTH per-module-timeout=${TIMEOUT_MS}ms wall=${WALL}s"

rule "Search-engine liveness (free, keyless; disabled engines shown too)"
"$BIN" engines || true

rule "Capability toggles (features / engines / modules)"
"$BIN" config || true

# The dossier prints every entity, every evidence attribute, and COMPLETE URLs,
# fully unredacted — the canonical "all results in full" view.
rule "Scan dossier: $KIND=$SEED"
"$BIN" scan --kind "$KIND" --value "$SEED" \
    --depth "$DEPTH" --timeout "$TIMEOUT_MS" --max-wall-time "$WALL" \
    --output dossier

if [ "${HSE_JSON:-0}" = "1" ]; then
    rule "Machine-readable scan (entities + complete URLs)"
    "$BIN" scan --kind "$KIND" --value "$SEED" \
        --depth "$DEPTH" --timeout "$TIMEOUT_MS" --max-wall-time "$WALL" \
        --output json
fi

rule "Done"
