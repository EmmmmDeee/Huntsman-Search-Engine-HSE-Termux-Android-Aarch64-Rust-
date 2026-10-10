#!/usr/bin/env bash
# capture.sh BASE OUT_DIR
#
# Writes the agent's change as data: OUT_DIR/change.patch, a binary git patch of
# everything the working tree changes against BASE, new files included. Later jobs
# apply that patch and check it. They never use the agent's repository, whose
# configuration and hooks the agent could have written. Refuses an empty change.
set -euo pipefail

base="${1:?usage: capture.sh BASE OUT_DIR}"
out="${2:?usage: capture.sh BASE OUT_DIR}"
mkdir -p "$out"

git add -A
if git diff --cached --quiet --no-ext-diff "$base" --; then
  echo "capture: the agent left no changes against $base" >&2
  exit 1
fi
git diff --cached --binary --full-index --no-ext-diff --no-textconv "$base" -- > "$out/change.patch"
printf 'capture: wrote %s bytes to %s/change.patch\n' "$(wc -c < "$out/change.patch")" "$out"
