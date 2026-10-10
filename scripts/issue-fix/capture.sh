#!/usr/bin/env bash
# capture.sh BASE OUT_DIR
#
# Writes the agent's change as data: OUT_DIR/change.patch, a binary git patch of
# everything the working tree changes against BASE, new files included. Later jobs
# apply that patch and check it. They never use the agent's repository, whose
# configuration and hooks the agent could have written. Refuses an empty change.
#
# In-tree attributes are ignored (--attr-source), so a .gitattributes filter in the
# change cannot rewrite the content that becomes the patch.
set -euo pipefail

base="${1:?usage: capture.sh BASE OUT_DIR}"
out="${2:?usage: capture.sh BASE OUT_DIR}"
EMPTY_TREE=4b825dc642cb6eb9a060e54bf8d69288fbee4904
g() { git --attr-source="$EMPTY_TREE" "$@"; }
mkdir -p "$out"

g add -A
changed=0
g diff --cached --quiet --no-ext-diff "$base" -- || changed=$?
case "$changed" in
  0)
    echo "capture: the agent left no changes against $base" >&2
    exit 1
    ;;
  1) ;;
  *)
    echo "capture: git diff failed (exit $changed) against $base" >&2
    exit 1
    ;;
esac
g diff --cached --binary --full-index --no-ext-diff --no-textconv "$base" -- > "$out/change.patch"
printf 'capture: wrote %s bytes to %s/change.patch\n' "$(wc -c < "$out/change.patch")" "$out"
