#!/usr/bin/env bash
# Pre-push gate validation — ensures commits pass CI before pushing.
# Run automatically before any git push via claude/claude-code-remote integration.
set -uo pipefail

log() { printf '[pre-push-gate] %s\n' "$*" >&2; }
error() { printf '[pre-push-gate] ERROR: %s\n' "$*" >&2; return 1; }

PROJECT_DIR="${CLAUDE_PROJECT_DIR:-$PWD}"
GATE_SCRIPT="$PROJECT_DIR/scripts/gate.sh"

# Only run in remote sessions (web/cloud).
if [ "${CLAUDE_CODE_REMOTE:-}" != "true" ]; then
  exit 0
fi

if [ ! -x "$GATE_SCRIPT" ]; then
  log "gate.sh not found — skipping pre-push validation"
  exit 0
fi

log "running CI gate validation before push..."
cd "$PROJECT_DIR"

# Run quick gate (skip MSRV and cross-build for speed).
if "$GATE_SCRIPT" --quick; then
  log "✓ gate passed — ready to push"
  exit 0
else
  error "✗ gate failed — fix errors before pushing"
  exit 1
fi
