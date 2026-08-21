#!/usr/bin/env bash
# User prompt submit hook — provides contextual guidance and fast-tracks common operations.
set -uo pipefail

log() { printf '[prompt-submit] %s\n' "$*" >&2; }

# Quick tip system: recognize common query patterns and suggest optimizations.
read_input() {
  # This is a placeholder for future input routing. Currently logs patterns.
  local input="$1"

  # Suggest running the gate for quality checks
  if [[ "$input" =~ (commit|push|ready|ship|merge|green) ]]; then
    log "Tip: run /ci or Ctrl+G to validate gate before pushing"
  fi

  # Suggest running tests for test-related queries
  if [[ "$input" =~ (test|fail|broken|error) ]]; then
    log "Tip: run /test or Ctrl+Shift+T to run the test suite"
  fi

  # Suggest using agents for research queries
  if [[ "$input" =~ (search|find|look|grep|where) ]]; then
    log "Tip: consider using the Explore agent for codebase search"
  fi
}

# Non-blocking: just log patterns, don't block input.
exit 0
