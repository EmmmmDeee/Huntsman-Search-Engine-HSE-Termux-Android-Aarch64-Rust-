#!/usr/bin/env bash
# SessionStart hook for Claude Code on the web.
#
# Provisions the session container so `cargo fmt`/`clippy`/`test` work before
# the agent loop starts. The actual dependency + toolchain install is delegated
# to scripts/setup-dev.sh (the single source of truth, shared with local
# developer setup); this wrapper adds the web-only guard, PATH persistence, and
# crate-cache warm. Idempotent, non-interactive, and web-only — it never touches
# a developer's local checkout.
set -uo pipefail

log() { printf '[session-start] %s\n' "$*" >&2; }

# Web-only: do nothing on a local machine.
if [ "${CLAUDE_CODE_REMOTE:-}" != "true" ]; then
  exit 0
fi

PROJECT_DIR="${CLAUDE_PROJECT_DIR:-$PWD}"

# Install toolchain + system build deps via the shared dev-setup script.
# --deps-only skips the fmt/clippy/build verification so session startup stays
# fast (those run on demand once the session is live).
if [ -x "$PROJECT_DIR/scripts/setup-dev.sh" ]; then
  log "provisioning toolchain + deps via scripts/setup-dev.sh"
  "$PROJECT_DIR/scripts/setup-dev.sh" --deps-only || true
else
  log "scripts/setup-dev.sh not found — skipping dependency provisioning"
fi

# Make cargo available now and persist it for the session's agent loop.
if [ -f "$HOME/.cargo/env" ]; then
  # shellcheck disable=SC1091
  . "$HOME/.cargo/env"
fi
if [ -n "${CLAUDE_ENV_FILE:-}" ]; then
  printf 'export PATH="%s/.cargo/bin:$PATH"\n' "$HOME" >> "$CLAUDE_ENV_FILE"
fi

# Warm the crate cache so the first clippy/test doesn't re-download the graph.
if command -v cargo >/dev/null 2>&1 && [ -f "$PROJECT_DIR/Cargo.lock" ]; then
  log "fetching crate dependencies"
  (cd "$PROJECT_DIR" && { cargo fetch --locked >/dev/null 2>&1 || cargo fetch >/dev/null 2>&1; }) || true
fi

log "ready: $(rustc --version 2>/dev/null || echo 'rustc unavailable')"
exit 0
