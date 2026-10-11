#!/usr/bin/env bash
set -euo pipefail

command -v railway >/dev/null 2>&1 || {
  echo "railway-iac-plan: Railway CLI is required" >&2
  exit 1
}

version="$(railway --version 2>/dev/null || true)"
printf 'railway-iac-plan: cli=%s\n' "$version"

# Railway config plan is intentionally read-only. Authentication/project linking
# must already be configured by railway login/token + railway link.
railway config plan
