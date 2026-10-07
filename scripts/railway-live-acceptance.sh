#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
usage: HUNTSMAN_RAILWAY_URL=https://service.example HSE_AUTH_TOKEN=... \
       bash scripts/railway-live-acceptance.sh

Runs the same HTTP acceptance contract used by CI against a live Railway
deployment. The bearer token is read only from HSE_AUTH_TOKEN; do not pass it
as a positional argument.
EOF
}

die() {
  printf 'railway-live-acceptance: %s\n' "$*" >&2
  exit 1
}

base="${HUNTSMAN_RAILWAY_URL:-${1:-}}"
if [[ -z "$base" ]]; then
  usage >&2
  exit 64
fi
base="${base%/}"

case "$base" in
  https://*) ;;
  http://127.0.0.1:*|http://localhost:*) ;;
  *) die "URL must use HTTPS (HTTP is allowed only for loopback CI)" ;;
esac

if [[ -z "${HSE_AUTH_TOKEN:-}" ]]; then
  die "HSE_AUTH_TOKEN is required for full live acceptance"
fi

tmpdir="$(mktemp -d "${TMPDIR:-/tmp}/huntsman-railway-acceptance.XXXXXX")"
trap 'rm -rf "$tmpdir"' EXIT

curl_common=(
  --silent
  --show-error
  --connect-timeout 10
  --max-time 20
)

request() {
  local output=$1
  shift
  curl "${curl_common[@]}" -o "$output" -w '%{http_code}' "$@"
}

health="$tmpdir/health.json"
health_code=""
for attempt in $(seq 1 30); do
  health_code="$(request "$health" "$base/api/health" || true)"
  if [[ "$health_code" == "200" ]]; then
    break
  fi
  if [[ "$attempt" -eq 30 ]]; then
    die "health endpoint never reached HTTP 200 (last status: ${health_code:-transport-error})"
  fi
  sleep 2
done

grep -Eq '"status"[[:space:]]*:[[:space:]]*"ok"' "$health"   || die "health endpoint returned 200 without status=ok"

unauth="$tmpdir/modules-unauth.json"
unauth_code="$(request "$unauth" "$base/api/modules" || true)"
[[ "$unauth_code" == "401" ]]   || die "protected endpoint must reject unauthenticated access with HTTP 401 (got ${unauth_code:-transport-error})"

auth_header="Authorization: Bearer $HSE_AUTH_TOKEN"

modules="$tmpdir/modules.json"
modules_code="$(request "$modules" -H "$auth_header" "$base/api/modules" || true)"
[[ "$modules_code" == "200" ]]   || die "authenticated /api/modules failed (HTTP ${modules_code:-transport-error})"
grep -Eq '"modules"[[:space:]]*:' "$modules"   || die "authenticated /api/modules response is missing modules"

command="$tmpdir/command.json"
command_code="$(request "$command" -H "$auth_header" "$base/api/command" || true)"
[[ "$command_code" == "200" ]]   || die "authenticated /api/command failed (HTTP ${command_code:-transport-error})"
grep -Eq '"invariant"[[:space:]]*:' "$command"   || die "authenticated /api/command response is missing invariant"

printf 'railway-live-acceptance: PASS\n'
printf 'url=%s\n' "$base"
printf 'health=200 status=ok\n'
printf 'unauthenticated_modules=401\n'
printf 'authenticated_modules=200\n'
printf 'authenticated_command=200\n'
