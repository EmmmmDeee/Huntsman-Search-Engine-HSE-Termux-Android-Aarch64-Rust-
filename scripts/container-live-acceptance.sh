#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
usage: HUNTSMAN_CONTAINER_URL=https://service.example HSE_AUTH_TOKEN=... \
       HUNTSMAN_EXPECTED_SHA=<40-character-lowercase-commit> \
       bash scripts/container-live-acceptance.sh

Runs the same HTTP acceptance contract used by CI against a live self-hosted container
deployment. The bearer token is read from HSE_AUTH_TOKEN, copied into a private
temporary curl header file, then removed from the environment before requests.
EOF
}

die() {
  printf 'container-live-acceptance: %s\n' "$*" >&2
  exit 1
}

base="${HUNTSMAN_CONTAINER_URL:-${1:-}}"
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

expected_sha="${HUNTSMAN_EXPECTED_SHA:-}"
if [[ -n "$expected_sha" && ! "$expected_sha" =~ ^[0-9a-f]{40}$ ]]; then
  die "HUNTSMAN_EXPECTED_SHA must be exactly 40 lowercase hexadecimal characters"
fi

if [[ -z "${HSE_AUTH_TOKEN:-}" ]]; then
  die "HSE_AUTH_TOKEN is required for full live acceptance"
fi
case "$HSE_AUTH_TOKEN" in
  *$'\r'*|*$'\n'*) die "HSE_AUTH_TOKEN must not contain CR/LF" ;;
esac

tmpdir="$(mktemp -d "${TMPDIR:-/tmp}/huntsman-container-acceptance.XXXXXX")"
trap 'rm -rf "$tmpdir"' EXIT
chmod 0700 "$tmpdir"

auth_headers="$tmpdir/auth.headers"
umask 077
printf 'Authorization: Bearer %s\n' "$HSE_AUTH_TOKEN" > "$auth_headers"
unset HSE_AUTH_TOKEN

allowed_proto='=https'
case "$base" in
  http://127.0.0.1:*|http://localhost:*) allowed_proto='=http' ;;
esac

curl_common=(
  --silent
  --show-error
  --connect-timeout 10
  --max-time 20
  --proto "$allowed_proto"
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

grep -Eq '"status"[[:space:]]*:[[:space:]]*"ok"' "$health" \
  || die "health endpoint returned 200 without status=ok"

# Exact build identity is a separate proof obligation from a 200/ok response.
# Match the whole JSON string value rather than accepting a SHA prefix.
if [[ -n "$expected_sha" ]]; then
  grep -Eq "\"build_sha\"[[:space:]]*:[[:space:]]*\"${expected_sha}\"[[:space:]]*[,}]" "$health" \
    || die "build SHA mismatch or missing build_sha in /api/health"
fi

unauth="$tmpdir/modules-unauth.json"
unauth_code="$(request "$unauth" "$base/api/modules" || true)"
[[ "$unauth_code" == "401" ]] \
  || die "protected endpoint must reject unauthenticated access with HTTP 401 (got ${unauth_code:-transport-error})"

modules="$tmpdir/modules.json"
modules_code="$(request "$modules" -H "@$auth_headers" "$base/api/modules" || true)"
[[ "$modules_code" == "200" ]] \
  || die "authenticated /api/modules failed (HTTP ${modules_code:-transport-error})"
grep -Eq '"modules"[[:space:]]*:' "$modules" \
  || die "authenticated /api/modules response is missing modules"

command="$tmpdir/command.json"
command_code="$(request "$command" -H "@$auth_headers" "$base/api/command" || true)"
[[ "$command_code" == "200" ]] \
  || die "authenticated /api/command failed (HTTP ${command_code:-transport-error})"
grep -Eq '"invariant"[[:space:]]*:' "$command" \
  || die "authenticated /api/command response is missing invariant"

printf 'container-live-acceptance: PASS\n'
printf 'url=%s\n' "$base"
printf 'health=200 status=ok\n'
printf 'unauthenticated_modules=401\n'
printf 'authenticated_modules=200\n'
printf 'authenticated_command=200\n'
if [[ -n "$expected_sha" ]]; then
  printf 'build_sha=%s\n' "$expected_sha"
else
  printf 'build_sha=UNVERIFIED (set HUNTSMAN_EXPECTED_SHA for release acceptance)\n'
fi
