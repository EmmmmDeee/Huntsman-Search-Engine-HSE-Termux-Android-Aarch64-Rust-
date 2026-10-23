#!/usr/bin/env bash
# Bounded Docker build retry for transient registry HTTP failures.
# Preserve real build failures and never treat an exhausted retry as success.
set -Eeuo pipefail

if (( $# == 0 )); then
  printf 'usage: bash scripts/container-build-retry.sh [docker build arguments...]\n' >&2
  exit 64
fi
command -v docker >/dev/null 2>&1 || { printf 'docker is not installed\n' >&2; exit 1; }
log="$(mktemp "${TMPDIR:-/tmp}/huntsman-docker-retry.XXXXXX")" || exit 1
trap 'rm -f -- "$log"' EXIT

for attempt in 1 2 3; do
  : > "$log"
  if docker build "$@" 2>&1 | tee "$log"; then
    printf 'Docker build verified on attempt %d\n' "$attempt"
    exit 0
  else
    status=$?
  fi
  if ! LC_ALL=C grep -Eiq \
    '(unexpected status code|received unexpected HTTP status|response status).*(429|5[0-9]{2})|(^|[[:space:]])(429|500|502|503|504) (Too Many Requests|Internal Server Error|Bad Gateway|Service Unavailable|Gateway Timeout)' \
    "$log"; then
    printf 'Docker build failed with a non-retryable error (exit %d)\n' "$status" >&2
    exit "$status"
  fi
  if (( attempt == 3 )); then
    printf 'Docker build failed after three transient-registry attempts (exit %d)\n' "$status" >&2
    exit "$status"
  fi
  printf 'Transient HTTP error during Docker build; retrying (%d/3)\n' "$attempt" >&2
  sleep "$attempt"
done
