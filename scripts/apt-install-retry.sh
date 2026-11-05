#!/usr/bin/env bash
# Bounded apt install for CI runners.
#
# A runner's Ubuntu mirror can trickle at a few kB/s. apt has no minimum-speed setting and its
# inactivity timeout never fires on a slow but live connection, so one slow download could hold
# a job until GitHub's six-hour limit. On 2026-11-05 one did for fourteen minutes, until it was
# cancelled by hand; the rerun installed the same packages in twelve seconds.
#
# So each attempt to refresh the package lists and download the packages is bounded, and the
# next attempt opens new connections and resumes what the last one fetched. The packages are
# installed only once every download completed, from the local cache. An exhausted retry is
# never treated as success.
set -Eeuo pipefail

if (( $# == 0 )); then
  printf 'usage: bash scripts/apt-install-retry.sh PACKAGE...\n' >&2
  exit 64
fi
bound="${HUNTSMAN_APT_BOUND_SECONDS:-180}"
if [[ ! "$bound" =~ ^[1-9][0-9]*$ ]]; then
  printf 'HUNTSMAN_APT_BOUND_SECONDS must be a whole number of seconds, not %s\n' "$bound" >&2
  exit 64
fi
apt=(sudo timeout "$bound" apt-get -o Acquire::Retries=3)
install=(install -y --no-install-recommends)

for attempt in 1 2 3; do
  if "${apt[@]}" update && "${apt[@]}" "${install[@]}" --download-only "$@"; then
    # Every package is in the local cache now, so this does no network I/O. A failure here is
    # a real one, so it is not retried.
    "${apt[@]}" "${install[@]}" "$@"
    printf 'apt installed %s on attempt %d\n' "$*" "$attempt"
    exit 0
  else
    status=$?
  fi
  # timeout exits 124 when a step ran past its bound.
  if (( attempt == 3 )); then
    printf '::error::apt could not fetch %s in three attempts (last exit %d; 124 is a step past %ss)\n' \
      "$*" "$status" "$bound" >&2
    exit "$status"
  fi
  printf '::warning::apt attempt %d failed (exit %d; 124 is a step past %ss); retrying\n' \
    "$attempt" "$status" "$bound" >&2
done
