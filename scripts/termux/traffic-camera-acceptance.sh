#!/data/data/com.termux/files/usr/bin/bash
# On-device release gate: real rootless Termux/aarch64 binary, official source fetches,
# and protected embedded Web UI API. Explicit operator invocation; never polls.
set -Eeuo pipefail
umask 077

if [[ "$(uname -m)" != "aarch64" || "${PREFIX:-}" != "/data/data/com.termux/files/usr" || "$(id -u)" == "0" ]]; then
  printf 'FAIL: run unprivileged in native Termux on Android aarch64 (no root).\n' >&2
  exit 69
fi
for command in huntsman-recon jq curl; do
  if ! command -v "$command" >/dev/null 2>&1; then
    printf 'FAIL: missing %s; install available Termux packages or Huntsman before testing.\n' "$command" >&2
    exit 69
  fi
done

root="$(mktemp -d "${TMPDIR:-$PREFIX/tmp}/hse-camera-check.XXXXXXXX")"
trap 'rm -rf -- "$root"' EXIT

printf 'HUNTSMAN_BUILD_SHA: '
huntsman-recon build-sha
printf 'Checking real one-shot QLDTraffic CLI collector and GIS reconciliation...\n'
if ! huntsman-recon traffic-cameras --reconcile --limit 2 >"$root/cli.json"; then
  jq -c '{webcam: .catalogue.outcome, gis: .gis_catalogue.outcome}' "$root/cli.json" 2>/dev/null || true
  printf 'FAIL: actual CLI collector or GIS reconciliation returned an error.\n' >&2
  exit 1
fi
jq -e '
  (.catalogue.outcome.kind == "success") and
  (.gis_catalogue.outcome.kind == "success") and
  (.catalogue.rejected_features == 0) and
  (.gis_catalogue.rejected_features == 0) and
  (.reconciliation.publisher_families == 1) and
  (.reconciliation.webcam_count == .provider_total) and
  (.reconciliation.gis_count == (.gis_catalogue.cameras | length)) and
  (.reconciliation.webcam_count == (.reconciliation.shared_ids + (.reconciliation.webcam_only_ids | length))) and
  (.reconciliation.gis_count == (.reconciliation.shared_ids + (.reconciliation.gis_only_ids | length)))
' "$root/cli.json" >/dev/null || {
  printf 'FAIL: CLI catalogue contains unresolved, partial or inconsistent counts.\n' >&2
  exit 1
}

base='http://127.0.0.1:8080'
if ! curl -fsS --noproxy '*' --connect-timeout 3 --max-time 8 "$base/api/health" -o "$root/health.json"; then
  printf 'FAIL: no Huntsman on %s; start the verified local server first.\n' "$base" >&2
  exit 69
fi
jq -e '.status == "ok" and .name == "huntsman-recon"' "$root/health.json" >/dev/null || {
  printf 'FAIL: the service on port 8080 is not Huntsman.\n' >&2
  exit 69
}

printf 'Checking protected Web UI API, using its real transport and source adapters...\n'
if ! curl -fsS --noproxy '*' --connect-timeout 3 --max-time 46 \
  -H 'X-Huntsman-Lookup: 1' -H 'Sec-Fetch-Site: same-origin' \
  "$base/api/traffic/cameras" -o "$root/web.json"; then
  printf 'FAIL: Web UI camera API did not complete.\n' >&2
  exit 1
fi
jq -e '
  (.webcam.outcome.kind == "success") and
  (.gis.outcome.kind == "success") and
  (.webcam.rejected_features == 0) and
  (.gis.rejected_features == 0) and
  (.reconciliation.publisher_families == 1) and
  (.reconciliation.webcam_count == (.webcam.cameras | length)) and
  (.reconciliation.gis_count == (.gis.cameras | length))
' "$root/web.json" >/dev/null || {
  printf 'FAIL: Web API evidence is incomplete or contradicts the reported inventory.\n' >&2
  exit 1
}

jq -r '"CLI verified: webcam=\(.reconciliation.webcam_count), GIS=\(.reconciliation.gis_count), shared=\(.reconciliation.shared_ids), position_conflicts=\(.reconciliation.position_conflicts | length), direction_conflicts=\(.reconciliation.direction_conflicts | length)"' "$root/cli.json"
jq -r '"Web verified: webcam=\(.reconciliation.webcam_count), GIS=\(.reconciliation.gis_count), shared=\(.reconciliation.shared_ids), position_conflicts=\(.reconciliation.position_conflicts | length), direction_conflicts=\(.reconciliation.direction_conflicts | length)"' "$root/web.json"
printf 'PASS: native Termux rootless CLI and guarded Web API ran their live source contracts.\n'
printf 'LIMIT: this does not verify JPEG freshness, complete provider coverage, or independent publisher corroboration.\n'
