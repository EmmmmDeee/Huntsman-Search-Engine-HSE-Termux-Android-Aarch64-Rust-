#!/data/data/com.termux/files/usr/bin/bash
# Huntsman MITM eligibility, read-only, one acquisition, identifiers never exported.
set -Eeuo pipefail
umask 077

fail() { printf 'UNAVAILABLE: %s\n' "$1" >&2; exit "${2:-20}"; }
for cmd in huntsman jq timeout mktemp wc; do
  command -v "$cmd" >/dev/null 2>&1 || fail "Missing command: $cmd"
done

work="$(mktemp -d "${TMPDIR:-${PREFIX:-/data/data/com.termux/files/usr}/tmp}/hse-mitm.XXXXXXXX")" || fail 'Cannot create private workspace'
trap 'rm -rf -- "$work"' EXIT

# Huntsman radar can return a nonzero status on stale-only captures while still
# emitting its complete JSON. Preserve this distinction without a second scan.
radar_rc=0
timeout 30 huntsman radar wifi --json >"$work/radar.json" 2>"$work/stderr" || radar_rc=$?

[[ -s "$work/radar.json" ]] || fail "No radar JSON (command exit $radar_rc); check Termux:API, Location, and Wi-Fi" 21
(( $(wc -c <"$work/radar.json") <= 2097152 )) || fail 'Radar JSON exceeds diagnostic bound' 21

# Accept only a LIVE, known-version radar report with its MITM assessment;
# never reclassify an imported/offline replay as current sensor evidence.
jq -e '
  type == "object" and
  .source == "termux-wifi-scaninfo" and
  .acquisition == "android_cached_scan_results_not_active_scan" and
  (.status | IN("inconclusive", "stale_only", "os_cached", "freshness_unknown")) and
  (.observed | type == "number" and . >= 0 and . == floor) and
  (.rejected | type == "number" and . >= 0 and . == floor) and
  (.observations | type == "array") and
  (.observed == (.observations | length)) and
  (.observations | all(.[];
      type == "object" and
      (.freshness | IN("stale", "os_cached", "unknown")) and
      (.sighting | type == "object") and
      (.sighting.network_id | type == "string") and
      ((.sighting.name == null) or (.sighting.name | type == "string")) and
      ((.age_secs == null) or (.age_secs | type == "number"))
  )) and
  (.mitm_assessment | type == "object") and
  (.mitm_assessment.source == "termux-wifi-scaninfo") and
  (.mitm_assessment.status | IN("inconclusive", "no_specific_indicators_observed", "unconfirmed_indicators")) and
  (.mitm_assessment.evaluated_access_points | type == "number" and . >= 0 and . == floor) and
  (.mitm_assessment.rejected_records == .rejected) and
  (.mitm_assessment.findings | type == "array") and
  (.mitm_assessment.mitm_confirmed == false)
' "$work/radar.json" >/dev/null 2>&1 || fail 'Invalid or non-live Huntsman radar schema; no claim possible' 22

# Mirror the installed Rust selection order: fresh -> visible 1..32 byte SSID
# -> valid individual BSSID -> unique SSID/BSSID pairs. It remains an
# independently calculated count, NOT evidence of current proximity.
jq --argjson radar_exit "$radar_rc" '
  def name: (.sighting.name // "");
  def mac: (.sighting.network_id | ascii_downcase);
  def valid_mac:
    (mac | test("^[0-9a-f][02468ace](:[0-9a-f]{2}){5}$")) and
    (mac != "00:00:00:00:00:00") and
    (mac != "02:00:00:00:00:00");
  def reason:
    if .freshness == "stale" then "stale"
    elif .freshness != "os_cached" then "freshness_unknown"
    elif (name | utf8bytelength) == 0 then "missing_ssid"
    elif (name | utf8bytelength) > 32 then "oversized_ssid"
    elif ((name | ascii_downcase) | IN("(hidden)", "(no ssid)")) then "hidden_ssid"
    elif (valid_mac | not) then "invalid_bssid"
    else "eligible" end;
  . as $input |
  ($input.observations | map({
    reason: reason,
    ssid: (if reason == "eligible" then name else null end),
    bssid: (if reason == "eligible" then mac else null end)
  })) as $classified |
  ($classified | map(select(.reason == "eligible"))) as $eligible |
  ($eligible | map([.ssid, .bssid]) | unique | length) as $unique |
  ($input.mitm_assessment.evaluated_access_points) as $rust |
  ($input.mitm_assessment.findings | length) as $findings |
  (
    ["stale", "freshness_unknown", "missing_ssid", "oversized_ssid", "hidden_ssid", "invalid_bssid"] |
    map(. as $reason | {key: $reason, value: ($classified | map(select(.reason == $reason)) | length)}) |
    from_entries
  ) as $exclusions |
  ($input.mitm_assessment.eligibility // null) as $native |
  (
    if $native == null then null
    elif ($native | type) != "object" then false
    else
      ($native.observed_records == ($classified | length)) and
      ($native.excluded_stale == $exclusions.stale) and
      ($native.excluded_unknown_freshness == $exclusions.freshness_unknown) and
      ($native.excluded_missing_ssid == $exclusions.missing_ssid) and
      ($native.excluded_oversized_ssid == $exclusions.oversized_ssid) and
      ($native.excluded_hidden_ssid == $exclusions.hidden_ssid) and
      ($native.excluded_invalid_bssid == $exclusions.invalid_bssid) and
      ($native.duplicate_rows == (($eligible | length) - $unique)) and
      ($native.eligible_access_points == $unique)
    end
  ) as $native_agrees |
  {
    schema: "huntsman.mitm.eligibility.v2",
    source: "termux-wifi-scaninfo",
    acquisition: "android_cached_scan_results_not_active_scan",
    command_exit: $radar_exit,
    sensor_status: $input.status,
    raw_records_rejected_by_rust: $input.rejected,
    observations: ($classified | length),
    android_timestamps_present: ($input.observations | map(select(.os_timestamp_us != null)) | length),
    computed_ages_present: ($input.observations | map(select(.age_secs != null)) | length),
    security_metadata_present: ($input.observations | map(select((.capabilities // "") != "")) | length),
    exclusions: $exclusions,
    eligibility: {
      raw_eligible_rows: ($eligible | length),
      duplicate_rows: (($eligible | length) - $unique),
      predicted_unique_eligible: $unique,
      rust_evaluated: $rust,
      native_count_verification: (
        if $native_agrees == null then "not_available_older_binary"
        elif $native_agrees then "agree"
        else "mismatch" end
      ),
      agrees: (($unique == $rust) and ($native_agrees != false))
    },
    mitm: {
      status: $input.mitm_assessment.status,
      unconfirmed_finding_count: $findings,
      confirmed: false
    },
    conclusion: (
      if $unique != $rust or $native_agrees == false then "COUNT_MISMATCH"
      elif $rust == 0 then "INCONCLUSIVE_ZERO_EVALUATED"
      elif $findings > 0 then "UNCONFIRMED_INDICATORS"
      else "NO_SPECIFIC_INDICATORS_NOT_PROOF_OF_SAFETY" end
    ),
    next_step: (
      if $unique != $rust or $native_agrees == false then "Review native Rust assessment selection, identity normalization and exclusion counters."
      elif $rust > 0 then "Review unconfirmed findings; compare with independently verified access-point inventory."
      elif ($input.observations | length) == 0 then "Android supplied no usable cached observations; inspect Wi-Fi and Location permissions."
      elif ($classified | any(.reason == "stale")) then "Refresh Android Wi-Fi available-networks display, then repeat this diagnostic."
      elif ($classified | any(.reason == "freshness_unknown")) then "Check whether Android supplied boot-relative timestamps and whether /proc/uptime is readable."
      elif ($classified | any(.reason == "hidden_ssid" or .reason == "missing_ssid")) then "SSID unavailable: investigate Wi-Fi/Location permission and hidden-network behaviour."
      else "Review discarded SSIDs/BSSIDs and the device Wi-Fi data source without treating them as a current attack." end
    ),
    note: "Cached OS observations do not prove attack presence or absence. No trusted baseline was enrolled."
  }
' "$work/radar.json" > "$work/summary.json" || fail 'Failed to derive privacy-preserving summary' 23

# Report itself is identifier-free. Do not echo raw JSON or stderr from scans.
state="${HUNTSMAN_HOME:-$HOME/.huntsman}"
if [[ -d "$state" && ! -L "$state" ]]; then
  report="$(mktemp "$state/mitm-eligibility.XXXXXXXX.json")"
  chmod 0600 "$report"
  cat "$work/summary.json" > "$report"
  printf 'Saved private summary: %s\n' "$report"
else
  printf 'NOTE: State directory unavailable; no report saved\n' >&2
fi
jq . "$work/summary.json"

if ! jq -e '.eligibility.agrees == true' "$work/summary.json" >/dev/null; then
  printf 'COUNT MISMATCH: summary preserved for investigation; no conclusion.\n' >&2
  exit 24
fi
if ((radar_rc != 0)) &&
   ! jq -e '.sensor_status == "stale_only" or .sensor_status == "inconclusive"' "$work/summary.json" >/dev/null; then
  printf 'INCONSISTENCY: radar exited nonzero despite non-stale sensor status.\n' >&2
  exit 25
fi
