#!/usr/bin/env bash
set -euo pipefail
script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
script="$script_dir/telegram-public-discovery.sh"
base=$(mktemp -d)
trap 'rm -rf -- "$base"' EXIT
cat > "$base/huntsman-recon" <<'MOCK'
#!/usr/bin/env bash
printf '%s\t%s\t%s\n' "${1-}" "${2-}" "${3-}" >> "$MOCK_LOG"
if [[ ${MOCK_ALL_FAIL:-0} == 1 ]]; then exit 70; fi
case "${3-}" in
  'site:tgstat.com sample topic') printf '{"query":"sample","entities":[],"outcomes":[]}\n'; exit 3 ;;
  'site:telemetr.io sample topic') exit 0 ;; # Empty stdout
  *) printf '{"query":"sample","entities":[],"outcomes":[]}\n' ;;
esac
MOCK
chmod +x "$base/huntsman-recon"
export HUNTSMAN_BIN="$base/huntsman-recon" MOCK_LOG="$base/arguments.tsv"
bash "$script" --output "$base/results" sample topic > "$base/out"
[[ $(wc -l < "$MOCK_LOG") -eq 4 ]]
[[ $(wc -l < "$base/results/manifest.tsv") -eq 5 ]]
[[ $(awk -F '\t' '$2==3{n++} END{print n+0}' "$base/results/manifest.tsv") -eq 1 ]]
[[ $(awk -F '\t' '$2==65{n++} END{print n+0}' "$base/results/manifest.tsv") -eq 1 ]]
[[ $(stat -c %a "$base/results") == 700 ]]
[[ $(stat -c %a "$base/results/manifest.tsv") == 600 ]]
grep -q 'answered_searches=2' "$base/out"
# Manifest integrity: reported byte counts and SHA-256 must reproduce exactly.
while IFS=$'\t' read -r provider exit_code query file state bytes digest elapsed; do
  [[ $provider == provider ]] && continue
  [[ $bytes == "$(wc -c < "$base/results/$file")" ]]
  [[ $digest == "$(sha256sum "$base/results/$file" | cut -d' ' -f1)" ]]
  [[ $elapsed =~ ^[0-9]+$ ]]
done < "$base/results/manifest.tsv"
# Extended mode adds four independent cohorts, still routed via the canonical Rust binary.
bash "$script" --expanded --output "$base/extended" sample topic > "$base/extended-out"
[[ $(wc -l < "$base/extended/manifest.tsv") -eq 9 ]]
[[ $(wc -l < "$MOCK_LOG") -eq 12 ]]
grep -q 'searches=8' "$base/extended-out"
# Bad input, overlong Unicode byte strings, and invalid budgets are rejected before I/O.
for input in $'bad\ninput' $'bad\tinput' 'bad"input' 'bad\input' "$(printf 'a%.0s' {1..121})" "$(printf 'é%.0s' {1..70})"; do
  if bash "$script" --output "$base/unsafe" "$input" > /dev/null 2>&1; then exit 1; fi
  [[ ! -e "$base/unsafe" ]]
done
if bash "$script" --output "$base/results" repeat > /dev/null 2>&1; then exit 1; fi
[[ $(wc -l < "$base/results/manifest.tsv") -eq 5 ]]
for bad in 0 121 garbage; do
  if HUNTSMAN_TELEGRAM_TIMEOUT_SECS=$bad bash "$script" --output "$base/invalid" test >/dev/null 2>&1; then exit 1; fi
  [[ ! -e "$base/invalid" ]]
done
for bad in 0 601 garbage; do
  if HUNTSMAN_TELEGRAM_TOTAL_TIMEOUT_SECS=$bad bash "$script" --output "$base/invalid2" test >/dev/null 2>&1; then exit 1; fi
  [[ ! -e "$base/invalid2" ]]
done
# All-failure means nonzero exit and no falsely claimed result.
if MOCK_ALL_FAIL=1 bash "$script" --output "$base/fail" test > /dev/null 2>&1; then exit 1; fi
[[ $(awk -F '\t' '$2==70{n++} END{print n+0}' "$base/fail/manifest.tsv") -eq 4 ]]
# Enforce actual kill of a slow mock.
cat > "$base/hung" <<'HUNG'
#!/usr/bin/env bash
sleep 2
HUNG
chmod +x "$base/hung"
if HUNTSMAN_BIN="$base/hung" HUNTSMAN_TELEGRAM_TIMEOUT_SECS=1 bash "$script" --output "$base/timed" test >/dev/null 2>&1; then exit 1; fi
[[ $(awk -F '\t' '$2==124{n++} END{print n+0}' "$base/timed/manifest.tsv") -eq 4 ]]
# Exhaust a global budget; remaining cohorts must be recorded as not run rather than silently discarded.
if HUNTSMAN_BIN="$base/hung" HUNTSMAN_TELEGRAM_TIMEOUT_SECS=2 HUNTSMAN_TELEGRAM_TOTAL_TIMEOUT_SECS=1 bash "$script" --output "$base/budget" test >/dev/null 2>&1; then exit 1; fi
[[ $(awk -F '\t' '$5=="not_run_budget_exhausted"{n++} END{print n+0}' "$base/budget/manifest.tsv") -ge 1 ]]
printf 'PASS: default/expanded cohorts, integrity digests, partial/empty/all-fail, input validation, output isolation, global and per-cohort timeouts.\n'
