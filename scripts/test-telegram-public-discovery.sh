#!/usr/bin/env bash
set -euo pipefail
script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
base=$(mktemp -d)
trap 'rm -rf -- "$base"' EXIT
cat > "$base/huntsman-recon" <<'MOCK'
#!/usr/bin/env bash
printf '%s\t%s\t%s\n' "${1-}" "${2-}" "${3-}" >> "$MOCK_LOG"
if [[ ${MOCK_ALL_FAIL:-0} == 1 ]]; then exit 70; fi
case "${3-}" in
  'site:tgstat.com sample topic') printf '{"query":"sample","entities":[],"outcomes":[]}\n'; exit 3 ;;
  'site:telemetr.io sample topic') exit 0 ;; # Empty body deliberately
  *) printf '{"query":"sample","entities":[],"outcomes":[]}\n' ;;
esac
MOCK
chmod +x "$base/huntsman-recon"
export HUNTSMAN_BIN="$base/huntsman-recon"
export MOCK_LOG="$base/arguments.tsv"
bash "$script_dir/telegram-public-discovery.sh" --output "$base/results" sample topic >"$base/out"
# Exactly four independent search cohorts, no extra provider fanout by the wrapper.
[[ $(wc -l < "$MOCK_LOG") -eq 4 ]]
[[ $(wc -l < "$base/results/manifest.tsv") -eq 5 ]]
[[ $(awk -F '\t' '$2==3{n++} END{print n+0}' "$base/results/manifest.tsv") -eq 1 ]]
[[ $(awk -F '\t' '$2==65{n++} END{print n+0}' "$base/results/manifest.tsv") -eq 1 ]]
[[ -f "$base/results/telegram_public_channels.json" ]]
grep -q 'successful_searches=2' "$base/out"
[[ $(stat -c %a "$base/results") == 700 ]]
[[ $(stat -c %a "$base/results/manifest.tsv") == 600 ]]
# Bad input must fail before creating a case directory.
for input in $'bad\ninput' $'bad\tinput' 'bad"input' 'bad\input' "$(printf 'a%.0s' {1..121})" "$(printf 'é%.0s' {1..70})"; do
  if bash "$script_dir/telegram-public-discovery.sh" --output "$base/unsafe" "$input" > /dev/null 2>&1; then exit 1; fi
  [[ ! -e "$base/unsafe" ]]
done
# The full prior result must not be overwritten.
if bash "$script_dir/telegram-public-discovery.sh" --output "$base/results" repeat > /dev/null 2>&1; then exit 1; fi
[[ $(wc -l < "$base/results/manifest.tsv") -eq 5 ]]
# Invalid resource budgets fail closed without writing a case.
for bad in 0 121 garbage; do
  if HUNTSMAN_TELEGRAM_TIMEOUT_SECS=$bad bash "$script_dir/telegram-public-discovery.sh" --output "$base/invalid" test > /dev/null 2>&1; then exit 1; fi
  [[ ! -e "$base/invalid" ]]
done
# A failed cohort never counts as an answered source. All failures return nonzero.
if MOCK_ALL_FAIL=1 bash "$script_dir/telegram-public-discovery.sh" --output "$base/fail" test > /dev/null 2>&1; then exit 1; fi
[[ $(awk -F '\t' '$2==70{n++} END{print n+0}' "$base/fail/manifest.tsv") -eq 4 ]]
# Timeout is actually enforced against a hung local mock.
cat > "$base/hung" <<'HUNG'
#!/usr/bin/env bash
sleep 2
HUNG
chmod +x "$base/hung"
if HUNTSMAN_BIN="$base/hung" HUNTSMAN_TELEGRAM_TIMEOUT_SECS=1 \
   bash "$script_dir/telegram-public-discovery.sh" --output "$base/timed" test > /dev/null 2>&1; then exit 1; fi
[[ $(awk -F '\t' '$2==124{n++} END{print n+0}' "$base/timed/manifest.tsv") -eq 4 ]]
printf 'PASS: bounded queries, partial/empty responses, permissions, input/overwrite checks, invalid budgets, all-fail status, and timeout enforcement.\n'
