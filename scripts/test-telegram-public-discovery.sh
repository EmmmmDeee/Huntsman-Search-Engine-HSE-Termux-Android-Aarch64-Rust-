#!/usr/bin/env bash
set -euo pipefail
script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
base=$(mktemp -d)
trap 'rm -rf -- "$base"' EXIT
cat > "$base/huntsman-recon" <<'MOCK'
#!/usr/bin/env bash
printf '%s\t%s\t%s\n' "${1-}" "${2-}" "${3-}" >> "$MOCK_LOG"
printf '{"query":"test","entities":[],"outcomes":[]}\n'
[[ "${3-}" != 'site:tgstat.com sample topic' ]]
MOCK
chmod +x "$base/huntsman-recon"
export HUNTSMAN_BIN="$base/huntsman-recon"
export MOCK_LOG="$base/arguments.tsv"
bash "$script_dir/telegram-public-discovery.sh" --output "$base/results" sample topic >"$base/out"
[[ $(wc -l < "$MOCK_LOG") -eq 4 ]]
[[ $(wc -l < "$base/results/manifest.tsv") -eq 5 ]]
[[ $(awk -F '\t' '$2==1{n++} END{print n+0}' "$base/results/manifest.tsv") -eq 1 ]]
[[ -f "$base/results/telegram_public_channels.json" ]]
[[ $(stat -c %a "$base/results") == 700 ]]
[[ $(stat -c %a "$base/results/manifest.tsv") == 600 ]]
if bash "$script_dir/telegram-public-discovery.sh" --output "$base/unsafe" $'bad\ninput' > /dev/null 2>&1; then exit 1; fi
[[ ! -e "$base/unsafe" ]]
if bash "$script_dir/telegram-public-discovery.sh" --output "$base/unsafe2" 'bad"input' > /dev/null 2>&1; then exit 1; fi
[[ ! -e "$base/unsafe2" ]]
if bash "$script_dir/telegram-public-discovery.sh" --output "$base/unsafe3" "$(printf 'a%.0s' {1..121})" > /dev/null 2>&1; then exit 1; fi
[[ ! -e "$base/unsafe3" ]]
if bash "$script_dir/telegram-public-discovery.sh" --output "$base/unsafe4" "$(printf 'é%.0s' {1..70})" > /dev/null 2>&1; then exit 1; fi
[[ ! -e "$base/unsafe4" ]]
if bash "$script_dir/telegram-public-discovery.sh" --output "$base/results" repeat > /dev/null 2>&1; then exit 1; fi
printf '6 checks passed (bounded fanout, partial failure, provenance manifest, permissions, input rejection, existing-dir refusal).\n'
