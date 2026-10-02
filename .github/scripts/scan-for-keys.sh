#!/usr/bin/env bash
# scan-for-keys.sh <path>... : exit 1 if any file under <path> holds key-like content.
#
# Used by .github/workflows/release.yml on the exact release artifacts before
# anything is published. It reports only the file and the rule name. It never
# prints a matched value. Binaries are scanned through `strings -a -n 8`; text
# files are scanned as-is and also get a high-entropy check.
set -uo pipefail

# Fail closed: without these the binary scan or the entropy check would
# silently find nothing.
for dep in strings python3 grep find; do
  command -v "$dep" >/dev/null 2>&1 || { echo "::error::scanner dependency missing: $dep"; exit 1; }
done

hits=0
report() {
  echo "FINDING file=$1 rule=$2 (value withheld)"
  echo "::error file=$1::key-like content ($2), value withheld"
  hits=$((hits + 1))
}

# name<TAB>ERE. Known provider token shapes.
RULES=(
  $'openai-style-sk\t(^|[^A-Za-z0-9_-])sk-[A-Za-z0-9_-]{20,}'
  $'anthropic\tsk-ant-[A-Za-z0-9_-]{20,}'
  $'google-api-key\tAIza[0-9A-Za-z_-]{35}'
  $'github-token\tgh[pousr]_[A-Za-z0-9]{36,}'
  $'github-pat\tgithub_pat_[A-Za-z0-9_]{60,}'
  $'slack-token\txox[abprs]-[A-Za-z0-9-]{10,}'
  $'aws-access-key-id\tAKIA[0-9A-Z]{16}'
  $'private-key-block\t-----BEGIN [A-Z ]*PRIVATE KEY-----'
  $'bearer-token\t[Bb]earer [A-Za-z0-9._~+/-]{24,}'
  # HIBP API keys are 32 lowercase hex. The boundaries exclude longer hex runs
  # (40-hex commit SHAs, 64-hex sha256 digests). A stripped release binary has
  # no 32-hex runs, so any hit is treated as an embedded key.
  $'hibp-key-hex\t(^|[^0-9a-fA-F])[0-9a-f]{32}([^0-9a-fA-F]|$)'
  # Credential variable names carrying a non-placeholder value.
  $'credential-assignment\t(HUNTSMAN_[A-Z0-9_]*|HIBP_[A-Z0-9_]*)(KEY|TOKEN|SECRET)["'"'"' ]*[:=]["'"'"' ]*[A-Za-z0-9_./+-]{12,}'
)
ALLOW_RE='insert_[a-z0-9_]+_here|AKIAIOSFODNN7EXAMPLE|<value>|\$\{?[A-Z_]+'

ENTROPY_PY='
import collections, math, re, sys
txt = open(sys.argv[1], errors="ignore").read()
for seg in set(re.findall(r"[A-Za-z0-9+]{24,}", txt)):
    if not (re.search(r"[A-Z]", seg) and re.search(r"[a-z]", seg) and re.search(r"[0-9]", seg)):
        continue
    c = collections.Counter(seg); n = len(seg)
    if -sum(v / n * math.log2(v / n) for v in c.values()) >= 4.2:
        print("hit")
'

scanned=0
while IFS= read -r -d '' f; do
  scanned=$((scanned + 1))
  if grep -Iq . "$f" 2>/dev/null; then
    text=1
    data=$(cat "$f") || { echo "::error::cannot read $f"; exit 1; }
  else
    text=0
    data=$(strings -a -n 8 "$f") || { echo "::error::strings failed on $f"; exit 1; }
  fi
  for rule in "${RULES[@]}"; do
    name=${rule%%$'\t'*}
    re=${rule#*$'\t'}
    if grep -Eo -- "$re" <<<"$data" | grep -Evq -- "$ALLOW_RE"; then report "$f" "$name"; fi
  done
  if [ "$text" = 1 ]; then
    # Segments of 24+ chars mixing upper, lower and digits at >= 4.2 bits/char:
    # catches base64/alnum secrets, not paths, snake_case or hex digests.
    ent=$(python3 -c "$ENTROPY_PY" "$f") || { echo "::error::entropy check failed on $f"; exit 1; }
    while IFS= read -r line; do
      [ -n "$line" ] && report "$f" "high-entropy-string"
    done <<<"$ent"
  fi
done < <(find "$@" -type f -print0 2>/dev/null | sort -z)

echo "rules: ${#RULES[@]} pattern rules + high-entropy (text files)"
echo "files scanned: $scanned"
echo "key scan: $hits finding(s)"
[ "$scanned" -gt 0 ] || { echo "::error::nothing scanned"; exit 1; }
[ "$hits" -eq 0 ]
