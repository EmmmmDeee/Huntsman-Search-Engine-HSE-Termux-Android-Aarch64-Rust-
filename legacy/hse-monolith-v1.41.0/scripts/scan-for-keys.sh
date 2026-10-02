#!/usr/bin/env bash
# scan-for-keys.sh <path>... — fail (exit 1) if any artifact or log contains a key-like string.
# Used by main-build.yml after the build. It reports only the location and rule; it never prints the matched value.
set -uo pipefail
hits=0
report() { echo "::error file=$1::key-like content ($2) — value withheld"; hits=$((hits+1)); }
# 1) Known provider token shapes.
PATTERNS=(
  '(^|[^A-Za-z0-9_-])sk-[A-Za-z0-9_-]{20,}'  # OpenAI-style (word boundary: not 'xtask-sdk-…')
  'sk-ant-[A-Za-z0-9_-]{20,}'        # Anthropic
  'AIza[0-9A-Za-z_-]{35}'            # Google API key
  'gh[pousr]_[A-Za-z0-9]{36,}'       # GitHub tokens
  'github_pat_[A-Za-z0-9_]{60,}'
  'xox[abprs]-[A-Za-z0-9-]{10,}'     # Slack
  'AKIA[0-9A-Z]{16}'                 # AWS access key id
  '-----BEGIN [A-Z ]*PRIVATE KEY-----'
)
# 2) Known HSE credential variable names, but only when they carry a non-placeholder value.
NAME_RE='HUNTSMAN_[A-Z0-9_]*(KEY|TOKEN|SECRET|USER|ID|GUID)[\"'"'"' ]*[:=][\"'"'"' ]*[A-Za-z0-9_./+-]{12,}'
ALLOW_RE='insert_[a-z0-9_]+_here|AKIAIOSFODNN7EXAMPLE|<value>|\$\{?[A-Z_]+'
for f in $(find "$@" -type f 2>/dev/null); do
  # binaries: scan the printable strings; text: scan as-is
  if grep -Iq . "$f" 2>/dev/null; then src=(cat "$f"); else src=(strings -n 8 "$f"); fi
  data=$("${src[@]}" 2>/dev/null)
  for p in "${PATTERNS[@]}"; do
    if grep -Eo -- "$p" <<<"$data" | grep -Evq -- "$ALLOW_RE"; then report "$f" "$p"; fi
  done
  if grep -Eo -- "$NAME_RE" <<<"$data" | grep -Evq -- "$ALLOW_RE"; then report "$f" "HUNTSMAN_* credential assignment"; fi
  # 3) Value digests of the credentials that earlier builds shipped (src/util/keys/constants.rs COMPROMISED_EMBEDDED_DIGESTS):
  #    a regression that re-embeds one shows up as its digest. (Done in the cargo test
  #    `no_credential_is_embedded_in_the_build`; here we add a high-entropy heuristic for text logs/artifacts only.)
  if grep -Iq . "$f" 2>/dev/null; then
    # Split on path/identifier separators and score each segment of 24+ chars that mixes upper,
    # lower and digits at >= 4.2 bits/char. That catches base64/alnum secrets but not paths, snake_case or hex digests.
    while read -r ent; do report "$f" "high-entropy string (H=$ent)"; done < <(python3 - "$f" <<'PY2'
import math,re,sys,collections
txt=open(sys.argv[1],errors="ignore").read()
for seg in set(re.findall(r"[A-Za-z0-9+]{24,}", txt)):
    if not (re.search(r"[A-Z]",seg) and re.search(r"[a-z]",seg) and re.search(r"[0-9]",seg)): continue
    c=collections.Counter(seg); n=len(seg); h=-sum(v/n*math.log2(v/n) for v in c.values())
    if h>=4.2: print(f"{h:.2f}")
PY2
)
  fi
done
echo "key scan: $hits finding(s)"
[ "$hits" -eq 0 ]
