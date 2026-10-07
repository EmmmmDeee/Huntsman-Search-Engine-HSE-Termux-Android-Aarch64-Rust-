#!/usr/bin/env bash
# scan-for-keys.sh <path>... : exit 1 if any file under <path> holds key-like content.
#
# Used by .github/workflows/release.yml on the exact release artifacts before
# anything is published: by the read-only `build` job from the checkout, and
# by the `publish` job from a byte-identical copy inlined in the workflow (that
# job checks out nothing; tests/release_ci.rs keeps the two copies equal).
# It reports only the file and the rule name. It never prints a matched value.
# Binaries are scanned through `strings -a -n 8`; text files are scanned as-is
# and also get a high-entropy check. Every failure mode exits non-zero: a
# missing tool, a missing path, an unreadable file, a broken rule or an
# entropy-check error is never reported as a clean scan.
set -uo pipefail

# Fail closed: without these the binary scan or the entropy check would
# silently find nothing.
for dep in strings python3 grep find sort cat mktemp; do
  command -v "$dep" >/dev/null 2>&1 || { echo "::error::scanner dependency missing: $dep"; exit 1; }
done
[ "$#" -gt 0 ] || { echo "::error::usage: scan-for-keys.sh <path>..."; exit 1; }
for p in "$@"; do
  [ -e "$p" ] || { echo "::error::scan path does not exist: $p"; exit 1; }
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
  # HIBP API keys are exactly 32 lowercase hex characters. The boundaries
  # (no hex character, of either case, on either side) exclude longer hex runs
  # such as 40-hex commit SHAs and 64-hex sha256 digests. A stripped release
  # binary built from main has no such run, so any hit fails the scan.
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

# Build and check the sorted file list before scanning anything, so a failing
# or truncating `find` or `sort` fails the scan (exit 2) instead of silently
# shortening it. Never read the list through a process substitution: its exit
# status would be lost.
list=$(mktemp) || { echo "::error::mktemp failed"; exit 2; }
sorted=$(mktemp) || { rm -f "$list"; echo "::error::mktemp failed"; exit 2; }
trap 'rm -f "$list" "$sorted"' EXIT
find "$@" -type f -print0 >"$list" || { echo "::error::find failed on: $*; refusing to scan a partial file list"; exit 2; }
sort -z "$list" >"$sorted" || { echo "::error::sort failed; refusing to scan a partial file list"; exit 2; }
mapfile -d '' -t found <"$list" || { echo "::error::cannot read the file list"; exit 2; }
mapfile -d '' -t files <"$sorted" || { echo "::error::cannot read the sorted file list"; exit 2; }
[ "${#files[@]}" -eq "${#found[@]}" ] \
  || { echo "::error::sort returned ${#files[@]} of ${#found[@]} files; refusing to scan a partial file list"; exit 2; }
[ "${#files[@]}" -gt 0 ] || { echo "::error::nothing scanned: no files under $*"; exit 2; }

scanned=0
for f in "${files[@]}"; do
  scanned=$((scanned + 1))
  if grep -Iq . "$f" 2>/dev/null; then
    text=1
    data=$(cat "$f") || { echo "::error::cannot read $f"; exit 1; }
  else
    text=0
    data=$(strings -a -n 8 "$f") || { echo "::error::strings failed on $f"; exit 1; }
  fi
  for rule in "${RULES[@]}"; do
    name=${rule%%    # SIGPIPE, which pipefail would turn into a silently missed finding.
    matches=$(grep -Eo -- "$re" <<<"$data")
    rc=$?
    [ "$rc" -le 1 ] || { echo "::error::rule $name failed (grep exit $rc)"; exit 1; }
    [ -n "$matches" ] || continue
    kept=$(grep -Ev -- "$ALLOW_RE" <<<"$matches")
    rc=$?
    [ "$rc" -le 1 ] || { echo "::error::allow filter failed for rule $name (grep exit $rc)"; exit 1; }
    [ -z "$kept" ] || report "$f" "$name"
  done
  if [ "$text" = 1 ]; then
    # Segments of 24+ chars mixing upper, lower and digits at >= 4.2 bits/char:
    # catches base64/alnum secrets, not paths, snake_case or hex digests.
    ent=$(python3 -c "$ENTROPY_PY" "$f") || { echo "::error::entropy check failed on $f"; exit 1; }
    while IFS= read -r line; do
      [ -n "$line" ] && report "$f" "high-entropy-string"
    done <<<"$ent"
  fi
done

echo "rules: ${#RULES[@]} pattern rules + high-entropy (text files)"
echo "files scanned: $scanned"
echo "key scan: $hits finding(s)"
[ "$scanned" -gt 0 ] || { echo "::error::nothing scanned"; exit 1; }
[ "$hits" -eq 0 ]
\t'*}
    re=${rule#*    # SIGPIPE, which pipefail would turn into a silently missed finding.
    matches=$(grep -Eo -- "$re" <<<"$data")
    rc=$?
    [ "$rc" -le 1 ] || { echo "::error::rule $name failed (grep exit $rc)"; exit 1; }
    [ -n "$matches" ] || continue
    kept=$(grep -Ev -- "$ALLOW_RE" <<<"$matches")
    rc=$?
    [ "$rc" -le 1 ] || { echo "::error::allow filter failed for rule $name (grep exit $rc)"; exit 1; }
    [ -z "$kept" ] || report "$f" "$name"
  done
  if [ "$text" = 1 ]; then
    # Segments of 24+ chars mixing upper, lower and digits at >= 4.2 bits/char:
    # catches base64/alnum secrets, not paths, snake_case or hex digests.
    ent=$(python3 -c "$ENTROPY_PY" "$f") || { echo "::error::entropy check failed on $f"; exit 1; }
    while IFS= read -r line; do
      [ -n "$line" ] && report "$f" "high-entropy-string"
    done <<<"$ent"
  fi
done

echo "rules: ${#RULES[@]} pattern rules + high-entropy (text files)"
echo "files scanned: $scanned"
echo "key scan: $hits finding(s)"
[ "$scanned" -gt 0 ] || { echo "::error::nothing scanned"; exit 1; }
[ "$hits" -eq 0 ]
\t'}
    # Generic bearer detection is intentionally text-only. In linked binaries,
    # `strings` can expose adjacent read-only literals as one printable run,
    # synthesising "Bearer <long-token>" even though no such runtime value
    # exists. Provider-specific token shapes and exact key rules still scan
    # binaries, while the build job separately proves credential-bearing build
    # inputs are absent.
    if [ "$text" = 0 ] && [ "$name" = "bearer-token" ]; then
      continue
    fi
    # Collect matches first: piping `grep -o` into `grep -q` can end in
    # SIGPIPE, which pipefail would turn into a silently missed finding.
    matches=$(grep -Eo -- "$re" <<<"$data")
    rc=$?
    [ "$rc" -le 1 ] || { echo "::error::rule $name failed (grep exit $rc)"; exit 1; }
    [ -n "$matches" ] || continue
    kept=$(grep -Ev -- "$ALLOW_RE" <<<"$matches")
    rc=$?
    [ "$rc" -le 1 ] || { echo "::error::allow filter failed for rule $name (grep exit $rc)"; exit 1; }
    [ -z "$kept" ] || report "$f" "$name"
  done
  if [ "$text" = 1 ]; then
    # Segments of 24+ chars mixing upper, lower and digits at >= 4.2 bits/char:
    # catches base64/alnum secrets, not paths, snake_case or hex digests.
    ent=$(python3 -c "$ENTROPY_PY" "$f") || { echo "::error::entropy check failed on $f"; exit 1; }
    while IFS= read -r line; do
      [ -n "$line" ] && report "$f" "high-entropy-string"
    done <<<"$ent"
  fi
done

echo "rules: ${#RULES[@]} pattern rules + high-entropy (text files)"
echo "files scanned: $scanned"
echo "key scan: $hits finding(s)"
[ "$scanned" -gt 0 ] || { echo "::error::nothing scanned"; exit 1; }
[ "$hits" -eq 0 ]
