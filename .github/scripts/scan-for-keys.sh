#!/usr/bin/env bash
# scan-for-keys.sh <path>... : exit 1 if any file under <path> holds key-like content.
#
# Exit status: 0 clean; 1 a finding, a missing tool or path, or an unreadable
# file; 2 the file list cannot be trusted (find or sort failed, sort dropped,
# added or rewrote an entry, a symlink is broken, loops or resolves outside
# the scanned roots, an entry is a fifo, socket or device, or there is nothing
# to scan). Symlinks inside the roots are followed; see "Symlinks" below.
#
# Used by .github/workflows/release.yml on the exact release artifacts before
# anything is published: by the read-only `build` job from the checkout, and
# by the `publish` job from a byte-identical copy inlined in the workflow (that
# job checks out nothing; tests/release_ci.rs keeps the two copies equal).
# It reports the file (as walked and as resolved) and the rule name only. It
# never prints a matched value.
# Binaries are scanned through `strings -a -n 8` plus `strings -a -e l -n 8`
# (UTF-16LE); text files are scanned as-is and also get a high-entropy check.
# Every failure mode exits non-zero: a missing tool, a missing path, an
# unreadable file, a broken rule or an entropy-check error is never reported
# as a clean scan.
set -uo pipefail
# Byte-wise matching and sort order: in a UTF-8 locale a bracket expression
# such as [^0-9a-fA-F] does not match an invalid byte (e.g. \xff), so a key
# next to one would be missed.
export LC_ALL=C

# Fail closed: without these the binary scan or the entropy check would
# silently find nothing.
for dep in strings python3 grep find sort cat mktemp realpath; do
  command -v "$dep" >/dev/null 2>&1 || { echo "::error::scanner dependency missing: $dep"; exit 1; }
done
[ "$#" -gt 0 ] || { echo "::error::usage: scan-for-keys.sh <path>..."; exit 1; }
for p in "$@"; do
  [ -e "$p" ] || [ -L "$p" ] || { echo "::error::scan path does not exist: $p"; exit 1; }
done

hits=0
# report <reported path> <rule> <resolved path that was read>
report() {
  echo "FINDING file=$1 resolved=$3 rule=$2 (value withheld)"
  echo "::error file=$1::key-like content ($2) in $3, value withheld"
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
  # HIBP API keys are 32 lowercase hex characters. This matches every maximal
  # hex run (either case) of 32+ characters; hex_runs() below keeps a run only
  # if its length is not exactly 40 (git SHA-1) or 64 (sha256) and it holds 32
  # lowercase hex characters in a row. So a key packed next to other hex (e.g.
  # right after "password", which ends in "d") is still caught.
  $'hibp-key-hex\t[0-9a-fA-F]{32,}'
  # Credential variable names carrying a non-placeholder value.
  $'credential-assignment\t(HUNTSMAN_[A-Z0-9_]*|HIBP_[A-Z0-9_]*)(KEY|TOKEN|SECRET)["'"'"' ]*[:=]["'"'"' ]*[A-Za-z0-9_./+-]{12,}'
)
ALLOW_RE='insert_[a-z0-9_]+_here|AKIAIOSFODNN7EXAMPLE|<value>|\$\{?[A-Z_]+'

# Filters hibp-key-hex matches (one maximal hex run per line) down to
# key-like runs. Two lookup tables that std links into every Rust binary are
# not keys and are skipped: all-digit runs (decimal formatting tables; a random
# 32-hex key has no letter with probability (10/16)^32, about 3e-7) and the
# 00..ff hex byte table or any part of it.
hex_table=""
for ((i = 0; i < 256; i++)); do printf -v b '%02x' "$i"; hex_table+=$b; done
hex_runs() {
  local m
  while IFS= read -r m; do
    case ${#m} in 40 | 64) continue ;; esac
    [[ $m =~ [0-9a-f]{32} ]] || continue
    [[ $m =~ [a-f] ]] || continue
    [[ $hex_table == *"$m"* ]] && continue
    printf '%s\n' "$m"
  done
}

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

# Symlinks. Rule: a link that resolves (`realpath -e`) to a file or directory
# inside a scanned root is followed and its target is scanned; a broken or
# looping link, or one that resolves outside every root, exits 2 and is named.
# Inside means target == root, or target starts with root + "/" (whole path
# segments: /a/root-evil is not inside /a/root); a root of / holds everything.
# A scan path that is itself a symlink is resolved first, and its target is
# the root; a broken or looping one exits 2.
#
# Order matters: links are listed and checked WITHOUT following them
# (`find -P`) before the followed walk (`find -L`) runs, so a link to /, $HOME
# or /proc is refused before it can take the walk outside the artifact or
# hang it. Paths travel NUL-separated end to end (`realpath -z`, `read -d ''`,
# `mapfile -d ''`), never through a command substitution, so a trailing
# newline in a name survives.
list=$(mktemp) || { echo "::error::mktemp failed"; exit 2; }
sorted=$(mktemp) || { rm -f "$list"; echo "::error::mktemp failed"; exit 2; }
other=$(mktemp) || { rm -f "$list" "$sorted"; echo "::error::mktemp failed"; exit 2; }
res=$(mktemp) || { rm -f "$list" "$sorted" "$other"; echo "::error::mktemp failed"; exit 2; }
trap 'rm -f "$list" "$sorted" "$other" "$res"' EXIT

roots=()
walk=()
for p in "$@"; do
  if ! { realpath -e -z -- "$p" >"$res" 2>/dev/null && IFS= read -r -d '' r <"$res"; }; then
    echo "::error::cannot resolve scan path $p (broken or looping symlink?); refusing"; exit 2
  fi
  roots+=("$r")
  # Walk a symlinked scan path through its resolved target. A relative path
  # starting with "-" gets "./" before any find call (the -P pre-check and the
  # -L walk), so find never parses it as an option: a root named -L, -H or -P
  # would otherwise switch find's link mode and make it walk "." instead.
  if [ -L "$p" ]; then w=$r; else w=$p; fi
  case $w in -*) w=./$w ;; esac
  walk+=("$w")
done
inside_roots() {
  local r
  for r in "${roots[@]}"; do
    if [ "$r" = / ] || [ "$1" = "$r" ] || [ "${1#"$r"/}" != "$1" ]; then return 0; fi
  done
  return 1
}

# Pre-check, nothing followed: fifos, sockets and devices are refused, and
# every link must resolve to a file or directory inside the roots.
find -P "${walk[@]}" ! -type f ! -type d ! -type l -print0 >"$other" \
  || { echo "::error::find failed on: $*; refusing to scan a partial file list"; exit 2; }
mapfile -d '' -t odd <"$other" || { echo "::error::cannot read the non-regular entry list"; exit 2; }
for o in "${odd[@]}"; do
  echo "::error file=$o::not a regular file, directory or symlink (fifo, socket or device); refusing to skip it unscanned"
  exit 2
done
find -P "${walk[@]}" -type l -print0 >"$other" \
  || { echo "::error::find failed on: $*; refusing to scan a partial file list"; exit 2; }
mapfile -d '' -t links <"$other" || { echo "::error::cannot read the symlink list"; exit 2; }
for l in "${links[@]}"; do
  if ! { realpath -e -z -- "$l" >"$res" 2>/dev/null && IFS= read -r -d '' t <"$res"; }; then
    echo "::error file=$l::broken or looping symlink; refusing to skip it unscanned"; exit 2
  fi
  inside_roots "$t" || { echo "::error file=$l::symlink resolves outside the scanned roots; refusing to follow it"; exit 2; }
  [ -f "$t" ] || [ -d "$t" ] \
    || { echo "::error file=$l::symlink target is not a regular file or directory; refusing to skip it unscanned"; exit 2; }
done
[ "${#links[@]}" -eq 0 ] || echo "symlinks: ${#links[@]}, all inside the scanned roots; following them"

# Build and check the sorted file list before scanning anything, so a failing,
# truncating or rewriting `find` or `sort` fails the scan (exit 2) instead of
# silently shortening it. Never read the list through a process substitution
# or a pipe: its exit status would be lost. The loop below runs over the
# checked array only. `find -L` reports a directory link back into its own
# ancestor as a filesystem loop and fails, which exits 2 here. Under -L only
# a dangling link is still -type l; it is listed so that it exits 2 below.
find -L "${walk[@]}" \( -type f -o -type l \) -print0 >"$list" || { echo "::error::find failed on: $*; refusing to scan a partial file list"; exit 2; }
sort -z "$list" >"$sorted" || { echo "::error::sort failed; refusing to scan a partial file list"; exit 2; }
mapfile -d '' -t found <"$list" || { echo "::error::cannot read the file list"; exit 2; }
mapfile -d '' -t files <"$sorted" || { echo "::error::cannot read the sorted file list"; exit 2; }
[ "${#files[@]}" -eq "${#found[@]}" ] \
  || { echo "::error::sort returned ${#files[@]} of ${#found[@]} files; refusing to scan a partial file list"; exit 2; }
# Equal counts are not enough: a sort that swaps one name for a duplicate of
# another keeps the count. Require `files` to be a permutation of `found`.
declare -A in_found=() in_files=()
for f in "${found[@]}"; do in_found["$f"]=1; done
for f in "${files[@]}"; do in_files["$f"]=1; done
for f in "${found[@]}"; do
  [ -n "${in_files["$f"]+x}" ] || { echo "::error::sort dropped or rewrote a listed file; refusing to scan a tampered file list"; exit 2; }
done
for f in "${files[@]}"; do
  [ -n "${in_found["$f"]+x}" ] || { echo "::error::sort returned a file find did not list; refusing to scan a tampered file list"; exit 2; }
done
[ "${#files[@]}" -gt 0 ] || { echo "::error::nothing scanned: no files under $*"; exit 2; }

# Re-check every file's resolved path (a link may have changed since the
# pre-check), and scan each real file once however many links reach it, so
# one token is one finding.
for f in "${files[@]}"; do
  if [ -L "$f" ] && [ ! -e "$f" ]; then echo "::error file=$f::broken symlink; refusing to skip it unscanned"; exit 2; fi
done
realpath -e -z -- "${files[@]}" >"$res" || { echo "::error::cannot resolve the file list; refusing"; exit 2; }
mapfile -d '' -t real <"$res" || { echo "::error::cannot read the resolved file list"; exit 2; }
[ "${#real[@]}" -eq "${#files[@]}" ] || { echo "::error::realpath returned ${#real[@]} of ${#files[@]} paths; refusing"; exit 2; }
# A real file is reported under its own path (no symlink in it) when the walk
# reached it that way too, else under the first path that reached it.
realpath -s -z -- "${files[@]}" >"$res" || { echo "::error::cannot absolutize the file list; refusing"; exit 2; }
mapfile -d '' -t plain <"$res" || { echo "::error::cannot read the absolutized file list"; exit 2; }
[ "${#plain[@]}" -eq "${#files[@]}" ] || { echo "::error::realpath -s returned ${#plain[@]} of ${#files[@]} paths; refusing"; exit 2; }
declare -A direct=() seen=() src_of=()
for i in "${!files[@]}"; do
  inside_roots "${real[$i]}" || { echo "::error file=${files[$i]}::resolves outside the scanned roots; refusing"; exit 2; }
  [ "${plain[$i]}" != "${real[$i]}" ] || direct["${real[$i]}"]=1
done
unique=()
for i in "${!files[@]}"; do
  if [ "${plain[$i]}" != "${real[$i]}" ] && [ -n "${direct["${real[$i]}"]+x}" ]; then continue; fi
  [ -z "${seen["${real[$i]}"]+x}" ] || continue
  seen["${real[$i]}"]=1
  unique+=("${files[$i]}")
  src_of["${files[$i]}"]=${real[$i]}
done
[ "${#unique[@]}" -eq "${#files[@]}" ] || echo "files reached by more than one path: scanning each once (${#unique[@]} of ${#files[@]})"
files=("${unique[@]}")

scanned=0
for f in "${files[@]}"; do
  scanned=$((scanned + 1))
  # Read only through the resolved path, re-checked right before the read: a
  # link swapped since the checks above is still never read outside the roots.
  src=${src_of["$f"]}
  if ! { realpath -e -z -- "$f" >"$res" 2>/dev/null && IFS= read -r -d '' now <"$res"; } \
    || [ "$now" != "$src" ] || ! inside_roots "$src" || [ ! -f "$src" ]; then
    echo "::error file=$f::changed or resolves outside the scanned roots since it was checked; refusing"; exit 2
  fi
  if grep -Iq . "$src" 2>/dev/null; then
    text=1
    data=$(cat -- "$src") || { echo "::error::cannot read $f"; exit 1; }
  else
    text=0
    data=$(strings -a -n 8 -- "$src") || { echo "::error::strings failed on $f"; exit 1; }
    # Second pass for UTF-16LE strings (e.g. wide-char literals), which the
    # 8-bit pass above never sees.
    wide=$(strings -a -e l -n 8 -- "$src") || { echo "::error::strings -e l failed on $f"; exit 1; }
    data+=$'\n'"$wide"
  fi
  for rule in "${RULES[@]}"; do
    name=${rule%%$'\t'*}
    re=${rule#*$'\t'}
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
    if [ "$name" = hibp-key-hex ]; then
      matches=$(hex_runs <<<"$matches")
      [ -n "$matches" ] || continue
    fi
    kept=$(grep -Ev -- "$ALLOW_RE" <<<"$matches")
    rc=$?
    [ "$rc" -le 1 ] || { echo "::error::allow filter failed for rule $name (grep exit $rc)"; exit 1; }
    [ -z "$kept" ] || report "$f" "$name" "$src"
  done
  if [ "$text" = 1 ]; then
    # Segments of 24+ chars mixing upper, lower and digits at >= 4.2 bits/char:
    # catches base64/alnum secrets, not paths, snake_case or hex digests.
    ent=$(python3 -c "$ENTROPY_PY" "$src") || { echo "::error::entropy check failed on $f"; exit 1; }
    while IFS= read -r line; do
      [ -n "$line" ] && report "$f" "high-entropy-string" "$src"
    done <<<"$ent"
  fi
done

echo "rules: ${#RULES[@]} pattern rules + high-entropy (text files)"
echo "files scanned: $scanned"
echo "key scan: $hits finding(s)"
[ "$scanned" -gt 0 ] || { echo "::error::nothing scanned"; exit 1; }
[ "$hits" -eq 0 ]
