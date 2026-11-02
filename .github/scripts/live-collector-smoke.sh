#!/usr/bin/env bash
# Live smoke of the keyless username/people collectors against their real public hosts.
# Usage: live-collector-smoke.sh BINARY OUTDIR
# Read-only: every probe is a keyless public lookup of a long-standing public account or record.
# It never reads a key file or a secret; HIBP_API_KEY and every HUNTSMAN_* override are unset.
# Writes OUTDIR/<probe>.out (stdout+stderr), OUTDIR/<probe>.exit and OUTDIR/verdict.tsv:
#   module  probe  verdict(PASS|FAIL)  evidence
# Exit status: 0 when every expected module is PASS, 1 otherwise.
set -uo pipefail
bin="${1:?binary}"
out="${2:?output directory}"
mkdir -p "$out"
unset HIBP_API_KEY
while IFS='=' read -r name _; do
  case "$name" in HUNTSMAN_*) unset "$name" ;; esac
done < <(env)

# probe-id|command line|source module (exact tab-delimited rows only)
probes=(
  "user-dtolnay|username dtolnay|github_user"
  "user-dtolnay|username dtolnay|crates_io"
  "user-pg|username pg|hacker_news"
  "user-jcs|username jcs|lobsters"
  "user-torvalds|username torvalds|docker_hub_user"
  "wikidata-q42|wikidata Q42|wikidata"
  "asn-13335|asn 13335|peeringdb"
)

printf 'module\tprobe\tverdict\tevidence\n' > "$out/verdict.tsv"
failed=0
tab="$(printf '\t')"
for row in "${probes[@]}"; do
  IFS='|' read -r id cmd module <<< "$row"
  if [ ! -e "$out/$id.exit" ]; then
    # shellcheck disable=SC2086 # the probe's words are its arguments
    timeout 180 "$bin" $cmd > "$out/$id.out" 2>&1
    echo "$?" > "$out/$id.exit"
  fi
  code="$(cat "$out/$id.exit")"
  # Match actual tab-delimited fields; grep -E "\\t" is not a portable tab match.
  line="$(awk -F "$tab" -v wanted="$module" '$1 == wanted && $2 == "success" { print; exit }' "$out/$id.out" | cut -c1-160)"
  if [ "$code" = "0" ] && [ -n "$line" ]; then
    verdict=PASS
  else
    verdict=FAIL
    failed=1
    line="$(awk -F "$tab" -v wanted="$module" '$1 == wanted { print; exit }' "$out/$id.out" | cut -c1-160)"
    [ -n "$line" ] || line="$(head -c 160 "$out/$id.out" | tr '\n\t' '  ')"
  fi
  printf '%s\t%s\t%s\texit=%s %s\n' "$module" "$id" "$verdict" "$code" "$line" >> "$out/verdict.tsv"
done
cat "$out/verdict.tsv"

# Sweep: every keyless networked command, report-only. Each per-module status line
# (`module<TAB>status<TAB>...`) is matched against `modules --json`; a module is PASS when a
# provider answered (success or valid_zero), otherwise the status it reported.
sweep=(
  "sw-user-octocat|username octocat"
  "sw-people|people Douglas Adams"
  "sw-domain|domain example.com"
  "sw-ip|ip 1.1.1.1"
  "sw-email|email test@example.com"
  "sw-netblock|netblock 1.1.1.0/24"
  "sw-btc|crypto 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
  "sw-eth|crypto eth:0xde0B295669a9FD93d5F28D9Ec85E40f4cb697BAe"
  "sw-sol|crypto sol:11111111111111111111111111111111"
  "sw-geocode|geocode Brisbane"
  "sw-gleif|gleif Apple Inc"
  "sw-itunes|itunes huntsman"
  "sw-query|query huntsman spider"
  "sw-crtsh|recon crtsh example.com"
  "sw-dns|recon dns example.com"
  "sw-osint-web|public-osint web huntsman spider"
  "sw-osint-news|public-osint news huntsman spider"
)
for row in "${sweep[@]}"; do
  IFS='|' read -r id cmd <<< "$row"
  # shellcheck disable=SC2086 # the probe's words are its arguments
  timeout 240 "$bin" $cmd > "$out/$id.out" 2>&1
  echo "$?" > "$out/$id.exit"
done
"$bin" modules --json > "$out/modules.json"
python3 - "$out" <<'PY'
import json, pathlib, re, sys
out = pathlib.Path(sys.argv[1])
mods = {m["name"]: m for m in json.loads((out / "modules.json").read_text())["modules"]}
keyless = sorted(n for n, m in mods.items() if m["network"] and m["access"] == "keyless")
seen = {}
for f in sorted(out.glob("*.out")):
    for line in f.read_text(errors="replace").splitlines():
        m = re.match(r"^([a-z0-9_]+)\t([a-z_]+)\t", line)
        if m and m.group(1) in mods:
            name, status = m.groups()
            ok = status in ("success", "valid_zero")
            prev = seen.get(name)
            if prev is None or (ok and not prev[0]):
                seen[name] = (ok, status, f.stem)
rows = ["module\tverdict\tstatus\tprobe"]
passed = 0
for name in keyless:
    if name in seen:
        ok, status, probe = seen[name]
        passed += ok
        rows.append(f"{name}\t{'PASS' if ok else 'FAIL'}\t{status}\t{probe}")
    else:
        rows.append(f"{name}\tNO-SIGNAL\t-\t-")
rows.append(f"# keyless networked modules live-PASS: {passed}/{len(keyless)}")
(out / "sweep.tsv").write_text("\n".join(rows) + "\n")
print("\n".join(rows))
PY
for f in "$out"/sw-*.exit; do printf '%s exit=%s\n' "$(basename "${f%.exit}")" "$(cat "$f")"; done

# Serve over the network (loopback on the runner): health, modules, web page.
port=18087
"$bin" serve --bind "127.0.0.1:$port" > "$out/serve.log" 2>&1 &
serve_pid=$!
for _ in $(seq 1 50); do curl -fsS "http://127.0.0.1:$port/api/health" > /dev/null 2>&1 && break; sleep 0.2; done
{
  for path in /api/health /api/modules /; do
    printf '%s %s\n' "$path" "$(curl -sS -o /dev/null -w '%{http_code} %{size_download}B' "http://127.0.0.1:$port$path")"
  done
} > "$out/serve.tsv"
kill "$serve_pid" 2>/dev/null
cat "$out/serve.tsv"
exit "$failed"
