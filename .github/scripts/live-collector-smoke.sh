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
  "sw-btc|crypto 1111111111111111111114oLvT2"
  "sw-sol|crypto sol:11111111111111111111111111111111"
  "sw-geopoint|geocode -27.4698,153.0251"
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
    text = f.read_text(errors="replace")
    found = []
    for line in text.splitlines():
        # `module<TAB>status<TAB>` and `module.part<TAB>status<TAB>` (one leg of a module)
        m = re.match(r"^([a-z0-9_]+)(?:\.[a-z0-9_]+)?\t([a-z0-9_]+)\t", line)
        if m and m.group(1) in mods:
            found.append((*m.groups(), line))
        # web_query's per-engine lines: `engine=NAME<TAB>outcome=STATUS`
        m = re.match(r"^engine=([a-z0-9_]+)\toutcome=([a-z0-9_]+)", line)
        if m:
            found.append(("web_query", m.group(2), line))
            found.append(("engine:" + m.group(1), m.group(2), line))
    # JSON reports (public-osint): {"module": NAME, "kind": STATUS, ...} outcome objects
    for m in re.finditer(r'"module":\s*"([a-z0-9_]+)",\s*"kind":\s*"([a-z0-9_]+)"', text):
        found.append((*m.groups(), m.group(0)))
    for name, status, line in found:
        ok = status in ("success", "valid_zero")
        prev = seen.get(name)
        if prev is None or (ok and not prev[0]):
            seen[name] = (ok, status, f.stem, " ".join(line.split())[:140])
rows = ["module\tverdict\tstatus\tprobe\tevidence"]
passed = 0
for name in keyless:
    if name in seen:
        ok, status, probe, line = seen[name]
        passed += ok
        rows.append(f"{name}\t{'PASS' if ok else 'FAIL'}\t{status}\t{probe}\t{line}")
    else:
        rows.append(f"{name}\tNO-SIGNAL\t-\t-")
rows.append(f"# keyless networked modules live-PASS: {passed}/{len(keyless)}")
for name in sorted(n for n in seen if n not in keyless):
    ok, status, probe, line = seen[name]
    rows.append(f"extra:{name}\t{'PASS' if ok else 'FAIL'}\t{status}\t{probe}\t{line}")
(out / "sweep.tsv").write_text("\n".join(rows) + "\n")
print("\n".join(rows))
PY
for f in "$out"/sw-*.exit; do printf '%s exit=%s\n' "$(basename "${f%.exit}")" "$(cat "$f")"; done

# Serve over the network (loopback on the runner): health, modules, web page.
port=18087
"$bin" serve --bind "127.0.0.1:$port" > "$out/serve.log" 2>&1 &
serve_pid=$!
for _ in $(seq 1 50); do curl -fsS "http://127.0.0.1:$port/api/health" > /dev/null 2>&1 && break; sleep 0.2; done
# The web UI's own flows: every read endpoint the page calls (with its X-Huntsman-Lookup
# header), then a live username scan started the way the "Run Scan Now" form starts it, polled
# to completion, and each scan tab the page opens.
base="http://127.0.0.1:$port"
lookup='X-Huntsman-Lookup: 1'
ui_get() {
  printf '%s %s\n' "$1" "$(curl -sS -H "$lookup" -o /dev/null -w '%{http_code} %{size_download}B' "$base$1")"
}
{
  for path in /api/health /api/modules / /api/settings /api/settings/keys /api/scans \
    /api/scans/alerts /api/eventtypes /api/correlationrules /api/rhinser/catalog; do
    ui_get "$path"
  done
  scan="$(curl -sS -H "$lookup" -X POST \
    "$base/api/scans?target=octocat&name=octocat&kind=username&depth=0&usecase=all")"
  id="$(printf '%s' "$scan" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("id",""))' 2>/dev/null)"
  printf 'POST /api/scans %s\n' "${id:-NO-ID}"
  state=none
  if [ -n "$id" ]; then
    for _ in $(seq 1 120); do
      state="$(curl -sS -H "$lookup" "$base/api/scans/$id" | python3 -c 'import json,sys; d=json.load(sys.stdin); print(d.get("status"), d.get("elements"))' 2>/dev/null)"
      case "$state" in RUNNING*|STARTING*|CREATED*|None*|"") sleep 2 ;; *) break ;; esac
    done
    printf 'scan-state %s\n' "$state"
    for tab in "" /summary /elements /correlations /graph /log "/export?format=csv" \
      "/export?format=json" "/correlations?format=csv"; do
      ui_get "/api/scans/$id$tab"
    done
  fi
} > "$out/serve.tsv"
# Every UI request answered 200, the scan finished, and it holds more than its seed.
ui_ok=1
grep -vE '^(POST|scan-state) ' "$out/serve.tsv" | grep -vq ' 200 ' && ui_ok=0
grep -q '^POST /api/scans NO-ID' "$out/serve.tsv" && ui_ok=0
grep -qE '^scan-state FINISHED ([2-9]|[1-9][0-9]+)$' "$out/serve.tsv" || ui_ok=0
printf 'web-ui-flow %s\n' "$([ "$ui_ok" = 1 ] && echo PASS || echo FAIL)" >> "$out/serve.tsv"
kill "$serve_pid" 2>/dev/null
cat "$out/serve.tsv"
exit "$failed"
