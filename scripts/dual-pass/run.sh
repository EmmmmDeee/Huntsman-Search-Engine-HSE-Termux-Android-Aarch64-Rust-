#!/usr/bin/env bash
# Dual-pass runner. Pass 1 writes execution-plan.json. Pass 2 is red-then-green.
# Existing tests, lockfile, and release workflows are restored if mutated.
set -Eeuo pipefail
IFS=$'\n\t'

: "${ISSUE_NUMBER:?issue number required}"
: "${REPO:?owner/repo required}"
MAX_TURNS=3
WORKDIR="$(pwd)"
REPORT="$WORKDIR/dual-pass-report.md"
PLAN="$WORKDIR/execution-plan.json"

log() { printf '%s\n' "$*"; }

fail_human() {
  local reason="$1"
  log "needs-human-review: $reason"
  git checkout -B "dual-pass/issue-${ISSUE_NUMBER}-wip"
  git add -A
  git -c user.email="41898282+github-actions[bot]@users.noreply.github.com" \
    -c user.name="github-actions[bot]" \
    commit -m "dual-pass WIP for issue ${ISSUE_NUMBER}" --allow-empty
  git push -u origin "dual-pass/issue-${ISSUE_NUMBER}-wip" --force-with-lease
  gh label create needs-human-review --repo "$REPO" --color B60205 --description "Dual-pass budget exhausted" 2>/dev/null || true
  gh issue edit "$ISSUE_NUMBER" --repo "$REPO" --add-label needs-human-review
  gh issue comment "$ISSUE_NUMBER" --repo "$REPO" --body "$(printf '%s\n\n```\n%s\n```\n' "$reason" "$(tail -n 80 "$REPORT" 2>/dev/null || true)")"
  exit 1
}

snapshot() {
  mkdir -p .dual-pass-base
  git ls-files tests Cargo.toml Cargo.lock .github/workflows/ci.yml .github/workflows/release.yml \
    | while read -r f; do
        mkdir -p ".dual-pass-base/$(dirname "$f")"
        cp "$f" ".dual-pass-base/$f"
      done
}

restore_protected() {
  local f rel src
  if [[ -d .dual-pass-base/tests ]]; then
    find .dual-pass-base/tests -type f | while read -r src; do
      rel="${src#.dual-pass-base/}"
      mkdir -p "$(dirname "$rel")"
      cp "$src" "$rel"
    done
  fi
  for f in Cargo.toml Cargo.lock .github/workflows/ci.yml .github/workflows/release.yml; do
    if [[ -f ".dual-pass-base/$f" ]]; then
      cp ".dual-pass-base/$f" "$f"
    fi
  done
}

ask() {
  local body="$1"
  if [[ -z "${XAI_API_KEY:-}" ]]; then
    fail_human "XAI_API_KEY secret is not set; pass 1 cannot run"
  fi
  python3 - "$body" <<'PY'
import json, os, sys, urllib.request
body = sys.argv[1]
payload = {
  "model": os.environ.get("XAI_MODEL", "grok-4"),
  "temperature": 0,
  "messages": [
    {"role": "system", "content": open("scripts/dual-pass/static-context.md", encoding="utf-8").read()},
    {"role": "user", "content": body},
  ],
}
req = urllib.request.Request(
  "https://api.x.ai/v1/chat/completions",
  data=json.dumps(payload).encode(),
  headers={"Authorization": "Bearer " + os.environ["XAI_API_KEY"], "Content-Type": "application/json"},
)
with urllib.request.urlopen(req, timeout=120) as resp:
    data = json.load(resp)
print(data["choices"][0]["message"]["content"])
PY
}

extract_json() {
  python3 -c 'import json,re,sys; t=sys.stdin.read();
m=re.search(r"\{[\s\S]*\}\s*$", t);
print(m.group(0) if m else t)'
}

printf '# Dual-pass report for issue %s\n\n' "$ISSUE_NUMBER" > "$REPORT"
snapshot

ISSUE_BODY="$(gh issue view "$ISSUE_NUMBER" --repo "$REPO" --json title,body,labels --jq '{title,body,labels}')"
DEPS="$(python3 - <<'PY'
import json, tomllib
from pathlib import Path
data = tomllib.loads(Path("Cargo.toml").read_text())
print(json.dumps({"package": data.get("package", {}), "dependencies": data.get("dependencies", {})}))
PY
)"
IFACES="$(grep -R -n -E '^pub (fn|struct|enum|trait) ' src --include='*.rs' | head -n 200 || true)"

log "pass 1: plan"
PLAN_TEXT="$(ask "Issue ${ISSUE_NUMBER}: ${ISSUE_BODY}
Dependencies: ${DEPS}
Public interfaces:
${IFACES}
Return only JSON with keys targets, new_tests, forbidden. Each new_tests item has path, signatures, and source. path must be tests/generated_<issue>.rs. Do not list tests/, Cargo.toml, Cargo.lock, or .github/ as targets.")"
printf '%s\n' "$PLAN_TEXT" | extract_json > "$PLAN"
python3 - <<PY
import json
from pathlib import Path
plan = json.loads(Path("execution-plan.json").read_text())
for item in plan.get("new_tests", []):
    path = item["path"]
    if not path.startswith("tests/generated_") or not path.endswith(".rs"):
        raise SystemExit(f"test path must be tests/generated_*.rs: {path}")
    if "/" in path[len("tests/"):]:
        raise SystemExit(f"nested test path is not a Cargo integration test: {path}")
    if "signatures" not in item:
        raise SystemExit(f"test spec missing signatures: {path}")
for item in plan.get("targets", []):
    path = item["path"]
    if path.startswith(("tests/", ".github/", "Cargo")):
        raise SystemExit(f"target touches a protected path: {path}")
    if "signatures" not in item:
        raise SystemExit(f"target missing signatures: {path}")
print("plan ok")
PY

log "red: write generated tests and require failure on untouched code"
python3 - <<'PY'
import json
from pathlib import Path
plan = json.loads(Path("execution-plan.json").read_text())
for item in plan.get("new_tests", []):
    Path(item["path"]).write_text(item["source"], encoding="utf-8")
PY
mapfile -t TEST_BINS < <(python3 -c 'import json; print("\n".join(item["path"].rsplit("/",1)[-1][:-3] for item in json.load(open("execution-plan.json"))["new_tests"]))')
set +e
red_log="$(cargo test --locked --test "${TEST_BINS[0]}" -- --test-threads=1 2>&1)"
red_status=$?
set -e
python3 - <<PY
from pathlib import Path
red = """${red_log}"""
Path("dual-pass-report.md").write_text(Path("dual-pass-report.md").read_text() + "\n## Red\n\nstatus=${red_status}\n\n```\n" + "\n".join(red.splitlines()[-40:]) + "\n```\n", encoding="utf-8")
PY
if [[ "$red_status" -eq 0 ]]; then
  fail_human "red gate rejected the plan: generated tests passed on untouched main"
fi
log "red confirmed"

turn=1
green=0
while [[ "$turn" -le "$MAX_TURNS" ]]; do
  log "green turn $turn"
  diag="$(tail -n 60 "$REPORT")"
  reply="$(ask "Implement only declared targets. Return JSON with diff and ops. diff is a unified git patch. ops is the tree-sitter fallback list of path, kind replace_fn, name, body. Plan: $(cat "$PLAN")
Structured diagnostics:
$diag")"
  if ! printf '%s\n' "$reply" | extract_json | python3 scripts/dual-pass/apply_change.py; then
    printf '\n## Turn %s apply failed\n\n' "$turn" >> "$REPORT"
    turn=$((turn + 1))
    continue
  fi
  restore_protected
  set +e
  syntax="$(cargo check --locked --bin huntsman-recon --message-format=short 2>&1)"
  syntax_status=$?
  set -e
  if [[ "$syntax_status" -ne 0 ]]; then
    printf '\n## Turn %s syntax\n\n```\n%s\n```\n' "$turn" "$(printf '%s\n' "$syntax" | tail -n 30)" >> "$REPORT"
    turn=$((turn + 1))
    continue
  fi
  set +e
  unit="$(cargo test --locked --test "${TEST_BINS[0]}" -- --test-threads=1 2>&1)"
  unit_status=$?
  set -e
  printf '\n## Turn %s unit\n\n```\n%s\n```\n' "$turn" "$(printf '%s\n' "$unit" | tail -n 40)" >> "$REPORT"
  if [[ "$unit_status" -eq 0 ]]; then
    green=1
    break
  fi
  turn=$((turn + 1))
done

if [[ "$green" -ne 1 ]]; then
  fail_human "self-correction budget exhausted after ${MAX_TURNS} turns"
fi

rustfmt --edition 2024 src tests/generated_*.rs >/dev/null 2>&1 || true
restore_protected
git checkout -B "dual-pass/issue-${ISSUE_NUMBER}"
git add execution-plan.json dual-pass-report.md tests/generated_*.rs src
git -c user.email="41898282+github-actions[bot]@users.noreply.github.com" \
  -c user.name="github-actions[bot]" \
  commit -m "dual-pass: issue ${ISSUE_NUMBER}"
git push -u origin "dual-pass/issue-${ISSUE_NUMBER}" --force-with-lease
gh pr create --repo "$REPO" --base main --head "dual-pass/issue-${ISSUE_NUMBER}" \
  --title "dual-pass: issue ${ISSUE_NUMBER}" \
  --body "$(cat "$REPORT")"
log "pull request opened"
