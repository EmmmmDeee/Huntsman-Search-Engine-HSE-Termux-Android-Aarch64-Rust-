#!/usr/bin/env bash
# Dual-pass runner. No LLM API.
# Pass 1 reads execution-plan.json from the issue body.
# Pass 2 proves red, then applies at most 3 declared patches.
set -Eeuo pipefail
IFS=$'\n\t'

: "${ISSUE_NUMBER:?issue number required}"
: "${REPO:?owner/repo required}"
MAX_TURNS=3
REPORT="$(pwd)/dual-pass-report.md"
PLAN="$(pwd)/execution-plan.json"

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

printf '# Dual-pass report for issue %s\n\nNo LLM API.\n\n' "$ISSUE_NUMBER" > "$REPORT"
snapshot

log "pass 1: read plan from issue body"
gh issue view "$ISSUE_NUMBER" --repo "$REPO" --json body --jq .body > .issue-body.md
python3 - <<'PY'
import json, re
from pathlib import Path
body = Path(".issue-body.md").read_text(encoding="utf-8")
match = re.search(r"```json\s*(\{.*?\})\s*```", body, re.S)
if not match:
    raise SystemExit("issue body has no fenced json plan")
plan = json.loads(match.group(1))
for item in plan.get("new_tests", []):
    path = item["path"]
    if not path.startswith("tests/generated_") or not path.endswith(".rs") or "/" in path[len("tests/"):]:
        raise SystemExit(f"test path must be tests/generated_*.rs: {path}")
    if "source" not in item or "signatures" not in item:
        raise SystemExit(f"test missing source or signatures: {path}")
for item in plan.get("targets", []):
    path = item["path"]
    if path.startswith(("tests/", ".github/", "Cargo")):
        raise SystemExit(f"target touches a protected path: {path}")
    if "signatures" not in item:
        raise SystemExit(f"target missing signatures: {path}")
patches = plan.get("patches") or []
if not patches or len(patches) > 3:
    raise SystemExit("patches must contain 1 to 3 items")
Path("execution-plan.json").write_text(json.dumps(plan, indent=2) + "\n", encoding="utf-8")
print("plan ok")
PY
if [[ $? -ne 0 ]]; then
  fail_human "pass 1 rejected the issue: add a fenced json plan with targets, new_tests, and 1 to 3 patches"
fi

log "red: write generated tests and require failure on untouched code"
python3 - <<'PY'
import json
from pathlib import Path
plan = json.loads(Path("execution-plan.json").read_text())
for item in plan["new_tests"]:
    Path(item["path"]).write_text(item["source"], encoding="utf-8")
print(plan["new_tests"][0]["path"].rsplit("/", 1)[-1][:-3])
PY
TEST_BIN="$(python3 -c 'import json; print(json.load(open("execution-plan.json"))["new_tests"][0]["path"].rsplit("/",1)[-1][:-3])' )"
set +e
red_log="$(cargo test --locked --test "$TEST_BIN" -- --test-threads=1 2>&1)"
red_status=$?
set -e
printf '\n## Red\n\nstatus=%s\n\n```\n%s\n```\n' "$red_status" "$(printf '%s\n' "$red_log" | tail -n 40)" >> "$REPORT"
if [[ "$red_status" -eq 0 ]]; then
  fail_human "red gate rejected the plan: generated tests passed on untouched main"
fi
log "red confirmed"

turn=1
green=0
while [[ "$turn" -le "$MAX_TURNS" ]]; do
  log "green turn $turn"
  if ! python3 - "$turn" <<'PY' | python3 scripts/dual-pass/apply_change.py
import json, sys
from pathlib import Path
plan = json.loads(Path("execution-plan.json").read_text())
turn = int(sys.argv[1])
patches = plan["patches"]
if turn > len(patches):
    raise SystemExit(0)
print(json.dumps(patches[turn - 1]))
PY
  then
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
  unit="$(cargo test --locked --test "$TEST_BIN" -- --test-threads=1 2>&1)"
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
  fail_human "self-correction budget exhausted after ${MAX_TURNS} declared patches"
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
