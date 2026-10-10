#!/usr/bin/env bash
# Dual-pass runner. No LLM API, no model secret, no prompt cache.
# Pass 1 binds the issue's fenced plan to live signatures and Cargo.lock.
# Pass 2 writes generated tests, requires red on untouched main, then applies
# at most 3 declared patches through syntax, type-check, and unit gates.
set -Eeuo pipefail
IFS=$'\n\t'

: "${ISSUE_NUMBER:?issue number required}"
: "${REPO:?owner/repo required}"
MAX_TURNS=3
REPORT="$(pwd)/dual-pass-report.md"
OFFLINE="${DUAL_PASS_OFFLINE:-0}"

log() { printf '%s\n' "$*"; }

# Pushes pass the token explicitly. The checkout persists no credential, so the
# generated tests that cargo runs cannot read one from .git/config.
git_push() {
  local auth
  auth="$(printf 'x-access-token:%s' "${GH_TOKEN:?GH_TOKEN required to push}" | base64 | tr -d '\n')"
  git -c "http.https://github.com/.extraheader=AUTHORIZATION: basic ${auth}" push "$@"
}

fail_human() {
  local reason="$1"
  log "needs-human-review: $reason"
  printf '\n## Needs human review\n\n%s\n' "$reason" >> "$REPORT"
  if [[ "$OFFLINE" == "1" ]]; then
    printf '%s\n' "$reason" > dual-pass-needs-human.txt
    exit 1
  fi
  git checkout -B "dual-pass/issue-${ISSUE_NUMBER}-wip"
  git add dual-pass-report.md execution-plan.json 2>/dev/null || true
  if compgen -G "tests/generated_*.rs" > /dev/null; then
    git add tests/generated_*.rs
  fi
  python3 - <<'PY'
import json
from pathlib import Path
plan = Path("execution-plan.json")
if plan.is_file():
    paths = [item["path"] for item in json.loads(plan.read_text()).get("targets", [])]
    Path(".dual-pass-add").write_text("\n".join(paths) + "\n")
PY
  if [[ -f .dual-pass-add ]]; then
    while read -r f; do
      [[ -n "$f" && -f "$f" ]] && git add -- "$f"
    done < .dual-pass-add
  fi
  git -c user.email="41898282+github-actions[bot]@users.noreply.github.com" \
    -c user.name="github-actions[bot]" \
    commit -m "dual-pass WIP for issue ${ISSUE_NUMBER}" --allow-empty
  git_push -u origin "dual-pass/issue-${ISSUE_NUMBER}-wip" --force-with-lease
  gh label create needs-human-review --repo "$REPO" --color B60205 --description "Dual-pass budget exhausted" 2>/dev/null || true
  gh issue edit "$ISSUE_NUMBER" --repo "$REPO" --add-label needs-human-review
  gh issue comment "$ISSUE_NUMBER" --repo "$REPO" --body "$(printf '%s\n\n```\n%s\n```\n' "$reason" "$(tail -n 80 "$REPORT" 2>/dev/null || true)")"
  exit 1
}

snapshot() {
  mkdir -p .dual-pass-base
  git ls-files tests Cargo.toml Cargo.lock .github/workflows/ci.yml .github/workflows/release.yml .github/workflows/dual-pass.yml \
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
  for f in Cargo.toml Cargo.lock .github/workflows/ci.yml .github/workflows/release.yml .github/workflows/dual-pass.yml; do
    if [[ -f ".dual-pass-base/$f" ]]; then
      cp ".dual-pass-base/$f" "$f"
    fi
  done
  find tests -type f -name 'generated_*.rs' -delete 2>/dev/null || true
  if [[ -f execution-plan.json ]]; then
    python3 - <<'PY'
import json
from pathlib import Path
plan = json.loads(Path("execution-plan.json").read_text())
for item in plan.get("new_tests", []):
    Path(item["path"]).parent.mkdir(parents=True, exist_ok=True)
    Path(item["path"]).write_text(item["source"], encoding="utf-8")
PY
  fi
}

diagnostic() {
  DUAL_PASS_DIAG="$2" python3 - "$1" <<'PY'
import os, re
text = os.environ.get("DUAL_PASS_DIAG", "")
lines = [line for line in text.splitlines() if re.search(r"error(\[|:)|assert|panicked|FAILED|could not compile", line)]
print("\n".join(lines[-25:] or text.splitlines()[-15:]))
PY
}

printf '# Dual-pass report for issue %s\n\nNo LLM API. No prompt cache. Context is a sha256 digest.\n\n' "$ISSUE_NUMBER" > "$REPORT"
snapshot

log "pass 1: bind issue plan to live interfaces"
if [[ "$OFFLINE" == "1" ]]; then
  cp "${DUAL_PASS_BODY:?}" .issue-body.md
else
  gh issue view "$ISSUE_NUMBER" --repo "$REPO" --json body --jq .body > .issue-body.md
fi
if ! python3 scripts/dual-pass/plan.py . .issue-body.md; then
  fail_human "pass 1 rejected the issue: add a fenced json plan with targets, asserting new_tests, and 1 to 3 patches, and no model fields"
fi
python3 - <<'PY' >> "$REPORT"
import json
from pathlib import Path
plan = json.loads(Path("execution-plan.json").read_text())
print(f"schema={plan['schema']} llm={plan['llm']} digest={plan['context_digest'][:12]}")
print(f"targets={len(plan['targets'])} dependencies={len(plan['dependency_tree'])}")
PY

log "red: write generated tests and require failure on untouched code"
python3 - <<'PY'
import json
from pathlib import Path
plan = json.loads(Path("execution-plan.json").read_text())
names = []
for item in plan["new_tests"]:
    Path(item["path"]).parent.mkdir(parents=True, exist_ok=True)
    Path(item["path"]).write_text(item["source"], encoding="utf-8")
    names.append(item["path"].rsplit("/", 1)[-1][:-3])
Path(".dual-pass-tests").write_text("\n".join(names) + "\n", encoding="utf-8")
PY
mapfile -t TEST_BINS < .dual-pass-tests
saved_token="${GH_TOKEN-}"
unset GH_TOKEN
set +e
red_log=""
red_status=0
for bin in "${TEST_BINS[@]}"; do
  one="$(cargo test --locked --test "$bin" -- --test-threads=1 2>&1)"
  one_status=$?
  red_log="${red_log}"$'\n'"${one}"
  if [[ "$one_status" -eq 0 ]]; then
    red_status=0
    break
  fi
  red_status=$one_status
done
set -e
if [[ -n "$saved_token" ]]; then export GH_TOKEN="$saved_token"; fi
printf '\n## Red\n\nstatus=%s\n\n```\n%s\n```\n' "$red_status" "$(printf '%s\n' "$red_log" | tail -n 40)" >> "$REPORT"
if [[ "$red_status" -eq 0 ]]; then
  fail_human "red gate rejected the plan: generated tests passed on untouched main"
fi
# Here-strings, not `printf | grep -q`: under pipefail a long log would make the
# pipeline report SIGPIPE and silently skip these classifications.
if grep -q 'expected one of' <<< "$red_log"; then
  fail_human "red gate rejected the plan: generated test does not parse"
fi
red_class="assertion-or-compile"
if grep -q 'cannot find' <<< "$red_log"; then
  red_class="missing-symbol"
elif grep -q 'assertion' <<< "$red_log"; then
  red_class="assertion-failed"
fi
printf '\nRed class: %s\n' "$red_class" >> "$REPORT"
log "red confirmed ($red_class)"

turn=1
green=0
while [[ "$turn" -le "$MAX_TURNS" ]]; do
  log "green turn $turn"
  set +e
  apply_out="$(python3 - "$turn" <<'PY' | python3 scripts/dual-pass/apply_change.py
import json, sys
from pathlib import Path
plan = json.loads(Path("execution-plan.json").read_text())
turn = int(sys.argv[1])
patches = plan["patches"]
if turn > len(patches):
    raise SystemExit(0)
item = dict(patches[turn - 1])
item["allowed"] = [target["path"] for target in plan["targets"]]
print(json.dumps(item))
PY
)"
  apply_status=$?
  set -e
  printf '\n## Turn %s apply\n\n```\n%s\n```\n' "$turn" "$apply_out" >> "$REPORT"
  if [[ "$apply_status" -ne 0 ]]; then
    turn=$((turn + 1))
    continue
  fi
  restore_protected
  saved_token="${GH_TOKEN-}"
  unset GH_TOKEN
  set +e
  syntax="$(cargo check --locked --message-format=short --tests --bins 2>&1)"
  syntax_status=$?
  set -e
  if [[ -n "$saved_token" ]]; then export GH_TOKEN="$saved_token"; fi
  if [[ "$syntax_status" -ne 0 ]]; then
    printf '\n## Turn %s syntax-type\n\n```\n%s\n```\n' "$turn" "$(diagnostic syntax "$syntax")" >> "$REPORT"
    turn=$((turn + 1))
    continue
  fi
  unit_status=0
  unit=""
  saved_token="${GH_TOKEN-}"
  unset GH_TOKEN
  for bin in "${TEST_BINS[@]}"; do
    set +e
    one="$(cargo test --locked --test "$bin" -- --test-threads=1 2>&1)"
    one_status=$?
    set -e
    unit="${unit}"$'\n'"${one}"
    if [[ "$one_status" -ne 0 ]]; then
      unit_status=$one_status
    fi
  done
  if [[ -n "$saved_token" ]]; then export GH_TOKEN="$saved_token"; fi
  printf '\n## Turn %s unit\n\n```\n%s\n```\n' "$turn" "$(diagnostic unit "$unit")" >> "$REPORT"
  if [[ "$unit_status" -eq 0 ]]; then
    if python3 - <<'PY'
import json, sys
from pathlib import Path
plan = json.loads(Path("execution-plan.json").read_text())
missing = []
for item in plan["targets"]:
    text = Path(item["path"]).read_text(encoding="utf-8")
    for sig in item["signatures"]:
        if sig not in text:
            missing.append(f"{item['path']}: {sig}")
if missing:
    print("\n".join(missing))
    raise SystemExit(1)
PY
    then
      green=1
      break
    else
      printf '\n## Turn %s signature mismatch\n\n' "$turn" >> "$REPORT"
    fi
  fi
  turn=$((turn + 1))
done

if [[ "$green" -ne 1 ]]; then
  fail_human "declared patch budget exhausted after ${MAX_TURNS} patches; diagnostics are not sent to a model"
fi

python3 -c 'import json; open(".dual-pass-targets","w").write("\n".join(i["path"] for i in json.load(open("execution-plan.json"))["targets"])+"\n")'
mapfile -t TOUCHED < .dual-pass-targets
rustfmt --edition 2021 "${TOUCHED[@]}" tests/generated_*.rs >/dev/null 2>&1 || true
restore_protected
printf '\n## Green\n\nCoverage tool not invoked. Gate evidence is cargo check, generated tests, and the existing locked suite. Initial red status=%s.\n' "$red_status" >> "$REPORT"
saved_token="${GH_TOKEN-}"
unset GH_TOKEN
set +e
suite="$(cargo test --locked -- --test-threads=1 2>&1)"
suite_status=$?
set -e
if [[ -n "$saved_token" ]]; then export GH_TOKEN="$saved_token"; fi
printf '\n## Existing suite\n\nstatus=%s\n\n```\n%s\n```\n' "$suite_status" "$(diagnostic suite "$suite")" >> "$REPORT"
if [[ "$suite_status" -ne 0 ]]; then
  fail_human "generated tests passed but the existing locked suite failed"
fi
if [[ "$OFFLINE" == "1" ]]; then
  log "offline green"
  exit 0
fi
git checkout -B "dual-pass/issue-${ISSUE_NUMBER}"
git add execution-plan.json dual-pass-report.md tests/generated_*.rs "${TOUCHED[@]}"
git -c user.email="41898282+github-actions[bot]@users.noreply.github.com" \
  -c user.name="github-actions[bot]" \
  commit -m "dual-pass: issue ${ISSUE_NUMBER}"
git_push -u origin "dual-pass/issue-${ISSUE_NUMBER}" --force-with-lease
gh pr create --repo "$REPO" --base main --head "dual-pass/issue-${ISSUE_NUMBER}" \
  --title "dual-pass: issue ${ISSUE_NUMBER}" \
  --body "$(cat "$REPORT")"
log "pull request opened"
