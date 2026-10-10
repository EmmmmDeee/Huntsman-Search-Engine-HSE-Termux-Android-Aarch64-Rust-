#!/usr/bin/env bash
# shellcheck disable=SC2016 # printf formats carry literal Markdown backticks
# Dual-pass plan stage. No LLM API, no model secret, and no token.
#
# This stage compiles and runs Rust written from the issue, so it holds no credential
# at all. A generated test could read any credential this process was started with,
# from its parent's environment, so none is passed in. The stage writes its result to
# DUAL_PASS_OUT: the outcome, the change as a patch, the plan, and the report. The
# publish stage (scripts/dual-pass/publish.sh) runs in a separate job that holds the
# write token, and it reads those files as data.
#
# Pass 1 binds the issue's fenced plan to live signatures and Cargo.lock.
# Pass 2 writes generated tests, requires red on untouched main, then applies at
# most 3 declared patches through syntax, type-check, and unit gates.
set -Eeuo pipefail
IFS=$'\n\t'

: "${ISSUE_NUMBER:?issue number required}"
: "${DUAL_PASS_BODY:?path to the issue body required}"
MAX_TURNS=3
OUT="${DUAL_PASS_OUT:-$(pwd)/dual-pass-out}"
REPORT="$OUT/dual-pass-report.md"
mkdir -p "$OUT"

log() { printf '%s\n' "$*"; }

# Writes the change as a patch: the declared targets and the generated tests, and
# nothing else. Publish applies the patch to a fresh checkout and checks it again.
write_change() {
  local path
  local targets=()
  if [[ -f execution-plan.json ]]; then
    mapfile -t targets < <(python3 -I -c 'import json; [print(t["path"]) for t in json.load(open("execution-plan.json")).get("targets", [])]' || true)
  fi
  git reset -q
  for path in "${targets[@]}" tests/generated_*.rs; do
    if [[ -f "$path" ]]; then
      git add -- "$path"
    fi
  done
  git diff --cached --binary --full-index --no-ext-diff HEAD -- > "$OUT/change.patch"
  git reset -q
}

# Records the outcome for the publish stage. Needs-human-review is a result, not a
# crash, so this stage exits 0 and the publish stage acts on the outcome.
finish() {
  printf '%s\n' "$1" > "$OUT/outcome"
  if [[ -f execution-plan.json ]]; then
    cp execution-plan.json "$OUT/execution-plan.json"
  fi
  log "outcome: $1"
  exit 0
}

fail_human() {
  local reason="$1"
  log "needs-human-review: $reason"
  printf '\n## Needs human review\n\n%s\n' "$reason" >> "$REPORT"
  printf '%s\n' "$reason" > "$OUT/reason.md"
  write_change
  finish needs-human-review
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
    python3 -I - <<'PY'
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
  DUAL_PASS_DIAG="$2" python3 -I - "$1" <<'PY'
import os, re
text = os.environ.get("DUAL_PASS_DIAG", "")
lines = [line for line in text.splitlines() if re.search(r"error(\[|:)|assert|panicked|FAILED|could not compile", line)]
print("\n".join(lines[-25:] or text.splitlines()[-15:]))
PY
}

printf '# Dual-pass report for issue %s\n\nNo LLM API. No prompt cache. Context is a sha256 digest. The plan stage holds no credential.\n\n' "$ISSUE_NUMBER" > "$REPORT"
snapshot

log "pass 1: bind issue plan to live interfaces"
cp "$DUAL_PASS_BODY" .issue-body.md
if ! python3 -I scripts/dual-pass/plan.py . .issue-body.md; then
  fail_human "pass 1 rejected the issue: add a fenced json plan with targets, asserting new_tests, and 1 to 3 patches, and no model fields"
fi
python3 -I - <<'PY' >> "$REPORT"
import json
from pathlib import Path
plan = json.loads(Path("execution-plan.json").read_text())
print(f"schema={plan['schema']} llm={plan['llm']} digest={plan['context_digest'][:12]}")
print(f"targets={len(plan['targets'])} dependencies={len(plan['dependency_tree'])}")
PY

log "red: write generated tests and require failure on untouched code"
python3 -I - <<'PY'
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
printf '\n## Red\n\nstatus=%s\n\n```\n%s\n```\n' "$red_status" "$(printf '%s\n' "$red_log" | tail -n 40)" >> "$REPORT"
if [[ "$red_status" -eq 0 ]]; then
  fail_human "red gate rejected the plan: generated tests passed on untouched main"
fi
# Here-strings, not `printf | grep -q`: under pipefail a long log would make the
# pipeline report SIGPIPE and silently skip these classifications.
if grep -q 'expected one of' <<< "$red_log"; then
  fail_human "red gate rejected the plan: generated test does not parse"
fi
# A valid red is a missing symbol (the build fails on `cannot find`) or a failed
# assertion (the test runs and panics). Any other compile error is rejected, because
# it shows nothing about the defect.
red_class="rejected"
if grep -q 'could not compile' <<< "$red_log"; then
  if grep -q 'cannot find' <<< "$red_log"; then
    red_class="missing-symbol"
  fi
elif grep -q -E 'panicked|test result: FAILED' <<< "$red_log"; then
  red_class="assertion-failed"
fi
if [[ "$red_class" == "rejected" ]]; then
  fail_human "red gate rejected the plan: the generated test neither failed an assertion nor referenced a missing symbol"
fi
printf '\nRed class: %s\n' "$red_class" >> "$REPORT"
log "red confirmed ($red_class)"

turn=1
green=0
while [[ "$turn" -le "$MAX_TURNS" ]]; do
  log "green turn $turn"
  set +e
  apply_out="$(python3 -I - "$turn" <<'PY' | python3 -I scripts/dual-pass/apply_change.py
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
  set +e
  syntax="$(cargo check --locked --message-format=short --tests --bins 2>&1)"
  syntax_status=$?
  set -e
  if [[ "$syntax_status" -ne 0 ]]; then
    printf '\n## Turn %s syntax-type\n\n```\n%s\n```\n' "$turn" "$(diagnostic syntax "$syntax")" >> "$REPORT"
    turn=$((turn + 1))
    continue
  fi
  unit_status=0
  unit=""
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
  printf '\n## Turn %s unit\n\n```\n%s\n```\n' "$turn" "$(diagnostic unit "$unit")" >> "$REPORT"
  if [[ "$unit_status" -eq 0 ]]; then
    if python3 -I - <<'PY'
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

python3 -I -c 'import json; open(".dual-pass-targets","w").write("\n".join(i["path"] for i in json.load(open("execution-plan.json"))["targets"])+"\n")'
mapfile -t TOUCHED < .dual-pass-targets
rustfmt --edition 2021 "${TOUCHED[@]}" tests/generated_*.rs >/dev/null 2>&1 || true
restore_protected
printf '\n## Green\n\nCoverage tool not invoked. Gate evidence is cargo check, generated tests, and the existing locked suite. Initial red status=%s.\n' "$red_status" >> "$REPORT"
set +e
suite="$(cargo test --locked -- --test-threads=1 2>&1)"
suite_status=$?
set -e
printf '\n## Existing suite\n\nstatus=%s\n\n```\n%s\n```\n' "$suite_status" "$(diagnostic suite "$suite")" >> "$REPORT"
if [[ "$suite_status" -ne 0 ]]; then
  fail_human "generated tests passed but the existing locked suite failed"
fi
write_change
finish green
