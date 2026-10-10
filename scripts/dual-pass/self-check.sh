#!/usr/bin/env bash
# shellcheck disable=SC2016 # printf formats carry literal Markdown backticks
set -Eeuo pipefail

# new_fixture ROOT: a crate whose answer() is 0, with the runner's scripts copied in and a
# committed main. ROOT must exist. The runner runs inside the fixture, never in the
# checkout, so a fixture cannot change the scripts that judge it.
new_fixture() {
  local root="$1"
  mkdir -p "$root/src" "$root/tests" "$root/.github/workflows"
  cp -a scripts "$root/scripts"
  cat > "$root/Cargo.toml" <<'EOF'
[package]
name = "fixture"
version = "0.1.0"
edition = "2021"

[lib]
path = "src/lib.rs"
EOF
  cat > "$root/src/lib.rs" <<'EOF'
pub fn answer() -> i32 {
    0
}
EOF
  printf 'name: ci\n' > "$root/.github/workflows/ci.yml"
  git -C "$root" init -q
  git -C "$root" add Cargo.toml src .github scripts
  git -C "$root" -c user.email=t@example.com -c user.name=t commit -qm init
  cargo generate-lockfile --manifest-path "$root/Cargo.toml"
  git -C "$root" add Cargo.lock
}

# plan_md FILE: an issue body whose fenced json plan is read from stdin.
plan_md() {
  {
    printf 'Reproduction plan.\n\n```json\n'
    cat
    printf '\n```\n'
  } > "$1"
}

# run_plan ROOT ISSUE BODY OUT: the plan stage, run inside the fixture ROOT. A plan that
# needs a human is a result and exits 0, so any other status is a crash.
run_plan() {
  local status=0
  (cd "$1" && ISSUE_NUMBER="$2" DUAL_PASS_BODY="$3" DUAL_PASS_OUT="$4" bash scripts/dual-pass/run.sh) > "$4.log" 2>&1 || status=$?
  if [[ "$status" -ne 0 ]]; then
    echo "plan stage crashed with status $status in $1" >&2
    cat "$4.log" >&2
    exit 1
  fi
}

# expect_outcome OUT WANT: the plan stage recorded WANT in OUT. Otherwise show the report.
expect_outcome() {
  local got
  got="$(cat "$1/outcome")"
  if [[ "$got" != "$2" ]]; then
    echo "expected outcome $2 in $1, got $got" >&2
    cat "$1/dual-pass-report.md" >&2
    exit 1
  fi
}

# Every fixture lives under one scratch directory, removed on exit, so a run leaves nothing
# behind in the temporary directory.
scratch=$(mktemp -d)
trap 'rm -rf "$scratch"' EXIT
root=$(mktemp -d "$scratch/XXXXXX")
new_fixture "$root"
body="$root/issue.md"
cat > "$body" <<'EOF'
```json
{
  "targets": [{"path": "src/lib.rs", "signatures": ["pub fn answer() -> i32"]}],
  "new_tests": [
    {
      "path": "tests/generated_1.rs",
      "signatures": ["fn mandated"],
      "source": "use fixture::answer;\n\n#[test]\nfn mandated() {\n    assert_eq!(answer(), 1);\n}\n"
    }
  ],
  "patches": [
    {
      "diff": "--- a/src/lib.rs\n+++ b/src/lib.rs\n@@ -1,3 +1,3 @@\n pub fn answer() -> i32 {\n-    0\n+    1\n }\n",
      "ops": [
        {
          "kind": "replace_fn",
          "path": "src/lib.rs",
          "name": "answer",
          "body": "pub fn answer() -> i32 {\n    1\n}\n"
        }
      ]
    }
  ]
}
```
EOF

echo "reject model field"
printf '```json\n{"model":"x","targets":[],"new_tests":[],"patches":[{}]}\n```\n' > "$root/bad.md"
if python3 -I "$root/scripts/dual-pass/plan.py" "$root" "$root/bad.md"; then
  echo "model field was accepted" >&2
  exit 1
fi

echo "reject protected target"
printf '```json\n{"targets":[{"path":"Cargo.toml","signatures":[]}],"new_tests":[{"path":"tests/generated_1.rs","signatures":[],"source":"assert!"}],"patches":[{"diff":"","ops":[]}]}\n```\n' > "$root/bad2.md"
if python3 -I "$root/scripts/dual-pass/plan.py" "$root" "$root/bad2.md"; then
  echo "protected target was accepted" >&2
  exit 1
fi

echo "reject a target outside the path policy: docs/ is neither under src/ nor a new test"
plan_md "$root/bad-docs.md" <<'JSON'
{
  "targets": [{"path": "docs/DUAL_PASS.md", "signatures": ["Dual-pass runner"]}],
  "new_tests": [{"path": "tests/generated_1.rs", "signatures": ["fn t"], "source": "#[test]\nfn t() { assert_eq!(1, 2); }\n"}],
  "patches": [{"diff": "", "ops": [{"kind": "replace_fn", "path": "docs/DUAL_PASS.md", "name": "x", "body": "x"}]}]
}
JSON
if python3 -I "$root/scripts/dual-pass/plan.py" "$root" "$root/bad-docs.md" > "$root/bad-docs.out" 2>&1; then
  echo "a docs/ target was accepted" >&2
  exit 1
fi
grep -q 'outside the path policy' "$root/bad-docs.out" \
  || { echo "docs/ target refused for the wrong reason" >&2; cat "$root/bad-docs.out" >&2; exit 1; }
echo "ok: plan.py refuses a docs/ target before any build"

echo "accept a new file under tests/ as a target"
plan_md "$root/new-test-target.md" <<'JSON'
{
  "targets": [{"path": "tests/helper_new.rs", "signatures": []}],
  "new_tests": [{"path": "tests/generated_1.rs", "signatures": ["fn t"], "source": "#[test]\nfn t() { assert_eq!(1, 2); }\n"}],
  "patches": [{"diff": "", "ops": []}]
}
JSON
python3 -I "$root/scripts/dual-pass/plan.py" "$root" "$root/new-test-target.md" > /dev/null \
  || { echo "a new file under tests/ was refused as a target" >&2; exit 1; }
echo "ok: a new file under tests/ is an accepted target"

echo "reject tautology"
python3 - "$root/bad3.md" <<'PY'
import sys
from pathlib import Path
Path(sys.argv[1]).write_text(
    "```json\n"
    '{"targets":[{"path":"src/lib.rs","signatures":["pub fn answer"]}],'
    '"new_tests":[{"path":"tests/generated_1.rs","signatures":["fn t"],'
    '"source":"#[test]\\nfn t() { assert!(true); }\\n"}],'
    '"patches":[{"diff":"","ops":[{"kind":"replace_fn","path":"src/lib.rs","name":"answer","body":"pub fn answer() -> i32 { 1 }"}]}]}'
    "\n```\n",
    encoding="utf-8",
)
PY
if python3 -I "$root/scripts/dual-pass/plan.py" "$root" "$root/bad3.md"; then
  echo "tautology was accepted" >&2
  exit 1
fi
python3 -I "$root/scripts/dual-pass/plan.py" "$root" "$root/bad3.md" >"$root/bad3.out" 2>&1 || true
if ! grep -q "tautological assertion rejected" "$root/bad3.out"; then
  echo "tautology rejection reason missing" >&2
  cat "$root/bad3.out" >&2
  exit 1
fi

echo "reject a rename that moves an undeclared path"
python3 - "$root/bad4.md" <<'PY'
import json, sys
from pathlib import Path
diff = (
    "diff --git a/src/lib.rs b/src/other.rs\n"
    "similarity index 100%\n"
    "rename from src/lib.rs\n"
    "rename to src/other.rs\n"
)
plan = {
    "targets": [{"path": "src/lib.rs", "signatures": ["pub fn answer"]}],
    "new_tests": [{"path": "tests/generated_1.rs", "signatures": ["fn t"],
                   "source": "#[test]\nfn t() { assert_eq!(1, 2); }\n"}],
    "patches": [{"diff": diff, "ops": []}],
}
Path(sys.argv[1]).write_text("```json\n" + json.dumps(plan) + "\n```\n", encoding="utf-8")
PY
if python3 -I "$root/scripts/dual-pass/plan.py" "$root" "$root/bad4.md"; then
  echo "a rename to an undeclared path was accepted" >&2
  exit 1
fi
echo "ok: a rename to an undeclared path is refused"

echo "offline red-green"
out="$root/out"
set +e
(
  cd "$root"
  ISSUE_NUMBER=1 DUAL_PASS_BODY="$body" DUAL_PASS_OUT="$out" bash scripts/dual-pass/run.sh
)
status=$?
set -e
if [[ "$status" -ne 0 ]]; then
  echo "plan stage failed" >&2
  cat "$out/dual-pass-report.md" >&2 || true
  exit 1
fi
[[ "$(cat "$out/outcome")" == "green" ]] || { echo "plan did not reach green" >&2; cat "$out/dual-pass-report.md" >&2; exit 1; }
grep -q 'llm=False' "$out/dual-pass-report.md"
grep -q 'No LLM API' "$out/dual-pass-report.md"
grep -q '^generated_1: assertion-failed$' "$out/dual-pass-report.md"
[[ -s "$out/change.patch" ]] || { echo "green plan wrote no change.patch" >&2; exit 1; }
python3 - "$root" <<'PY'
import pathlib, sys
text = pathlib.Path(sys.argv[1], "src/lib.rs").read_text()
assert "1" in text, text
print("implementation green")
PY

echo "ast fallback"
printf 'pub fn answer() -> i32 {\n    0\n}\n' > "$root/src/lib.rs"
(
cd "$root"
python3 - <<'PY' | python3 -I scripts/dual-pass/apply_change.py
import json
print(json.dumps({
  "allowed": ["src/lib.rs"],
  "diff": "--- a/src/lib.rs\n+++ b/src/lib.rs\n@@ -1 +1 @@\n-not the file\n+nope\n",
  "ops": [{
    "kind": "replace_fn",
    "path": "src/lib.rs",
    "name": "answer",
    "body": "pub fn answer() -> i32 {\n    7\n}\n"
  }]
}))
PY
)
grep -q '7' "$root/src/lib.rs"
echo "ast fallback applied"

# The red classes. The classifier is one file, run here on the same fixture logs that the
# contract test reads. Each log is judged on its own, and the exact verdict is required.
fixtures="$root/scripts/dual-pass/fixtures/red"

# expect_red NAME VERDICT: judges the one fixture log NAME. It must print VERDICT, and
# exit 0 for a valid red or 1 for a rejected one.
expect_red() {
  local name="$1" want="$2" verdict="" status=0 exit_want=0
  verdict="$(python3 -I "$root/scripts/dual-pass/red_class.py" "$fixtures/$name.log")" || status=$?
  if [[ "$verdict" != "$want" ]]; then
    echo "red class: $name printed '$verdict', expected '$want'" >&2
    exit 1
  fi
  if [[ "$want" == *": rejected ("* ]]; then
    exit_want=1
  fi
  if [[ "$status" -ne "$exit_want" ]]; then
    echo "red class: $name exited $status, expected $exit_want" >&2
    exit 1
  fi
  echo "ok: $verdict"
}

# expect_red_run WANT NAME...: the judgement of a whole red run, one log per failing
# binary. WANT is 0 when every log is a valid red, and 1 when any one is refused.
expect_red_run() {
  local want="$1" status=0 logs=() name
  shift
  for name in "$@"; do
    logs+=("$fixtures/$name.log")
  done
  python3 -I "$root/scripts/dual-pass/red_class.py" "${logs[@]}" > "$root/red-run.out" 2>&1 || status=$?
  if [[ "$status" -ne "$want" ]]; then
    echo "red run [$*] exited $status, expected $want" >&2
    cat "$root/red-run.out" >&2
    exit 1
  fi
  echo "ok: red run [$*] exits $want"
}

echo "red classes, judged one log at a time"
expect_red missing-symbol "missing-symbol: missing-symbol"
expect_red assertion "assertion: assertion-failed"
expect_red assertion-with-message "assertion-with-message: assertion-failed"
expect_red custom-assert "custom-assert: rejected (a panic that is not an assertion: answer must be one)"
expect_red unwrap-on-err 'unwrap-on-err: rejected (a panic that is not an assertion: called `Result::unwrap()` on an `Err` value: ParseIntError { kind: InvalidDigit })'
expect_red err-return "err-return: rejected (the test failed without an assertion panic)"
expect_red lone-mismatch "lone-mismatch: rejected (the build failed on an error other than a missing symbol)"
expect_red mismatch-and-missing "mismatch-and-missing: rejected (the build failed on an error other than a missing symbol)"
expect_red does-not-parse "does-not-parse: rejected (the generated test does not parse)"
expect_red missing-symbol-colored "missing-symbol-colored: missing-symbol"
expect_red missing-value "missing-value: missing-symbol"
expect_red missing-type "missing-type: missing-symbol"
echo "red runs: every failing binary must be a valid red"
expect_red_run 0 missing-symbol assertion
expect_red_run 0 assertion-with-message missing-symbol
expect_red_run 0 missing-symbol-colored assertion
expect_red_run 1 lone-mismatch missing-symbol
expect_red_run 1 lone-mismatch missing-symbol-colored
expect_red_run 1 lone-mismatch assertion

# The red gate in the runner. A lone E0308 next to a valid missing symbol refuses the run.
mixed="$(mktemp -d "$scratch/XXXXXX")"
new_fixture "$mixed"
plan_md "$mixed/issue.md" <<'JSON'
{
  "targets": [{"path": "src/lib.rs", "signatures": ["pub fn answer() -> i32"]}],
  "new_tests": [
    {"path": "tests/generated_1.rs", "signatures": ["fn typed"],
     "source": "use fixture::answer;\n\n#[test]\nfn typed() {\n    let x: i32 = \"one\";\n    assert_eq!(answer(), x);\n}\n"},
    {"path": "tests/generated_2.rs", "signatures": ["fn missing"],
     "source": "#[test]\nfn missing() {\n    assert_eq!(fixture::answer_v2(), 1);\n}\n"}
  ],
  "patches": [{"diff": "--- a/src/lib.rs\n+++ b/src/lib.rs\n@@ -1,3 +1,3 @@\n pub fn answer() -> i32 {\n-    0\n+    1\n }\n",
    "ops": [{"kind": "replace_fn", "path": "src/lib.rs", "name": "answer", "body": "pub fn answer() -> i32 {\n    1\n}\n"}]}]
}
JSON
run_plan "$mixed" 12 "$mixed/issue.md" "$mixed/out"
expect_outcome "$mixed/out" needs-human-review
# Each verdict is checked on its own line: the lone E0308 is refused as a build failure, and
# the missing symbol next to it is a valid red. The run is refused because of the first.
grep -Fxq 'generated_1: rejected (the build failed on an error other than a missing symbol)' "$mixed/out/dual-pass-report.md" \
  || { echo "generated_1 (the lone E0308) was not judged as a refused build" >&2; cat "$mixed/out/dual-pass-report.md" >&2; exit 1; }
grep -Fxq 'generated_2: missing-symbol' "$mixed/out/dual-pass-report.md" \
  || { echo "generated_2 (the missing symbol) was not judged as a valid red" >&2; cat "$mixed/out/dual-pass-report.md" >&2; exit 1; }
grep -q 'red gate rejected the plan' "$mixed/out/dual-pass-report.md" \
  || { echo "the run did not record the red refusal" >&2; exit 1; }
echo "ok: a run with a lone E0308 is refused, though the other binary is a valid missing symbol"

# The red gate in the runner. A test that panics on unwrap() of an Err is not a red.
unwrap="$(mktemp -d "$scratch/XXXXXX")"
new_fixture "$unwrap"
plan_md "$unwrap/issue.md" <<'JSON'
{
  "targets": [{"path": "src/lib.rs", "signatures": ["pub fn answer() -> i32"]}],
  "new_tests": [{"path": "tests/generated_1.rs", "signatures": ["fn parses_the_answer"],
    "source": "use fixture::answer;\n\n#[test]\nfn parses_the_answer() {\n    let parsed: i32 = \"not a number\".parse().unwrap();\n    assert_eq!(answer() + parsed, 1);\n}\n"}],
  "patches": [{"diff": "--- a/src/lib.rs\n+++ b/src/lib.rs\n@@ -1,3 +1,3 @@\n pub fn answer() -> i32 {\n-    0\n+    1\n }\n",
    "ops": [{"kind": "replace_fn", "path": "src/lib.rs", "name": "answer", "body": "pub fn answer() -> i32 {\n    1\n}\n"}]}]
}
JSON
run_plan "$unwrap" 13 "$unwrap/issue.md" "$unwrap/out"
expect_outcome "$unwrap/out" needs-human-review
grep -Fq 'generated_1: rejected (a panic that is not an assertion: called `Result::unwrap()`' "$unwrap/out/dual-pass-report.md" \
  || { echo "a panic on unwrap() of an Err was accepted as a red" >&2; cat "$unwrap/out/dual-pass-report.md" >&2; exit 1; }
echo "ok: a test that panics on unwrap() of an Err is not a red"

# A generated test that an earlier plan merged stays in the existing suite. A patch that
# breaks it must fail the suite, and the tracked file must still be on disk, unchanged.
merged="$(mktemp -d "$scratch/XXXXXX")"
new_fixture "$merged"
cat > "$merged/tests/generated_1.rs" <<'RS'
use fixture::answer;

#[test]
fn merged_answer_is_zero() {
    assert_eq!(answer(), 0);
}
RS
git -C "$merged" add tests
git -C "$merged" -c user.email=t@example.com -c user.name=t commit -qm "merged generated test"
plan_md "$merged/issue.md" <<'JSON'
{
  "targets": [{"path": "src/lib.rs", "signatures": ["pub fn answer() -> i32"]}],
  "new_tests": [{"path": "tests/generated_2.rs", "signatures": ["fn mandated"],
    "source": "use fixture::answer;\n\n#[test]\nfn mandated() {\n    assert_eq!(answer(), 1);\n}\n"}],
  "patches": [{"diff": "--- a/src/lib.rs\n+++ b/src/lib.rs\n@@ -1,3 +1,3 @@\n pub fn answer() -> i32 {\n-    0\n+    1\n }\n",
    "ops": [{"kind": "replace_fn", "path": "src/lib.rs", "name": "answer", "body": "pub fn answer() -> i32 {\n    1\n}\n"}]}]
}
JSON
plan_md "$merged/bad-target.md" <<'JSON'
{
  "targets": [{"path": "tests/generated_1.rs", "signatures": ["fn merged_answer_is_zero"]}],
  "new_tests": [{"path": "tests/generated_3.rs", "signatures": ["fn t"], "source": "#[test]\nfn t() { assert_eq!(1, 2); }\n"}],
  "patches": [{"diff": "", "ops": []}]
}
JSON
if python3 -I "$merged/scripts/dual-pass/plan.py" "$merged" "$merged/bad-target.md" > "$merged/bad-target.out" 2>&1; then
  echo "an existing tests/ file was accepted as a target" >&2
  exit 1
fi
grep -q 'outside the path policy' "$merged/bad-target.out" \
  || { echo "an existing tests/ target was refused for the wrong reason" >&2; cat "$merged/bad-target.out" >&2; exit 1; }
plan_md "$merged/bad-overwrite.md" <<'JSON'
{
  "targets": [{"path": "src/lib.rs", "signatures": ["pub fn answer"]}],
  "new_tests": [{"path": "tests/generated_1.rs", "signatures": ["fn t"], "source": "#[test]\nfn t() { assert_eq!(1, 2); }\n"}],
  "patches": [{"diff": "", "ops": []}]
}
JSON
if python3 -I "$merged/scripts/dual-pass/plan.py" "$merged" "$merged/bad-overwrite.md" > "$merged/bad-overwrite.out" 2>&1; then
  echo "a new test overwrote a merged test" >&2
  exit 1
fi
grep -q 'already exists on main' "$merged/bad-overwrite.out" \
  || { echo "an overwrite was refused for the wrong reason" >&2; cat "$merged/bad-overwrite.out" >&2; exit 1; }
run_plan "$merged" 11 "$merged/issue.md" "$merged/out"
expect_outcome "$merged/out" needs-human-review
grep -q 'generated tests passed but the existing locked suite failed' "$merged/out/dual-pass-report.md" \
  || { echo "a patch that breaks a merged generated test passed the gate" >&2; cat "$merged/out/dual-pass-report.md" >&2; exit 1; }
grep -q 'merged_answer_is_zero' "$merged/out/dual-pass-report.md" \
  || { echo "the existing suite did not run the merged test" >&2; exit 1; }
git -C "$merged" diff --quiet HEAD -- tests/generated_1.rs \
  || { echo "the merged generated test was changed or deleted on disk" >&2; exit 1; }
echo "ok: a patch that breaks a merged generated test fails the existing suite, and the test stays on disk"

# A docs/ target stops the run in pass 1, before any build.
docs="$(mktemp -d "$scratch/XXXXXX")"
new_fixture "$docs"
plan_md "$docs/issue.md" <<'JSON'
{
  "targets": [{"path": "docs/DUAL_PASS.md", "signatures": ["Dual-pass runner"]}],
  "new_tests": [{"path": "tests/generated_1.rs", "signatures": ["fn t"], "source": "#[test]\nfn t() { assert_eq!(1, 2); }\n"}],
  "patches": [{"diff": "", "ops": [{"kind": "replace_fn", "path": "docs/DUAL_PASS.md", "name": "x", "body": "x"}]}]
}
JSON
run_plan "$docs" 16 "$docs/issue.md" "$docs/out"
expect_outcome "$docs/out" needs-human-review
grep -q 'pass 1 rejected the issue' "$docs/out/dual-pass-report.md" \
  || { echo "a docs/ target was not refused in pass 1" >&2; cat "$docs/out/dual-pass-report.md" >&2; exit 1; }
if grep -qx '## Red' "$docs/out/dual-pass-report.md"; then
  echo "a docs/ target reached the red stage" >&2
  exit 1
fi
echo "ok: a docs/ target stops the run in pass 1, before any build"

remote="$root/remote.git"
git init -q --bare "$remote"
git -C "$remote" symbolic-ref HEAD refs/heads/main
git -C "$root" push -q "$remote" HEAD:refs/heads/main
trusted() { rm -rf "$root/trusted"; git clone -q "$remote" "$root/trusted"; }
publish() { # ISSUE OUT_DIR
  (cd "$root/trusted" && ISSUE_NUMBER="$1" REPO=fixture/fixture DRY_RUN=1 \
    REMOTE_URL="$remote" POLICY="$root/scripts/issue-fix/check-protected.sh" \
    bash "$root/scripts/dual-pass/publish.sh" "$2")
}

trusted
publish 1 "$out" >/dev/null || { echo "publish refused a green plan" >&2; exit 1; }
published_lib="$(git -C "$remote" show refs/heads/dual-pass/issue-1:src/lib.rs)"
grep -q 'pub fn answer() -> i32 {' <<< "$published_lib" \
  || { echo "published branch lacks the change" >&2; exit 1; }
git -C "$remote" cat-file -e refs/heads/dual-pass/issue-1:execution-plan.json \
  || { echo "published branch lacks the plan" >&2; exit 1; }
echo "ok: publish pushes dual-pass/issue-1 with the change, the plan, and the report"

# A second run replaces the bot's own branch, leased to the tip it saw.
trusted
publish 1 "$out" >/dev/null || { echo "publish could not replace its own branch" >&2; exit 1; }
echo "ok: publish replaces an existing dual-pass branch under a lease"

# A patch that touches a protected file is refused by the policy, and nothing is pushed.
mkdir -p "$root/out-bad"
cp "$out/outcome" "$out/dual-pass-report.md" "$root/out-bad/"
cat > "$root/out-bad/change.patch" <<'PATCH'
diff --git a/Cargo.toml b/Cargo.toml
--- a/Cargo.toml
+++ b/Cargo.toml
@@ -1,3 +1,3 @@
 [package]
-name = "fixture"
+name = "tampered"
 version = "0.1.0"
PATCH
trusted
if publish 2 "$root/out-bad" >"$root/bad-publish.out" 2>&1; then
  echo "publish accepted a patch that touches Cargo.toml" >&2
  exit 1
fi
grep -q 'check-protected: refused' "$root/bad-publish.out" \
  || { echo "publish refused for the wrong reason" >&2; cat "$root/bad-publish.out" >&2; exit 1; }
if git -C "$remote" rev-parse -q --verify refs/heads/dual-pass/issue-2 >/dev/null; then
  echo "a refused patch was pushed" >&2
  exit 1
fi
grep -q 'gh issue edit' "$root/bad-publish.out" \
  || { echo "a refused green patch did not reach the hand-off" >&2; cat "$root/bad-publish.out" >&2; exit 1; }
echo "ok: publish refuses a patch that touches a protected file, and hands it to a person"

# A plan that needs a human pushes nothing when it has no change, and says so.
mkdir -p "$root/out-human"
printf 'the red gate rejected the plan\n' > "$root/out-human/reason.md"
printf '# Dual-pass report\n' > "$root/out-human/dual-pass-report.md"
printf 'needs-human-review\n' > "$root/out-human/outcome"
: > "$root/out-human/change.patch"
trusted
publish 3 "$root/out-human" >/dev/null || { echo "publish failed for a human-review outcome" >&2; exit 1; }
if git -C "$remote" rev-parse -q --verify refs/heads/dual-pass/issue-3-wip >/dev/null; then
  echo "a human-review plan with no change pushed a branch" >&2
  exit 1
fi
echo "ok: a human-review plan with no change pushes nothing"

# The hand-off, with a stub gh that records each call and the body of each comment. A
# change that cannot be published still labels the issue and comments the reason.
mkdir -p "$root/stub"
cat > "$root/stub/gh" <<'EOF'
#!/usr/bin/env bash
printf 'gh %s\n' "$*" >> "$GH_LOG"
prev=""
for arg in "$@"; do
  if [[ "$prev" == "--body-file" ]]; then
    cat "$arg" >> "$GH_LOG"
  fi
  prev="$arg"
done
exit 0
EOF
chmod +x "$root/stub/gh"

# handoff_out DIR OUTCOME PATCH: a plan's output with the outcome and the change named.
handoff_out() {
  mkdir -p "$1"
  printf '%s\n' "$2" > "$1/outcome"
  printf '# Dual-pass report\n' > "$1/dual-pass-report.md"
  printf 'the plan needs a person\n' > "$1/reason.md"
  cp "$3" "$1/change.patch"
}

# publish_live NAME OUT_DIR ISSUE [REMOTE]: publishes for real, with the stub gh, to the
# fixture remote or to REMOTE. The exit status is left in last_status.
publish_live() {
  local name="$1" out_dir="$2" issue="$3" target="${4:-$remote}"
  last_status=0
  trusted
  : > "$root/gh-$name.log"
  (cd "$root/trusted" && PATH="$root/stub:$PATH" GH_LOG="$root/gh-$name.log" ISSUE_NUMBER="$issue" \
    REPO=fixture/fixture REMOTE_URL="$target" POLICY="$root/scripts/issue-fix/check-protected.sh" \
    bash "$root/scripts/dual-pass/publish.sh" "$out_dir") > "$root/publish-$name.out" 2>&1 || last_status=$?
}

cat > "$root/stale.patch" <<'PATCH'
diff --git a/src/lib.rs b/src/lib.rs
--- a/src/lib.rs
+++ b/src/lib.rs
@@ -1 +1 @@
-not the file
+nope
PATCH

handoff_out "$root/out-stale" needs-human-review "$root/stale.patch"
publish_live stale "$root/out-stale" 41
[[ "$last_status" -eq 1 ]] || { echo "a patch that does not apply exited $last_status, expected 1" >&2; cat "$root/publish-stale.out" >&2; exit 1; }
grep -q -- '--add-label needs-human-review' "$root/gh-stale.log" \
  || { echo "a patch that does not apply left the issue unlabelled" >&2; cat "$root/gh-stale.log" >&2; exit 1; }
grep -q 'Publish stopped: the patch does not apply to main' "$root/gh-stale.log" \
  || { echo "a patch that does not apply posted no reason" >&2; cat "$root/gh-stale.log" >&2; exit 1; }
if git -C "$remote" rev-parse -q --verify refs/heads/dual-pass/issue-41-wip >/dev/null; then
  echo "a patch that does not apply was pushed" >&2
  exit 1
fi
echo "ok: a patch that does not apply labels the issue, comments the reason, and exits 1"

handoff_out "$root/out-policy" needs-human-review "$root/out-bad/change.patch"
publish_live policy "$root/out-policy" 42
[[ "$last_status" -eq 1 ]] || { echo "a refused change exited $last_status, expected 1" >&2; cat "$root/publish-policy.out" >&2; exit 1; }
grep -q 'check-protected: refused' "$root/publish-policy.out" \
  || { echo "a refused change was refused for another reason" >&2; cat "$root/publish-policy.out" >&2; exit 1; }
grep -q -- '--add-label needs-human-review' "$root/gh-policy.log" \
  || { echo "a refused change left the issue unlabelled" >&2; cat "$root/gh-policy.log" >&2; exit 1; }
grep -q 'Publish stopped: the path policy refused the change' "$root/gh-policy.log" \
  || { echo "a refused change posted no reason" >&2; cat "$root/gh-policy.log" >&2; exit 1; }
if git -C "$remote" rev-parse -q --verify refs/heads/dual-pass/issue-42-wip >/dev/null; then
  echo "a refused change was pushed" >&2
  exit 1
fi
echo "ok: a refused human-review change labels the issue, comments the reason, and exits 1"

handoff_out "$root/out-push" needs-human-review "$out/change.patch"
publish_live push "$root/out-push" 43 "$root/no-such-remote.git"
[[ "$last_status" -eq 1 ]] || { echo "a failed push exited $last_status, expected 1" >&2; cat "$root/publish-push.out" >&2; exit 1; }
grep -q -- '--add-label needs-human-review' "$root/gh-push.log" \
  || { echo "a failed push left the issue unlabelled" >&2; cat "$root/gh-push.log" >&2; exit 1; }
grep -q 'Publish stopped: could not push dual-pass/issue-43-wip' "$root/gh-push.log" \
  || { echo "a failed push posted no reason" >&2; cat "$root/gh-push.log" >&2; exit 1; }
echo "ok: a push that fails labels the issue, comments the reason, and exits 1"

publish_live nochange "$root/out-human" 3
[[ "$last_status" -eq 0 ]] || { echo "a human-review plan with no change exited $last_status, expected 0" >&2; exit 1; }
grep -q -- '--add-label needs-human-review' "$root/gh-nochange.log" \
  || { echo "a human-review plan with no change left the issue unlabelled" >&2; exit 1; }
grep -q 'the red gate rejected the plan' "$root/gh-nochange.log" \
  || { echo "a human-review plan with no change posted no reason" >&2; exit 1; }
echo "ok: a human-review plan with no change labels the issue and comments the reason"

echo "self-check ok, no model field, no endpoint in the runner"
if grep -R -n -E 'https?://api\.x\.ai|secrets\.XAI|openai\.com|anthropic\.com' scripts/dual-pass .github/workflows/dual-pass.yml; then
  echo "endpoint reference found" >&2
  exit 1
fi
echo "self-check ok"
