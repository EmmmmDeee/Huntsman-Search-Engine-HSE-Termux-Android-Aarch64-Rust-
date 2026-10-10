#!/usr/bin/env bash
# shellcheck disable=SC2016 # printf formats carry literal Markdown backticks
set -Eeuo pipefail
root=$(mktemp -d)
cp -a scripts "$root/scripts"
mkdir -p "$root/src" "$root/tests" "$root/.github/workflows"
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

body="$root/issue.md"
cat > "$body" <<'EOF'
```json
{
  "targets": [
    {"path": "src/lib.rs", "signatures": ["pub fn answer() -> i32"]}
  ],
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
grep -q 'Red class: assertion-failed' "$out/dual-pass-report.md"
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

# Publish: from a clone of main that the plan never touched, against a bare remote.
# Publish runs the policy from the issue-fix scripts, which the fixture copied.
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
echo "ok: publish refuses a patch that touches a protected file"

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

echo "self-check ok, no model field, no endpoint in the runner"
if grep -R -n -E 'https?://api\.x\.ai|secrets\.XAI|openai\.com|anthropic\.com' scripts/dual-pass .github/workflows/dual-pass.yml; then
  echo "endpoint reference found" >&2
  exit 1
fi
echo "self-check ok"
