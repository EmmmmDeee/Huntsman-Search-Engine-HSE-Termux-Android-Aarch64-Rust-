#!/usr/bin/env bash
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
if python3 "$root/scripts/dual-pass/plan.py" "$root" "$root/bad.md"; then
  echo "model field was accepted" >&2
  exit 1
fi

echo "reject protected target"
printf '```json\n{"targets":[{"path":"Cargo.toml","signatures":[]}],"new_tests":[{"path":"tests/generated_1.rs","signatures":[],"source":"assert!"}],"patches":[{"diff":"","ops":[]}]}\n```\n' > "$root/bad2.md"
if python3 "$root/scripts/dual-pass/plan.py" "$root" "$root/bad2.md"; then
  echo "protected target was accepted" >&2
  exit 1
fi

echo "offline red-green"
set +e
(
  cd "$root"
  ISSUE_NUMBER=1 REPO=fixture/fixture DUAL_PASS_OFFLINE=1 DUAL_PASS_BODY="$body" \
    bash scripts/dual-pass/run.sh
)
status=$?
set -e
if [[ "$status" -ne 0 ]]; then
  echo "runner failed" >&2
  cat "$root/dual-pass-report.md" >&2 || true
  exit 1
fi
grep -q 'llm=False' "$root/dual-pass-report.md"
grep -q 'No LLM API' "$root/dual-pass-report.md"
python3 - <<PY
import pathlib
text = pathlib.Path("$root/src/lib.rs").read_text()
assert "1" in text, text
print("implementation green")
PY

echo "ast fallback"
printf 'pub fn answer() -> i32 {\n    0\n}\n' > "$root/src/lib.rs"
(
cd "$root"
python3 - <<'PY' | python3 scripts/dual-pass/apply_change.py
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
if grep -R -n -E 'https?://api\.x\.ai|secrets\.XAI|openai\.com|anthropic\.com' scripts/dual-pass .github/workflows/dual-pass.yml; then
  echo "endpoint reference found" >&2
  exit 1
fi
echo "self-check ok"
