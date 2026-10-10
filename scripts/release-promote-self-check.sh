#!/usr/bin/env bash
# Offline self-check for the rolling `latest` promotion in .github/workflows/release.yml.
# The step's shell is read from the workflow, so this runs the code CI runs, against a stub
# `gh` that serves a published release from a fixture directory. It needs no network and no
# token. A re-run rebuilds the binary, and the rebuild's provenance (a build time and a run
# URL) differs from the published one, so the promotion must take the published bytes and
# never compare them with the rebuild.
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
workflow="$root/.github/workflows/release.yml"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

fail() { echo "release-promote self-check: FAIL: $*" >&2; exit 1; }

# The `run:` body of the promotion step, with its indentation removed.
awk '
  /^      - name: Move the rolling `latest`/ { inside = 1; next }
  inside && /^      - name: / { exit }
  inside && /^        run: \|$/ { run = 1; next }
  run { sub(/^          /, ""); print }' "$workflow" > "$work/step.sh"
[[ -s "$work/step.sh" ]] || fail "could not read the promotion step from $workflow"

mkdir -p "$work/bin"
cat > "$work/bin/gh" <<'GH'
#!/usr/bin/env bash
# A stub gh. It serves the published release from $FAKE_DIR/published and records the
# files that `gh release create latest` receives in $FAKE_DIR/created.
case "$*" in
  "api repos/"*"/git/ref/heads/main --jq .object.sha") echo "$GITHUB_SHA" ;;
  "api repos/"*"/commits/refs/tags/latest --jq .sha") echo "gh: Not Found (HTTP 404)" >&2; exit 1 ;;
  "api repos/"*"/releases/tags/"*) cat "$FAKE_DIR/release.json" ;;
  "release download "*) cp "$FAKE_DIR/published/${5}" "${7}/" ;;
  "release view latest"*) exit 1 ;;
  "api repos/"*"/git/ref/tags/latest") echo "gh: Not Found (HTTP 404)" >&2; exit 1 ;;
  "release create latest"*)
    for arg in "$@"; do
      if [ -f "$arg" ]; then cp "$arg" "$FAKE_DIR/created/"; fi
    done
    echo created ;;
  *) echo "unexpected gh call: $*" >&2; exit 2 ;;
esac
GH
chmod +x "$work/bin/gh"

# publish_fixture: the published release, and a rebuild whose provenance differs from it.
publish_fixture() {
  rm -rf "$work/published" "$work/dist" "$work/created" "$work/runner"
  mkdir -p "$work/published" "$work/dist" "$work/created" "$work/runner"
  printf 'BIN-v1\n' > "$work/published/huntsman-recon-test"
  (cd "$work/published" && sha256sum huntsman-recon-test | sed 's/ \+/  /' > huntsman-recon-test.sha256)
  printf '{"built_at":"2026-10-10T10:00:00Z","run":"run/1"}\n' > "$work/published/huntsman-recon-test.provenance.json"
  printf 'scan: clean\n' > "$work/published/key-scan-report.txt"
  printf '#!/bin/sh\n' > "$work/published/install-termux.sh"
  cp "$work/published/huntsman-recon-test" "$work/published/huntsman-recon-test.sha256" \
    "$work/published/key-scan-report.txt" "$work/published/install-termux.sh" "$work/dist/"
  printf '{"built_at":"2026-10-10T11:30:00Z","run":"run/2"}\n' > "$work/dist/huntsman-recon-test.provenance.json"
  write_release_json
}

# write_release_json: the digests GitHub would record for the files now in published/.
write_release_json() {
  python3 -I - "$work/published" > "$work/release.json" <<'PY'
import hashlib, json, os, sys

root = sys.argv[1]
assets = []
for name in sorted(os.listdir(root)):
    with open(os.path.join(root, name), "rb") as handle:
        digest = hashlib.sha256(handle.read()).hexdigest()
    assets.append({"name": name, "digest": "sha256:" + digest})
print(json.dumps({"prerelease": True, "draft": False, "assets": assets}))
PY
}

# promote: runs the step in the workflow's shape, from the directory that holds dist/.
promote() {
  local rc=0
  (cd "$work" && env -i PATH="$work/bin:/usr/bin:/bin" FAKE_DIR="$work" \
    ASSET=huntsman-recon-test TAG=main-abc1234 \
    GITHUB_SHA=abc1234abc1234abc1234abc1234abc1234abc1234 GITHUB_REPOSITORY=owner/repo \
    RUNNER_TEMP="$work/runner" GITHUB_OUTPUT="$work/output" GITHUB_STEP_SUMMARY="$work/summary" \
    GH_TOKEN=fixture bash "$work/step.sh") > "$work/stdout" 2> "$work/stderr" || rc=$?
  return "$rc"
}

: > "$work/output"
: > "$work/summary"

# A re-run whose rebuilt provenance differs from the published one is promoted, and the
# promoted files are the published bytes.
publish_fixture
promote || fail "a re-run with a rebuilt provenance was not promoted: $(cat "$work/stdout")"
grep -q '^moved=true$' "$work/output" || fail "the step did not report that latest moved"
for name in huntsman-recon-test huntsman-recon-test.sha256 huntsman-recon-test.provenance.json \
  key-scan-report.txt install-termux.sh; do
  cmp -s "$work/published/$name" "$work/created/$name" \
    || fail "latest carries a file other than the published $name"
done
echo "ok: a re-run promotes the published bytes, not the rebuild"

# A file whose bytes differ from the digest GitHub recorded is refused. The digests stay the
# published ones, so the download is what changed.
publish_fixture
printf 'tampered\n' > "$work/published/huntsman-recon-test.provenance.json"
if promote; then fail "a download that differs from its published digest was promoted"; fi
grep -q 'is not the published main-abc1234 digest' "$work/stdout" \
  || fail "the digest refusal did not name the published digest: $(cat "$work/stdout")"
echo "ok: a download that differs from its published digest is refused"

# A binary that matches its digest but not its own .sha256 is refused.
publish_fixture
printf 'BIN-v2\n' > "$work/published/huntsman-recon-test"
write_release_json
if promote; then fail "a binary that does not match its own .sha256 was promoted"; fi
grep -q 'does not match its own huntsman-recon-test.sha256' "$work/stdout" \
  || fail "the checksum refusal did not name the .sha256 file: $(cat "$work/stdout")"
echo "ok: a binary that does not match its own .sha256 is refused"

echo "release-promote self-check: ok"
