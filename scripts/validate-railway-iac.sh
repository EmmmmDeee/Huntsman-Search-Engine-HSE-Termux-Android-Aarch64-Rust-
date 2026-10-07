#!/usr/bin/env bash
set -euo pipefail

root="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
src="$root/.railway/railway.ts"
[[ -f "$src" ]] || { echo "railway-iac: missing $src" >&2; exit 1; }

for tool in node npm mktemp; do
  command -v "$tool" >/dev/null 2>&1 || {
    echo "railway-iac: missing required tool: $tool" >&2
    exit 1
  }
done

node_major="$(node -p 'process.versions.node.split(".")[0]')"
if [[ "$node_major" -lt 22 ]]; then
  echo "railway-iac: Node.js 22+ required (found $(node --version))" >&2
  exit 1
fi

tmp="$(mktemp -d "${TMPDIR:-/tmp}/huntsman-railway-iac.XXXXXX")"
trap 'rm -rf "$tmp"' EXIT

cp "$src" "$tmp/railway.ts"
cat > "$tmp/package.json" <<'JSON'
{
  "private": true,
  "type": "module",
  "dependencies": {
    "railway": "3.12.0",
    "typescript": "5.9.3"
  }
}
JSON

cat > "$tmp/tsconfig.json" <<'JSON'
{
  "compilerOptions": {
    "target": "ES2022",
    "module": "NodeNext",
    "moduleResolution": "NodeNext",
    "strict": true,
    "noEmit": true,
    "skipLibCheck": false
  },
  "files": ["railway.ts"]
}
JSON

(
  cd "$tmp"
  npm install --ignore-scripts --no-audit --no-fund --package-lock=false >/dev/null
  ./node_modules/.bin/tsc -p tsconfig.json
)

printf 'railway-iac: PASS sdk=3.12.0 typescript=5.9.3 node=%s\n' "$(node --version)"
