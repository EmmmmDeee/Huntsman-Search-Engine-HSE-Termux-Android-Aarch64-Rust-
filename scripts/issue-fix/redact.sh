#!/usr/bin/env bash
# redact.sh FILE
#
# Replaces the model key, and anything shaped like an Anthropic key, in FILE. Run
# it in the model's own step, the only step that holds ANTHROPIC_API_KEY. The key
# is never printed. A key encoded some other way is not caught, which is why the
# artifact is limited to the redacted output and the patch.
set -euo pipefail

file="${1:?usage: redact.sh FILE}"
[[ -f "$file" ]] || exit 0

python3 -I - "$file" <<'PY'
import os
import re
import sys

path = sys.argv[1]
with open(path, encoding="utf-8", errors="surrogateescape") as handle:
    text = handle.read()
key = os.environ.get("ANTHROPIC_API_KEY", "")
if key:
    text = text.replace(key, "[redacted]")
text = re.sub(r"sk-ant-[A-Za-z0-9_-]+", "[redacted]", text)
with open(path, "w", encoding="utf-8", errors="surrogateescape") as handle:
    handle.write(text)
PY
