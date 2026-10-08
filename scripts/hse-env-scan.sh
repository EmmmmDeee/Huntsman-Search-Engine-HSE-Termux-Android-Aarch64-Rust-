#!/data/data/com.termux/files/usr/bin/bash
(
set -uo pipefail
TIMEOUT="${HSE_TIMEOUT:-120}"
MAX_RETRIES="${HSE_MAX_RETRIES:-3}"
MAX_INPUT="${HSE_MAX_INPUT:-268435456}"
TMPDIR="${TMPDIR:-/tmp}"
HOME="${HOME:-$TMPDIR}"
WORKDIR="$(mktemp -d "${TMPDIR}/hse.XXXXXX")" || exit 1
BIN="${WORKDIR}/engine"
cleanup() {
  if [[ -n "${WORKDIR:-}" && -d "${WORKDIR}" ]]; then
    rm -rf "${WORKDIR}"
  fi
}
trap cleanup EXIT
trap 'cleanup; exit 130' INT
trap 'cleanup; exit 143' TERM
printf 'WARN: libc and rustls crates not satisfiable because stdin rustc cannot link external crates; std only\n' >&2
printf 'WARN: exec not used so the EXIT trap can purge WORKDIR\n' >&2
has() { command -v "$1" >/dev/null 2>&1; }
ensure_rust() {
  if has rustc; then
    return 0
  fi
  if ! has pkg; then
    printf 'phase: rust-missing-no-pkg\n' >&2
    return 1
  fi
  local attempt=0
  while [[ "${attempt}" -lt "${MAX_RETRIES}" ]]; do
    if timeout "${TIMEOUT}" pkg install -y rust && has rustc; then
      return 0
    fi
    attempt=$((attempt + 1))
    sleep "${attempt}"
  done
  return 1
}
ROOT="${1:-${HSE_ROOT:-${HOME}/hse}}"
INCLUDE_TEST="${HSE_INCLUDE_TEST:-0}"
INCLUDE_EXAMPLE="${HSE_INCLUDE_EXAMPLE:-0}"
INCLUDE_COMMENT="${HSE_INCLUDE_COMMENT:-0}"
INCLUDE_DOCS="${HSE_INCLUDE_DOCS:-0}"
if [[ ! -d "${ROOT}" ]]; then
  printf 'phase: root-missing %s\n' "${ROOT}" >&2
  exit 2
fi
printf 'phase: toolchain\n' >&2
if ! ensure_rust; then
  exit 1
fi
HOST_TRIPLE="$(rustc -vV 2>/dev/null | awk '/^host:/ {print $2; exit}')"
if [[ "${HOST_TRIPLE}" != "aarch64-linux-android" ]]; then
  printf 'WARN: aarch64-linux-android not selected because rustc host is %s\n' "${HOST_TRIPLE:-unknown}" >&2
fi
printf 'phase: compile\n' >&2
if ! timeout "${TIMEOUT}" rustc -O --edition 2021 -o "${BIN}" - <<'RUST_BEGIN'
echo placeholder
RUST_BEGIN
then
  printf 'phase: compile-failed\n' >&2
  exit 1
fi
exit 0
)
