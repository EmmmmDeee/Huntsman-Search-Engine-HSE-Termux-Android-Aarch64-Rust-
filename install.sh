#!/usr/bin/env bash
set -euo pipefail

REPO="https://github.com/EmmmmDeee/Huntsman-Search-Engine-HSE-Termux-Android-Aarch64-Rust-.git"
TERMUX_PREFIX="${PREFIX:-/data/data/com.termux/files/usr}"

if ! command -v pkg >/dev/null 2>&1; then
  printf 'error: Termux pkg command not found; run this installer inside Termux\n' >&2
  exit 1
fi

pkg install -y git rust clang

export HUNTSMAN_HIBP_NO_EMBED="${HUNTSMAN_HIBP_NO_EMBED:-1}"

cargo_args=(
  install
  --git "$REPO"
)

if [[ -n "${HUNTSMAN_REV:-}" ]]; then
  cargo_args+=(--rev "$HUNTSMAN_REV")
fi

cargo_args+=(
  --locked
  --root "$TERMUX_PREFIX"
  --force
  huntsman-recon
)

cargo "${cargo_args[@]}"

printf 'Huntsman installed: %s/bin/huntsman-recon\n' "$TERMUX_PREFIX"
