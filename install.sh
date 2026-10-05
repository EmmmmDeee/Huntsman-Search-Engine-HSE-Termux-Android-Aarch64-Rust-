#!/usr/bin/env bash
set -euo pipefail

REPO="https://github.com/EmmmmDeee/Huntsman-Search-Engine-HSE-Termux-Android-Aarch64-Rust-.git"
TERMUX_PREFIX="${PREFIX:-/data/data/com.termux/files/usr}"

if ! command -v pkg >/dev/null 2>&1; then
  printf 'error: Termux pkg command not found; run this installer inside Termux\n' >&2
  exit 1
fi

# Termux packages the Rust host standard library separately. Installing/upgrading
# `rust` alone can leave rustc newer than rust-std-<host>, which makes Cargo
# build scripts and proc macros fail with "crate std required ... in rlib format".
pkg install -y git rust clang

rust_host="$(rustc -vV | sed -n 's/^host: //p')"
if [[ -z "$rust_host" ]]; then
  printf 'error: unable to determine rustc host target\n' >&2
  exit 1
fi

rust_std_pkg="rust-std-${rust_host}"
pkg install -y "$rust_std_pkg"

rust_target_libdir="$(rustc --print target-libdir)"
if [[ ! -d "$rust_target_libdir" ]] || ! find "$rust_target_libdir" -maxdepth 1 -type f -name '*.rlib' -print -quit | grep -q .; then
  printf 'error: Rust host stdlib rlibs are unavailable after installing %s\n' "$rust_std_pkg" >&2
  printf '       rustc: %s\n' "$(rustc --version)" >&2
  printf '       target libdir: %s\n' "$rust_target_libdir" >&2
  exit 1
fi

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
