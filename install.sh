#!/usr/bin/env bash
set -euo pipefail

REPO="https://github.com/EmmmmDeee/Huntsman-Search-Engine-HSE-Termux-Android-Aarch64-Rust-.git"
TERMUX_PREFIX="${PREFIX:-/data/data/com.termux/files/usr}"

if ! command -v pkg >/dev/null 2>&1; then
  printf 'error: Termux pkg command not found; run this installer inside Termux\n' >&2
  exit 1
fi

# Termux packages the Rust host standard library separately. A partial upgrade can
# leave rustc newer than rust-std-<host>, producing Cargo failures such as
# "crate std required to be available in rlib format" before Huntsman is compiled.
pkg install -y git rust clang

rust_host="$(rustc -vV | sed -n 's/^host: //p')"
if [[ -z "$rust_host" ]]; then
  printf 'error: unable to determine rustc host target\n' >&2
  exit 1
fi

rust_std_pkg="rust-std-${rust_host}"
# Ask apt to resolve the compiler and its stdlib together, repairing half-upgraded
# toolchains instead of assuming the existing rust package is coherent.
pkg install -y rust "$rust_std_pkg"

rust_pkg_version="$(dpkg-query -W -f='${Version}' rust 2>/dev/null || true)"
rust_std_version="$(dpkg-query -W -f='${Version}' "$rust_std_pkg" 2>/dev/null || true)"
if [[ -z "$rust_pkg_version" || -z "$rust_std_version" || "$rust_pkg_version" != "$rust_std_version" ]]; then
  printf 'error: Rust compiler/stdlib package versions are not aligned\n' >&2
  printf '       rust: %s\n' "${rust_pkg_version:-missing}" >&2
  printf '       %s: %s\n' "$rust_std_pkg" "${rust_std_version:-missing}" >&2
  exit 1
fi

rust_target_libdir="$(rustc --print target-libdir)"
if [[ ! -d "$rust_target_libdir" ]] || ! find "$rust_target_libdir" -maxdepth 1 -type f -name '*.rlib' -print -quit | grep -q .; then
  printf 'error: Rust host stdlib rlibs are unavailable after installing %s\n' "$rust_std_pkg" >&2
  printf '       rustc: %s\n' "$(rustc --version)" >&2
  printf '       target libdir: %s\n' "$rust_target_libdir" >&2
  exit 1
fi

# Compile and run a native probe. This tests the property Cargo build scripts need:
# rustc must be able to consume the installed host stdlib, not merely find files.
probe_dir="$(mktemp -d "${TMPDIR:-$TERMUX_PREFIX/tmp}/huntsman-rust-probe.XXXXXX")"
trap 'rm -rf "$probe_dir"' EXIT
cat > "$probe_dir/probe.rs" <<'RS'
fn main() {
    println!("huntsman-rust-toolchain-ok");
}
RS
if ! rustc "$probe_dir/probe.rs" -o "$probe_dir/probe"; then
  printf 'error: Rust compiler cannot build a native std-linked probe\n' >&2
  printf '       rustc: %s\n' "$(rustc --version)" >&2
  printf '       %s: %s\n' "$rust_std_pkg" "$rust_std_version" >&2
  exit 1
fi
if [[ "$("$probe_dir/probe")" != "huntsman-rust-toolchain-ok" ]]; then
  printf 'error: Rust native toolchain probe did not execute correctly\n' >&2
  exit 1
fi
rm -rf "$probe_dir"
trap - EXIT

export HUNTSMAN_HIBP_NO_EMBED="${HUNTSMAN_HIBP_NO_EMBED:-1}"

# Reuse intermediates after an interrupted build or a revision update. Preserve
# an explicit caller-selected cache. Cargo checks its installation metadata and
# skips an already installed matching revision without --force.
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$HOME/.cache/huntsman-recon-target}"

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
  huntsman-recon
)

cargo "${cargo_args[@]}"

printf 'Huntsman installed: %s/bin/huntsman-recon\n' "$TERMUX_PREFIX"
