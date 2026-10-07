#!/usr/bin/env bash
set -euo pipefail

REPO="https://github.com/EmmmmDeee/Huntsman-Search-Engine-HSE-Termux-Android-Aarch64-Rust-.git"
TERMUX_PREFIX="${PREFIX:-/data/data/com.termux/files/usr}"

if ! command -v pkg >/dev/null 2>&1; then
  printf 'error: Termux pkg command not found; run this installer inside Termux\n' >&2
  exit 1
fi

case "$(uname -m)" in
  aarch64|arm64) ;;
  *)
    printf 'error: Huntsman Termux installer requires Android ARM64/aarch64 (got %s)\n' "$(uname -m)" >&2
    exit 1
    ;;
esac

case "$TERMUX_PREFIX" in
  /data/data/com.termux/files/usr*) ;;
  *)
    printf 'error: non-standard Termux PREFIX: %s\n' "$TERMUX_PREFIX" >&2
    exit 1
    ;;
esac

# Refresh repository metadata before resolving the compiler and runtime tools.
pkg update -y

# Termux packages the Rust host standard library separately. A partial upgrade can
# leave rustc newer than rust-std-<host>, producing Cargo failures such as
# "crate std required to be available in rlib format" before Huntsman is compiled.
pkg install -y git rust clang curl coreutils

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

# Keep Cargo intermediates across retries/upgrades instead of rebuilding them in
# a disposable default target directory. Respect an explicit caller override.
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

STATE_DIR="${HUNTSMAN_HOME:-$HOME/.huntsman}"
mkdir -p "$STATE_DIR"
chmod 0700 "$STATE_DIR"

ENV_FILE="${HUNTSMAN_ENV_FILE:-$HOME/.huntsman.env}"
if [[ ! -e "$ENV_FILE" ]]; then
  old_umask="$(umask)"
  umask 077
  : > "$ENV_FILE"
  umask "$old_umask"
fi
chmod 0600 "$ENV_FILE"

installed="$TERMUX_PREFIX/bin/huntsman-recon"
accept_dir="$(mktemp -d "${TMPDIR:-$TERMUX_PREFIX/tmp}/huntsman-install-accept.XXXXXX")"
cleanup_accept() { rm -rf "$accept_dir"; }
trap cleanup_accept EXIT

(
  cd "$accept_dir"
  timeout 30 "$installed" check >/dev/null
  timeout 30 "$installed" verify var/ledger.json >/dev/null
)

rm -rf "$accept_dir"
trap - EXIT

printf 'Huntsman installed and accepted: %s\n' "$installed"
printf 'State directory: %s\n' "$STATE_DIR"
printf 'Runtime variables file: %s\n' "$ENV_FILE"
printf 'Next: huntsman-recon --help\n'
