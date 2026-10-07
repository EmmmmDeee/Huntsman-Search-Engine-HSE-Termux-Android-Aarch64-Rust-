#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'

readonly REPO="https://github.com/EmmmmDeee/Huntsman-Search-Engine-HSE-Termux-Android-Aarch64-Rust-.git"
readonly TERMUX_PREFIX="${PREFIX:-/data/data/com.termux/files/usr}"

probe_dir=""
accept_dir=""

cleanup() {
  if [[ -n "${probe_dir:-}" && -d "$probe_dir" ]]; then
    rm -rf "$probe_dir"
  fi
  if [[ -n "${accept_dir:-}" && -d "$accept_dir" ]]; then
    rm -rf "$accept_dir"
  fi
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

die() {
  printf 'error: %s\n' "$*" >&2
  exit 1
}

if ! command -v pkg >/dev/null 2>&1; then
  die "Termux pkg command not found; run this installer inside Termux"
fi

case "$(uname -m)" in
  aarch64|arm64) ;;
  *) die "Huntsman Termux installer requires Android ARM64/aarch64 (got $(uname -m))" ;;
esac

case "$TERMUX_PREFIX" in
  /data/data/com.termux/files/usr*) ;;
  *) die "non-standard Termux PREFIX: $TERMUX_PREFIX" ;;
esac

# Refresh repository metadata before resolving the compiler and runtime tools.
pkg update -y

# Termux packages the Rust host standard library separately. A partial upgrade can
# leave rustc newer than rust-std-<host>, producing Cargo failures such as
# "crate std required to be available in rlib format" before Huntsman is compiled.
pkg install -y git rust clang curl coreutils

rust_host="$(rustc -vV | sed -n 's/^host: //p')"
[[ -n "$rust_host" ]] || die "unable to determine rustc host target"

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
[[ "$("$probe_dir/probe")" == "huntsman-rust-toolchain-ok" ]] ||
  die "Rust native toolchain probe did not execute correctly"
rm -rf "$probe_dir"
probe_dir=""

export HUNTSMAN_HIBP_NO_EMBED="${HUNTSMAN_HIBP_NO_EMBED:-1}"

# Keep Cargo intermediates across retries/upgrades instead of rebuilding them in
# a disposable default target directory. Respect an explicit caller override.
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$HOME/.cache/huntsman-recon-target}"

# Freeze the source revision before Cargo starts. Without an explicit revision,
# resolve main exactly once and build that immutable commit. This prevents a
# moving-main race where install.sh and the crate could come from different states.
install_rev="${HUNTSMAN_REV:-}"
if [[ -z "$install_rev" ]]; then
  install_ref=""
  if ! IFS=$'\t ' read -r install_rev install_ref < <(
    git ls-remote --exit-code "$REPO" refs/heads/main
  ); then
    die "unable to resolve repository main revision"
  fi
  [[ "$install_ref" == "refs/heads/main" ]] ||
    die "repository main revision was not returned"
fi

[[ "$install_rev" =~ ^[0-9a-fA-F]{40}$ ]] ||
  die "HUNTSMAN_REV must be a full 40-character Git commit SHA"

cargo install   --git "$REPO"   --rev "$install_rev"   --locked   --root "$TERMUX_PREFIX"   huntsman-recon

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

(
  cd "$accept_dir"
  timeout 30 "$installed" check >/dev/null
  timeout 30 "$installed" verify var/ledger.json >/dev/null
)

rm -rf "$accept_dir"
accept_dir=""

# Record provenance only after the installed binary passes acceptance.
PROVENANCE_FILE="$STATE_DIR/installed-revision"
PROVENANCE_TMP="$STATE_DIR/.installed-revision.$$"
{
  printf 'revision=%s\n' "$install_rev"
  printf 'repository=%s\n' "$REPO"
  printf 'rustc=%s\n' "$(rustc --version)"
  printf 'cargo_target_dir=%s\n' "$CARGO_TARGET_DIR"
} > "$PROVENANCE_TMP"
chmod 0600 "$PROVENANCE_TMP"
mv -f "$PROVENANCE_TMP" "$PROVENANCE_FILE"

grep -qx "revision=$install_rev" "$PROVENANCE_FILE" ||
  die "installed revision provenance check failed"

printf 'Huntsman installed and accepted: %s\n' "$installed"
printf 'Revision: %s\n' "$install_rev"
printf 'State directory: %s\n' "$STATE_DIR"
printf 'Runtime variables file: %s\n' "$ENV_FILE"
printf 'Install provenance: %s\n' "$PROVENANCE_FILE"
printf 'Next: huntsman-recon --help\n'
