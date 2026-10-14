#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'

readonly REPO="https://github.com/EmmmmDeee/Huntsman-Search-Engine-HSE-Termux-Android-Aarch64-Rust-.git"
readonly TERMUX_PREFIX="${PREFIX:-/data/data/com.termux/files/usr}"
readonly REPO_SLUG="EmmmmDeee/Huntsman-Search-Engine-HSE-Termux-Android-Aarch64-Rust-"
readonly ASSET="huntsman-recon-aarch64-linux-android"
# Where the binary goes: $INSTALL_ROOT/bin, for a prebuilt and a source build alike.
readonly INSTALL_ROOT="${HUNTSMAN_INSTALL_ROOT:-$TERMUX_PREFIX}"

probe_dir=""
accept_dir=""
legacy_download=""
release_dir=""
stage=""

cleanup() {
  if [[ -n "${probe_dir:-}" && -d "$probe_dir" ]]; then
    rm -rf "$probe_dir"
  fi
  if [[ -n "${accept_dir:-}" && -d "$accept_dir" ]]; then
    rm -rf "$accept_dir"
  fi
  if [[ -n "${legacy_download:-}" ]]; then
    rm -f "$legacy_download"
  fi
  if [[ -n "${release_dir:-}" && -d "$release_dir" ]]; then
    rm -rf "$release_dir"
  fi
  if [[ -n "${stage:-}" ]]; then
    rm -f "$stage"
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

# Product line. HUNTSMAN_REV installs huntsman-recon. Everything else named
# hse installs legacy-hse, then stops. Recon setup below does not run.
is_hse_update() {
  [[ -z "${HUNTSMAN_REV:-}" ]] || return 1
  [[ -n "${HSE_REF:-}${HSE_REQUIRE_SHA:-}" ]] && return 0
  [[ "${HUNTSMAN_LEGACY_CALLER:-}" == "hse" ]] && return 0
  local root="${HUNTSMAN_PROC_ROOT:-/proc}" pid="$$" ppid cmd
  local _
  for _ in 1 2 3 4 5; do
    [[ -r "$root/$pid/status" ]] || return 1
    ppid="$(awk '/^PPid:/ { print $2; exit }' "$root/$pid/status" 2>/dev/null || true)"
    [[ -n "$ppid" && "$ppid" != "0" && "$ppid" != "$pid" ]] || return 1
    pid="$ppid"
    [[ -r "$root/$pid/cmdline" ]] || continue
    cmd="$(tr '\0' '\n' < "$root/$pid/cmdline" | head -n 1)"
    [[ "${cmd##*/}" == "hse" ]] && return 0
  done
  return 1
}

install_legacy_hse() {
  printf 'hse update: installing legacy-hse, not huntsman-recon.\n'
  local installer="${HUNTSMAN_LEGACY_CHANNEL_INSTALLER:-}" downloaded=""
  if [[ -z "$installer" ]]; then
    command -v curl >/dev/null 2>&1 || die "curl is required for the legacy hse handoff"
    command -v mktemp >/dev/null 2>&1 || die "mktemp is required for the legacy hse handoff"
    downloaded="$(mktemp "${TMPDIR:-$TERMUX_PREFIX/tmp}/huntsman-legacy-install.XXXXXX")"
    legacy_download="$downloaded"
    installer="$downloaded"
    curl -fsSL --proto '=https' \
      "https://raw.githubusercontent.com/EmmmmDeee/Huntsman-Search-Engine-HSE-Termux-Android-Aarch64-Rust-/legacy-hse/install.sh" \
      -o "$installer"
  fi
  set +e
  env -u HSE_REQUIRE_SHA HSE_REF=legacy-hse bash "$installer"
  local status=$?
  set -e
  [[ -z "$downloaded" ]] || rm -f "$downloaded"
  legacy_download=""
  (( status == 0 )) || die "legacy hse installer exited $status"
  printf 'legacy-hse installed; huntsman-recon was not substituted for hse.\n'
}

if is_hse_update; then
  install_legacy_hse
  exit 0
fi

# Refresh repository metadata, then install what every path needs: git resolves
# main, curl and coreutils fetch and verify a prebuilt build.
pkg update -y
pkg install -y git curl coreutils

installed="$INSTALL_ROOT/bin/huntsman-recon"

build_sha_of() {
  local sha
  sha="$(timeout 30 "$1" build-sha 2>/dev/null)" || sha=""
  printf '%s' "$sha"
}

# Offline acceptance: `check` writes var/*.json in a disposable directory and
# `verify` reads the ledger back, with bounded wall-clock time.
accept_binary() {
  local status=0
  accept_dir="$(mktemp -d "${TMPDIR:-$TERMUX_PREFIX/tmp}/huntsman-install-accept.XXXXXX")"
  (
    cd "$accept_dir" &&
      timeout 30 "$1" check >/dev/null &&
      timeout 30 "$1" verify var/ledger.json >/dev/null
  ) || status=1
  rm -rf "$accept_dir"
  accept_dir=""
  return "$status"
}

# Freeze the source revision before anything is fetched. Without an explicit
# revision, resolve main exactly once. This prevents a moving-main race where
# install.sh and the binary could come from different states.
install_rev="${HUNTSMAN_REV:-}"
if [[ -z "$install_rev" ]]; then
  install_ref=""
  # A temp file, not process substitution: this host may not have /dev/fd.
  rev_file="$(mktemp "${TMPDIR:-$TERMUX_PREFIX/tmp}/huntsman-main-rev.XXXXXX")"
  if ! git ls-remote --exit-code "$REPO" refs/heads/main > "$rev_file"; then
    rm -f "$rev_file"
    die "unable to resolve repository main revision"
  fi
  IFS=$'\t ' read -r install_rev install_ref < "$rev_file" || true
  rm -f "$rev_file"
  [[ "$install_ref" == "refs/heads/main" ]] ||
    die "repository main revision was not returned"
fi

[[ "$install_rev" =~ ^[0-9a-fA-F]{40}$ ]] ||
  die "HUNTSMAN_REV must be a full 40-character Git commit SHA"
install_rev="${install_rev,,}"

# --- Prebuilt: the checksum-verified release build of a main commit ---------
#
# CI publishes main-<sha7> with the binary and its .sha256 for a main commit
# that is still the head of main when its build finishes. A missing asset means
# that commit has no build; any other failure after the download is fatal.

fetch_release_asset() { # TAG NAME DIR: 0 = downloaded into DIR, 1 = not published
  curl -fsSL --proto '=https' -o "$3/$2" \
    "https://github.com/${REPO_SLUG}/releases/download/$1/$2" 2>/dev/null
}

# The newest main commit, at most 30 back from the head, that has a published
# build. Prints its full SHA, or nothing when none has one or GitHub cannot be read.
newest_published_rev() {
  local depth sha
  release_dir="$(mktemp -d "${TMPDIR:-$TERMUX_PREFIX/tmp}/huntsman-release.XXXXXX")"
  for ((depth = 1; depth < 30; depth++)); do
    sha="$(curl -fsSL --proto '=https' -H 'Accept: application/vnd.github.sha' \
      "https://api.github.com/repos/${REPO_SLUG}/commits/main~${depth}" 2>/dev/null)" || break
    [[ "$sha" =~ ^[0-9a-f]{40}$ ]] || break
    if fetch_release_asset "main-${sha:0:7}" "$ASSET.sha256" "$release_dir"; then
      printf '%s' "$sha"
      break
    fi
  done
  rm -rf "$release_dir"
  release_dir=""
}

install_prebuilt() { # REV: 0 = installed, 1 = REV has no published build
  local rev="$1" tag="main-${1:0:7}" want got staged_sha
  release_dir="$(mktemp -d "${TMPDIR:-$TERMUX_PREFIX/tmp}/huntsman-release.XXXXXX")"
  if ! fetch_release_asset "$tag" "$ASSET.sha256" "$release_dir"; then
    rm -rf "$release_dir"
    release_dir=""
    return 1
  fi
  printf 'Downloading verified build %s\n' "$tag"
  fetch_release_asset "$tag" "$ASSET" "$release_dir" || die "release $tag lists no $ASSET; not installing"
  ( cd "$release_dir" && sha256sum -c --quiet "$ASSET.sha256" ) ||
    die "sha256 mismatch for $tag; not installing"
  chmod 0755 "$release_dir/$ASSET"

  staged_sha="$(build_sha_of "$release_dir/$ASSET")"
  [[ "$staged_sha" == "$rev" ]] ||
    die "build $tag reports build-sha ${staged_sha:-<none>}, expected $rev; not installing"
  accept_binary "$release_dir/$ASSET" ||
    die "build $tag failed offline acceptance; $installed left unchanged"

  # Stage on the destination filesystem, re-check the bytes there, then rename
  # into place, so an interrupted install never leaves a half-written binary.
  mkdir -p "$INSTALL_ROOT/bin"
  stage="$INSTALL_ROOT/bin/.huntsman-recon.install.$$"
  install -m 0755 "$release_dir/$ASSET" "$stage" ||
    die "could not stage $stage; $installed left unchanged"
  want="$(cut -d' ' -f1 "$release_dir/$ASSET.sha256")"
  got="$(sha256sum "$stage" | cut -d' ' -f1)"
  [[ -n "$want" && "$got" == "$want" ]] ||
    die "staged copy failed the sha256 check; $installed left unchanged"
  mv -f "$stage" "$installed" ||
    die "could not move $stage into place; $installed left unchanged"
  stage=""
  rm -rf "$release_dir"
  release_dir=""
  install_source="prebuilt $tag"
}

# --- Source build: only when no published build fits ------------------------

prepare_rust_toolchain() {
  # Termux packages the Rust host standard library separately. A partial upgrade can
  # leave rustc newer than rust-std-<host>, producing Cargo failures such as
  # "crate std required to be available in rlib format" before Huntsman is compiled.
  pkg install -y git rust clang curl coreutils

  local rust_host rust_std_pkg rust_pkg_version rust_std_version rust_target_libdir rlib_found
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
  rlib_found=""
  if [[ -d "$rust_target_libdir" ]]; then
    # A failed find must still reach the diagnostic below, so it is not allowed to end the script.
    rlib_found="$(find "$rust_target_libdir" -maxdepth 1 -type f -name '*.rlib' -print -quit)" || rlib_found=""
  fi
  if [[ -z "$rlib_found" ]]; then
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
}

install_recon() {
  cargo install   --git "$REPO"   --rev "$install_rev"   --locked   --root "$INSTALL_ROOT"   "$@"   huntsman-recon
}

build_from_source() {
  prepare_rust_toolchain

  export HUNTSMAN_HIBP_NO_EMBED="${HUNTSMAN_HIBP_NO_EMBED:-1}"
  # Keep Cargo intermediates across retries/upgrades instead of rebuilding them in
  # a disposable default target directory. Respect an explicit caller override.
  export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$HOME/.cache/huntsman-recon-target}"
  # Embed the resolved commit so `huntsman-recon build-sha` and diagnostics name the
  # source on the phone, the same way CI and release builds do.
  export HUNTSMAN_BUILD_SHA="$install_rev"

  local installed_sha
  install_recon
  # Cargo skips the build when this revision is already recorded as installed,
  # even if that binary was built without provenance. The binary's own
  # build-sha decides: on a mismatch, rebuild once with --force.
  installed_sha="$(build_sha_of "$installed")"
  if [[ "$installed_sha" != "$HUNTSMAN_BUILD_SHA" ]]; then
    printf 'Installed binary reports build-sha %s, expected %s; rebuilding.\n' \
      "${installed_sha:-<none>}" "$HUNTSMAN_BUILD_SHA"
    install_recon --force
    installed_sha="$(build_sha_of "$installed")"
  fi
  [[ "$installed_sha" == "$HUNTSMAN_BUILD_SHA" ]] ||
    die "installed binary reports build-sha ${installed_sha:-<none>}, expected $HUNTSMAN_BUILD_SHA"
  accept_binary "$installed" || die "installed binary failed offline acceptance"
  install_source="source $(rustc --version)"
}

# --- Choose: prebuilt first, source build only when no build fits -----------

install_source=""
if [[ "${HUNTSMAN_FROM_SOURCE:-}" == 1 ]]; then
  printf 'HUNTSMAN_FROM_SOURCE=1: building %s from source.\n' "$install_rev"
elif ! install_prebuilt "$install_rev" && [[ -z "${HUNTSMAN_REV:-}" ]]; then
  # The head of main has no build yet (CI is still building it, or a newer
  # push superseded it). Install the newest main commit that has one.
  newer_rev="$(newest_published_rev)"
  if [[ -n "$newer_rev" ]]; then
    printf 'main is at %s, which has no published build yet; installing main-%s.\n' \
      "${install_rev:0:7}" "${newer_rev:0:7}"
    install_rev="$newer_rev"
    install_prebuilt "$install_rev" || die "main-${install_rev:0:7} disappeared while installing"
  fi
fi
if [[ -z "$install_source" ]]; then
  [[ "${HUNTSMAN_FROM_SOURCE:-}" == 1 ]] ||
    printf 'No published build for %s; building from source.\n' "${install_rev:0:7}"
  build_from_source
fi

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

# Record provenance only after the installed binary passes acceptance.
PROVENANCE_FILE="$STATE_DIR/installed-revision"
PROVENANCE_TMP="$STATE_DIR/.installed-revision.$$"
{
  printf 'revision=%s\n' "$install_rev"
  printf 'repository=%s\n' "$REPO"
  printf 'installed_from=%s\n' "$install_source"
  if [[ -n "${CARGO_TARGET_DIR:-}" ]]; then
    printf 'cargo_target_dir=%s\n' "$CARGO_TARGET_DIR"
  fi
} > "$PROVENANCE_TMP"
chmod 0600 "$PROVENANCE_TMP"
mv -f "$PROVENANCE_TMP" "$PROVENANCE_FILE"

grep -qx "revision=$install_rev" "$PROVENANCE_FILE" ||
  die "installed revision provenance check failed"

printf 'Huntsman installed and accepted: %s\n' "$installed"
printf 'Revision: %s (%s)\n' "$install_rev" "$install_source"
printf 'State directory: %s\n' "$STATE_DIR"
printf 'Runtime variables file: %s\n' "$ENV_FILE"
printf 'Install provenance: %s\n' "$PROVENANCE_FILE"
printf 'Next: huntsman-recon --help\n'
