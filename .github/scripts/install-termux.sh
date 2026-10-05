#!/usr/bin/env bash
# install-termux.sh: install a prebuilt aarch64 Huntsman binary on Termux.
#
# Default (HUNTSMAN_CHANNEL=hse): the legacy `hse` binary, which still runs
# person lookups, into $PREFIX/bin/hse. Release HSE_TAG, default main-7dca720
# (the newest legacy hse build).
#
# Opt-in (HUNTSMAN_CHANNEL=recon): the huntsman-recon pre-release, an
# in-progress replacement with a subset of person lookups, into
# $PREFIX/bin/huntsman-recon. Release HUNTSMAN_RELEASE_TAG, default: the
# main-<sha7> release this script was attached to.
#
# Both channels download the binary and its .sha256 over HTTPS, verify the
# sha256 and install only on a match. The verified binary is staged next to
# the destination in $PREFIX/bin, re-checked there, then renamed into place,
# so an interrupted install or a full disk never leaves a missing or
# half-written binary behind.
set -euo pipefail

REPO="EmmmmDeee/Huntsman-Search-Engine-HSE-Termux-Android-Aarch64-Rust-"
RECON_TAG_DEFAULT="@RECON_TAG@"
CHANNEL="${HUNTSMAN_CHANNEL:-hse}"

die() { echo "install-termux: $*" >&2; exit 1; }

case "$CHANNEL" in
  hse)
    TAG="${HSE_TAG:-main-7dca720}"
    ASSET="hse-aarch64-linux-android"
    DEST_NAME="hse"
    ;;
  recon)
    TAG="${HUNTSMAN_RELEASE_TAG:-$RECON_TAG_DEFAULT}"
    ASSET="huntsman-recon-aarch64-linux-android"
    DEST_NAME="huntsman-recon"
    echo "Note: huntsman-recon provides partial person lookups; it does not replace the full HSE server."
    ;;
  *) die "HUNTSMAN_CHANNEL must be 'hse' (default) or 'recon'" ;;
esac
[[ "$TAG" =~ ^(latest|main-[0-9a-f]{7}|v[0-9]+\.[0-9]+\.[0-9]+)$ ]] || die "bad release tag '$TAG'"
[ -n "${PREFIX:-}" ] && [ -d "$PREFIX/bin" ] || die "\$PREFIX/bin not found; run this inside Termux"
case "$(uname -m)" in aarch64 | arm64) ;; *) die "these binaries are aarch64 only (got $(uname -m))" ;; esac
for c in curl sha256sum install mktemp mv cut cmp; do
  command -v "$c" >/dev/null 2>&1 || die "missing $c (pkg install curl coreutils)"
done
if [ "$CHANNEL" = recon ]; then
  command -v timeout >/dev/null 2>&1 || die "missing timeout (pkg install coreutils)"
fi

base="https://github.com/${REPO}/releases/download/${TAG}"
dest="$PREFIX/bin/$DEST_NAME"
stage_dir=""
stage=""
tmp="$(mktemp -d "${TMPDIR:-$PREFIX/tmp}/huntsman-install.XXXXXX")"
cleanup() {
  rm -rf "$tmp"
  if [ -n "$stage_dir" ]; then
    rm -rf "$stage_dir"
  fi
}
trap cleanup EXIT

echo "Downloading ${ASSET} from release ${TAG}"
curl -fsSL --proto '=https' -o "$tmp/$ASSET" "$base/$ASSET"
curl -fsSL --proto '=https' -o "$tmp/$ASSET.sha256" "$base/$ASSET.sha256"
( cd "$tmp" && sha256sum -c "$ASSET.sha256" ) || die "sha256 mismatch; not installing"

stage_verified_download() {
  # Allocate a private directory on the destination filesystem. Installation
  # remains atomic, and cleanup owns only this invocation's staging directory.
  stage_dir="$(mktemp -d "$PREFIX/bin/.${DEST_NAME}.install.XXXXXX")" ||
    die "could not allocate staging directory; $dest left unchanged"
  stage="$stage_dir/binary"
  install -m 0755 "$tmp/$ASSET" "$stage" || die "could not stage $stage; $dest left unchanged"
  local want got
  want="$(cut -d' ' -f1 "$tmp/$ASSET.sha256")"
  got="$(sha256sum "$stage" | cut -d' ' -f1)"
  [ -n "$want" ] && [ "$got" = "$want" ] || die "staged copy failed the sha256 check; $dest left unchanged"
}

# A valid download hash does not establish that this handset can execute the
# binary. Run offline acceptance in a disposable directory before replacing it.
# Keep generated ledgers out of the caller's working directory and cap hangs.
accept_staged_runtime() {
  if [ "$CHANNEL" = recon ]; then
    mkdir "$tmp/acceptance"
    (
      cd "$tmp/acceptance"
      timeout 30 "$stage" check &&
      timeout 30 "$stage" verify var/ledger.json
    ) || die "offline runtime acceptance failed; $dest left unchanged"
  fi
}

activate_staged_binary() {
  # Retain the inode of an identical executable, including one in active use.
  if [ -f "$dest" ] && [ -x "$dest" ] && [ ! -L "$dest" ] && cmp -s "$stage" "$dest"; then
    echo "Already installed and verified $dest (${TAG})"
    return
  fi
  mv -f "$stage" "$dest" || die "could not move $stage into place; $dest left unchanged"
  echo "Installed $dest (${TAG})"
}

stage_verified_download
accept_staged_runtime
activate_staged_binary
