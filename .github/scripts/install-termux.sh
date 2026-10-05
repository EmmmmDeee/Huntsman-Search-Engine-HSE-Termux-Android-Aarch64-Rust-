#!/usr/bin/env bash
# install-termux.sh: install a prebuilt aarch64 Huntsman binary on Termux.
#
# Default (HUNTSMAN_CHANNEL=hse): the legacy `hse` binary, which still runs
# person lookups, into $PREFIX/bin/hse. Release HSE_TAG, default main-7dca720
# (the newest legacy hse build).
#
# Opt-in (HUNTSMAN_CHANNEL=recon): the huntsman-recon pre-release, an
# in-progress replacement that cannot run person lookups yet, into
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
    echo "Note: huntsman-recon is an in-progress replacement and cannot run person lookups yet."
    ;;
  *) die "HUNTSMAN_CHANNEL must be 'hse' (default) or 'recon'" ;;
esac
[[ "$TAG" =~ ^(latest|main-[0-9a-f]{7}|v[0-9]+\.[0-9]+\.[0-9]+)$ ]] || die "bad release tag '$TAG'"
[ -n "${PREFIX:-}" ] && [ -d "$PREFIX/bin" ] || die "\$PREFIX/bin not found; run this inside Termux"
case "$(uname -m)" in aarch64 | arm64) ;; *) die "these binaries are aarch64 only (got $(uname -m))" ;; esac
for c in curl sha256sum install mktemp mv cut; do
  command -v "$c" >/dev/null 2>&1 || die "missing $c (pkg install curl coreutils)"
done

base="https://github.com/${REPO}/releases/download/${TAG}"
dest="$PREFIX/bin/$DEST_NAME"
stage="$PREFIX/bin/.${DEST_NAME}.install.$$"
tmp="$(mktemp -d "${TMPDIR:-$PREFIX/tmp}/huntsman-install.XXXXXX")"
trap 'rm -rf "$tmp"; rm -f "$stage"' EXIT

echo "Downloading ${ASSET} from release ${TAG}"
curl -fsSL --proto '=https' -o "$tmp/$ASSET" "$base/$ASSET"
curl -fsSL --proto '=https' -o "$tmp/$ASSET.sha256" "$base/$ASSET.sha256"
( cd "$tmp" && sha256sum -c "$ASSET.sha256" ) || die "sha256 mismatch; not installing"

# Stage on the destination filesystem, then rename(2): the old binary stays
# intact until the new one is complete and verified.
install -m 0755 "$tmp/$ASSET" "$stage" || die "could not stage $stage; $dest left unchanged"
want="$(cut -d' ' -f1 "$tmp/$ASSET.sha256")"
got="$(sha256sum "$stage" | cut -d' ' -f1)"
[ -n "$want" ] && [ "$got" = "$want" ] || die "staged copy failed the sha256 check; $dest left unchanged"
mv -f "$stage" "$dest" || die "could not move $stage into place; $dest left unchanged"
echo "Installed $dest (${TAG})"
