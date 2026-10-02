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
# sha256 and install only on a match.
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
for c in curl sha256sum install mktemp; do
  command -v "$c" >/dev/null 2>&1 || die "missing $c (pkg install curl coreutils)"
done

base="https://github.com/${REPO}/releases/download/${TAG}"
tmp="$(mktemp -d "${TMPDIR:-$PREFIX/tmp}/huntsman-install.XXXXXX")"
trap 'rm -rf "$tmp"' EXIT

echo "Downloading ${ASSET} from release ${TAG}"
curl -fsSL --proto '=https' -o "$tmp/$ASSET" "$base/$ASSET"
curl -fsSL --proto '=https' -o "$tmp/$ASSET.sha256" "$base/$ASSET.sha256"
( cd "$tmp" && sha256sum -c "$ASSET.sha256" ) || die "sha256 mismatch; not installing"

install -m 0755 "$tmp/$ASSET" "$PREFIX/bin/$DEST_NAME"
echo "Installed $PREFIX/bin/$DEST_NAME (${TAG})"
