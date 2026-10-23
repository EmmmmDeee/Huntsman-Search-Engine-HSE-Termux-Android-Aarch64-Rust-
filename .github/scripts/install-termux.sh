#!/usr/bin/env bash
# install-termux.sh: install a prebuilt aarch64 Huntsman binary on Termux.
#
# Default (HUNTSMAN_CHANNEL=recon): the current huntsman-recon build, with
# rebuilt people/email/username/offline-phone lookup paths, into
# $PREFIX/bin/huntsman-recon. Release HUNTSMAN_RELEASE_TAG, default: the
# main-<sha7> release this script was attached to. The copy in the repository
# was attached to no release; it installs the newest published recon build.
#
# Opt-in (HUNTSMAN_CHANNEL=hse): the legacy `hse` monolith, which still runs
# the full legacy person-lookup surface, into $PREFIX/bin/hse. Release HSE_TAG,
# default main-7dca720 (the newest legacy hse build). Recon does not yet cover
# the complete legacy surface, so this channel stays available for it.
#
# Both channels download the binary and its .sha256 over HTTPS, verify the
# sha256 and install only on a match. The verified binary is staged next to
# the destination in $PREFIX/bin, re-checked there, then renamed into place,
# so an interrupted install or a full disk never leaves a missing or
# half-written binary behind.
set -euo pipefail

REPO="EmmmmDeee/Huntsman-Search-Engine-HSE-Termux-Android-Aarch64-Rust-"
RECON_TAG_DEFAULT="@RECON_TAG@"
CHANNEL="${HUNTSMAN_CHANNEL:-recon}"

die() { echo "install-termux: $*" >&2; exit 1; }

case "$CHANNEL" in
  hse)
    TAG="${HSE_TAG:-main-7dca720}"
    ASSET="hse-aarch64-linux-android"
    DEST_NAME="hse"
    ;;
  recon)
    TAG="${HUNTSMAN_RELEASE_TAG:-$RECON_TAG_DEFAULT}"
    # The release job stamps its own tag into the default. Left unstamped, this
    # is the repository's copy: the newest build is found once the tools pass.
    if [ -z "${HUNTSMAN_RELEASE_TAG:-}" ]; then
      case "$RECON_TAG_DEFAULT" in @*@) TAG="" ;; esac
    fi
    ASSET="huntsman-recon-aarch64-linux-android"
    DEST_NAME="huntsman-recon"
    echo "Note: huntsman-recon is still a partial replacement for the legacy HSE surface."
    ;;
  *) die "HUNTSMAN_CHANNEL must be 'recon' (default) or 'hse', got '$CHANNEL'" ;;
esac
valid_tag() { [[ "$1" =~ ^(latest|main-[0-9a-f]{7}|v[0-9]+\.[0-9]+\.[0-9]+)$ ]]; }
[ -z "$TAG" ] || valid_tag "$TAG" || die "bad release tag '$TAG'"
[ -n "${PREFIX:-}" ] && [ -d "$PREFIX/bin" ] || die "\$PREFIX/bin not found; run this inside Termux"
case "$(uname -m)" in aarch64 | arm64) ;; *) die "these binaries are aarch64 only (got $(uname -m))" ;; esac
for c in curl sha256sum install mktemp mv cut cmp; do
  command -v "$c" >/dev/null 2>&1 || die "missing $c (pkg install curl coreutils)"
done
if [ "$CHANNEL" = recon ]; then
  command -v timeout >/dev/null 2>&1 || die "missing timeout (pkg install coreutils)"
fi

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

# The newest published recon build. The release job publishes main-<sha7> only
# while that commit is the head of main, so the newest build belongs to the
# newest commit of main that has one: walk back from the head, at most 30
# commits, and take the first whose checksum asset exists. The releases list is
# not in date order, so it cannot be used for this.
newest_recon_tag() {
  local depth sha tag
  for ((depth = 0; depth < 30; depth++)); do
    sha="$(curl -fsSL --proto '=https' -H 'Accept: application/vnd.github.sha' \
      "https://api.github.com/repos/${REPO}/commits/main~${depth}")" ||
      die "could not read main~${depth} from the GitHub API; set HUNTSMAN_RELEASE_TAG=main-<sha7>"
    [[ "$sha" =~ ^[0-9a-f]{40}$ ]] || die "the GitHub API did not return a commit id for main~${depth}"
    tag="main-${sha:0:7}"
    if curl -fsSL --proto '=https' -o "$tmp/probe.sha256" \
      "https://github.com/${REPO}/releases/download/${tag}/${ASSET}.sha256" 2>/dev/null; then
      printf '%s\n' "$tag"
      return
    fi
  done
  die "no published recon build among the last 30 commits of main; set HUNTSMAN_RELEASE_TAG=main-<sha7>"
}

if [ -z "$TAG" ]; then
  TAG="$(newest_recon_tag)"
  valid_tag "$TAG" || die "bad release tag '$TAG'"
  echo "Newest published build: ${TAG}"
fi
base="https://github.com/${REPO}/releases/download/${TAG}"

echo "Downloading ${ASSET} from release ${TAG}"
curl -fsSL --proto '=https' -o "$tmp/$ASSET" "$base/$ASSET"
curl -fsSL --proto '=https' -o "$tmp/$ASSET.sha256" "$base/$ASSET.sha256"
( cd "$tmp" && sha256sum -c "$ASSET.sha256" ) || die "sha256 mismatch; not installing"

stage_verified_download() {
  # Stage on the destination filesystem inside a private random directory.
  # The live executable is untouched until the staged copy is fully verified.
  stage_dir="$(mktemp -d "$PREFIX/bin/.${DEST_NAME}.install.XXXXXX")" ||
    die "could not allocate staging directory; $dest left unchanged"
  stage="$stage_dir/binary"
  install -m 0755 "$tmp/$ASSET" "$stage" ||
    die "could not stage $stage; $dest left unchanged"

  local want got
  want="$(cut -d' ' -f1 "$tmp/$ASSET.sha256")"
  got="$(sha256sum "$stage" | cut -d' ' -f1)"
  [ -n "$want" ] && [ "$got" = "$want" ] ||
    die "staged copy failed the sha256 check; $dest left unchanged"
}

accept_staged_runtime() {
  # A matching download hash establishes byte identity, not executability on
  # this handset. Exercise the recon binary offline before replacing the live
  # copy, with bounded wall-clock time and disposable generated artifacts.
  if [ "$CHANNEL" = recon ]; then
    # A checksum-verified release can still carry an older or mislabelled
    # binary. Main-channel tags encode the first seven digits of the exact
    # source revision; bind the running executable to that tag before install.
    if [[ "$TAG" == main-* ]]; then
      local built_sha
      built_sha="$(timeout 30 "$stage" build-sha)" ||
        die "could not read staged binary build-sha; $dest left unchanged"
      [[ "$built_sha" =~ ^[0-9a-f]{40}$ ]] ||
        die "staged binary has invalid build-sha; $dest left unchanged"
      [[ "${built_sha:0:7}" == "${TAG#main-}" ]] ||
        die "staged binary revision does not match release $TAG; $dest left unchanged"
    fi
    mkdir "$tmp/acceptance"
    (
      cd "$tmp/acceptance"
      timeout 30 "$stage" check &&
      timeout 30 "$stage" verify var/ledger.json
    ) || die "offline runtime acceptance failed; $dest left unchanged"
  fi
}

activate_staged_binary() {
  # Reinstalling identical verified bytes should not replace a live inode.
  if [ -f "$dest" ] && [ -x "$dest" ] && [ ! -L "$dest" ] && cmp -s "$stage" "$dest"; then
    echo "Already installed and verified $dest (${TAG})"
    return
  fi
  mv -fT "$stage" "$dest" ||
    die "could not move $stage into place; $dest left unchanged"
  echo "Installed $dest (${TAG})"
}

stage_verified_download
accept_staged_runtime
activate_staged_binary
