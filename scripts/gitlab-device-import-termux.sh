#!/usr/bin/env bash
# Device-code OAuth and fail-closed GitLab import of the complete HUNTSMAN source.
# Usage: bash gitlab-device-import-termux.sh
set -Eeuo pipefail
umask 077

source_git='https://github.com/EmmmmDeee/Huntsman-Search-Engine-HSE-Termux-Android-Aarch64-Rust-.git'
slug='huntsman-hse-source'
die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }

if ! command -v glab >/dev/null 2>&1 || ! command -v git >/dev/null 2>&1 || ! command -v jq >/dev/null 2>&1; then
  command -v pkg >/dev/null 2>&1 || die 'Run inside Termux, with git, jq and glab installed'
  pkg install -y git jq glab-cli || die 'Termux package installation failed; check pkg search glab-cli'
fi

# Credentials remain in Termux. Do not print an OAuth token or enter one in chat.
if ! glab auth status --hostname gitlab.com >/dev/null 2>&1; then
  printf 'Authorize GitLab CLI using the one-time code shown below.\n'
  glab auth login --hostname gitlab.com --device --git-protocol https --setup-git-credential-helper
fi
glab auth status --hostname gitlab.com >/dev/null 2>&1 || die 'GitLab OAuth authorization is not complete'
username="$(glab api user --hostname gitlab.com --jq '.username')" || die 'Cannot read authenticated GitLab account'
[[ "$username" =~ ^[A-Za-z0-9_.-]+$ ]] || die 'Unexpected GitLab username response'
printf 'GitLab account: %s\n' "$username"

source_main="$(git ls-remote "$source_git" refs/heads/main | awk '$2 == "refs/heads/main" { print $1 }')" || die 'Cannot read GitHub main'
[[ "$source_main" =~ ^[a-f0-9]{40}$ ]] || die 'Source main SHA missing or invalid'

# Dedicated private import avoids overwriting an existing GitLab HUNTSMAN project.
encoded_path="${username}%2F${slug}"
if existing="$(glab api --hostname gitlab.com "projects/${encoded_path}" 2>/dev/null)"; then
  project="$existing"
  printf 'A project already exists at this import destination; no write attempted.\n'
else
  printf 'Creating a NEW private project; existing GitLab projects are left untouched.\n'
  project="$(glab api --hostname gitlab.com --method POST projects \
    --raw-field "path=${slug}" \
    --raw-field 'name=HUNTSMAN HSE Source' \
    --raw-field 'visibility=private' \
    --raw-field "import_url=${source_git}")" || die 'Project import request failed; no existing project was modified'
fi
id="$(jq -er '.id | select(type == "number")' <<<"$project")" || die 'GitLab did not return a valid project ID'
url="$(jq -er '.web_url | select(type == "string")' <<<"$project")" || die 'GitLab did not return a project URL'
visibility="$(jq -er '.visibility | select(type == "string")' <<<"$project")" || die 'GitLab did not return project visibility'
[[ "$visibility" == private ]] || die "Destination is not private: ${url}"
printf 'Project: %s\n' "$url"

# A repository-by-URL import is asynchronous. Read status, do not overwrite refs.
status=''
for attempt in $(seq 1 30); do
  response="$(glab api --hostname gitlab.com "projects/${id}/import")" || die 'Import status API failed'
  status="$(jq -r '.import_status // empty' <<<"$response")"
  case "$status" in
    finished|none) break ;;
    failed) jq -r '.import_error // "Import failed with no error text"' <<<"$response" >&2; die 'GitLab import failed' ;;
    started|scheduled|'') sleep 15 ;;
    *) die "Unexpected import status: ${status}" ;;
  esac
done
[[ "$status" == finished || "$status" == none ]] || die "Import has not finished (status=${status})"

dest_main="$(glab api --hostname gitlab.com "projects/${id}/repository/branches/main" --jq '.commit.id')" || die 'Cannot read GitLab main'
[[ "$dest_main" =~ ^[a-f0-9]{40}$ ]] || die 'Destination main SHA invalid'
printf 'GitHub main: %s\nGitLab main: %s\n' "$source_main" "$dest_main"
[[ "$source_main" == "$dest_main" ]] || die 'Main commits differ: refuse cutover'

# Git credentials are handled by the glab credential helper. Compare branch/tag object IDs.
destination_git="$(jq -er '.http_url_to_repo | select(type == "string")' <<<"$project")" || die 'No GitLab clone URL'
tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT
for item in source destination; do
  if [[ "$item" == source ]]; then remote="$source_git"; else remote="$destination_git"; fi
  git ls-remote --heads --tags --refs "$remote" \
    | awk 'NF == 2 { print $2 "\t" $1 }' | LC_ALL=C sort > "$tmpdir/$item" || die "Cannot read ${item} refs"
done
[[ -s "$tmpdir/source" && -s "$tmpdir/destination" ]] || die 'Missing branch/tag references'
if ! diff -u "$tmpdir/source" "$tmpdir/destination"; then
  die 'Branch/tag refs do not match; refuse cutover'
fi
printf 'PASS: private GitLab import and branch/tag refs verified at %s\n' "$url"
printf 'NOTE: GitLab runners, release provenance, CI secrets and Android handset acceptance are separate gates.\n'