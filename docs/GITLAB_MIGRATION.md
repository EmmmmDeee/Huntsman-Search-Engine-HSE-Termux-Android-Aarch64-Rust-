# HUNTSMAN — GitLab migration and cutover

## Authoritative source

Import the complete GitHub repository, NOT the existing Codeberg placeholder:

- Git source: https://github.com/EmmmmDeee/Huntsman-Search-Engine-HSE-Termux-Android-Aarch64-Rust-.git
- Codeberg placeholder: https://codeberg.org/EmmmmDeee/HuntsmanSearchEngine
- Last observed GitHub main (2026-11-22): 9488c3e0b3941ade36f8d05ca5e4565f756f1bd6
- Last observed Codeberg main: 6b38d016a4bbb18a5cc5ca84265f65eb01fe705a

The Codeberg repository has a single initial README commit and is not a
complete mirror. The observed SHAs are baselines; re-fetch the CURRENT source
heads before the actual import and cutover.

## GitLab import

1. Sign in to https://gitlab.com and open Create new → Import project → Repository by URL.
2. Import the GitHub Git source URL above to an explicitly owned namespace.
   Do not initialise a new README or rewrite the history.
3. Keep the imported project restricted until permissions and secrets are reviewed.
   Do not delete, archive, or disable the functioning GitHub repository or releases.
4. Verify every branch and tag with the provided script:

       bash scripts/gitlab-migration-verify.sh          "https://github.com/EmmmmDeee/Huntsman-Search-Engine-HSE-Termux-Android-Aarch64-Rust-.git"          "https://gitlab.com/YOUR_NAMESPACE/YOUR_PROJECT.git"

   Use the actual destination URL. Exit code 0 means matching branch/tag names
   and Git object SHAs, NOT CI or artifact equivalence.
5. Confirm GitLab main matches the most recent GitHub main at cutover.
6. Protect GitLab main, require merge requests and successful checks, minimise
   write access, and run both jobs from .gitlab-ci.yml to green.

## Host acceptance versus Android/release parity

GitLab pipeline gates match the existing MSRV (Rust 1.87) and pinned stable
(Rust 1.99) xtask repair modes. They do NOT replace the GitHub-only Android
AArch64 cross-build, 16 KiB ELF alignment tests, browser acceptance, key scans,
publish provenance, attestation, or pre-release promotion.

The existing README and install.sh depend on GitHub raw files, release assets
and legacy-hse compatibility. Preserve that working install/update channel
until the GitLab release pipeline is verified with source-SHA matching,
artifact checksums, controlled publication and a real Android handset.

A repository-by-URL import does not migrate GitHub issues, pull requests,
branch protections, CI secrets, Releases or Actions history. Handle those
separately, with an explicit access and provenance audit.

## Mirrors and rollback

After successful import AND parity validation, use a scoped Codeberg credential
to configure GitLab → Codeberg push mirroring. GitLab Free supports push mirrors;
pull mirrors require a higher tier. Because existing Codeberg main has an
unrelated README-only history, NEVER overwrite its branch by blind force-push.
Prefer a new empty Codeberg mirror repository or explicitly back up the stub
before changing its history.

Retain the known-good GitHub installation/release channel during rollout.
For any ref, CI, artifact, secret-scanning or handset mismatch, suspend cutover
and return to the unchanged GitHub source and releases.
