# Huntsman Codeberg hosting migration

This is a reversible Git-host migration for the canonical, public, MIT/Apache-licensed Huntsman engine. It does not deploy the Termux binary, change the canonical GitHub repository, or carry credentials across services.

## Migration strategy — preserve the HSE evidence and engineering backlog

**Prefer metadata-aware Codeberg `New Migration > GitHub` when the objective is
to relocate the whole project.** The live GitHub repository currently contains
dozens of unmerged review branches and open defect reports. A Git-only push
preserves reachable branch/tag commits but **cannot** recreate issues, PR/MR
reviews, milestones, wiki and release attachments. The Codeberg import screen
allows selected metadata categories; independently inspect the imported item
counts, review states and referenced commit SHAs before treating them as
preserved. Importer support varies by item type and source permissions.

There are two **mutually exclusive** first-transfer methods:

- **Metadata-aware:** Create the destination through Codeberg's migration UI
  with the GitHub source URL and a privately provided, least-privilege access
  token; do not pre-create an empty repository. Verify imported commits,
  branches, open proposals and issue records separately; revoke the token
  after the import. Do **not** run this script's `push` against that repository.
  You **may** run the read-only `bash scripts/codeberg-migrate.sh verify USER/REPO`
  against an importer-created repository to compare Git refs and the default
  branch. That command checks Git object identities only; it cannot attest to
  imported PR comments, issue status, release assets or Codeberg permissions.
  If the importer intentionally omits branches, it will fail with a visible
  ref difference rather than falsely reporting complete migration.
- **Git-history-only:** Create a truly empty Codeberg repository, then use
  `plan`, `push` and `verify` below. Branch and tag SHAs are tested; PR and
  issue metadata are intentionally out of scope. Keep the original GitHub
  project readable for that context.

Do not re-label a draft feature PR as validated during migration, change
branch protections, import secrets as CI variables, or treat a mirrored source
commit as an installed binary. The historical issue/pr links remain useful
even after another forge becomes primary.

## Preparation (one-time user account step)

1. Create or sign in to an account at https://codeberg.org . Confirm its terms permit your public free-software project.
2. Add your own SSH public key to Codeberg. Verify the host's published SSH fingerprint before accepting its first host-key prompt: https://docs.codeberg.org/security/ssh-key/ . Do not send private keys or tokens to a chat, issue, or repository.
3. Create an **empty** public repository with no README, .gitignore, license initialization, or files. Choose a name for the Codeberg project. This name is not presumed to match the GitHub account name.

## Migrate the Git history (Termux, no root)

```sh
pkg install git coreutils openssh gawk diffutils
bash scripts/codeberg-migrate.sh plan YOUR_CODEBERG_USER/YOUR_REPO
# Optional: pin the reviewed source main before the initial push.
export HUNTSMAN_MIGRATION_EXPECT_MAIN=9488c3e0b3941ade36f8d05ca5e4565f756f1bd6
bash scripts/codeberg-migrate.sh push YOUR_CODEBERG_USER/YOUR_REPO
bash scripts/codeberg-migrate.sh verify YOUR_CODEBERG_USER/YOUR_REPO
```

The script clones the *live public canonical* GitHub repository into a private temporary bare checkout, then pushes `main`, all ordinary branches, and all tags to the new empty Codeberg repository. It compares every branch/tag SHA after migration, **and now refuses a
destination whose advertised default `HEAD` is not the exact copied
`refs/heads/main` commit**. A forge can otherwise possess identical named
refs while its default clone checkout points to missing `master`.
If `verify` reports a default-branch mismatch, use Codeberg's repository
settings to set the default branch to `main`, then run `verify` again.
This is a destination-setting fix, **not** a reason to force-push or
rewrite any branch. It never force-pushes, deletes remote refs, updates GitHub, or reconfigures any checkout. It intentionally refuses a destination already containing branch/tag refs. Reruns use `verify`, not `push`. If a network failure interrupts the first transfer **after some refs have been created**, run `bash scripts/codeberg-migrate.sh resume YOUR_CODEBERG_USER/YOUR_REPO`: it only creates missing refs, verifies that all existing refs match the original source snapshot, and rejects unexpected or advanced branches/tags. The conditional-create lease rejects concurrent ref creation; it cannot overwrite existing refs. The optional 40-character `HUNTSMAN_MIGRATION_EXPECT_MAIN` stops the migration before writes if the source's `main` has changed since the reviewed SHA; **update it intentionally** once the canonical head changes. The normal mode also refuses noncanonical source-URL overrides. Never set `HUNTSMAN_MIGRATION_TEST_MODE` in a production migration. This is a Git-history migration, not a migration of issue conversations, repository settings, GitHub releases, secrets, workflows, or GitHub's internal pull-request refs. Git-LFS objects and Git submodule repositories are **not** copied by this command (pointers/submodule refs may be present); migrate those independently before declaring a complete transfer. The script does not create an on-host running service; Codeberg is the source host, while the Android binary remains local.

If you need GitHub issues, release records, and metadata migrated too, use Codeberg's **New Migration > GitHub** importer *instead of* the empty-repo push path. That importer requires an operator-supplied GitHub access token to migrate metadata; revoke it after migration. See https://docs.codeberg.org/advanced/migrating-repos/ . Never run this script's `push` against an importer-created nonempty destination.

## Change the local development remote only after verification

From an existing Termux checkout:

```sh
git remote rename origin github
git remote add origin git@codeberg.org:YOUR_CODEBERG_USER/YOUR_REPO.git
git remote -v
git ls-remote origin refs/heads/main
```

These commands are **not** performed by the migration script. Use `git push origin HEAD` only after verifying the Codeberg branch and its protection policy. The old GitHub remote remains available as `github` for rollback. Keep the existing installed Termux binary unchanged until a Codeberg-source build has passed the full Rust and handset acceptance gates.

## CI and limitations

`.woodpecker.yaml` is an intentionally small, source-only, nonprivileged Rust **fast-gate** pipeline. Codeberg-hosted Woodpecker requires manual approval (https://docs.codeberg.org/ci/) and offers `linux/amd64` workers, not native Android AArch64 builders. It does **not** replace strict full Rust tests, static security checks, Android cross-build, 16 KiB ELF verification, or physical rootless Termux acceptance. Never merge/release on its green fast-gate verdict alone.

The existing `install.sh` still depends on GitHub for release metadata and downloads. Git hosting can move independently, but a fully GitHub-free installer and release channel require a separate, verified implementation once a working Codeberg release destination exists. Do not edit the live installer until that release path is proven.

GitLab can also host the repository; hosted GitLab shared CI runners may require account/card validation. Codeberg Git hosting itself does not require GitLab shared runners.

## Verification record

- Original canonical: `https://github.com/EmmmmDeee/Huntsman-Search-Engine-HSE-Termux-Android-Aarch64-Rust-`
- Source head on 22 November 2026: `9488c3e0b3941ade36f8d05ca5e4565f756f1bd6`
- Existing Crossref draft PR #1840 remains unmerged: no changes from this migration are applied to `main` automatically.
- `bash tests/codeberg_migration.sh` performs offline clone, push, SHA checks, safe resume, interrupted transfer recovery, foreign-ref/divergence refusals, pinned-source protection and nonempty-destination refusal against local bare Git repositories. It does **not** exercise the actual Codeberg service or SSH authentication.

## Existing initialized Codeberg target (22 Nov 2026)

The **publicly confirmed** repository at https://codeberg.org/EmmmmDeee/HuntsmanSearchEngine
already has an unrelated initial commit at
`6b38d016a4bbb18a5cc5ca84265f65eb01fe705a` on `main`, containing
a `README.md`. The empty-repository `push` route intentionally refuses this
target; do not force-push, reset, delete its default branch or claim that a
one-file stub is a Huntsman migration.

Use the separately gated `scripts/codeberg-adopt.sh` and
`docs/CODEBERG-ADOPTION.md` to create a **fast-forward, two-parent adoption
merge**, preserving the original Codeberg root and the entire canonical GitHub
ancestry. This creates a new Codeberg `main` SHA; the exact original GitHub
`main` SHA is retained at `github-main`. Adoption requires owner SSH write
permissions and exact source/destination SHA pins. It does not migrate issue
threads, binary releases, LFS objects or secrets. The ordinary ref-equality
`codeberg-migrate.sh verify` is inapplicable to the adopted merge; use
`codeberg-adopt.sh verify` instead.
