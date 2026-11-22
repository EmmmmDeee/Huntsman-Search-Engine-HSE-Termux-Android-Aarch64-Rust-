# Huntsman Codeberg hosting migration

This is a reversible Git-host migration for the canonical, public, MIT/Apache-licensed Huntsman engine. It does not deploy the Termux binary, change the canonical GitHub repository, or carry credentials across services.

## Preparation (one-time user account step)

1. Create or sign in to an account at https://codeberg.org . Confirm its terms permit your public free-software project.
2. Add your own SSH public key to Codeberg. Verify the host's published SSH fingerprint before accepting its first host-key prompt: https://docs.codeberg.org/security/ssh-key/ . Do not send private keys or tokens to a chat, issue, or repository.
3. Create an **empty** public repository with no README, .gitignore, license initialization, or files. Choose a name for the Codeberg project. This name is not presumed to match the GitHub account name.

## Migrate the Git history (Termux, no root)

```sh
pkg install git coreutils openssh gawk diffutils
bash scripts/codeberg-migrate.sh plan YOUR_CODEBERG_USER/YOUR_REPO
bash scripts/codeberg-migrate.sh push YOUR_CODEBERG_USER/YOUR_REPO
bash scripts/codeberg-migrate.sh verify YOUR_CODEBERG_USER/YOUR_REPO
```

The script clones the *live public canonical* GitHub repository into a private temporary bare checkout, then pushes `main`, all ordinary branches, and all tags to the new empty Codeberg repository. It compares every branch/tag SHA after migration. It never force-pushes, deletes remote refs, updates GitHub, or reconfigures any checkout. It intentionally refuses a destination already containing branch/tag refs. Reruns use `verify`, not `push`. This is a Git-history migration, not a migration of issue conversations, repository settings, GitHub releases, secrets, workflows, or GitHub's internal pull-request refs.

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
- `bash tests/codeberg_migration.sh` performs offline clone, push, SHA checks and nonempty-destination refusal against local bare Git repositories. It does **not** exercise the actual Codeberg service or SSH authentication.
