# Codeberg migration — guarded cutover

This document prepares the canonical HUNTSMAN Termux Rust repository for an
optional Codeberg migration. The read-only audit does **not** perform migration,
publish source code, modify repository settings, or change the Android installer.
The existing GitHub `main`, build artifacts, and installer stay authoritative
until a separately verified cutover.

## Prerequisites and blockers

1. Resolve the licensing decision. `Cargo.toml` advertises
   `MIT OR Apache-2.0`, but the GitHub root currently has no corresponding
   license file. Confirm ownership and third-party obligations before publishing.
   Do not silently select or invent copyright authorization.
2. Confirm that the intended destination exists and is under your control.
   The default candidate is `https://codeberg.org/EmmmmDeee/HuntsmanSearchEngine`;
   this address is **not proof** that the migration has completed.
3. Use Codeberg's *New Migration → GitHub* flow to transfer issues, wiki,
   releases and milestones where available, instead of a plain `git push`.
   A GitHub access token may be necessary for metadata migration; revoke
   the short-lived token afterward.
4. Expect separate work on `.github/workflows/` and GitHub release assets:
   those are not a working Codeberg CI/release pipeline. Codeberg documents
   Woodpecker CI and separate Forgejo Actions facilities.

## Git reference parity gate

Run from any Bash environment with Git and remote network access:

```sh
bash scripts/codeberg-migration-audit.sh audit
```

Override either URL if the migrated repository uses a different name:

```sh
HUNTSMAN_DEST_REMOTE=https://codeberg.org/OWNER/REPOSITORY.git \
  bash scripts/codeberg-migration-audit.sh audit
```

The command fetches no working tree and changes neither remote. It enumerates
branch and tag refs at both hosts, rechecks the source for movement and requires
exact ref names **and** object IDs to match, including annotated tags. It fails
closed on unreachable repositories, missing `main`, source movement, missing or
unexpected refs, and different object IDs.

This is a **necessary, not sufficient** migration check. It cannot prove issue,
release, wiki, package/LFS, permission, legal, or CI equivalence. A successful
check is a snapshot, not an ongoing synchronization guarantee.

Test locally without touching either host:

```sh
bash tests/codeberg_migration_audit.sh
```

## Separate acceptance and cutover

Verify migrated issues/releases/attachments manually, select a supported CI
runner, and reproduce the existing Linux/Android Rust gates. Then audit all
GitHub-specific dependencies, particularly `install.sh`, `.github/workflows/`,
`scripts/lifecycle.sh`, release tags/assets, GitHub API lookups, README install
instructions, and any scripts that assert GitHub `main` is canonical.

Do not change DNS, archive GitHub, force-push, delete branches, or switch the
Termux installer merely because the parity gate passed. First prove that a
Codeberg-hosted binary built from the exact accepted commit passes offline
verification and actual Android Web UI/runtime acceptance, or deliberately retain
GitHub as a release artifact mirror while source control moves.

Primary references:

- https://docs.codeberg.org/advanced/migrating-repos/
- https://docs.codeberg.org/getting-started/faq/
- https://docs.codeberg.org/ci/
