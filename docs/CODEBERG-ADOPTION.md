# Huntsman — adopt the existing Codeberg repository without losing history

## Verified baseline (22 November 2026)

The public destination https://codeberg.org/EmmmmDeee/HuntsmanSearchEngine exists. It is **not empty**: its `main` is an unrelated, single-README initial root commit:

- Codeberg main: `6b38d016a4bbb18a5cc5ca84265f65eb01fe705a`
- Canonical GitHub main: `9488c3e0b3941ade36f8d05ca5e4565f756f1bd6`

Never force-push GitHub main onto this initialized destination. The existing empty-repository migration script correctly refuses to overwrite it.

## Non-destructive alternative: `scripts/codeberg-adopt.sh`

The `adopt` operation requires the destination to have **only** the pinned Codeberg root on `main` (one `README.md` and no other branch or tag). It independently clones canonical GitHub history and checks both exact pinned main SHAs before writing.

It constructs a **two-parent merge commit** with the original Codeberg root as parent 1 and the original GitHub main as parent 2. Its tree equals GitHub main plus `docs/legacy-codeberg-README.md`, a byte-identical copy of the original Codeberg README. Pushing this new commit is a verified fast-forward of Codeberg main, with an exact expected-SHA lease against concurrent updates. The original Codeberg history is retained rather than overwritten.

All ordinary GitHub branches/tags are copied by exact SHA with conditional-create leases. The original GitHub main is also preserved under a new `github-main` branch. The resulting Codeberg `main` SHA is **intentionally different** from the GitHub `main` SHA; do not label the two as byte-identical mirrors.

`verify` checks the complete expected refs, two parents, original README blob, source tree delta and Codeberg's advertised symbolic HEAD. `resume` can finish missing branch/tag transfers after a network interruption. It refuses unexpected or divergent remote refs, changed source pins, and attempts to replace any existing ref.

## Run from rootless Termux

Use the files from this review branch or the verified migration archive. The **repo owner** must configure an authorized Codeberg SSH key first. Verify the SSH host fingerprint independently against https://docs.codeberg.org/security/ssh-key/; never paste private keys or account tokens into ChatGPT.

```bash
pkg install git openssh coreutils gawk diffutils
bash -n scripts/codeberg-adopt.sh
bash tests/codeberg_adopt.sh

# Recheck both SHA values immediately before execution.
export HUNTSMAN_CODEBERG_EXPECT_MAIN=6b38d016a4bbb18a5cc5ca84265f65eb01fe705a
export HUNTSMAN_MIGRATION_EXPECT_MAIN=9488c3e0b3941ade36f8d05ca5e4565f756f1bd6

bash scripts/codeberg-adopt.sh plan EmmmmDeee/HuntsmanSearchEngine
bash scripts/codeberg-adopt.sh adopt EmmmmDeee/HuntsmanSearchEngine
bash scripts/codeberg-adopt.sh verify EmmmmDeee/HuntsmanSearchEngine
```

If `adopt` transferred the merge commit but stopped before all refs were created:

```bash
bash scripts/codeberg-adopt.sh resume EmmmmDeee/HuntsmanSearchEngine
bash scripts/codeberg-adopt.sh verify EmmmmDeee/HuntsmanSearchEngine
```

**Do not rerun `adopt` after main moved**; use `resume`. Never run the empty-repository `codeberg-migrate.sh verify` on an adopted merge: it intentionally expects the original GitHub main SHA, whereas adoption creates a different two-parent Codeberg main.

After independent verification, the development checkout can retain GitHub for rollback while switching the preferred remote:

```bash
git remote rename origin github
git remote add origin git@codeberg.org:EmmmmDeee/HuntsmanSearchEngine.git
git ls-remote --symref origin HEAD
```

No push from the development checkout is automatic. The script does not change GitHub, repository settings or the installed Android binary.

## Completion and release gates

The Woodpecker pipeline includes offline tests for both migration strategies before the existing Rust fast gate. Codeberg CI requires separate approval and does not replace full Rust, CodeQL/security, Android AArch64 cross-build, 16 KiB ELF alignment validation or a real rootless Termux device acceptance.

This Git-only transfer does **not** migrate GitHub issues, PR discussions, wiki, release attachments, passwords, CI secrets, Git LFS object storage or submodule repositories. To migrate GitHub issue/review metadata, use Codeberg's `New Migration > GitHub` importer into a **different new repository**; do not run the Git-only script over an importer-created repository. Leave GitHub readable until issue and release provenance is independently preserved.

The existing `install.sh` still uses GitHub release assets. Repointing it to Codeberg before a verified Codeberg release/attestation channel exists would risk invalid installations. This is an **infrastructure preparation**, not a deployed alternative release system.

Local offline validation: `bash tests/codeberg_adopt.sh` exercises a real local bare Git destination with unrelated initial commit, two-parent merge ancestry, preserved README, exact branch/tag refs, idempotent resume, missing branch recovery, extra-ref rejection, source-pin refusal and default-HEAD mismatch. A live Codeberg write requires owner authentication, which has not been supplied to this session.
