# Huntsman verified auto-merge policy

`merge-policy.json` expresses the expected **GitHub repository settings**, not a rule
that can be enforced by committing source alone. The `merge-policy.sh` controller is
**read-only by default** and refuses to overwrite any other branch policy.

**Verified baseline:** `main` must require pull requests, exact source CI checks
from the GitHub Actions app (integration ID `15368`), up-to-date PRs, resolved
review threads, no force pushes, no deletion, and zero bypass actors. The twelve
checks include native Rust/MSRV, Android AArch64, QEMU, browser, container, MITM,
completion, and release-preflight gates. The post-merge-only origin and release
publication checks are deliberately not listed as PR requirements.

## Apply only from a repository-admin GitHub session

1. Install `gh` and `jq`; run `gh auth login` using an account with repository
   **Administration:write** or a fine-grained PAT with that permission. Do not
   paste your token into the command line or commit it to source.
2. From this repository, execute:

   ```sh
   bash scripts/github/merge-policy.sh check
   bash scripts/github/merge-policy.sh apply
   bash scripts/github/merge-policy.sh check
   ```

3. Confirm the settings at
   `https://github.com/EmmmmDeee/Huntsman-Search-Engine-HSE-Termux-Android-Aarch64-Rust-/settings/rules`
   and verify a deliberately failing check actually blocks a test PR. A successful
   `check` verifies API configuration but **cannot by itself prove enforcement**.

If another policy already protects `main`, `apply` stops rather than changing it.
If the named policy exists but has drift, it reports the drift rather than
silently granting exemptions. No operation merges a PR or modifies `main`.

The repository app integration can read rulesets but currently does not have
permission to change them (branch-protection detail returned HTTP 403). `apply`
must run through an administrator-authorized GitHub CLI outside that integration.

## Enable GraphQL auto-merge on an eligible PR

After the main ruleset is active, a PR is out of draft and has its reviewed
head commit, use the expected-head-guarded GraphQL controller:

```sh
bash scripts/github/enable-pr-automerge.sh 1434 check
bash scripts/github/enable-pr-automerge.sh 1434 enable
```

The second command uses `enablePullRequestAutoMerge` with `SQUASH` and
`expectedHeadOid`; it refuses any missing/weak main ruleset, draft or closed PR,
wrong target or moving head. GitHub's protected branch remains the authority for
required CI. **Enabling auto-merge may merge immediately when all conditions
already pass**, so the `enable` operation is intentionally explicit.

## Tests

```sh
bash -n scripts/github/merge-policy.sh scripts/github/enable-pr-automerge.sh tests/github-merge-policy.sh tests/github-automerge.sh
jq -e '.' scripts/github/merge-policy.json
bash tests/github-merge-policy.sh
bash tests/github-automerge.sh
```

The mock-based tests cover both successful and refused changes; GitHub Actions
runs them on PRs and runs a separate read-only live drift check weekly or on
manual dispatch. No runtime LLM, extra Rust dependency, network access or
Termux privilege is introduced into Huntsman.
