# Issue-fix workflow

`.github/workflows/issue-fix.yml` turns a GitHub issue into a pull request with a
Claude model. It is separate from the model-free dual-pass runner, which stays
model-free (see `docs/DUAL_PASS.md`).

## How to use it

1. Create the `ai-fix` label in the repository, if it does not exist.
2. Add the `ai-fix` label to an issue, or dispatch the workflow with an issue number.
   Only people with triage access can apply the label. That is the control.
3. The job runs, and on success it opens a pull request on `ai-fix/issue-N`.
   It never merges. A maintainer reviews and merges.

## Secrets and variables

- `ANTHROPIC_API_KEY` (required, secret). Read only by the model step.
- `ISSUE_FIX_TOKEN` (optional, secret). A token with contents and pull-requests write.
  Without it the pull request is opened with the workflow token, and GitHub does
  not start CI for it. Start CI from the Actions tab, or set this secret.
- `ISSUE_FIX_MODEL` (optional variable, default `opus`).
- `ISSUE_FIX_BUDGET_USD` (optional variable, default `10`). The spend cap for one run.

## What the job does

1. Checks out `main` and reads the issue. The job refuses a closed issue.
2. Builds the prompt. The issue title and body sit between two markers made of a
   random token, and they are treated as data.
3. Runs the pinned Claude Code CLI (`CLAUDE_CODE_VERSION`) in `--bare` mode. Bare mode
   skips the repository's `CLAUDE.md` and auto-memory, and it uses only
   `ANTHROPIC_API_KEY`. The tools are restricted to read and edit, and to a short
   list of cargo and git commands. Network tools, `gh`, `env`, and `git push` and
   `git commit` are denied. Permission prompts are answered with "none".
4. Checks the change against the path policy (`scripts/issue-fix/check-protected.sh`).
   Allowed: changes under `src/`, and new files under `tests/`. Refused: any change to an
   existing test, to scripts, workflows, manifests, or the lockfile. The check compares
   against the commit the job checked out, so a commit made by the agent cannot hide a change.
5. Runs `scripts/repair-gate.sh full` on the runner, not in the model's sandbox.
6. Commits, pushes, and opens the pull request. If anything stops before that, it
   comments on the issue with the stage outcomes and the tail of the gate log.

## Limits and residual risk

- The model's Bash tool can run `cargo`, and `cargo` can run code from the repository.
  The API key is in the model step's environment, so a tool call could read it.
  GitHub masks the value in logs, but a test could still transmit it. The control is
  that only triage-level maintainers can apply the label.
- The spend cap is `--max-budget-usd`. This CLI version has no `--max-turns`, so runtime
  is capped by the job timeout (90 minutes).
- Model quality is not verified. The workflow only proves that the change passes the
  path policy and the repair gate, which is the same bar as any other pull request.
- Pull requests opened with the workflow token do not start CI automatically.

## Verification status

- `scripts/issue-fix/self-check.sh` runs offline and passes. It covers the path policy,
  the prompt fencing, and the publish step against a local bare remote.
- `actionlint` reports no findings on the workflow. shellcheck reports none on the scripts.
- The CLI accepts the argument vector. A fake key reaches the API and returns 401.
- Not verified: an actual model run (no API key in this environment), a GitHub Actions
  run (the account is billing-locked), and the Rust contract test in `tests/issue_fix_contract.rs`.
