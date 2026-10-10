# Issue-fix workflow

`.github/workflows/issue-fix.yml` turns a GitHub issue into a pull request with a
Claude model. It is separate from the model-free dual-pass runner, which stays
model-free (see `docs/DUAL_PASS.md`).

## How to use it

1. Create the `ai-fix` label in the repository, if it does not exist.
2. Add the `ai-fix` label to an issue, or dispatch the workflow with an issue number.
   Only people with triage access can apply the label. That is the control.
3. On success the workflow opens a pull request on `ai-fix/issue-N`. It never merges.
   A maintainer reviews and merges.
4. If `ai-fix/issue-N` already exists on the remote, the workflow refuses and leaves
   that branch alone. Delete or rename the branch, then label the issue again.

## The four jobs

Only the publish job can write to the repository. The jobs that run code the model
wrote cannot.

| Job | Runs | Holds | Passes on |
| --- | --- | --- | --- |
| `fix` | The model, the path policy, and the capture of the change | `ANTHROPIC_API_KEY`, in the model step only. No write permission. | A patch file and the redacted model output |
| `gate` | The full repair gate, on `main` with the patch applied | Nothing | The gate log |
| `publish` | `publish.sh`, from a copy of the scripts made before the patch arrived | `ISSUE_FIX_TOKEN` or the workflow token, with write permission | Nothing |
| `report` | `report.sh`, from a checkout of `main` | The workflow token, with issue write permission | Nothing |

The jobs pass files, never code. The patch and the model output are data. `publish`
applies the patch to its own checkout of `main`, runs the path policy on the result,
and only then commits. It never reads the agent's working tree, the agent's `.git`,
or any script that the patch could have written.

## Path policy

`scripts/issue-fix/check-protected.sh` decides what the change may touch:

- Allowed: a change under `src/` that stays above the file's test code. Test code
  starts at the first `#[cfg(test)]` or `#[test]` line and runs to the end of the
  file. Allowed: a new file under `src/` or `tests/`.
- Refused: any change to an existing file under `tests/`, `scripts/`, or `.github/`,
  and to `Cargo.toml`, `Cargo.lock`, `build.rs`, and the Docker files. Refused: a
  change to test code in `src/`, deleting or renaming away a file that holds test
  code, and any symbolic link or submodule.

The policy runs in `fix` for early feedback and again in `publish`, which is the
authority. The policy scripts are copied before the model runs.

## Secrets and variables

- `ANTHROPIC_API_KEY` (required, secret). Read only by the model step.
- `ISSUE_FIX_TOKEN` (optional, secret). A token with contents and pull-requests write,
  read only by `publish`. Without it the pull request is opened with the workflow
  token, and GitHub does not start CI for it. Start CI from the Actions tab, or set
  this secret.
- `ISSUE_FIX_MODEL` (optional variable, default `opus`).
- `ISSUE_FIX_BUDGET_USD` (optional variable, default `10`). The spend cap for one run.

## Limits and residual risk

- The model's Bash tool can run `cargo`, and `cargo` runs code the model wrote. That
  code runs in the `fix` and `gate` jobs. The model key is in the `fix` job's model
  step, so test code in that step could read it and send it out. The control is that
  only triage-level maintainers can apply the label.
- Redaction removes the literal key value, and anything shaped like an Anthropic key,
  from the model output and the artifact. It does not catch a key encoded some other
  way.
- Model output is published in the pull request body, labelled unreviewed. It is
  truncated to 4000 characters.
- The gate runs model-written code with no secrets, so a test could alter the gate's
  own result. The patch, not the gate, is what `publish` checks.
- The spend cap is `--max-budget-usd`. This CLI version has no `--max-turns`, so
  runtime is capped by the job timeout (90 minutes).
- Model quality is not verified. The workflow proves that the change passes the path
  policy and the repair gate, which is the same bar as any other pull request.
- Pull requests opened with the workflow token do not start CI automatically.

## Verification status

- `scripts/issue-fix/self-check.sh` runs offline. It covers the path policy, the
  capture of a change as a patch, the redaction of the key, and the publish step
  against a bare remote. Publish runs from a clone that the agent never touched, and
  the self-check plants a hook in the agent's repository to show that it is ignored.
  It also covers refusal of an existing branch, an empty patch, and a patch that does
  not apply.
- `tests/issue_fix_contract.rs` pins the job boundaries: which job holds the model
  key, which jobs can write, that checkouts persist no credential, and that nothing
  merges.
- `actionlint` reports no findings on the workflow. `shellcheck` reports none on the
  scripts.
- Not verified: an actual model run (no API key in this environment) and a GitHub
  Actions run of the three jobs.
