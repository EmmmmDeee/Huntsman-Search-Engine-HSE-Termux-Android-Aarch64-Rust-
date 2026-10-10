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
5. If `main` moves while the run is in progress, publish refuses and the issue must be
   labelled again. A pull request is never opened on a `main` the gate did not test.

## The four jobs

Only the publish job holds a write token, and only its publish step receives it. The
jobs that run code the model wrote hold no write permission.

| Job | Runs | Holds | Passes on |
| --- | --- | --- | --- |
| `fix` | The model, the key scan, the path policy, and the capture of the change | `ANTHROPIC_API_KEY`, in the require and model steps only. No write permission. | A patch file and the redacted model output |
| `gate` | `git apply` of the patch on the commit the run started from, then the full repair gate | Nothing | The gate log |
| `publish` | `publish.sh`, from a copy of the scripts made before the patch arrived | `ISSUE_FIX_TOKEN` or the workflow token, in the publish step only | Nothing |
| `report` | `report.sh`, when an attempt stops before a pull request | Issue write permission | Nothing |

Every job reads `github.sha`, the commit the run started from, and no step can change
it. `publish` checks out `main` and refuses unless `main` is still that commit.

The jobs pass files, never code. The patch and the model output are data. `publish`
applies the patch to its own checkout of `main`, runs the path policy on the result,
and only then commits. It never reads the agent's working tree, the agent's `.git`,
or any script that the patch could have written.

## Path policy

`scripts/issue-fix/check-protected.sh` decides what the change may touch. It runs in
`fix` for early feedback and again in `publish`, which is the authority.

Allowed:

- a new file under `src/` or `tests/`;
- a change under `src/` that stays above the test code of its file.

Test code in a file starts at its first test marker and runs to the end of the file.
A marker is `#[cfg(test)]`, `#[test]`, `#[rstest]`, or any attribute whose name ends in
`test` or `test_case` (for example `#[tokio::test]`). Spacing does not matter, so
`# [test]` is a marker too.

A file is wholly test code, and no change to it is allowed, when:

- its name is `tests.rs`, `test.rs`, `*_tests.rs`, or `*_test.rs`;
- it is under a `tests/` directory;
- it opens with `#![cfg(test)]`; or
- a module that test code declares loads it. That covers a file named by `#[path]` and
  everything under that file's directory. A module is test code when it carries a cfg
  that names `test`, or when it is declared on or after the first marker of its file.

Refused:

- a change to an existing file under `tests/`, including a rename or deletion;
- a change to test code in `src/`, including deleting or renaming away a file that
  holds test code;
- any change outside `src/` and `tests/`, including untracked files;
- a symbolic link or submodule, added or removed.

How the change is read:

- Every git command runs with `--attr-source` set to the empty tree. A `.gitattributes`
  file in the change cannot run a filter, disable a diff with `-diff`, or change what
  is compared. Every diff is read as text, so a file that git calls binary is still
  checked.
- Git output is read NUL-separated, so no file name can be split, and a git command
  that fails is a refusal, never a pass.

Known false refusal: a marker inside a string literal, such as a raw string with a line
that starts with `#[cfg(test)]`, starts test code early. An edit below that line is
refused even when it is not test code. The refusal fails closed. Move the literal, or
split the line, to make the edit.

## Publish

`publish.sh` pushes `ai-fix/issue-N` and opens the pull request. It refuses when:

- `GATED_SHA` is not set, or `main` is not that commit, so a pull request is never a
  combination that the gate did not run on;
- `ai-fix/issue-N` already exists on the remote;
- the patch is empty, does not apply, or changes nothing; or
- the path policy refuses the result on `main`.

It runs git from its own checkout, so hooks and configuration in the agent's repository
are never used.

## Key scan

After the model step's CLI exits, the scan in `issue-fix.yml` runs in isolated Python
mode. It reads the Python from the workflow file itself, which the model cannot write.
It does two things:

- It redacts the model output: the literal key, its hex forms, every base64 run that
  decodes to the key, and any `sk-ant-*` string.
- It lists the files the change would carry with
  `git ls-files -c -o --exclude-standard`, the same ignore rules that `git add -A`
  applies in `capture.sh`, and it searches each listed file, each symbolic-link target,
  and each file name for the key. A hit refuses the change. A key in a source file, a
  test, an untracked file, or a directory that a nested `.gitignore` re-includes (such
  as `target/`) never reaches the patch. A key in an ignored file does not, because
  the patch does not carry that file. The name of a file is not printed when it holds
  the key.

The key forms the scan finds are the literal key, lower- and upper-case hex, base64 in
either alphabet, the key after `KEY=`, and the key inside a longer base64 stream at each
of the four alignments. `self-check.sh` extracts this step's shell from the workflow and
runs it in a git tree, so CI and the check run the same code.

## Secrets and variables

- `ANTHROPIC_API_KEY` (required, secret). Read by the require step, which checks that it
  is set, and by the model step, which passes it to the CLI and runs the key scan. No
  other step receives it.
- `ISSUE_FIX_TOKEN` (optional, secret). A token with contents and pull-requests write,
  read only by the publish step. Without it the pull request is opened with the
  workflow token, and GitHub does not start CI for it. Start CI from the Actions tab, or
  set this secret.
- `ISSUE_FIX_MODEL` (optional variable, default `opus`).
- `ISSUE_FIX_BUDGET_USD` (optional variable, default `10`). The spend cap for one run.

## Limits and residual risk

- The model's Bash tool can run `cargo`, and `cargo` runs code the model wrote. That
  code runs in the model step while the model key is in the environment, so a test
  could read the key and send it out over the network. The key scan does not catch
  that. The control is that only triage-level maintainers can apply the label.
- The scan finds the whole key in the forms listed above. A key that is split across
  lines, reversed, cut so that only part of it appears, or encoded some other way is not
  caught, and the redaction covers only the same forms. The model step holds the key in
  its environment, so a partial key is a leak the scan cannot rule out.
- Files the patch does not carry, such as `.git` and ignored files, are not scanned.
  The patch never carries them.
- Model output is published in the pull request body, labelled unreviewed, redacted as
  above, and truncated to 4000 characters.
- The gate runs model-written tests with no secrets, so a test can make the gate pass.
  The patch passes the path policy on its own, and the gate is a signal, not a proof.
- The gate log that `report.sh` posts can contain text the model chose. It is posted
  as a code block of at most 40 lines, with backticks replaced and each line cut at 400
  characters.
- The spend cap is `--max-budget-usd`. This CLI version has no `--max-turns`, so the
  runtime is capped by the job timeout (90 minutes).
- Model quality is not verified. The workflow proves that the change passes the path
  policy and the full repair gate, which is the same bar as any other pull request.
- Pull requests opened with the workflow token do not start CI automatically.

## Verification status

- `scripts/issue-fix/self-check.sh` runs offline in about 6 seconds. It covers the path
  policy (allowed and refused changes, whole-file and loaded test code, `# [test]`, NUL
  bytes, `-diff` attributes, symbolic links, and unknown bases), the filter that
  `.gitattributes` names (which must not run), the capture of a change as a patch, the
  key scan extracted from the workflow, and the publish step against a bare remote
  (`GATED_SHA`, the refusals, a hook in the agent's repository, an existing branch, an
  empty patch, and a patch that does not apply).
- `tests/issue_fix_contract.rs` pins the job boundaries: which job holds the model
  key, which jobs can write, that every job reads `github.sha`, that the environment
  file is not used, that only the publish step sees a write token, that checkouts
  persist no credential, and that nothing merges.
- `actionlint` 1.7.12 and `shellcheck` 0.11.0 report no findings on the workflow and
  the scripts.
- Not verified: an actual model run (no API key in this environment) and a GitHub
  Actions run of the four jobs.
