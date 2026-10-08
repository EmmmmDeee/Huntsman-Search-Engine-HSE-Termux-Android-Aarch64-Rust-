# Dual-pass operator instructions

These are the executable methods. None of them call a model.

## Method 1 — Plan is data, not a prompt

Write the change as one fenced `json` block in the issue. The runner binds it to live signatures and `Cargo.lock`. It does not infer files, invent tests, or call an endpoint.

Required keys: `targets`, `new_tests`, `patches`.
Forbidden keys: `model`, `prompt`, `endpoint`, `api_key`, and `llm: true`.

`targets` are existing source files. They must not be `tests/`, `Cargo.toml`, `Cargo.lock`, or workflow files.
`new_tests` must be `tests/generated_<issue>.rs`, must assert a behavior that is false on untouched main, and must not be `assert!(true)` or `assert_eq!(x, x)`.
`patches` has one to three items. Each item has a unified `diff` and a `replace_fn` fallback (`path`, `name`, `body`). Diffs may touch only declared targets.

Label the issue `dual-pass`, or run the workflow with the issue number.

## Method 2 — Red before any edit

The runner writes the generated tests and runs them before applying a patch. A pass on untouched main is a rejected specification. A test that does not parse is also rejected. A missing symbol or a failed assertion is a valid red. The report records which class fired.

## Method 3 — Patch, then type, then unit

Turn order is the patch array order, maximum three. `git apply` is first. If the diff misses, the runner replaces the named function node with tree-sitter, then a brace scan. After each apply it restores protected files, runs `cargo check --locked --tests --bins`, then the generated tests. A turn that fails does not call out. The next declared patch is the only correction.

## Method 4 — Context is a digest

There is no prompt cache. Pass 1 records sha256 of `static-context.md`, `Cargo.toml`, and `Cargo.lock` on `execution-plan.json`. Diagnostics kept in the report are failing compiler and assertion lines, not the full log.

## Method 5 — Green opens a PR; red budget hands off

On green, only declared targets, generated tests, the plan, and the report are committed. The branch is `dual-pass/issue-<n>`. On exhaustion, the same narrow set is committed to `dual-pass/issue-<n>-wip`, the issue is labeled `needs-human-review`, and the failure trace is commented. Protected files are restored before either commit.

## Secrets

The runner receives one secret: `GH_TOKEN`, set from `github.token`. It is used to read the issue, push the branch, open the pull request, add `needs-human-review`, and comment the trace. It is not an LLM credential.

Do not add a model secret. Do not add `XAI_API_KEY`, an OpenAI key, or an Anthropic key. The workflow rejects a live model URL or `secrets.XAI` reference.

Do not pass provider keys into this job. Issue-authored tests run in the same environment, so `HUNTSMAN_*` keys, breach keys, and registry tokens would be readable by the patch under test. Those keys stay out of dual-pass. Release and CI already use their own tokens; this workflow does not import them.

No secret value is written to the plan, the report, or the pull request body.

Do not add a model secret to the workflow. Do not let a patch edit the existing suite to make itself pass. Do not treat a green generated test on untouched main as success.
