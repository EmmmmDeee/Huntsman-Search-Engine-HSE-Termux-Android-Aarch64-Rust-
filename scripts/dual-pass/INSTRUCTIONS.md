# Dual-pass operator instructions

These are the executable methods. None of them call a model.

## Method 1 — Plan is data, not a prompt

Write the change as one fenced `json` block in the issue. The runner binds it to live signatures and `Cargo.lock`. It does not infer files, invent tests, or call an endpoint. Only the repository owner or a member can write a plan that runs.

Required keys: `targets`, `new_tests`, `patches`.
Forbidden keys: `model`, `prompt`, `endpoint`, `api_key`, and `llm: true`.

`targets` are a path under `src/`, or a new file under `tests/`. Anything else, such as `docs/`, `Cargo.toml`, `Cargo.lock`, or a workflow file, is refused before any build.
`new_tests` must be `tests/generated_<issue>.rs`, must not already exist on main, must assert a behavior that is false on untouched main, and must not be `assert!(true)` or `assert_eq!(x, x)`.
`patches` has one to three items. Each item has a unified `diff` and a `replace_fn` fallback (`path`, `name`, `body`). Diffs may touch only declared targets. Every path a diff names is checked, including the source and destination of a rename or copy.

Label the issue `dual-pass`, or run the workflow with the issue number.

## Method 2 — Red before any edit

The runner writes the generated tests and runs them before applying a patch. A pass on untouched main is a rejected specification, and so is a test that does not parse. Each failing binary is judged on its own by `red_class.py`. A valid red is a missing symbol (every compile error is `cannot find`) or a failed assertion (every panic is an assertion's default message, which begins ``assertion `left`` or ``assertion failed``). A custom message on `assert!` is refused, and a custom message on `assert_eq!` is accepted only when the default text stays at its start. Any other error or panic refuses the plan, because it shows nothing about the defect. The report records the class of each binary.

## Method 3 — Patch, then type, then unit

Turn order is the patch array order, maximum three. These are declared fallbacks, not a model correction loop. A failed turn does not call out and does not rewrite the next patch. `git apply` is first. If the diff misses, the runner replaces the named function node through the tree-sitter Rust grammar, which is required; a name that matches no function, or more than one, refuses the patch. Each attempt starts from the declared targets as they are on main. After each apply it restores protected files, runs `cargo check --locked --tests --bins`, then every generated test. After the generated tests pass, the existing locked suite must also pass before the change is handed to the publish stage.

## Method 4 — Context is a digest

There is no prompt cache. Pass 1 records sha256 of `static-context.md`, `Cargo.toml`, and `Cargo.lock` on `execution-plan.json`. Diagnostics kept in the report are failing compiler and assertion lines, not the full log.

## Method 5 — Green opens a PR; red budget hands off

The plan stage writes `change.patch` with only declared targets and generated tests. The publish stage applies that patch to a fresh checkout of `main`, runs the path policy on the result, and only then commits. On green the branch is `dual-pass/issue-<n>` and a pull request opens. On exhaustion, when the patch has a change, the branch is `dual-pass/issue-<n>-wip`, the issue is labeled `needs-human-review`, and the failure trace is commented. A plan with no change pushes nothing. A change that cannot be published (the patch does not apply, the path policy refuses it, or the push fails) still labels the issue and comments the reason, and publish exits non-zero. Protected files are restored before the change is written.

## Secrets

The plan job is given no credential. The Rust it runs can read its process's environment and its parent's, so a token in any step of that job would be readable. The publish job holds `github.token`, and it runs only the scripts it copied before the plan's output arrived. Do not add a model secret. Do not add `XAI_API_KEY`, an OpenAI key, or an Anthropic key. Do not pass `HUNTSMAN_*` keys, breach keys, or registry tokens into either job. No secret value is written to the plan, the report, or the pull request body.

Do not add a model secret to the workflow. Do not let a patch edit the existing suite to make itself pass. Do not treat a green generated test on untouched main as success.
