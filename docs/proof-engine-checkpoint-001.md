# Proof Engine — verified checkpoint 001

## Claim
The standalone Rust repository mapper compiles and its included tests and smoke test pass on the GitHub-hosted Ubuntu runner.

## Reproducible evidence
- Repository: `EmmmmDeee/Huntsman-Search-Engine-HSE-Termux-Android-Aarch64-Rust-`
- PR: https://github.com/EmmmmDeee/Huntsman-Search-Engine-HSE-Termux-Android-Aarch64-Rust-/pull/1546
- Evaluated commit: `5cf20d9b08a5254950a10081bb7b00895da1cef7`
- Workflow run ID: `41007269300`
- Workflow job ID: `123904904582`
- Workflow: `Android agent mapper verification`
- Outcome: `completed / success`
- Job steps observed successful: `Compile standalone mapper`, `Compile and run mapper tests`, `Smoke test repository indexing`.

## Exact test commands
```sh
rustc --edition=2024 -D warnings tools/agent_repo_map.rs -o /tmp/agent-repo-map
rustc --edition=2024 -D warnings --test tools/agent_repo_map.rs -o /tmp/agent-repo-map-tests
/tmp/agent-repo-map-tests
/tmp/agent-repo-map . entity provenance correlation > /tmp/agent-repo-map-output
grep -q 'Repository symbol map' /tmp/agent-repo-map-output
grep -q 'Rust files inspected:' /tmp/agent-repo-map-output
grep -q '^## ' /tmp/agent-repo-map-output
```

## Limits
This establishes compilation and test success on a hosted Ubuntu runner only. It does **not** establish Android Termux execution, full agent operation, or overall repository CI success. It does not prove completeness of the lexical symbol map.

## Falsification targets
- Verify a physical Android AArch64 Termux compile/run.
- Test ranking against adversarial symbol/path queries and large repositories.
- Verify CI/security checks on the final PR head before merge.
- Keep runtime HSE code unchanged until independently characterized.

## Next decision
Advance only after verifying the new commit's CI and then target the smallest measurable defect or missing agent-harness capability. Record failures with exact command and environment rather than claiming completion.
