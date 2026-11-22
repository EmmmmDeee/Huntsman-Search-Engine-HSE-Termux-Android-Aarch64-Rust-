# Huntsman/HSE independent CI

Native CircleCI execution of the **canonical huntsman-recon Rust OSINT engine**, using the existing workspace verification and phone browser tests. This pipeline intentionally does not substitute peripheral modules for core engine acceptance.

## Jobs

1. **hse-core-full** — Rust 1.99.1 runs the repository's exact cargo xtask full gate: Bash syntax, rustfmt, production Clippy, strict workspace Clippy, locked Rust workspace tests, CLI check and source-tree mutation check.
2. **hse-msrv** — Rust 1.87.0 runs the exact cargo xtask MSRV gate: full locked workspace tests, CLI check and toolchain-floor validation.
3. **hse-web-ui** — builds the canonical binary and runs the existing browser test at mobile width against the local web server.

All jobs refuse a checkout whose HEAD differs from CircleCI's checkout SHA. They are read-only with respect to the GitHub repository: no pushes, releases, merging or deployment.

## Setup

- Connect **EmmmmDeee/Huntsman-Search-Engine-HSE-Termux-Android-Aarch64-Rust-** to CircleCI using its GitHub App integration.
- Select a **native CircleCI configuration file**, path **.circleci/config.yml**. Do not select the GitHub Actions YAML compatibility preview.
- Configure GitHub PR opened/updated and main-branch push events to trigger this pipeline; ensure draft PR updates are included.
- Run an exact-commit PR and inspect logs for all three jobs, confirming checkout SHA, Rust compiler versions, tests actually executed and browser behaviour.

## Mandatory release boundaries

Linux x86-64 CI cannot prove **Android AArch64** binary format, 16-KiB ELF page alignment, actual rootless Termux execution, long-running resource constraints, or radio and provider-network access. Continue to require the repository's existing Android cross-build, binary integrity checks, physical Termux acceptance, independent vulnerability assessment and GitHub required checks before deployment. The existing Termux PR verifier and runtime acceptance script are complementary, not a substitute for required branch protection.

GitHub Actions is currently blocked by an account billing lock. Do not claim CircleCI tests satisfy unchanged required GitHub Actions checks; an owner-authorised, separately reviewed branch-protection configuration is needed if the organisation later chooses external checks as approved replacements. Never bypass billing restrictions or label skipped tests as passed.

## Verification before CircleCI onboarding

The committed CircleCI config parses as YAML with three jobs and three workflow entries. All eight embedded Bash step commands pass bash -n. The GitHub blob hash matches the tested local YAML. **No CircleCI run, real Rust compilation, browser execution or Termux acceptance has occurred through this new pipeline yet.**
