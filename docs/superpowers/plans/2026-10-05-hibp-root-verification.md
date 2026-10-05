# Active HIBP Verification Repair Plan

> **Execution requirement:** Use the evidence-gated implementation loop. Product changes are forbidden unless verification demonstrates an active-root defect.

**Objective:** Replace the false-failing Railpack verifier with a deterministic verifier for the active root `huntsman-recon` crate, while preserving production behavior and the immutable legacy reference tree.

## Established state

- Active product: repository root package `huntsman-recon` (`rust-version = 1.87`).
- Archival oracle: `legacy/hse-monolith-v1.41.0`; do not modify it.
- Active HIBP client already sends `User-Agent`, uses `hibp-api-key` only on keyed requests, pins the HIBP origin, and implements `GET /subscription/status`.
- Existing active tests cover request shape, credential non-leakage, auth/status handling, redirects, subscription parsing, plan gating, and CLI behavior.
- Previous Railway failure occurred before Rust tests because Railpack pruned source files needed by the custom command.
- No live HIBP credential is available in the verification project, so valid-key production execution cannot be claimed.

## Acceptance criteria

1. Verification runs against the root crate from an intact source checkout.
2. A real network request to `https://haveibeenpwned.com/api/v3/subscription/status` with an intentionally invalid key and explicit User-Agent is rejected with HTTP 401, proving the endpoint is authentication-gated.
3. Root HIBP unit, CLI, and build-contract tests pass.
4. Root `cargo fmt --check`, `cargo check --all-targets`, `cargo clippy --all-targets -- -D warnings`, and `cargo test --locked` pass on the verifier branch.
5. Existing Android aarch64 CI continues to pass.
6. Production Railway services and runtime configuration remain unchanged.
7. No `unsafe`, no new Rust dependency, and no product-code change unless a failing test proves one is necessary.

## Reproduction / competing hypotheses

- H1: active HIBP implementation is defective.
- H2: active implementation is correct; failure is verifier/buildpack infrastructure.
- H3: HIBP's live auth contract has drifted from the implementation.

**Cheapest discriminator:** custom-Dockerfile verifier on an intact checkout, combining the existing root HIBP test suite with a live invalid-key subscription-status probe.

## Execution

- [ ] Add a verifier-only Dockerfile outside the legacy tree.
- [ ] Build it from a disposable Railway service attached to this branch.
- [ ] Require live invalid-key `/subscription/status` => 401.
- [ ] Require root HIBP tests and quality gates to pass.
- [ ] Inspect failures and change product code only if evidence localizes a defect there.
- [ ] Confirm Android aarch64 CI and root CI.
- [ ] Delete the disposable Railway service after evidence is captured.
