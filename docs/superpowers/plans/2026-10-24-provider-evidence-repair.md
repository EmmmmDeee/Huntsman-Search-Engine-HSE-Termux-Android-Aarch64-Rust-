# Provider Evidence Repair Implementation Plan

> **For agentic workers:** Execute the two independent repairs with test-driven development and independent whole-branch review. Steps use checkbox syntax.

**Goal:** Correct reproduced Censys evidence errors and shared abuse.ch credential availability without changing provider activation, budgets, or supported platforms.

**Architecture:** Retain the existing provider decoder, indicator fold, credential resolver and CLI/server adapter. Validate consumed Censys fields before aggregation; reuse the canonical credential resolver for server settings.

**Tech Stack:** Rust 2024; MSRV 1.87; pinned verification compiler 1.99; existing Cargo workspace.

**Spec:** `docs/REPAIR_PROTOCOL.md`, `AGENTS.md`, and the user's HUNTSMAN protocol. Official provider schema evidence and finding records are in the accompanying adversarial review report.

## Global Constraints

- Preserve Android Termux AArch64 compatibility without root or embedded LLM.
- No additional runtime dependencies, paid API requests, automatic source activation, or workflow/settings changes.
- Missing credentials send no requests; authentication and malformed responses never become valid-zero.
- Preserve documented absent/null collections and sparse service objects; no invented required provider fields.
- Use one coherent repair branch and merge only after full acceptance; independently verify the resulting main revision.

## Review Focus

- Distinct AS name and organization, including absent/blank organization: only the supplied managing organization may become an organization entity.
- Malformed service/DNS elements and optional metadata shapes: schema-drift outcome and no fabricated evidence.
- Sparse valid services, empty/null collections and port boundaries: remain compatible.
- Credential alias availability: either abuse.ch slot enables both compatible sources; WiGLE still requires both separate credentials.
- Provider activation, host identity and secret handling: existing bounded/no-key/origin tests remain passing.

### Task 1: Censys evidence integrity

**Files:** `src/censys.rs`, `tests/ip_censys.rs`, `changelog.d/censys-evidence-integrity.fixed.md`.

**Interfaces:** Preserve `censys::decode(body, ip) -> Result<Finding, LegError>` and `indicator_legs::run`; no public signature changes.

- [x] Add offline behavior tests using real decoder/indicator folding with only transport responses substituted. Distinct `name=AS-LABEL` and `organization=Actual Operator Ltd` must retain the AS label as metadata and create only `Actual Operator Ltd` as an organization. Missing organization must create none.
- [x] Assert malformed service rows, present invalid port/protocol values, non-string DNS names and malformed consumed DNS/routing/location fields produce `SchemaDrift` with no entities. Run `cargo test --locked --test ip_censys` against original production code and record the failures.
- [x] Implement the smallest field mapping and fallible row validation; preserve missing/null fields and sparse objects.
- [x] Run the same test plus existing Censys/Exa/API-leg tests; require zero failures. Verify empty/null/sparse compatibility and unchanged identity/auth behavior.

### Task 2: Credential settings agree with executable sources

**Files:** `src/cli/scans.rs`, a focused server integration test, and one changelog fragment.

**Interfaces:** Preserve `SlotCheck`, `/api/settings`, and `Keys`; use public `provider_credentials::secret_for_slot` rather than raw key storage lookup.

- [x] Exercise the actual server with isolated synthetic credentials. Either single abuse.ch slot must mark both threatfox/urlhaus configured; neither marks both false. WiGLE must still require both slots and HIBP aliases remain supported.
- [x] Run the regression against original production code; require the alias cases to fail for the expected configured-state mismatch.
- [x] Reuse the canonical credential resolver in the production adapter, then rerun; require zero failures without any provider requests.

### Integration and delivery

- [x] Compare bounded alternatives and reject broader schema/workflow rewrites unsupported by evidence.
- [x] Record a matched Censys decode microbenchmark; do not claim a speedup from a correctness repair.
- [x] Run `cargo gate full` and inspect all step results: 3,481 tests passed, zero failures/ignored.
- [ ] Require the PR CI 1.87 gate to establish MSRV compatibility.
- [x] Obtain an independent correctness/security review and resolve material findings.
- [ ] Commit coherent changes, push repair branch, create PR, and require relevant CI checks before merge.
- [ ] Verify actual merged SHA, main CI, Android artifact identity and release status; report any unavailable real-device/live-provider evidence explicitly.
