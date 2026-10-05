# SeekNow Collector Reconstruction Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Restore SeekNow as a keyed Rust collector that uses the guarded network boundary, preserves upstream provenance/lineage, and exposes truthful diagnostics plus universal fast/deep search without leaking credential material.

**Architecture:** Extend the generic source-outcome model, add the reusable L5 collector contract, then implement an L4 `seeknow` client over `fetch::fetch` and an L5 `seeknow_collector` that owns selector planning, fast/deep orchestration and evidence conversion. The binary calls an L5 `seeknow_cli` adapter only; source responses become bounded typed records before they become entities/evidence.

**Tech Stack:** Rust 1.87+, edition 2024, safe Rust only, `serde`, `serde_json`, existing blocking `ureq` transport through `http::Transport`/`fetch::fetch`; GitHub Actions for Rust 1.87/stable and Android AArch64 verification.

**Spec:** `docs/superpowers/specs/2026-10-05-seeknow-collector-reconstruction-design.md`

## Global Constraints

- Rust-first; `#![deny(unsafe_code)]`; no runtime LLM and no async runtime.
- Termux/Android aarch64 remains first-class.
- No new socket path: all SeekNow requests go `seeknow_collector -> seeknow -> fetch::fetch -> injected Transport`.
- API base is `https://see-know.ru/api/v1`; credential slot is `HUNTSMAN_SEEKNOW_KEY`; auth header is `X-API-Key`.
- Credential-bearing SeekNow requests use `FetchOptions { max_redirects: 0 }`; no automatic mirror rotation.
- Universal search max is 500 rows; `Auto` omits the `type` field.
- A truncated, malformed, auth-failed, quota-failed, WAF-blocked or otherwise ambiguous response can never become `ValidZero`.
- `seeknow` is a collector, not an independent upstream family. Lineage remains `dbname -> breach -> source_db -> database_name -> dataset`; provider `source` stays non-counting.
- Duplicate rows, fast/deep duplication and provider multiplexing must not manufacture independent corroboration.
- Raw password/token/cookie/API-key values from exposure data are not emitted as entities, pivots, CLI output or persisted evidence in this slice.
- No SeekNow-facing output may include the API key or credential fingerprint.
- Legacy behavioral oracle is commit `7dca720`; overlapping semantics require differential fixtures or documented intentional divergence.

## Review Focus

1. A provider payload containing text such as `invalid_api_key` inside an ordinary leaked field must not be misclassified as an auth failure; only the top-level provider envelope may drive provider-failure classification. Task 3 tests this.
2. `success=true` with positive rows and `credits_remaining=0` must remain `Success`; spending the last credit cannot discard evidence. Task 3 tests this.
3. A fast `ValidZero` followed by deep failure must be partial/inconclusive, not evidence of absence. Task 4 tests this.
4. Multiple rows from the same `dbname`, and the same row returned by fast and deep modes, must contribute one upstream family rather than inflated corroboration. Task 4 tests lineage and deduplication.
5. Missing keys, redirects, diagnostics and rendered search output must never expose key values or credential fingerprints. Tasks 3 and 5 test this.

---

### Task 1: Extend causal source outcomes

**Files:**
- Modify: `src/source_outcome.rs`

**Interfaces:**
- Produces: `SourceOutcomeKind::EntitlementDenied`, `SourceOutcomeKind::QuotaExhausted`; `recommended_action` maps entitlement to `Investigate` and quota exhaustion to `Backoff`; neither is accepted or immediately retryable.

- [ ] **Step 1: Write failing tests**

Add tests asserting both new variants serialize to snake_case, are non-accepted/non-retryable, and map to the required actions while `RateLimited` remains transient/backoff.

- [ ] **Step 2: Run the source-outcome tests and verify RED**

Run: `cargo test --locked source_outcome::tests`
Expected: compile/test failure because the variants do not yet exist.

- [ ] **Step 3: Implement the two variants and helper mappings**

Keep the variants provider-generic. Do not hide either condition in `detail`.

- [ ] **Step 4: Verify GREEN and full suite**

Run: `cargo test --locked source_outcome::tests && cargo test --locked`
Expected: all pass.

- [ ] **Step 5: Commit**

`git commit -am "feat: distinguish entitlement and quota outcomes"`

### Task 2: Add the reusable collector boundary

**Files:**
- Create: `src/collector.rs`
- Modify: `src/lib.rs`
- Modify: `ARCHITECTURE.md`
- Modify: `tests/architecture_doc.rs`

**Interfaces:**
- Produces: `CollectionLimits`, `ObservationReceipt`, `CollectorPivot`, `CollectionBatch`, `CollectorError`, and trait `Collector` with `id`, `accepts`, and `collect` over `Entity`, injected `Transport`, limits and `now_unix`.
- `CollectionBatch` retains entities, source outcomes, receipts and typed pivots without manufacturing source-family counts.

- [ ] **Step 1: Write failing collector-contract tests**

Tests pin default bounded limits, unsupported-selector error representation, and that receipts carry `SourceExecutionOutcome`, response hash/truncation metadata without credentials.

- [ ] **Step 2: Run and verify RED**

Run: `cargo test --locked collector::tests`
Expected: failure because `collector` is not compiled yet.

- [ ] **Step 3: Implement the minimal synchronous generic contract**

Use existing `Entity`, `EntityKind`, `EvidenceNodeId`, `Transport` and `SourceExecutionOutcome`. Do not add networking, caching or source-specific behavior.

- [ ] **Step 4: Map the module in L5 and update architecture tests/docs**

`collector` is L5. Preserve the no-upward-edge invariant.

- [ ] **Step 5: Verify GREEN and architecture**

Run: `cargo test --locked collector::tests && cargo test --locked --test architecture_doc && cargo test --locked`
Expected: all pass.

- [ ] **Step 6: Commit**

`git commit -am "feat: add reusable collector boundary"`

### Task 3: Implement the L4 SeekNow REST client

**Files:**
- Create: `src/seeknow.rs`
- Modify: `src/lib.rs`
- Modify: `ARCHITECTURE.md`
- Modify: `tests/architecture_doc.rs`

**Interfaces:**
- Produces constants `API_BASE`, `KEY_SLOT`, `SEARCH_LIMIT_MAX`; `SeekNowQueryType`; `SeekNowSearch`; bounded `SeekNowValue`, `SeekNowUpstream`, `SeekNowRow`, `SeekNowResponseMeta`, `SeekNowSearchResult`, `SeekNowCredits`, `SeekNowStatus`; authenticated functions `credits`, `status`, `search_fast`, `search_deep` accepting injected `Transport`, `Credential`, request data and `now_unix`.
- L4 never depends on entity/lineage types.

- [ ] **Step 1: Write failing request-construction tests**

Use a fake `Transport` that records requests. Assert exact `/search` and `/search/deep` URLs, POST, JSON content type, `limit` clamped to 1..=500, `Auto` omits `type`, typed kinds serialize to documented strings, and `X-API-Key` is present only at the transport boundary while request `Debug` redacts it.

- [ ] **Step 2: Run and verify RED**

Run: `cargo test --locked seeknow::tests`
Expected: failure because `seeknow` does not exist.

- [ ] **Step 3: Implement credential-safe request execution**

All four endpoints call `fetch::fetch` with zero redirects. Build JSON with `serde_json`; never interpolate the key into URL/body/diagnostics.

- [ ] **Step 4: Add failing parser/outcome tests**

Fixtures cover: positive rows; valid zero; top-level invalid key; leaked payload text `invalid_api_key` that must remain a result; entitlement denial; transient 429; quota-exhausted envelope; positive last-credit response; 5xx; challenge; malformed JSON; incompatible schema; truncated body; rate-limit headers.

- [ ] **Step 5: Implement bounded envelope/row parsing**

Classify HTTP/WAF first, then only top-level provider envelope fields. Preserve upstream aliases `dbname`, `breach`, `source_db`, `database_name`, `dataset`, non-counting `source`, and record id. Bound rows to 500, fields per row and stored scalar length; credential-like result fields become exposure-presence metadata instead of raw secrets.

- [ ] **Step 6: Verify GREEN and architecture**

Run: `cargo test --locked seeknow::tests && cargo test --locked --test architecture_doc && cargo test --locked`
Expected: all pass.

- [ ] **Step 7: Commit**

`git commit -am "feat: add guarded SeekNow REST client"`

### Task 4: Implement SeekNow collection, fast/deep escalation and lineage-safe evidence

**Files:**
- Create: `src/seeknow_collector.rs`
- Modify: `src/lib.rs`
- Modify: `ARCHITECTURE.md`
- Modify: `tests/architecture_doc.rs`

**Interfaces:**
- Produces `SeekNowCollector`, selector planning for Email/Username/Phone/IpAddress/Domain/Person, and `collect_with_credential(...) -> Result<CollectionBatch, CollectorError>`.
- Consumes Task 2 collector contract and Task 3 L4 client.

- [ ] **Step 1: Write failing selector-planning tests**

Assert existing canonicalizers are used; unsupported/invalid selectors fail before transport; Person uses auto-detect; email/username/phone/IP/domain use expected type.

- [ ] **Step 2: Verify RED**

Run: `cargo test --locked seeknow_collector::tests`
Expected: failure because the module does not exist.

- [ ] **Step 3: Implement fast-first orchestration**

Fast positive stops. Only non-truncated structurally valid `ValidZero` escalates once to deep. Every other non-success state stops without spending deep credit. Fast-zero + deep failure retains receipts and reports partial/inconclusive rather than absence.

- [ ] **Step 4: Add failing evidence/lineage/dedup tests**

Assert safe entity extraction; `EvidenceProvenance.source == "seeknow"`; upstream alias attributes survive; `Lineage::of` uses existing precedence; duplicate rows and fast/deep duplicates do not multiply evidence families; multiple distinct values in the deciding field produce `Lineage::Ambiguous`; source-only rows are unattributed; raw secret fields never appear in entity/evidence text.

- [ ] **Step 5: Implement row-to-evidence/entity conversion and UID dedup**

Use existing `Entity`/canonicalization/`absorb` conventions. Count no family by result volume. Keep per-observation provenance while deduplicating entity shells.

- [ ] **Step 6: Verify GREEN and full suite**

Run: `cargo test --locked seeknow_collector::tests && cargo test --locked lineage::tests && cargo test --locked`
Expected: all pass.

- [ ] **Step 7: Commit**

`git commit -am "feat: collect SeekNow evidence with lineage"`

### Task 5: Add the L5 CLI adapter and binary surface

**Files:**
- Create: `src/seeknow_cli.rs`
- Modify: `src/lib.rs`
- Modify: `src/main.rs`
- Modify: `ARCHITECTURE.md`
- Modify: `README.md`
- Modify: `tests/architecture_doc.rs`

**Interfaces:**
- Produces `SEEKNOW_USAGE`, `SEEKNOW_HELP`, `SeekNowRun`, and `run<T: Transport + ?Sized>(transport, args, resolved_keys, now_unix)` (or equivalent key-resolver injection that remains testable).
- Binary exposes `seeknow status`, `seeknow credits`, `seeknow search KIND VALUE [--deep|--fast-only] [--keys FILE]` and calls only L5.

- [ ] **Step 1: Write failing CLI tests**

Cover usage, missing key with zero requests, status/credits rendering, positive/zero/partial outcome wording, exact stable exit-class mapping through `SeekNowRun`, and absence of raw key/fingerprint/raw password in rendered output.

- [ ] **Step 2: Verify RED**

Run: `cargo test --locked seeknow_cli::tests`
Expected: failure because the adapter does not exist.

- [ ] **Step 3: Implement key loading and L5 command adapter**

Resolve `--keys` or default `~/.huntsman.env` through `Keys::resolve`; build `AuthenticationAuthority` + `Credential` for SeekNow; never print fingerprint. `status` and `credits` are still routed through L5 adapter functions, not called from `main` into L4.

- [ ] **Step 4: Wire binary and docs**

Map usage 64, invalid selector/data 65, missing/unreadable key 66, unavailable/rate/quota/parser 69, auth/entitlement/egress 77. Update help/README and architecture binary command count/role.

- [ ] **Step 5: Verify GREEN and full suite**

Run: `cargo test --locked seeknow_cli::tests && cargo test --locked --test architecture_doc && cargo test --locked`
Expected: all pass.

- [ ] **Step 6: Commit**

`git commit -am "feat: expose SeekNow collector CLI"`

### Task 6: Differential, adversarial and release verification

**Files:**
- Add/update recorded SeekNow fixtures/tests under existing test conventions.
- Modify documentation only where verification evidence requires it.

**Interfaces:**
- Proves overlap against oracle `7dca720` for request body/type omission/limit, fast/deep separation, envelope-vs-payload failure classification, and zero-vs-failure semantics.

- [ ] **Step 1: Add differential/adversarial fixtures**

Fixtures are synthetic/recorded and contain no live secrets. Pin documented intentional divergences: no mirror rotation, no key fingerprint persistence, malformed/truncated is not zero.

- [ ] **Step 2: Run focused and full verification**

Run: `cargo fmt --check`
Expected: success.

Run: `cargo clippy --all-targets --locked -- -D warnings`
Expected: success.

Run: `cargo test --locked`
Expected: success on stable and Rust 1.87.

Run: `cargo run --locked -- check && git diff --exit-code -- var/`
Expected: success and no committed-artifact drift.

Run: `.github/scripts/scan-for-keys.sh`
Expected: success/no secret finding.

- [ ] **Step 3: Verify Android AArch64**

Run the repository CI `Android aarch64 cross-build` job on the final commit.
Expected: release binary builds for `aarch64-linux-android` and ELF verification succeeds.

- [ ] **Step 4: Attempt bounded live diagnostics when an operator key is available**

Run `/credits`, `/status`, then a neutral synthetic/reserved-domain search (`example.com`). Record commit SHA, UTC, response hash/outcome, count and truncation. If no usable key is available, record this as an external live-verification blocker; do not fabricate a pass.

- [ ] **Step 5: Whole-branch review and one repair pass**

Compare against the approved spec and Review Focus. Any Critical/Important finding gets one test-first repair and full re-verification.

- [ ] **Step 6: Commit verification artifacts/docs if changed**

`git commit -am "test: verify SeekNow reconstruction"`
