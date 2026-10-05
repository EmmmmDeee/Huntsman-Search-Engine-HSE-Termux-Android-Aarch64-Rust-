# Telegram Read-only Intelligence Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a Rust-native, authenticated, strictly read-only Telegram intelligence module with bounded local indexing and reuse of Huntsman's existing entity/correlation pipeline.

**Architecture:** Pure indexing/entity-conversion logic always compiles; authenticated Telegram networking is isolated behind the optional `telegram` feature. A private grammers client wrapper provides only auth and search methods, while HSE-owned JSON indexing uses existing bounded atomic file I/O.

**Tech Stack:** Rust 2024, serde/serde_json, existing HSE entity/classifier/correlation/fsio code, optional grammers-client 0.10, grammers-stringsession 0.1.1, Tokio.

**Spec:** `docs/superpowers/specs/2026-10-06-telegram-readonly-intelligence-design.md`

## Global Constraints

- Rust only; `unsafe` remains denied.
- Rust MSRV remains 1.87.
- Default builds do not compile Telegram dependencies.
- Network capability is opt-in via Cargo feature `telegram`.
- No Telegram mutation APIs may be exposed or invoked.
- Telegram session credentials are stored separately in a private file.
- HSE-owned index snapshot is at most 16 MiB and at most 10,000 records.
- Tests must not require a Telegram account or network access.

## Review Focus

- Duplicate `(peer_id, message_id)` observations update deterministically instead of multiplying records.
- Empty/tokenless local queries return no hits and cannot panic.
- Oversize/corrupt index files fail closed rather than becoming an empty index silently.
- Telegram-derived identifiers carry the message URI and source provenance needed for auditability.
- Feature-off builds never reference optional grammers/Tokio types.

---

### Task 1: Pure Telegram record/index contract

**Files:**
- Create: `src/telegram_intel.rs`
- Modify: `src/lib.rs`

**Interfaces:**
- Produces: `TelegramRecord`, `TelegramIndex`, `TelegramSearchHit`, `TelegramIntelError`.
- Produces: `TelegramIndex::{new, ingest, search, load, save}`.

- [ ] **Step 1: Write failing unit tests** in `src/telegram_intel.rs` for stable deduplication, all-term token search, empty-query behavior, and save/load round trip.
- [ ] **Step 2: Push tests only and verify CI fails** because the Telegram index types/functions do not exist yet.
- [ ] **Step 3: Implement the minimal pure index** using `search::tokenize`, `fsio::read_bounded`, and `fsio::write_atomic`; enforce 10,000 records and 16 MiB.
- [ ] **Step 4: Run/observe CI** and require the default test matrix to pass.

### Task 2: HSE entity extraction and cross-source correlation

**Files:**
- Modify: `src/telegram_intel.rs`

**Interfaces:**
- Produces: `TelegramIntelBatch`.
- Produces: `record_entities(record, scan_id) -> (Vec<Entity>, Vec<EntityRelation>)`.
- Produces: `correlate_with(existing, telegram_entities, scan_id, now_unix) -> Vec<Correlation>`.

- [ ] **Step 1: Add failing tests** proving a message creates a `Document`, classifier-derived identifiers with `telegram` provenance/URI attributes, `MentionedWith` relations, and deterministic UID merging with existing entities.
- [ ] **Step 2: Verify red in CI** before adding production behavior.
- [ ] **Step 3: Implement extraction/correlation** with existing `classifier`, `Entity`, `Evidence`, `EntityRelation`, and `correlation_bridge` APIs only.
- [ ] **Step 4: Verify default CI green** and no existing correlation tests regress.

### Task 3: Feature-gated authenticated read-only Telegram client

**Files:**
- Modify: `Cargo.toml`
- Modify: `Cargo.lock`
- Modify: `src/telegram_intel.rs`

**Interfaces:**
- Feature: `telegram`.
- Produces: `TelegramAccount::open`, `is_authorized`, `request_login_code`, `sign_in`, `search_global`, `search_peer` and `save_session`.
- Raw grammers client remains private.

- [ ] **Step 1: Add compile-time/source-surface tests first** that require the feature API and assert the module source does not contain Huntsman calls to mutating grammers methods (`send_message`, `edit_message`, `delete_messages`, `join_chat`, `leave_chat`, `react`, `forward_messages`).
- [ ] **Step 2: Verify feature CI is red** because optional dependencies/API are absent.
- [ ] **Step 3: Add optional dependencies and implement wrapper** using `grammers-client = 0.10`, `grammers-stringsession = 0.1.1`, and a Tokio current-thread runtime; session string is read/written through private bounded HSE file I/O.
- [ ] **Step 4: Compile/test with `--features telegram`** and fix only code/dependency compatibility issues surfaced by the real compiler.

### Task 4: CLI integration and feature-off behavior

**Files:**
- Create: `src/telegram_cli.rs`
- Modify: `src/lib.rs`
- Modify: `src/main.rs`

**Interfaces:**
- Produces: `telegram local`, `telegram auth`, `telegram search` command handling.

- [ ] **Step 1: Add failing CLI parser tests** for local search, feature-off network error text, bounded numeric limit, and secret-free diagnostics.
- [ ] **Step 2: Verify tests fail before CLI implementation.**
- [ ] **Step 3: Implement CLI** with defaults under `~/.huntsman/telegram/` and environment slots `HUNTSMAN_TELEGRAM_API_ID` / `HUNTSMAN_TELEGRAM_API_HASH`.
- [ ] **Step 4: Verify default and Telegram-feature test suites.**

### Task 5: CI and regression verification

**Files:**
- Modify: `.github/workflows/ci.yml`

**Interfaces:**
- Produces: a stable Linux job compiling/testing `--features telegram` on Rust 1.87 and stable while preserving the existing Android default-feature cross-build.

- [ ] **Step 1: Add the feature CI job.**
- [ ] **Step 2: Observe workflow results for default Rust 1.87, stable/clippy/fmt, Android aarch64 default build, and Telegram feature build/tests.**
- [ ] **Step 3: Inspect the final diff for accidental mutation APIs, secret leakage, unbounded inputs, or default-build dependency regressions.**
- [ ] **Step 4: Only then create the PR and report residual limitation:** live authenticated search cannot be exercised by CI without user credentials, so compile-time and pure-behavior verification are complete while live-account verification remains external.
