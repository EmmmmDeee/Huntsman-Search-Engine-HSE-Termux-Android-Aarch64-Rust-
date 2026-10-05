# Rust-native read-only Telegram intelligence design

## Objective

Add a first-class Huntsman Telegram intelligence subsystem that can authenticate a Telegram user account, perform read-only message search, persist bounded local search state, extract HSE entities with provenance, and correlate those entities with existing Huntsman evidence.

The subsystem must not expose message sending, reactions, joins/leaves, contact mutation, moderation, deletion, editing, or other Telegram account mutation operations.

## Constraints

- Rust only in the Huntsman runtime.
- Existing default build stays dependency-light and remains functional without Telegram support.
- Telegram networking is opt-in behind the Cargo feature `telegram`.
- Rust version remains `1.87`.
- `unsafe` remains denied.
- Android/Termux is a target platform; avoid native database dependencies in the Huntsman-owned message index.
- Telegram session material is credential-equivalent and is stored separately from evidence/index data with private-file semantics.
- Collection is bounded: a caller supplies a result limit and the module enforces hard record/index size limits.
- Every entity derived from Telegram carries explicit `telegram` provenance and a stable message URI.
- Cross-source correlation must reuse Huntsman's existing entity/correlation primitives rather than inventing a Telegram-specific identity model.

## Architecture

### `src/telegram_intel.rs`

Owns all Telegram-specific data shapes and pure logic:

- `TelegramRecord`: normalized immutable observation of one Telegram message.
- `TelegramIndex`: bounded persistent record set plus deterministic inverted token index.
- `TelegramSearchHit`: local hit with score and record.
- `TelegramIntelBatch`: records, extracted entities, relations, and HSE correlations produced from a collection.
- entity extraction from message text through `classifier::extract`, augmented with authoritative Telegram peer/sender usernames and visible sender phone metadata when available.
- one `Document` entity per Telegram message plus `MentionedWith` relations to extracted entities.
- `correlate_with(existing, telegram_entities, scan_id, now_unix)` delegates to `correlation_bridge::correlate_entities_at` after deterministic entity merging.

Persistence uses HSE `fsio::{read_bounded, write_atomic}`. The index snapshot is JSON and includes both records and the inverted map. Writes are atomic; symlinks and oversize snapshots are refused by the shared I/O layer. The implementation caps the snapshot at 16 MiB and 10,000 records.

### Authenticated networking (`telegram` feature)

The same module contains a feature-gated `TelegramAccount` wrapper around `grammers-client 0.10`.

- Session state uses a grammers `MemorySession` serialized through `grammers-stringsession` into a private file using `write_atomic_private`.
- `SenderPool` is run on an internal Tokio current-thread runtime owned by the wrapper.
- Public methods are intentionally limited to authentication status/login and read operations: global search and per-username peer search.
- The raw `grammers_client::Client` is private and is never returned.
- No method invokes Telegram mutation APIs.
- Login may request a code and complete sign-in (including optional 2FA password) because authentication is required to obtain the read-only session; this is not treated as content mutation.

### Cross-source flow

1. An authenticated search returns `TelegramRecord` values.
2. Records are ingested into `TelegramIndex` with stable `(peer_id, message_id)` deduplication.
3. Each record is converted into a `Document` entity and zero or more extracted entities with `telegram` provenance attributes (`peer_id`, `message_id`, `telegram_uri`).
4. `MentionedWith` relations connect the message document to identifiers observed in the message.
5. Telegram entities are merged with caller-supplied existing HSE entities by UID.
6. The existing Huntsman correlation registry runs on the merged set; Telegram does not create its own correlation confidence rules.

## CLI integration

Add a `telegram` command:

- `telegram local QUERY [INDEX]` works in every build and searches the local index only.
- When compiled with `--features telegram`, `telegram auth PHONE [SESSION]` performs interactive login if required and saves the private session.
- When compiled with `--features telegram`, `telegram search QUERY [LIMIT] [INDEX] [SESSION]` performs authenticated global Telegram search, indexes results, emits JSON, and reports extracted entity/correlation counts.
- Without the feature, network subcommands fail clearly with an instruction to rebuild using `--features telegram`.

Credentials come from `HUNTSMAN_TELEGRAM_API_ID` and `HUNTSMAN_TELEGRAM_API_HASH`; secret values are never logged or serialized into evidence.

## Verification / acceptance

The feature is accepted when:

1. Default `cargo test --locked` remains green without compiling Telegram dependencies.
2. Pure tests prove stable deduplication, bounded persistence, deterministic token search, provenance-bearing entity extraction, and reuse of the correlation bridge.
3. Feature build/tests compile with Rust 1.87 using `cargo test --locked --features telegram` without network access.
4. A source-surface regression test proves the public Telegram module contains no mutating operation names and the wrapper exposes no raw client accessor.
5. CI adds a Telegram-feature compile/test job while preserving the existing Android default build.
6. No test requires real Telegram credentials or network access.
