# CLAUDE.md

Guidance for Claude Code (and other automated contributors) working in this
repository.

## Operational Constitution — binding

[`docs/OPERATIONAL_CONSTITUTION.md`](docs/OPERATIONAL_CONSTITUTION.md) is an
active operational specification, not background reading. Read it before
non-trivial analysis, and apply it continuously.

The directives that bite most often here:

- **Separate observation from inference.** Say what the code/test output
  actually shows, then say what you concluded from it. Never present an
  inference as a verified fact.
- **Confidence follows evidence.** If you have not run it, say you have not run
  it. Report failing tests with their output rather than around them.
- **Unknowns and assumptions stay explicit.** State them at the point where
  they affect the work, not in a footnote.
- **Never fabricate** evidence, observations, sources, or certainty.
- **Truthfulness outranks presentation.** A clear, hedged answer beats a clean,
  overconfident one.

[`docs/PERSISTENT_INTELLIGENCE.md`](docs/PERSISTENT_INTELLIGENCE.md) is its
companion, governing what carries forward between reasoning cycles: carry
validated findings forward, treat every contradiction and failure as diagnostic
rather than noise, and don't close an investigation while material uncertainty
is still reducible. Where the two overlap, the constitution's Order of
Precedence wins — persistence never outranks truthfulness.

For security work, this repository is defensive-only: asset discovery, exposure
assessment, threat modelling, detection, and remediation. Do not add or
recommend capability whose primary use is unauthorized access, exploitation,
persistence, credential theft, or evasion. See
[`SECURITY.md`](SECURITY.md).

## Project

Huntsman Search Engine (`hse`) — on-device OSINT/GEOINT and breach-intelligence
platform targeting Termux aarch64, no root. Rust, edition 2024, MSRV 1.88.
Proprietary; `publish = false` — never publish to crates.io.

- Binary: `hse` (`src/main.rs`)
- Library: `huntsman_search_engine` (`src/lib.rs`)

## Commands

These mirror CI (`.github/workflows/ci.yml`); run them before pushing.

```sh
cargo fmt --all -- --check
cargo clippy --all-targets --locked -- -D warnings
cargo test --all --locked
```

Cross-compilation check for the real target:

```sh
cargo build --locked --lib --bin hse --target aarch64-linux-android
```

Benchmarks (Criterion, `harness = false`): `cargo bench`. CI only compiles them
(`cargo bench --no-run`), so a perf-path API change fails the build rather than
rotting silently.

Live-network drift tests are `#[ignore]`d by default and run in their own
workflow: `cargo test --test live_drift --locked -- --ignored --nocapture`.

## Conventions

- Lint policy lives in `Cargo.toml` under `[lints]` so it applies to local
  builds, rust-analyzer, and CI alike. CI additionally passes `-D warnings`.
  Fix lints rather than adding blanket `allow`s; if a targeted `allow` is
  genuinely correct, comment why.
- Architecture invariants are asserted in `src/lib.rs` and
  `tests/architecture.rs`. A change that trips them is a design decision — raise
  it, don't silence the assertion.
- The running software is the source of truth for module and CLI reference:
  `hse --help`, `hse modules`, `hse selftest`, `hse diagnostics`. Prefer
  checking those over trusting a static doc that may have drifted.
