# `huntsman-search-engine-fuzz`

`cargo-fuzz` targets for Huntsman's untrusted-byte parsers — the
`cargo-fuzz` leg of `docs/PROBLEM_TREE.md` §3.F (F.3, "proof & measurement
infrastructure"). See that node (and its paired `docs/SOLUTION_TREE.md`
SOL-F3 node) for the full rationale.

## Why this is a separate crate

This directory has its own `Cargo.toml` and is **deliberately not** a
`[workspace]` member of the parent crate (which has no `[workspace]` table
at all). `libfuzzer-sys` needs nightly-only sanitizer instrumentation
(`-Z sanitizer=address` under the hood) that fails to build on the stable
toolchain the project's four-command verification gate (`cargo fmt` /
`clippy` / `doc` / `test`) runs on every cycle. Keeping `fuzz/` a wholly
separate crate means those commands never see it — the gate stays green on
stable, unaffected — and only `cargo fuzz` (nightly-only, its own CI lane:
`../.github/workflows/fuzz.yml`) ever builds it.

## Targets

- **`cert_der`** — `cert_intel`'s hand-rolled DER certificate scanner
  (`extract_sans_from_der` / `extract_field_from_der` / `extract_serial_hex`,
  reached via the crate's `#[doc(hidden)] pub fn fuzz_entry_parse_der`).
  This parser reads a live TLS peer's certificate bytes directly — fully
  attacker-controlled input — and is the same code that fixture testing
  alone already found two real bugs in (see `PROBLEM_TREE.md` T2.3).

## Running locally

Requires a nightly toolchain and `cargo-fuzz`:

```sh
rustup toolchain install nightly
cargo install cargo-fuzz
```

**Important:** libFuzzer treats every corpus directory passed on its command
line as read *and write* — it saves newly-discovered interesting inputs back
into it. Never point a run directly at `../src/modules/cert_intel/testdata/`
(or any other real fixture directory) or it will get littered with generated
files. Seed a scratch corpus dir first:

```sh
mkdir -p corpus/cert_der
cp ../src/modules/cert_intel/testdata/selfsigned.der corpus/cert_der/seed_selfsigned.der
cargo +nightly fuzz run cert_der corpus/cert_der -- -max_total_time=60
```

`corpus/`, `artifacts/`, `target/`, and `coverage/` are all gitignored
(`fuzz/.gitignore`) — this crate has no persisted, growing corpus checked
into the repository; each run (local or CI) starts fresh from the real
fixture seed above.

## CI

`../.github/workflows/fuzz.yml` runs `cert_der` for a bounded 120s on a
weekly schedule, on a change to `fuzz/**` or `src/modules/cert_intel/**`, and
on manual dispatch. Advisory-quality, like `../.github/workflows/audit.yml`
— not a required check, since the from-scratch ASAN-instrumented rebuild of
the whole crate is too slow (~12 minutes) for every push/PR.
