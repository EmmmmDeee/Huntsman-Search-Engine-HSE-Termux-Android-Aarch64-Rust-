# Huntsman HSE End-to-End Refactor Delivery

**Exact audited base:** `feef60ab48ffe4be599c2ef0f678600cdaffc2aa`

This archive is designed to be merged into an exact checkout of that revision.

## Apply the active refactor

From the Huntsman repository root at the audited base:

```bash
git rev-parse HEAD
# must print:
# feef60ab48ffe4be599c2ef0f678600cdaffc2aa

# Preferred: one combined exact-base patch
git apply --check /path/to/unzipped/HUNTSMAN_REFACTOR_ALL_ACTIVE.patch
git apply /path/to/unzipped/HUNTSMAN_REFACTOR_ALL_ACTIVE.patch

# Equivalent: apply the files listed in APPLY_ORDER.txt one by one.
```

Do **not** batch-apply `patches/revalidation-required/`. Re-derive each affected
provider/semantic contract against current authoritative evidence first.

## Mandatory host verification

```bash
cargo fmt --all -- --check
cargo test --locked --features dep-cooldown --test architectural_invariants
cargo test --all --locked --features dep-cooldown --lib --bins --tests
cargo clippy --all-targets --all-features -- -D warnings
cargo run --bin architecture-audit -- --repo-invariants .
```

If the repository uses narrower feature gates for clippy/test jobs, reproduce
the checked-in CI commands exactly rather than weakening the gate.

## Required falsification

In a disposable worktree:

1. reintroduce a second `skips_auto_update` predicate; require invariant failure;
2. change one workflow/Docker Rust version; require invariant failure;
3. restore both and require the gate to pass;
4. run identity ancestry tests showing two mirrors of one upstream count once;
5. run evaluation tests showing a catastrophic false merge blocks promotion;
6. prove delayed work prevents a `FixedPoint` termination.

## Required Android/Termux acceptance

After host/CI gates:

```bash
cargo build --target aarch64-linux-android --release
hse-test
hse doctor
hse doctor --live
```

Use the project’s normal installer/release verification path on the actual
Android device. Host execution cannot substitute for device verification.

## Directory map

- `overlay/` — complete active new/replacement files.
- `patches/primary/` — ordered exact-base active merge series.
- `patches/revalidation-required/` — prior implementation work requiring
  current-base revalidation before promotion.
- `patches/superseded-reference/` — retained provenance for designs replaced
  by stronger architecture.
- `docs/` / `overlay/docs/` — approved program and execution plan.
- `OUTSTANDING_WORK.json` — machine-readable disposition ledger.
- `STATUS.md` — exact verification boundary.
- `MANIFEST.json` / `SHA256SUMS.txt` — artifact integrity.

No file in this archive should be treated as device-verified until the real
Termux acceptance gates have run.
