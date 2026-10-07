# Repair protocol

Use this protocol for any error, bug, broken file, malfunctioning code path,
failed refactor, unexpected test result, or repository inconsistency.

## Objective

Restore the repository to the strongest verified working state without hiding,
weakening, or bypassing the failing invariant.

## Required sequence

1. **Reproduce** the failure with the smallest command that demonstrates it.
2. **Localize** the causal boundary: identify the first failing layer, file,
   invariant, or interface.
3. **Diagnose** the defect from evidence. Do not treat a downstream symptom as
   the root cause.
4. **Repair** the smallest sufficient surface. Preserve verified behavior and
   avoid unrelated rewrites.
5. **Verify** the original reproducer now passes.
6. **Regression-check** the repository with the deterministic repair gate.
7. **Falsify** the fix by checking the strongest plausible adjacent failure mode
   or invariant that could have been broken by the repair.
8. **Retain or roll back**: keep only changes that pass the relevant acceptance
   gates.

## Deterministic repair gate

Run one of:

```sh
bash scripts/repair-gate.sh fast
bash scripts/repair-gate.sh msrv
bash scripts/repair-gate.sh full
```

Use `full` before declaring a general Rust/code repair complete. Use `msrv`
when validating under the repository minimum Rust version. Use `fast` only for
cheap iteration while the defect is still being localized.

A successful `full` gate requires:

- shell syntax checks for the repository repair and Railway runtime harnesses;
- `cargo fmt --check`;
- strict `cargo clippy --all-targets --locked -- -D warnings`;
- `cargo test --locked`;
- `huntsman-recon check`;
- no uncommitted drift in committed `var/` artifacts.

## Railway-specific continuation

If the repaired surface can affect Railway/container behavior, local repair is
not the terminal acceptance state. After the full gate and GitHub CI pass, run:

```sh
HUNTSMAN_RAILWAY_URL=https://YOUR-SERVICE.up.railway.app \
HSE_AUTH_TOKEN="$HSE_AUTH_TOKEN" \
  bash scripts/railway-live-acceptance.sh
```

Then verify Railway deployment metadata identifies the exact intended commit.

## Stop conditions

A repair is complete only when the original failure is reproduced before the
fix, absent after the fix, the relevant regression gate passes, and no
decision-relevant adjacent regression remains. If a gate fails, continue from
that failing evidence rather than weakening the gate.
