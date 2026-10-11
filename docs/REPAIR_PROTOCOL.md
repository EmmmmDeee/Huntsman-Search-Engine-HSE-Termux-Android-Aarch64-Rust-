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

## Integration discipline

A repair that spans multiple dependent files must not be published as a sequence
of knowingly inconsistent intermediate states on `main`. Prefer one atomic
commit or a temporary branch/PR, run the relevant gates there, and merge only
the coherent state. If tooling cannot create an atomic multi-file change, use a
branch rather than relying on a later commit to repair an earlier broken one.

Release publication must independently require the shared repair and Railway
quality gate. A successful artifact build alone is not sufficient evidence that
the source revision is releasable.

## Deterministic repair gate

Run one of:

```sh
cargo gate fast
cargo gate msrv
cargo gate full
```

Use `full` before declaring the host-side Rust/code repair complete. Use `msrv`
when validating under the repository minimum Rust version. Use `fast` only for
cheap iteration while the defect is still being localized. The host gate is necessary, not universally sufficient: platform-specific behavior needs its own evidence.

A successful `full` gate requires:

- shell syntax checks for the repository repair and Railway runtime harnesses;
- `cargo fmt --check`;
- no `unwrap()` in production code: `cargo clippy -p huntsman-recon --lib --bins --locked -- -D clippy::unwrap_used` and the same for the `xtask` binary (these targets compile without `cfg(test)`, so tests are not linted; `fast` runs this step too);
- strict `cargo clippy --all-targets --locked -- -D warnings`;
- `cargo test --locked`;
- `huntsman-recon check`;
- verification does not mutate tracked or untracked repository content, including a worktree that was already dirty before the gate.

## Acceptance scope matrix

The repair gate verifies the host repository contract, not every deployment
environment. Choose additional evidence from the surface changed:

- **Rust/core logic or ordinary repository files:** original reproducer + `full` gate.
- **Railway/container:** original reproducer + `full` gate + Railway container CI + live Railway acceptance against the exact deployed commit.
- **Android cross-build:** original reproducer + `full` gate + Android aarch64 CI artifact verification.
- **Termux runtime behavior:** Android build evidence is insufficient; run the real-device Termux acceptance harness before claiming handset-runtime success.
- **Documentation/config/data files:** run the narrow parser/validator or reproducer that proves that file's semantics, then the relevant repository/platform gates.

A generic green gate must never replace the original reproducer. It shows that
the repair did not break the covered contract; it does not by itself prove the
reported defect was fixed.

## Railway-specific continuation

If the repaired surface can affect Railway/container behavior, local repair is
not the terminal acceptance state. After the full gate and GitHub CI pass, run:

```sh
HUNTSMAN_RAILWAY_URL=https://YOUR-SERVICE.up.railway.app \
HSE_AUTH_TOKEN="$HSE_AUTH_TOKEN" \
  bash scripts/railway-live-acceptance.sh
```

Then verify Railway deployment metadata identifies the exact intended commit.

For Railway Infrastructure as Code, CI type-checks `.railway/railway.ts` against
pinned Railway SDK and TypeScript versions. Before applying infrastructure
changes, run the authenticated read-only live plan:

```sh
bash scripts/railway-iac-plan.sh
```

The plan is evidence of live drift; the type check alone is not.

## Historical prerelease quarantine

Nine main-channel prereleases were independently revalidated as having been
published from commits whose corresponding CI run concluded `failure`. They
are pinned in `.github/unverified-prereleases.json` and are not acceptable
evidence for deployment or release acceptance.

Audit the set without mutation:

```sh
bash scripts/cleanup-unverified-prereleases.sh audit
```

Deletion is deliberately guarded and requires explicit operator action plus a
GitHub token with release write permission:

```sh
bash scripts/cleanup-unverified-prereleases.sh delete
```

Before deletion, the script rechecks that each target still exists as a
prerelease, still points at the recorded commit, and still has the recorded CI
conclusion `failure`.

For Termux runtime claims, use the existing stronger harness:

```sh
bash scripts/termux-runtime-acceptance.sh
```

A cross-build alone does not establish real-device runtime behavior.

## Stop conditions

A repair is complete only when the original failure is reproduced before the
fix, absent after the fix, the relevant regression gate passes, and no
decision-relevant adjacent regression remains. If a gate fails, continue from
that failing evidence rather than weakening the gate.
