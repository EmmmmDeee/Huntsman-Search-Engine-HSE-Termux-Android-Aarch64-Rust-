# Fortified engineering controller (Rust)

The command runs in the existing `xtask` development crate, **not** in the Android runtime.
Its role names are static responsibilities, not separately running agents or endorsements.

## Commands

```sh
cargo run --locked -p xtask -- fortify plan
cargo run --locked -p xtask -- fortify validate
cargo run --locked -p xtask -- fortify status
cargo run --locked -p xtask -- fortify run fast
cargo run --locked -p xtask -- fortify run full
cargo run --locked -p xtask -- fortify score 1000 100 50 200 150
```

The last example returns net value **500 units**. Inputs are nonnegative integer units. Output
explicitly separates calculation from any approval to spend money or deliver software.

- **Design:** immutable 16-role authority hierarchy, phase dependencies and acceptance contracts.
- **Research:** evidence, timestamps, and unknowns are required for claims; the controller does
  not fabricate outside research.
- **Implement:** reuse current rootless Android AArch64 Rust project and existing interfaces.
- **Optimise:** `fortify run` delegates to `xtask gate`, retaining its lock, timeouts, logs,
  formatting, clippy, tests, mutation detection and error propagation.
- **Deploy:** release promotion stays with existing dedicated workflows and explicit approval.
  This controller cannot merge, publish, rotate credentials or purchase infrastructure.

`status` prints the actual checkout commit, branch, dirty flag and observation timestamp;
it **never** claims that tests ran or that a deployment succeeded. `validate` checks static
topology and repository gate wiring, not runtime or provider availability.

## Continuous checks and recovery

`.github/workflows/fortified-controller.yml` runs daily and on manual dispatch with only
read permissions. Existing `ci.yml`, `audit.yml` and `release.yml` remain authoritative.
A failed required gate blocks promotion; no automatic merge or destructive rollback is
attempted. Rebuild/redeploy and health-checked rollback must be supplied by the target
platform's deployment workflow. The Android runtime retains its existing lightweight
local operation and does not acquire an LLM or additional runtime crate.

The policy targets (including mutation and contract coverage) are objectives, **not**
statements that measurement has reached 100%. Real results are determined by CI, Android
acceptance checks, and verified release receipts.
