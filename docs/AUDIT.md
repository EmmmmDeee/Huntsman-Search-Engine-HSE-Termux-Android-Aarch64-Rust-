# Huntsman adversarial repair audit

Date: 2026-10-24. Recovered baseline: `8473375441c524d24cc45dc0d1daa86d91fb28ff`.
Exact delivered commit, checks and measurements: archive `VERIFICATION.md`.

## Executive summary

The old workspace did not survive the environment replacement. Its unpublished
commit `e8640cb5161fefff786202a2def82ab09b803b3e`, pending patches, audit and ZIP
were absent; GitHub could not resolve that commit. This tree comes from current
public main. It is not a reconstruction of missing source from conversation text.
Earlier repair counts and test results do not describe this revision.

Current main explicitly calls `hse` the legacy monolith. Its canonical product is
`huntsman-recon`, a synchronous Rust collector, saved-scan/evidence system and web
UI. It uses ureq, JSON files and a hash-chained evidence ledger. The old curl and
SQLite objections do not apply. Copying those fixes here would repair imaginary
code and risk real capability.

Three current production defects and one test-isolation defect are repaired below. This is a repository inventory plus a
focused adversarial repair, not a claim that every provider, parser or requirement
has been proved. The requested legacy offline index and recovery of the unpublished
repair tree remain unverified. A source ZIP does not manufacture a phone result.

## Inventory and acceptance scope

- One runtime package/binary, `huntsman-recon`; `xtask` is development automation.
- Rust edition 2024, MSRV 1.87; serde, serde_json, thiserror, ureq and ring.
- Shared HTTP boundary in `src/http.rs`; redirect/auth policy in `src/fetch.rs`.
- Saved scans in `scan_store`; portable JSON artifacts in `scan_artifact`.
- Offline ledger checks, saved-scan analysis/search/export and graph logic exist;
  live OSINT requests require network. No Tantivy/vector implementation is claimed.
- Existing CLI/API, valid version-1 data, auth and origin policies are preserved.
- Changes add no dependencies, unsafe, schema migration or runtime non-Rust code.
- Independent source/counterexample reviews used actual transport and persistence
  sub-agents. No named person was consulted and no independent device run occurred.

## Repaired items

| ID | Severity / classification | File:line | Issue and trigger | Fix and cost | Verification / falsification condition |
|---|---|---|---|---|---|
| AV-01 | medium / verified defect | `src/http.rs:455`; `src/fetch.rs:782` | Query-only, empty and fragment-only redirects lose the current page/query; literal dot segments are not normalized. All followed provider redirects share the defect. | RFC3986 path/reference merging and a shared dot-segment helper. Preserve raw query/encoded octets/empty segments; exclude fragments. Cost: small parser maintenance surface; WHATWG normalization is not claimed. | Baseline RFC regression fails on empty reference. Fixed tests cover 29 reference vectors, a fragment-bearing base, 216 generated path/query invariants, fetch target/auth/redaction, and an independent compiled six-case probe. Failure means wrong target, modified query, origin drift or credential regression. |
| AV-02 | medium / verified defect | `src/scan_store.rs:435`; `src/scan_store.rs:481` | Create/update accepts unsupported row versions that get() rejects. Invalid updates can replace a readable record. | Shared format guard before admission/directory creation/update. Cost: invalid-version errors now precede path-existence errors; valid v1 behavior unchanged. | Two baseline-red filesystem tests; versions 0, 2 and u32::MAX must fail, create no scan directory, and preserve existing bytes/reloadability. |
| AV-03 | medium / verified defect | `src/scan_artifact.rs:125` | Artifact writer can replace a readable artifact with a version its reader refuses. | Reject unsupported format before serialization/parent creation. Existing reader-corruption test now writes its raw fixture directly. Cost: formerly accepted invalid writes return existing UnsupportedVersion errors. | Two baseline-red tests; invalid versions must not create parents or replace bytes, and the saved artifact must still reload. Reader rejection remains tested independently. |

| AV-04 | low / verified test-isolation defect | `tests/serve_startup.rs:14` | Startup fixtures inherit HOME/HUNTSMAN_HOME and may use real operator state. A read-only HOME makes two exact-diagnostic assertions fail. | Shared helper selects writable test-only HOME and removes inherited HUNTSMAN_HOME before explicit fixture overrides. Cost: test-only environment isolation; production warnings and behavior unchanged. | The full gate reproduced two failures with a read-only host HOME. All nine startup cases must pass without modifying the operator's directory. |

Verification commands:

```sh
cargo test --locked --lib redirect_reference_rfc_path_and_query_cases
cargo test --locked --lib path_normalization_is_idempotent_and_never_normalizes_query_data
cargo test --locked --lib query_only_redirect_keeps_the_page_and_same_origin_credential
cargo test --locked --lib unsupported_version_write
cargo run --locked -p xtask -- gate full
```

The first full gate also failed two startup cases because inherited HOME was read-only.
The helper now isolates default state; production correctly retains its warning.

The first broad library run failed a new test that expected an unredacted public
URL. Production correctly returned `?[redacted]`. The test was corrected to inspect
the internal request separately and require public redaction. This objection was
disproved, not patched around. Final executed counts are in VERIFICATION.md.

## Remaining/deferred roadmap

| Priority / ID | Severity / classification | File:line / evidence | Why open; failure mechanism | Recommended correction, cost and measurable closure |
|---|---|---|---|---|
| 1 / R-01 | high acceptance gap / unresolved blocker | Missing previous workspace and unpublished commit; GitHub returned 422 | Cannot compare or preserve every unique legacy repair/capability without its source. Current main is a different architecture. | Recover the earlier ZIP or Git bundle; inventory unique capability against this tree before porting. Cost: external source recovery plus integration. Close with verified blobs and behavior comparisons; never infer recovery from this ZIP. |
| 2 / R-02 | high acceptance gap / unverified | `CANONICAL.md`; `scripts/termux-runtime-acceptance.sh` | No physical Termux device is attached. Cross-builds do not exercise Bionic runtime, flash, process death, Android lifecycle or radio permissions. | Run exact delivered commit through on-device acceptance and saved-state/restart checks, without root. Cost: device/operator access. Target build status is separately recorded in VERIFICATION.md. |
| 3 / R-03 | medium / conditional static concern | `src/http.rs:360` system_resolve | Timeout returns to caller but cannot cancel native resolution; repeated stalled lookups can accumulate worker threads. No live resolver-stall reproduction was performed. | Bound process-wide outstanding native work; retain capacity until worker exit and classify saturation. Cost: medium concurrency design. Falsify with injected blocked resolver and repeated timeouts; outstanding work must stay bounded. |
| 4 / R-04 | medium / probable, unreproduced | `src/session.rs:233`; session Store::save | Wall-clock nanoseconds plus PID do not guarantee distinct IDs; repeated time values can collide with replacement writes. Ordinary runtime collision was not observed. | Separate exclusive creation from intentional updates, with collision retry; frozen-clock regression must preserve both sessions. Cost: store/API design and compatibility review. |
| 5 / R-05 | medium / known durability limitation | `src/fsio.rs:323-339` | Directory open/fsync failures are ignored after rename; visibility is not power-loss durability. Ancestor creation also needs a defined durability boundary. | Define committed-but-unsynced outcome and fault tests before changing post-rename errors. Cost: medium caller/error contract migration. Prove bytes/visibility/retry behavior under injected failures and on target storage. |
| 6 / R-06 | medium / verified license-metadata gap | `xtask/Cargo.toml`; cargo-deny 0.20.2 | The development-only xtask package declares no license. Workspace license checking fails; this is not a vulnerability finding. Fresh cargo-audit reported zero vulnerabilities/warnings against database commit 21d909e4c8bd4e14c7aea58bf980c881a0053ab1 (2026-10-24). | Owner must establish the applicable xtask license and declare it; do not invent rights or suppress the failure. Include the CA-root data CDLA-Permissive-2.0 agreement when distributing that data. Cost: small metadata/notice change after ownership confirmation. Re-run the explicit policy in VERIFICATION.md. |
| 7 / R-07 | medium / unverified requirements | `src/ledger.rs`; `docs/EVIDENCE_REGISTER.md` | Hash chains and raw-data digests do not authenticate upstream claims or supply independent external anchors. No universal document-source/RFC3339/hash/collector provenance guarantee was established. | Audit each collector and define explicit document/snapshot provenance plus external chain anchors. Cost: versioned schemas and collector migration. Test tampering, rollback, deterministic replay and missing fields. |
| 8 / R-08 | medium / unverified | `src/http.rs`, provider adapters, web UI | Fixture success does not prove live paid-provider behavior, independent corroboration or full mobile accessibility. | Quota-bounded credentialed canaries and real device UI checks with provenance. Cost: authorised credentials/device access. No live provider success is claimed here. |
| 9 / R-09 | low / parser scope trade-off | `src/http.rs:455` | RFC3986 raw HTTP URI handling is not a WHATWG/Unicode URL implementation. Generated cases are not exhaustive fuzzing. | Add independent parser differential/fuzz corpus before expanding normalization. Cost: separate parser/dependency review; retain encoded-octet and credential boundaries. |

No merger or release may convert these acceptance gaps into success by relabelling
host tests as target evidence. Prioritize source recovery and device acceptance
before expanding the product.

## Consolidations, UI and Rust status

One shared redirect resolver fixes all fetch callers. One scan-row format guard
serves create and update; no provider, endpoint or evidence source was removed.
The dot-segment helper avoids per-provider URI patches. UI layouts are unchanged:
no demonstrated UI redundancy justified touching them in this repair.

Current orchestration, HTTP, storage and domain logic are Rust. Browser DOM code,
installation/acceptance shell and optional tooling remain where they are needed.
No Rust migration is necessary for these repairs. Ring has native C/assembly;
pure application code does not prove the dependency graph is native-code-free.

## Security, data and deployment findings

- Existing cross-origin credential stripping, downgrade policy, egress validation,
  body limits and public query redaction stay in place; regression gates exercise
  their existing tests. No claim of a new vulnerability in those policies is made.
- Unsupported write versions are rejected before mutation; valid files need no
  migration. Hashing alone is not source authentication or an external time anchor.
- No unsafe, telemetry or new egress path was added. No secret value was introduced.
  This is not a complete secrets/history or dependency-advisory clearance.
- Absolute HUNTSMAN_HOME selects state; legacy HOME/.huntsman remains the default.
  Credentials remain HOME/.huntsman.env. Container-only HUNTSMAN_DATA_DIR is not a
  general CLI storage override. Use the correct variable, not a guessed path.
- Process timeouts cannot kill arbitrary native resolver work. Wall-clock values
  are not unique IDs. Rename is not the same guarantee as durable directory sync.
- Cargo declares MIT OR Apache-2.0. This review does not establish historical
  licensing provenance or provider redistribution rights. Keep provider terms,
  credentials and collected data separate from the source archive; verify those
  rights before distributing data. No external service was provisioned.

## Termux aarch64, non-root

Native Termux uses Android/Bionic: `aarch64-linux-android`. GNU and musl targets are
not native replacements. Commands below are operator instructions, not a claimed
on-device run. Cold dependency download needs network; core checks and saved-data
analysis can run offline once dependencies and inputs are cached.

```sh
pkg update
pkg install -y git rust clang make pkg-config curl
cd Huntsman-Search-Engine
rustc -vV                 # host aarch64-linux-android; Rust >= 1.87
export CARGO_BUILD_JOBS=1
export CARGO_INCREMENTAL=0
export CARGO_PROFILE_TEST_DEBUG=0
export HUNTSMAN_HOME="$HOME/.local/share/huntsman"
# Alternative: export HUNTSMAN_HOME="$PREFIX/var/lib/huntsman"
mkdir -p "$HUNTSMAN_HOME"
chmod 700 "$HUNTSMAN_HOME"
cargo build --release --locked
cargo test --locked --lib
cargo test --locked --lib unsupported_version_write
./target/release/huntsman-recon check
./target/release/huntsman-recon scans list --json
./target/release/huntsman-recon scans analyze SCAN_ID --json
# After caching: cargo test --locked --offline --lib
```

Do not substitute `hse` commands or old SQLite assumptions. See `CANONICAL.md`,
`docs/INSTALL.md` and target acceptance scripts for current integration. Run the
acceptance script from a Git checkout; the source ZIP intentionally excludes .git.

## Performance and tests

Seven regression test functions were added: four storage preservation cases and
three URL/fetch cases. Existing invalid-file reader coverage remains. The RFC
case table and generated corpus cover paths, queries, encoded separators, empty
segments, Unicode safety and same-origin request credentials. Independent compiled
probes challenged additional empty/base-fragment and repeated-slash cases.

Default multi-toolchain debug/incremental artifacts exhausted this 32 GiB workspace.
Generated caches were removed; the MSRV suite then passed with incremental and
debug-symbol output disabled. The Termux commands use the same storage-saving
settings without changing release behavior.

The changes prioritize correctness, not speed. No speedup or provider latency
improvement is claimed. VERIFICATION.md distinguishes actual benchmark workloads,
profiles and measurements from unavailable legacy index/ranking benchmarks.

### Measured redirect cost

Isolated x86_64 host microbenchmark, Rust 1.87, unoptimized library with debug
symbols/incremental output disabled; opt-level=2 benchmark driver. Five legacy
valid references, 10,000 warmups, seven samples of 100,000 resolutions each:

| Version | Median per resolution |
|---|---:|
| Recovered baseline 8473375 | 2.254 microseconds |
| Repaired resolver | 2.672 microseconds |

The measured cost is +0.418 microseconds (+18.6%) in this synthetic debug-path
comparison. This is a correctness repair, not a speed improvement. No provider or
end-to-end latency conclusion follows. Source and raw samples are packaged as
verification evidence. An initial shared-target-directory baseline reused the
repaired library and was discarded after a behavior probe exposed it. The retained
comparison uses separate target directories and asserts the old/new query-only
behavior before timing. Legacy index/query/ranking/dedup measurements cannot be
recovered from the missing old source and are not fabricated here.
