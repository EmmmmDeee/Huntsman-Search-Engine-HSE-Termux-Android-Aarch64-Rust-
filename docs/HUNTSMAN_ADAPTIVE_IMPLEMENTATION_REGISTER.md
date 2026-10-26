# Huntsman adaptive implementation register

Repository: https://github.com/EmmmmDeee/Huntsman-Search-Engine-HSE-Termux-Android-Aarch64-Rust-
Baseline main: 7760296feff852e505d4579e4b4866798eaf75ea
Open identity-resolution integration: PR #1427, head 433cf2d213d7634ab7f755fceb657d9512f6dad5.
Status: CI and Android release checks in progress when inspected. Never mark merged until confirmed.

## Execution contract
Discover → inventory → classify → correlate → prioritise → implement → wire → test → cross-build → merge → verify → refresh. Preserve existing functionality, evidence provenance, CLI, localhost Web UI and rootless Termux AArch64 operation. No runtime LLM, mandatory cloud dependency, or invented provider keys.

## Priorities
P0: Build failures, security flaws, evidence corruption, data loss, broken installs, regressions. Fix before feature expansion.
P1: Rootless Termux startup, CLI, Web UI, Android AArch64 cross-build, compatibility and release pipeline.
P2: Unwired modules, duplicate providers, mismatched contracts, unused but valid code, adapter normalisation.
P3: Resource-bounded concurrency, streaming results, caches, latency, storage, documentation and observability.

## Inventory classification
Every file starts EXISTING/UNKNOWN. Upgrade classification only with proof:
WIRED: reachable from production entrypoint and exercised in a test.
UNWIRED: no production path, confirmed by call graph and feature-aware tests.
OVERLAPPING: same behavior as another module, with tested equivalence.
INCOMPATIBLE: reproducible contract, dependency, target, or data-schema conflict.
BLOCKED: exact external limitation and reproduction.
VERIFIED: tests and runtime evidence attached.
Do not delete or rename on filename heuristics. Record owner, dependencies, affected contracts, migration, rollback, and evidence.

## Verified baseline inventory
GitHub recursive tree on main was complete (truncated=false): 1,084 files, 80 directories, 360 src files, 161 tests files, 39 scripts files, 39 docs files, 36 xtask files, 400 changelog fragments. This is a point-in-time inventory, not an assessment of wiring.
Existing src subtrees: asn_cli, certspotter, cli/lookup, correlations/spiderfoot, correlator, crtsh, dehashed, dns_filter, dns_wire, dnsbl, docmeta, doctor, domain_cli/resolve, evidence_register, exif, hibp, ip_cli, isc, lookup_modules, maltiverse, mnemonic, netblock_cli, network_cli, nominatim, oathnet, phishstats, rdap, rdap_legs, relation/builders, sf_correlate, shodan, stolen_tax, threat_feeds, trafficking_intel, wigle, wikipedia, x509.
Existing workflow files: audit.yml, ci.yml, dual-pass.yml, fortified-controller.yml, issue-fix.yml, mitm-eligibility.yml, release.yml.

## Implementation ordering
1. Read AGENTS.md, CANONICAL.md, ARCHITECTURE.md, Cargo.toml, Cargo.lock, .cargo/config.toml and existing CI workflow contracts.
2. Inventory tracked files and all Rust modules, features, exports, calls, web routes, provider registrations, tests, and schema changes. Maintain every original path in a tree.
3. Generate a dependency DAG; find entrypoints and disconnected components. Classify each with evidence. Never equate unused exports with dead code without checking feature flags, tests, and dynamic registries.
4. Repair build/security/provenance failures first. Work in small isolated commits with explicit tests.
5. Preserve shared immutable evidence contracts; enforce bounded queues, timeouts, concurrency, memory, disk, and deterministic output.
6. Keep Android rootless: no privileged interfaces, root assumptions, glibc-only dependencies, or mandatory background services. Bind local Web UI to 127.0.0.1 by default.
7. Verify cargo fmt, cargo test --workspace --locked, cargo clippy --workspace --all-targets --locked -- -D warnings; check both pinned supported Rust versions.
8. Verify Android aarch64 build, Termux install and recovery, localhost Web UI, QEMU where appropriate, credential handling, and low-resource behavior.
9. Merge only exact-head green checks and permitted review; verify origin/main SHA, installation and health after merge.
10. Regenerate inventory after each accepted change; repeat until no verified open blockers. Absolute completion is not provable for an evolving codebase.

## Machine-readable task schema
Each task is a JSON object:
{"id":"HSE-P0-001","priority":"P0","status":"open","paths":["src/resolve.rs"],"classification":"existing","defect":"description","evidence":[],"dependencies":[],"acceptance":["repro test","regression test","CI","Termux smoke"],"risk":"medium","owner":null,"commit":null,"verified_at":null}
Task state transitions: open → investigated → reproducible → implementing → locally_verified → ci_verified → merged → postmerge_verified. Blocked tasks require reason and retry trigger.

## Adaptive refresh
Use the companion inventory generator after every checkout, commit, and merge. It walks the current git tracked tree, preserves all paths, and writes a full tree plus JSON index. A scheduled GitHub Actions workflow can run it on push or a daily schedule; automation does not run unless installed and enabled in the repository.
