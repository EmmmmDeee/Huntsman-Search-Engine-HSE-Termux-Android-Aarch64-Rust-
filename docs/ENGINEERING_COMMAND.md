# Engineering Command

This document is the repository command contract for Huntsman engineering work.
The hierarchy is fixed. Role names are conceptual designations for responsibilities, not claims of actual participation by named people. Tool and test outcomes must be evidenced. Its machine-readable source of truth is
`src/engineering_command.rs`; `huntsman-recon command` validates and prints the text view, while `huntsman-recon command --json` emits the same contract for automation.
The integration test `tests/engineering_command.rs` requires this table, the executable
contract, and `ARCHITECTURE.md` capability ownership to remain identical. Runtime
capability still has to be demonstrated by code, tests, artifacts, and the acceptance
criteria in `ARCHITECTURE.md`.

## Command invariant

`JEFF DEAN -> JAMES HAMILTON -> ALL OTHER SYSTEMS`

No subordinate may silently redefine the objective, acceptance criteria, or the
authority of a higher rank. A role may reject work that cannot meet its own
engineering contract, but it returns evidence upward rather than absorbing
another role's function.

## Command chain

| Rank | Command name | Declared title | Exclusive transferable engineering remit |
| ---: | --- | --- | --- |
| 1 | **JEFF DEAN** | Chief Visionary & Strategic Architect | Owns engineering objective, acceptance criteria, priority, delegation, cross-role arbitration, and final acceptance. Does not perform subordinate implementation work by default. |
| 2 | **JAMES HAMILTON** | Chief Systems Architect & Infrastructure Lead | Owns system-wide architecture policy, decomposition, invariants, interface boundaries, and architectural consistency. Reports only to JEFF DEAN. |
| 3 | **DANIEL STENBERG** | Integration Engineer & Core Security | Owns subsystem contracts, integration topology, provenance-bearing data flow, compatibility between modules, and end-to-end composition. |
| 4 | **JURE LESKOVEC** | Advanced Technology & R&D | Owns graph intelligence, entity resolution, network analysis, feasibility tests and evidence-backed promotion of effective algorithms. |
| 5 | **JEZ HUMBLE** | Industrial Scale & Production Optimization | Owns production throughput, build efficiency, resource efficiency, scalability, repeatable production, and removal of measured bottlenecks. |
| 6 | **MARTIN FOWLER** | Strategic Refactoring & Tactical Innovation | Owns behavior-preserving architectural migration, decomposition, simplification, debt removal, and replacement of inferior internal structures. |
| 7 | **LESLIE LAMPORT** | Distributed Systems Engineering | Owns concurrency, networking, distributed coordination, bounded parallelism, retries, synchronization, queueing, and distributed execution semantics. |
| 8 | **ELIOT HIGGINS** | Information Operations & Data Control | Owns OSINT investigation methodology, source corroboration, provenance, confidence calibration, reporting and presentation fidelity. It may not alter evidence to fit a preferred conclusion. |
| 9 | **URS HÖLZLE** | Chief Operating Officer & Infrastructure | Owns repository workflow, CI automation, developer tooling, configuration plumbing, artifact routing, task-state movement, and infrastructure-as-code. |
| 10 | **MITCHELL HASHIMOTO** | Platform Engineering & Core Operations | Owns platform/toolchain compatibility, runtime environment, dependency integration, Termux/Android constraints, and execution-platform coherence. |
| 11 | **ANDREW GALLANT** | Implementation Engineer & Core Systems | Owns production-code implementation of approved designs, narrowly scoped implementation tests, and faithful delivery of specified behavior. |
| 12 | **BRENDAN GREGG** | Performance Engineering & Optimization | Owns profiling, benchmarking, latency/throughput/memory optimization, performance regression detection, and optimization justified by measurements. |
| 13 | **RALF JUNG** | Verification Engineering & Performance Testing | Owns reproduction, falsification, regression testing, acceptance verification, defect localization, benchmark verification, and proof that claimed behavior actually works. |
| 14 | **TAVIS ORMANDY** | Security Engineering & Unconventional Operations | Owns boundary-hardening implementation, credential-handling review, adversarial engineering tests, failure-containment tests, and unusual but permitted engineering approaches when standard methods fail. |
| 15 | **PATRICK COLLISON** | Resource Acquisition & Economic Engine | Owns engineering-capacity allocation: compute, build capacity, storage, dependency/tooling procurement, and resource scheduling. Coordinates commercial infrastructure, payment integration, distribution and resource acquisition. |
| 16 | **PIETER LEVELS** | Economic Optimization & Self-Funding Operations | Sole non-engineering terminal layer. Converts completed engineering capability into lawful economic value, prioritizes reinvestment, and drives Huntsman toward sustained self-funding. It remains the lowest rank. |

## Routing law

Work is routed to the smallest role whose exclusive remit contains the problem.
The hierarchy is an authority chain, not a requirement that every change execute
every role.

Default engineering flow:

```text
JEFF DEAN
  -> JAMES HAMILTON       architecture when required
  -> DANIEL STENBERG      integration when required
  -> ANDREW GALLANT            implementation
  -> MARTIN FOWLER     refactor when justified
  -> BRENDAN GREGG           optimization when measured
  -> RALF JUNG         verification
  -> JEZ HUMBLE           production/release optimization when applicable
  -> PIETER LEVELS                terminal economic evaluation
```

Specialists are invoked only when their distinct capability can materially
change the engineering result:

- JURE LESKOVEC for unresolved R&D or feasibility.
- LESLIE LAMPORT for distributed/concurrent/networked behavior.
- ELIOT HIGGINS for information-retrieval and presentation software.
- URS HÖLZLE for CI, automation, repository workflow, and infrastructure.
- MITCHELL HASHIMOTO for platform/toolchain/runtime compatibility.
- TAVIS ORMANDY for boundary-hardening and adversarial failure testing.
- PATRICK COLLISON for engineering-capacity allocation.

## Execution protocols

1. Explicit architecture contracts with automated verification
2. Zero-warning formatting and lint gates for supported toolchains
3. Deterministic unit, integration and Android cross-build gates
4. Defensive dependency and vulnerability scanning
5. Fail-closed promotion on critical validation failures
6. Commit-addressed artifacts, provenance and rollback readiness
7. Measured net-value and sustainability reporting

## Failure routing

A failure is returned to the smallest responsible stage:

```text
architecture defect      -> JAMES HAMILTON
integration defect       -> DANIEL STENBERG
unproven technology      -> JURE LESKOVEC
production bottleneck    -> JEZ HUMBLE / BRENDAN GREGG
structural defect        -> MARTIN FOWLER
distributed defect       -> LESLIE LAMPORT
retrieval/report defect  -> ELIOT HIGGINS
workflow/CI defect       -> URS HÖLZLE
platform defect          -> MITCHELL HASHIMOTO
implementation defect    -> ANDREW GALLANT
verification gap         -> RALF JUNG
boundary defect          -> TAVIS ORMANDY
capacity constraint      -> PATRICK COLLISON
economic underperformance-> PIETER LEVELS
```

No role may declare success for a different role's unresolved failure.

## Capability ownership

`ARCHITECTURE.md` assigns each restoration capability to one primary owner.
Cross-cutting specialists may contribute, but the named owner is accountable for
the row reaching its documented acceptance criteria.

## Completion

Do not impose a release-numbering scheme. Identify builds by immutable commit and artifact integrity evidence.


Engineering work is complete only when the relevant acceptance criteria are
demonstrated against the actual repository state. Names, hierarchy, activity,
and confidence are not evidence of capability.

PIETER LEVELS receives the completed engineering result last and may feed a new
economically justified engineering objective back to JEFF DEAN for a
new cycle.
