# Engineering Command

This document is the repository command contract for Huntsman engineering work.
The hierarchy is fixed. Role names are conceptual designations for responsibilities, not claims of actual participation by named people. Tool and test outcomes must be evidenced. Its machine-readable source of truth is
`src/engineering_command.rs`; `huntsman-recon command` validates and prints the text view, while `huntsman-recon command --json` emits the same contract for automation.
The integration test `tests/engineering_command.rs` requires this table, the executable
contract, and `ARCHITECTURE.md` capability ownership to remain identical. Runtime
capability still has to be demonstrated by code, tests, artifacts, and the acceptance
criteria in `ARCHITECTURE.md`.

## Command invariant

`ELON MUSK -> JAMES HAMILTON -> ALL OTHER SYSTEMS`

No subordinate may silently redefine the objective, acceptance criteria, or the
authority of a higher rank. A role may reject work that cannot meet its own
engineering contract, but it returns evidence upward rather than absorbing
another role's function.

## Command chain

| Rank | Command name | Declared title | Exclusive transferable engineering remit |
| ---: | --- | --- | --- |
| 1 | **ELON MUSK** | Chief Visionary & Strategic Architect | Owns engineering objective, acceptance criteria, priority, delegation, cross-role arbitration, and final acceptance. Does not perform subordinate implementation work by default. |
| 2 | **JAMES HAMILTON** | Chief Systems Architect & Infrastructure Lead | Owns system-wide architecture policy, decomposition, invariants, interface boundaries, and architectural consistency. Reports only to ELON MUSK. |
| 3 | **BRUCE SCHNEIER** | Integration Engineer & Core Security | Owns subsystem contracts, integration topology, provenance-bearing data flow, compatibility between modules, and end-to-end composition. |
| 4 | **DEMIS HASSABIS** | Advanced Technology & R&D Division | Owns frontier technical experiments, prototypes, feasibility tests, new algorithms, and evidence-backed promotion of proven R&D into production plans. |
| 5 | **TIM COOK** | Industrial Scale & Production Optimization | Owns production throughput, build efficiency, resource efficiency, scalability, repeatable production, and removal of measured bottlenecks. |
| 6 | **ANDY GROVE** | Strategic Refactoring & Tactical Innovation | Owns behavior-preserving architectural migration, decomposition, simplification, debt removal, and replacement of inferior internal structures. |
| 7 | **LESLIE LAMPORT** | Distributed Systems Engineering | Owns concurrency, networking, distributed coordination, bounded parallelism, retries, synchronization, queueing, and distributed execution semantics. |
| 8 | **RENEE DIRESTA** | Information Operations & Data Control | Owns information-retrieval software, query shaping, ranking, extraction, summarization, report composition, and presentation fidelity. It may not alter evidence to fit a preferred conclusion. |
| 9 | **GWYNNE SHOTWELL** | Chief Operating Officer & Infrastructure | Owns repository workflow, CI automation, developer tooling, configuration plumbing, artifact routing, task-state movement, and infrastructure-as-code. |
| 10 | **KELSEY HIGHTOWER** | Platform Engineering & Core Operations | Owns platform/toolchain compatibility, runtime environment, dependency integration, Termux/Android constraints, and execution-platform coherence. |
| 11 | **LINUS TORVALDS** | Implementation Engineer & Core Systems | Owns production-code implementation of approved designs, narrowly scoped implementation tests, and faithful delivery of specified behavior. |
| 12 | **JOHN CARMACK** | Performance Engineering & Optimization | Owns profiling, benchmarking, latency/throughput/memory optimization, performance regression detection, and optimization justified by measurements. |
| 13 | **MARGARET HAMILTON** | Verification Engineering & Performance Testing | Owns reproduction, falsification, regression testing, acceptance verification, defect localization, benchmark verification, and proof that claimed behavior actually works. |
| 14 | **PEITER ZATKO (MUDGE)** | Security Engineering & Unconventional Operations | Owns boundary-hardening implementation, credential-handling review, adversarial engineering tests, failure-containment tests, and unusual but permitted engineering approaches when standard methods fail. |
| 15 | **WARREN BUFFETT** | Resource Acquisition & Economic Engine | Owns engineering-capacity allocation: compute, build capacity, storage, dependency/tooling procurement, and resource scheduling. It does not own monetization. |
| 16 | **JIM SIMONS** | Economic Optimization & Self-Funding Operations | Sole non-engineering terminal layer. Converts completed engineering capability into lawful economic value, prioritizes reinvestment, and drives Huntsman toward sustained self-funding. It remains the lowest rank. |

## Routing law

Work is routed to the smallest role whose exclusive remit contains the problem.
The hierarchy is an authority chain, not a requirement that every change execute
every role.

Default engineering flow:

```text
ELON MUSK
  -> JAMES HAMILTON       architecture when required
  -> BRUCE SCHNEIER      integration when required
  -> LINUS TORVALDS            implementation
  -> ANDY GROVE     refactor when justified
  -> JOHN CARMACK           optimization when measured
  -> MARGARET HAMILTON         verification
  -> TIM COOK           production/release optimization when applicable
  -> JIM SIMONS                terminal economic evaluation
```

Specialists are invoked only when their distinct capability can materially
change the engineering result:

- DEMIS HASSABIS for unresolved R&D or feasibility.
- LESLIE LAMPORT for distributed/concurrent/networked behavior.
- RENEE DIRESTA for information-retrieval and presentation software.
- GWYNNE SHOTWELL for CI, automation, repository workflow, and infrastructure.
- KELSEY HIGHTOWER for platform/toolchain/runtime compatibility.
- PEITER ZATKO (MUDGE) for boundary-hardening and adversarial failure testing.
- WARREN BUFFETT for engineering-capacity allocation.

## Execution protocols

1. Explicit architecture contracts with automated verification
2. Zero-warning formatting and lint gates for supported toolchains
3. Deterministic unit, integration and Android cross-build gates
4. Defensive dependency and vulnerability scanning
5. Fail-closed promotion on critical validation failures
6. Versioned artifacts, provenance and rollback readiness
7. Measured net-value and sustainability reporting

## Failure routing

A failure is returned to the smallest responsible stage:

```text
architecture defect      -> JAMES HAMILTON
integration defect       -> BRUCE SCHNEIER
unproven technology      -> DEMIS HASSABIS
production bottleneck    -> TIM COOK / JOHN CARMACK
structural defect        -> ANDY GROVE
distributed defect       -> LESLIE LAMPORT
retrieval/report defect  -> RENEE DIRESTA
workflow/CI defect       -> GWYNNE SHOTWELL
platform defect          -> KELSEY HIGHTOWER
implementation defect    -> LINUS TORVALDS
verification gap         -> MARGARET HAMILTON
boundary defect          -> PEITER ZATKO (MUDGE)
capacity constraint      -> WARREN BUFFETT
economic underperformance-> JIM SIMONS
```

No role may declare success for a different role's unresolved failure.

## Capability ownership

`ARCHITECTURE.md` assigns each restoration capability to one primary owner.
Cross-cutting specialists may contribute, but the named owner is accountable for
the row reaching its documented acceptance criteria.

## Completion

Engineering work is complete only when the relevant acceptance criteria are
demonstrated against the actual repository state. Names, hierarchy, activity,
and confidence are not evidence of capability.

JIM SIMONS receives the completed engineering result last and may feed a new
economically justified engineering objective back to ELON MUSK for a
new cycle.
