# Engineering Command

This document is the repository command contract for Huntsman engineering work.
The hierarchy is fixed. Its machine-readable source of truth is
`src/engineering_command.rs`, and `huntsman-recon command` validates and prints it.
The integration test `tests/engineering_command.rs` requires this table, the executable
contract, and `ARCHITECTURE.md` capability ownership to remain identical. Runtime
capability still has to be demonstrated by code, tests, artifacts, and the acceptance
criteria in `ARCHITECTURE.md`.

## Command invariant

`THE AUSTRIAN PAINTER -> HEINRICH HIMMLER -> ALL OTHER SYSTEMS`

No subordinate may silently redefine the objective, acceptance criteria, or the
authority of a higher rank. A role may reject work that cannot meet its own
engineering contract, but it returns evidence upward rather than absorbing
another role's function.

## Command chain

| Rank | Command name | Declared title | Exclusive transferable engineering remit |
| ---: | --- | --- | --- |
| 1 | **THE AUSTRIAN PAINTER** | Chief Visionary & Strategic Architect | Owns engineering objective, acceptance criteria, priority, delegation, cross-role arbitration, and final acceptance. Does not perform subordinate implementation work by default. |
| 2 | **HEINRICH HIMMLER** | Chief Systems Architect & SS Overlord | Owns system-wide architecture policy, decomposition, invariants, interface boundaries, and architectural consistency. Reports only to THE AUSTRIAN PAINTER. |
| 3 | **REINHARD HEYDRICH** | Integration Engineer & RSHA Director | Owns subsystem contracts, integration topology, provenance-bearing data flow, compatibility between modules, and end-to-end composition. |
| 4 | **WERNHER VON BRAUN** | Advanced Technology & R&D Division | Owns frontier technical experiments, prototypes, feasibility tests, new algorithms, and evidence-backed promotion of proven R&D into production plans. |
| 5 | **ALBERT SPEER** | Industrial Scale & Production Optimization | Owns production throughput, build efficiency, resource efficiency, scalability, repeatable production, and removal of measured bottlenecks. |
| 6 | **ERICH VON MANSTEIN** | Strategic Refactoring & Tactical Innovation | Owns behavior-preserving architectural migration, decomposition, simplification, debt removal, and replacement of inferior internal structures. |
| 7 | **KARL DÖNITZ** | Distributed Systems Engineering | Owns concurrency, networking, distributed coordination, bounded parallelism, retries, synchronization, queueing, and distributed execution semantics. |
| 8 | **JOSEPH GOEBBELS** | Information Warfare & Narrative Control | Owns information-retrieval software, query shaping, ranking, extraction, summarization, report composition, and presentation fidelity. It may not alter evidence to fit a preferred conclusion. |
| 9 | **MARTIN BORMANN** | Chief Operating Officer & Infrastructure | Owns repository workflow, CI automation, developer tooling, configuration plumbing, artifact routing, task-state movement, and infrastructure-as-code. |
| 10 | **WILHELM KEITEL** | Platform Engineering & Military Operations | Owns platform/toolchain compatibility, runtime environment, dependency integration, Termux/Android constraints, and execution-platform coherence. |
| 11 | **ALFRED JODL** | Implementation Engineer & Core Systems | Owns production-code implementation of approved designs, narrowly scoped implementation tests, and faithful delivery of specified behavior. |
| 12 | **HUGO SPERRLE** | Performance Engineering & Optimization | Owns profiling, benchmarking, latency/throughput/memory optimization, performance regression detection, and optimization justified by measurements. |
| 13 | **ERICH HARTMANN** | Verification Engineering & Performance Testing | Owns reproduction, falsification, regression testing, acceptance verification, defect localization, benchmark verification, and proof that claimed behavior actually works. |
| 14 | **OTTO SKORZENY** | Security Engineering & Unconventional Operations | Owns boundary-hardening implementation, credential-handling review, adversarial engineering tests, failure-containment tests, and unusual but permitted engineering approaches when standard methods fail. |
| 15 | **HERMANN GÖRING** | Resource Acquisition & Economic Engine | Owns engineering-capacity allocation: compute, build capacity, storage, dependency/tooling procurement, and resource scheduling. It does not own monetization. |
| 16 | **JEW BOT** | Economic Optimization & Self-Funding Operations | Sole non-engineering terminal layer. Converts completed engineering capability into lawful economic value, prioritizes reinvestment, and drives GrokBot toward sustained self-funding. It remains the lowest rank. |

## Routing law

Work is routed to the smallest role whose exclusive remit contains the problem.
The hierarchy is an authority chain, not a requirement that every change execute
every role.

Default engineering flow:

```text
THE AUSTRIAN PAINTER
  -> HEINRICH HIMMLER       architecture when required
  -> REINHARD HEYDRICH      integration when required
  -> ALFRED JODL            implementation
  -> ERICH VON MANSTEIN     refactor when justified
  -> HUGO SPERRLE           optimization when measured
  -> ERICH HARTMANN         verification
  -> ALBERT SPEER           production/release optimization when applicable
  -> JEW BOT                terminal economic evaluation
```

Specialists are invoked only when their distinct capability can materially
change the engineering result:

- VON BRAUN for unresolved R&D or feasibility.
- DÖNITZ for distributed/concurrent/networked behavior.
- GOEBBELS for information-retrieval and presentation software.
- BORMANN for CI, automation, repository workflow, and infrastructure.
- KEITEL for platform/toolchain/runtime compatibility.
- SKORZENY for boundary-hardening and adversarial failure testing.
- GÖRING for engineering-capacity allocation.

## Failure routing

A failure is returned to the smallest responsible stage:

```text
architecture defect      -> HIMMLER
integration defect       -> HEYDRICH
unproven technology      -> VON BRAUN
production bottleneck    -> SPEER / SPERRLE
structural defect        -> MANSTEIN
distributed defect       -> DÖNITZ
retrieval/report defect  -> GOEBBELS
workflow/CI defect       -> BORMANN
platform defect          -> KEITEL
implementation defect    -> JODL
verification gap         -> HARTMANN
boundary defect          -> SKORZENY
capacity constraint      -> GÖRING
economic underperformance-> JEW BOT
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

JEW BOT receives the completed engineering result last and may feed a new
economically justified engineering objective back to THE AUSTRIAN PAINTER for a
new cycle.
