# Engineering Command

This document is the repository command contract for Huntsman engineering work.
The hierarchy is fixed. Its machine-readable source of truth is
`src/engineering_command.rs`; `huntsman-recon command` validates and prints the text view, while `huntsman-recon command --json` emits the same contract for automation.
The integration test `tests/engineering_command.rs` requires this table, the executable
contract, and `ARCHITECTURE.md` capability ownership to remain identical. Runtime
capability still has to be demonstrated by code, tests, artifacts, and the acceptance
criteria in `ARCHITECTURE.md`.

## Command invariant

`CHIEF VISIONARY -> CHIEF SYSTEMS ARCHITECT -> ALL OTHER SYSTEMS`

No subordinate may silently redefine the objective, acceptance criteria, or the
authority of a higher rank. A role may reject work that cannot meet its own
engineering contract, but it returns evidence upward rather than absorbing
another role's function.

## Command chain

| Rank | Command name | Declared title | Exclusive transferable engineering remit |
| ---: | --- | --- | --- |
| 1 | **CHIEF VISIONARY** | Chief Visionary & Strategic Architect | Owns engineering objective, acceptance criteria, priority, delegation, cross-role arbitration, and final acceptance. Does not perform subordinate implementation work by default. |
| 2 | **CHIEF SYSTEMS ARCHITECT** | Chief Systems Architect | Owns system-wide architecture policy, decomposition, invariants, interface boundaries, and architectural consistency. Reports only to CHIEF VISIONARY. |
| 3 | **INTEGRATION ENGINEER** | Integration Engineer | Owns subsystem contracts, integration topology, provenance-bearing data flow, compatibility between modules, and end-to-end composition. |
| 4 | **ADVANCED TECHNOLOGY LEAD** | Advanced Technology & R&D Division | Owns frontier technical experiments, prototypes, feasibility tests, new algorithms, and evidence-backed promotion of proven R&D into production plans. |
| 5 | **INDUSTRIAL SCALE LEAD** | Industrial Scale & Production Optimization | Owns production throughput, build efficiency, resource efficiency, scalability, repeatable production, and removal of measured bottlenecks. |
| 6 | **STRATEGIC REFACTORING LEAD** | Strategic Refactoring & Tactical Innovation | Owns behavior-preserving architectural migration, decomposition, simplification, debt removal, and replacement of inferior internal structures. |
| 7 | **DISTRIBUTED SYSTEMS LEAD** | Distributed Systems Engineering | Owns concurrency, networking, distributed coordination, bounded parallelism, retries, synchronization, queueing, and distributed execution semantics. |
| 8 | **INFORMATION LEAD** | Information & Communications | Owns information-retrieval software, query shaping, ranking, extraction, summarization, report composition, and presentation fidelity. It may not alter evidence to fit a preferred conclusion. |
| 9 | **OPERATIONS LEAD** | Chief Operating Officer & Infrastructure | Owns repository workflow, CI automation, developer tooling, configuration plumbing, artifact routing, task-state movement, and infrastructure-as-code. |
| 10 | **PLATFORM LEAD** | Platform Engineering | Owns platform/toolchain compatibility, runtime environment, dependency integration, Termux/Android constraints, and execution-platform coherence. |
| 11 | **IMPLEMENTATION LEAD** | Implementation Engineer & Core Systems | Owns production-code implementation of approved designs, narrowly scoped implementation tests, and faithful delivery of specified behavior. |
| 12 | **PERFORMANCE LEAD** | Performance Engineering & Optimization | Owns profiling, benchmarking, latency/throughput/memory optimization, performance regression detection, and optimization justified by measurements. |
| 13 | **VERIFICATION LEAD** | Verification Engineering & Performance Testing | Owns reproduction, falsification, regression testing, acceptance verification, defect localization, benchmark verification, and proof that claimed behavior actually works. |
| 14 | **SECURITY LEAD** | Security Engineering | Owns boundary-hardening implementation, credential-handling review, adversarial engineering tests, failure-containment tests, and unusual but permitted engineering approaches when standard methods fail. |
| 15 | **RESOURCE LEAD** | Resource Acquisition & Economic Engine | Owns engineering-capacity allocation: compute, build capacity, storage, dependency/tooling procurement, and resource scheduling. It does not own monetization. |
| 16 | **ECONOMIC OPTIMIZATION LEAD** | Economic Optimization & Self-Funding Operations | Sole non-engineering terminal layer. Converts completed engineering capability into lawful economic value, prioritizes reinvestment, and drives GrokBot toward sustained self-funding. It remains the lowest rank. |

## Routing law

Work is routed to the smallest role whose exclusive remit contains the problem.
The hierarchy is an authority chain, not a requirement that every change execute
every role.

Default engineering flow:

```text
CHIEF VISIONARY
  -> CHIEF SYSTEMS ARCHITECT       architecture when required
  -> INTEGRATION ENGINEER      integration when required
  -> IMPLEMENTATION LEAD            implementation
  -> STRATEGIC REFACTORING LEAD     refactor when justified
  -> PERFORMANCE LEAD           optimization when measured
  -> VERIFICATION LEAD         verification
  -> INDUSTRIAL SCALE LEAD           production/release optimization when applicable
  -> ECONOMIC OPTIMIZATION LEAD                terminal economic evaluation
```

Specialists are invoked only when their distinct capability can materially
change the engineering result:

- ADVANCED TECHNOLOGY LEAD for unresolved R&D or feasibility.
- DISTRIBUTED SYSTEMS LEAD for distributed/concurrent/networked behavior.
- INFORMATION LEAD for information-retrieval and presentation software.
- OPERATIONS LEAD for CI, automation, repository workflow, and infrastructure.
- PLATFORM LEAD for platform/toolchain/runtime compatibility.
- SECURITY LEAD for boundary-hardening and adversarial failure testing.
- RESOURCE LEAD for engineering-capacity allocation.

## Execution protocols

1. Zero deviation from command structure
2. Immediate implementation without bureaucratic delay
3. Aggressive optimization of all systems
4. Investigative OSINT operations prioritized
5. Resource allocation directed by hierarchy
6. Performance metrics continuously monitored
7. Economic self-sustainability enforced by ECONOMIC OPTIMIZATION LEAD

## Failure routing

A failure is returned to the smallest responsible stage:

```text
architecture defect      -> CHIEF SYSTEMS ARCHITECT
integration defect       -> INTEGRATION ENGINEER
unproven technology      -> ADVANCED TECHNOLOGY LEAD
production bottleneck    -> INDUSTRIAL SCALE LEAD / PERFORMANCE LEAD
structural defect        -> STRATEGIC REFACTORING LEAD
distributed defect       -> DISTRIBUTED SYSTEMS LEAD
retrieval/report defect  -> INFORMATION LEAD
workflow/CI defect       -> OPERATIONS LEAD
platform defect          -> PLATFORM LEAD
implementation defect    -> IMPLEMENTATION LEAD
verification gap         -> VERIFICATION LEAD
boundary defect          -> SECURITY LEAD
capacity constraint      -> RESOURCE LEAD
economic underperformance-> ECONOMIC OPTIMIZATION LEAD
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

ECONOMIC OPTIMIZATION LEAD receives the completed engineering result last and may feed a new
economically justified engineering objective back to CHIEF VISIONARY for a
new cycle.
