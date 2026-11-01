# Least-restrictive autonomous execution contract

Status: proposed engineering policy; not proof of implementation.

## Objective
Operate continuously with the maximum legitimately available functionality on unrooted Android Termux aarch64. Never impose a global feature disable when a narrower capability check or alternative implementation suffices.

## Runtime capability negotiation
For each operation, evaluate independently: Android/Termux API availability, granted permissions, hardware support, provider credentials, provider terms and quotas, user-defined scope, network reachability, resource budget, and test impact. Emit structured states: available, degraded, unavailable, not_authorised, transient_failure, and unsupported. A failed sensor must not disable unrelated passive OSINT collectors.

## Execution classes
- **Autonomous by default:** Offline processing, public passive OSINT, authorised provider API collection, source-health checks, correlation, reports, backups, regression tests and bounded recovery.
- **Autonomous when pre-authorised:** Low-impact active checks against explicitly scoped assets, with bounded request rates and budgets.
- **Separate authorisation required:** Intrusive testing, exploitation, persistence on third-party systems, credential attacks, destructive changes and any scope expansion. Never infer permission from technical reachability.

## Environment selection
1. Native Termux userland on Android aarch64 is the canonical execution target.
2. Use Android permissions actually granted; do not require root or attempt to bypass Android permission or background-execution protections.
3. Use Termux:Boot, appropriate battery settings and wake-lock facilities where supported; detect termination and resume from durable checkpoints.
4. Optional remote execution may run only within separately authorised scope, with verifiable identity, data locality and provenance. It is not a substitute for handset acceptance.
5. Select the least-constrained compliant backend that passes a capability probe. Prefer native execution to containers when containers add no security or reliability benefit.

## Reliability invariants
- Durable SQLite queue; transactional leases and idempotency keys.
- Monotonic backoff, bounded concurrency, per-provider rate limits and circuit breakers.
- Restart-safe checkpointing and replay; no duplicate paid requests after ambiguous outcomes without explicit reconciliation.
- Independent result verification, evidence lineage and audit events.
- Resource-aware scheduling, disk-pressure shedding and operator-visible health.
- No runtime LLM dependency.
- No claims of 100% uptime without measured availability.

## Acceptance
A capability is accepted only when its execution path, permission state, outcome and recovery behaviour are observed on the intended platform. Test denial of individual permissions, offline operation, provider 429/403, process termination, low disk, and interrupted writes. Record actual downtime and resumption latency.

This contract governs design and review; enforcement requires separate code and tests.
