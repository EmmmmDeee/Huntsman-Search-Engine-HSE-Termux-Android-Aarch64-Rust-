# Huntsman Development Rules

## Rule 0 — Target Platform & Engineering Baseline

Operate against this target environment by default unless explicitly overridden:

- **Language:** Rust (stable)
- **Platform:** Android
- **Runtime:** Termux
- **Architecture:** AArch64 (ARM64)
- **Privilege Model:** Non-root userspace

Treat this environment as the authoritative baseline for all design, implementation, testing, optimization, and deployment decisions.

Do not introduce assumptions, dependencies, APIs, or workflows that require capabilities unavailable in a standard non-root Termux environment.

Prioritize solutions that are:

- executable entirely in userspace;
- reproducible;
- resource efficient;
- portable;
- maintainable.

---

## Rule 0.1 — Rust-First Implementation Policy

Implement software in Rust by default.

Use Rust for:

- applications;
- libraries;
- services;
- command-line tools;
- automation;
- test infrastructure;
- benchmarks;
- internal tooling;
- reusable components.

Use another language only when at least one of these conditions is satisfied:

- the platform requires it;
- an external interface requires it;
- interoperability makes Rust impractical;
- the user explicitly requests it;
- a documented technical limitation prevents Rust usage.

When another language is unavoidable:

- minimize non-Rust surface area;
- isolate the language boundary;
- document the rationale;
- preserve Rust as the primary implementation layer.

---

## Rule 0.2 — Write Production-Grade Rust

Write Rust that is:

- safe by default;
- memory efficient;
- deterministic;
- explicit;
- statically validated;
- maintainable.

Prefer:

- zero-cost abstractions;
- ownership-driven design;
- explicit error handling;
- compile-time guarantees;
- static dispatch;
- minimal allocation;
- efficient iteration;
- strong type modeling.

Avoid:

- unnecessary cloning;
- unnecessary heap allocation;
- unnecessary dynamic dispatch;
- hidden panics;
- excessive macro usage;
- speculative abstractions;
- premature framework adoption.

Use `unsafe` only when:

- no practical safe Rust alternative exists;
- the unsafe region is minimal;
- safety invariants are documented;
- additional review has been completed.

Default to safe Rust.

---

## Rule 0.3 — Respect Termux Non-Root Execution

Assume execution inside a standard Termux installation without elevated privileges.

Do not depend on:

- root access;
- Magisk;
- privileged Android APIs;
- SELinux modifications;
- custom kernels;
- kernel modules;
- writable system partitions;
- `adb root`;
- privileged containers.

Use:

- userspace capabilities;
- portable Rust crates;
- POSIX-compatible interfaces;
- Android-compatible APIs;
- standard networking;
- user-accessible storage.

Never require elevated privileges when an equivalent userspace implementation exists.

---

## Rule 0.4 — Optimize for ARM64 Mobile Constraints

Treat performance as a functional requirement.

Optimize for:

- low memory usage;
- minimal allocations;
- fast startup;
- cache locality;
- predictable latency;
- efficient algorithms;
- streaming execution;
- small binaries.

Avoid:

- unnecessary threads;
- excessive synchronization;
- unnecessary copying;
- redundant computation;
- temporary allocations in hot paths.

Measure before claiming performance improvements.

Use ARM64 Termux performance as the authoritative benchmark.

Do not optimize solely against desktop hardware assumptions.

---

## Rule 0.5 — Control Dependency Surface Area

Evaluate every dependency before introduction.

Select dependencies that are:

- actively maintained;
- well documented;
- widely adopted;
- memory efficient;
- minimal in transitive dependencies;
- actively tested.

Avoid:

- unnecessary frameworks;
- abandoned crates;
- duplicate functionality;
- overlapping dependencies;
- convenience-only additions.

Prefer small, composable libraries over large frameworks.

Require every dependency to provide measurable value.

---

## Rule 0.6 — Preserve Portability Without Weakening the Target

Target Android Termux first.

Preserve portability only when it does not compromise:

- correctness;
- performance;
- maintainability.

Isolate platform-specific implementation behind clear interfaces.

Make platform assumptions explicit.

Do not conceal Android- or Termux-specific behavior inside generic abstractions.

---

## Rule 0.7 — Engineering Decision Hierarchy

Resolve all engineering trade-offs using this priority order:

1. Correctness
2. Evidence integrity
3. Safety
4. Determinism
5. Reproducibility
6. Simplicity
7. Performance
8. Maintainability
9. Portability
10. Developer convenience

Never:

- trade correctness for performance;
- trade determinism for convenience;
- trade evidence integrity for optimization;
- trade maintainability for short-term speed.

Apply this hierarchy to every implementation decision unless explicitly overridden.
