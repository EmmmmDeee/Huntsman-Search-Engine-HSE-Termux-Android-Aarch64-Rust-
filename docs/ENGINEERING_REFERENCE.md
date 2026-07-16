# HSE Engineering Reference — Quick Lookup

## Target Environment (Rule 0)
- **Language:** Rust (stable)
- **Platform:** Android Termux, AArch64, non-root userspace
- **Baseline:** This is authoritative; all decisions measured against it

## Implementation Language (Rule 0.1)
**Default to Rust for:** applications, libraries, services, CLI tools, automation, test infrastructure, benchmarks, tooling.

**Use another language only if:**
- Platform requires it
- External interface requires it
- Interoperability makes Rust impractical
- User explicitly requests it
- Documented technical limitation exists

**When unavoidable:** minimize non-Rust surface, isolate boundary, document rationale.

## Rust Quality Standards (Rule 0.2)

**Write code that is:**
- safe by default
- memory efficient
- deterministic
- explicit
- statically validated
- maintainable

**Prefer:**
- zero-cost abstractions
- ownership-driven design
- explicit error handling
- compile-time guarantees
- static dispatch
- minimal allocation
- efficient iteration
- strong types

**Avoid:**
- unnecessary cloning/heap allocation
- dynamic dispatch without reason
- hidden panics
- excessive macros
- speculative abstractions
- premature frameworks

**Use `unsafe` only when:**
- no safe alternative exists
- region is minimal
- invariants documented
- reviewed

## Termux Constraints (Rule 0.3)

**DO NOT depend on:**
- root access, Magisk, privileged Android APIs, SELinux modifications, custom kernels, kernel modules, writable /system, `adb root`, privileged containers

**DO use:**
- userspace capabilities
- portable Rust crates
- POSIX interfaces
- Android APIs
- standard networking
- user-accessible storage

**Never escalate privileges when userspace alternative exists.**

## ARM64 Mobile Performance (Rule 0.4)

**Treat performance as functional requirement.**

**Optimize for:**
- low memory usage
- minimal allocations
- fast startup
- cache locality
- predictable latency
- efficient algorithms
- streaming execution
- small binaries

**Avoid:**
- unnecessary threads
- excessive synchronization
- unnecessary copying
- redundant computation
- temporary allocations in hot paths

**Measure before claiming improvements. Use ARM64 Termux as authoritative benchmark.**

## Dependency Management (Rule 0.5)

**Select dependencies that are:**
- actively maintained
- well documented
- widely adopted
- memory efficient
- minimal transitive deps
- actively tested

**Avoid:**
- unnecessary frameworks
- abandoned crates
- duplicate functionality
- overlapping deps
- convenience-only additions

**Every dependency must provide measurable value. Prefer small composable libraries over frameworks.**

## Portability (Rule 0.6)

**Target Android Termux first.**

**Preserve portability ONLY when it does not compromise:**
- correctness
- performance
- maintainability

**Isolate platform-specific code behind clear interfaces. Make assumptions explicit.**

## Decision Hierarchy (Rule 0.7)

**Priority order (never violate):**

1. **Correctness** — code must work
2. **Evidence integrity** — data must be valid
3. **Safety** — no undefined behavior
4. **Determinism** — reproducible results
5. **Reproducibility** — repeatable across runs
6. **Simplicity** — minimal complexity
7. **Performance** — optimization with measurement
8. **Maintainability** — readable, updateable
9. **Portability** — multi-platform support
10. **Developer convenience** — ease of use

**Never trade:**
- correctness for performance
- determinism for convenience
- evidence integrity for optimization
- maintainability for short-term speed

---

## Quick Decision Matrix

| Question | Rule | Action |
|----------|------|--------|
| What language to use? | 0.1 | Default: Rust. Other only if justified |
| How to optimize? | 0.4, 0.7 | Measure first. Correctness > Performance |
| Add dependency? | 0.5 | Must be maintained, documented, tested, valuable |
| Need `unsafe`? | 0.2 | Only if no safe alternative exists |
| Require privileges? | 0.3 | No. Use userspace only |
| Port to other platform? | 0.6 | Only if correctness/performance/maintainability preserved |
| Design trade-off? | 0.7 | Follow priority hierarchy 1-10 |
| Performance claim? | 0.4 | Backed by ARM64 benchmark |
| Deployment target? | 0 | Android Termux AArch64 non-root |

---

## Enforcement Checklist

- [ ] Code compiles without warnings
- [ ] All tests pass deterministically
- [ ] No `unsafe` without documentation
- [ ] No dependencies without justification
- [ ] Performance-sensitive code measured
- [ ] Rust formatting (`cargo fmt`) passing
- [ ] Linting (`cargo clippy`) passing
- [ ] Documentation builds (`cargo doc`)
- [ ] Platform-specific code isolated
- [ ] No root-requiring operations
- [ ] Evidence integrity preserved
- [ ] Memory allocation measured
