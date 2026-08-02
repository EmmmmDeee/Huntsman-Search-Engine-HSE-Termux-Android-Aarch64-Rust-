# See-Know Gap Analysis Implementation Blueprint
**Date:** July 22, 2026  
**Branch:** `claude/see-know-gap-analysis-3yydci`  
**Scope:** Complete file structure and architecture for all 4 phases

---

## Part 1: Current File Structure (As-Is)

```
src/
├── modules/
│   └── see_know/
│       ├── mod.rs (790 lines) — Main orchestration
│       ├── endpoints.rs — Endpoint routing
│       ├── extract.rs — Entity extraction
│       ├── pivots.rs — Identity cascade resolution
│       ├── tests.rs (1,300+ lines) — Module tests
│       └── tests/ — Test support files
│
├── util/
│   └── see_know/
│       ├── mod.rs (65 lines) — Public API
│       ├── client.rs — HTTP client wrapper
│       ├── endpoints.rs — Endpoint type definitions
│       ├── budget.rs — Credit budget management
│       ├── tests.rs — Utility tests
│       └── integration_tests.rs (382 lines) — Endpoint ledger
│
└── (other modules...)

docs/
├── SEEKNOW_SETUP.md (596 lines) — Setup guide
├── OSINT_API_REFERENCE.md — API reference
├── SEEKNOW_GAP_ANALYSIS.md (873 lines) — Gap analysis report
└── README.md — Project overview
```

---

## Part 2: Target File Structure (To-Be)

After implementing all 4 phases, the structure will be:

```
src/
├── modules/
│   └── see_know/
│       ├── mod.rs (900+ lines) — EXPANDED: Added /status support
│       ├── endpoints/
│       │   ├── mod.rs — NEW: Endpoint dispatch
│       │   ├── search.rs — REFACTORED: /search & /search/deep
│       │   ├── username.rs — REFACTORED: All username endpoints
│       │   ├── discord.rs — EXPANDED: Basic + enterprise endpoints
│       │   ├── network.rs — REFACTORED: IP/email/phone
│       │   ├── domain.rs — REFACTORED: Domain intel/whois
│       │   ├── gaming.rs — REFACTORED: All gaming platforms
│       │   ├── utility.rs — NEW: /status & /credits
│       │   └── tests.rs — NEW: Per-endpoint tests
│       ├── extract.rs — UNCHANGED: Entity extraction
│       ├── pivots.rs — UNCHANGED: Identity cascades
│       ├── metrics.rs — NEW: Latency/cache tracking (Phase 3)
│       ├── cache.rs — NEW: Cache management with hit tracking (Phase 3)
│       ├── tests.rs — EXPANDED: Load testing (Phase 1.4)
│       └── tests/
│           ├── load_tests.rs — NEW: Concurrent scan tests
│           ├── rate_limit_sim.rs — NEW: 429 backoff tests
│           └── cascade_optimization_tests.rs — NEW: Cascade profiling
│
├── util/
│   └── see_know/
│       ├── mod.rs — EXPANDED: Trait-based client interface
│       ├── client/
│       │   ├── mod.rs — NEW: Client trait definition
│       │   ├── real.rs — NEW: Real HTTP implementation
│       │   ├── mock.rs — NEW: Mock implementation (testing)
│       │   └── error.rs — NEW: Error handling
│       ├── tier.rs — NEW: Plan tier detection & caching (Phase 1.3)
│       ├── endpoints.rs — UNCHANGED: Type definitions
│       ├── budget.rs — EXPANDED: Tier-aware budget scaling
│       ├── metrics.rs — NEW: Instrumentation (Phase 3)
│       ├── tests.rs — EXPANDED: Tier auto-detection tests
│       └── integration_tests.rs — EXPANDED: Live HTTP seam tests
│
└── (other modules...)

docs/
├── SEEKNOW_SETUP.md — UPDATED: Phase 1-4 integration
├── SEEKNOW_GAP_ANALYSIS.md — UNCHANGED: Reference document
├── IMPLEMENTATION_BLUEPRINT.md — NEW: This file
├── OSINT_API_REFERENCE.md — UPDATED: All 24 endpoints
├── ENTERPRISE_GUIDE.md — NEW: Enterprise feature walkthrough (Phase 2.4)
├── OPENAPI_SCHEMA.yaml — NEW: Full OpenAPI 3.1 spec (Phase 4.1)
├── TROUBLESHOOTING.md — NEW: Expanded guide (Phase 4.2)
└── SECURITY_AUDIT.md — NEW: Security review findings (Phase 4.3)

tests/
├── integration/
│   └── see_know_e2e.rs — NEW: End-to-end tests (Phase 1-2)
│
└── load/
    ├── concurrent_scans.rs — NEW: 10+ concurrent tests (Phase 1.4)
    ├── rate_limiting.rs — NEW: 429 handling tests (Phase 3.3)
    └── cascade_profiling.rs — NEW: Cascade efficiency (Phase 3.4)

.github/
├── workflows/
│   └── see-know-ci.yml — NEW: See-Know specific CI (Phase 1.2)

config/
└── openapi/
    └── see_know_schema.yml — NEW: OpenAPI definition (Phase 4.1)
```

---

## Part 3: Phase-by-Phase File Changes

### Phase 1: Foundation (Weeks 1–2)

#### Task 1.1: Implement `/status` endpoint

**Files Modified:**
1. `src/modules/see_know/endpoints/utility.rs` — **NEW**
   - `EndpointCall::Status` variant
   - Status response parsing
   - Service health extraction

2. `src/util/see_know/endpoints.rs`
   - Add `Status` to `EndpointCall` enum
   - Add status request/response types

3. `src/modules/see_know/mod.rs`
   - Wire `/status` into endpoint dispatch
   - Add status query handler

4. `src/modules/see_know/tests.rs`
   - Test `/status` parsing
   - Test upstream service list extraction

**Lines of Code:** +150–200

---

#### Task 1.2: Create live HTTP client seam

**Files Created:**
1. `src/util/see_know/client/mod.rs` — **NEW**
   - `HttpClient` trait definition
   - Async request/response methods
   - Error types

2. `src/util/see_know/client/real.rs` — **NEW**
   - Real HTTP implementation (current logic extracted)
   - Uses reqwest/curl
   - Timeout management

3. `src/util/see_know/client/mock.rs` — **NEW**
   - Mock implementation for testing
   - Configurable response fixtures
   - Failure injection

4. `src/util/see_know/client/error.rs` — **NEW**
   - Error enum for HTTP operations
   - Retry logic
   - Status code mapping

**Files Modified:**
1. `src/util/see_know/mod.rs`
   - Update public API to use trait
   - Export client types

2. `src/util/see_know/client.rs` — **REFACTORED**
   - Extract to use `HttpClient` trait
   - Remove hardcoded reqwest calls

3. `src/modules/see_know/mod.rs`
   - Inject client via context
   - Support mock in tests

4. `.github/workflows/see-know-ci.yml` — **NEW**
   - CI toggle for live integration tests
   - `SEEKNOW_INTEGRATION_TEST` env var

**Lines of Code:** +800–1000

---

#### Task 1.3: Implement plan tier auto-detection

**Files Created:**
1. `src/util/see_know/tier.rs` — **NEW**
   - `PlanTier` enum (Free, Pro, Enterprise)
   - Tier detection from response headers
   - Tier caching (session lifetime)
   - Endpoint availability matrix per tier

2. `src/modules/see_know/tier_dispatch.rs` — **NEW**
   - Conditional endpoint dispatch based on tier
   - Runtime capability checks
   - Tier upgrade prompts

**Files Modified:**
1. `src/util/see_know/mod.rs`
   - Expose tier detection API
   - Cache tier in session context

2. `src/util/see_know/budget.rs`
   - Tier-aware budget scaling
   - Enterprise credit limits

3. `src/modules/see_know/mod.rs`
   - Call tier detection on first request
   - Pass tier to endpoint dispatch

4. `src/util/see_know/tests.rs`
   - Test tier detection from headers
   - Test endpoint availability per tier
   - Test tier caching

**Lines of Code:** +400–500

---

#### Task 1.4: Implement concurrent load testing

**Files Created:**
1. `src/modules/see_know/tests/load_tests.rs` — **NEW**
   - `#[tokio::test]` for concurrent scans
   - 10+ concurrent scan spawning
   - Budget atomicity verification
   - Latency collection (p50/p95/p99)
   - Deadlock detection

2. `tests/integration/see_know_e2e.rs` — **NEW**
   - End-to-end concurrent scan tests
   - Real API integration (with mock fallback)
   - Performance assertions
   - Budget exhaustion scenarios

**Files Modified:**
1. `src/util/see_know/tests.rs`
   - Add concurrent budget tests
   - Add cache contention tests

2. `Cargo.toml`
   - Add `tokio::test` if not present
   - Add `criterion` for benchmarking (optional)

**Lines of Code:** +600–800

**Total Phase 1:** ~2000–2500 lines

---

### Phase 2: Enterprise Support (Weeks 3–4)

#### Task 2.1: Implement `/enterprise/discord/history`

**Files Created/Modified:**
1. `src/modules/see_know/endpoints/discord.rs` — **EXPANDED**
   - `EndpointCall::DiscordHistory` variant
   - History request builder (Discord ID, date range, limit)
   - Response parsing (conversation list, metadata)
   - Entity extraction (participants, mentions, URLs)
   - Pagination handler

2. `src/util/see_know/endpoints.rs`
   - Add `DiscordHistory` request/response types
   - Schema for history records

3. `src/modules/see_know/tests.rs`
   - Test history endpoint with mock responses
   - Test pagination logic
   - Test entity extraction from messages

**Lines of Code:** +400–500

---

#### Task 2.2: Implement `/enterprise/discord/messages`

**Files Created/Modified:**
1. `src/modules/see_know/endpoints/discord.rs` — **EXPANDED**
   - `EndpointCall::DiscordMessages` variant
   - Message request builder (Discord ID, filters)
   - Response parsing (raw message payloads)
   - Entity extraction (emails, URLs, API keys in content)
   - Large result set handling

2. `src/util/see_know/endpoints.rs`
   - Add `DiscordMessages` types
   - Message content schema

3. `src/modules/see_know/tests.rs`
   - Test message parsing
   - Test API key extraction from message content
   - Test large result batching

**Lines of Code:** +400–500

---

#### Task 2.3: Implement `/enterprise/discord/export`

**Files Created/Modified:**
1. `src/modules/see_know/endpoints/discord.rs` — **EXPANDED**
   - `EndpointCall::DiscordExport` variant
   - Export request builder (Discord ID)
   - ZIP URL handling (streaming download)
   - Metadata extraction (file count, size, date range)
   - Temporary file management

2. `src/util/see_know/client/mod.rs`
   - Add streaming download capability
   - Add `Range` header support for large files

3. `src/modules/see_know/tests.rs`
   - Test export workflow
   - Test ZIP extraction and validation
   - Test temp file cleanup

**Lines of Code:** +300–400

---

#### Task 2.4: Document enterprise features

**Files Created:**
1. `docs/ENTERPRISE_GUIDE.md` — **NEW**
   - Enterprise upgrade flow
   - Discord history/messages/export examples
   - Budget allocation for enterprise
   - SLA and response times
   - Billing integration guide
   - FAQ for enterprise users

2. `docs/SEEKNOW_SETUP.md` — **UPDATED**
   - Add enterprise section
   - Update budget calculator examples
   - Add tier-specific recommendations

**Lines of Code:** +300–400 (docs)

**Total Phase 2:** ~2000–2300 lines

---

### Phase 3: Performance & Observability (Weeks 5–6)

#### Task 3.1: Add latency SLA monitoring

**Files Created:**
1. `src/modules/see_know/metrics.rs` — **NEW**
   - `LatencyMetrics` struct
   - Histogram collection (p50/p95/p99)
   - Per-endpoint tracking
   - Export to Prometheus format
   - SLA violation logging

2. `src/modules/see_know/tests/load_tests.rs` — **EXPANDED**
   - SLA assertion tests
   - Latency percentile validation

**Files Modified:**
1. `src/modules/see_know/mod.rs`
   - Wire metrics collection into endpoint calls
   - Add timing instrumentation

2. `src/util/see_know/mod.rs`
   - Expose metrics API
   - Add metrics reset/export methods

**Lines of Code:** +500–700

---

#### Task 3.2: Add cache hit ratio tracking

**Files Created:**
1. `src/modules/see_know/cache.rs` — **NEW**
   - `CacheMetrics` struct (hits/misses/rate)
   - Per-endpoint hit tracking
   - Time-of-day analysis
   - Query pattern correlation
   - TTL optimization suggestions

**Files Modified:**
1. `src/util/see_know/mod.rs` (cache logic)
   - Add hit/miss counters
   - Calculate hit ratio
   - Track query patterns

2. `src/modules/see_know/tests.rs`
   - Test cache hit measurement
   - Test pattern analysis

**Lines of Code:** +300–400

---

#### Task 3.3: Implement rate limit backoff simulation

**Files Created:**
1. `src/modules/see_know/tests/rate_limit_sim.rs` — **NEW**
   - Mock 429 response injection
   - Backoff verification (2s → 4s → 8s)
   - Jitter validation
   - Recovery time measurement
   - Max retry exhaustion testing

**Files Modified:**
1. `src/util/see_know/client/mock.rs`
   - Add 429 injection capability
   - Configurable rate limit scenarios

2. `src/modules/see_know/tests.rs`
   - Add rate limit test suite

**Lines of Code:** +400–500

---

#### Task 3.4: Optimize cascade queries

**Files Created:**
1. `src/modules/see_know/tests/cascade_optimization_tests.rs` — **NEW**
   - Profile cascade query paths
   - Identify over-queried targets
   - Measure API call reduction
   - Efficiency comparison (before/after)

2. `src/modules/see_know/cascade_optimizer.rs` — **NEW**
   - Cascade depth/width tuning per target type
   - Deduplication logic
   - Budget-aware path selection

**Files Modified:**
1. `src/modules/see_know/pivots.rs`
   - Integrate optimizer
   - Add dedup on email cascades
   - Tune depth per query pattern

2. `src/modules/see_know/tests.rs`
   - Add cascade efficiency tests

**Lines of Code:** +500–700

**Total Phase 3:** ~2000–2300 lines

---

### Phase 4: Polish & Hardening (Week 7+, Optional)

#### Task 4.1: Create OpenAPI schema documentation

**Files Created:**
1. `config/openapi/see_know_schema.yaml` — **NEW**
   - OpenAPI 3.1 specification
   - All 24 endpoints documented
   - Request/response schemas
   - Error codes
   - Examples

2. `docs/OPENAPI_SCHEMA.md` — **NEW**
   - OpenAPI usage guide
   - Schema validation
   - Client generation

**Lines of Code:** +500–700 (YAML)

---

#### Task 4.2: Expand troubleshooting guide

**Files Created:**
1. `docs/TROUBLESHOOTING.md` — **NEW**
   - 15+ troubleshooting scenarios
   - Common error codes + fixes
   - Timeout debugging
   - Budget exhaustion recovery
   - Cascade query debugging
   - Rate limit escalation

**Lines of Code:** +400–500 (docs)

---

#### Task 4.3: Security audit

**Files Created:**
1. `docs/SECURITY_AUDIT.md` — **NEW**
   - Key storage audit results
   - Cache isolation verification
   - Rate limit bypass prevention
   - Response sanitization checks
   - Cascade query security tests
   - Findings and remediations

**Lines of Code:** +300–400 (docs)

**Total Phase 4:** ~1200–1600 lines

---

## Part 4: File Modification Summary

### Summary Table

| File | Phase | Status | LOC Change | Impact |
|------|-------|--------|-----------|--------|
| `src/modules/see_know/mod.rs` | 1-3 | Modified | +200 | Core dispatch |
| `src/modules/see_know/endpoints/*.rs` | 1-2 | New/Expanded | +2500 | All endpoints |
| `src/modules/see_know/metrics.rs` | 3 | New | +500 | Observability |
| `src/modules/see_know/cache.rs` | 3 | New | +400 | Efficiency tracking |
| `src/modules/see_know/tests/*.rs` | 1-3 | Expanded | +2000 | Testing |
| `src/util/see_know/client/*.rs` | 1 | New | +1000 | HTTP abstraction |
| `src/util/see_know/tier.rs` | 1 | New | +500 | Plan tier support |
| `src/util/see_know/mod.rs` | 1-3 | Modified | +300 | API updates |
| `docs/*.md` | 1-4 | New/Updated | +2000 | Documentation |
| `.github/workflows/*.yml` | 1 | New | +100 | CI/CD |
| **Total** | **1-4** | — | **~10,000** | Complete implementation |

---

## Part 5: Dependency Graph

```
Phase 1 (Foundation)
├── 1.1: /status endpoint (independent)
├── 1.2: Live HTTP seam (independent)
├── 1.3: Plan tier auto-detect (independent)
└── 1.4: Concurrent load testing (independent)

Phase 2 (Enterprise) — Depends on Phase 1.3
├── 2.1: Discord history (→ 1.3)
├── 2.2: Discord messages (→ 1.3)
├── 2.3: Discord export (→ 1.3)
└── 2.4: Enterprise docs (→ 2.1, 2.2, 2.3)

Phase 3 (Performance) — Depends on Phase 1.2, 1.4
├── 3.1: Latency monitoring (→ 1.4)
├── 3.2: Cache hit tracking (independent)
├── 3.3: Rate limit backoff (→ 1.2)
└── 3.4: Cascade optimization (independent)

Phase 4 (Polish) — Optional
├── 4.1: OpenAPI schema (independent)
├── 4.2: Troubleshooting guide (independent)
└── 4.3: Security audit (independent)
```

---

## Part 6: Implementation Checklist

### Pre-Implementation
- [ ] Review this blueprint
- [ ] Check branch `claude/see-know-gap-analysis-3yydci` is active
- [ ] Run existing tests to establish baseline
- [ ] Document current test execution time

### Phase 1: Foundation
- [ ] Task 1.1: `/status` endpoint
  - [ ] Create `endpoints/utility.rs`
  - [ ] Add endpoint enum variant
  - [ ] Implement response parsing
  - [ ] Add tests
  - [ ] Commit: "Add /status endpoint support"

- [ ] Task 1.2: Live HTTP seam
  - [ ] Create `client/mod.rs` trait
  - [ ] Create `client/real.rs` impl
  - [ ] Create `client/mock.rs` impl
  - [ ] Refactor existing client
  - [ ] Add CI workflow
  - [ ] Commit: "Introduce live HTTP client abstraction"

- [ ] Task 1.3: Plan tier auto-detection
  - [ ] Create `tier.rs`
  - [ ] Implement tier parsing
  - [ ] Add caching
  - [ ] Wire into dispatch
  - [ ] Add tests
  - [ ] Commit: "Add plan tier auto-detection"

- [ ] Task 1.4: Concurrent load testing
  - [ ] Create `tests/load_tests.rs`
  - [ ] Implement concurrent scan spawning
  - [ ] Add latency collection
  - [ ] Verify atomicity
  - [ ] Commit: "Add concurrent load testing"

### Phase 2: Enterprise
- [ ] Task 2.1: Discord history endpoint
- [ ] Task 2.2: Discord messages endpoint
- [ ] Task 2.3: Discord export endpoint
- [ ] Task 2.4: Enterprise documentation

### Phase 3: Performance
- [ ] Task 3.1: Latency monitoring
- [ ] Task 3.2: Cache hit tracking
- [ ] Task 3.3: Rate limit backoff sim
- [ ] Task 3.4: Cascade optimization

### Phase 4: Polish (Optional)
- [ ] Task 4.1: OpenAPI schema
- [ ] Task 4.2: Troubleshooting guide
- [ ] Task 4.3: Security audit

### Post-Implementation
- [ ] All tests passing
- [ ] All new code has test coverage >80%
- [ ] Documentation updated
- [ ] Gap analysis metrics re-evaluated
- [ ] Performance baseline established

---

## Part 7: Code Organization Principles

### Module Structure
```
src/modules/see_know/
├── mod.rs — Main orchestration, module trait impl
├── endpoints/ — Endpoint-specific logic (new structure)
├── extract.rs — Entity extraction (unchanged)
├── pivots.rs — Cascade resolution (unchanged)
├── metrics.rs — Instrumentation (new)
├── cache.rs — Cache management (new)
└── tests/ — All test suites (new structure)
```

### Traits & Interfaces
1. **HttpClient trait** — Abstract HTTP operations
   - Real implementation (production)
   - Mock implementation (testing)

2. **PlanTier enum** — Endpoint availability
   - Free, Pro, Enterprise variants
   - Endpoint matrix per tier

3. **LatencyMetrics trait** — Performance tracking
   - Histogram collection
   - Percentile calculation
   - Export interface

### Error Handling
- Use `anyhow::Result<T>` for fallible operations
- Custom error enum for HTTP layer
- Retry logic baked into client
- Rate limit backoff (exponential)

### Testing Strategy
1. Unit tests — Per-function tests
2. Integration tests — Endpoint-to-endpoint
3. Load tests — Concurrent scan validation
4. E2E tests — Real API with mock fallback

---

## Part 8: Build & Compile Considerations

### New Dependencies (if needed)
- `tokio` — Already present (async runtime)
- `reqwest` — Already present (HTTP client)
- `prometheus` — For metrics export (optional, Phase 3)
- `criterion` — For benchmarking (optional, Phase 3)

### Compile Times
- Phase 1: +5–10s (minor changes)
- Phase 2: +5–10s (endpoint additions)
- Phase 3: +10–15s (metrics/instrumentation)
- Phase 4: Minimal (docs only)

### Feature Flags (Optional)
```toml
[features]
default = ["see-know"]
see-know = []
see-know-enterprise = ["see-know"]
see-know-metrics = ["see-know", "prometheus"]
```

---

## Conclusion

This blueprint provides a complete file structure roadmap for implementing all gap analysis recommendations. The design emphasizes:

1. **Modularity** — Clear separation of concerns
2. **Testability** — Trait-based abstractions for mocking
3. **Observability** — Metrics and instrumentation built-in
4. **Backward Compatibility** — No breaking changes to existing API
5. **Incremental Delivery** — 4 clear phases with dependencies

**Total Implementation Effort:** ~10,000 LOC across 4 phases (8–10 weeks)

---

**Next Step:** Begin Phase 1 implementation using this blueprint as the guide.

