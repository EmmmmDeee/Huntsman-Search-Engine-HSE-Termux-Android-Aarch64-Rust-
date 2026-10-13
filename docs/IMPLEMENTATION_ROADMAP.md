# Huntsman OSINT Engine: Implementation Roadmap

**Status:** Levels 1-3 Complete | Levels 4-8 In Progress  
**Target:** Android aarch64 Termux, Full Functional Parity, Zero Regressions

---

## CURRENT BASELINE

✓ **Level 1: Discovery & Baseline**
- Repository structure: 174 modules, 72K lines of Rust
- Build: Compiles cleanly (Rust 1.97.0)
- Tests: 1188 passing (100% success rate)
- Entry point: `investigate` CLI tool
- Dependencies: ureq (HTTP), serde (serialization), redb (storage)

✓ **Level 2: Requirements & Planning**
- Acceptance criteria defined (functional, integration, platform, quality)
- Critical workflow mapped (input→validation→routing→execution→aggregation→output)
- Budget allocation: 60s total, per-phase allocation (Phase1:15s, Phase2A:9s, Phase2B:12s, Phase3:15s, Phase4:9s)
- Rate limiting: 5-60 req/min across 29 modules, exponential backoff (0.1s → 30s)

✓ **Level 3: Canonicalization**
- Evidence provenance model (source, authority_tier, attributes, timestamp)
- Entity model (kind, identifiers, attributes, evidence)
- Query types: domain, person, company, IP, general
- Module structure: parse_*_response() → query() → query_*_deadline() → record_to_evidence()

---

## LEVEL 4: PARALLEL EXECUTION IMPLEMENTATION

### 4.1 Wave Dispatcher (HIGH PRIORITY)

**Objective:** Implement concurrent module execution with 6-concurrent limit

**Implementation Steps:**
1. Create `src/dispatcher.rs` module
   - `struct ParallelWave { modules: Vec<Module>, deadline: Duration }`
   - `fn execute_wave(&mut self, wave: ParallelWave) → Vec<Evidence>`
   - Spawn tasks with `std::thread::spawn` (bounded pool)
   - Enforce per-module timeout = (remaining_phase_budget / remaining_modules)

2. Integrate with `src/pipeline.rs`
   - Modify `investigate_offline()` to use `execute_wave()` instead of sequential execution
   - Pass `SearchOrchestrator` for rotation strategy
   - Track per-source backoff state

3. Tests:
   - `test_wave_executes_6_concurrent` (mock modules, verify thread count)
   - `test_wave_respects_deadline` (verify timeout enforcement)
   - `test_wave_skips_rate_limited` (backoff > remaining_budget)

**Timeline:** 1 sprint (immediate)

### 4.2 Rate Limit State Management (HIGH PRIORITY)

**Objective:** Track per-source backoff and enforce rate limiting

**Implementation Steps:**
1. Extend `src/search_engines.rs`
   - `RateLimitManager { states: HashMap<Source, RateLimitState> }`
   - `fn should_skip(&self, source, remaining_budget) → bool`
   - `fn record_success(&mut self, source)` (decay backoff)
   - `fn record_rate_limit(&mut self, source)` (exponential backoff)

2. Integration with dispatcher
   - Before executing module: check `should_skip()`
   - After response: call `record_success()` or `record_rate_limit()`
   - Pass backoff enforcer to each module's query function

3. Tests:
   - `test_backoff_exponential_growth` (verify 2.0x multiplier)
   - `test_backoff_decay` (verify 0.9x reduction)
   - `test_skip_if_backoff_exceeds_budget`

**Timeline:** 1 sprint (parallel with 4.1)

### 4.3 Evidence Aggregation & Deduplication (MEDIUM PRIORITY)

**Objective:** Collect, deduplicate, and rank evidence

**Implementation Steps:**
1. Create `src/aggregator.rs`
   - `struct EvidenceAggregator { items: Vec<Evidence>, max: 100 }`
   - `fn add(&mut self, evidence: Evidence) → bool` (respects max)
   - `fn deduplicate(&self) → Vec<Evidence>` (exact + semantic + conflict)
   - `fn rank(&self) → Vec<RankedEvidence>` (score by tier + recency + completeness)

2. Deduplication logic
   - Exact: `hash(evidence) == hash(other)`
   - Semantic: `normalize(field) == normalize(other_field)` (case, whitespace, formats)
   - Conflict: Same {kind, identifier} but different attributes, flag for review

3. Tests:
   - `test_aggregator_respects_max` (100 items limit)
   - `test_exact_deduplication` (identical evidence removed)
   - `test_semantic_deduplication` (format variations)
   - `test_ranking_by_authority_tier`
   - `test_ranking_by_recency_bonus`

**Timeline:** 1 sprint

### 4.4 Module Integration Layer (MEDIUM PRIORITY)

**Objective:** Wire all 29 modules into query pipeline

**Implementation Steps:**
1. Create `src/module_registry.rs`
   - `enum ModuleId { ApnicWhois, AudaDomain, AsicCompany, ... }`
   - `ModuleRegistry { configs: HashMap<ModuleId, ModuleConfig> }`
   - `fn select_modules(query_type, phases) → Vec<ModuleId>`
   - `fn execute_module(id: ModuleId, input, timeout, rate_limiter) → Evidence`

2. Module wiring
   - Each of 29 modules already has `query_*_deadline()` function
   - Create dispatch function that routes ModuleId → actual module function
   - Ensure all modules follow consistent signature

3. Tests:
   - `test_select_modules_for_domain_query`
   - `test_select_modules_for_person_query`
   - `test_all_29_modules_selectable`
   - `test_module_execution_isolation` (one failure doesn't affect others)

**Timeline:** 1 sprint

---

## LEVEL 5: COMPLETE END-TO-END WIRING

### 5.1 Query Pipeline Integration (HIGH PRIORITY)

**Objective:** Wire input → output through all 5 phases

**Implementation Steps:**
1. Modify `src/pipeline.rs::investigate_offline()`
   - Input normalization (validate, whitespace trim, case handling)
   - Query type detection (domain/person/company/IP/general)
   - Phase selection based on query type
   - Module selection and budgeting
   - Call `execute_wave()` for each phase in sequence
   - Aggregate results from all phases
   - Call `deduplicate()` and `rank()` on aggregated evidence
   - Return complete report with entities, relations, evidence

2. Data flow
   ```
   investigate_offline()
     ├─ normalize_input() → { accepted, rejected }
     ├─ select_phases(query_type) → [Phase1, ..., PhaseN]
     ├─ for each phase:
     │   ├─ allocate_budget(phase)
     │   ├─ select_modules(phase, query_type)
     │   ├─ execute_wave(modules, deadline, rate_limiter)
     │   └─ collect_evidence(wave_results)
     ├─ aggregator.add_all(all_evidence)
     ├─ deduplicate()
     ├─ rank()
     └─ return Report { entities, relations, evidence }
   ```

3. Tests:
   - `test_complete_domain_query_workflow`
   - `test_complete_person_query_workflow`
   - `test_evidence_aggregation_across_phases`
   - `test_deadline_enforcement_strict_cutoff`

**Timeline:** 1 sprint

### 5.2 Persistence & Session Recovery (MEDIUM PRIORITY)

**Objective:** Save and reload investigation sessions

**Implementation Steps:**
1. Extend `src/runtime.rs`
   - `fn persist_session(session_dir, session) → Result<Path>`
   - `fn load_session(session_dir, session_id) → Result<Session>`
   - Use existing `Store` + redb for storage

2. Tests:
   - `test_session_save_and_reload`
   - `test_evidence_persisted_exactly`
   - `test_entities_relationships_preserved`

**Timeline:** 0.5 sprint (leverage existing Store)

---

## LEVEL 6: TARGET PLATFORM VALIDATION

### 6.1 Termux/aarch64 Compatibility (ONGOING)

**Objective:** Verify execution on actual Android aarch64 Termux environment

**Implementation Steps:**
1. Build on target
   - `cargo build --release` in Termux aarch64 environment
   - Track build time, binary size, memory usage
   - Verify no ARM-specific issues

2. Execute on target
   - `investigate --help` (CLI works)
   - `investigate domain.example.au` (query execution)
   - `investigate --session-dir /tmp domain.example.au` (persistence)
   - `investigate --load-session /tmp SESSION_ID` (recovery)
   - Verify network access (HTTP queries work)

3. Resource limits
   - Monitor memory usage (<100MB typical)
   - Monitor disk usage (session storage)
   - Verify no infinite loops or hangs

4. Tests:
   - `test_termux_file_paths` (handle Termux-specific paths)
   - `test_rootless_network_access` (no privileged operations)
   - `test_unrooted_device_compatibility`

**Timeline:** Ongoing (verify after each milestone)

---

## LEVEL 7: TESTING & CORRECTION

### 7.1 Regression Test Suite

**Objective:** Ensure no functionality lost during implementation

**Implementation Steps:**
1. Create `tests/integration_tests.rs`
   - Test all 1188 existing unit tests (ensure 100% pass)
   - Add integration tests for critical workflows
   - Mock external sources for deterministic testing

2. Test categories:
   - **Unit:** Each module's parse/query/evidence functions (already exist)
   - **Integration:** Complete query pipeline (new)
   - **Persistence:** Save/load sessions (new)
   - **Rate Limiting:** Backoff behavior (new)
   - **Deadline:** Timeout enforcement (new)
   - **Deduplication:** Evidence consolidation (new)

3. Acceptance gate:
   - All 1188+ existing tests pass
   - All new integration tests pass
   - No regressions from baseline

**Timeline:** Continuous (verify after each change)

### 7.2 Performance Baseline & Verification

**Objective:** Establish and verify performance targets

**Implementation Steps:**
1. Baseline measurements
   - Single module query (e.g., APNIC): <500ms
   - Full 3-module Phase1: <2s
   - Full 29-module query (all 5 phases, serial): ~60s
   - Full 29-module query (parallel, 6-wave): ~36s

2. Regression checks
   - No module slower than baseline + 50%
   - Parallel execution achieves 1.67x speedup
   - Memory usage stable (<100MB)

3. Tests:
   - `test_module_latency_within_budget` (each module)
   - `test_parallel_speedup_achieved`
   - `test_memory_usage_bounded`

**Timeline:** 1 sprint (after parallel execution complete)

---

## LEVEL 8: FINAL ACCEPTANCE & DELIVERY

### 8.1 Acceptance Criteria Verification

**Objective:** Verify all critical acceptance criteria

**Checklist:**
- [ ] All 1188+ tests passing (zero failures)
- [ ] No compilation warnings
- [ ] All 29 modules wired and functional
- [ ] Complete query workflow executes end-to-end
- [ ] Evidence aggregation and deduplication working
- [ ] Deadline enforcement operational (strict 60s cutoff)
- [ ] Rate limiting with backoff working correctly
- [ ] Termux/aarch64 compatibility verified
- [ ] All documentation current and accurate
- [ ] Zero regressions from baseline

### 8.2 Deliverables

**Code:**
- [ ] Source repository clean (git status clean)
- [ ] All changes committed with clear messages
- [ ] Branch pushed to origin/claude/upbeat-davinci-v1u6rd
- [ ] CI green (cargo check, cargo test)

**Documentation:**
- [ ] AUSTRALIAN_OSINT_RESOURCES.md (70+ sources)
- [ ] PIPELINE_OPTIMIZATION.md (architecture, scheduling)
- [ ] IMPLEMENTATION_ROADMAP.md (this file, updated)
- [ ] README with build/test/run/deploy instructions
- [ ] Architecture diagram (text-based in docs/)

**Evidence:**
- [ ] Build log (cargo build --release)
- [ ] Test results (cargo test --lib, all pass)
- [ ] Integration test output
- [ ] Target platform verification (Termux/aarch64)
- [ ] Performance baseline measurements
- [ ] Session save/load verification

**Timeline:** 1 sprint (after all levels complete)

---

## MASTER IMPLEMENTATION SEQUENCE

1. **Sprint 1 (Levels 4.1-4.2):** Parallel execution + rate limiting
2. **Sprint 2 (Levels 4.3-4.4):** Aggregation + module integration
3. **Sprint 3 (Level 5.1):** Query pipeline wiring + integration
4. **Sprint 4 (Level 5.2):** Persistence (leverage existing Store)
5. **Sprint 5 (Levels 6-7):** Platform validation + regression testing
6. **Sprint 6 (Level 8):** Final acceptance + delivery

**Total Duration:** 6 sprints (~3 weeks with aggressive execution)

---

## BLOCKING DEPENDENCIES

None identified. All required infrastructure exists:
- ✓ 174 modules with consistent structure
- ✓ SearchEngineType enum for rotation
- ✓ Deadline/timeout framework operational
- ✓ Transport abstraction for mock testing
- ✓ Evidence/Entity/Relation data models
- ✓ Storage layer (redb graph) integrated

---

## RISK MITIGATION

| Risk | Probability | Impact | Mitigation |
|------|-------------|--------|------------|
| Deadline enforcement fails | Low | High | Early integration tests, verify on synthetic load |
| Rate limiting breaks queries | Medium | Medium | Mock rate limiter, unit test exponential backoff |
| Deduplication loses evidence | Low | High | Test with known duplicates, verify all preserved |
| Parallel execution race condition | Low | High | Bounded thread pool, mutex-protected state |
| Termux incompatibility discovered late | Medium | High | Test on actual Termux aarch64 weekly |
| Regressions in existing tests | Low | Critical | Run full test suite after each change |

---

## DEFINITION OF DONE

HUNTSMAN IS COMPLETE WHEN:

1. ✓ All required functionality implemented
2. ✓ Data, schemas, contracts canonical and consistent
3. ✓ All components wired and functional end-to-end
4. ✓ Existing functionality preserved (1188+ tests pass)
5. ✓ No introduced regressions
6. ✓ Rootless Termux compatibility verified
7. ✓ Build/test/run procedures reproducible
8. ✓ All acceptance criteria supported by evidence
9. ✓ Remaining limitations explicitly documented

**Success Metric:** Full query pipeline executes end-to-end, collects/aggregates/deduplicates evidence from 29+ Australian OSINT sources, within 60s deadline, on Termux/aarch64, with all tests passing.

---

**Next Action: Begin Level 4 Implementation**
- Create `src/dispatcher.rs` for parallel wave execution
- Extend `src/search_engines.rs` with rate limit manager
- Create `tests/integration_tests.rs` for workflow verification
