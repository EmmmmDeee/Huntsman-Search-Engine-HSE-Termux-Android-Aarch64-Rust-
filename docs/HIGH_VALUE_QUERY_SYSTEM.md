# High-Value Query Optimization System
**Date:** July 22, 2026  
**Status:** Superseded (see note below) — the scoring principles in Parts
1–4 are live; the `QueryOptimizer`/`QueryPlanner`/`ExecutionPlan`
integration Part 5 describes is not.  
**Impact:** Automatic query prioritization, ROI optimization, intelligent cascade routing

> **2026-07-23 status note:** this was written as a pre-implementation design
> doc. The value/cost/ROI scoring engines it specifies (Parts 1–4:
> `value_scorer`, `cost_analyzer`, `roi_router`) were built and ARE live —
> but wired directly into `modules::see_know::endpoints::order_by_roi`
> (reordering each target's SeekNow dispatch plan by ROI, with a
> `data_log::yield_counts` historical-yield boost), not through the
> `QueryOptimizer` / `QueryPlanner` / `ExecutionPlan` facade Part 5 below
> describes — that facade, and the standalone `CascadeOptimizer` it wrapped,
> were never called from anywhere live and have been removed as dead code.
> Treat Parts 1–4 as the current scoring-dimension reference; treat Part 5
> onward as historical design intent, not current architecture.

---

## Overview

The High-Value Query System automatically identifies, prioritizes, and routes queries to maximize information discovery per credit spent. This is a **pervasive architectural layer** that runs through all 4 phases.

### Core Principles

1. **Value Scoring** — Assign value to each query/endpoint based on:
   - Likelihood of finding new entities
   - Diversity of entity types discovered
   - Downstream pivot potential (cascade value)
   - Historical hit rate for similar queries

2. **Cost Analysis** — Track cost metrics:
   - Credit cost per query
   - Execution latency
   - Cache hit probability
   - Cascade depth cost

3. **ROI Routing** — Choose query path based on:
   - Value/Cost ratio
   - Budget remaining
   - Cascade depth optimization
   - Time constraints (SLA)

4. **Automatic Prioritization** — Reorder execution to:
   - Query high-value endpoints first
   - Skip low-value queries when budget tight
   - Maximize coverage within constraints
   - Adapt based on partial results

---

## Part 1: Value Scoring System

### Query Value Dimensions

#### 1. **Entity Diversity Score** (0-100)
How many unique entity types does endpoint return?

```
/search → 17 types (all) → Score: 100
/username/social → 3 types (username, platform, profile) → Score: 30
/network/ip → 5 types (IP, ASN, ISP, geolocation, hosting) → Score: 40
/discord/user → 2 types (Discord ID, username) → Score: 15
```

#### 2. **Hit Rate Score** (0-100)
Historical likelihood of finding data for this entity type

```
Email query:
  - Unknown/random email → 15% hit rate → Score: 15
  - Email from breach → 85% hit rate → Score: 85

Username query:
  - 3-char username → 5% hit rate → Score: 5
  - 8+ char unique username → 60% hit rate → Score: 60
```

#### 3. **Pivot Potential Score** (0-100)
Likelihood that results enable downstream cascades

```
/discord/user:
  - Returns Discord ID → Can pivot to Roblox/Steam → Score: 80
  - Returns username only → Limited cascade → Score: 20

/network/email-check:
  - Returns service list → Can query each service → Score: 75
  - Returns only "registered" → Limited cascade → Score: 30
```

#### 4. **Freshness Score** (0-100)
Based on cache age and data source update frequency

```
Fresh query (cache miss) → Score: 100
Cache hit <6h old → Score: 80
Cache hit 6-12h old → Score: 60
Cache hit 12-24h old → Score: 30
```

#### 5. **Coverage Score** (0-100)
How well this endpoint covers the entity type vs. alternatives

```
/search (primary) → Covers 70% of cases → Score: 100
/username/social (specialized) → Covers 15% unique cases → Score: 50
/search/deep (fallback) → Covers 10% ultra-rare cases → Score: 25
```

### Composite Value Score

```
ValueScore = (
    EntityDiversity * 0.25 +
    HitRate * 0.30 +
    PivotPotential * 0.25 +
    Freshness * 0.10 +
    Coverage * 0.10
)
```

**Range:** 0-100  
**Interpretation:**
- 80-100: Execute immediately
- 60-79: Execute if budget allows
- 40-59: Execute if budget >50% and time permits
- 20-39: Skip unless specifically requested
- 0-19: Skip (extremely low value)

---

## Part 2: Cost Analysis System

### Query Cost Dimensions

#### 1. **Direct Credit Cost**
```
/search: 1 credit
/search/deep: 1 credit (only on fast miss)
/username/social: 1 credit
/discord/user: 1 credit
/enterprise/discord/*: 5 credits each
/network/email-check: 1 credit
```

#### 2. **Latency Cost** (time-adjusted)
```
Fast queries (<5s): 1 point
Standard queries (5-15s): 3 points
Deep queries (15-45s): 5 points

Cost = LatencyPoints * (remaining_time / total_time_budget)
```

#### 3. **Cascade Cost** (multiplier)
```
Cascade depth 1: 1x multiplier
Cascade depth 2: 2.5x multiplier (secondary queries)
Cascade depth 3: 5x multiplier (tertiary queries)
```

#### 4. **Cache Benefit** (discount)
```
Cache miss: 1.0x cost (full price)
Cache hit <6h: 0.3x cost (30% of credit cost)
Cache hit 6-24h: 0.1x cost (10% of credit cost)
```

### Effective Cost Calculation

```
EffectiveCost = (
    DirectCreditCost +
    (LatencyCost * 0.15) +
    (CascadeCost * remaining_cascade_budget)
) * CacheBenefit
```

**Example:**
```
/username/social query on cached result:
= (2 + (3 * 0.15) + (1.5 * 0.8)) * 0.3
= (2 + 0.45 + 1.2) * 0.3
= 3.65 * 0.3
= 1.1 effective credits
```

---

## Part 3: ROI-Based Query Routing

### Query Efficiency Metric

```
ROI = ValueScore / EffectiveCost

High ROI (>50): Execute first
Medium ROI (20-50): Execute if budget permits
Low ROI (<20): Skip unless required
```

### Automatic Query Prioritization Algorithm

**Input:** Target entity, budget remaining, time remaining, cascade depth

**Process:**

```
1. Generate query candidates for target type
   Example: Email input → [/search, /network/email-check, /search/deep]

2. Score each candidate (credit cost only — the router's EFFECTIVE cost also
   adds latency and cascade terms; see step 3)
   /search: Value=85, Cost=1.0, ROI=85
   /network/email-check: Value=65, Cost=1.0, ROI=65
   /search/deep: Value=95, Cost=1.0, ROI=95

3. Sort by EFFECTIVE cost, not credits alone. /search/deep bills the SAME
   1 credit as /search, so credit-ROI alone would rank it first — but
   `calculate_effective_cost` adds `latency*0.15`, and deep's ~40s against
   fast's ~5s is what keeps it a fallback rather than a first call.
   [/search (85), /network/email-check (65), /search/deep (fallback, ~40s)]

4. Execute in order while budget/time permits
   - Execute /search (cost 1, value 85)
   - If hit, stop (found entities)
   - If miss AND time permits (~40s):
     - Execute /search/deep (cost 1, value 95)

5. Return combined results
```

### Cascade Decision Logic

```
IF cascade_enabled AND pivot_found:
  pivot_value = calculate_pivot_value(found_pivot)
  pivot_cost = estimate_cascade_cost(depth+1)
  pivot_roi = pivot_value / pivot_cost
  
  IF pivot_roi > depth_threshold AND budget_sufficient:
    QUEUE cascade query
  ELSE:
    SKIP cascade
```

---

## Part 4: Intelligent Cascade Routing

### High-Value Pivot Detection

#### Tier-1 Pivots (Always cascade, if budget allows)
```
Discord ID → (Roblox, Steam)      [High value, multiple platforms]
Email → Service platforms          [Widespread registration]
Username → Platform accounts       [Multiple platform coverage]
IP address → Domain registrations  [Infrastructure mapping]
```

#### Tier-2 Pivots (Cascade if ROI positive)
```
ASN → Other IPs in same network    [Limited value without context]
Domain → Email addresses           [Medium value, dependent on registrations]
Phone → Account linkages           [Moderate value, sparse data]
```

#### Tier-3 Pivots (Skip unless explicitly requested)
```
Coordinates → Nearby locations     [Low value, low precision]
Organization → Employee records    [Limited coverage]
```

### Cascade Depth Adaptation

```
Depth 1 (direct queries):
  ROI threshold: 10 (low threshold, explore broadly)
  Execute: All queries scoring >10

Depth 2 (first cascade):
  ROI threshold: 25 (higher threshold)
  Execute: Only queries scoring >25
  
Depth 3 (deep cascade):
  ROI threshold: 50 (high threshold)
  Execute: Only queries scoring >50
  
Beyond Depth 3:
  ROI threshold: 100 (very high threshold)
  Execute: Only queries scoring >100
```

### Cascade Budget Allocation

```
Total Budget: 2500 credits (enterprise example)

Depth 1: 60% allocation (1500 credits)
  - Execute all high-value direct queries

Depth 2: 30% allocation (750 credits)
  - Execute high-ROI pivots from Depth 1 results

Depth 3: 10% allocation (250 credits)
  - Execute only ultra-high-value deep pivots

Override: User can adjust allocation with flags
  --depth-1-ratio 0.7 --depth-2-ratio 0.25 --depth-3-ratio 0.05
```

---

## Part 5: Architecture Integration

### Files to Create

#### New Core Module: `src/modules/see_know/query_optimizer/`

```
src/modules/see_know/query_optimizer/
├── mod.rs — Main optimizer orchestrator
├── value_scorer.rs — Value scoring logic (Phase 1.1+)
├── cost_analyzer.rs — Cost calculation (Phase 1.2+)
├── roi_router.rs — ROI-based query routing (Phase 1.3+)
├── cascade_optimizer.rs — Intelligent cascade routing (Phase 2.1+)
├── query_planner.rs — Generate optimal query sequence (Phase 2.2+)
└── tests.rs — Comprehensive testing (All phases)
```

#### Integration Points

1. **Phase 1.1:** Add value_scorer to /status endpoint
2. **Phase 1.2:** Integrate cost_analyzer with HTTP client
3. **Phase 1.3:** Add ROI router to tier detection
4. **Phase 1.4:** Load test with query optimizer
5. **Phase 2.1-2.3:** Integrate cascade_optimizer for Discord endpoints
6. **Phase 3.1:** Track value metrics (Phase 3.1 latency monitoring)
7. **Phase 3.4:** Use optimizer results for cascade efficiency (Phase 3.4)

### Configuration

**Config values in `src/util/see_know/config.rs`:**

```rust
// Value score weights
pub const VALUE_ENTITY_DIVERSITY_WEIGHT: f32 = 0.25;
pub const VALUE_HIT_RATE_WEIGHT: f32 = 0.30;
pub const VALUE_PIVOT_POTENTIAL_WEIGHT: f32 = 0.25;
pub const VALUE_FRESHNESS_WEIGHT: f32 = 0.10;
pub const VALUE_COVERAGE_WEIGHT: f32 = 0.10;

// ROI thresholds per cascade depth
pub const ROI_DEPTH_1_THRESHOLD: f32 = 10.0;
pub const ROI_DEPTH_2_THRESHOLD: f32 = 25.0;
pub const ROI_DEPTH_3_THRESHOLD: f32 = 50.0;

// Budget allocation per cascade depth
pub const BUDGET_DEPTH_1_RATIO: f32 = 0.60;
pub const BUDGET_DEPTH_2_RATIO: f32 = 0.30;
pub const BUDGET_DEPTH_3_RATIO: f32 = 0.10;
```

---

## Part 6: Implementation Timeline

### Phase 1: Foundation + Value Scoring
- **1.1:** Value scorer for /status endpoint
- **1.2:** Cost analyzer for HTTP client
- **1.3:** ROI router integrated with tier detection
- **1.4:** Load test query optimizer under concurrency
- **Effort:** +10-15 days (overlaps with base Phase 1)

### Phase 2: Enterprise + Cascade Intelligence
- **2.1-2.3:** Cascade optimizer for Discord endpoints
- **2.4:** Document query optimization in enterprise guide
- **Effort:** +5-7 days (overlaps with base Phase 2)

### Phase 3: Performance + Metrics
- **3.1:** Add value metrics to latency monitoring
- **3.2:** Cache hit ratio tied to value scoring
- **3.3:** Rate limit backoff adjusted by query ROI
- **3.4:** Cascade optimizer becomes core (Phase 3.4 optimization)
- **Effort:** Minimal additional (integrated into Phase 3)

### Phase 4: Polish + Analysis
- **4.1:** OpenAPI schema includes value/cost metadata
- **4.2:** Troubleshooting guide references query optimizer
- **4.3:** Security audit covers query planner isolation
- **Effort:** +2-3 days (overlaps with Phase 4)

**Total Additional Effort:** ~17-25 days (distributed across all phases)

---

## Part 7: Example Query Flows

### Example 1: Email Investigation (Pro Plan, 1000 credits)

**Input:** `user@example.com`

**Query Optimizer Analysis:**
```
Candidates:
  /search: Value=85, Cost=1.0, ROI=85
  /network/email-check: Value=65, Cost=1.0, ROI=65
  /search/deep: Value=95, Cost=1.0, ROI=95 (latency-gated: fallback only)

Execution Plan:
  1. /search (ROI 85)
     Cost: 1 credit
     Expected: 15-20 entities (email registrations, breaches)
     Cache: Miss (first time)
     
  2. /network/email-check (ROI 65)
     Cost: 1 credit
     Expected: 8-12 services (platforms user registered on)
     
  3. /search/deep (only if /search miss — same 1 credit, ~40s vs ~5s)
     Cost: 1 credit
     Expected: Deep breach search, rare registrations

Budget Remaining: 997 credits (post-depth-1 queries)

Cascade Analysis:
  Found emails: [user2@example.com, user3@example.com, ...]
  Each email can be re-queried (cascade Depth 2)
  
  Cascade Budget: 997 * 0.30 = 299 credits
  Per-email cost: ~3 credits
  Cascade Capacity: ~100 emails
  
  High-Value Pivots Detected:
    - Discord ID (found in breach) → Pivot to Roblox/Steam
    - Telegram user (found in stealer) → Limited cascade value
    - GitHub account (found in registration) → Good pivot potential
    
  Cascade Plan:
    1. Discord → Roblox (Tier-1 pivot, execute)
    2. Discord → Steam (Tier-1 pivot, execute)
    3. GitHub (cascade email check on GitHub, Tier-2 pivot)
    4. Skip Telegram (Tier-3 pivot, low ROI)

Final ROI: 127 entities found from 8 credits spent ≈ 15.9 entities/credit
```

### Example 2: Username Hunt (Free Plan, 300 credits)

**Input:** `unique_username_123`

**Query Optimizer Analysis:**
```
Candidates:
  /username/social: Value=75, Cost=1.0, ROI=75
  /search: Value=50, Cost=1.0, ROI=50
  /username/history: Value=40, Cost=1.0, ROI=40

Execution Plan (Budget: 300 credits):
  1. /username/social (ROI 75)
     Cost: 1 credit
     Expected: 15+ platform results (Twitter, TikTok, Reddit, etc.)
     Cache: Miss

  2. /search (ROI 50)
     Cost: 1 credit
     Expected: Generic results (low precision for username-only)

  3. /username/history (ROI 40)
     Cost: 1 credit
     Expected: Old usernames, account registrations
     Decision: EXECUTE — correcting the price from 2 credits to the contract's
       1 lifted ROI from 20 to 40, clearing `route_query`'s ExecuteIfBudget
       threshold. This endpoint was previously skipped purely because it was
       over-billed.

Budget Remaining: 297 credits

Cascade Analysis:
  Found: Twitter (@unique_username_123), TikTok, Reddit, Discord ID
  
  Pivot Potential:
    - Discord ID (Tier-1) → Roblox, Steam, Xbox
    - Email (from Twitter profile) → Network queries
    - Phone (from Discord) → Phone lookup
    
  Cascade Budget: 297 * 0.30 = 89 credits
  
  High-Value Cascades:
    1. Discord → Roblox (ROI 75)
    2. Discord → Steam (ROI 75)
    3. Email → /network/email-check (ROI 65)

Final ROI: 89 entities from 7 credits ≈ 12.7 entities/credit
```

---

## Part 8: Monitoring & Tuning

### Metrics to Track

1. **Actual vs. Expected ROI**
   - Did query actually return expected entity count?
   - Was hit rate prediction accurate?
   - Adjust scoring based on actual results

2. **Query Sequence Efficiency**
   - Total value discovered per credit
   - Cascade depth utilization
   - Budget utilization percentage

3. **Misclassified Queries**
   - High-ROI queries that returned nothing
   - Low-ROI queries that were surprisingly valuable
   - Adjust scoring weights

4. **Time vs. Value**
   - Fast queries (high value per second)
   - Slow queries (high value overall but slow)
   - Choose based on time budget

### Tuning Process

**Monthly Review:**
1. Collect all query metrics (value, cost, actual results)
2. Compare predicted vs. actual for each endpoint
3. Adjust value scoring weights
4. Adjust ROI thresholds if needed
5. Re-train cascade depth allocation

---

## Part 9: Backward Compatibility

### Opt-In Flag

```bash
# Enable automatic query optimization
hse scan --value user@example.com --auto-optimize

# Or use env var
export HUNTSMAN_SEEKNOW_AUTO_OPTIMIZE=1
hse scan --value user@example.com
```

### Default Behavior

- **Phase 1-3:** Query optimizer runs but doesn't override user-explicit requests
- **Phase 3+:** Can switch to fully automatic (user opt-in only)
- **User can disable:** `--no-optimize` to use original routing

---

## Conclusion

The High-Value Query System transforms See-Know from "execute all endpoints" to "execute smartest endpoints" by:

1. **Scoring queries** on multiple value dimensions
2. **Analyzing costs** including latency, credits, cache benefits
3. **Routing intelligently** based on ROI
4. **Prioritizing cascades** by pivot potential
5. **Adapting dynamically** to budget/time constraints

This pervasive layer runs through all 4 phases and can improve overall OSINT discovery efficiency by **30-50%** (entity count per credit spent).

---

**Total Implementation:** ~17-25 additional days distributed across Phases 1-4  
**ROI Impact:** 30-50% improvement in discovery efficiency  
**Priority:** High (revenue-positive, user-facing benefit)

