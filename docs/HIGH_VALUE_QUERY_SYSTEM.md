# High-Value Query Optimization System
**Date:** July 22, 2026  
**Status:** Superseded (see note below) — the scoring principles in Parts
1–4 are live; the `QueryOptimizer`/`QueryPlanner`/`ExecutionPlan`
integration Part 5 (and onward) described is not and has been removed from
this document — see the note below.  
**Impact:** Automatic query prioritization, ROI optimization, intelligent cascade routing

> **2026-07-23 status note:** this was written as a pre-implementation design
> doc. The value/cost/ROI scoring engines it specifies (Parts 1–4:
> `value_scorer`, `cost_analyzer`, `roi_router`) were built and ARE live —
> but wired directly into `modules::see_know::endpoints::order_by_roi`
> (reordering each target's SeekNow dispatch plan by ROI, with a
> `data_log::yield_counts` historical-yield boost), not through the
> `QueryOptimizer` / `QueryPlanner` / `ExecutionPlan` facade the original
> Part 5 described — that facade, and the standalone `CascadeOptimizer` it
> wrapped, were never called from anywhere live and were removed as dead
> code. The original Parts 5–9 (architecture-integration plan, implementation
> timeline, and a backward-compatibility section for a facade that was never
> built) described that unimplemented integration and have been deleted from
> this file as stale planning content — see git history if you need them.
> Treat Parts 1–4 below as the current scoring-dimension reference.

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

### Worked Example: Username Target

A second candidate set, to show the scoring isn't specific to email targets —
same mechanical ranking as the email example above (step 2), applied to a
username input:

```
Candidates for `unique_username_123`:
  /username/social: Value=75, Cost=1.0, ROI=75
  /search: Value=50, Cost=1.0, ROI=50
  /username/history: Value=40, Cost=1.0, ROI=40

Ranked by ROI: /username/social first, then /search, then /username/history
— all three are cheap enough (1 credit each) that a typical budget executes
all three rather than stopping at the first hit.
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
```

There is currently no CLI flag to override this allocation — the ratios
above are fixed constants, not tunable at runtime.
