# SeekNow Performance Monitoring & Analytics

Real-time performance tracking, credit utilization analytics, and optimization recommendations for enterprise OSINT operations.

---

## Quick Stats Dashboard

Check your real-time performance:

```bash
# Get current credits + usage metrics
curl -s -H "X-API-Key: $HUNTSMAN_SEEKNOW_KEY" https://see-know.eu/api/v1/credits | jq '.'

# Expected output:
{
  "success": true,
  "plan": "enterprise",
  "credits_remaining": 15000,
  "credits_daily_limit": 15000,
  "credits_used_today": 0,
  "resets_at": "2026-07-10T00:00:00Z"
}
```

---

## Performance Metrics

### Per-Scan Analytics

After each scan, HSE logs:

```
Scan: test@example.com (email, depth 1)
Duration: 8.3s
Endpoints queried:
  ✓ /search (1 credit, 42 results) — 5.2s
  ✓ /network/email-check (1 credit, 1 result) — 2.1s
  ✓ Cache hits: 0
Credits consumed: 2
Entities extracted: 15 (12 Email, 3 Person)
Average credit per entity: 0.13
Effectiveness: High (15 new entities)
```

### Cumulative Daily Report

```bash
# HSE maintains a session-level budget tracker
hse doctor
# Shows:
# - Credits remaining
# - Per-scan cap (auto-calculated)
# - Scans completed this session
# - Total credits consumed
# - Average cost per scan
# - Predicted scans remaining at current rate
```

---

## Optimization Strategies

### 1. Budget Allocation by Depth

| Depth | Typical Cost | ROI | Use Case |
|-------|------------|-----|----------|
| **1** | 50–100 | High | Quick verification, single target |
| **2** | 150–300 | Very High | Expanded reconnaissance, 2–3 pivots |
| **3** | 300–750 | Extreme | Full infrastructure, force-multiplier cascade |
| **4+** | 1000+ | Diminishing | Exhaustive hunting (usually not needed) |

**Recommendation:** Most cases need depth 2. Depth 3 for high-value targets or incident response.

### 2. Endpoint Efficiency

**Highest ROI endpoints:**
1. `/search` (1 credit) — Returns 10–100 records, extracts multiple entity types
2. `/username/social` (1 credit) — Tests 70+ platforms in one call
3. `/domain/intel` (1 credit) — Returns DNS + tech stack + related subdomains
4. `/network/email-check` (1 credit) — Fast validation, counts breach mentions

**Lower ROI endpoints (use only if target-specific):**
- Individual social profiles (`/username/github`, `/username/twitter`) — Duplicate coverage from `/username/social`
- Gaming profiles — Unless you're hunting gaming-community threat actors

### 3. Caching Strategy

**HSE caches automatically** within a session. Duplicate queries = 0 credits.

**Manual caching (cross-session):**
```bash
# Archive responses are saved to ~/.hse/raw_archive/see-know/
# Re-query any historical target → HSE checks archive first

# Extract cached response (no API call)
ls ~/.hse/raw_archive/see-know/search/
# Shows: john_doe.json, alice_92.json, etc.
```

### 4. Batch Processing

For multiple targets, batch and monitor:

```bash
# Process 10 email targets (estimated 200 credits)
for email in $(cat targets.txt | head -10); do
  echo "Scanning: $email"
  hse scan --kind email --value "$email" --depth 1 --seeknow-scan-cap 20
  # After each scan, review progress
  curl -s -H "X-API-Key: $HUNTSMAN_SEEKNOW_KEY" https://see-know.eu/api/v1/credits | \
    jq '.credits_remaining'
done

# Daily limit management
echo "Credits remaining today: $(curl -s -H "X-API-Key: ..." https://see-know.eu/api/v1/credits | jq '.credits_remaining')"
```

---

## Cost Breakdown Examples

### Example 1: Single Email Investigation
```
Target: target@company.com
Depth: 1

Endpoints:
  /search (1 credit, 30 results)
  /network/email-check (1 credit, 1 result)

Total Cost: 2 credits
Time: 8 seconds
Entities: 12 (Email, Person, Password, ApiKey)
Cost per entity: 0.17 credits
```

### Example 2: Domain Infrastructure Assessment
```
Target: acme.com
Depth: 3

Phase 1 (Paid):
  /search (1 credit, 45 results)
  /domain/intel (1 credit)
  /domain/whois (1 credit)
  /search on emails found (auto-expansion, 2 credits)

Phase 2 (Free):
  dns_intel (DNS records)
  cert_intel (Certificate SANs)
  web_crawler (103 config paths per domain × 5 domains = 500 HTTP requests, ~0 cost*)
  *web_crawler uses local DNS + HTTP, no SeekNow credits

API keys found:
  2 Shodan keys (force-multiplier) → unlock Shodan module
  1 GitHub token → unlock GitHub module

Total Cost: 5 SeekNow credits + unlimited free module usage
Time: 2–3 minutes
Entities: 87 (Domain, IP, Email, Person, ApiKey, Credential, etc.)
Cost per entity: 0.06 credits
Infrastructure unlocked: 2 additional paid modules (Shodan, GitHub)
```

### Example 3: Threat Actor Profile (3 username variants)
```
Targets: alice_92, alice92, alice.92
Depth: 3

Per target:
  Phase 1: /search, /username/social, /username/history (3 credits)
  Phase 2: Email found → expand (2 credits/email × 2 emails = 4 credits)
  Phase 3: Force-multiplier cascade (2 credits)
  Total per target: ~9 credits

Total for 3 variants: 27 credits
Time: 8–10 minutes
Entities: 145+ (deduped to ~45 unique)
Correlations: All 3 usernames linked to same Person
Cost per unique entity: 0.6 credits (high because of deduplication)
**Value:** Complete threat actor profile with OPSEC failure documentation
```

---

## Performance Monitoring Checklist

### Daily Health Check

```bash
#!/bin/bash
# save as ~/hse-daily-check.sh

API_KEY="${HUNTSMAN_SEEKNOW_KEY}"
CREDITS=$(curl -s -H "X-API-Key: $API_KEY" https://see-know.eu/api/v1/credits)

REMAINING=$(echo $CREDITS | jq '.credits_remaining')
DAILY_LIMIT=$(echo $CREDITS | jq '.credits_daily_limit')
RESETS=$(echo $CREDITS | jq -r '.resets_at')

echo "=== SeekNow Daily Report ==="
echo "Credits: $REMAINING / $DAILY_LIMIT"
echo "Usage: $(( (DAILY_LIMIT - REMAINING) * 100 / DAILY_LIMIT ))%"
echo "Resets: $RESETS"

# Estimate remaining scans at average cost (2-5 credits per scan)
SCANS_REMAINING=$((REMAINING / 3))
echo "Estimated scans remaining: ~$SCANS_REMAINING (at 3 credits/scan average)"
```

Run daily:
```bash
chmod +x ~/hse-daily-check.sh
./hse-daily-check.sh
```

---

## Optimization Recommendations

### For Light Users (Beginner Plan: 100/day)
- Target depth 1 scans only (50–100 credits)
- Focus on high-value targets
- Batch 2–3 scans per day
- Use weekly (not daily)

### For Active Users (Pro Plan: 500/day)
- Mix depth 1 (quick) and depth 2 (comprehensive)
- Target 5–10 scans per day
- Rotate between different target types
- Weekly deep dives (depth 3) on priority targets

### For Intensive Operations (PremiumHQ: 5,000/day)
- Full depth 3 scans on all targets
- Daily monitoring of threat actors (3+ username variants)
- Real-time incident response (domain assessments)
- ~10–15 deep scans per day
- Force-multiplier cascade unlocks all downstream APIs

### For Enterprise (Unlimited)
- Unrestricted depth 3 operations
- Discord history archives (`/enterprise/discord/*`)
- Bulk processing (100+ targets/day)
- Continuous threat monitoring
- No budget constraints

---

## Advanced Analytics

### Cost Efficiency by Target Type

```bash
# (HSE automatically tracks this per scan)

Email scan:      2–3 credits (fast, focused)
Username scan:   2–5 credits (depends on platform coverage)
Domain scan:     3–10 credits (depends on subdomain count)
IP scan:         2–3 credits (fast)
Person scan:     5–20 credits (depends on entity diversity)
Phone scan:      2–3 credits (fast)
```

### Entity Extraction Rates

```
/search endpoint yields:
  Email query:     8–12 entities per credit
  Username query:  5–8 entities per credit
  Domain query:    15–30 entities per credit (if subdomains found)
  IP query:        3–5 entities per credit

/username/social endpoint yields:
  100–200+ platform checks, 3–8 platforms found per credit

Force-multiplier cascade:
  1 API key found = 10–100x entity multiplier (unlocks downstream modules)
```

---

## Alert Thresholds

Set up monitoring:

```bash
# Alert if 80% of daily quota used
if [ $REMAINING -lt $(( DAILY_LIMIT / 5 )) ]; then
  echo "⚠️  WARNING: 80% of daily quota consumed"
fi

# Alert if slow response time
if [ $RESPONSE_TIME -gt 30000 ]; then
  echo "⚠️  WARNING: Slow API response (>30s)"
  # Likely deep search hitting 40s server cap
  # Consider using --depth 1 or increasing timeout
fi
```

---

## Billing Optimization (Enterprise)

For high-volume users:

1. **Monitor weekly trends** — Are you using 60–80% of daily quota?
2. **Consider upgrading** — If consistently hitting limits, next tier is better ROI
3. **Batch operations** — Group scans to maximize cache hits
4. **Use free modules first** — dns_intel, cert_intel, web_crawler (0 credits)
5. **Force-multiplier strategy** — Prioritize API key discovery to unlock other paid APIs

---

## SLA & Uptime

SeekNow guarantees **99.97% uptime**. In case of service degradation:

```bash
# Check status anytime
curl -s -H "X-API-Key: $HUNTSMAN_SEEKNOW_KEY" \
  https://see-know.eu/api/v1/status | jq '.sources'

# Shows: snusbase, leakcheck, intelx, breachhub status
# "ok" = operational
# "degraded" = slow/partial
# "down" = unreachable
```

**HSE's auto-recovery:**
- Service degraded? → Auto-retry with exponential backoff
- Transient timeout? → Automatic 3x retry
- One endpoint down? → Skip, continue with others
- Quota exhausted? → Graceful stop, no error

---

## Next Steps

1. **Run daily health check** — `./hse-daily-check.sh`
2. **Profile your usage** — Track cost per entity type
3. **Optimize depths** — Use depth 1 for verification, depth 3 for high-value
4. **Monitor alerts** — Set thresholds for quota/performance
5. **Plan scans** — Batch multiple targets to maximize ROI

**Your current plan:** Enterprise (15,000 credits/day, unlimited)  
**Recommendation:** Run 10–15 depth-3 scans daily, or 50–100 depth-1 scans  
**ROI:** At current budget, each depth-3 domain scan costs ~5 credits and yields 20+ entities = **0.25 credits per entity**
