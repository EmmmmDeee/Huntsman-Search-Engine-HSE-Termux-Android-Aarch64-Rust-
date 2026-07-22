# See-Know Troubleshooting Guide
**Status:** Phase 4.2 (To-Be Implemented)

## Common Issues & Solutions

### API Connectivity

#### Issue: "Connection refused" or "Cannot reach see-know.eu"
**Cause:** Network connectivity issue or upstream maintenance
**Solutions:**
1. Verify internet connectivity: `ping see-know.eu`
2. Check outbound proxy settings
3. Try alternate domain: `.vip` or `.ru`
4. Check upstream status: `hse scan --value status-check`

### Authentication & Keys

#### Issue: "Invalid API key" (401 Unauthorized)
**Cause:** API key is expired, rotated, or misconfigured
**Solutions:**
1. Verify key format: `echo $HUNTSMAN_SEEKNOW_KEY | head -c 5`
   - Should start with `seek-`
2. Check key hasn't been rotated: Log in to account dashboard
3. Ensure no extra whitespace: `echo -n "$HUNTSMAN_SEEKNOW_KEY" | wc -c`
   - Should be 64+ characters
4. Regenerate key if compromised: Update in ~/.huntsman.env

#### Issue: "Plan tier not detected"
**Cause:** Tier detection failed; using default tier
**Solutions:**
1. Force tier re-detection: Clear cache and retry
2. Check account status: Log in to see-know.eu dashboard
3. Verify plan is active (not suspended/expired)
4. Run: `hse doctor` to see tier detection status

### Budget & Credits

#### Issue: "Insufficient credits for scan"
**Cause:** Ran out of daily quota
**Solutions:**
1. Check remaining credits: `hse scan --value credits`
2. Wait for daily reset (UTC midnight)
3. Upgrade plan for higher daily limit
4. Estimate cost before scanning: `hse scan --dry-run`

#### Issue: "Budget exceeded on cascade"
**Cause:** Cascade depth too high; consider tuning
**Solutions:**
1. Reduce cascade depth: `--cascade-depth 2` (default 3)
2. Disable cascade: `--no-cascade`
3. Increase daily budget: Upgrade plan
4. Profile cascade efficiency: Check Phase 3.4 cascade optimizer

### Performance & Timeouts

#### Issue: "Request timeout" (>78s)
**Cause:** Slow endpoint response or network latency
**Solutions:**
1. Retry query (transient issue): `hse scan --retry 3`
2. Use fast path only: `--fast-only` (skip /search/deep)
3. Check latency to server: `curl -w "@/dev/stdin" -o /dev/null -s https://see-know.eu/api/v1`
4. For very slow queries, increase timeout: Check Phase 1.4 timeout tuning

#### Issue: "High latency on /search/deep"
**Cause:** Deep search is slower (40s avg vs 5s fast)
**Solutions:**
1. Ensure only fallback on miss: Check if fast /search returned empty
2. Batch queries during low-traffic hours
3. Use Pro+ plan for priority queue (if available)
4. Monitor Phase 3.1 latency SLA metrics

### Rate Limiting

#### Issue: "429 Too Many Requests"
**Cause:** Hit rate limit; backoff in progress
**Solutions:**
1. Automatic backoff active (2s → 4s → 8s)
2. Wait for backoff to complete (<10s typically)
3. Reduce query rate if repeated
4. Upgrade plan for higher rate limit

#### Issue: "Backoff not working / still getting 429"
**Cause:** Backoff exhausted (3 retries max)
**Solutions:**
1. Implement exponential backoff in client (Phase 3.3)
2. Check backoff jitter: Should vary by ±10%
3. Wait longer before retry (manual wait recommended)
4. Check if IP is globally rate-limited: Contact support

### Data Quality

#### Issue: "Missing entities in results"
**Cause:** Endpoint incomplete or entity extraction failed
**Solutions:**
1. Verify endpoint is wired: `hse doctor` shows module status
2. Check entity extraction rules: Phase 1.0 extraction tests
3. Ensure sufficient query specificity (not too generic)
4. Try alternative endpoints for same target

#### Issue: "Stale data in response"
**Cause:** Cache hit on older entry (24h TTL)
**Solutions:**
1. Bypass cache: `--no-cache` (if supported)
2. Wait for cache expiry: 24 hours from original query
3. Use different query variant to bypass cache key
4. Monitor Phase 3.2 cache hit ratio metrics

### Enterprise Features

#### Issue: "/enterprise/discord/* endpoints return 403"
**Cause:** Plan tier verification failed
**Solutions:**
1. Verify enterprise plan is active
2. Check tier auto-detection: `hse doctor`
3. Regenerate API key: May restore enterprise access
4. Contact support: Escalate if tier is correct but endpoints still blocked

#### Issue: "Discord history export is empty"
**Cause:** No Discord data found for user (not in breach sources)
**Solutions:**
1. Verify Discord ID is correct (should be numeric)
2. Account may not be in See-Know's data sources
3. Try alternative query: Search by username/email associated with Discord
4. Check if account was breached: Search data dumps directly

---

## Performance Tuning

### Optimize for Speed
1. Use `--fast-only` for queries where /search/deep not needed
2. Enable cache: Repeat queries benefit from 24h TTL
3. Batch similar targets (same entity type)

### Optimize for Cost
1. Use `--no-cascade` for simple queries
2. Set `--cascade-depth 2` instead of default 3
3. Batch bulk queries to maximize cache hits
4. Monitor Phase 3.4 cascade efficiency metrics

### Optimize for Coverage
1. Use `--cascade-depth 3` for deep investigation
2. Enable all platforms: `/username/social` covers 15+ platforms
3. Try multiple query formats (email, username, phone)

---

## Monitoring & Debugging

### Enable Debug Logging
```bash
RUST_LOG=debug hse scan --value user@example.com
```

### Check Module Status
```bash
hse doctor
# Look for "See-Know account" section
# Should show: Plan tier, remaining credits, last request timestamp
```

### Measure Performance
```bash
time hse scan --value test@example.com
# Note: Real latency will be shown with timing
```

### Validate Setup
```bash
# Quick validation
cargo test --lib see_know::tests::integration

# Full validation (requires live API)
SEEKNOW_INTEGRATION_TEST=1 cargo test see_know_e2e
```

---

**Report Generated:** Phase 4.2 (To-Be Implemented)
**Branch:** claude/see-know-gap-analysis-3yydci
