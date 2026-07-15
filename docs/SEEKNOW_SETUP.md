# SeekNow API Setup & Configuration Guide

Huntsman Search Engine (HSE) **automatically** uses the SeekNow API for breach + stealer + OSINT intelligence across 212M+ records and 70+ data sources. Just add your API key — HSE handles everything else: endpoint routing, budget management, credit detection, error recovery, request caching, and response archiving.

**Official SeekNow API:** https://see-know.eu/api/v1 (24 endpoints, 99.97% uptime)

---

## Quick Start (2 minutes)

### 1. Get Your SeekNow API Key

1. **Sign up** at [see-know.eu](https://see-know.eu/signup) and verify your account
2. Go to **Account → API Dashboard**: https://see-know.eu/account/dashboard
3. Under **API Key Status**, copy your active key (starts with `seek-`, typically 64+ characters)
4. Check your **plan tier** (Beginner/Pro/PremiumHQ/Enterprise) and daily credit limit

### 2. Add Your Key to HSE (Automatic Setup)

```bash
# Copy the template
cp .env.example ~/.huntsman.env

# Add just your API key (HSE auto-configures everything else)
echo 'export HUNTSMAN_SEEKNOW_KEY="seek-your-api-key-here"' >> ~/.huntsman.env
```

That's it! HSE **automatically**:
- Uses the official `https://see-know.eu/api/v1` endpoint
- Detects your daily credit limit (via `/credits` endpoint — free, no budget consumed)
- Routes queries to optimal endpoints by target type
- Caches responses to avoid duplicate lookups
- Archives all responses for audit/replay
- Handles quota exhaustion gracefully
- Manages request timeouts (75s curl, 78s outer)
- Identifies 80+ API key patterns in leaked data

### 3. Verify the Setup

```bash
# HSE reads ~/.huntsman.env automatically on startup
hse doctor

# Expected output:
# ✓ SeekNow: key present
# ✓ SeekNow: quota probe successful — daily limit 15000, scan cap 750
```

**Done!** Run your first scan:

```bash
hse scan --kind email --value test@example.com --depth 1
```

---

## How SeekNow Works in HSE

### SeekNow Endpoint Coverage: 18 of 24 documented endpoints wired

SeekNow's own published API surface documents 24 endpoints across 6
categories. HSE actually calls 18 of them — the table below states each
one's real status honestly (verified 2026-07-15 against the actual
dispatch code, not assumed from the vendor's docs):

| Category | Endpoints | Credits | Status |
|----------|-----------|---------|--------|
| **Search** | `/search` | 1 | **Wired** — the universal call, dispatched for every target kind |
| **Search** | `/search/deep` | 1 | Not implemented — HSE always calls fast `/search`, never deep |
| **Stealer Logs** | `/stealer` | 2 | Removed — live-verified 404 against the real API; its data still arrives via `/search`'s stealer-shaped response instead |
| **Social/Gaming** | `/username/{github,twitter,tiktok,reddit,social,history}`, `/discord/{user,to-roblox}`, `/gaming/{xbox,roblox,minecraft}` | 1 each | **Wired** (9 endpoints) |
| **Network** | `/network/{ip,email-check,phone}` | 1 each | **Wired** (3 endpoints) |
| **Domain** | `/domain/{intel,whois}` | 1 each | **Wired** (2 endpoints) |
| **Enterprise** | `/enterprise/discord/{history,messages,export}` | 5 each | Not implemented — Enterprise-plan-gated; never built |
| **Meta** | `/credits` | 0 | **Wired** — used for quota probing (`hse doctor`, scan-cap scaling) |
| **Meta** | `/status` | 0 | Not implemented — informational only, no entities to extract |

Also wired but not part of the vendor's own documented 24: `/gaming/steam`
(`gaming/steam?id=<SteamID64>`), dispatched for a target that resolves to a
Steam64 ID.

**Key advantages:**
- **212M+ records** across 70+ data sources (Snusbase, LeakCheck, IntelX, Breachhub, etc.)
- **Fast mode** (~5s typical) — the only search mode HSE currently calls
- **Unified authentication**: one API key for every wired endpoint
- **99.97% uptime** SLA with rate-limit headers on every response
- **Auto-retry logic**: Handles 429 (quota), 500 (server errors), timeouts

### Automatic Budget & Credit Management

HSE **automatically detects and optimizes your credit usage**:

**Detection (first scan):**
1. HSE calls `/credits` endpoint (free — 0 credits consumed)
2. Reads your plan tier + daily limit (e.g., "PremiumHQ: 5,000/day")
3. Calculates per-scan budget: `daily_limit ÷ 20` (e.g., 5,000 ÷ 20 = 250)
4. Clamps to 300–2,500 range per operator directive

**Your Plans (Official SeekNow Tiers):**

| Plan | Credits/Day | Use Case |
|------|-------------|----------|
| **Beginner** | 100 | Testing, single scans |
| **Pro** | 500 | Regular OSINT workload |
| **PremiumHQ** | 5,000 | Active threat hunting |
| **Enterprise** | Unlimited* | Intensive operations (also unlocks `/enterprise/discord/*`) |

*Enterprise plans also get access to Discord history archives via 5-credit `/enterprise/discord/{history,messages,export}` endpoints.

**Override if needed:**

```bash
# Temporarily limit to 50 credits for testing
hse scan --kind email --value test@example.com --depth 1 --seeknow-scan-cap 50

# Or set globally in ~/.huntsman.env
export HUNTSMAN_SEEKNOW_SCAN_CAP=250
```

### API Response Handling

- **Empty results** (no breach/stealer records) → No entities emitted, budget credited back
- **Auth error** (`invalid_api_key` / `plan_required`) → Module disables for the scan
- **Quota exhausted** (`credits_remaining: 0`) → Module stops, remaining modules continue
- **Rate limit** → Automatic backoff, request retried
- **Timeout** (55s+ for name searches) → Gracefully degraded, logged as module timeout

### Automatic Data Extraction & Enrichment

HSE extracts **17 entity types** from SeekNow responses across the 18 wired endpoints:

| Entity Type | Sources | Examples |
|-------------|---------|----------|
| **Email** | `/search`, `/network/email-check`, stealer logs | user@example.com |
| **Username** | `/search`, `/username/*` endpoints, stealer logs | john_doe, @elonmusk |
| **Phone** | `/search`, `/network/phone`, stealer logs | +1-555-0123, +33612345678 |
| **Person** | `/search`, names from breach records | John Doe, Alice Smith |
| **Credentials** | `/stealer`, `/search`, password hashes | alice:password123 (or hashed) |
| **ApiKey** | `/search`, leaked configs (80+ patterns) | sk-ant-..., AKIA..., ghp_... |
| **Address** | `/search`, stealer machine info | 123 Main St, Paris, FR |
| **Coordinates** | `/network/ip`, geolocation data | 48.8566°N, 2.3522°E |
| **Organisation** | `/search`, employer records | Acme Corp, Google Inc |
| **Domain** | `/search`, `/domain/*`, email domains | example.com, acme.com |
| **IpAddress** | `/network/ip`, `/search`, infrastructure | 192.0.2.1, 2001:db8::1 |
| **Asn** | `/network/ip`, routing data | AS15169, AS8452 |
| **MacAddress** | Stealer logs, machine fingerprints | 00:1A:2B:3C:4D:5E |
| **DeviceId** | `/gaming/*`, platform IDs | Discord: 123456789, Xbox: gamertag |
| **Url** | `/search`, breach URLs, leaked data | https://login.target.com |
| **Password** | `/stealer`, plaintext + hashes | Password123, $2b$12$... |
| **CryptoAddress** | Leaked crypto wallets | 1A1z7agoat..., 0xd8dA6... |

**API Key Auto-Recognition:** HSE identifies 80+ key patterns (`sk-ant-`, `AKIA`, `ghp_`, `AIzaSy`, `eyJ`, etc.) and tags them as `force-multiplier` — discovered keys automatically unlock Shodan, Censys, SecurityTrails, and other paid modules.

---

## Configuration Reference

### Automatic Setup (Recommended)

```bash
# Just add your key — HSE configures everything else automatically
echo 'export HUNTSMAN_SEEKNOW_KEY="seek-your-api-key-here"' >> ~/.huntsman.env

# Verify setup
hse doctor
```

### Environment Variables

| Variable | Required | Default | Use Case |
|----------|----------|---------|----------|
| `HUNTSMAN_SEEKNOW_KEY` | ✅ Yes | — | Your API key (64+ chars, starts with `seek-`) |
| `HUNTSMAN_SEEKNOW_BASE` | ❌ No | `https://see-know.eu/api/v1` | Override endpoint (testing, proxy, alternative) |
| `HUNTSMAN_SEEKNOW_SCAN_CAP` | ❌ No | Auto-detected | Override per-scan budget (1–2500, useful for testing) |

### Example ~/.huntsman.env

```bash
# Minimal (HSE auto-configures everything)
export HUNTSMAN_SEEKNOW_KEY="seek-fdc8677a1c480a7bf59b866b81eda1f44b9944caf395c699"

# Advanced (override per-scan budget for testing)
export HUNTSMAN_SEEKNOW_KEY="seek-fdc8677a1c480a7bf59b866b81eda1f44b9944caf395c699"
export HUNTSMAN_SEEKNOW_SCAN_CAP=100  # Limit to 100 credits per scan

# Explicit endpoint (only if self-hosting or using an alternate mirror — rare)
export HUNTSMAN_SEEKNOW_KEY="seek-fdc8677a1c480a7bf59b866b81eda1f44b9944caf395c699"
export HUNTSMAN_SEEKNOW_BASE="https://see-know.eu/api/v1"
```

### File Permissions

HSE automatically sets secure permissions:
```bash
chmod 600 ~/.huntsman.env  # Owner read/write only (no group/world access)
```

**Never commit** `~/.huntsman.env` to git — use `.gitignore`:
```bash
echo "~/.huntsman.env" >> ~/.gitignore
```

---

## Automatic Error Handling

HSE **automatically handles** these scenarios:

| Error | Cause | HSE Action |
|-------|-------|-----------|
| **401 Unauthorized** | Invalid/expired API key | Logs "key invalid", disables SeekNow for scan |
| **403 Forbidden** | Plan doesn't allow endpoint | Skips endpoint, continues with others |
| **429 Rate Limited** | Quota exhausted or cooldown | Stops SeekNow, other modules continue |
| **500 Server Error** | SeekNow internal error | Automatic retry (up to 3x with backoff) |
| **Timeout (>78s)** | Slow search/network delay | Graceful degradation, logs timeout, continues |
| **Connection Error** | Network/DNS/firewall issue | Retries with exponential backoff |

## Troubleshooting

### "SeekNow: key invalid" or "plan_required"

**Cause:** API key is wrong, expired, or account lacks a paid plan.

**Fix:**
1. Go to https://see-know.eu/account/dashboard
2. Check **API Key Status** — should say "Active"
3. If disabled/revoked, regenerate and update `~/.huntsman.env`
4. Verify your plan is **Beginner or higher** (Free tier = dashboard only, no API access)
5. Restart HSE: `hse serve` (reloads `~/.huntsman.env`)

**Test manually:**
```bash
curl -H "X-API-Key: seek-YOUR_KEY" https://see-know.eu/api/v1/credits
# Expected: {"success":true,"plan":"premiumhq","credits_remaining":5000,...}
```

### "SeekNow: quota exhausted" (HTTP 429)

**Cause:** Daily credit limit reached (resets at midnight UTC).

**Fix:**
1. Check balance: `curl -H "X-API-Key: seek-..." https://see-know.eu/api/v1/credits`
2. Credits reset **daily at midnight UTC** (shown in response: `resets_at`)
3. For testing: `export HUNTSMAN_SEEKNOW_SCAN_CAP=50` to limit budget
4. Upgrade your plan at https://see-know.eu/pricing

### "SeekNow: timeout" (takes >40s)

**Cause:** Deep searches or name auto-detect queries are slow (server cap ~40s).

**Fix:**
1. HSE timeout budget: 75s curl + 78s tokio (exceeds server cap)
2. If search takes >40s, it's the server (not HSE) hitting its limit
3. Retry the scan (transient slow response)
4. Use `--depth 1` to reduce query volume

### "Connection refused" or DNS lookup failed

**Cause:** Network unreachable, firewall blocking `see-know.eu`, or DNS resolver issues.

**Fix:**
```bash
# Test connectivity
curl -H "X-API-Key: seek-..." https://see-know.eu/api/v1/status

# Check DNS
nslookup see-know.eu

# Check firewall (should respond)
curl -I https://see-know.eu
```

### Service Status

Check upstream data source status anytime:

```bash
curl -H "X-API-Key: seek-..." https://see-know.eu/api/v1/status
# Response shows: snusbase, leakcheck, intelx, breachhub, etc. status
```

---

## Best Practices

### 1. API Key Security

- **Never commit** `~/.huntsman.env` to git
- **Never log** your key (HSE doesn't, but watch scripts)
- **Never paste** your key in chat, issue trackers, or screenshots
- **Rotate regularly** if you suspect exposure
- **Disable immediately** if you lose the key file

### 2. Budget Management

- **Depth 3 scans** use ~100–300 credits per seed (depending on entity types discovered)
- **Large scans** (10+ entities, multiple rounds) can hit 500–1000 credits
- **Name searches** are expensive (one lookup returns 10–100+ records)
- **Test with depth 1** first to gauge budget burn
- **Use `--full`** only on high-value targets (keys, infrastructure, people)

### 3. Data Retention

- **Raw API responses** are archived locally for audit/replay
  - Location: `~/.hse/raw_archive/see-know/`
  - Retention: Manual deletion only (HSE never auto-deletes)
  - Use case: Reproduce a finding, verify API schema
- **Scan results** (entities, relationships) are stored in SQLite
  - HSE keeps ~2500 most-recent entities per scan by default

### 4. Multiple Environments

If you're running HSE on multiple devices or have different keys for different roles:

```bash
# ~/.huntsman.env (primary — production API key)
export HUNTSMAN_SEEKNOW_KEY="seek-production-key-..."

# For testing/dev, override at runtime:
HUNTSMAN_SEEKNOW_KEY="seek-test-key-..." hse scan --kind email --value test@ex.com
```

---

## Quick Verification

### One-Command Validation

```bash
# This single command validates everything
hse doctor
```

**Expected output:**
```
✓ SeekNow: key present
✓ SeekNow: quota probe successful
✓ Plan: PremiumHQ, daily limit: 5000, scan cap: 250 credits/scan
✓ Base URL: https://see-know.eu/api/v1
✓ API Key: see-know.eu:seek-fdc8…c699 (fingerprinted, full secret hidden)
```

### First Scan

```bash
# Run a real scan against any target
hse scan --kind email --value test@example.com --depth 1
```

HSE will **automatically**:
1. Validate the API key
2. Detect your daily credit limit
3. Calculate per-scan budget
4. Route queries to optimal endpoints
5. Cache and archive responses
6. Extract and deduplicate results
7. Generate entity correlations

Open the Web UI at `http://127.0.0.1:8080` to see live results.

### Debug Logs (If Needed)

```bash
# Show SeekNow operation traces
RUST_LOG=debug hse scan --kind email --value test@example.com --depth 1 2>&1 | grep see_know
```

Example output:
```
see_know: query=test@example.com type=email budget=250
see_know: /search cache miss, fetching…
see_know: 42 items returned, extracted 15 Email + 8 Person
see_know: budget remaining: 249
```

---

## HSE's Automatic Orchestration

**You don't configure this — HSE does it automatically:**

### Module Priority (Execution Order)

```
Phase 1 (Paid, Sequential Priority)
  255: SeekNow (discovers keys, emails, infrastructure)
   ↓ (discovered keys unlock downstream modules)
  200: OathNet Pro (overlapping coverage, complementary corpus)
  190: Shodan (if API key found)
  180: Censys (if API key found)
   
Phase 2 (Free Expansion, Unlimited Parallelism)
  ↓ (on every new Domain, Email, IP entity)
   
  • dns_intel (DNS resolution, MX, SOA)
  • cert_intel (CT logs, certificate SANs)
  • crtsh (CT aggregator, historical certs)
  • web_crawler (probes 103 config-file paths per domain)
  • social_probe (600+ social network checks)
  • search_engines (Google, Bing, Duckduckgo scraping)
```

**SeekNow's Role:** Highest priority (255) because:
1. Discovers most entity types in one call
2. Returns potential API keys early
3. Feeds keys to unlock downstream paid modules
4. Its 18 wired endpoints give overlapping coverage with OathNet (separate data sources)

### The Force-Multiplication Loop

```
SeekNow /search
  ↓
Extracts: emails, IPs, domains, usernames, API keys
  ↓
API Keys → Force-Multiplier Tag
  ↓
Shodan/Censys/SecurityTrails unlock (if keys found)
  ↓
web_crawler probes domains (finds config files)
  ↓
More API keys discovered
  ↓
Loop continues (depth 2, 3, … on configured depth)
```

**Result:** Every discovered credential becomes a force-multiplier that cascades through the scanning pipeline, exponentially increasing coverage.

### Free Module Benefits

Once SeekNow extracts **emails, IPs, domains, usernames**, these **free modules automatically expand**:

| Module | Input | Benefit |
|--------|-------|---------|
| **dns_intel** | Domain | MX records, nameservers, A/AAAA records |
| **cert_intel** | Domain/IP | Certificate SANs, issuance history |
| **crtsh** | Domain | CT log aggregation, historical certs |
| **web_crawler** | Domain | Probes 103 config paths (finds env vars, keys!) |
| **social_probe** | Username/Email | 600+ social platform checks |
| **search_engines** | Domain/IP | Google/Bing scraping for exposed configs |

---

## Example Workflows

### Workflow 1: "Catch a data breach on first alert"

```bash
# New breach announced for "acme.com"
hse scan --kind domain --value acme.com --depth 1

# SeekNow immediately returns: employees, emails, breaches
# If it finds API keys → unlocks Shodan/Censys for infrastructure
# Result: Domain's attack surface in <30 seconds
```

### Workflow 2: "Profile a target person"

```bash
# Given a name and employer
hse scan --kind name --value "John Doe" --depth 2

# SeekNow returns: emails, social profiles, physical locations
# Depth 2 expansion: web_crawler probes those domains for config files
# Result: Complete contact + infrastructure map
```

### Workflow 3: "Hunt leaked API keys"

```bash
# Monitor a third-party data provider for breaches
hse scan --kind email --value admin@mycompany.com --depth 3 --full

# SeekNow extracts all credentials (including keys from /password fields)
# api_key_probe module recognizes 80+ key prefixes
# Found keys tagged as "force-multiplier" → cascade unlocks more modules
# Result: Every exposed credential and all discoverable APIs
```

---

## FAQ

**Q: What's the difference between `/search` and `/search/deep`?**
- **Fast (~5s):** Local DB + low-latency sources, 212M+ records
- **Deep (~40s):** Fast + slower high-yield databases, maximum coverage
- HSE auto-selects based on target type and expansion depth

**Q: How many credits do typical scans use?**
- Single email lookup: 1–5 credits
- Full profile scan (depth 2): 50–150 credits  
- Deep hunting scan (depth 3): 200–500 credits
- Depends on what entities are discovered (pivots expand budget)

**Q: What if I run out of credits mid-scan?**
- SeekNow stops, logs "quota exhausted"
- Other free/paid modules continue (no crash)
- Scan completes with partial results
- Credits reset tomorrow at midnight UTC

**Q: Can I use SeekNow without OathNet Pro?**
- Yes, SeekNow is standalone
- OathNet Pro is optional (overlapping data, separate quota)
- SeekNow's 18 wired endpoints provide broad coverage alone

**Q: Are my API keys kept secret?**
- ✅ Keys stored in `~/.huntsman.env` only (local disk)
- ✅ Never logged to console or scan results
- ✅ Only transmitted to see-know.eu over HTTPS
- ✅ Key fingerprinting (head…tail) used in results, never full secret
- ✅ Per-module isolation (each module gets only its own key)

**Q: I've seen both `.eu` and `.icu` mentioned for SeekNow — which should I use?**
- **Use `.eu`** — it's the vendor's own stated domain (HSE default) and what
  their live site's own generated exports name as their platform
- `.icu` has been observed failing to resolve via DNS on some real-world
  networks/carriers (a common failure mode for that TLD's abuse reputation)
  even when it happens to be reachable from others — prefer `.eu`
- HSE automatically uses `https://see-know.eu/api/v1`

**Q: How do I disable SeekNow temporarily?**
```bash
# Option 1: Comment out in ~/.huntsman.env
# export HUNTSMAN_SEEKNOW_KEY="seek-..."

# Option 2: Unset before running HSE
unset HUNTSMAN_SEEKNOW_KEY
hse scan --kind email --value test@example.com --depth 1
```

**Q: Can I use multiple API keys for different scans?**
- Yes: `HUNTSMAN_SEEKNOW_KEY=key2 hse scan ...` (overrides)
- Or manage via Web UI: **Settings → API Keys** (paste/update keys in browser)

**Q: What's the difference between Beginner/Pro/PremiumHQ/Enterprise?**

| Plan | Credits/Day | Cost | Best For |
|------|-------------|------|----------|
| Beginner | 100 | $ | Learning, testing |
| Pro | 500 | $$ | Regular OSINT ops |
| PremiumHQ | 5,000 | $$$ | Active threat hunting |
| Enterprise | Unlimited | $$$$$ | Intensive ops + Discord archives |

**Q: Do I need to restart HSE after updating `~/.huntsman.env`?**
- Yes: `hse serve` reloads the file on startup
- Key changes take effect immediately on next run

---

## Ready-to-Use Workflows

### 1. "Catch a Data Breach"
```bash
hse scan --kind domain --value acme.com --depth 1
```
SeekNow returns employees, emails, breaches in <5s. API keys found → auto-unlock Shodan/Censys.

### 2. "Profile a Person"
```bash
hse scan --kind email --value john@example.com --depth 2
```
SeekNow extracts emails, socials, locations. Depth 2 auto-probes domains for config files.

### 3. "Hunt API Keys"
```bash
hse scan --kind email --value admin@company.com --depth 3 --full
```
SeekNow extracts credentials + 80+ key patterns. Found keys auto-unlock downstream modules.

### 4. "IP Reconnaissance"
```bash
hse scan --kind ip --value 1.2.3.4 --depth 2
```
SeekNow returns geolocation, ASN, breach mentions. Depth 2 auto-expands to related domains.

---

## Setup Complete ✅

1. ✅ API key added to `~/.huntsman.env`
2. ✅ Verified with `hse doctor`
3. ✅ Start scanning: `hse scan --kind email --value test@example.com --depth 1`

**HSE automatically handles** endpoint routing, credit optimization, caching, archiving, error recovery, key extraction, and force-multiplier cascade.
