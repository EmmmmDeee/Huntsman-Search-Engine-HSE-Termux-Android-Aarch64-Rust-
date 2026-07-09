# SeekNow API Setup & Configuration Guide

This guide walks you through configuring HSE to use the SeekNow (see-know.eu) API — a powerful breach + stealer + OSINT pool that runs parallel to OathNet, providing overlapping coverage of the same data corpus with a separate daily quota.

---

## Quick Start (3 minutes)

### 1. Get Your SeekNow API Key

1. **Sign up** at [see-know.eu](https://see-know.eu/signup) and verify your account
2. Go to your **API Dashboard**: https://see-know.eu/account/dashboard
3. Under **API Key Status**, copy your active key (64-character hex string starting with `seek-`)
4. Note your **API Base URL**: `https://see-know.eu/api/v1`
5. Note your **daily credits limit** (e.g., 15,000 for enterprise plans)

### 2. Add Your Key to HSE

Copy the `.env.example` to your home directory and add your credentials:

```bash
# Copy the template
cp .env.example ~/.huntsman.env

# Edit and add your SeekNow key
# nano ~/.huntsman.env
```

Add these lines to `~/.huntsman.env`:

```bash
export HUNTSMAN_SEEKNOW_BASE="https://see-know.eu/api/v1"
export HUNTSMAN_SEEKNOW_KEY="seek-your-64-character-key-here"
```

### 3. Verify the Setup

```bash
# HSE reads ~/.huntsman.env automatically on startup
hse doctor

# You should see: ✓ SeekNow: key present, validating...
```

That's it! SeekNow is now configured.

---

## How SeekNow Works in HSE

### Endpoints & Query Types

SeekNow provides 18 specialized endpoints. HSE automatically routes queries to the best endpoint for each target type:

| Target Type | Primary Endpoint    | Additional Endpoints                      |
|-------------|-------------------|-------------------------------------------|
| **Email**   | `/search`          | `/network/email-check` (service mapping) |
| **Username** | `/search`          | `/username/social`, `/username/history`, gaming ID resolution |
| **Phone**   | `/search`          | `/network/phone` (carrier enrichment)   |
| **Domain**  | `/search`          | `/domain/intel`, `/domain/whois`        |
| **IP**      | `/search`          | `/network/ip`                            |
| **Name**    | `/search` (auto)   | (no add-ons needed)                      |

The universal `/search` endpoint returns:
- Breach records (leaked credentials, password hashes)
- Stealer logs (malware-harvested data from infected machines)
- External OSINT records (social media, employment data, networking)
- Unified counts: `breach_count`, `stealer_count`, `external_count`

All results are returned in a **single paid lookup** — there's no separate breach vs. stealer vs. external cost; the `/search` endpoint covers everything.

### Budget & Daily Limits

HSE automatically **discovers your daily credit limit** at runtime via the `/credits` endpoint:

1. **First scan of the session** → HSE queries `/credits` (free, no budget consumed)
2. **Detected daily limit** → `15,000` (or your plan's limit)
3. **Per-scan budget calculated** → `limit / 20` (e.g., 15,000 ÷ 20 = 750 lookups/scan)
4. **Capped to sane bounds** → `clamp(750, 300, 2500)` per scan
5. **Scan executes** with that budget allocation

**Override the budget** if you want to test or fine-tune:

```bash
# Limit a single scan to 100 lookups (useful for testing)
hse scan --kind email --value test@example.com --depth 1 --seeknow-scan-cap 100

# Or set it globally in ~/.huntsman.env
export HUNTSMAN_SEEKNOW_SCAN_CAP=160
```

### API Response Handling

- **Empty results** (no breach/stealer records) → No entities emitted, budget credited back
- **Auth error** (`invalid_api_key` / `plan_required`) → Module disables for the scan
- **Quota exhausted** (`credits_remaining: 0`) → Module stops, remaining modules continue
- **Rate limit** → Automatic backoff, request retried
- **Timeout** (55s+ for name searches) → Gracefully degraded, logged as module timeout

### Data Extraction

HSE extracts these entity types from SeekNow responses:

| Entity Type | Source Fields | Examples |
|-------------|---------------|----------|
| **Email** | Leaked emails, accounts | user@example.com |
| **Username** | Social media handles, stealer usernames | alice_92 |
| **Phone** | Leaked phone numbers | +1-555-0123 |
| **Person** | Names, employee records | John Doe |
| **Credentials** | Username + password pairs (hashed or plaintext) | alice:password123 |
| **ApiKey** | Leaked API keys, tokens | sk-ant-abc123... |
| **Address** | Physical addresses from stealer logs | 123 Main St, City, State |
| **Coordinates** | GPS coordinates, location data | lat/lng |
| **Organisation** | Employer, company name | Acme Corp |
| **Domain** | Email domain, corporate domain | acme.com |
| **IpAddress** | Leaked IPs, infrastructure | 192.0.2.1 |

Plus: **API Keys** (80+ prefix patterns: `sk-ant-`, `AKIA`, `ghp_`, `AIzaSy`, `eyJ`, etc.) are automatically extracted and tagged as `force-multiplier` — they unlock downstream paid modules.

---

## Configuration Reference

### Environment Variables

#### Required
- `HUNTSMAN_SEEKNOW_KEY` — Your API key (64-char hex string)

#### Optional
- `HUNTSMAN_SEEKNOW_BASE` — Override API base URL
  - Default: `https://see-know.eu/api/v1`
  - Use cases: Testing, corporate proxy, alternative endpoint
  - Must be HTTPS with valid TLS cert
- `HUNTSMAN_SEEKNOW_SCAN_CAP` — Per-scan credit budget (integer)
  - Default: Auto-detected from daily plan limit
  - Range: 1–2500
  - Use case: Testing, quota management

### .env File Setup

Create/edit `~/.huntsman.env`:

```bash
# SeekNow API configuration
export HUNTSMAN_SEEKNOW_BASE="https://see-know.eu/api/v1"
export HUNTSMAN_SEEKNOW_KEY="seek-fdc8677a1c480a7bf59b866b81eda1f44b9944caf395c699"

# Optional: override per-scan budget
# export HUNTSMAN_SEEKNOW_SCAN_CAP=160
```

File permissions (auto-set):
```bash
chmod 600 ~/.huntsman.env  # Read/write for owner only, no group/world access
```

---

## Troubleshooting

### "SeekNow: key invalid" or "plan_required"

**Causes:**
1. API key is wrong or disabled
2. Account doesn't have a paid plan
3. Key was regenerated (old key is now invalid)

**Fix:**
1. Go to https://see-know.eu/account/dashboard
2. Check **API Key Status** → should say "Active"
3. If it says "Disabled" or "Revoked", regenerate a new key and update `~/.huntsman.env`
4. Verify your account has a paid plan (free tier doesn't work)
5. Restart HSE: `hse serve` (HSE reloads `~/.huntsman.env` on startup)

### "SeekNow: quota exhausted" or "credits_remaining: 0"

**Causes:**
1. You've used all 15,000 daily credits (example for enterprise plan)
2. Credits reset at midnight UTC

**Fix:**
1. Check **Credits Overview** at https://see-know.eu/account/dashboard
2. Credits reset **daily at midnight UTC** (shows time until reset)
3. For testing, use `HUNTSMAN_SEEKNOW_SCAN_CAP=10` to limit a scan to 10 lookups
4. You can **upgrade your plan** to increase daily limit

### "SeekNow timeout" or "No results returned"

**Causes:**
1. Name searches (`/search` with `type: ""`) take 50–60 seconds (server cap is ~55s)
2. Network latency or TLS handshake delay
3. Server is overloaded

**Fix:**
1. HSE's timeout budget is **75s (curl) + 78s (outer tokio)** — exceeds the server cap
2. If you see "curl failed: timeout (28)", the server hit its own limit, not HSE's
3. Retry the scan (transient failure)
4. Use `--depth 1` or `--expansion-floor 0.5` to reduce queries and latency

### "Connection refused" or "DNS lookup failed"

**Causes:**
1. Network offline or firewall blocking `see-know.eu`
2. DNS resolver not working
3. Proxy misconfiguration

**Fix:**
1. Test manually: `curl -X POST https://see-know.eu/api/v1/search -H "X-API-Key: seek-..." -d '{"query":"test","limit":1}'`
2. Check DNS: `nslookup see-know.eu` (should resolve to an IP)
3. Check network: `ping see-know.eu` (should get responses)
4. If behind a proxy, check `HTTPS_PROXY` environment variable

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

## Testing Your Configuration

### Step 1: Verify the key is loaded

```bash
hse doctor
```

**Expected output:**
```
✓ SeekNow: key present, validating...
✓ SeekNow: quota probe successful — daily limit 15000, scan cap 750
```

### Step 2: Run a test scan

```bash
hse scan --kind email --value test@example.com --depth 1
```

**Expected behavior:**
- SeekNow queries first (highest priority)
- Results page shows entities extracted from SeekNow
- Browser UI tabs: **Entities · Correlations · D3 Graph · Logs**

### Step 3: Check the debug logs

```bash
RUST_LOG=debug hse scan --kind email --value test@example.com --depth 1 2>&1 | grep see_know
```

**Expected log lines:**
```
see_know: query={test@example.com} type=email budget_remaining=750
see_know: cache miss, calling /search
see_know: 3 items returned, budget_remaining=749
see_know: extracted 2 Email, 1 Person from results
```

---

## Integration with Other Modules

### OathNet Pro vs. SeekNow

Both are paid breach/stealer sources. They run **in parallel**, not sequentially:

| Aspect | OathNet Pro | SeekNow |
|--------|------------|---------|
| **Corpus** | ~5 billion records | ~8 billion records |
| **Coverage** | Overlapping | Overlapping but distinct |
| **Priority** | High (90) | Highest (255) |
| **Daily Budget** | Session-bundled (1 lookup) | 15,000 per day (auto-scaling) |
| **Cost** | Per-lookup (variable) | Monthly subscription |
| **Use** | Primary discovery source | Complementary, high-coverage expansion |

**Strategy:** Run SeekNow first (depth 0 → discovers keys/emails), then OathNet (depth 1 → validates/enriches). The discovered keys unlock other paid modules (Shodan, Censys, SecurityTrails).

### Free Modules That Benefit from SeekNow

Once SeekNow extracts emails/IPs/domains, these free modules expand on them:

- **dns_intel** — DNS resolution, MX records
- **cert_intel** — Certificate transparency logs
- **crtsh** — CT log aggregator
- **web_crawler** — Config file probing (finds more keys!)
- **social_probe** — Username existence on 600+ sites

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

**Q: How much do my 15,000 daily credits cost?**
A: Depends on your SeekNow plan. Check https://see-know.eu/pricing — enterprise plans are tiered by volume.

**Q: What happens if I run out of credits mid-scan?**
A: SeekNow stops returning results, logs "quota exhausted", and the scan continues with other free/paid modules. No error or crash.

**Q: Can I use SeekNow without OathNet Pro?**
A: Yes! SeekNow works standalone. OathNet Pro is optional (adds a second source). SeekNow alone gives full coverage.

**Q: Do my API keys get sent anywhere except see-know.eu?**
A: No. HSE is fully local — keys are stored in `~/.huntsman.env` and never transmitted except to see-know.eu over HTTPS.

**Q: Can I use the `.icu` endpoint instead of `.eu`?**
A: Not recommended. The canonical endpoint is `https://see-know.eu/api/v1`. If see-know.eu becomes unavailable, check their status page for alternative endpoints. Set `HUNTSMAN_SEEKNOW_BASE` to override.

**Q: How do I disable SeekNow if I want to save credits?**
A: Unset the key: `unset HUNTSMAN_SEEKNOW_KEY` before running HSE, or comment out the line in `~/.huntsman.env`.

---

## Next Steps

1. ✅ Sign up at [see-know.eu](https://see-know.eu/signup)
2. ✅ Copy `.env.example` to `~/.huntsman.env` and add your key
3. ✅ Run `hse doctor` to verify
4. ✅ Run a test scan: `hse scan --kind email --value test@example.com --depth 1`
5. ✅ Check the **Settings** page in the Web UI to paste additional API keys (OathNet, Shodan, etc.)

**Read next:** [API Key Hunting Guide](./API_KEY_HUNTING_GUIDE.md) — how to leverage discovered credentials to unlock the full scanning pipeline.
